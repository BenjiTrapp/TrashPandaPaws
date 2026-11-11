#!/usr/bin/env python3
"""
Unit tests for the operator-facing shell port: one authenticated loopback
port per build identity, which pairs a connection with a terminal session
on the endpoint.

Five things these tests are careful about.

**Both sides are real.** The server end is a real `TunnelServer` with a
real `KeyStore`, and the far end is a stub endpoint that speaks the
protocol an implant speaks: a real `NoiseSession.initiator` over a real
TCP connection, a `HELLO` advertising `features`, and a second connection
dialled per `OPEN_SHELL` carrying the token it was given. That is the
pattern `test_tunnel_socks.py` and `test_listeners.py` set out -- a mock
of either side agrees with whatever the code does and proves nothing
about the two ends matching.

**The client's bytes are the ones an attach client sends**: the prompt is
read, then one line of text ending in `\\n`, then raw terminal bytes. They
are written here as literals rather than built by the module's own
formatter, so what is asserted is the wire `tools/raccoon_shell.py` has to
speak and not what `shell.py` happens to believe.

**Every refusal is read back off the stream.** The operator is looking at
a terminal, so a refusal is one line of plain text and then a close; each
test that provokes one asserts the text, asserts the close, and asserts
which counter moved. A silent drop would pass an assertion that only
counted.

**The two-operator test is two connections at once.** Each one attaches
with its own geometry and the stub echoes with a tag built from the
geometry it was asked for, so a crossed pair shows up as one session
holding the other's terminal size rather than as a count that still adds
up. Both are still live when the assertions run.

**No thread may die quietly.** `setUp` installs a `threading.excepthook`
and a handler on both tunnel loggers, and the last cleanup to run asserts
that no thread raised and that nothing was logged at ERROR or above. A
port that survives a hostile client by crashing a worker would otherwise
pass every assertion in this file.
"""

import logging
import os
import queue
import socket
import tempfile
import threading
import time
import traceback
import unittest

from software.c2.tunnel.keys import KeyStore
from software.c2.tunnel.protocol import (
    MSG_HELLO,
    MSG_OPEN_SHELL,
    MSG_PING,
    MSG_PONG,
    MSG_SHELL,
    SHELL_DEFAULT_COLS,
    SHELL_DEFAULT_ROWS,
    SHELL_GEOMETRY_MAX,
    TUNNEL_FEATURES,
    NoiseSession,
    decode_message,
    encode_message,
    read_frame,
    write_frame,
)
from software.c2.tunnel.server import TunnelServer
from software.c2.tunnel import shell as shell_mod
from software.c2.tunnel.shell import (
    DEFAULT_MAX_SESSIONS,
    PROMPT,
    ShellFront,
    parse_auth_line,
)

_LOOPBACK = "127.0.0.1"

# The range the tunnel server assigns SOCKS ports from. Nothing binds one
# here -- every listener in this file binds port 0 and is read back -- so
# this is a pair of numbers in a JSON file and not a port in a test.
_PORT_RANGE = (40300, 40399)


def _drain(sock, timeout=3.0):
    """Everything the peer sent before it closed, and whether it closed."""
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            return b"".join(chunks), False
        except ConnectionResetError:
            # An RST carries no application bytes; anything the port had
            # sent is already in `chunks`.
            return b"".join(chunks), True
        if not chunk:
            return b"".join(chunks), True
        chunks.append(chunk)


def _waiting(sock):
    """True if a byte is waiting, False on an orderly close."""
    return bool(sock.recv(1, socket.MSG_PEEK))


class _ShellClient(object):
    """An operator's terminal: the prompt, one line, then raw bytes."""

    def __init__(self, port, timeout=10.0):
        self.sock = socket.create_connection((_LOOPBACK, port),
                                             timeout=timeout)

    def prompt(self):
        return self.exactly(len(PROMPT))

    def send_line(self, line):
        """The auth line exactly as an attach client sends it."""
        self.sock.sendall(line.encode("utf-8") + b"\n")

    def send(self, data):
        self.sock.sendall(data)

    def exactly(self, count):
        chunks = b""
        while len(chunks) < count:
            chunk = self.sock.recv(count - len(chunks))
            if not chunk:
                raise AssertionError(
                    "the port closed after %r with %d bytes still expected"
                    % (chunks, count - len(chunks)))
            chunks += chunk
        return chunks

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class _Channel(object):
    """One Noise-protected connection to the tunnel's implant-facing port."""

    def __init__(self, host, port, server_public, psk, payload, timeout=20.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self._noise = NoiseSession.initiator(server_public, psk)
        try:
            write_frame(self.sock, self._noise.initiate(payload))
            self._noise.complete(read_frame(self.sock))
        except BaseException:
            # A handshake the server declines -- a token whose session has
            # already gone, at teardown -- would otherwise leave this
            # socket to the garbage collector, which reports it as a
            # ResourceWarning in the middle of another test's output.
            self.close()
            raise

    def send(self, data):
        write_frame(self.sock, self._noise.encrypt(data))

    def receive(self):
        """One frame's plaintext. `b""` means the far end is finished."""
        if not _waiting(self.sock):
            return b""
        return self._noise.decrypt(read_frame(self.sock))

    def settimeout(self, timeout):
        self.sock.settimeout(timeout)

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


def tagged_echo(shell, cols, rows):
    """The implant's terminal, for a test: say who you are, then echo.

    The tag is what makes a crossed stream visible. Terminal output that
    merely arrived looks identical on every session; output carrying
    another session's geometry does not.
    """
    tag = ("%dx%d|" % (cols, rows)).encode("utf-8")
    while True:
        data = shell.receive()
        if not data:
            return
        shell.send(tag + data)


class _StubEndpoint(object):
    """An endpoint: one command channel, and a shell dialled per OPEN_SHELL.

    `handler(shell, cols, rows)` is the terminal for whichever test
    installed it, and owns everything written on the session. `features`
    is what the `HELLO` advertises; `None` leaves the key out entirely,
    which is a build that predates shell sessions.
    """

    def __init__(self, host, port, server_public, psk, identity,
                 handler=tagged_echo, features=TUNNEL_FEATURES):
        self._host = host
        self._port = port
        self._public = server_public
        self._psk = psk
        self._handler = handler
        self.errors = []
        self.shells = queue.Queue()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._streams = []
        self._threads = []
        body = {"identity": identity, "hostname": "stub-endpoint",
                "os": "Linux-6.1"}
        if features is not None:
            body["features"] = list(features)
        self.channel = _Channel(host, port, server_public, psk,
                                encode_message(MSG_HELLO, body))
        self._pump = threading.Thread(target=self._run, name="stub-command",
                                      daemon=True)
        self._pump.start()

    def _run(self):
        """Answer PING, and dial a shell for every OPEN_SHELL."""
        while not self._stop.is_set():
            try:
                # Peek on a short timeout rather than blocking on the read:
                # closing a socket does not wake a thread already inside
                # `recv` on macOS, so this loop has to come back and look
                # at the stop flag by itself.
                self.channel.settimeout(0.2)
                if not _waiting(self.channel.sock):
                    return
                self.channel.settimeout(10.0)
                kind, body = decode_message(self.channel.receive())
            except socket.timeout:
                continue
            except (OSError, ValueError):
                return
            if kind == MSG_PING:
                try:
                    self.channel.send(encode_message(MSG_PONG, {}))
                except (OSError, ValueError):
                    return
            elif kind == MSG_OPEN_SHELL:
                thread = threading.Thread(target=self._shell, args=(body,),
                                          name="stub-shell", daemon=True)
                with self._lock:
                    self._threads.append(thread)
                thread.start()

    def _shell(self, body):
        cols, rows = body.get("cols"), body.get("rows")
        self.shells.put((cols, rows))
        stream = None
        try:
            stream = _Channel(self._host, self._port, self._public, self._psk,
                              encode_message(MSG_SHELL,
                                             {"token": body["token"]}))
            with self._lock:
                self._streams.append(stream)
            stream.settimeout(30.0)
            self._handler(stream, cols, rows)
        except (OSError, ValueError) as exc:
            # The front shutting a live session down arrives here, so it is
            # only an error while a test still expects this session to work.
            if not self._stop.is_set():
                self.errors.append("%s: %s" % (type(exc).__name__, exc))
        except Exception:
            self.errors.append(traceback.format_exc())
        finally:
            if stream is not None:
                stream.close()

    def next_shell(self, timeout=10.0):
        """The geometry of the next OPEN_SHELL this endpoint was asked for."""
        return self.shells.get(timeout=timeout)

    def close(self):
        self._stop.set()
        self.channel.close()
        with self._lock:
            streams, threads = list(self._streams), list(self._threads)
        for stream in streams:
            stream.close()
        self._pump.join(timeout=5.0)
        for thread in threads:
            thread.join(timeout=5.0)


class _NoThreads(ShellFront):
    """A front whose per-connection threads cannot be started.

    `_start` is the seam `SocksFront` keeps for exactly this, and this
    module inherits it. The branch under test is a process with no threads
    left, and exhausting this machine's thread table to reach it would be
    neither quick nor kind to the rest of the suite.
    """

    def _start(self, thread):
        raise RuntimeError("can't start new thread")


class TestTheAuthLine(unittest.TestCase):
    """`parse_auth_line` on its own: the password is not split blindly.

    The geometry rides on the end of the same line as the password, so a
    naive split reads part of a password as a terminal size and locks the
    operator out of their own port.
    """

    def test_a_bare_password_takes_the_default_geometry(self):
        self.assertEqual(parse_auth_line("s3cret"), ("s3cret", 120, 40))

    def test_a_trailing_geometry_is_taken_off_the_end(self):
        self.assertEqual(parse_auth_line("s3cret 200x50"), ("s3cret", 200, 50))

    def test_a_password_containing_a_space_survives(self):
        self.assertEqual(parse_auth_line("two words"), ("two words", 120, 40))
        self.assertEqual(parse_auth_line("two words 200x50"),
                         ("two words", 200, 50))

    def test_a_tail_that_is_not_a_geometry_stays_in_the_password(self):
        self.assertEqual(parse_auth_line("pw 200x"), ("pw 200x", 120, 40))

    def test_geometry_outside_the_bounds_is_clamped(self):
        self.assertEqual(parse_auth_line("pw 0x99999"), ("pw", 1, 1000))

    def test_the_defaults_and_the_bound_are_the_wires_own(self):
        # The endpoint clamps against these same three numbers before its
        # `ioctl`, so a second copy here would be a defect that only shows
        # up as a terminal of the wrong size.
        self.assertEqual(parse_auth_line("pw"),
                         ("pw", SHELL_DEFAULT_COLS, SHELL_DEFAULT_ROWS))
        self.assertEqual(parse_auth_line("pw 99999x99999"),
                         ("pw", SHELL_GEOMETRY_MAX, SHELL_GEOMETRY_MAX))


class TestARefusalIsOneReadableLine(unittest.TestCase):
    """What a refusal looks like, called directly.

    Not every reason this port writes is written in this module: the ones
    out of `open_shell_session` carry the tunnel server's wording, and one
    of them quotes the feature list the endpoint advertised, which came
    from the implant host. So the shaping is asserted on its own rather
    than through a reason this file would have to keep in step.
    """

    def test_a_reason_from_another_module_is_still_one_line(self):
        self.assertEqual(shell_mod._line("two\nlines   here"),
                         b"raccoon: two lines here\r\n")

    def test_a_terminal_escape_in_a_reason_is_not_written_to_the_terminal(self):
        # The operator's terminal is in raw mode, and part of one reason
        # comes from a host this end does not trust.
        written = shell_mod._line("gone \x1b[2J\x07rogue")
        self.assertNotIn(b"\x1b", written)
        self.assertNotIn(b"\x07", written)
        self.assertEqual(written.count(b"\n"), 1)


class ShellFrontTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name
        self.state_path = os.path.join(self.root, "state", "tunnel_ports.json")
        self.keys_path = os.path.join(self.root, "keys", "tunnel_keys.json")
        self.store = KeyStore(self.keys_path)
        self.identity = "build-alpha"
        self.psk = os.urandom(32)
        self.store.register_build(self.identity, self.psk)
        self.public = self.store.static_public()
        # Generated per test: nothing here invents a fixture that could be
        # mistaken for a shipped default, because this port has none.
        self.password = os.urandom(16).hex()

        # Registered first so it runs last: every other cleanup -- stopping
        # the front, the endpoint and the server -- has to have happened
        # before the verdict on thread health is read.
        self.thread_errors = []
        self.log_records = []
        self.addCleanup(self._assert_nothing_broke_quietly)

        previous_hook = threading.excepthook
        threading.excepthook = self.thread_errors.append
        self.addCleanup(setattr, threading, "excepthook", previous_hook)

        handler = logging.Handler(level=logging.ERROR)
        handler.emit = self.log_records.append
        for name in ("raccoon.tunnel.shell", "raccoon.tunnel.server"):
            logger = logging.getLogger(name)
            logger.addHandler(handler)
            self.addCleanup(logger.removeHandler, handler)

    def _assert_nothing_broke_quietly(self):
        self.assertEqual(
            [getattr(args, "exc_value", args)
             for args in self.thread_errors], [],
            "a thread raised; the accept loop or a connection handler let "
            "an exception escape")
        self.assertEqual(
            [record.getMessage() for record in self.log_records], [],
            "something was logged at ERROR or above; an expected refusal is "
            "logged below that")

    # ── harness ──

    def start_server(self, **kwargs):
        options = {
            # Long enough that no test sees an unasked-for PING, and long
            # enough that a held session cannot age out mid-test.
            "keepalive_interval": 30.0,
            "idle_timeout": 60.0,
            "handshake_timeout": 10.0,
            "session_timeout": 30.0,
        }
        options.update(kwargs)
        server = TunnelServer(self.store, _LOOPBACK, 0, _PORT_RANGE,
                              self.state_path, **options)
        server.start()
        self.addCleanup(server.stop)
        return server

    def start_front(self, server, **kwargs):
        front = ShellFront(server, self.identity, 0, self.password, **kwargs)
        front.start()
        self.addCleanup(front.stop)
        return front

    def start_endpoint(self, server, handler=tagged_echo,
                       features=TUNNEL_FEATURES):
        endpoint = _StubEndpoint(_LOOPBACK, server.port, self.public,
                                 self.psk, self.identity, handler, features)
        self.addCleanup(endpoint.close)
        self.wait_for(lambda: any(row["state"] == "connected"
                                  for row in server.endpoints()))
        return endpoint

    def rig(self, handler=tagged_echo, with_endpoint=True,
            features=TUNNEL_FEATURES, **front_options):
        """A server, a front and an endpoint, with their teardown ordered.

        The cleanups are registered server, front, endpoint and therefore
        run endpoint, front, server: the endpoint goes first so that a
        session it is still reading from is never shut down under it,
        which would land in `_StubEndpoint.errors` as a failure of this
        file's own harness rather than of the code under test.
        """
        server = self.start_server()
        front = self.start_front(server, **front_options)
        endpoint = (self.start_endpoint(server, handler, features)
                    if with_endpoint else None)
        return server, front, endpoint

    def attach(self, front, line=None, timeout=20.0):
        """A client past the prompt, with `line` sent as its auth line."""
        client = _ShellClient(front.port, timeout=timeout)
        self.addCleanup(client.close)
        self.assertEqual(client.prompt(), PROMPT)
        client.send_line(self.password if line is None else line)
        return client

    def carried(self, front, probe=b"echo\n", line=None, cols=120, rows=40):
        """An attached client whose session is proven to be carrying bytes."""
        client = self.attach(front, line=line)
        client.send(probe)
        expected = b"%dx%d|%s" % (cols, rows, probe)
        self.assertEqual(client.exactly(len(expected)), expected)
        return client

    def wait_for(self, predicate, timeout=20.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return True
            time.sleep(0.01)
        self.fail("condition was still false after %.1fs" % timeout)

    def assert_endpoint_healthy(self, endpoint):
        self.assertEqual(endpoint.errors, [],
                         "the stub endpoint reported a protocol failure")

    def assert_one_line(self, text, *expected):
        """A refusal is one line of plain text an operator can read."""
        self.assertTrue(text.startswith(b"raccoon: "),
                        "a refusal must name this tool: %r" % (text,))
        self.assertTrue(text.endswith(b"\r\n"),
                        "a terminal in raw mode needs the carriage return: "
                        "%r" % (text,))
        self.assertEqual(text.count(b"\n"), 1,
                         "a refusal is one line, not several: %r" % (text,))
        for fragment in expected:
            self.assertIn(fragment, text)

    def refusal(self, client):
        """The refusal line this client was sent, once it has been closed."""
        text, closed = _drain(client.sock)
        self.assertTrue(closed, "a refused client was left connected")
        return text


class TestAttaching(ShellFrontTestCase):
    def test_the_prompt_is_written_before_anything_is_read(self):
        # The operator is looking at a terminal: a port that waited for a
        # line before saying anything would look like a hung connection.
        _, front, _ = self.rig(with_endpoint=False)
        client = _ShellClient(front.port, timeout=10.0)
        self.addCleanup(client.close)
        self.assertEqual(client.exactly(len(PROMPT)), PROMPT)
        self.assertEqual(PROMPT, b"password: ")

    def test_the_right_password_pairs_and_bytes_flow_both_ways(self):
        _, front, endpoint = self.rig()
        client = self.attach(front)

        client.send(b"id\n")
        expected = b"120x40|id\n"
        self.assertEqual(client.exactly(len(expected)), expected)
        self.assertEqual(endpoint.next_shell(), (120, 40))

        stats = front.stats()
        self.assertEqual(stats["identity"], self.identity)
        self.assertEqual(stats["port"], front.port)
        self.assertEqual(stats["accepted"], 1)
        self.assertEqual(stats["carried"], 1)
        self.assertEqual(stats["live"], 1)
        self.assertEqual(sum(stats["refused"].values()), 0)
        self.assert_endpoint_healthy(endpoint)

    def test_a_wrong_password_is_refused_and_counted_under_auth(self):
        _, front, _ = self.rig(with_endpoint=False)
        client = self.attach(front, line="not-the-password")

        text = self.refusal(client)
        self.assert_one_line(text, b"password")
        self.assertNotIn(self.password.encode("utf-8"), text,
                         "a refusal must not quote the password back")
        stats = front.stats()
        self.assertEqual(stats["refused"]["auth"], 1)
        self.assertEqual(stats["carried"], 0)
        self.assertEqual(stats["live"], 0)

    def test_an_empty_line_is_refused_and_counted_under_auth(self):
        # A bare newline is the client that pressed return at the prompt.
        # It is compared like any other answer rather than short-circuited,
        # so absent and wrong are the same refusal and take the same path.
        _, front, _ = self.rig(with_endpoint=False)
        client = self.attach(front, line="")

        self.assert_one_line(self.refusal(client), b"password")
        self.assertEqual(front.stats()["refused"]["auth"], 1)

    def test_a_password_with_a_space_in_it_is_accepted_over_the_wire(self):
        # The module-level test above proves the parse; this proves the
        # port built from it authenticates such a password end to end.
        server = self.start_server()
        spaced = "two words " + os.urandom(4).hex()
        front = ShellFront(server, self.identity, 0, spaced)
        front.start()
        self.addCleanup(front.stop)
        endpoint = self.start_endpoint(server)

        client = _ShellClient(front.port, timeout=20.0)
        self.addCleanup(client.close)
        self.assertEqual(client.prompt(), PROMPT)
        client.send_line("%s 90x30" % spaced)
        client.send(b"pwd\n")
        self.assertEqual(client.exactly(len(b"90x30|pwd\n")), b"90x30|pwd\n")
        self.assertEqual(front.stats()["carried"], 1)
        self.assert_endpoint_healthy(endpoint)

    def test_a_client_that_never_sends_a_line_is_dropped_on_the_deadline(self):
        # A per-`recv` timeout bounds nothing: a peer that sends one byte
        # just inside it holds its thread for as long as it likes. The
        # deadline is absolute and measured from the accept.
        _, front, _ = self.rig(with_endpoint=False, handshake_timeout=0.5)
        client = _ShellClient(front.port, timeout=10.0)
        self.addCleanup(client.close)
        self.assertEqual(client.prompt(), PROMPT)

        self.wait_for(lambda: front.stats()["refused"]["timeout"] == 1,
                      timeout=10.0)
        self.assert_one_line(self.refusal(client), b"password")
        stats = front.stats()
        self.assertEqual(stats["refused"]["auth"], 0)
        self.assertEqual(stats["pending"], 0)
        self.assertEqual(stats["live"], 0)

    def test_a_drip_fed_line_is_cut_off_at_the_same_deadline(self):
        _, front, _ = self.rig(with_endpoint=False, handshake_timeout=0.5)
        client = _ShellClient(front.port, timeout=10.0)
        self.addCleanup(client.close)
        self.assertEqual(client.prompt(), PROMPT)
        # The right password, one byte at a time. Every read lands far
        # inside a per-`recv` timeout of 0.5s, so only an absolute
        # deadline can stop this peer holding its thread.
        payload = (self.password + "\n").encode("utf-8")
        stop = threading.Event()

        def drip():
            for index in range(len(payload)):
                if stop.wait(0.15):
                    return
                try:
                    client.sock.sendall(payload[index:index + 1])
                except OSError:
                    return

        thread = threading.Thread(target=drip, name="drip", daemon=True)

        def unwind():
            stop.set()
            thread.join(timeout=5.0)

        self.addCleanup(unwind)
        thread.start()
        self.wait_for(lambda: front.stats()["refused"]["timeout"] == 1,
                      timeout=10.0)
        self.assertEqual(front.stats()["live"], 0)

    def test_a_line_longer_than_the_bound_is_refused(self):
        _, front, _ = self.rig(with_endpoint=False)
        client = _ShellClient(front.port, timeout=10.0)
        self.addCleanup(client.close)
        self.assertEqual(client.prompt(), PROMPT)
        # No newline at all: an unauthenticated peer must not be able to
        # make this port buffer whatever it feels like sending.
        client.send(b"A" * 8192)

        self.assert_one_line(self.refusal(client), b"password")
        self.assertEqual(front.stats()["refused"]["auth"], 1)

    def test_input_pipelined_behind_the_auth_line_is_not_lost(self):
        # An attach client is free to put the line and the first keystrokes
        # in one segment, and the bytes after the newline are already input
        # for the shell.
        _, front, endpoint = self.rig()
        client = _ShellClient(front.port, timeout=20.0)
        self.addCleanup(client.close)
        self.assertEqual(client.prompt(), PROMPT)
        client.send((self.password + "\n").encode("utf-8") + b"id\n")

        self.assertEqual(client.exactly(len(b"120x40|id\n")), b"120x40|id\n")
        self.assertEqual(front.stats()["bytes_out"], len(b"id\n"))
        self.assert_endpoint_healthy(endpoint)


class TestTheGeometry(ShellFrontTestCase):
    def test_the_geometry_reaches_open_shell_session(self):
        _, front, endpoint = self.rig()
        # Carried rather than merely attached: the stub tags its output
        # with the geometry it was asked for, so the echo is the geometry
        # arriving at the far end and not just a number in a message.
        self.carried(front, line="%s 200x50" % self.password,
                     cols=200, rows=50)
        self.assertEqual(endpoint.next_shell(), (200, 50))

        self.carried(front)
        self.assertEqual(endpoint.next_shell(),
                         (SHELL_DEFAULT_COLS, SHELL_DEFAULT_ROWS))
        self.assert_endpoint_healthy(endpoint)

    def test_absurd_geometry_is_clamped_before_it_is_asked_for(self):
        _, front, endpoint = self.rig()
        self.carried(front, line="%s 0x99999" % self.password,
                     cols=1, rows=SHELL_GEOMETRY_MAX)
        self.assertEqual(endpoint.next_shell(), (1, SHELL_GEOMETRY_MAX))
        self.assert_endpoint_healthy(endpoint)


class TestTwoOperators(ShellFrontTestCase):
    """Review Focus: two operators on one identity, with no crossed bytes."""

    def test_two_operators_on_one_identity_do_not_cross_streams(self):
        _, front, endpoint = self.rig()
        answers = queue.Queue()
        release = threading.Event()
        geometries = ((81, 24), (100, 30))

        def one(index, cols, rows):
            """One operator, attaching with a geometry no other one uses."""
            client = None
            try:
                client = _ShellClient(front.port, timeout=30.0)
                prompt = client.exactly(len(PROMPT))
                client.send_line("%s %dx%d" % (self.password, cols, rows))
                probe = b"whoami-%d\n" % index
                client.send(probe)
                expected = b"%dx%d|%s" % (cols, rows, probe)
                echo = client.exactly(len(expected))
                answers.put({"index": index, "prompt": prompt, "echo": echo,
                             "expected": expected})
                # Held open until both have answered, so the assertions
                # below run against two live sessions and not against two
                # that happened one after the other.
                release.wait(30.0)
            except Exception:
                answers.put({"index": index, "error": traceback.format_exc()})
            finally:
                if client is not None:
                    client.close()

        threads = [threading.Thread(target=one, args=(index, cols, rows),
                                    name="shell-client-%d" % index,
                                    daemon=True)
                   for index, (cols, rows) in enumerate(geometries)]

        def unwind():
            release.set()
            for thread in threads:
                thread.join(timeout=30.0)

        self.addCleanup(unwind)
        for thread in threads:
            thread.start()

        collected = {}
        for _ in range(len(geometries)):
            answer = answers.get(timeout=60.0)
            collected[answer["index"]] = answer

        broken = {index: answer["error"] for index, answer in
                  collected.items() if "error" in answer}
        if broken:
            first = sorted(broken)[0]
            self.fail("operator %d raised:\n%s" % (first, broken[first]))

        self.assertEqual(sorted(collected), [0, 1])
        for index in sorted(collected):
            answer = collected[index]
            self.assertEqual(answer["prompt"], PROMPT)
            self.assertEqual(
                answer["echo"], answer["expected"],
                "operator %d was answered with the other one's terminal"
                % index)

        stats = front.stats()
        self.assertEqual(stats["live"], 2,
                         "the two sessions did not overlap, so nothing about "
                         "crossed streams was proven")
        self.assertEqual(stats["carried"], 2)
        self.assertEqual(sum(stats["refused"].values()), 0)
        self.assert_endpoint_healthy(endpoint)

        release.set()
        for thread in threads:
            thread.join(timeout=30.0)
        self.wait_for(lambda: front.stats()["live"] == 0)


class TestWhatIsRefusedInText(ShellFrontTestCase):
    def test_beyond_max_sessions_the_client_is_refused_in_text(self):
        _, front, endpoint = self.rig(max_sessions=1)
        held = self.carried(front)
        self.assertEqual(front.stats()["live"], 1)

        over = self.attach(front)
        self.assert_one_line(self.refusal(over), b"1")
        stats = front.stats()
        self.assertEqual(stats["refused"]["capacity"], 1)
        self.assertEqual(stats["live"], 1)
        self.assertEqual(stats["max_sessions"], 1)

        # The slot is released, not leaked: closing one lets the next in.
        held.close()
        self.wait_for(lambda: front.stats()["live"] == 0)
        self.carried(front)
        self.assertEqual(front.stats()["refused"]["capacity"], 1)
        self.assert_endpoint_healthy(endpoint)

    def test_an_endpoint_without_the_feature_is_refused_in_text_and_counted(self):
        # A build that predates shell sessions sends no `features` at all.
        # Asking it for one would drop its command channel and every live
        # SOCKS pivot on it, so the tunnel server refuses without sending
        # anything and this port tells the operator why.
        server, front, endpoint = self.rig(features=None)
        client = self.attach(front)

        text = self.refusal(client)
        self.assert_one_line(text, b"shell", b"feature")
        stats = front.stats()
        self.assertEqual(stats["refused"]["unsupported"], 1)
        self.assertEqual(stats["refused"]["tunnel"], 0)
        self.assertEqual(stats["carried"], 0)
        # And the refusal cost the endpoint nothing: it is still connected.
        self.assertEqual([row["state"] for row in server.endpoints()],
                         ["connected"])
        self.assert_endpoint_healthy(endpoint)

    def test_no_endpoint_connected_is_refused_in_text_under_tunnel(self):
        _, front, _ = self.rig(with_endpoint=False)
        client = self.attach(front)

        self.assert_one_line(self.refusal(client), self.identity.encode())
        stats = front.stats()
        self.assertEqual(stats["refused"]["tunnel"], 1)
        self.assertEqual(stats["refused"]["unsupported"], 0)

    def test_too_many_handshakes_in_flight_are_refused_and_counted(self):
        _, front, _ = self.rig(with_endpoint=False, max_pending=1,
                               handshake_timeout=10.0)
        # One client that reads the prompt and says nothing holds the only
        # slot.
        silent = _ShellClient(front.port, timeout=10.0)
        self.addCleanup(silent.close)
        self.assertEqual(silent.prompt(), PROMPT)
        self.wait_for(lambda: front.stats()["pending"] == 1)

        crowded = _ShellClient(front.port, timeout=10.0)
        self.addCleanup(crowded.close)
        text, closed = _drain(crowded.sock)
        # Nothing was read from this peer, but a line of text is still
        # readable at the far end -- unlike SOCKS, this port's refusals
        # need no protocol state to be meaningful.
        self.assert_one_line(text, b"1")
        self.assertTrue(closed, "a connection past the cap was left open")
        stats = front.stats()
        self.assertEqual(stats["refused"]["pending"], 1)
        self.assertEqual(stats["refused"]["capacity"], 0)
        self.assertEqual(stats["max_pending"], 1)
        self.assertEqual(stats["accepted"], 2)

        # Authenticating releases the slot: a flood of silent peers must
        # not crowd out the operator, whose connection stops counting
        # against this cap the moment it proves who it is.
        silent.send_line(self.password)
        self.wait_for(lambda: front.stats()["pending"] == 0)
        self.assertEqual(front.stats()["refused"]["pending"], 1)

    def test_a_connection_is_refused_and_counted_when_no_thread_can_start(self):
        server = self.start_server()
        front = _NoThreads(server, self.identity, 0, self.password)
        front.start()
        self.addCleanup(front.stop)

        with self.assertLogs("raccoon.tunnel.shell", level="WARNING") as caught:
            client = _ShellClient(front.port, timeout=10.0)
            self.addCleanup(client.close)
            text, closed = _drain(client.sock)
        self.assert_one_line(text, b"thread")
        self.assertTrue(closed)
        self.assertTrue(any("thread" in line for line in caught.output))

        stats = front.stats()
        self.assertEqual(stats["refused"]["threads"], 1)
        # Its own key: the two caps are this port's policy and this is the
        # host having run out, which is a different thing to tune.
        self.assertEqual(stats["refused"]["capacity"], 0)
        self.assertEqual(stats["refused"]["pending"], 0)
        self.assertEqual(stats["pending"], 0)

        # And the accept loop survived it, rather than dying and leaving
        # the port open but mute.
        second = _ShellClient(front.port, timeout=10.0)
        self.addCleanup(second.close)
        self.assertTrue(_drain(second.sock)[1])
        self.wait_for(lambda: front.stats()["refused"]["threads"] == 2)


class TestTheListener(ShellFrontTestCase):
    def test_a_non_loopback_bind_is_refused(self):
        server = self.start_server()
        for host in ("0.0.0.0", "10.0.0.1", "::", "192.168.1.7"):
            with self.assertRaises(ValueError) as caught:
                ShellFront(server, self.identity, 0, self.password,
                           bind_host=host)
            self.assertIn(host, str(caught.exception))
        # A name resolves through a resolver this process does not own, so
        # "localhost" is not proof of loopback at bind time.
        with self.assertRaises(ValueError):
            ShellFront(server, self.identity, 0, self.password,
                       bind_host="localhost")

    def test_loopback_v4_and_v6_are_both_accepted(self):
        server = self.start_server()
        for host in (_LOOPBACK, "::1"):
            front = ShellFront(server, self.identity, 0, self.password,
                               bind_host=host)
            front.start()
            self.addCleanup(front.stop)
            self.assertTrue(front.stats()["serving"])
            self.assertGreater(front.port, 0)

    def test_there_is_no_password_this_port_will_do_without(self):
        server = self.start_server()
        for bad in ("", None, 0):
            with self.assertRaises(ValueError):
                ShellFront(server, self.identity, 0, bad)

    def test_the_default_cap_is_four_sessions(self):
        # The endpoint holds four shell sessions at once, so a fifth this
        # port admitted could only be refused at the far end.
        self.assertEqual(DEFAULT_MAX_SESSIONS, 4)
        _, front, _ = self.rig(with_endpoint=False)
        stats = front.stats()
        self.assertEqual(stats["max_sessions"], 4)
        self.assertEqual(stats["max_pending"], 4)

    def test_stop_is_safe_before_start_and_twice(self):
        server = self.start_server()
        front = ShellFront(server, self.identity, 0, self.password)
        self.assertFalse(front.stats()["serving"])
        self.assertIsNone(front.stats()["port"])
        front.stop()
        front.start()
        self.addCleanup(front.stop)
        port = front.port
        front.stop()
        front.stop()
        self.assertFalse(front.stats()["serving"])
        # The port it was serving on stays in `stats`, because an operator
        # reading a stopped row wants to know which port went away.
        self.assertEqual(front.stats()["port"], port)
        self.assertRaises(OSError, socket.create_connection,
                          (_LOOPBACK, port), 1.0)

    def test_starting_twice_is_an_error(self):
        _, front, _ = self.rig(with_endpoint=False)
        self.assertRaises(RuntimeError, front.start)

    def test_stop_drops_a_live_session(self):
        _, front, endpoint = self.rig()
        client = self.carried(front)
        self.assertEqual(front.stats()["live"], 1)

        # `stop` while the endpoint is still connected and the session is
        # still live, so that what ends it is this call and nothing else.
        front.stop()
        self.assertEqual(front.stats()["live"], 0)
        self.assertFalse(front.stats()["serving"])
        self.assertTrue(_drain(client.sock)[1],
                        "a session outlived the port it arrived on")
        self.assert_endpoint_healthy(endpoint)

    def test_an_idle_session_outlives_the_handshake_timeout(self):
        # The auth line has a deadline so that a client which connects and
        # says nothing cannot hold a thread. A session must not inherit it:
        # a shell waiting at a prompt is idle for minutes at a time.
        _, front, endpoint = self.rig(handshake_timeout=0.4)
        client = self.carried(front)

        time.sleep(1.2)                       # three handshake deadlines
        self.assertEqual(front.stats()["live"], 1)
        client.send(b"date\n")
        self.assertEqual(client.exactly(len(b"120x40|date\n")),
                         b"120x40|date\n")
        self.assertEqual(front.stats()["refused"]["timeout"], 0)
        self.assert_endpoint_healthy(endpoint)


class TestWhatTheOperatorPanelReads(ShellFrontTestCase):
    def test_stats_counts_bytes_both_ways(self):
        _, front, endpoint = self.rig()
        client = self.attach(front)
        client.send(b"ls -la\n")
        expected = b"120x40|ls -la\n"
        self.assertEqual(client.exactly(len(expected)), expected)

        stats = front.stats()
        # Out is toward the implant's terminal and in is back from it,
        # both plaintext and both for the life of this object.
        self.assertEqual(stats["bytes_out"], len(b"ls -la\n"))
        self.assertEqual(stats["bytes_in"], len(expected))
        self.assertEqual(stats["accepted"], 1)
        self.assertEqual(stats["carried"], 1)
        self.assertEqual(stats["live"], 1)
        self.assert_endpoint_healthy(endpoint)

    def test_the_refusal_counters_are_one_dictionary_per_kind(self):
        # `max_pending` is set apart from `max_sessions` here: with one of
        # each, a client still at the prompt would make the next arrival a
        # `pending` refusal rather than the one being provoked, and these
        # three are sequenced on their own counter so the order is the
        # test's and not the scheduler's.
        _, front, _ = self.rig(with_endpoint=False, max_sessions=1,
                               max_pending=4)
        self.assertEqual(
            sorted(front.stats()["refused"]),
            ["auth", "capacity", "pending", "threads", "timeout", "tunnel",
             "unsupported"])
        self.assertEqual(sum(front.stats()["refused"].values()), 0)

        self.attach(front, line="wrong")
        self.wait_for(lambda: front.stats()["refused"]["auth"] == 1)
        self.attach(front, line="")
        self.wait_for(lambda: front.stats()["refused"]["auth"] == 2)
        self.attach(front)                      # no endpoint: tunnel
        self.wait_for(lambda: front.stats()["refused"]["tunnel"] == 1)

        refused = front.stats()["refused"]
        self.assertEqual(refused["auth"], 2)
        self.assertEqual(refused["tunnel"], 1)
        self.assertEqual(refused["capacity"], 0)
        self.assertEqual(refused["unsupported"], 0)
        self.assertEqual(refused["timeout"], 0)
        self.assertEqual(refused["pending"], 0)
        self.assertEqual(refused["threads"], 0)
        self.assertEqual(front.stats()["accepted"], 3)
        self.assertEqual(front.stats()["carried"], 0)

    def test_a_transcripts_object_is_accepted_and_otherwise_untouched(self):
        # Task 6 fills this parameter in. Until then it is stored and
        # nothing is asked of it, which is what this asserts: a session
        # carries bytes with an object that would raise on any call.
        class Explodes(object):
            def __getattr__(self, name):
                raise AssertionError("nothing may be asked of transcripts "
                                     "yet, and %r was" % name)

        _, front, endpoint = self.rig(transcripts=Explodes())
        self.carried(front)
        self.assertEqual(front.stats()["carried"], 1)
        self.assert_endpoint_healthy(endpoint)


if __name__ == "__main__":
    unittest.main()
