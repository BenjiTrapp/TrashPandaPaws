#!/usr/bin/env python3
"""
Unit tests for the operator-facing shell port: one authenticated loopback
port per build identity, which pairs a connection with a terminal session
on the endpoint.

Six things these tests are careful about.

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

**A transcript is read back off the disk.** Every assertion about a
recording opens the file the port wrote and looks at its bytes, its mode
and its sidecar, rather than at a recorder that was handed in: what is
being checked is that an operator who comes back to this directory after
the engagement finds the session in it, and that the attach password is
not in it. The one exception is the ceiling, whose 16 MiB is passed in
smaller rather than pushed through a session.

**No thread may die quietly.** `setUp` installs a `threading.excepthook`
and a handler on both tunnel loggers, and the last cleanup to run asserts
that no thread raised and that nothing was logged at ERROR or above. A
port that survives a hostile client by crashing a worker would otherwise
pass every assertion in this file.
"""

import json
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
from software.c2.tunnel.socks import SocksFront
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


def quiet_terminal(shell, cols, rows):
    """A terminal that prints one line of its own and never echoes.

    `tagged_echo` cannot tell a transcript's two directions apart, because
    everything it prints is the input coming back. This one prints
    something the operator never typed and swallows everything they did.
    """
    shell.send(SHOWN_BY_THE_TERMINAL)
    while True:
        if not shell.receive():
            return


# What `quiet_terminal` prints, and what it is answering: a transcript
# holds the first and not the second.
SHOWN_BY_THE_TERMINAL = b"shown-by-the-terminal\r\n"
TYPED_BY_THE_OPERATOR = b"typed-by-the-operator\n"


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
    """A front whose threads stop being startable after `allowed` of them.

    `_start` is the seam `SocksFront` keeps for exactly this, and this
    module inherits it. The branches under test are a process with no
    threads left, and exhausting this machine's thread table to reach them
    would be neither quick nor kind to the rest of the suite.

    The count is what makes the *second* branch reachable: with
    `allowed=1` the connection's own thread starts and the output
    direction of its session is the one that cannot, which is a live
    session that has to be refused in text rather than dropped.
    """

    allowed = 0

    def __init__(self, *args, **kwargs):
        ShellFront.__init__(self, *args, **kwargs)
        self._started = 0
        self._start_lock = threading.Lock()

    def _start(self, thread):
        with self._start_lock:
            self._started += 1
            spent = self._started > self.allowed
        if spent:
            raise RuntimeError("can't start new thread")
        thread.start()


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
        self.assertEqual(stats["sessions"], 1)
        self.assertEqual(stats["refused"], 0)
        self.assert_endpoint_healthy(endpoint)

    def test_a_wrong_password_is_refused_and_counted_under_auth(self):
        _, front, _ = self.rig(with_endpoint=False)
        client = self.attach(front, line="not-the-password")

        text = self.refusal(client)
        self.assert_one_line(text, b"password")
        self.assertNotIn(self.password.encode("utf-8"), text,
                         "a refusal must not quote the password back")
        stats = front.stats()
        self.assertEqual(stats["refused_auth"], 1)
        self.assertEqual(stats["carried"], 0)
        self.assertEqual(stats["sessions"], 0)

    def test_an_empty_line_is_refused_and_counted_under_auth(self):
        # A bare newline is the client that pressed return at the prompt.
        # It is compared like any other answer rather than short-circuited,
        # so absent and wrong are the same refusal and take the same path.
        _, front, _ = self.rig(with_endpoint=False)
        client = self.attach(front, line="")

        self.assert_one_line(self.refusal(client), b"password")
        self.assertEqual(front.stats()["refused_auth"], 1)

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

        self.wait_for(lambda: front.stats()["refused_timeout"] == 1,
                      timeout=10.0)
        self.assert_one_line(self.refusal(client), b"password")
        stats = front.stats()
        self.assertEqual(stats["refused_auth"], 0)
        self.assertEqual(stats["pending"], 0)
        self.assertEqual(stats["sessions"], 0)

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
        self.wait_for(lambda: front.stats()["refused_timeout"] == 1,
                      timeout=10.0)
        self.assertEqual(front.stats()["sessions"], 0)

    def test_a_line_longer_than_the_bound_is_refused(self):
        _, front, _ = self.rig(with_endpoint=False)
        client = _ShellClient(front.port, timeout=10.0)
        self.addCleanup(client.close)
        self.assertEqual(client.prompt(), PROMPT)
        # No newline at all: an unauthenticated peer must not be able to
        # make this port buffer whatever it feels like sending.
        client.send(b"A" * 8192)

        self.assert_one_line(self.refusal(client), b"password")
        self.assertEqual(front.stats()["refused_auth"], 1)

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
        self.assertEqual(stats["sessions"], 2,
                         "the two sessions did not overlap, so nothing about "
                         "crossed streams was proven")
        self.assertEqual(stats["carried"], 2)
        self.assertEqual(stats["refused"], 0)
        self.assert_endpoint_healthy(endpoint)

        release.set()
        for thread in threads:
            thread.join(timeout=30.0)
        self.wait_for(lambda: front.stats()["sessions"] == 0)


class TestWhatIsRefusedInText(ShellFrontTestCase):
    def test_beyond_max_sessions_the_client_is_refused_in_text(self):
        _, front, endpoint = self.rig(max_sessions=1)
        held = self.carried(front)
        self.assertEqual(front.stats()["sessions"], 1)

        over = self.attach(front)
        self.assert_one_line(self.refusal(over), b"1")
        stats = front.stats()
        self.assertEqual(stats["refused_capacity"], 1)
        self.assertEqual(stats["sessions"], 1)
        self.assertEqual(stats["max_sessions"], 1)

        # The slot is released, not leaked: closing one lets the next in.
        held.close()
        self.wait_for(lambda: front.stats()["sessions"] == 0)
        self.carried(front)
        self.assertEqual(front.stats()["refused_capacity"], 1)
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
        self.assertEqual(stats["refused_unsupported"], 1)
        self.assertEqual(stats["refused_tunnel"], 0)
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
        self.assertEqual(stats["refused_tunnel"], 1)
        self.assertEqual(stats["refused_unsupported"], 0)

    def test_an_identity_that_reads_like_the_reason_is_still_a_tunnel(self):
        # The two are told apart by a discriminator the tunnel server sets
        # on the one refusal that means "this build cannot do it", not by a
        # word in the text. An identity is an operator-chosen string, so
        # one containing "feature" used to turn every *not connected yet*
        # refusal into "replace the build" when the answer was "wait for it
        # to call home".
        server = self.start_server()
        front = ShellFront(server, "feature-flag-build", 0, self.password)
        front.start()
        self.addCleanup(front.stop)
        client = self.attach(front)

        text = self.refusal(client)
        self.assert_one_line(text, b"feature-flag-build")
        stats = front.stats()
        self.assertEqual(stats["refused_tunnel"], 1)
        self.assertEqual(stats["refused_unsupported"], 0)

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
        self.assertEqual(stats["refused_pending"], 1)
        self.assertEqual(stats["refused_capacity"], 0)
        self.assertEqual(stats["max_pending"], 1)
        self.assertEqual(stats["accepted"], 2)

        # Authenticating releases the slot: a flood of silent peers must
        # not crowd out the operator, whose connection stops counting
        # against this cap the moment it proves who it is.
        silent.send_line(self.password)
        self.wait_for(lambda: front.stats()["pending"] == 0)
        self.assertEqual(front.stats()["refused_pending"], 1)

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
        self.assertEqual(stats["refused_threads"], 1)
        # Its own key: the two caps are this port's policy and this is the
        # host having run out, which is a different thing to tune.
        self.assertEqual(stats["refused_capacity"], 0)
        self.assertEqual(stats["refused_pending"], 0)
        self.assertEqual(stats["pending"], 0)

        # And the accept loop survived it, rather than dying and leaving
        # the port open but mute.
        second = _ShellClient(front.port, timeout=10.0)
        self.addCleanup(second.close)
        self.assertTrue(_drain(second.sock)[1])
        self.wait_for(lambda: front.stats()["refused_threads"] == 2)

    def test_a_session_whose_output_direction_cannot_start_is_told_so(self):
        # The connection's own thread starts; the session's *output*
        # direction is the one with no thread. A one-way terminal is worse
        # than none, so the session ends -- but in text and counted, like
        # every other refusal on this port, and not as a carried session
        # that closed for no stated reason.
        server = self.start_server()
        front = _NoThreads(server, self.identity, 0, self.password)
        front.allowed = 1
        front.start()
        self.addCleanup(front.stop)
        endpoint = self.start_endpoint(server)

        with self.assertLogs("raccoon.tunnel.shell", level="WARNING") as caught:
            client = self.attach(front)
            text, closed = _drain(client.sock)
        self.assert_one_line(text, b"thread", b"output")
        self.assertTrue(closed, "the session was left half-open")
        self.assertTrue(any("output direction" in line
                            for line in caught.output), caught.output)

        stats = front.stats()
        self.assertEqual(stats["refused_threads"], 1)
        self.assertEqual(stats["refused"], 1)
        # Not counted as carried: the session never ran in both
        # directions, and a panel row showing one carried session and no
        # refusal is the ambiguity this port exists not to produce.
        self.assertEqual(stats["carried"], 0)
        self.assertEqual(stats["sessions"], 0)
        self.assert_endpoint_healthy(endpoint)


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
        # And the handshakes in flight are *not* capped at four with it:
        # four silent sockets would then be able to turn the operator's own
        # attach away for a whole handshake timeout.
        self.assertGreater(stats["max_pending"], stats["max_sessions"])
        self.assertEqual(stats["max_pending"], 8)
        # A front that carries more than the floor keeps its own number.
        many = ShellFront(self.start_server(), self.identity, 0,
                          self.password, max_sessions=20)
        self.assertEqual(many.stats()["max_pending"], 20)

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
        self.assertEqual(front.stats()["sessions"], 1)

        # `stop` while the endpoint is still connected and the session is
        # still live, so that what ends it is this call and nothing else.
        front.stop()
        self.assertEqual(front.stats()["sessions"], 0)
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
        self.assertEqual(front.stats()["sessions"], 1)
        client.send(b"date\n")
        self.assertEqual(client.exactly(len(b"120x40|date\n")),
                         b"120x40|date\n")
        self.assertEqual(front.stats()["refused_timeout"], 0)
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
        self.assertEqual(stats["sessions"], 1)
        self.assert_endpoint_healthy(endpoint)

    def test_the_refusal_counters_are_the_socks_rows_own_shape(self):
        # The panel reads both rows generically: `refused` is the total and
        # the kinds are discovered by their `refused_` prefix. A shell row
        # that spelled either differently would need a rendering of its
        # own, so the shape is asserted here rather than left to Task 9 to
        # find out.
        #
        # `max_pending` is set apart from `max_sessions` as well: with one
        # of each, a client still at the prompt would make the next arrival
        # a `pending` refusal rather than the one being provoked, and the
        # three below are sequenced on their own counters so the order is
        # this test's and not the scheduler's.
        _, front, _ = self.rig(with_endpoint=False, max_sessions=1,
                               max_pending=4)
        stats = front.stats()
        self.assertEqual(
            sorted(key[len("refused_"):] for key in stats
                   if key.startswith("refused_")),
            ["auth", "capacity", "pending", "threads", "timeout", "tunnel",
             "unsupported"])
        self.assertIsInstance(stats["refused"], int)
        self.assertEqual(stats["refused"], 0)
        # And outside its own refusal kinds, the row is the SOCKS row's: the
        # two ports sit side by side on the panel and are read by the same
        # code.
        socks = SocksFront(self.start_server(), self.identity, 0, "operator",
                           self.password).stats()
        self.assertEqual(
            sorted(key for key in socks if not key.startswith("refused_")),
            sorted(key for key in stats if not key.startswith("refused_")))

        self.attach(front, line="wrong")
        self.wait_for(lambda: front.stats()["refused_auth"] == 1)
        self.attach(front, line="")
        self.wait_for(lambda: front.stats()["refused_auth"] == 2)
        self.attach(front)                      # no endpoint: tunnel
        self.wait_for(lambda: front.stats()["refused_tunnel"] == 1)

        stats = front.stats()
        self.assertEqual(stats["refused_auth"], 2)
        self.assertEqual(stats["refused_tunnel"], 1)
        self.assertEqual(stats["refused_capacity"], 0)
        self.assertEqual(stats["refused_unsupported"], 0)
        self.assertEqual(stats["refused_timeout"], 0)
        self.assertEqual(stats["refused_pending"], 0)
        self.assertEqual(stats["refused_threads"], 0)
        self.assertEqual(stats["refused"], 3)
        self.assertEqual(front.stats()["accepted"], 3)
        self.assertEqual(front.stats()["carried"], 0)

    def test_a_transcripts_object_is_what_the_recording_switch_passes(self):
        # The parameter is a `Transcripts`; `TestTranscripts` below covers
        # what it then writes. Here it is only that an off one -- which is
        # what a deployment with no configured directory has -- changes
        # nothing about a session.
        _, front, endpoint = self.rig(transcripts=shell_mod.Transcripts(None))
        self.carried(front)
        self.assertEqual(front.stats()["carried"], 1)
        self.assert_endpoint_healthy(endpoint)


class _BrokenWrites(shell_mod.Transcripts):
    """Transcripts whose recorder loses its file the instant it is opened.

    A real file object raising a real `ValueError` on the first write,
    which is what a revoked descriptor looks like from here and is the
    nearest a test gets to a full disk. The point is that the session must
    not notice.
    """

    def open(self, identity, session, peer):
        recorder = shell_mod.Transcripts.open(self, identity, session, peer)
        if recorder is not None:
            recorder._handle.close()
        return recorder


class TestTranscripts(ShellFrontTestCase):
    """Review Focus: recording is off unless a directory is configured, and
    a recording that fails costs the recording and never the session.
    """

    # ── harness ──

    def recording(self, **kwargs):
        """A `Transcripts` under a directory that does not exist yet.

        Two levels deep on purpose: `os.makedirs(mode=0o700)` applies the
        mode to the leaf alone, so a parent left at the process umask
        would be a listable directory holding 0600 files.
        """
        directory = os.path.join(self.root, "recordings", "shell")
        return shell_mod.Transcripts(directory, **kwargs), directory

    def tree(self):
        """Every path under the test's root, for a before-and-after."""
        found = []
        for base, directories, files in os.walk(self.root):
            for name in list(directories) + list(files):
                found.append(os.path.relpath(os.path.join(base, name),
                                             self.root))
        return sorted(found)

    def mode(self, path):
        return os.stat(path).st_mode & 0o777

    def folder(self, directory):
        return os.path.join(directory, self.identity)

    def written(self, directory, count=2):
        """The one session's files under `directory`, as paths.

        `count` is how many are expected, so a missing sidecar is a named
        failure rather than an `IndexError` three lines later.
        """
        folder = self.folder(directory)
        self.assertTrue(os.path.isdir(folder),
                        "no directory was made for %r" % self.identity)
        names = sorted(os.listdir(folder))
        self.assertEqual(len(names), count,
                         "expected %d file(s) under %s, found %r"
                         % (count, folder, names))
        return [os.path.join(folder, name) for name in names]

    def ended(self, front, client):
        """Close a client and wait until its session is finished.

        A session's slot is given back after the output direction has been
        joined, and the recorder is closed by that direction's own
        teardown -- so a port reporting no live session has written the
        sidecar already, and nothing here has to poll for the file.
        """
        client.close()
        self.wait_for(lambda: front.stats()["sessions"] == 0)

    def degradations(self):
        """This port's warnings, which is where a degradation says why.

        Every failure to record is logged once with its reason, so every
        test below that provokes one reads it back rather than trusting
        that it happened.
        """
        return self.assertLogs("raccoon.tunnel.shell", level="WARNING")

    # ── off unless switched on ──

    def test_no_directory_records_nothing(self):
        off = shell_mod.Transcripts(None)
        self.assertFalse(off.enabled)
        self.assertIsNone(off.open(self.identity, 1, "127.0.0.1:1"))
        # An empty string is the same answer: a configuration key that is
        # present and blank is not a directory.
        self.assertFalse(shell_mod.Transcripts("").enabled)
        self.assertTrue(self.recording()[0].enabled)

        for transcripts in (None, off):
            _, front, endpoint = self.rig(transcripts=transcripts)
            before = self.tree()
            self.carried(front)
            self.assertEqual(front.stats()["carried"], 1)
            # No directory created, nothing written: off means off.
            self.assertEqual(self.tree(), before)
            self.assert_endpoint_healthy(endpoint)

    # ── what a recording is ──

    def test_a_session_writes_a_typescript_and_a_sidecar(self):
        transcripts, directory = self.recording()
        _, front, endpoint = self.rig(transcripts=transcripts)
        client = self.carried(front)
        self.ended(front, client)

        path, sidecar = self.written(directory)
        name = os.path.basename(path)
        self.assertRegex(name, r"\A\d{8}T\d{6}Z-1\.typescript\Z")
        self.assertEqual(os.path.basename(sidecar), name + ".json")
        with open(path, "rb") as handle:
            content = handle.read()
        # Byte for byte what the terminal showed, which here is the stub's
        # tag and the probe `carried` sent.
        self.assertEqual(content, b"120x40|echo\n")

        with open(sidecar, "rb") as handle:
            facts = json.loads(handle.read().decode("utf-8"))
        self.assertEqual(sorted(facts),
                         ["bytes", "ended", "identity", "peer", "reason",
                          "session", "started", "truncated"])
        self.assertEqual(facts["identity"], self.identity)
        self.assertEqual(facts["session"], 1)
        self.assertTrue(facts["peer"].startswith(_LOOPBACK + ":"),
                        "the sidecar must say which operator attached: %r"
                        % (facts["peer"],))
        self.assertFalse(facts["truncated"])
        self.assertEqual(facts["bytes"], len(content))
        self.assertEqual(facts["bytes"], os.path.getsize(path))
        self.assertIsInstance(facts["reason"], str)
        self.assertTrue(facts["reason"], "a closed transcript says why")
        for when in (facts["started"], facts["ended"]):
            self.assertRegex(when, r"\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z")

        # The next session is the next number, so two recordings in the
        # same second are still two files.
        self.ended(front, self.carried(front))
        second = self.written(directory, count=4)
        self.assertRegex(os.path.basename(second[2]),
                         r"\A\d{8}T\d{6}Z-2\.typescript\Z")
        self.assert_endpoint_healthy(endpoint)

    def test_the_typescript_is_0600_in_a_0700_directory(self):
        # A transcript is evidence and a secret at the same time:
        # credentials typed inside a session are in it.
        transcripts, directory = self.recording()
        _, front, endpoint = self.rig(transcripts=transcripts)
        self.ended(front, self.carried(front))

        for path in self.written(directory):
            self.assertEqual(self.mode(path), 0o600, path)
        self.assertEqual(self.mode(self.folder(directory)), 0o700)
        # Both levels this module made, not just the leaf.
        self.assertEqual(self.mode(directory), 0o700)
        self.assertEqual(self.mode(os.path.dirname(directory)), 0o700)
        self.assert_endpoint_healthy(endpoint)

    def test_the_attach_password_is_in_neither_file(self):
        # Recording opens at the pairing, which is after the password line
        # has been read and compared, and it records the output direction
        # only. Both halves of that are load-bearing here.
        transcripts, directory = self.recording()
        _, front, endpoint = self.rig(transcripts=transcripts)
        client = self.attach(front)
        typed = b"secret-typed-inside-the-session\n"
        client.send(typed)
        echo = b"120x40|" + typed
        self.assertEqual(client.exactly(len(echo)), echo)
        self.ended(front, client)

        password = self.password.encode("utf-8")
        for path in self.written(directory):
            with open(path, "rb") as handle:
                content = handle.read()
            self.assertNotIn(password, content,
                             "the attach password reached %s" % path)
        with open(self.written(directory)[0], "rb") as handle:
            content = handle.read()
        # And the file is a real recording rather than an empty one that
        # would pass every assertion above: what the operator typed is in
        # it, because the terminal echoed it.
        self.assertEqual(content, echo)

    def test_only_the_output_direction_is_recorded(self):
        transcripts, directory = self.recording()
        _, front, endpoint = self.rig(handler=quiet_terminal,
                                      transcripts=transcripts)
        client = self.attach(front)
        self.assertEqual(client.exactly(len(SHOWN_BY_THE_TERMINAL)),
                         SHOWN_BY_THE_TERMINAL)
        client.send(TYPED_BY_THE_OPERATOR)
        self.wait_for(lambda: front.stats()["bytes_out"]
                      == len(TYPED_BY_THE_OPERATOR))
        self.ended(front, client)

        path, sidecar = self.written(directory)
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), SHOWN_BY_THE_TERMINAL)
        # Nor in the sidecar, which is read by whoever reads the
        # transcript and holds no session bytes at all.
        with open(sidecar, "rb") as handle:
            self.assertNotIn(TYPED_BY_THE_OPERATOR.strip(), handle.read())
        self.assert_endpoint_healthy(endpoint)

    def test_the_sidecar_is_written_when_the_session_ends(self):
        transcripts, directory = self.recording()
        _, front, endpoint = self.rig(transcripts=transcripts)
        client = self.carried(front)

        # While the session is live there is a typescript and no sidecar,
        # and the bytes are already on the disk rather than in a buffer
        # that would die with the process.
        path = self.written(directory, count=1)[0]
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), b"120x40|echo\n")
        self.assertFalse(os.path.exists(path + ".json"))

        self.ended(front, client)
        self.assertTrue(os.path.exists(path + ".json"))
        with open(path + ".json", "rb") as handle:
            facts = json.loads(handle.read().decode("utf-8"))
        self.assertEqual(facts["bytes"], len(b"120x40|echo\n"))
        self.assertFalse(facts["truncated"])
        self.assertTrue(facts["ended"])
        self.assert_endpoint_healthy(endpoint)

    def test_a_recorder_closed_with_a_reason_puts_it_in_the_sidecar(self):
        # Called directly, because which of the four ways a session can
        # end a test sees is the scheduler's business, and the field is
        # not: a sidecar an operator reads has to say why it stops.
        transcripts, _ = self.recording()
        recorder = transcripts.open(self.identity, 3, "127.0.0.1:9000")
        self.assertFalse(recorder.truncated)
        recorder.write(b"two words\n")
        recorder.close("the operator's connection ended")

        with open(recorder.path + ".json", "rb") as handle:
            facts = json.loads(handle.read().decode("utf-8"))
        self.assertEqual(facts["reason"], "the operator's connection ended")
        self.assertEqual(facts["session"], 3)
        self.assertEqual(facts["peer"], "127.0.0.1:9000")
        self.assertEqual(facts["bytes"], len(b"two words\n"))
        self.assertFalse(facts["truncated"])

        # Closing is where the session's teardown ends up, so it is
        # idempotent, and a write after it writes nothing.
        recorder.close("something else entirely")
        recorder.write(b"late")
        with open(recorder.path + ".json", "rb") as handle:
            self.assertEqual(
                json.loads(handle.read().decode("utf-8"))["reason"],
                "the operator's connection ended")
        self.assertEqual(os.path.getsize(recorder.path), len(b"two words\n"))

    def test_an_identity_that_is_not_a_filename_still_gets_one_directory(self):
        # An identity is an operator-chosen string, and this is the only
        # place one becomes a path.
        transcripts, directory = self.recording()
        recorder = transcripts.open("../../etc/raccoon", 7, "127.0.0.1:1")
        self.addCleanup(recorder.close, "the test ended")
        self.assertTrue(
            os.path.realpath(recorder.path).startswith(
                os.path.realpath(directory) + os.sep),
            "%r escaped %r" % (recorder.path, directory))
        self.assertTrue(os.path.basename(recorder.path)
                        .endswith("-7.typescript"), recorder.path)

    # ── a recording problem is never the session's problem ──

    def test_the_ceiling_stops_recording_and_records_that_it_did(self):
        # Review Focus. The shipped ceiling is 16 MiB; this one is 16
        # bytes, so that what is tested is the behaviour and not the
        # patience of whoever runs the suite.
        self.assertEqual(shell_mod.TRANSCRIPT_MAX_BYTES, 16 * 1024 * 1024)
        transcripts, directory = self.recording(max_bytes=16)
        _, front, endpoint = self.rig(transcripts=transcripts)
        client = self.attach(front)

        with self.degradations() as caught:
            first = b"0123456789abcdef\n"           # 7 + 17 bytes of output
            client.send(first)
            self.assertEqual(client.exactly(len(b"120x40|") + len(first)),
                             b"120x40|" + first)
            # Past the ceiling the session is untouched: it carries on
            # printing to the operator's terminal.
            client.send(b"more\n")
            self.assertEqual(client.exactly(len(b"120x40|more\n")),
                             b"120x40|more\n")
        hit = [record.getMessage() for record in caught.records
               if "ceiling" in record.getMessage()]
        self.assertEqual(len(hit), 1,
                         "the ceiling is logged once and not per write: %r"
                         % (hit,))

        path = self.written(directory, count=1)[0]
        self.assertIn(path, hit[0])
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), b"120x40|012345678")
        self.ended(front, client)

        with open(path + ".json", "rb") as handle:
            facts = json.loads(handle.read().decode("utf-8"))
        self.assertTrue(facts["truncated"],
                        "a reader of a short transcript has to be told")
        self.assertEqual(facts["bytes"], 16)
        self.assertEqual(facts["bytes"], os.path.getsize(path))
        # And the session itself was carried in full, both ways.
        stats = front.stats()
        self.assertEqual(stats["carried"], 1)
        self.assertEqual(stats["bytes_out"], len(first) + len(b"more\n"))
        self.assertEqual(stats["bytes_in"],
                         len(b"120x40|") * 2 + len(first) + len(b"more\n"))
        self.assertEqual(stats["refused"], 0)
        self.assert_endpoint_healthy(endpoint)

    def test_exactly_filling_the_ceiling_is_not_truncated(self):
        # The boundary, called directly: a session whose output lands
        # exactly on the ceiling lost nothing, and must not be labelled as
        # though it had. The byte after it is what truncates.
        transcripts, _ = self.recording(max_bytes=4)
        recorder = transcripts.open(self.identity, 1, "127.0.0.1:9000")
        recorder.write(b"abcd")
        self.assertFalse(recorder.truncated)
        self.assertEqual(recorder.bytes, 4)

        with self.degradations() as caught:
            recorder.write(b"e")
            recorder.write(b"f")
        self.assertEqual(len([record for record in caught.records
                              if "ceiling" in record.getMessage()]), 1)
        self.assertTrue(recorder.truncated)
        self.assertEqual(recorder.bytes, 4)
        recorder.close("the test ended")
        self.assertEqual(os.path.getsize(recorder.path), 4)

    @unittest.skipIf(os.name == "posix" and os.geteuid() == 0,
                     "root is not stopped by a directory's mode")
    def test_an_unwritable_directory_costs_the_recording_not_the_session(self):
        # Review Focus. The operator's shell must not die because a log
        # file could not be opened.
        transcripts, directory = self.recording()
        os.makedirs(directory, mode=0o700)
        os.chmod(directory, 0o500)
        # Put it back, or the temporary directory cannot be cleaned up.
        self.addCleanup(os.chmod, directory, 0o700)
        _, front, endpoint = self.rig(transcripts=transcripts)

        with self.degradations() as caught:
            client = self.carried(front)
        self.assertTrue(any(directory in record.getMessage()
                            for record in caught.records),
                        "a degradation says what it was: %r"
                        % ([r.getMessage() for r in caught.records],))

        # The session is carried, both ways, and nothing was written.
        client.send(b"still here\n")
        expected = b"120x40|still here\n"
        self.assertEqual(client.exactly(len(expected)), expected)
        self.assertEqual(os.listdir(directory), [])
        stats = front.stats()
        self.assertEqual(stats["carried"], 1)
        self.assertEqual(stats["sessions"], 1)
        self.assertEqual(stats["refused"], 0)
        self.assertGreater(stats["bytes_out"], 0)
        self.assertGreater(stats["bytes_in"], 0)
        self.assert_endpoint_healthy(endpoint)

    def test_a_failing_write_costs_the_recording_not_the_session(self):
        _, directory = self.recording()
        broken = _BrokenWrites(directory)
        _, front, endpoint = self.rig(transcripts=broken)

        with self.degradations() as caught:
            client = self.carried(front)
            client.send(b"and again\n")
            expected = b"120x40|and again\n"
            self.assertEqual(client.exactly(len(expected)), expected)
        lost = [record.getMessage() for record in caught.records
                if "could not be written" in record.getMessage()]
        self.assertEqual(len(lost), 1,
                         "a failing write is logged once and the recorder "
                         "set aside: %r" % (lost,))

        stats = front.stats()
        self.assertEqual(stats["carried"], 1)
        self.assertEqual(stats["refused"], 0)
        self.ended(front, client)

        path, sidecar = self.written(directory)
        self.assertEqual(os.path.getsize(path), 0)
        with open(sidecar, "rb") as handle:
            facts = json.loads(handle.read().decode("utf-8"))
        # Short of the session, which is what `truncated` says.
        self.assertTrue(facts["truncated"])
        self.assertEqual(facts["bytes"], 0)
        self.assert_endpoint_healthy(endpoint)


if __name__ == "__main__":
    unittest.main()
