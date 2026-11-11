#!/usr/bin/env python3
"""
Unit tests for the operator-facing SOCKS5 port: RFC 1928 with RFC 1929
authentication on loopback, handing each connection to a relay through
the tunnel.

Five things these tests are careful about.

**Both sides are real.** The server end is a real `TunnelServer` with a
real `KeyStore`, and the far end is a stub endpoint that speaks the
protocol an implant speaks: a real `NoiseSession.initiator` over a real
TCP connection, a `HELLO`, and a relay dialled per `OPEN_RELAY` carrying
the token it was given. That is the pattern `test_listeners.py` sets out
in its docstring -- a mock of either side agrees with whatever the code
does and proves nothing about the two ends matching.

**The client's bytes are written as literals.** The greeting, the
sub-negotiation and the expected answers are spelled `b"\\x05\\x02"` and
`b"\\x01\\x00"` rather than built from the module's own constants, so
these tests assert what RFC 1928 §3 and RFC 1929 §2 say and not what
`socks.py` happens to believe.

**The concurrency test proves the mapping, not the count.** Every one of
the 200 sessions asks for a different target and sends a different probe,
and the stub endpoint answers with a tag built from the target it was
asked for. A test that counted successes would pass just as well with two
streams crossed; this one fails, naming the pair, because session 7 would
come back holding session 12's address. All 200 are still open when the
assertions run, which is what makes them concurrent rather than merely
numerous.

**The credentials are generated.** The protocol this one derives from
shipped two hardcoded credential strings that are now literals in a
public detection rule, so nothing here invents a fixture that echoes a
real product's defaults.

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
    ATYP_DOMAIN,
    ATYP_IPV4,
    ATYP_IPV6,
    CMD_BIND,
    CMD_CONNECT,
    CMD_UDP_ASSOCIATE,
    MSG_HELLO,
    MSG_OPEN_RELAY,
    MSG_PING,
    MSG_PONG,
    MSG_RELAY,
    REPLY_COMMAND_NOT_SUPPORTED,
    REPLY_CONNECTION_REFUSED,
    REPLY_GENERAL_FAILURE,
    REPLY_SUCCEEDED,
    NoiseSession,
    decode_message,
    decode_socks_reply,
    decode_socks_request,
    encode_message,
    encode_socks_reply,
    encode_socks_request,
    read_frame,
    write_frame,
)
from software.c2.tunnel.server import TunnelServer
from software.c2.tunnel import socks as socks_mod
from software.c2.tunnel.socks import SocksFront

_LOOPBACK = "127.0.0.1"

# The range the tunnel server assigns SOCKS ports from. Nothing binds one
# here -- every listener in this file binds port 0 and is read back -- so
# this is a pair of numbers in a JSON file and not a port in a test.
_PORT_RANGE = (40200, 40299)

# How many sessions the parallel test opens at once. `nmap` against a /24
# opens sockets faster than anything else this project meets, which is why
# the number is this large and why they are all held open together.
_PARALLEL = 200


def _drain(sock, timeout=2.0):
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


class _SocksClient(object):
    """A proxy-aware client: exactly the bytes RFC 1928 and RFC 1929 define."""

    def __init__(self, port, timeout=10.0):
        self.sock = socket.create_connection((_LOOPBACK, port),
                                             timeout=timeout)

    # ── the handshake ──

    def greet(self, methods=(2,)):
        """Send VER, NMETHODS, METHODS and return the two-byte answer."""
        self.sock.sendall(bytes([5, len(methods)]) + bytes(methods))
        return self.exactly(2)

    def authenticate(self, username, password):
        """RFC 1929 §2, returning the two-byte status."""
        user = username.encode("utf-8")
        secret = password.encode("utf-8")
        self.sock.sendall(bytes([1, len(user)]) + user
                          + bytes([len(secret)]) + secret)
        return self.exactly(2)

    def request(self, cmd, atyp, address, port):
        """One request, and the decoded reply to it."""
        self.sock.sendall(encode_socks_request(cmd, atyp, address, port))
        return self.reply()

    def reply(self):
        """`(reply, atyp, address, port)`, delimited the way a client must."""
        header = self.exactly(4)
        atyp = header[3]
        if atyp == ATYP_IPV4:
            body = self.exactly(4)
        elif atyp == ATYP_IPV6:
            body = self.exactly(16)
        elif atyp == ATYP_DOMAIN:
            length = self.exactly(1)
            body = length + self.exactly(length[0])
        else:
            raise AssertionError("ATYP %d in a reply is not RFC 1928" % atyp)
        return decode_socks_reply(header + body + self.exactly(2))

    # ── the stream ──

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
        write_frame(self.sock, self._noise.initiate(payload))
        self._noise.complete(read_frame(self.sock))

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


def tagged_echo(relay, cmd, atyp, address, port):
    """The target network, for a test: say who was asked for, then echo.

    The tag is what makes a crossed stream visible. A reply that merely
    arrived looks identical on every session; a reply carrying another
    session's address does not.
    """
    relay.send(encode_socks_reply(REPLY_SUCCEEDED, ATYP_IPV4, _LOOPBACK,
                                  port))
    tag = ("%s:%d|" % (address, port)).encode("utf-8")
    while True:
        data = relay.receive()
        if not data:
            return
        relay.send(tag + data)


class _StubEndpoint(object):
    """An endpoint: one command channel, and a relay dialled per OPEN_RELAY.

    `handler(relay, cmd, atyp, address, port)` is the target network for
    whichever test installed it. It is called with the request already
    decoded off its own frame, and owns the reply.
    """

    def __init__(self, host, port, server_public, psk, identity,
                 handler=tagged_echo):
        self._host = host
        self._port = port
        self._public = server_public
        self._psk = psk
        self._handler = handler
        self.errors = []
        self.requests = queue.Queue()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._relays = []
        self._threads = []
        self.channel = _Channel(
            host, port, server_public, psk,
            encode_message(MSG_HELLO, {"identity": identity,
                                       "hostname": "stub-endpoint",
                                       "os": "Linux-6.1"}))
        self._pump = threading.Thread(target=self._run, name="stub-command",
                                      daemon=True)
        self._pump.start()

    def _run(self):
        """Answer PING, and dial a relay for every OPEN_RELAY."""
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
            elif kind == MSG_OPEN_RELAY:
                thread = threading.Thread(target=self._relay,
                                          args=(body["token"],),
                                          name="stub-relay", daemon=True)
                with self._lock:
                    self._threads.append(thread)
                thread.start()

    def _relay(self, token):
        relay = None
        try:
            relay = _Channel(self._host, self._port, self._public, self._psk,
                             encode_message(MSG_RELAY, {"token": token}))
            with self._lock:
                self._relays.append(relay)
            relay.settimeout(30.0)
            request = relay.receive()
            if not request:
                return
            cmd, atyp, address, port = decode_socks_request(request)
            self.requests.put((cmd, atyp, address, port))
            self._handler(relay, cmd, atyp, address, port)
        except (OSError, ValueError) as exc:
            # The front shutting a live session down arrives here, so it is
            # only an error while a test still expects this relay to work.
            if not self._stop.is_set():
                self.errors.append("%s: %s" % (type(exc).__name__, exc))
        except Exception:
            self.errors.append(traceback.format_exc())
        finally:
            if relay is not None:
                relay.close()

    def next_request(self, timeout=10.0):
        return self.requests.get(timeout=timeout)

    def close(self):
        self._stop.set()
        self.channel.close()
        with self._lock:
            relays, threads = list(self._relays), list(self._threads)
        for relay in relays:
            relay.close()
        self._pump.join(timeout=5.0)
        for thread in threads:
            thread.join(timeout=5.0)


class _NoThreads(SocksFront):
    """A front whose per-connection threads cannot be started.

    `_start` is the seam the module keeps for exactly this. The branch
    under test is a process with no threads left, and exhausting this
    machine's thread table to reach it would be neither quick nor kind to
    the rest of the suite.
    """

    def _start(self, thread):
        raise RuntimeError("can't start new thread")


class SocksFrontTestCase(unittest.TestCase):
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
        # Generated per test, because the credentials the published
        # original hardcoded are themselves strings in a public YARA rule.
        self.username = "op-" + os.urandom(4).hex()
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
        for name in ("raccoon.tunnel.socks", "raccoon.tunnel.server"):
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
            # enough that 200 pending sessions cannot age out mid-test.
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
        front = SocksFront(server, self.identity, 0, self.username,
                           self.password, **kwargs)
        front.start()
        self.addCleanup(front.stop)
        return front

    def start_endpoint(self, server, handler=tagged_echo):
        endpoint = _StubEndpoint(_LOOPBACK, server.port, self.public,
                                 self.psk, self.identity, handler)
        self.addCleanup(endpoint.close)
        self.wait_for(lambda: any(row["state"] == "connected"
                                  for row in server.endpoints()))
        return endpoint

    def rig(self, handler=tagged_echo, with_endpoint=True, **front_options):
        """A server, a front and an endpoint, with their teardown ordered.

        The cleanups are registered server, front, endpoint and therefore
        run endpoint, front, server: the endpoint goes first so that a
        relay it is still reading from is never shut down under it, which
        would land in `_StubEndpoint.errors` as a failure of this file's
        own harness rather than of the code under test.
        """
        server = self.start_server()
        front = self.start_front(server, **front_options)
        endpoint = (self.start_endpoint(server, handler)
                    if with_endpoint else None)
        return server, front, endpoint

    def client(self, front, authenticate=True, timeout=20.0):
        """A connected client, through the handshake unless asked not to be."""
        client = _SocksClient(front.port, timeout=timeout)
        self.addCleanup(client.close)
        if authenticate:
            self.assertEqual(client.greet(), b"\x05\x02")
            self.assertEqual(
                client.authenticate(self.username, self.password),
                b"\x01\x00")
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


class TestTheHandshake(SocksFrontTestCase):
    def test_rfc1928_greeting_selects_username_password(self):
        _, front, _ = self.rig(with_endpoint=False)
        client = self.client(front, authenticate=False)

        # 05 01 02: one method offered, username/password.
        self.assertEqual(client.greet(), b"\x05\x02")

        # And the same selection when it is one of several on offer, which
        # is what a real client sends.
        other = self.client(front, authenticate=False)
        self.assertEqual(other.greet(methods=(0, 1, 2)), b"\x05\x02")

    def test_no_auth_offered_alone_is_refused(self):
        _, front, _ = self.rig(with_endpoint=False)
        client = self.client(front, authenticate=False)

        # 05 01 00: a client that will not authenticate.
        self.assertEqual(client.greet(methods=(0,)), b"\x05\xff")
        received, closed = _drain(client.sock)
        self.assertEqual(received, b"")
        self.assertTrue(closed, "the refused client was left connected")
        self.assertEqual(front.stats()["refused_auth"], 1)

    def test_correct_credentials_are_accepted(self):
        _, front, _ = self.rig(with_endpoint=False)
        client = self.client(front, authenticate=False)

        self.assertEqual(client.greet(), b"\x05\x02")
        # RFC 1929 §2: the sub-negotiation version is 1, not 5, and a
        # status of 0 is success.
        self.assertEqual(client.authenticate(self.username, self.password),
                         b"\x01\x00")
        self.assertEqual(front.stats()["refused_auth"], 0)

    def test_wrong_credentials_are_refused_and_the_socket_closed(self):
        _, front, _ = self.rig(with_endpoint=False)

        wrong_password = self.client(front, authenticate=False)
        self.assertEqual(wrong_password.greet(), b"\x05\x02")
        self.assertEqual(
            wrong_password.authenticate(self.username, "not-the-password"),
            b"\x01\x01")
        received, closed = _drain(wrong_password.sock)
        self.assertEqual(received, b"")
        self.assertTrue(closed, "a refused client was left connected")

        wrong_user = self.client(front, authenticate=False)
        self.assertEqual(wrong_user.greet(), b"\x05\x02")
        self.assertEqual(
            wrong_user.authenticate("somebody-else", self.password),
            b"\x01\x01")
        self.assertTrue(_drain(wrong_user.sock)[1])

        self.assertEqual(front.stats()["refused_auth"], 2)

    def test_a_greeting_that_is_not_socks5_gets_nothing_back(self):
        _, front, _ = self.rig(with_endpoint=False)
        client = self.client(front, authenticate=False)

        # SOCKS4 asks for CONNECT to 1.2.3.4:80. There is no reply this
        # port could send that such a client would understand, and the
        # only message it has is itself a SOCKS5 message.
        client.send(b"\x04\x01\x00\x50\x01\x02\x03\x04root\x00")
        received, closed = _drain(client.sock)
        self.assertEqual(received, b"")
        self.assertTrue(closed)
        self.assertEqual(front.stats()["refused_protocol"], 1)


class TestCarryingAConnect(SocksFrontTestCase):
    def test_connect_is_carried_to_the_endpoint_and_bytes_flow_both_ways(self):
        _, front, endpoint = self.rig()
        client = self.client(front)

        reply, atyp, address, port = client.request(
            CMD_CONNECT, ATYP_DOMAIN, "intranet.example", 8080)
        self.assertEqual(reply, REPLY_SUCCEEDED)
        self.assertEqual(atyp, ATYP_IPV4)
        self.assertEqual(address, _LOOPBACK)
        self.assertEqual(port, 8080)

        # The endpoint was asked for exactly what the client asked for.
        self.assertEqual(endpoint.next_request(),
                         (CMD_CONNECT, ATYP_DOMAIN, "intranet.example", 8080))

        client.send(b"GET / HTTP/1.0\r\n\r\n")
        expected = b"intranet.example:8080|GET / HTTP/1.0\r\n\r\n"
        self.assertEqual(client.exactly(len(expected)), expected)

        stats = front.stats()
        self.assertEqual(stats["identity"], self.identity)
        self.assertEqual(stats["port"], front.port)
        self.assertEqual(stats["accepted"], 1)
        self.assertEqual(stats["carried"], 1)
        self.assertEqual(stats["sessions"], 1)
        self.assertEqual(stats["refused"], 0)
        self.assertEqual(stats["bytes_out"], len(b"GET / HTTP/1.0\r\n\r\n"))
        self.assertEqual(stats["bytes_in"], len(expected))
        self.assert_endpoint_healthy(endpoint)

    def test_a_domain_name_and_an_ipv6_target_reach_the_endpoint_verbatim(self):
        _, front, endpoint = self.rig()

        for atyp, address, port in ((ATYP_IPV4, "10.1.2.3", 445),
                                    (ATYP_DOMAIN, "dc01.corp.example", 389),
                                    (ATYP_IPV6, "fd00::5", 22)):
            client = self.client(front)
            reply = client.request(CMD_CONNECT, atyp, address, port)[0]
            self.assertEqual(reply, REPLY_SUCCEEDED)
            self.assertEqual(endpoint.next_request(),
                             (CMD_CONNECT, atyp, address, port))
            client.close()
        self.assert_endpoint_healthy(endpoint)

    def test_the_endpoints_own_refusal_reaches_the_client_unchanged(self):
        def refuse(relay, cmd, atyp, address, port):
            relay.send(encode_socks_reply(REPLY_CONNECTION_REFUSED))

        _, front, endpoint = self.rig(handler=refuse)
        client = self.client(front)

        reply, _, _, _ = client.request(CMD_CONNECT, ATYP_IPV4, "10.0.0.9", 25)
        # The endpoint is the only thing that knows why a target did not
        # answer, so its code is passed through rather than flattened into
        # a general failure.
        self.assertEqual(reply, REPLY_CONNECTION_REFUSED)
        received, closed = _drain(client.sock)
        self.assertEqual(received, b"")
        self.assertTrue(closed, "a refused session was left connected")
        self.assertEqual(front.stats()["carried"], 0)
        self.assert_endpoint_healthy(endpoint)

    def test_the_client_sees_end_of_stream_when_the_endpoint_closes(self):
        def hang_up(relay, cmd, atyp, address, port):
            relay.send(encode_socks_reply(REPLY_SUCCEEDED, ATYP_IPV4,
                                          _LOOPBACK, port))
            relay.send(b"220 ready\r\n")
            relay.close()

        _, front, endpoint = self.rig(handler=hang_up)
        client = self.client(front)

        self.assertEqual(client.request(CMD_CONNECT, ATYP_IPV4, "10.0.0.9",
                                        25)[0], REPLY_SUCCEEDED)
        self.assertEqual(client.exactly(len(b"220 ready\r\n")),
                         b"220 ready\r\n")
        received, closed = _drain(client.sock)
        self.assertEqual(received, b"")
        self.assertTrue(closed, "the session outlived the relay")
        self.wait_for(lambda: front.stats()["sessions"] == 0)
        self.assert_endpoint_healthy(endpoint)

    def test_an_idle_session_outlives_the_handshake_timeout(self):
        # The handshake has a timeout so that a client which connects and
        # says nothing cannot hold a thread. A session must not inherit it:
        # a target that speaks first, or a shell waiting at a prompt, is
        # idle for minutes at a time and is not a stalled client.
        _, front, endpoint = self.rig(handshake_timeout=0.4)
        client = self.client(front)
        self.assertEqual(
            client.request(CMD_CONNECT, ATYP_IPV4, "10.0.0.9", 22)[0],
            REPLY_SUCCEEDED)

        time.sleep(1.2)                       # three handshake timeouts
        self.assertEqual(front.stats()["sessions"], 1)
        client.send(b"SSH-2.0-client")
        expected = b"10.0.0.9:22|SSH-2.0-client"
        self.assertEqual(client.exactly(len(expected)), expected)
        self.assert_endpoint_healthy(endpoint)

    def test_no_endpoint_connected_is_a_general_failure(self):
        _, front, _ = self.rig(with_endpoint=False)
        client = self.client(front)

        reply, _, _, _ = client.request(CMD_CONNECT, ATYP_IPV4, "10.0.0.9", 80)
        self.assertEqual(reply, REPLY_GENERAL_FAILURE)
        self.assertTrue(_drain(client.sock)[1])
        stats = front.stats()
        self.assertEqual(stats["refused_tunnel"], 1)
        self.assertEqual(stats["refused"], 1)


class TestRefusedCommands(SocksFrontTestCase):
    def test_bind_is_refused_with_command_not_supported(self):
        # No endpoint on purpose: a command this port does not implement is
        # refused before anything is asked of the tunnel.
        _, front, _ = self.rig(with_endpoint=False)
        client = self.client(front)

        reply, _, _, _ = client.request(CMD_BIND, ATYP_IPV4, "10.0.0.9", 4444)
        self.assertEqual(reply, REPLY_COMMAND_NOT_SUPPORTED)
        received, closed = _drain(client.sock)
        self.assertEqual(received, b"")
        self.assertTrue(closed)
        self.assertEqual(front.stats()["refused_command"], 1)

    def test_udp_associate_is_refused_with_command_not_supported(self):
        _, front, _ = self.rig(with_endpoint=False)
        client = self.client(front)

        reply, _, _, _ = client.request(CMD_UDP_ASSOCIATE, ATYP_IPV4,
                                        "0.0.0.0", 0)
        self.assertEqual(reply, REPLY_COMMAND_NOT_SUPPORTED)
        self.assertTrue(_drain(client.sock)[1])
        self.assertEqual(front.stats()["refused_command"], 1)

    def test_an_unknown_address_type_is_refused_rather_than_read_blindly(self):
        _, front, _ = self.rig(with_endpoint=False)
        client = self.client(front)

        # ATYP 2 is not assigned, so its address has no length this end
        # can know; there is nothing to delimit and nothing to forward.
        client.send(b"\x05\x01\x00\x02\x7f\x00\x00\x01\x00\x50")
        reply, _, _, _ = client.reply()
        # RFC 1928 reply 0x08, address type not supported.
        self.assertEqual(reply, 8)
        self.assertTrue(_drain(client.sock)[1])
        self.assertEqual(front.stats()["refused_address"], 1)


class TestHundredsOfParallelSessions(SocksFrontTestCase):
    """Review Focus: hundreds of parallel sessions from one tunnel."""

    def test_two_hundred_concurrent_connects_do_not_cross_streams(self):
        _, front, endpoint = self.rig()
        self.assertGreaterEqual(
            front.stats()["max_sessions"], _PARALLEL,
            "the default cap is below what one scan through this port opens")

        release = threading.Event()
        answers = queue.Queue()

        def one(index):
            """One session, asking for a target no other session asks for."""
            address = "host-%d.example" % index
            port = 10000 + index
            probe = b"probe-%d" % index
            expected = b"%s:%d|%s" % (address.encode(), port, probe)
            client = None
            try:
                client = _SocksClient(front.port, timeout=60.0)
                greeting = client.greet()
                status = client.authenticate(self.username, self.password)
                reply = client.request(CMD_CONNECT, ATYP_DOMAIN, address, port)
                client.send(probe)
                echo = client.exactly(len(expected))
                answers.put({"index": index, "greeting": greeting,
                             "status": status, "reply": reply, "echo": echo,
                             "expected": expected})
                # Hold the session open until every other one has answered,
                # so the assertions below run against 200 live sessions and
                # not against 200 that happened one after another.
                release.wait(60.0)
            except Exception:
                answers.put({"index": index,
                             "error": traceback.format_exc()})
            finally:
                if client is not None:
                    client.close()

        threads = [threading.Thread(target=one, args=(index,),
                                    name="socks-client-%d" % index,
                                    daemon=True)
                   for index in range(_PARALLEL)]

        def unwind():
            """Release the clients, then wait for them. In that order.

            A failing assertion below leaves 200 threads parked in
            `release.wait`, and joining them before releasing them would
            make every failure in this test cost minutes.
            """
            release.set()
            for thread in threads:
                thread.join(timeout=30.0)

        self.addCleanup(unwind)
        for thread in threads:
            thread.start()

        collected = {}
        for _ in range(_PARALLEL):
            answer = answers.get(timeout=120.0)
            collected[answer["index"]] = answer

        broken = {index: answer["error"]
                  for index, answer in collected.items()
                  if "error" in answer}
        if broken:
            first = sorted(broken)[0]
            self.fail("%d of %d sessions failed; session %d raised:\n%s"
                      % (len(broken), _PARALLEL, first, broken[first]))

        # Every session got its own answer, and the proof is the content:
        # a crossed pair would show up here as session N holding session
        # M's address, which is a different string.
        self.assertEqual(sorted(collected), list(range(_PARALLEL)))
        for index in range(_PARALLEL):
            answer = collected[index]
            self.assertEqual(answer["greeting"], b"\x05\x02")
            self.assertEqual(answer["status"], b"\x01\x00")
            self.assertEqual(answer["reply"][0], REPLY_SUCCEEDED)
            # The reply's bound port is the one this session asked for, so
            # even the reply is checked for belonging to this session.
            self.assertEqual(answer["reply"][3], 10000 + index)
            self.assertEqual(
                answer["echo"], answer["expected"],
                "session %d was answered with another session's stream"
                % index)

        stats = front.stats()
        self.assertEqual(stats["sessions"], _PARALLEL,
                         "the sessions did not overlap, so nothing about "
                         "crossed streams was proven")
        self.assertEqual(stats["accepted"], _PARALLEL)
        self.assertEqual(stats["carried"], _PARALLEL)
        self.assertEqual(stats["refused"], 0)
        self.assert_endpoint_healthy(endpoint)

        release.set()
        for thread in threads:
            thread.join(timeout=30.0)
        self.wait_for(lambda: front.stats()["sessions"] == 0, timeout=30.0)

    def test_beyond_max_sessions_the_client_gets_a_general_failure_not_a_silent_drop(self):
        _, front, endpoint = self.rig(max_sessions=2)
        held = []
        for index in range(2):
            client = self.client(front)
            self.assertEqual(
                client.request(CMD_CONNECT, ATYP_IPV4, "10.0.0.1",
                               1000 + index)[0], REPLY_SUCCEEDED)
            held.append(client)
        self.assertEqual(front.stats()["sessions"], 2)

        over = self.client(front)
        reply, _, _, _ = over.request(CMD_CONNECT, ATYP_IPV4, "10.0.0.1", 9000)
        # RFC 1928 reply 0x01. A silent drop here is what a port scanner
        # finds first, and it is indistinguishable from a dead tunnel.
        self.assertEqual(reply, REPLY_GENERAL_FAILURE)
        received, closed = _drain(over.sock)
        self.assertEqual(received, b"")
        self.assertTrue(closed, "the refused client was left connected")

        stats = front.stats()
        self.assertEqual(stats["refused_capacity"], 1)
        self.assertEqual(stats["refused"], 1)
        self.assertEqual(stats["sessions"], 2)
        self.assertEqual(stats["max_sessions"], 2)

        # The slot is released, not leaked: closing one lets the next in.
        held.pop().close()
        self.wait_for(lambda: front.stats()["sessions"] == 1)
        after = self.client(front)
        self.assertEqual(
            after.request(CMD_CONNECT, ATYP_IPV4, "10.0.0.1", 9001)[0],
            REPLY_SUCCEEDED)
        self.assertEqual(front.stats()["refused_capacity"], 1)
        self.assert_endpoint_healthy(endpoint)

    def test_stats_report_the_refusals(self):
        _, front, _ = self.rig(with_endpoint=False, max_sessions=1)

        self.assertEqual(front.stats()["refused"], 0)

        declined = self.client(front, authenticate=False)
        self.assertEqual(declined.greet(methods=(0,)), b"\x05\xff")

        wrong = self.client(front, authenticate=False)
        self.assertEqual(wrong.greet(), b"\x05\x02")
        self.assertEqual(wrong.authenticate(self.username, "wrong"),
                         b"\x01\x01")

        bind = self.client(front)
        self.assertEqual(bind.request(CMD_BIND, ATYP_IPV4, "10.0.0.1", 80)[0],
                         REPLY_COMMAND_NOT_SUPPORTED)

        udp = self.client(front)
        self.assertEqual(
            udp.request(CMD_UDP_ASSOCIATE, ATYP_IPV4, "10.0.0.1", 80)[0],
            REPLY_COMMAND_NOT_SUPPORTED)

        orphan = self.client(front)
        self.assertEqual(
            orphan.request(CMD_CONNECT, ATYP_IPV4, "10.0.0.1", 80)[0],
            REPLY_GENERAL_FAILURE)

        stats = front.stats()
        self.assertEqual(stats["refused_auth"], 2)
        self.assertEqual(stats["refused_command"], 2)
        self.assertEqual(stats["refused_tunnel"], 1)
        self.assertEqual(stats["refused_capacity"], 0)
        self.assertEqual(stats["refused_protocol"], 0)
        self.assertEqual(stats["refused_address"], 0)
        self.assertEqual(stats["refused"], 5)
        self.assertEqual(stats["accepted"], 5)
        self.assertEqual(stats["carried"], 0)


class TestWhatAnUnauthenticatedPeerCanHold(SocksFrontTestCase):
    """Review focus: this port's threat model is the other local users.

    Loopback keeps other hosts out, so what is left is whoever has a shell
    here -- and this process hosts the rest of the C2's listeners, so a
    peer that can hold threads and descriptors can take those down with
    it. Each test here is a peer that is never refused by any check that
    only looks at bytes, because it sends them correctly and slowly.
    """

    def test_a_drip_fed_handshake_is_cut_off_at_its_deadline(self):
        _, front, _ = self.rig(with_endpoint=False, handshake_timeout=0.5)
        client = self.client(front, authenticate=False)
        user = self.username.encode("utf-8")
        secret = self.password.encode("utf-8")
        # A correct greeting and a correct RFC 1929 exchange -- with the
        # right credentials -- sent one byte at a time. Every single read
        # lands far inside a per-`recv` timeout of 0.5s, so nothing but an
        # absolute deadline can ever stop this peer: it would otherwise
        # hold its thread and its descriptor for as long as it kept
        # dripping, which is the whole technique.
        payload = (b"\x05\x01\x02" + bytes([1, len(user)]) + user
                   + bytes([len(secret)]) + secret)
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
        self.assertTrue(_drain(client.sock, timeout=3.0)[1],
                        "the drip feed was left holding its thread")
        # Cut off, not lost: a deliberate close is counted, and it is not
        # confused with any of the three resource limits.
        stats = front.stats()
        self.assertEqual(stats["refused"], 1)
        self.assertEqual(stats["refused_capacity"], 0)
        self.assertEqual(stats["refused_pending"], 0)
        self.assertEqual(stats["pending"], 0)

    def test_too_many_handshakes_in_flight_are_closed_and_counted(self):
        _, front, _ = self.rig(with_endpoint=False, max_pending=1,
                               handshake_timeout=10.0)
        # One client that connects and says nothing holds the only slot.
        silent = self.client(front, authenticate=False)
        self.wait_for(lambda: front.stats()["pending"] == 1)

        crowded = _SocksClient(front.port, timeout=10.0)
        self.addCleanup(crowded.close)
        received, closed = _drain(crowded.sock, timeout=3.0)
        # Before a greeting there is no SOCKS message to refuse it with,
        # so this one is closed rather than answered -- and counted, so it
        # is not a silent drop as far as the operator's row is concerned.
        self.assertEqual(received, b"")
        self.assertTrue(closed, "a connection past the cap was left open")
        stats = front.stats()
        self.assertEqual(stats["refused_pending"], 1)
        self.assertEqual(stats["refused_capacity"], 0)
        self.assertEqual(stats["refused_threads"], 0)
        self.assertEqual(stats["max_pending"], 1)
        self.assertEqual(stats["accepted"], 2)

        # Authenticating releases the slot. That is the point of the cap
        # being separate: a flood of silent peers must not be able to
        # crowd out the operator, whose connections stop counting against
        # it the moment they prove who they are.
        self.assertEqual(silent.greet(), b"\x05\x02")
        self.assertEqual(silent.authenticate(self.username, self.password),
                         b"\x01\x00")
        self.wait_for(lambda: front.stats()["pending"] == 0)
        admitted = self.client(front)
        self.assertEqual(
            admitted.request(CMD_BIND, ATYP_IPV4, "10.0.0.1", 80)[0],
            REPLY_COMMAND_NOT_SUPPORTED)
        self.assertEqual(front.stats()["refused_pending"], 1)

    def test_a_connection_is_closed_and_counted_when_no_thread_can_start(self):
        server = self.start_server()
        front = _NoThreads(server, self.identity, 0, self.username,
                           self.password)
        front.start()
        self.addCleanup(front.stop)

        with self.assertLogs("raccoon.tunnel.socks", level="WARNING") as caught:
            first = _SocksClient(front.port, timeout=10.0)
            self.addCleanup(first.close)
            received, closed = _drain(first.sock, timeout=3.0)
        self.assertEqual(received, b"")
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
        second = _SocksClient(front.port, timeout=10.0)
        self.addCleanup(second.close)
        self.assertTrue(_drain(second.sock, timeout=3.0)[1])
        self.wait_for(lambda: front.stats()["refused_threads"] == 2)

    def test_finish_stops_draining_at_its_deadline(self):
        # `finish` drains what a client sent and nobody wanted, so that
        # closing cannot replace an already-written refusal with an RST.
        # Against a client that keeps sending, a timeout per read never
        # ends: only the deadline does. Called directly because there is
        # no way to observe a thread pinned inside it from outside.
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        stop = threading.Event()

        def blast():
            while not stop.is_set():
                try:
                    left.sendall(b"x" * 4096)
                except OSError:
                    return

        blaster = threading.Thread(target=blast, name="blast", daemon=True)

        def unwind():
            stop.set()
            try:
                left.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            blaster.join(timeout=5.0)

        self.addCleanup(unwind)
        blaster.start()

        done = threading.Event()

        def drain_it():
            socks_mod.finish(right)
            done.set()

        runner = threading.Thread(target=drain_it, name="finish", daemon=True)
        runner.start()
        self.assertTrue(
            done.wait(3.0),
            "finish drained past its deadline; a client that keeps sending "
            "pins the thread that is trying to close it")
        runner.join(timeout=5.0)


class TestTheListener(SocksFrontTestCase):
    def test_a_bind_address_that_is_not_loopback_is_refused(self):
        server = self.start_server()
        for host in ("0.0.0.0", "10.0.0.1", "::", "192.168.1.7"):
            with self.assertRaises(ValueError) as caught:
                SocksFront(server, self.identity, 0, self.username,
                           self.password, bind_host=host)
            self.assertIn(host, str(caught.exception))

    def test_a_bind_address_that_is_a_name_is_refused(self):
        server = self.start_server()
        # A name resolves through a resolver this process does not own, so
        # "localhost" is not proof of loopback at bind time.
        with self.assertRaises(ValueError):
            SocksFront(server, self.identity, 0, self.username,
                       self.password, bind_host="localhost")

    def test_loopback_v4_and_v6_are_both_accepted(self):
        server = self.start_server()
        for host in (_LOOPBACK, "::1"):
            front = SocksFront(server, self.identity, 0, self.username,
                               self.password, bind_host=host)
            front.start()
            self.addCleanup(front.stop)
            self.assertTrue(front.stats()["serving"])
            self.assertGreater(front.port, 0)

    def test_empty_credentials_are_refused(self):
        server = self.start_server()
        with self.assertRaises(ValueError):
            SocksFront(server, self.identity, 0, "", self.password)
        with self.assertRaises(ValueError):
            SocksFront(server, self.identity, 0, self.username, "")

    def test_a_credential_too_long_for_rfc1929_is_refused(self):
        server = self.start_server()
        with self.assertRaises(ValueError):
            SocksFront(server, self.identity, 0, "u" * 256, self.password)
        with self.assertRaises(ValueError):
            SocksFront(server, self.identity, 0, self.username, "p" * 256)

    def test_max_sessions_must_be_at_least_one(self):
        server = self.start_server()
        for bad in (0, -1):
            with self.assertRaises(ValueError):
                SocksFront(server, self.identity, 0, self.username,
                           self.password, max_sessions=bad)

    def test_max_pending_must_be_at_least_one(self):
        server = self.start_server()
        for bad in (0, -1):
            with self.assertRaises(ValueError):
                SocksFront(server, self.identity, 0, self.username,
                           self.password, max_pending=bad)
        # Unset, it follows the session cap: a handshake that could never
        # become a session is one this port has no use for.
        front = SocksFront(server, self.identity, 0, self.username,
                           self.password, max_sessions=7)
        self.assertEqual(front.stats()["max_pending"], 7)

    def test_stop_is_safe_before_start_and_twice(self):
        server = self.start_server()
        front = SocksFront(server, self.identity, 0, self.username,
                           self.password)
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

    def test_stop_drops_a_live_session(self):
        _, front, endpoint = self.rig()
        client = self.client(front)
        self.assertEqual(
            client.request(CMD_CONNECT, ATYP_IPV4, "10.0.0.1", 80)[0],
            REPLY_SUCCEEDED)
        self.assertEqual(front.stats()["sessions"], 1)

        # `stop` while the endpoint is still connected and the relay is
        # still live, so that what ends the session is this call and
        # nothing else. Closing the endpoint first would let the relay
        # hang up on its own, and this test would then pass with `stop`
        # doing nothing at all.
        front.stop()
        self.assertEqual(front.stats()["sessions"], 0)
        self.assertFalse(front.stats()["serving"])
        self.assertTrue(_drain(client.sock)[1],
                        "a session outlived the port it arrived on")
        self.assert_endpoint_healthy(endpoint)

    def test_starting_twice_is_an_error(self):
        _, front, _ = self.rig(with_endpoint=False)
        self.assertRaises(RuntimeError, front.start)


if __name__ == "__main__":
    unittest.main()
