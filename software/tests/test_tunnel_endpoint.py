#!/usr/bin/env python3
"""
Unit tests for the tunnel endpoint in `software/c2/beacon.py`: the far end
of the tunnel, which connects out, holds one command channel, and dials a
second connection per relay the operator asks for.

Six things these tests are careful about.

**Both halves are real.** The server end is a real `TunnelServer` with a
real `KeyStore`, and the near end is the real `TunnelEndpoint` running
`run()` on a thread. There is no mock of a Noise session, no mock of a
socket and no stub of either half: the whole point of this task is that
the two ends match, and a mock of one agrees with whatever the other does.
The operator's side is driven through `TunnelServer.open_session`, which
is the API `SocksFront` calls.

**The target speaks first, on purpose.** `_Target` sends a banner the
instant it accepts. So `test_endpoint_dials_a_relay_when_asked_and_carries_
a_connect` fails if the endpoint ever coalesces the target's first bytes
into its SOCKS reply: the reply would arrive as one frame with the banner
glued on and `decode_socks_reply` refuses that, exactly as the operator's
port does.

**The restart test restarts.** It stops the server and constructs a new
one over the same `state_path` and the same port, because the property
under test is that an endpoint whose server vanished retries rather than
exits -- and that it comes back to the same identity and the same assigned
SOCKS port. Nothing calls an internal reconnect method.

**Two of the four unreachable-target cases come from a seam, and it is
named.** Connection refused and an unresolvable name are produced for
real: a closed loopback port refuses, and a `.invalid` name cannot resolve
(RFC 2606). "No route" and "a connect that hangs" cannot be produced
portably -- on this machine an unrouted IPv6 address answers
`EHOSTUNREACH` rather than `ENETUNREACH`, and whether a TEST-NET-1 address
hangs or is refused outright depends on the host's default route. So
`_UnreachableEndpoint` overrides `_dial_target`, which is the one call that
touches the target network, and raises what the OS raises in those
conditions. Everything else in those two tests is real: the server, the
Noise sessions, the SOCKS codec, the reply framing and the session
teardown.

**No port is hardcoded.** Every listener in this file binds port 0 and is
read back. `_PORT_RANGE` is the range the server assigns loopback SOCKS
ports from; nothing in this task binds one, so it is a pair of numbers in
a JSON file.

**No thread may die quietly.** `setUp` installs a `threading.excepthook`
and a handler on both loggers, and the last cleanup to run asserts that no
thread raised and that nothing was logged at ERROR or above. An endpoint
that survives a dead relay by crashing a pump thread would otherwise pass
every assertion here.
"""

import base64
import errno
import logging
import os
import socket
import tempfile
import threading
import time
import traceback
import unittest

from software.c2 import beacon as beacon_mod
from software.c2.beacon import (
    ATYP_DOMAIN,
    ATYP_IPV4,
    ATYP_IPV6,
    CMD_CONNECT,
    REPLY_CONNECTION_REFUSED,
    REPLY_HOST_UNREACHABLE,
    REPLY_NETWORK_UNREACHABLE,
    REPLY_SUCCEEDED,
    REPLY_TTL_EXPIRED,
    TunnelEndpoint,
    decode_socks_reply,
    encode_socks_request,
    tunnel_config_problem,
)
from software.c2.tunnel.keys import KeyStore
from software.c2.tunnel.server import TunnelServer

_LOOPBACK = "127.0.0.1"
_LOOPBACK6 = "::1"

# The range the tunnel server assigns SOCKS ports from. Nothing binds one
# in this task, so this is a pair of numbers in a JSON file and not a port
# in a test; every listener here binds 0 and is read back.
_PORT_RANGE = (40300, 40399)

# A name that cannot resolve, per RFC 2606 §2: `.invalid` is reserved and
# guaranteed not to be delegated.
_UNRESOLVABLE = "no-endpoint-here.invalid"


def _free_port():
    """A loopback port with nothing on it: bound, read back, released.

    What connects to it afterwards is refused, which is the one
    unreachable-target condition a test can produce for real and quickly.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((_LOOPBACK, 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def _ipv6_loopback_works():
    """True if `::1` can be bound here, so the IPv6 test means something."""
    if not socket.has_ipv6:
        return False
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        sock.bind((_LOOPBACK6, 0))
        return True
    except OSError:
        return False
    finally:
        sock.close()


class _Target(object):
    """A TCP service in the endpoint's own network: a banner, then an echo.

    The banner goes out the moment the connection is accepted, so a reply
    that carried the target's first bytes with it would be visible as a
    frame that is not a SOCKS reply. The echo is tagged with the port that
    was asked for, so a crossed stream is visible too.
    """

    def __init__(self, host=_LOOPBACK, banner=b"", echo=True):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self._listener = socket.socket(family, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((host, 0))
        self._listener.listen(8)
        self._listener.settimeout(0.2)
        self.host = host
        self.port = self._listener.getsockname()[1]
        self.banner = banner
        self._echo = echo
        self._lock = threading.Lock()
        self._conns = []
        self._stop = threading.Event()
        self.errors = []
        self._thread = threading.Thread(target=self._accept, daemon=True,
                                        name="target-accept")
        self._thread.start()

    def _accept(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self._conns.append(conn)
            threading.Thread(target=self._serve, args=(conn,), daemon=True,
                             name="target-conn").start()

    def _serve(self, conn):
        try:
            if self.banner:
                conn.sendall(self.banner)
            while self._echo:
                data = conn.recv(4096)
                if not data:
                    return
                conn.sendall(b"echo:" + data)
        except OSError:
            return
        except Exception:
            self.errors.append(traceback.format_exc())

    def close(self):
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        with self._lock:
            conns, self._conns = self._conns, []
        for conn in conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
        self._thread.join(timeout=3.0)


class _ConnectProxy(object):
    """A stub HTTP `CONNECT` proxy on loopback that records what it is asked.

    Deliberately not an HTTP server: the request line, the headers and
    `200 Connection Established` are the whole of what a corporate proxy
    gives the endpoint and the whole of what the endpoint has to get
    right. `request_lines` is what the test asserts on, because a
    `CONNECT` with the wrong target is how a tunnel silently goes direct.
    """

    def __init__(self):
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((_LOOPBACK, 0))
        self._listener.listen(8)
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        self._lock = threading.Lock()
        self._request_lines = []
        self._socks = []
        self._stop = threading.Event()
        self.errors = []
        self._thread = threading.Thread(target=self._accept, daemon=True,
                                        name="proxy-accept")
        self._thread.start()

    @property
    def request_lines(self):
        with self._lock:
            return list(self._request_lines)

    def _accept(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self._socks.append(conn)
            threading.Thread(target=self._serve, args=(conn,), daemon=True,
                             name="proxy-conn").start()

    def _serve(self, client):
        upstream = None
        try:
            line = self._read_line(client)
            while True:
                header = self._read_line(client)
                if not header:
                    break
            with self._lock:
                self._request_lines.append(line)
            parts = line.split(" ")
            if len(parts) < 2 or parts[0] != "CONNECT":
                client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                return
            host, _, port = parts[1].rpartition(":")
            upstream = socket.create_connection((host, int(port)),
                                                timeout=10.0)
            with self._lock:
                self._socks.append(upstream)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._bridge(client, upstream)
        except OSError:
            return
        except Exception:
            self.errors.append(traceback.format_exc())

    @staticmethod
    def _read_line(sock):
        chunks = []
        while len(chunks) < 8192:
            byte = sock.recv(1)
            if not byte:
                break
            if byte == b"\n":
                break
            if byte != b"\r":
                chunks.append(byte)
        return b"".join(chunks).decode("latin-1")

    def _bridge(self, one, two):
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(65535)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        back = threading.Thread(target=forward, args=(two, one), daemon=True,
                                name="proxy-down")
        back.start()
        forward(one, two)
        back.join(timeout=3.0)

    def close(self):
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        with self._lock:
            socks, self._socks = self._socks, []
        for sock in socks:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        self._thread.join(timeout=3.0)


class _UnreachableEndpoint(TunnelEndpoint):
    """An endpoint whose target network always answers with one error.

    The seam the module docstring explains: `_dial_target` is the single
    call that touches the target network, and the two conditions no test
    can produce portably -- no route, and a connect that hangs past the
    timeout -- are injected there as the exception the OS raises for them.
    """

    failure = None

    def _dial_target(self, address, port, timeout):
        raise self.failure


class TunnelEndpointTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name
        self.state_path = os.path.join(self.root, "state", "tunnel_ports.json")
        self.keys_path = os.path.join(self.root, "keys", "tunnel_keys.json")
        self.store = KeyStore(self.keys_path)
        self.psks = {}
        for identity in ("build-alpha", "build-beta"):
            psk = os.urandom(32)
            self.store.register_build(identity, psk)
            self.psks[identity] = psk
        self.public = self.store.static_public()

        # Registered first so it runs last: the server has to be stopped
        # and every endpoint shut down before the verdict is read.
        self.thread_errors = []
        self.log_records = []
        self.addCleanup(self._assert_nothing_broke_quietly)

        previous_hook = threading.excepthook
        threading.excepthook = self.thread_errors.append
        self.addCleanup(setattr, threading, "excepthook", previous_hook)

        handler = logging.Handler(level=logging.ERROR)
        handler.emit = self.log_records.append
        for name in ("raccoon.c2", "raccoon.tunnel.server"):
            log = logging.getLogger(name)
            log.addHandler(handler)
            self.addCleanup(log.removeHandler, handler)

    def _assert_nothing_broke_quietly(self):
        self.assertEqual(
            [getattr(args, "exc_value", args) for args in self.thread_errors],
            [], "a thread raised; the endpoint let an exception escape one "
                "of its loops")
        self.assertEqual(
            [record.getMessage() for record in self.log_records], [],
            "something was logged at ERROR or above; an expected failure is "
            "logged below that")

    # ── harness ──

    def start_server(self, **kwargs):
        port_range = kwargs.pop("port_range", _PORT_RANGE)
        bind_port = kwargs.pop("bind_port", 0)
        options = {
            # Long enough that no test sees an unasked-for PING; the
            # keep-alive test sets its own.
            "keepalive_interval": 30.0,
            "idle_timeout": 30.0,
            "handshake_timeout": 10.0,
            "session_timeout": 20.0,
        }
        options.update(kwargs)
        server = TunnelServer(self.store, _LOOPBACK, bind_port, port_range,
                              self.state_path, **options)
        server.start()
        self.addCleanup(server.stop)
        return server

    def config_for(self, server_port, identity="build-alpha", **overrides):
        """A beacon config whose `c2.tunnel` block points at `server_port`."""
        proxy = overrides.pop("proxy", {"mode": "none"})
        tunnel = {
            "enabled": True,
            "server": _LOOPBACK,
            "port": server_port,
            "public_key": base64.b64encode(self.public).decode("ascii"),
            "psk": base64.b64encode(self.psks[identity]).decode("ascii"),
            "identity": identity,
        }
        tunnel.update(overrides)
        return {"c2": {"tunnel": tunnel, "proxy": proxy}}

    def start_endpoint(self, config, factory=TunnelEndpoint):
        """An endpoint running `run()` on a thread, stopped and joined."""
        endpoint = factory(config)
        thread = threading.Thread(target=endpoint.run, name="endpoint",
                                  daemon=True)
        # LIFO: `stop` runs first, then the join it unblocks, and last the
        # assertion that the join was not a timeout. Without that
        # assertion a `run` that outlived its `stop` would leave the suite
        # green, which is a tunnel that ignores shutdown.
        self.addCleanup(self.assert_ended, thread)
        self.addCleanup(thread.join, 5.0)
        self.addCleanup(endpoint.stop)
        thread.start()
        return endpoint

    def assert_ended(self, thread):
        self.assertFalse(thread.is_alive(),
                         "the endpoint's run() thread outlived its stop()")

    def fast_retries(self):
        """Shrink the reconnect backoff so a restart test is not a wait.

        The shape is the beacon's own -- a base delay, 1.5 per failure, a
        ceiling -- and only the base is moved, so what is exercised is the
        real loop and not a different one.
        """
        original = beacon_mod._TUNNEL_RETRY_BASE
        beacon_mod._TUNNEL_RETRY_BASE = 0.05
        self.addCleanup(setattr, beacon_mod, "_TUNNEL_RETRY_BASE", original)

    def pure_python_aes(self, enabled):
        """Force the AES backend flag, as `test_tunnel_noise.py` does."""
        original = beacon_mod._USE_PURE_PYTHON_AES
        beacon_mod._USE_PURE_PYTHON_AES = enabled
        self.addCleanup(setattr, beacon_mod, "_USE_PURE_PYTHON_AES", original)

    def target(self, host=_LOOPBACK, banner=b"", echo=True):
        service = _Target(host=host, banner=banner, echo=echo)
        self.addCleanup(service.close)
        return service

    def row(self, server, identity):
        for row in server.endpoints():
            if row["identity"] == identity:
                return row
        return {"identity": identity, "state": "absent"}

    def wait_for(self, predicate, timeout=15.0, what="condition"):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return True
            time.sleep(0.01)
        self.fail("%s was still false after %.1fs" % (what, timeout))

    def wait_connected(self, server, identity="build-alpha", timeout=15.0):
        self.wait_for(
            lambda: self.row(server, identity)["state"] == "connected",
            timeout=timeout, what="the endpoint registering as %r" % identity)
        return self.row(server, identity)

    def relay(self, server, identity="build-alpha", timeout=15.0):
        """A paired relay stream, asked for the way the SOCKS port asks."""
        session = server.open_session(identity)
        self.addCleanup(session.close)
        self.assertTrue(
            session.wait_paired(timeout),
            "the endpoint did not dial a relay within %.1fs" % timeout)
        stream = session.sock
        stream.settimeout(timeout)
        return stream

    def request(self, stream, cmd, atyp, address, port):
        """One SOCKS request down a relay, and the decoded reply to it.

        The reply is read with `recv_message`, so a frame carrying anything
        but exactly one reply fails here -- which is what makes this the
        check that the endpoint never coalesces the target's first bytes
        into its answer.
        """
        stream.sendall(encode_socks_request(cmd, atyp, address, port))
        raw = stream.recv_message()
        self.assertTrue(raw, "the endpoint closed the relay without a reply")
        return decode_socks_reply(raw)


class TestRegistration(TunnelEndpointTestCase):
    def test_endpoint_connects_registers_and_appears_on_the_server(self):
        server = self.start_server()
        endpoint = self.start_endpoint(self.config_for(server.port))

        row = self.wait_connected(server)
        self.assertEqual(row["identity"], "build-alpha")
        self.assertEqual(row["state"], "connected")
        self.assertTrue(_PORT_RANGE[0] <= row["port"] <= _PORT_RANGE[1])
        # The HELLO carries what the panel shows, and the endpoint knows
        # its own host rather than being told it.
        self.assertTrue(row["hostname"])
        self.assertTrue(row["os"])
        # No beacon above this endpoint, so no implant to correlate with.
        # The server reports that as unlinked, which is a supported
        # deployment and not a missing field.
        self.assertIsNone(row["implant_id"])

        status = endpoint.status()
        self.assertEqual(status["identity"], "build-alpha")
        self.assertEqual(status["port"], server.port)
        self.assertTrue(status["connected"])
        self.assertEqual(status["egress"], "direct")
        self.assertEqual(status["sessions"], 0)

    def test_endpoint_sends_the_implant_id_when_the_config_carries_one(self):
        server = self.start_server()
        self.start_endpoint(self.config_for(server.port,
                                            implant_id="implant-abcd"))

        row = self.wait_connected(server)
        self.assertEqual(row["implant_id"], "implant-abcd")

    def test_endpoint_answers_ping_with_pong(self):
        # The server drops an endpoint that is silent for a whole idle
        # timeout, so an endpoint still connected well past three
        # keep-alives is one whose PONGs are arriving.
        server = self.start_server(keepalive_interval=0.2, idle_timeout=0.8)
        self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)

        time.sleep(2.0)
        row = self.row(server, "build-alpha")
        self.assertEqual(row["state"], "connected")
        self.assertLess(row["last_seen_age"], 0.8)

    def test_endpoint_reconnects_after_the_server_disappears(self):
        self.fast_retries()
        server = self.start_server()
        port = server.port
        self.start_endpoint(self.config_for(port))
        first = self.wait_connected(server)

        server.stop()
        # `stop` clears the endpoint table synchronously, so the row is
        # already disconnected -- and it is still a row, because the
        # identity keeps the SOCKS port it was assigned.
        self.assertEqual(self.row(server, "build-alpha")["state"],
                         "disconnected")

        # A new server over the same port table and the same port: a
        # restart as an operator performs it, not a reconnect method.
        restarted = self.start_server(bind_port=port)
        self.assertEqual(restarted.port, port)
        row = self.wait_connected(restarted)
        self.assertEqual(row["port"], first["port"],
                         "the identity came back on a different SOCKS port")


class TestCarryingAConnect(TunnelEndpointTestCase):
    def test_endpoint_dials_a_relay_when_asked_and_carries_a_connect(self):
        server = self.start_server()
        endpoint = self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)
        service = self.target(banner=b"SSH-2.0-stub\r\n")

        stream = self.relay(server)
        reply, atyp, address, port = self.request(
            stream, CMD_CONNECT, ATYP_IPV4, _LOOPBACK, service.port)
        self.assertEqual(reply, REPLY_SUCCEEDED)
        # RFC 1928 §6: BND.ADDR and BND.PORT are the endpoint's own
        # outgoing socket, not a canned zero.
        self.assertEqual(atyp, ATYP_IPV4)
        self.assertEqual(address, _LOOPBACK)
        self.assertNotEqual(port, 0)

        # The banner was already on its way when the reply was written, so
        # this is the assertion that the reply was a frame of its own.
        self.assertEqual(stream.recv(len(service.banner)), service.banner)
        stream.sendall(b"hello")
        self.assertEqual(stream.recv(64), b"echo:hello")

        self.wait_for(lambda: endpoint.status()["sessions"] == 1,
                      what="the endpoint counting its relay")

    def test_endpoint_carries_a_connect_to_a_domain_name(self):
        server = self.start_server()
        self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)
        service = self.target()

        stream = self.relay(server)
        reply = self.request(stream, CMD_CONNECT, ATYP_DOMAIN, "localhost",
                             service.port)[0]
        self.assertEqual(reply, REPLY_SUCCEEDED)
        stream.sendall(b"named")
        self.assertEqual(stream.recv(64), b"echo:named")

    @unittest.skipUnless(_ipv6_loopback_works(), "no IPv6 loopback here")
    def test_endpoint_carries_a_connect_to_an_ipv6_target(self):
        server = self.start_server()
        self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)
        service = self.target(host=_LOOPBACK6)

        stream = self.relay(server)
        reply, atyp, address, port = self.request(
            stream, CMD_CONNECT, ATYP_IPV6, _LOOPBACK6, service.port)
        self.assertEqual(reply, REPLY_SUCCEEDED)
        # The bound address is the family the endpoint actually left on,
        # which for an IPv6 target is an IPv6 socket.
        self.assertEqual(atyp, ATYP_IPV6)
        self.assertEqual(socket.inet_pton(socket.AF_INET6, address),
                         socket.inet_pton(socket.AF_INET6, _LOOPBACK6))
        self.assertNotEqual(port, 0)

        stream.sendall(b"six")
        self.assertEqual(stream.recv(64), b"echo:six")

    def test_two_relays_at_once_do_not_cross_their_streams(self):
        server = self.start_server()
        self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)
        one = self.target()
        two = self.target()

        first = self.relay(server)
        second = self.relay(server)
        self.assertEqual(self.request(first, CMD_CONNECT, ATYP_IPV4,
                                      _LOOPBACK, one.port)[0], REPLY_SUCCEEDED)
        self.assertEqual(self.request(second, CMD_CONNECT, ATYP_IPV4,
                                      _LOOPBACK, two.port)[0], REPLY_SUCCEEDED)
        first.sendall(b"one")
        second.sendall(b"two")
        self.assertEqual(first.recv(64), b"echo:one")
        self.assertEqual(second.recv(64), b"echo:two")

    def test_a_target_that_closes_ends_the_session(self):
        server = self.start_server()
        self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)
        service = self.target(banner=b"bye", echo=False)

        stream = self.relay(server)
        self.assertEqual(self.request(stream, CMD_CONNECT, ATYP_IPV4,
                                      _LOOPBACK, service.port)[0],
                         REPLY_SUCCEEDED)
        self.assertEqual(stream.recv(3), b"bye")
        service.close()
        # The far end finishing is reported as an empty read and not as a
        # session that hangs on for ever.
        self.assertEqual(stream.recv(64), b"")


class TestEgress(TunnelEndpointTestCase):
    def test_endpoint_connects_through_a_local_connect_proxy(self):
        server = self.start_server()
        proxy = _ConnectProxy()
        self.addCleanup(proxy.close)
        config = self.config_for(
            server.port,
            proxy={"mode": "manual", "url": "http://%s:%d" % (_LOOPBACK,
                                                              proxy.port)})
        endpoint = self.start_endpoint(config)

        self.wait_connected(server)
        self.assertEqual(
            proxy.request_lines[0],
            "CONNECT %s:%d HTTP/1.1" % (_LOOPBACK, server.port),
            "the endpoint asked the proxy for the wrong target")
        self.assertEqual(endpoint.status()["egress"],
                         "proxy %s:%d" % (_LOOPBACK, proxy.port))
        self.assertEqual(proxy.errors, [])

    def test_a_relay_takes_the_same_way_out_as_the_command_channel(self):
        server = self.start_server()
        proxy = _ConnectProxy()
        self.addCleanup(proxy.close)
        config = self.config_for(
            server.port,
            proxy={"mode": "manual", "url": "http://%s:%d" % (_LOOPBACK,
                                                              proxy.port)})
        self.start_endpoint(config)
        self.wait_connected(server)
        service = self.target()

        stream = self.relay(server)
        self.assertEqual(self.request(stream, CMD_CONNECT, ATYP_IPV4,
                                      _LOOPBACK, service.port)[0],
                         REPLY_SUCCEEDED)
        # One CONNECT for the command channel and one for the relay: the
        # single server port is what makes both acceptable to a proxy that
        # permits 443 and nothing else.
        self.assertEqual(len(proxy.request_lines), 2)
        self.assertEqual(set(proxy.request_lines),
                         {"CONNECT %s:%d HTTP/1.1" % (_LOOPBACK,
                                                      server.port)})

    def test_a_proxy_that_refuses_the_connect_falls_back_to_direct(self):
        # A proxy answering 403 is the corporate case this endpoint has to
        # survive: the way out has to be tried in order and the last of
        # them is always direct.
        server = self.start_server()
        refuser = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(refuser.close)
        refuser.bind((_LOOPBACK, 0))
        refuser.listen(4)
        refused_port = refuser.getsockname()[1]
        stop = threading.Event()

        def refuse():
            refuser.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = refuser.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                try:
                    conn.recv(4096)
                    conn.sendall(b"HTTP/1.1 403 Forbidden\r\n"
                                 b"Content-Length: 0\r\n\r\n")
                except OSError:
                    pass
                finally:
                    conn.close()

        thread = threading.Thread(target=refuse, daemon=True, name="refuser")
        # LIFO, so the flag is set before the join that waits on it.
        self.addCleanup(thread.join, 3.0)
        self.addCleanup(stop.set)
        thread.start()

        config = self.config_for(
            server.port,
            proxy={"mode": "manual",
                   "url": "http://%s:%d" % (_LOOPBACK, refused_port)})
        endpoint = self.start_endpoint(config)

        self.wait_connected(server)
        self.assertEqual(endpoint.status()["egress"], "direct")


class TestAnUnreachableTarget(TunnelEndpointTestCase):
    def unreachable(self, server, failure, atyp=ATYP_IPV4,
                    address=_LOOPBACK, port=1):
        """Ask for a target that cannot be reached, and read the answer."""
        factory = TunnelEndpoint
        if failure is not None:
            def factory(config):
                endpoint = _UnreachableEndpoint(config)
                endpoint.failure = failure
                return endpoint
        self.start_endpoint(self.config_for(server.port), factory=factory)
        self.wait_connected(server)
        stream = self.relay(server)
        reply = self.request(stream, CMD_CONNECT, atyp, address, port)[0]
        return reply, stream

    def test_connection_refused_becomes_socks_reply_05(self):
        server = self.start_server()
        reply, stream = self.unreachable(server, None, port=_free_port())
        self.assertEqual(reply, REPLY_CONNECTION_REFUSED)
        # And the session is over rather than left half-open: an operator's
        # tool waiting on a refused connection is the failure this answers.
        self.assertEqual(stream.recv(16), b"")

    def test_no_route_becomes_socks_reply_03(self):
        server = self.start_server()
        reply, stream = self.unreachable(
            server, OSError(errno.ENETUNREACH, "Network is unreachable"))
        self.assertEqual(reply, REPLY_NETWORK_UNREACHABLE)
        self.assertEqual(stream.recv(16), b"")

    def test_unresolvable_name_becomes_socks_reply_04(self):
        server = self.start_server()
        reply, stream = self.unreachable(server, None, atyp=ATYP_DOMAIN,
                                         address=_UNRESOLVABLE, port=80)
        self.assertEqual(reply, REPLY_HOST_UNREACHABLE)
        self.assertEqual(stream.recv(16), b"")

    def test_a_connect_that_hangs_past_the_timeout_closes_the_session(self):
        server = self.start_server()
        reply, stream = self.unreachable(
            server, socket.timeout("timed out"))
        self.assertEqual(reply, REPLY_TTL_EXPIRED)
        self.assertEqual(stream.recv(16), b"")

    def test_an_unmapped_errno_becomes_the_general_failure_reply(self):
        server = self.start_server()
        reply = self.unreachable(
            server, OSError(errno.EPIPE, "Broken pipe"))[0]
        self.assertEqual(reply, beacon_mod.REPLY_GENERAL_FAILURE)

    def test_bind_and_udp_associate_are_refused_with_the_right_code(self):
        server = self.start_server()
        self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)
        for cmd in (beacon_mod.CMD_BIND, beacon_mod.CMD_UDP_ASSOCIATE):
            with self.subTest(cmd=cmd):
                stream = self.relay(server)
                reply = self.request(stream, cmd, ATYP_IPV4, _LOOPBACK,
                                     9)[0]
                self.assertEqual(reply,
                                 beacon_mod.REPLY_COMMAND_NOT_SUPPORTED)


class TestTheThroughputGate(TunnelEndpointTestCase):
    def test_pure_python_aes_refuses_to_start_and_says_why(self):
        self.pure_python_aes(True)
        server = self.start_server()
        endpoint = TunnelEndpoint(self.config_for(server.port))
        self.addCleanup(endpoint.stop)

        with self.assertRaises(RuntimeError) as caught:
            endpoint.run()
        message = str(caught.exception)
        self.assertIn("allow_slow_crypto", message)
        self.assertIn("KB/s", message)
        # It refused before connecting, so nothing registered.
        self.assertEqual(server.endpoints(), [])

    def test_the_override_lets_it_start_and_the_status_reports_the_slow_path(
            self):
        self.pure_python_aes(True)
        server = self.start_server()
        endpoint = self.start_endpoint(
            self.config_for(server.port, allow_slow_crypto=True))

        row = self.wait_connected(server)
        self.assertEqual(row["crypto"], "pure-python")
        status = endpoint.status()
        self.assertEqual(status["crypto"], "pure-python")
        self.assertTrue(status["slow_crypto_allowed"])

    def test_the_fast_path_needs_no_override(self):
        if beacon_mod._USE_PURE_PYTHON_AES:
            self.skipTest("this host has no libcrypto, so there is no fast "
                          "path to assert on")
        server = self.start_server()
        endpoint = self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)
        self.assertEqual(endpoint.status()["crypto"], "openssl")


class TestLifecycle(TunnelEndpointTestCase):
    """`stop` is final, and final before `run` as well as during it.

    Task 8 is the consumer that owns this: it starts the endpoint on a
    thread and stops it on a command, so a `stop` arriving in the
    milliseconds between `thread.start()` and `run`'s first line is an
    ordinary event and not a contrived one. These tests do not race for
    it -- they set the flag first and then require `run` to honour it,
    which is the same property without the timing.
    """

    def test_stop_before_run_keeps_the_endpoint_from_dialling(self):
        server = self.start_server()
        endpoint = TunnelEndpoint(self.config_for(server.port))
        endpoint.stop()

        ended = threading.Event()

        def once():
            endpoint.run()
            ended.set()

        thread = threading.Thread(target=once, name="endpoint", daemon=True)
        self.addCleanup(self.assert_ended, thread)
        self.addCleanup(thread.join, 5.0)
        thread.start()

        self.assertTrue(
            ended.wait(5.0),
            "run() did not return after a stop() that preceded it; a run "
            "that clears the flag reconnects for ever instead")
        self.assertEqual(server.endpoints(), [],
                         "the endpoint dialled out after it had been stopped")
        self.assertFalse(endpoint.status()["connected"])

    def test_stop_is_safe_twice_and_after_a_session(self):
        server = self.start_server()
        endpoint = self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)

        endpoint.stop()
        endpoint.stop()
        self.assertFalse(endpoint.status()["connected"])


class TestTheNtlmRoute(TunnelEndpointTestCase):
    """`_ntlm_route`, with no NTLM upstream in sight.

    `_NtlmProxyRelay.start()` binds its loopback port before it returns
    and touches the upstream only when a CONNECT arrives, so the route it
    offers can be asserted without a proxy that speaks NTLM at all. What
    is under test is this class's half of the wiring: that the config keys
    are read, that the local relay is put ahead of `proxy.url`, that a
    config with no credentials yields no route rather than a relay that
    could never authenticate, and that `stop` takes the relay's port with
    it. Everything from `_dial_route` onward is the same code the stub
    CONNECT proxy tests above already carry traffic through.
    """

    def endpoint(self, ntlm, url=""):
        proxy = {"mode": "manual", "url": url, "ntlm": ntlm}
        # Port 1234 is never dialled here: nothing in this class connects.
        endpoint = TunnelEndpoint(self.config_for(1234, proxy=proxy))
        self.addCleanup(endpoint.stop)
        return endpoint

    @staticmethod
    def _refuses(port):
        """True once nothing is listening on `port`."""
        try:
            sock = socket.create_connection((_LOOPBACK, port), timeout=1.0)
        except OSError:
            return True
        sock.close()
        return False

    def test_an_ntlm_upstream_becomes_the_first_way_out(self):
        endpoint = self.endpoint(
            {"enabled": True, "host": "proxy.corp.invalid", "port": 8080,
             "username": "CORP\\operator", "password": "not-a-real-secret"},
            url="http://%s:3128" % _LOOPBACK)

        # `_configured_routes` rather than `_routes`, so that asserting on
        # the order does not also run proxy discovery, which shells out
        # and resolves names on whatever host this is.
        routes = endpoint._configured_routes()
        self.assertEqual(len(routes), 2)
        host, port = routes[0]
        self.assertEqual(host, _LOOPBACK)
        self.assertNotEqual(port, 0)
        # The local relay and not the configured proxy: a build told to
        # authenticate with NTLM has to reach the upstream through the
        # thing that can do it, and `proxy.url` is the fallback behind it.
        self.assertNotEqual(port, 3128)
        self.assertEqual(routes[1], (_LOOPBACK, 3128))
        # Asked twice, the same relay: one local port per endpoint.
        self.assertEqual(endpoint._configured_routes(), routes)

        endpoint.stop()
        self.wait_for(lambda: self._refuses(port), timeout=5.0,
                      what="the NTLM relay's port closing with its endpoint")

    def test_ntlm_without_credentials_offers_no_route(self):
        endpoint = self.endpoint({"enabled": True,
                                  "host": "proxy.corp.invalid"},
                                 url="http://%s:3128" % _LOOPBACK)
        self.assertEqual(endpoint._configured_routes(), [(_LOOPBACK, 3128)])

    def test_ntlm_disabled_offers_no_route(self):
        endpoint = self.endpoint({"enabled": False, "host": "proxy.corp",
                                  "username": "u", "password": "p"},
                                 url="http://%s:3128" % _LOOPBACK)
        self.assertEqual(endpoint._configured_routes(), [(_LOOPBACK, 3128)])


class TestConfigProblems(TunnelEndpointTestCase):
    def good(self):
        return self.config_for(1234)

    def test_a_complete_config_has_no_problem(self):
        self.assertIsNone(tunnel_config_problem(self.good()))

    def test_config_problem_names_the_missing_field(self):
        for field in ("server", "port", "public_key", "psk", "identity"):
            with self.subTest(field=field):
                config = self.good()
                del config["c2"]["tunnel"][field]
                problem = tunnel_config_problem(config)
                self.assertIsNotNone(problem,
                                     "a config missing %r was accepted"
                                     % field)
                self.assertIn("c2.tunnel." + field, problem)

    def test_a_disabled_or_absent_tunnel_is_not_a_problem(self):
        config = self.good()
        config["c2"]["tunnel"]["enabled"] = False
        del config["c2"]["tunnel"]["server"]
        self.assertIsNone(tunnel_config_problem(config))
        self.assertIsNone(tunnel_config_problem({"c2": {}}))
        self.assertIsNone(tunnel_config_problem({}))
        self.assertIsNone(tunnel_config_problem(None))

    def test_a_key_that_is_not_32_bytes_is_named_and_not_echoed(self):
        for field in ("public_key", "psk"):
            for value in (base64.b64encode(os.urandom(31)).decode("ascii"),
                          "not base64 at all!!"):
                with self.subTest(field=field, value=value):
                    config = self.good()
                    config["c2"]["tunnel"][field] = value
                    problem = tunnel_config_problem(config)
                    self.assertIsNotNone(problem)
                    self.assertIn("c2.tunnel." + field, problem)
                    self.assertNotIn(value, problem)

    def test_a_port_that_is_not_a_port_is_named(self):
        for value in (0, 70000, "https", True, None):
            with self.subTest(value=value):
                config = self.good()
                config["c2"]["tunnel"]["port"] = value
                problem = tunnel_config_problem(config)
                self.assertIsNotNone(problem,
                                     "port %r was accepted" % (value,))
                self.assertIn("c2.tunnel.port", problem)

    def test_the_endpoint_refuses_a_config_it_cannot_run(self):
        config = self.good()
        del config["c2"]["tunnel"]["psk"]
        with self.assertRaises(ValueError) as caught:
            TunnelEndpoint(config)
        self.assertIn("c2.tunnel.psk", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
