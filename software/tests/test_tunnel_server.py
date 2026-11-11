#!/usr/bin/env python3
"""
Unit tests for the tunnel server: one port that serves both a command
channel and a relay, with the role of a connection read from inside the
encryption.

Five things these tests are careful about.

**Every client here speaks the real protocol.** There is no mock of a
Noise session and no mock of a socket: a test endpoint is a real
`NoiseSession.initiator` over a real TCP connection to a real listener,
which is the pattern `test_listeners.py` sets out. A mocked handshake
would pass against a server that never authenticated anybody.

**The silence tests prove silence.** Each one sends its garbage, then
reads until the socket closes and asserts the bytes read are empty --
not that the read "did not return something recognisable". The published
original answered every connection on its port with the two bytes
`00 00`, and that is how its infrastructure was enumerated across
hosting providers with a single scan, so "nothing came back" is the
property under test and it is asserted as an empty read.
`test_random_bytes_get_no_deterministic_reply` sends the *same* bytes
twice and asserts both reads were empty, because a server that answered
one probe in three would still be fingerprintable.

**A reset counts as no reply, and nothing else does.** A peer that
closes while bytes it never read are still in its receive buffer gets an
RST rather than a FIN, which surfaces here as `ConnectionResetError`. An
RST carries no application bytes, so it is recorded as an empty read --
but any byte the server actually sent would have arrived before it.

**The restart test restarts.** It stops the server and constructs a new
one over the same `state_path`, because a `reload()` call would test a
method rather than the property that makes a SOCKS port stable, which is
the file.

**No thread may die quietly.** `setUp` installs a `threading.excepthook`
and a handler on the server's logger, and the last cleanup to run asserts
that no thread raised and that nothing was logged at ERROR or above. An
accept loop that survives a hostile probe by crashing a worker would
otherwise pass every assertion in this file.
"""

import json
import logging
import os
import queue
import socket
import stat
import tempfile
import threading
import time
import unittest
from unittest import mock

from software.c2.tunnel.keys import KeyStore
from software.c2.tunnel.protocol import (
    MSG_CLOSE,
    MSG_HELLO,
    MSG_OPEN_RELAY,
    MSG_OPEN_SHELL,
    MSG_PING,
    MSG_PONG,
    MSG_RELAY,
    MSG_SHELL,
    NoiseSession,
    decode_message,
    encode_message,
    SHELL_DEFAULT_COLS,
    SHELL_DEFAULT_ROWS,
    TUNNEL_FEATURES,
    read_frame,
    write_frame,
)
from software.c2.tunnel.server import TunnelServer

# The range SOCKS ports are assigned from. Nothing in this task binds one
# -- the assignment is recorded in the port table and a later task opens
# the port -- so a fixed range here is a pair of numbers in a JSON file
# and not a port in a test. The listener itself always binds port 0.
_PORT_RANGE = (40100, 40199)

# A real TLS 1.0 record header followed by a ClientHello handshake header.
# Its first two bytes, 16 03, are a length prefix of 5635 to this protocol,
# so it is also the shape of a frame whose body never arrives.
_TLS_CLIENT_HELLO = (
    b"\x16\x03\x01\x00\x75\x01\x00\x00\x71\x03\x03"
    + b"\x2a" * 32
    + b"\x00\x00\x04\x00\x2f\x00\x35\x01\x00"
)


def _drain(sock, timeout=1.0):
    """Everything the peer sent before it closed. Empty means it said nothing."""
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            # The server is still holding the connection open. That is a
            # failure of boundedness, reported by the caller, but whatever
            # arrived so far is what it said.
            return b"".join(chunks), False
        except ConnectionResetError:
            # An RST, which carries no application bytes. Anything the
            # server had sent would already be in `chunks`.
            return b"".join(chunks), True
        if not chunk:
            return b"".join(chunks), True
        chunks.append(chunk)


class _Peer(object):
    """One client connection, speaking the protocol the endpoint speaks."""

    def __init__(self, host, port, server_public, psk, timeout=10.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self._noise = NoiseSession.initiator(server_public, psk)

    def handshake(self, payload):
        """Message 1 carrying `payload`, then message 2 back."""
        self.send_first(payload)
        self._noise.complete(read_frame(self.sock))

    def send_first(self, payload):
        """Message 1 only, for a peer whose message 2 is never going to come."""
        write_frame(self.sock, self._noise.initiate(payload))

    def send_message(self, kind, body):
        write_frame(self.sock, self._noise.encrypt(encode_message(kind, body)))

    def recv_message(self):
        return decode_message(self._noise.decrypt(read_frame(self.sock)))

    def send_raw(self, data):
        write_frame(self.sock, self._noise.encrypt(data))

    def recv_raw(self):
        return self._noise.decrypt(read_frame(self.sock))

    def close(self):
        # Shut the descriptor down rather than only closing it, so a pump
        # thread blocked in `recv` wakes now instead of on its timeout.
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class _CommandPeer(_Peer):
    """A command channel, optionally with the keep-alive pump an endpoint runs."""

    def __init__(self, *args, **kwargs):
        _Peer.__init__(self, *args, **kwargs)
        self.opens = queue.Queue()
        self.shells = queue.Queue()
        self._stop = threading.Event()
        self._thread = None

    def hello(self, identity, implant_id=None, hostname="raccoon-host",
              os_name="Linux-6.1", features=None):
        body = {"identity": identity, "hostname": hostname, "os": os_name}
        if implant_id is not None:
            body["implant_id"] = implant_id
        # Left out entirely when None: an endpoint built before the shell
        # sends no `features` key at all, and that is the case to cover.
        if features is not None:
            body["features"] = features
        self.handshake(encode_message(MSG_HELLO, body))

    def start_pump(self):
        """Answer PING with PONG and queue OPEN_RELAY, as an endpoint does."""
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def next_open_relay(self, timeout=5.0):
        return self.opens.get(timeout=timeout)

    def next_open_shell(self, timeout=5.0):
        return self.shells.get(timeout=timeout)

    def _run(self):
        while not self._stop.is_set():
            try:
                # Peek on a short timeout rather than blocking on the read:
                # closing a socket does not wake a thread already inside
                # `recv` on macOS, so the pump has to come back and look at
                # the stop flag by itself or every test would pay a join
                # timeout at teardown.
                self.sock.settimeout(0.2)
                if not self.sock.recv(1, socket.MSG_PEEK):
                    return
                self.sock.settimeout(5.0)
                kind, body = self.recv_message()
            except socket.timeout:
                continue
            except (OSError, ValueError):
                return
            if kind == MSG_PING:
                try:
                    self.send_message(MSG_PONG, {})
                except (OSError, ValueError):
                    return
            elif kind == MSG_OPEN_RELAY:
                self.opens.put(body)
            elif kind == MSG_OPEN_SHELL:
                self.shells.put(body)

    def close(self):
        self._stop.set()
        _Peer.close(self)
        if self._thread is not None:
            self._thread.join(timeout=3.0)


class TunnelServerTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name
        self.state_path = os.path.join(self.root, "state", "tunnel_ports.json")
        self.keys_path = os.path.join(self.root, "keys", "tunnel_keys.json")
        self.store = KeyStore(self.keys_path)
        self.psks = {}
        for identity in ("build-alpha", "build-beta", "build-gamma"):
            psk = os.urandom(32)
            self.store.register_build(identity, psk)
            self.psks[identity] = psk
        self.public = self.store.static_public()

        # Registered first so it runs last: every other cleanup -- stopping
        # the server, closing the peers -- has to have happened before the
        # verdict on thread health is read.
        self.thread_errors = []
        self.log_records = []
        self.addCleanup(self._assert_nothing_broke_quietly)

        previous_hook = threading.excepthook
        threading.excepthook = self.thread_errors.append
        self.addCleanup(setattr, threading, "excepthook", previous_hook)

        handler = logging.Handler(level=logging.ERROR)
        handler.emit = self.log_records.append
        logger = logging.getLogger("raccoon.tunnel.server")
        logger.addHandler(handler)
        self.addCleanup(logger.removeHandler, handler)

    def _assert_nothing_broke_quietly(self):
        self.assertEqual(
            [getattr(args, "exc_value", args)
             for args in self.thread_errors], [],
            "a thread raised; the accept loop or a connection handler let an "
            "exception escape")
        self.assertEqual(
            [record.getMessage() for record in self.log_records], [],
            "something was logged at ERROR or above; an expected refusal is "
            "logged below that")

    # ── harness ──

    def start_server(self, **kwargs):
        # `port_range` is a positional in the constructor, so a test that
        # wants a different one passes it as a keyword here.
        port_range = kwargs.pop("port_range", _PORT_RANGE)
        options = {
            # Long enough that no test sees an unasked-for PING in its
            # stream; the keep-alive test sets its own.
            "keepalive_interval": 30.0,
            "idle_timeout": 5.0,
            "handshake_timeout": 0.5,
            "session_timeout": 5.0,
        }
        options.update(kwargs)
        server = TunnelServer(self.store, "127.0.0.1", 0, port_range,
                              self.state_path, **options)
        server.start()
        self.addCleanup(server.stop)
        return server

    def command_peer(self, server, identity, pump=False, **hello):
        peer = _CommandPeer("127.0.0.1", server.port, self.public,
                            self.psks[identity])
        self.addCleanup(peer.close)
        peer.hello(identity, **hello)
        if pump:
            peer.start_pump()
        self.wait_for(lambda: self.row(server, identity)["state"] == "connected")
        return peer

    def relay_peer(self, server, identity, token):
        peer = _Peer("127.0.0.1", server.port, self.public, self.psks[identity])
        self.addCleanup(peer.close)
        peer.handshake(encode_message(MSG_RELAY, {"token": token.hex()}))
        return peer

    def shell_peer(self, server, identity, token):
        peer = _Peer("127.0.0.1", server.port, self.public, self.psks[identity])
        self.addCleanup(peer.close)
        peer.handshake(encode_message(MSG_SHELL, {"token": token.hex()}))
        return peer

    def dial_relay(self, server, identity, token):
        """Open a relay connection, or None if the server refused it.

        Unlike `relay_peer` this tolerates a refusal, registers no cleanup
        and touches no `TestCase` state, because it is called from threads.
        """
        peer = _Peer("127.0.0.1", server.port, self.public,
                     self.psks[identity])
        try:
            peer.handshake(encode_message(MSG_RELAY, {"token": token.hex()}))
        except (OSError, ValueError):
            peer.close()
            return None
        return peer

    def probe(self, server, data=b"", timeout=1.0):
        """Open a connection, send `data`, and return what came back."""
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=10.0)
        self.addCleanup(sock.close)
        if data:
            sock.sendall(data)
        return _drain(sock, timeout=timeout)

    def row(self, server, identity):
        for row in server.endpoints():
            if row["identity"] == identity:
                return row
        return {"identity": identity, "state": "absent"}

    def wait_for(self, predicate, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return True
            time.sleep(0.01)
        self.fail("condition was still false after %.1fs" % timeout)


class TestRegistration(TunnelServerTestCase):
    def test_hello_registers_an_endpoint_and_assigns_a_stable_port(self):
        server = self.start_server()
        peer = self.command_peer(server, "build-alpha",
                                 implant_id="implant-aaaa")

        rows = server.endpoints()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["identity"], "build-alpha")
        self.assertEqual(row["state"], "connected")
        self.assertEqual(row["hostname"], "raccoon-host")
        self.assertEqual(row["os"], "Linux-6.1")
        self.assertEqual(row["implant_id"], "implant-aaaa")
        self.assertTrue(_PORT_RANGE[0] <= row["port"] <= _PORT_RANGE[1])
        self.assertEqual(row["sessions"], 0)

        # Asking twice does not re-point the port, and the port the panel
        # reads is the port on disk.
        self.assertEqual(self.row(server, "build-alpha")["port"], row["port"])
        with open(self.state_path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        self.assertEqual(document["ports"]["build-alpha"], row["port"])
        peer.close()

    def test_the_same_identity_gets_the_same_port_after_a_server_restart(self):
        first = self.start_server()
        self.assertTrue(first.is_serving())
        peer = self.command_peer(first, "build-alpha")
        assigned = self.row(first, "build-alpha")["port"]
        other = self.command_peer(first, "build-beta")
        beta_port = self.row(first, "build-beta")["port"]
        self.assertNotEqual(assigned, beta_port)
        peer.close()
        other.close()
        first.stop()
        self.assertFalse(first.is_serving())

        # A new server over the same file, binding port 0 again, because
        # the file is what makes the assignment stable and not the process.
        second = self.start_server()
        self.assertEqual(
            sorted(row["port"] for row in second.endpoints()),
            sorted([assigned, beta_port]))
        self.assertEqual(
            [row["state"] for row in second.endpoints()],
            ["disconnected", "disconnected"])
        self.command_peer(second, "build-alpha")
        self.assertEqual(self.row(second, "build-alpha")["port"], assigned)

    def test_a_second_connection_claiming_a_connected_identity_is_refused(self):
        server = self.start_server()
        first = self.command_peer(server, "build-alpha",
                                  implant_id="implant-aaaa")
        assigned = self.row(server, "build-alpha")["port"]

        with self.assertLogs("raccoon.tunnel.server", level="WARNING") as caught:
            second = _CommandPeer("127.0.0.1", server.port, self.public,
                                  self.psks["build-alpha"])
            self.addCleanup(second.close)
            second.send_first(
                encode_message(MSG_HELLO, {"identity": "build-alpha",
                                           "hostname": "impostor",
                                           "os": "Linux-6.1"}))
            received, closed = _drain(second.sock, timeout=2.0)

        self.assertEqual(received, b"")
        self.assertTrue(closed, "the refused connection was left open")
        # Both peers in the log line, so an operator can tell which host
        # arrived second.
        self.assertTrue(any("build-alpha" in line
                            for line in caught.output))

        # What matters is that the first channel is untouched: same row,
        # same port, still answering, and still able to carry a session.
        row = self.row(server, "build-alpha")
        self.assertEqual(row["state"], "connected")
        self.assertEqual(row["port"], assigned)
        self.assertEqual(row["hostname"], "raccoon-host")
        self.assertEqual(len(server.endpoints()), 1)
        first.send_message(MSG_PING, {})
        kind, _ = first.recv_message()
        self.assertEqual(kind, MSG_PONG)
        session = server.open_session("build-alpha")
        first.start_pump()
        self.assertEqual(first.next_open_relay()["token"], session.token.hex())

    def test_a_hello_claiming_another_builds_identity_is_refused(self):
        server = self.start_server()
        peer = _CommandPeer("127.0.0.1", server.port, self.public,
                            self.psks["build-beta"])
        self.addCleanup(peer.close)
        with self.assertLogs("raccoon.tunnel.server", level="WARNING"):
            peer.send_first(
                encode_message(MSG_HELLO, {"identity": "build-alpha",
                                           "hostname": "h", "os": "o"}))
            received, closed = _drain(peer.sock, timeout=2.0)
        self.assertEqual(received, b"")
        self.assertTrue(closed)
        self.assertEqual(server.endpoints(), [])

    def test_an_endpoint_whose_implant_id_matches_no_agent_is_reported_unlinked(self):
        known = {"implant-aaaa": "clever-raccoon"}
        server = self.start_server(agent_lookup=known.get)
        self.command_peer(server, "build-alpha", implant_id="implant-aaaa")
        self.command_peer(server, "build-beta", implant_id="implant-nobody")
        self.command_peer(server, "build-gamma")

        rows = {row["identity"]: row for row in server.endpoints()}
        self.assertEqual(sorted(rows),
                         ["build-alpha", "build-beta", "build-gamma"])
        self.assertEqual(rows["build-alpha"]["agent"], "clever-raccoon")
        self.assertTrue(rows["build-alpha"]["linked"])
        # Unlinked, and still a row: on the Pi systemd starts the endpoint
        # with no beacon above it, which is a supported deployment.
        self.assertIsNone(rows["build-beta"]["agent"])
        self.assertFalse(rows["build-beta"]["linked"])
        self.assertEqual(rows["build-beta"]["implant_id"], "implant-nobody")
        self.assertIsNone(rows["build-gamma"]["agent"])
        self.assertFalse(rows["build-gamma"]["linked"])
        self.assertIsNone(rows["build-gamma"]["implant_id"])

    def test_a_range_with_no_free_port_refuses_the_endpoint_rather_than_sharing_one(self):
        server = self.start_server(port_range=(40100, 40100))
        self.command_peer(server, "build-alpha")
        peer = _CommandPeer("127.0.0.1", server.port, self.public,
                            self.psks["build-beta"])
        self.addCleanup(peer.close)
        with self.assertLogs("raccoon.tunnel.server", level="WARNING"):
            peer.send_first(
                encode_message(MSG_HELLO, {"identity": "build-beta",
                                           "hostname": "h", "os": "o"}))
            received, closed = _drain(peer.sock, timeout=2.0)
        self.assertEqual(received, b"")
        self.assertTrue(closed)
        self.assertEqual([row["identity"] for row in server.endpoints()],
                         ["build-alpha"])


_SHELL_RANGE = (40300, 40399)


class TestTheShellPortTable(TunnelServerTestCase):
    """A second table beside the SOCKS one, which must never cost it anything.

    The SOCKS port is part of the registration -- no port, no tunnel. The
    shell port is a feature on top of a tunnel that already works, so every
    way it can be unavailable has to leave the registration, the SOCKS port
    and the traffic exactly as they were.
    """

    def write_state(self, text):
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        with open(self.state_path, "w", encoding="utf-8") as handle:
            handle.write(text)

    def build(self, **kwargs):
        return TunnelServer(self.store, "127.0.0.1", 0, _PORT_RANGE,
                            self.state_path, **kwargs)

    def test_a_shell_port_is_stable_across_a_restart(self):
        first = self.start_server(shell_port_range=_SHELL_RANGE)
        self.command_peer(first, "build-alpha")
        self.command_peer(first, "build-beta")
        rows = {row["identity"]: row for row in first.endpoints()}
        alpha, beta = rows["build-alpha"], rows["build-beta"]
        for row in (alpha, beta):
            self.assertTrue(_SHELL_RANGE[0] <= row["shell_port"]
                            <= _SHELL_RANGE[1])
            self.assertEqual(row["shell_detail"], "")
        self.assertNotEqual(alpha["shell_port"], beta["shell_port"])
        first.stop()

        # Even with the range moved away: an identity that has a port keeps
        # it, the same rule the SOCKS table follows.
        second = self.start_server(shell_port_range=(50300, 50399))
        after = {row["identity"]: row for row in second.endpoints()}
        self.assertEqual(after["build-alpha"]["shell_port"],
                         alpha["shell_port"])
        self.assertEqual(after["build-beta"]["shell_port"],
                         beta["shell_port"])
        self.command_peer(second, "build-alpha")
        self.assertEqual(self.row(second, "build-alpha")["shell_port"],
                         alpha["shell_port"])
        with open(self.state_path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        self.assertEqual(document["version"], 2)
        self.assertEqual(document["shell_ports"]["build-alpha"],
                         alpha["shell_port"])
        self.assertEqual(stat.S_IMODE(os.stat(self.state_path).st_mode), 0o600)

    def test_a_server_with_no_shell_range_assigns_none_and_says_why(self):
        server = self.build()
        self.assertIsNone(server.shell_first_port)
        self.assertIsNone(server.shell_last_port)
        with server._lock:
            self.assertIsNone(server._assign_shell_port("build-alpha"))

        server = self.start_server()
        self.command_peer(server, "build-alpha")
        row = self.row(server, "build-alpha")
        self.assertEqual(row["state"], "connected")
        self.assertIsNotNone(row["port"])
        self.assertIsNone(row["shell_port"])
        self.assertIn("shell_port_range", row["shell_detail"])
        with open(self.state_path, "r", encoding="utf-8") as handle:
            self.assertEqual(json.load(handle)["shell_ports"], {})

    def test_an_exhausted_shell_range_leaves_registration_and_the_socks_port_intact(self):
        server = self.start_server(shell_port_range=(40300, 40300))
        self.command_peer(server, "build-alpha")
        with self.assertLogs("raccoon.tunnel.server", level="WARNING") as caught:
            peer = self.command_peer(server, "build-beta", pump=True)
        self.assertTrue(any("shell port" in line and "build-beta" in line
                            for line in caught.output))

        alpha = self.row(server, "build-alpha")
        beta = self.row(server, "build-beta")
        self.assertEqual(alpha["shell_port"], 40300)
        self.assertEqual(beta["state"], "connected")
        self.assertTrue(_PORT_RANGE[0] <= beta["port"] <= _PORT_RANGE[1])
        self.assertIsNone(beta["shell_port"])
        self.assertIn("40300-40300", beta["shell_detail"])

        # And the pivot still works end to end for the identity that lost
        # out on the shell port.
        session = server.open_session("build-beta")
        self.assertEqual(peer.next_open_relay()["token"], session.token.hex())

    def test_a_shell_port_that_cannot_be_written_does_not_raise(self):
        server = self.build(shell_port_range=_SHELL_RANGE)
        with server._lock:
            server._ports["build-alpha"] = 40100
            with mock.patch.object(server, "_write_state",
                                   side_effect=OSError("disk full")):
                self.assertIsNone(server._assign_shell_port("build-alpha"))
            self.assertEqual(server._shell_ports, {})
        self.assertIn("disk full", server.endpoints()[0]["shell_detail"])

    def test_a_state_document_from_version_one_loads_with_an_empty_shell_table(self):
        self.write_state('{"version": 1, "ports": {"build-alpha": 40100}}')
        server = self.build(shell_port_range=_SHELL_RANGE)
        rows = server.endpoints()
        self.assertEqual([row["identity"] for row in rows], ["build-alpha"])
        self.assertEqual(rows[0]["port"], 40100)
        self.assertIsNone(rows[0]["shell_port"])
        self.assertNotEqual(rows[0]["shell_detail"], "")

        # And it upgrades in place the next time the identity registers.
        server.start()
        self.addCleanup(server.stop)
        self.command_peer(server, "build-alpha")
        row = self.row(server, "build-alpha")
        self.assertEqual(row["port"], 40100)
        self.assertTrue(_SHELL_RANGE[0] <= row["shell_port"] <= _SHELL_RANGE[1])

    def test_a_shell_port_colliding_with_an_assigned_port_is_refused_by_field_name(self):
        self.write_state('{"version": 2, "ports": {"build-alpha": 40100}, '
                         '"shell_ports": {"build-beta": 40100}}')
        with self.assertRaises(ValueError) as caught:
            self.build()
        message = str(caught.exception)
        self.assertIn("shell_ports[", message)
        self.assertIn("build-beta", message)
        self.assertIn("40100", message)
        self.assertIn(self.state_path, message)

        self.write_state('{"version": 2, "ports": {}, "shell_ports": '
                         '{"build-alpha": 40300, "build-beta": 40300}}')
        with self.assertRaises(ValueError) as caught:
            self.build()
        self.assertIn("shell_ports[", str(caught.exception))
        self.assertIn(self.state_path, str(caught.exception))

    def test_a_damaged_shell_port_entry_is_refused_by_field_name(self):
        for entry in ('70000', '"40300"', 'true', '0'):
            self.write_state('{"version": 2, "ports": {}, '
                             '"shell_ports": {"build-alpha": %s}}' % entry)
            with self.assertRaises(ValueError) as caught:
                self.build()
            message = str(caught.exception)
            self.assertIn("shell_ports[", message, entry)
            self.assertIn("build-alpha", message, entry)
            self.assertIn(self.state_path, message, entry)

        self.write_state('{"version": 2, "ports": {}, "shell_ports": []}')
        with self.assertRaises(ValueError) as caught:
            self.build()
        self.assertIn("shell_ports", str(caught.exception))
        self.assertIn(self.state_path, str(caught.exception))

    def test_overlapping_ranges_are_refused_naming_both_fields(self):
        for shell_range in ((40150, 40250), (40000, 40100), (40199, 40300),
                            (40120, 40130), (40000, 40500)):
            with self.assertRaises(ValueError, msg=shell_range) as caught:
                self.build(shell_port_range=shell_range)
            message = str(caught.exception)
            self.assertIn("shell_port_range", message)
            self.assertIn("port_range", message)
            self.assertIn("%d-%d" % shell_range, message)
            self.assertIn("%d-%d" % _PORT_RANGE, message)
        # Adjacent is not overlapping.
        self.build(shell_port_range=(40200, 40299))
        self.build(shell_port_range=(40000, 40099))

    def test_every_identity_gets_both_ports_when_the_ranges_are_disjoint(self):
        server = self.start_server(port_range=(40100, 40102),
                                   shell_port_range=(40103, 40105))
        for identity in ("build-alpha", "build-beta", "build-gamma"):
            self.command_peer(server, identity)
        rows = server.endpoints()
        self.assertEqual([row["state"] for row in rows], ["connected"] * 3)
        self.assertEqual(sorted(row["port"] for row in rows),
                         [40100, 40101, 40102])
        self.assertEqual(sorted(row["shell_port"] for row in rows),
                         [40103, 40104, 40105])

    def test_a_shell_port_is_never_assigned_a_port_a_socks_entry_holds(self):
        self.write_state('{"version": 2, "ports": {"build-alpha": 40300}, '
                         '"shell_ports": {}}')
        server = self.build(shell_port_range=(40300, 40301))
        with server._lock:
            self.assertEqual(server._assign_shell_port("build-beta"), 40301)
            self.assertIsNone(server._assign_shell_port("build-gamma"))

    def test_a_socks_port_is_never_assigned_a_port_a_shell_already_holds(self):
        self.write_state('{"version": 2, "ports": {}, '
                         '"shell_ports": {"build-alpha": 40100}}')
        server = self.build()
        with server._lock:
            self.assertEqual(server._assign_port("build-beta"), 40101)


class TestAMalformedPortTable(TunnelServerTestCase):
    """A damaged table means a SOCKS port is about to move, so it is an error.

    Each case writes a table that is wrong in exactly one way and asserts
    the message names both the file and the field -- "your tunnel state is
    bad" is not something an operator can act on at the moment a server
    refuses to start.
    """

    def write_state(self, text):
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        with open(self.state_path, "w", encoding="utf-8") as handle:
            handle.write(text)

    def build(self):
        return TunnelServer(self.store, "127.0.0.1", 0, _PORT_RANGE,
                            self.state_path)

    def test_a_table_that_is_not_json_is_refused_by_name(self):
        self.write_state("{not json")
        with self.assertRaises(ValueError) as caught:
            self.build()
        self.assertIn(self.state_path, str(caught.exception))
        self.assertIn("(file)", str(caught.exception))

    def test_a_table_without_a_ports_object_is_refused(self):
        self.write_state('{"version": 1, "ports": []}')
        with self.assertRaises(ValueError) as caught:
            self.build()
        self.assertIn("ports", str(caught.exception))

    def test_a_port_that_is_not_a_port_is_refused_by_field(self):
        self.write_state('{"version": 1, "ports": {"build-alpha": 70000}}')
        with self.assertRaises(ValueError) as caught:
            self.build()
        self.assertIn("build-alpha", str(caught.exception))
        self.assertIn("70000", str(caught.exception))

    def test_two_identities_sharing_one_port_is_refused(self):
        self.write_state('{"version": 1, '
                         '"ports": {"build-alpha": 40100, "build-beta": 40100}}')
        with self.assertRaises(ValueError) as caught:
            self.build()
        self.assertIn("40100", str(caught.exception))
        self.assertIn("build-alpha", str(caught.exception))

    def test_a_missing_table_is_not_an_error(self):
        self.assertFalse(os.path.exists(self.state_path))
        self.assertEqual(self.build().endpoints(), [])


class TestRelayPairing(TunnelServerTestCase):
    def test_relay_with_the_issued_token_is_paired_to_its_session(self):
        server = self.start_server()
        peer = self.command_peer(server, "build-alpha", pump=True)

        session = server.open_session("build-alpha")
        self.assertEqual(len(session.token), 32)
        instruction = peer.next_open_relay()
        self.assertEqual(instruction["token"], session.token.hex())
        # The same port the command channel already came in on: one
        # destination, because a second one would not cross a CONNECT proxy.
        self.assertEqual(instruction["port"], server.port)

        relay = self.relay_peer(server, "build-alpha", session.token)
        self.assertTrue(session.wait_paired(5.0))

        session.sock.sendall(b"down the tunnel")
        self.assertEqual(relay.recv_raw(), b"down the tunnel")
        relay.send_raw(b"back up the tunnel")
        self.assertEqual(session.sock.recv(64), b"back up the tunnel")

        self.assertEqual(self.row(server, "build-alpha")["sessions"], 1)
        states = [row["state"] for row in server.status()]
        self.assertEqual(states, ["paired"])
        session.close()
        self.wait_for(lambda: self.row(server, "build-alpha")["sessions"] == 0)

    def test_relay_with_an_unknown_token_is_refused_and_the_session_stays_open(self):
        server = self.start_server()
        peer = self.command_peer(server, "build-alpha", pump=True)
        session = server.open_session("build-alpha")
        peer.next_open_relay()

        impostor = _Peer("127.0.0.1", server.port, self.public,
                         self.psks["build-alpha"])
        self.addCleanup(impostor.close)
        impostor.send_first(
            encode_message(MSG_RELAY, {"token": os.urandom(32).hex()}))
        received, closed = _drain(impostor.sock, timeout=2.0)
        self.assertEqual(received, b"")
        self.assertTrue(closed)

        self.assertFalse(session.wait_paired(0.2))
        self.assertEqual([row["state"] for row in server.status()], ["pending"])

        # And the session the operator is waiting on still takes its own
        # token afterwards.
        relay = self.relay_peer(server, "build-alpha", session.token)
        self.assertTrue(session.wait_paired(5.0))
        session.sock.sendall(b"still mine")
        self.assertEqual(relay.recv_raw(), b"still mine")

    def test_a_relay_token_cannot_be_used_by_another_build(self):
        server = self.start_server()
        peer = self.command_peer(server, "build-alpha", pump=True)
        self.command_peer(server, "build-beta", pump=True)
        session = server.open_session("build-alpha")
        peer.next_open_relay()

        thief = _Peer("127.0.0.1", server.port, self.public,
                      self.psks["build-beta"])
        self.addCleanup(thief.close)
        with self.assertLogs("raccoon.tunnel.server", level="WARNING") as caught:
            thief.send_first(
                encode_message(MSG_RELAY, {"token": session.token.hex()}))
            received, closed = _drain(thief.sock, timeout=2.0)
        self.assertEqual(received, b"")
        self.assertTrue(closed)
        self.assertFalse(session.wait_paired(0.2))
        self.assertTrue(any("build-beta" in line and "build-alpha" in line
                            for line in caught.output))

    def test_an_endpoint_that_sends_close_is_dropped_without_a_reply(self):
        server = self.start_server()
        peer = self.command_peer(server, "build-alpha")
        peer.send_message(MSG_CLOSE, {})
        received, closed = _drain(peer.sock, timeout=2.0)
        self.assertEqual(received, b"")
        self.assertTrue(closed)
        self.wait_for(
            lambda: self.row(server, "build-alpha")["state"] == "disconnected")

    def test_open_session_for_an_identity_with_no_channel_is_refused(self):
        server = self.start_server()
        with self.assertRaises(ValueError) as caught:
            server.open_session("build-alpha")
        self.assertIn("build-alpha", str(caught.exception))

    def test_a_session_that_is_never_paired_is_expired_rather_than_leaked(self):
        server = self.start_server(session_timeout=0.3)
        peer = self.command_peer(server, "build-alpha", pump=True)
        session = server.open_session("build-alpha")
        peer.next_open_relay()
        self.assertFalse(session.wait_paired(0.2))
        self.wait_for(lambda: server.status() == [])
        self.assertEqual(session.state, "expired")

    def test_a_relay_that_arrives_as_its_session_expires_is_not_lost(self):
        server = self.start_server(session_timeout=0.3)
        peer = self.command_peer(server, "build-alpha", pump=True)
        session = server.open_session("build-alpha")
        peer.next_open_relay()

        # The window is driven deliberately rather than hoped for: the hook
        # runs at the instant the expiry is applied and dials the relay
        # from another thread while it does. If the deadline check and the
        # write are not one critical section, the relay is claimed and
        # paired in between and then overwritten as expired -- a live,
        # spliced connection in no table at all, and an operator told the
        # pairing failed.
        arrived = []
        dialled = []
        expire = session._expire

        def expiring(why):
            thread = threading.Thread(
                target=lambda: arrived.append(
                    self.dial_relay(server, "build-alpha", session.token)),
                daemon=True)
            dialled.append(thread)
            thread.start()
            # Long enough for the dial to complete outright if nothing is
            # holding it off, which is what the unlocked version did.
            thread.join(0.5)
            expire(why)

        session._expire = expiring
        self.wait_for(lambda: session.state != "pending", timeout=5.0)
        for thread in dialled:
            thread.join(timeout=5.0)
            self.assertFalse(thread.is_alive())
        for peer_or_none in arrived:
            if peer_or_none is not None:
                self.addCleanup(peer_or_none.close)

        # The invariant, whichever side of the race won: a session is never
        # both expired and holding a live stream.
        self.assertEqual(len(arrived), 1)
        if session.sock is not None:
            self.assertEqual(session.state, "paired")
            self.assertTrue(session.wait_paired(0))
            self.assertIsNotNone(arrived[0])
        else:
            self.assertEqual(session.state, "expired")
            self.assertIsNone(arrived[0])
            self.assertFalse(session.wait_paired(0))

    def test_stop_returns_while_a_relay_consumer_is_parked_on_a_full_buffer(self):
        server = self.start_server()
        peer = self.command_peer(server, "build-alpha", pump=True)
        session = server.open_session("build-alpha")
        peer.next_open_relay()
        relay = self.relay_peer(server, "build-alpha", session.token)
        self.assertTrue(session.wait_paired(5.0))

        # The relay peer never reads, so ordinary TCP backpressure parks
        # the consumer inside write_frame holding the stream's write lock.
        # The stream has no socket timeout -- the consumer owns that -- so
        # nothing bounds the park but `stop`.
        broken = []

        def consumer():
            try:
                while True:
                    session.sock.sendall(b"x" * 32768)
            except (OSError, ValueError) as exc:
                broken.append(exc)

        writer = threading.Thread(target=consumer, daemon=True)
        writer.start()

        def parked():
            before = session.sock.bytes_out
            time.sleep(0.2)
            return writer.is_alive() and session.sock.bytes_out == before

        # Observed, not assumed: the test's precondition is that the
        # consumer really is blocked and holding the lock.
        self.wait_for(parked, timeout=15.0)

        stopper = threading.Thread(target=server.stop, daemon=True)
        stopper.start()
        stopper.join(timeout=10.0)
        blocked = stopper.is_alive()

        # Release the far end before asserting, so a regression fails this
        # test instead of hanging every cleanup behind it.
        relay.close()
        stopper.join(timeout=10.0)
        writer.join(timeout=5.0)

        self.assertFalse(blocked, "stop() queued behind a parked sendall")
        self.assertFalse(writer.is_alive(),
                         "the parked consumer was never unparked")
        self.assertTrue(broken, "the parked consumer saw no error")

    def test_endpoint_bytes_survive_the_session_that_carried_them(self):
        server = self.start_server()
        peer = self.command_peer(server, "build-alpha", pump=True)

        first = server.open_session("build-alpha")
        peer.next_open_relay()
        relay = self.relay_peer(server, "build-alpha", first.token)
        self.assertTrue(first.wait_paired(5.0))
        first.sock.sendall(b"a" * 100)
        self.assertEqual(relay.recv_raw(), b"a" * 100)
        relay.send_raw(b"b" * 40)
        self.assertEqual(first.sock.recv(128), b"b" * 40)

        row = self.row(server, "build-alpha")
        self.assertEqual((row["bytes_out"], row["bytes_in"]), (100, 40))

        # Closing the relay must not make the panel say nothing moved.
        first.close()
        relay.close()
        row = self.row(server, "build-alpha")
        self.assertEqual((row["bytes_out"], row["bytes_in"]), (100, 40))
        # And still not after the prune, which is where the hand-over to
        # the per-identity total happens -- once, not twice.
        self.wait_for(lambda: server.status() == [])
        row = self.row(server, "build-alpha")
        self.assertEqual((row["bytes_out"], row["bytes_in"]), (100, 40))
        self.assertEqual(row["sessions"], 0)

        # A second session adds to the total rather than replacing it.
        second = server.open_session("build-alpha")
        peer.next_open_relay()
        again = self.relay_peer(server, "build-alpha", second.token)
        self.assertTrue(second.wait_paired(5.0))
        second.sock.sendall(b"c" * 7)
        self.assertEqual(again.recv_raw(), b"c" * 7)
        row = self.row(server, "build-alpha")
        self.assertEqual((row["bytes_out"], row["bytes_in"]), (107, 40))
        self.assertEqual(row["sessions"], 1)


class TestShellSessions(TunnelServerTestCase):
    def shell_endpoint(self, server, identity="build-alpha", **hello):
        hello.setdefault("features", TUNNEL_FEATURES)
        return self.command_peer(server, identity, pump=True, **hello)

    def test_open_shell_session_sends_open_shell_with_a_token_and_the_geometry(self):
        server = self.start_server()
        peer = self.shell_endpoint(server)

        session = server.open_shell_session("build-alpha", cols=100, rows=30)
        self.assertEqual(session.kind, "shell")
        self.assertEqual(len(session.token), 32)
        instruction = peer.next_open_shell()
        self.assertEqual(instruction["token"], session.token.hex())
        self.assertEqual((instruction["cols"], instruction["rows"]), (100, 30))
        # The same advisory port a relay is told: one destination.
        self.assertEqual(instruction["port"], server.port)

        # Named by the codec's constants, so the defaults here are the
        # endpoint's and not a second pair that can drift.
        server.open_shell_session("build-alpha")
        instruction = peer.next_open_shell()
        self.assertEqual((instruction["cols"], instruction["rows"]),
                         (SHELL_DEFAULT_COLS, SHELL_DEFAULT_ROWS))
        # And nothing was sent as a relay.
        self.assertTrue(peer.opens.empty())

    def test_a_shell_claim_pairs_the_session_and_bytes_flow_both_ways(self):
        server = self.start_server()
        peer = self.shell_endpoint(server)
        session = server.open_shell_session("build-alpha")
        peer.next_open_shell()

        shell = self.shell_peer(server, "build-alpha", session.token)
        self.assertTrue(session.wait_paired(5.0))
        self.assertEqual(session.state, "paired")

        session.sock.sendall(b"ls -la\n")
        self.assertEqual(shell.recv_raw(), b"ls -la\n")
        shell.send_raw(b"total 0\n")
        self.assertEqual(session.sock.recv(64), b"total 0\n")

        self.assertEqual(self.row(server, "build-alpha")["sessions"], 1)
        session.close()
        self.wait_for(lambda: self.row(server, "build-alpha")["sessions"] == 0)

    def test_a_relay_token_cannot_claim_a_shell_session(self):
        server = self.start_server()
        peer = self.shell_endpoint(server)
        session = server.open_shell_session("build-alpha")
        peer.next_open_shell()

        impostor = _Peer("127.0.0.1", server.port, self.public,
                         self.psks["build-alpha"])
        self.addCleanup(impostor.close)
        with self.assertLogs("raccoon.tunnel.server", level="WARNING") as caught:
            impostor.send_first(
                encode_message(MSG_RELAY, {"token": session.token.hex()}))
            received, closed = _drain(impostor.sock, timeout=2.0)
        self.assertEqual(received, b"")
        self.assertTrue(closed)
        self.assertFalse(session.wait_paired(0.2))
        self.assertEqual(session.state, "pending")
        self.assertTrue(any("shell" in line and "relay" in line
                            for line in caught.output), caught.output)

        # The refusal did not spend the token: its own kind still takes it.
        shell = self.shell_peer(server, "build-alpha", session.token)
        self.assertTrue(session.wait_paired(5.0))
        session.sock.sendall(b"mine")
        self.assertEqual(shell.recv_raw(), b"mine")

    def test_a_shell_token_cannot_claim_a_relay(self):
        server = self.start_server()
        peer = self.shell_endpoint(server)
        session = server.open_session("build-alpha")
        peer.next_open_relay()

        impostor = _Peer("127.0.0.1", server.port, self.public,
                         self.psks["build-alpha"])
        self.addCleanup(impostor.close)
        with self.assertLogs("raccoon.tunnel.server", level="WARNING") as caught:
            impostor.send_first(
                encode_message(MSG_SHELL, {"token": session.token.hex()}))
            received, closed = _drain(impostor.sock, timeout=2.0)
        self.assertEqual(received, b"")
        self.assertTrue(closed)
        self.assertFalse(session.wait_paired(0.2))
        self.assertEqual(session.state, "pending")
        self.assertTrue(any("shell" in line and "relay" in line
                            for line in caught.output), caught.output)

        relay = self.relay_peer(server, "build-alpha", session.token)
        self.assertTrue(session.wait_paired(5.0))
        session.sock.sendall(b"mine")
        self.assertEqual(relay.recv_raw(), b"mine")

    def test_an_endpoint_that_advertised_no_shell_feature_is_refused(self):
        server = self.start_server()
        # No `features` key at all: an endpoint built before the shell.
        self.command_peer(server, "build-alpha", pump=True)
        with self.assertRaises(ValueError) as caught:
            server.open_shell_session("build-alpha")
        message = str(caught.exception)
        self.assertIn("build-alpha", message)
        self.assertIn("shell", message)
        # And marked, so the operator-facing front can tell this refusal
        # from "no endpoint is connected" without reading the wording: one
        # says replace the build, the other says wait for it to call home.
        self.assertTrue(getattr(caught.exception, "shell_unsupported",
                                False))

        # A features list that does not name it is the same answer.
        self.command_peer(server, "build-beta", pump=True, features=["other"])
        with self.assertRaises(ValueError) as caught:
            server.open_shell_session("build-beta")
        self.assertIn("shell", str(caught.exception))
        self.assertTrue(getattr(caught.exception, "shell_unsupported",
                                False))

    def test_open_shell_session_for_an_identity_with_no_channel_is_refused(self):
        server = self.start_server()
        with self.assertRaises(ValueError) as caught:
            server.open_shell_session("build-alpha")
        self.assertIn("build-alpha", str(caught.exception))
        # Not the feature refusal: nothing is wrong with this build, and a
        # front that treated the two alike would tell the operator to
        # rebuild an implant that has simply not called home yet.
        self.assertFalse(getattr(caught.exception, "shell_unsupported",
                                 False))

    def test_the_refusal_sends_nothing_on_the_command_channel(self):
        # An endpoint that meets a kind it does not know ends its control
        # loop, which drops the command channel and every session that
        # rode on it. So the property is on the channel itself: after the
        # refusal the next frame the endpoint reads is the answer to the
        # next thing *it* asks, not a stray OPEN_SHELL.
        server = self.start_server()
        # No pump: this peer reads the channel itself.
        peer = self.command_peer(server, "build-alpha")
        with self.assertRaises(ValueError):
            server.open_shell_session("build-alpha")

        peer.send_message(MSG_PING, {})
        peer.sock.settimeout(5.0)
        self.assertEqual(peer.recv_message(), (MSG_PONG, {}))

        # No token was minted either, so there is no session to expire.
        self.assertEqual(server.status(), [])
        self.assertEqual(self.row(server, "build-alpha")["state"], "connected")

    def test_a_hello_without_features_leaves_the_tuple_empty(self):
        server = self.start_server()
        old = self.command_peer(server, "build-alpha")
        self.command_peer(server, "build-beta", features=["shell"])
        self.assertEqual(self.row(server, "build-alpha")["features"], [])
        self.assertEqual(self.row(server, "build-beta")["features"], ["shell"])
        with server._lock:
            channel = server._channels["build-alpha"]
        self.assertEqual(channel.features, ())

        # A disconnected row reports no features: nothing here knows them.
        old.close()
        self.wait_for(
            lambda: self.row(server, "build-alpha")["state"] == "disconnected")
        self.assertEqual(self.row(server, "build-alpha")["features"], [])

    def test_a_malformed_features_value_reads_as_none(self):
        server = self.start_server()
        self.command_peer(server, "build-alpha", features="shell")
        with server._lock:
            channel = server._channels["build-alpha"]
        self.assertEqual(channel.features, ())

    def test_the_status_row_names_the_kind(self):
        server = self.start_server()
        peer = self.shell_endpoint(server)
        server.open_session("build-alpha")
        peer.next_open_relay()
        server.open_shell_session("build-alpha")
        peer.next_open_shell()
        self.assertEqual([row["kind"] for row in server.status()],
                         ["relay", "shell"])


class TestKeepAlive(TunnelServerTestCase):
    def test_ping_keeps_an_endpoint_alive_and_a_silent_one_ages_out(self):
        server = self.start_server(keepalive_interval=0.1, idle_timeout=0.5)
        alive = self.command_peer(server, "build-alpha", pump=True)
        silent = self.command_peer(server, "build-beta")

        # The silent endpoint never answers a PING, so it ages out on the
        # idle timer; the row stays, because the port is still its port.
        self.wait_for(
            lambda: self.row(server, "build-beta")["state"] == "disconnected",
            timeout=5.0)
        self.assertIsNotNone(self.row(server, "build-beta")["port"])

        # Three idle timeouts later the pumped one is still connected,
        # which it could only be by having answered.
        time.sleep(1.5)
        row = self.row(server, "build-alpha")
        self.assertEqual(row["state"], "connected")
        self.assertLess(row["last_seen_age"], 0.5)
        alive.close()
        silent.close()


class TestGarbageOnThePort(TunnelServerTestCase):
    def test_random_bytes_get_no_deterministic_reply(self):
        server = self.start_server()
        probe = os.urandom(48)
        first, first_closed = self.probe(server, probe, timeout=2.0)
        second, second_closed = self.probe(server, probe, timeout=2.0)
        self.assertEqual(first, b"")
        self.assertEqual(second, b"")
        self.assertEqual(first, second)
        self.assertTrue(first_closed and second_closed,
                        "a probe was left connected")
        # And the service is still there afterwards.
        self.command_peer(server, "build-alpha")

    def test_tls_client_hello_is_closed_without_a_reply(self):
        server = self.start_server()
        received, closed = self.probe(server, _TLS_CLIENT_HELLO, timeout=2.0)
        self.assertEqual(received, b"")
        self.assertTrue(closed)

    def test_immediate_fin_does_not_raise_in_the_accept_loop(self):
        server = self.start_server()
        for _ in range(5):
            sock = socket.create_connection(("127.0.0.1", server.port),
                                            timeout=10.0)
            sock.close()
        # The accept loop is still accepting, and the cleanup assertion at
        # the end of this test would have caught a dead worker thread.
        self.command_peer(server, "build-alpha")

    def test_a_connection_that_sends_nothing_is_closed_on_a_bounded_timer(self):
        server = self.start_server(handshake_timeout=0.3)
        started = time.time()
        received, closed = self.probe(server, b"", timeout=5.0)
        elapsed = time.time() - started
        self.assertEqual(received, b"")
        self.assertTrue(closed, "a silent connection was held open")
        self.assertGreater(elapsed, 0.2)
        self.assertLess(elapsed, 5.0)

    def test_a_frame_claiming_65535_bytes_that_never_arrives_is_bounded(self):
        server = self.start_server(handshake_timeout=0.3)
        started = time.time()
        received, closed = self.probe(server, b"\xff\xff", timeout=5.0)
        elapsed = time.time() - started
        self.assertEqual(received, b"")
        self.assertTrue(closed, "a frame that never arrived was waited on")
        self.assertLess(elapsed, 5.0)
        self.command_peer(server, "build-alpha")

    def test_a_peer_that_dribbles_bytes_is_dropped_on_an_absolute_timer(self):
        # The socket's own timeout is per-read, so a byte every 0.2s with a
        # 0.3s timeout would never trip it: a peer could hold a thread for
        # as long as it liked on a frame claiming 65535 bytes. The bound
        # has to be absolute, and this is what proves it is.
        server = self.start_server(handshake_timeout=0.3)
        sock = socket.create_connection(("127.0.0.1", server.port),
                                        timeout=10.0)
        self.addCleanup(sock.close)
        sock.sendall(b"\xff\xff")
        started = time.time()
        dribbled = 0
        try:
            for _ in range(20):
                time.sleep(0.2)
                sock.sendall(b"\x41")
                dribbled += 1
        except OSError:
            pass
        elapsed = time.time() - started
        received, closed = _drain(sock, timeout=2.0)
        self.assertEqual(received, b"")
        self.assertTrue(closed, "a dribbling peer was held open")
        self.assertLess(elapsed, 3.0,
                        "it took %d dribbles to be dropped" % dribbled)

    def test_a_forged_transport_frame_closes_the_channel(self):
        server = self.start_server()
        peer = self.command_peer(server, "build-alpha")
        # Authenticated, then one frame that will not decrypt. Noise's own
        # rule is that the session is abandoned after a decrypt failure,
        # and the session class leaves that to its caller.
        with self.assertLogs("raccoon.tunnel.server", level="WARNING"):
            write_frame(peer.sock, os.urandom(64))
            received, closed = _drain(peer.sock, timeout=2.0)
        self.assertEqual(received, b"")
        self.assertTrue(closed)
        self.wait_for(
            lambda: self.row(server, "build-alpha")["state"] == "disconnected")

    def test_a_damaged_key_store_drops_one_connection_and_not_the_loop(self):
        server = self.start_server()
        self.command_peer(server, "build-alpha")
        # The store fails closed: once the file is gone every call raises.
        # That must cost one connection, never the accept loop.
        with open(self.keys_path, "rb") as handle:
            saved = handle.read()
        os.unlink(self.keys_path)
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=10.0)
        self.addCleanup(sock.close)
        sock.sendall(b"\x00\x30" + os.urandom(48))
        received, closed = _drain(sock, timeout=2.0)
        self.assertEqual(received, b"")
        self.assertTrue(closed)
        # Put the store back and connect for real: the loop is still there.
        with open(self.keys_path, "wb") as handle:
            handle.write(saved)
        self.command_peer(server, "build-beta")


class TestNoBeaconKeyAnywhere(TunnelServerTestCase):
    _FORBIDDEN_FIELDS = ("encryption_key", "psk", "token", "secret",
                         "password", "private")

    def test_the_tunnel_server_never_reads_the_beacon_encryption_key(self):
        from software.c2.tunnel import server as server_mod

        with open(server_mod.__file__, "r", encoding="utf-8") as handle:
            source = handle.read()
        for name in ("encryption_key", "decode_key", "beacon_key_problem"):
            self.assertNotIn(
                name, source,
                "the tunnel server has no business with the beacon's "
                "symmetric key")

        server = self.start_server()
        self.command_peer(server, "build-alpha", implant_id="implant-aaaa")
        session = server.open_session("build-alpha")
        self.assertEqual(len(session.token), 32)

        with open(self.state_path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
        for document in [state] + server.endpoints() + server.status():
            self._assert_no_secret_fields(document)

    def _assert_no_secret_fields(self, document, path="(root)"):
        if isinstance(document, dict):
            for name, value in document.items():
                lowered = str(name).lower()
                for forbidden in self._FORBIDDEN_FIELDS:
                    self.assertNotIn(
                        forbidden, lowered,
                        "%s.%s is a field a screenshot must not carry"
                        % (path, name))
                self._assert_no_secret_fields(value, "%s.%s" % (path, name))
        elif isinstance(document, list):
            for index, value in enumerate(document):
                self._assert_no_secret_fields(value, "%s[%d]" % (path, index))

    def test_the_tunnel_package_does_not_import_ServerCrypto(self):
        import ast

        from software.c2 import tunnel

        package = os.path.dirname(tunnel.__file__)
        names = sorted(name for name in os.listdir(package)
                       if name.endswith(".py"))
        self.assertIn("server.py", names)
        for name in names:
            path = os.path.join(package, name)
            with open(path, "r", encoding="utf-8") as handle:
                source = handle.read()
            self.assertNotIn("ServerCrypto", source, path)
            for node in ast.walk(ast.parse(source, filename=path)):
                if isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    # `from ..server import x` is level 2 with module
                    # "server"; `from software.c2.server import x` is level 0.
                    #
                    # `.server` is deliberately NOT in the list below,
                    # though an earlier version of this test had it:
                    # inside this package a single dot is the package
                    # itself, so `from .server import TunnelServer` is the
                    # tunnel's own implant-facing server -- the module
                    # three lines above requires to exist. It never fired
                    # only because nothing imported it until
                    # `__main__.py` did, and then it failed a module for
                    # importing the thing this file is about. A check
                    # looser than the property it names eventually fires
                    # on something innocent.
                    #
                    # The names are checked as well as the module,
                    # because `from .. import server` and `from software.c2
                    # import server` put it there -- the shape
                    # `server.py`'s own `from .. import beacon` uses, and
                    # the one spelling the module field alone would miss.
                    base = "." * node.level + (node.module or "")
                    joined = base if base.endswith(".") else base + "."
                    modules = [base] + [joined + alias.name
                                        for alias in node.names]
                else:
                    continue
                for module in modules:
                    self.assertNotIn(
                        module,
                        ("software.c2.server", "..server"),
                        "%s imports the flask-bearing team server" % path)


if __name__ == "__main__":
    unittest.main()
