#!/usr/bin/env python3
"""Tests for the beacon's alternative transports and their listeners.

The beacon is the specification for every listener in this package: its
request builders are the only description of the wire format that exists.
So the tests here exercise the real client against the real
`ServerCrypto`, not a mock of either -- a mock would agree with whatever
the code does and prove nothing about the two sides matching.
"""

import base64
import io
import json
import logging
import os
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
import pathlib
import re
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from software.c2 import beacon as beacon_mod
from software.c2.beacon import Beacon, beacon_config_from_fallback
from software.c2.listeners.dns import DnsListener
from software.c2.listeners.quic import QuicListener
from software.c2.listeners.registry import ListenerSpec, load_listeners
from software.c2.listeners.supervisor import Supervisor, SupervisorError
from software.c2.listeners.smb import SmbListener
from software.c2.listeners.relay import relay
from software.c2.server import ServerCrypto
from tools import listener_lab as lab


def _read_source(*parts):
    """Read a file in the repository as text, for assertions about it."""
    return Path(__file__).resolve().parents[2].joinpath(*parts).read_text()


def _imports_and_names(*parts):
    """Every module a file imports, and every identifier it uses in code.

    Parsed with `ast` rather than grepped, so a module that explains in
    prose which packages it deliberately avoids does not fail a test about
    what it imports.
    """
    import ast
    tree = ast.parse(_read_source(*parts))
    imported, used = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name)
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            imported.add(base)
            if base:
                imported.add(base.split(".")[0])
            for alias in node.names:
                used.add(alias.name)
        elif isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            used.add(node.attr)
    return imported, used


class _TaskingServer:
    """A real team server on two sockets, with agents you can register.

    The suite shares `agents`, `task_queues` and `results` as module state,
    so each instance snapshots and restores them: a test that leaves a
    registered agent behind changes what the next one sees, and that is a
    class of flake this repository has paid for before.
    """

    operator_token = "operator-token-for-tests"

    def __init__(self, key: bytes, listener_token: str, supervisor=None):
        self.key = key
        self.listener_token = listener_token
        self.supervisor = supervisor
        self.crypto = ServerCrypto(key)
        self._saved = None
        self.servers = ()

    def start(self):
        from werkzeug.serving import make_server

        from software.c2 import server as server_mod

        self._mod = server_mod
        self._saved = (dict(server_mod.agents), dict(server_mod.task_queues),
                       dict(server_mod.results))

        operator = make_server("127.0.0.1", 0, None, threaded=True)
        agent = make_server("127.0.0.1", 0, None, threaded=True)
        self.operator_port = operator.server_port
        self.agent_port = agent.server_port
        app = server_mod.create_app(
            self.crypto, self.operator_token,
            pathlib.Path(tempfile.mkdtemp()),
            server_config={"host": "127.0.0.1", "port": self.agent_port,
                           "operator_host": "127.0.0.1",
                           "operator_port": self.operator_port},
            operator_port=self.operator_port,
            listener_token=self.listener_token,
            supervisor=self.supervisor)
        self.app = app
        self.servers = (operator, agent)
        for srv in self.servers:
            srv.app = app
            threading.Thread(target=srv.serve_forever, daemon=True).start()

    def stop(self):
        for srv in self.servers:
            srv.shutdown()
        if self._saved is not None:
            agents, queues, results_ = self._saved
            self._mod.agents.clear()
            self._mod.agents.update(agents)
            self._mod.task_queues.clear()
            self._mod.task_queues.update(queues)
            self._mod.results.clear()
            self._mod.results.update(results_)

    def register(self, implant_id: str) -> str:
        """Register an agent the way a beacon does, and return its name."""
        before = set(self._mod.agents)
        body = json.dumps(self.crypto.wrap({
            "action": "register", "id": implant_id, "agent_id": None,
            "hostname": "probe", "os": "Linux 6.1", "user": "nobody",
            "pid": 1, "uptime": 1, "interval": 300,
        })).encode()
        request = urllib.request.Request(
            "http://127.0.0.1:%d/api/v1/beacon" % self.agent_port,
            data=body, method="POST",
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=5):
            pass
        new = set(self._mod.agents) - before
        if not new:
            raise AssertionError("the probe agent did not register")
        return new.pop()

    def check_in(self, implant_id: str, action: str = "beacon") -> None:
        """Contact the agent socket the way a beacon does, without expecting
        a new agent. `register` asserts that one appeared, which is right
        for a first contact and wrong for every one after it."""
        body = json.dumps(self.crypto.wrap({
            "action": action, "id": implant_id, "agent_id": None,
            "hostname": "probe", "os": "Linux 6.1", "user": "nobody",
            "pid": 1, "uptime": 2, "interval": 300,
        })).encode()
        request = urllib.request.Request(
            "http://127.0.0.1:%d/api/v1/beacon" % self.agent_port,
            data=body, method="POST",
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=5):
            pass

    def agents(self):
        """The fleet as the server holds it, for before/after comparisons."""
        return dict(self._mod.agents)

    def result(self, task_id: str):
        return self._mod.results.get(task_id)

    def queue(self, name: str, cmd: str, args: str) -> str:
        body = json.dumps({"cmd": cmd, "args": args, "data": ""}).encode()
        request = urllib.request.Request(
            "http://127.0.0.1:%d/api/agents/%s/task"
            % (self.operator_port, name),
            data=body, method="POST",
            headers={"Authorization": "Bearer %s" % self.operator_token,
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read())["id"]


# The control token a supervised child authenticates its control socket
# with. Deliberately not the operator token: a listener holding that could
# task the fleet if it ever reached the operator socket, and a listener is
# the most exposed process in the arrangement.
_CONTROL_TOKEN = "control-token-for-tests"


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _command_line_of(pid: int) -> str:
    """The child's argv as `ps` shows it, which is the threat being tested."""
    try:
        done = subprocess.run(["ps", "-o", "command=", "-p", str(pid)],
                              capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return done.stdout.strip()


def _served_page() -> str:
    """The operator page as the server serves it.

    Read through a real request rather than out of the source, so a change
    that breaks the template is a failure here and not a surprise in a
    browser.
    """
    raw, _b64 = _key_pair()
    quiet = logging.getLogger("werkzeug")
    previous = quiet.level
    quiet.setLevel(logging.ERROR)
    env = _TaskingServer(raw, None)
    try:
        env.start()
        request = urllib.request.Request(
            "http://127.0.0.1:%d/" % env.operator_port)
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.read().decode("utf-8", "replace")
    finally:
        env.stop()
        quiet.setLevel(previous)


def _free_port() -> int:
    """A port that was free a moment ago.

    Inherently racy, and that is why `bind_port: 0` is refused in a
    configuration file but used freely in tests: an operator needs a fixed
    port because the beacon is configured with one, while a test only
    needs a port no other test is using right now.
    """
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def _dns_question(name, qtype=16):
    """A well-formed single-question DNS query for `name`.

    Built here rather than borrowed from the client, because these tests
    need queries the client would never send.
    """
    qname = b""
    for label in name.encode().split(b"."):
        qname += struct.pack("B", len(label)) + label
    qname += b"\x00"
    return (struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0)
            + qname + struct.pack("!HH", qtype, 1))


def _wait_until(predicate, what, timeout=10.0):
    """Poll for a condition rather than sleeping a guessed interval."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("timed out waiting for %s" % what)


_PAYLOAD_FIELD_FOR_TEST = beacon_mod._PAYLOAD_FIELDS[0]


def _key_pair():
    """One key, both ends -- the mismatch this repository has paid for twice."""
    raw = os.urandom(32)
    return raw, base64.b64encode(raw).decode()


def _beacon(key_b64, **protocols):
    cfg = {"c2": {"encryption_key": key_b64,
                  "https": {"enabled": False},
                  "dns": {"enabled": False}}}
    cfg["c2"].update(protocols)
    return Beacon(cfg)


class TestTheEncryptContract(unittest.TestCase):
    """`_encrypt(data: dict)` serialises its own argument.

    Given bytes it raised `TypeError` from inside `json.dumps` and the
    caller's `except` discarded it, so three transports never put a byte on
    the wire. Given a `str` it would have serialised a second time and
    produced JSON inside JSON -- no error, and a peer decrypting it would
    get a string where it expected a dict. The type hint said `dict` all
    along; these tests make it true.
    """

    def setUp(self):
        self.raw, self.b64 = _key_pair()
        self.crypto = ServerCrypto(self.raw)

    # ── the contract itself ──

    def test_encrypt_accepts_a_dict(self):
        b = _beacon(self.b64)
        out = b._encrypt({"action": "beacon"})
        self.assertIsInstance(out, str)
        self.assertEqual(self.crypto.decrypt(out), {"action": "beacon"})

    def test_encrypt_refuses_a_str(self):
        b = _beacon(self.b64)
        with self.assertRaises(TypeError) as caught:
            b._encrypt(json.dumps({"action": "beacon"}))
        message = str(caught.exception)
        self.assertIn("dict", message)
        # The type received must appear too, or the message tells a caller
        # what was wanted and not what it gave.
        self.assertIn("str", message)

    def test_encrypt_refuses_bytes(self):
        b = _beacon(self.b64)
        with self.assertRaises(TypeError) as caught:
            b._encrypt(json.dumps({"action": "beacon"}).encode())
        message = str(caught.exception)
        self.assertIn("dict", message)
        self.assertIn("bytes", message)

    def test_the_refusal_names_the_parameter(self):
        b = _beacon(self.b64)
        with self.assertRaises(TypeError) as caught:
            b._encrypt(b"x")
        self.assertIn("data", str(caught.exception))

    def test_encrypt_refuses_none_and_a_list(self):
        b = _beacon(self.b64)
        for bad in (None, [{"action": "beacon"}], 7):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    b._encrypt(bad)

    def test_the_refusal_never_contains_the_value(self):
        # The argument is plaintext about to be encrypted. The message may
        # name the parameter and the type; it may not quote the content.
        b = _beacon(self.b64)
        secret = "sensitive-marker-9f3a1c"
        for bad in (json.dumps({"k": secret}), json.dumps({"k": secret}).encode()):
            with self.subTest(kind=type(bad).__name__):
                with self.assertRaises(TypeError) as caught:
                    b._encrypt(bad)
                self.assertNotIn(secret, str(caught.exception))

    # ── the three call sites, through the real ServerCrypto ──

    def _smb_capture(self, b):
        """Run an SMB path with the socket layer stubbed; return what it wrote."""
        written = []
        return written, (
            patch.object(b, "_smb_connect", return_value=MagicMock()),
            patch.object(b, "_smb_write_pipe",
                         side_effect=lambda sock, data: written.append(data) or True),
            patch.object(b, "_smb_read_pipe", return_value=None),
        )

    def _enter(self, patches):
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_smb_checkin_payload_round_trips_through_server_crypto(self):
        b = _beacon(self.b64, smb={"enabled": True, "server": "10.0.0.1"})
        written, patches = self._smb_capture(b)
        self._enter(patches)

        b._beacon_smb()

        self.assertEqual(len(written), 1, "the check-in wrote nothing")
        payload = written[0]
        if isinstance(payload, bytes):
            payload = payload.decode()
        got = self.crypto.decrypt(payload)
        self.assertIsInstance(got, dict,
                              "the server decrypted a %s, not a dict"
                              % type(got).__name__)
        self.assertEqual(got["action"], "register")
        # On first contact the implant is identified by "id"; "agent_id" is
        # None until the server assigns one. _system_info() carries both,
        # and HTTPS does exactly the same -- so a listener must key off
        # "id" for a registration, not "agent_id".
        self.assertEqual(got["id"], b._implant_id)
        self.assertIsNone(got["agent_id"])

    def test_smb_result_payload_round_trips(self):
        b = _beacon(self.b64, smb={"enabled": True, "server": "10.0.0.1"})
        written, patches = self._smb_capture(b)
        self._enter(patches)

        b._send_result_smb("task-1", "ok", "uid=0(root)")

        self.assertEqual(len(written), 1, "the result wrote nothing")
        payload = written[0]
        if isinstance(payload, bytes):
            payload = payload.decode()
        got = self.crypto.decrypt(payload)
        self.assertIsInstance(got, dict)
        self.assertEqual(got["action"], "result")
        self.assertEqual(got["task_id"], "task-1")
        self.assertEqual(got["output"], "uid=0(root)")

    def test_quic_payload_round_trips(self):
        b = _beacon(self.b64, quic={"enabled": True, "server": "10.0.0.1:4433"})
        sent = []

        class _FakeUdp:
            def settimeout(self, _):
                pass

            def sendto(self, data, _addr):
                sent.append(data)

            def recvfrom(self, _n):
                raise OSError("no answer in this test")

            def close(self):
                pass

        self._enter((patch.object(beacon_mod.socket, "socket",
                                  side_effect=lambda *a, **k: _FakeUdp()),))

        b._quic_send({"action": "beacon", "agent_id": "probe"})

        self.assertTrue(sent, "the QUIC path sent nothing")
        # Each datagram is [stream_id(4)][frag_index(2)][total_frags(2)]
        # then the chunk -- struct ">IHH", eight bytes, not sixteen.
        frame = b"".join(d[8:] for d in sent)
        # The frame itself is [4-byte big-endian length][payload].
        length = int.from_bytes(frame[:4], "big")
        body = frame[4:4 + length]
        self.assertEqual(len(body), length, "the frame length header lies")
        got = self.crypto.decrypt(body.decode())
        self.assertIsInstance(got, dict)
        self.assertEqual(got["action"], "beacon")
        self.assertEqual(got["agent_id"], "probe")


class TestTheRelay(unittest.TestCase):
    """The relay moves an opaque string and never learns what is in it.

    It is the one piece all three listeners share, so it is also the one
    place where a key could leak into a container that has no business
    holding one. The tests therefore pin two things that are easy to lose
    later: that its signature takes no key, and that its module imports
    nothing from the crypto code.

    Everything else runs against a real HTTP server on an ephemeral port.
    A mock would agree with whatever the relay does; the point is that the
    far end finds the payload where the relay puts it.
    """

    def setUp(self):
        self.raw, self.b64 = _key_pair()
        self.crypto = ServerCrypto(self.raw)
        self._servers = []
        # werkzeug's development server logs every request at INFO, which
        # would put a line per test into the suite's output. This project
        # keeps that output pristine.
        quiet = logging.getLogger("werkzeug")
        previous = quiet.level
        quiet.setLevel(logging.ERROR)
        self.addCleanup(quiet.setLevel, previous)

    def _serve(self, handler):
        """Run `handler(body_dict) -> (status, dict|None)` on a free port."""
        from werkzeug.serving import make_server

        def app(environ, start_response):
            length = int(environ.get("CONTENT_LENGTH") or 0)
            body = json.loads(environ["wsgi.input"].read(length) or b"{}")
            status, answer = handler(body)
            payload = json.dumps(answer or {}).encode()
            start_response("%d WHATEVER" % status,
                           [("Content-Type", "application/json"),
                            ("Content-Length", str(len(payload)))])
            return [payload]

        srv = make_server("127.0.0.1", 0, app, threaded=True)
        self._servers.append(srv)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return "http://127.0.0.1:%d/" % srv.server_port

    # ── the happy path, both directions ──

    def test_a_payload_reaches_the_server_and_the_answer_comes_back(self):
        seen = []

        def handler(body):
            seen.append(body)
            return 200, self.crypto.wrap({"tasks": [{"cmd": "shell"}]})

        url = self._serve(handler)
        sent = self.crypto.encrypt({"action": "beacon"})
        got = relay(sent, url=url)

        self.assertIsNotNone(got, "the relay returned nothing")
        self.assertEqual(self.crypto.decrypt(got), {"tasks": [{"cmd": "shell"}]})
        self.assertEqual(len(seen), 1)

    def test_the_request_field_is_one_the_server_scans_for(self):
        # unwrap() checks 14 named fields and then falls back to any string
        # over 32 characters. The fallback is robustness, not an interface:
        # the relay must land in the named loop.
        seen = []
        url = self._serve(lambda body: (seen.append(body) or (200, {})))
        sent = self.crypto.encrypt({"action": "beacon"})
        relay(sent, url=url)

        self.assertEqual(len(seen), 1)
        field = next(k for k, v in seen[0].items() if v == sent)
        self.assertIn(field, beacon_mod._PAYLOAD_FIELDS,
                      "the relay used a field unwrap()'s named loop misses")
        self.assertEqual(self.crypto.unwrap(seen[0]), {"action": "beacon"})

    def test_the_answer_is_found_whichever_field_carries_it(self):
        # ServerCrypto.wrap picks the field at random, so the relay cannot
        # rely on a fixed one.
        answer = {"tasks": []}
        for field in beacon_mod._PAYLOAD_FIELDS:
            with self.subTest(field=field):
                body = {field: self.crypto.encrypt(answer), "seq": 7}
                url = self._serve(lambda _b, body=body: (200, body))
                got = relay(self.crypto.encrypt({"action": "beacon"}), url=url)
                self.assertIsNotNone(got, "field %s was not found" % field)
                self.assertEqual(self.crypto.decrypt(got), answer)

    # ── failure is None, never an exception ──

    def test_a_server_that_is_down_gives_None(self):
        import socket as _s
        probe = _s.socket()
        probe.bind(("127.0.0.1", 0))
        dead = probe.getsockname()[1]
        probe.close()
        self.assertIsNone(relay("x" * 40, url="http://127.0.0.1:%d/" % dead,
                                timeout=2.0))

    def test_a_server_that_hangs_gives_None_within_the_timeout(self):
        # A hang here would hold a listener's connection open. The timeout
        # is the whole reason it does not, so assert the clock too.
        def handler(_body):
            time.sleep(5)
            return 200, {}

        url = self._serve(handler)
        start = time.monotonic()
        got = relay("x" * 40, url=url, timeout=1.0)
        elapsed = time.monotonic() - start

        self.assertIsNone(got)
        self.assertLess(elapsed, 4.0,
                        "the relay waited %.1fs on a 1s timeout" % elapsed)

    def test_a_non_200_gives_None(self):
        for status in (401, 404, 500, 503):
            with self.subTest(status=status):
                url = self._serve(lambda _b, s=status: (s, {}))
                self.assertIsNone(relay("x" * 40, url=url, timeout=5.0))

    def test_a_200_with_no_usable_field_gives_None(self):
        for answer in ({}, {"seq": 1, "ok": True}, {"short": "abc"}):
            with self.subTest(answer=answer):
                url = self._serve(lambda _b, a=answer: (200, a))
                self.assertIsNone(relay("x" * 40, url=url, timeout=5.0))

    def test_an_answer_over_the_ceiling_gives_None(self):
        # Found by enumerating the failure modes rather than by reading:
        # without a ceiling, a 1 MB body with one long string came back as
        # a 1 MB payload, and the listener above would have fragmented that
        # into some 850 datagrams on a hostile server's behalf.
        from software.c2.listeners import relay as relay_mod
        from werkzeug.serving import make_server

        oversized = (b'{"x":"' + b"y" * (relay_mod._MAX_ANSWER_BYTES + 64)
                     + b'"}')

        def app(environ, start_response):
            start_response("200 OK",
                           [("Content-Type", "application/json"),
                            ("Content-Length", str(len(oversized)))])
            return [oversized]

        srv = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        url = "http://127.0.0.1:%d/" % srv.server_port
        self.assertIsNone(relay("x" * 40, url=url, timeout=30.0))

    def test_an_answer_just_under_the_ceiling_still_arrives(self):
        # The ceiling must not reject real work. A task may carry a file.
        from software.c2.listeners import relay as relay_mod
        payload = self.crypto.encrypt({"tasks": [{"cmd": "upload"}]})
        filler = "z" * 4096
        url = self._serve(lambda _b: (200, {_PAYLOAD_FIELD_FOR_TEST: payload,
                                            "pad": filler}))
        got = relay("x" * 40, url=url, timeout=30.0)
        self.assertIsNotNone(got)
        self.assertEqual(self.crypto.decrypt(got),
                         {"tasks": [{"cmd": "upload"}]})
        self.assertLess(len(filler), relay_mod._MAX_ANSWER_BYTES)

    def test_a_decoy_field_cannot_be_mistaken_for_the_payload(self):
        # ServerCrypto.wrap adds decoy fields beside the payload. Measured
        # over 200 draws: every decoy is an int or a float, never a string,
        # so the scan cannot return one. This test holds that property on
        # the server's side, where it is decided.
        from software.c2.server import _decoy_fields
        for _ in range(50):
            for value in _decoy_fields(8).values():
                self.assertNotIsInstance(
                    value, str,
                    "a decoy field became a string; the relay's scan takes "
                    "the first long string it finds")

    def test_a_200_with_a_body_that_is_not_json_gives_None(self):
        from werkzeug.serving import make_server

        def app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/html"),
                                      ("Content-Length", "5")])
            return [b"<html"]

        srv = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        url = "http://127.0.0.1:%d/" % srv.server_port
        self.assertIsNone(relay("x" * 40, url=url, timeout=5.0))

    # ── the relay cannot be handed a key ──

    def test_the_signature_takes_no_key(self):
        import inspect
        params = set(inspect.signature(relay).parameters)
        self.assertEqual(params, {"payload", "url", "timeout"})
        for name in params:
            self.assertNotIn("key", name.lower())

    def test_the_module_imports_nothing_from_the_crypto_code(self):
        # Parsed, not grepped: the module's own prose explains which
        # packages it avoids and why, so a substring scan fires on the
        # explanation. What matters is what it imports and what names it
        # uses in code.
        imported, used = _imports_and_names("software", "c2", "listeners",
                                            "relay.py")
        for banned in ("cryptography", "software.c2.server"):
            self.assertNotIn(banned, imported,
                             "relay.py imports %s; it must never be able "
                             "to hold or use a key" % banned)
        for banned in ("ServerCrypto", "AESGCM", "decode_key",
                       "_aes_gcm_encrypt", "_aes_gcm_decrypt"):
            self.assertNotIn(banned, used,
                             "relay.py uses %s in code" % banned)

    def test_the_module_needs_no_third_party_import(self):
        # A listener container must stay stdlib-only. server.py pulls in
        # flask, werkzeug, cryptography, jinja2 and click -- measured;
        # beacon.py pulls in none of them, which is why the field list
        # comes from there.
        imported, _ = _imports_and_names("software", "c2", "listeners",
                                         "relay.py")
        third_party = {"flask", "werkzeug", "cryptography", "jinja2", "click",
                       "requests"}
        self.assertEqual(third_party & imported, set(),
                         "relay.py imports %s" % (third_party & imported))
        for name in imported:
            self.assertFalse(name.endswith(".server") or name == "server",
                             "relay.py imports the team server module (%s)"
                             % name)


class TestTheUdpListener(unittest.TestCase):
    """The UDP listener against the client that defines its wire format.

    The framing is the beacon's: a frame is [4-byte length][payload], cut
    into 1200-byte chunks, each datagram prefixed
    struct ">IHH" = [stream_id][frag_index][total_frags]. Eight bytes, not
    sixteen -- an assumption that cost one earlier test in this file.

    The client reads answers with recvfrom(1500) and ignores the stream_id
    it gets back, so an answer datagram must stay under 1500 bytes
    including its header, and every answer datagram must agree on
    total_frags because the client takes `expected` from whichever it last
    parsed.
    """

    FRAG = 1200
    HEADER = struct.Struct(">IHH")

    def setUp(self):
        self.raw, self.b64 = _key_pair()
        self.crypto = ServerCrypto(self.raw)
        quiet = logging.getLogger("werkzeug")
        previous = quiet.level
        quiet.setLevel(logging.ERROR)
        self.addCleanup(quiet.setLevel, previous)
        self._deferred = []

    # ── helpers ──

    def _listener(self, relay_url="http://127.0.0.1:1/"):
        listener = QuicListener("127.0.0.1", 0, relay_url=relay_url)
        listener.start()
        self.addCleanup(listener.shutdown)
        return listener

    def _relaying_to(self, handler):
        """A real HTTP endpoint on a free port, plus a listener aimed at it."""
        from werkzeug.serving import make_server

        def app(environ, start_response):
            length = int(environ.get("CONTENT_LENGTH") or 0)
            body = json.loads(environ["wsgi.input"].read(length) or b"{}")
            answer = json.dumps(handler(body) or {}).encode()
            start_response("200 OK", [("Content-Type", "application/json"),
                                      ("Content-Length", str(len(answer)))])
            return [answer]

        srv = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        url = "http://127.0.0.1:%d/" % srv.server_port
        return self._listener(url)

    def _send_frame(self, listener, payload: bytes, stream_id=None,
                    sock=None, interleave=False):
        """Frame and fragment `payload` exactly as the beacon does."""
        import random as _random
        stream_id = (stream_id if stream_id is not None
                     else _random.getrandbits(32))
        frame = struct.pack(">I", len(payload)) + payload
        total = (len(frame) + self.FRAG - 1) // self.FRAG or 1
        own = sock is None
        sock = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if own:
            sock.settimeout(10)
            self.addCleanup(sock.close)
        datagrams = []
        for i in range(total):
            chunk = frame[i * self.FRAG:(i + 1) * self.FRAG]
            datagrams.append(self.HEADER.pack(stream_id, i, total) + chunk)
        if interleave and total > 1:
            # Send everything but the last fragment now and the last one
            # on the deferred call, so two senders' partials coexist in the
            # listener at the same time. That is the only arrangement in
            # which a collision on stream_id can actually splice them.
            for dgram in datagrams[:-1]:
                sock.sendto(dgram, listener.address)
            self._deferred.append((sock, datagrams[-1], listener.address))
        else:
            for dgram in datagrams:
                sock.sendto(dgram, listener.address)
        return sock, stream_id

    def _flush_deferred(self):
        for sock, dgram, addr in self._deferred:
            sock.sendto(dgram, addr)
        self._deferred = []

    def _read_frame(self, sock):
        """Collect an answer the way the beacon does, and unframe it."""
        fragments, expected = {}, None
        while True:
            data, _ = sock.recvfrom(1500)
            if len(data) < 8:
                continue
            _sid, idx, total = self.HEADER.unpack(data[:8])
            expected = total
            fragments[idx] = data[8:]
            if len(fragments) == expected:
                break
        joined = b"".join(fragments[i] for i in sorted(fragments))
        length = struct.unpack(">I", joined[:4])[0]
        return joined[4:4 + length]

    # ── the exchange ──

    def test_a_payload_is_relayed_and_the_answer_comes_back(self):
        answer = self.crypto.wrap({"tasks": [{"cmd": "shell"}]})
        seen = []
        listener = self._relaying_to(lambda body: seen.append(body) or answer)

        sent = self.crypto.encrypt({"action": "beacon"})
        sock, _ = self._send_frame(listener, sent.encode())
        got = self._read_frame(sock)

        self.assertEqual(self.crypto.decrypt(got.decode()),
                         {"tasks": [{"cmd": "shell"}]})
        self.assertEqual(len(seen), 1)
        self.assertEqual(self.crypto.unwrap(seen[0]), {"action": "beacon"})

    def test_a_payload_larger_than_one_fragment_reassembles(self):
        # A task carrying a file is the real case; 4 KB is three fragments.
        big = self.crypto.encrypt({"action": "result", "output": "x" * 4096})
        self.assertGreater(len(big), self.FRAG * 2,
                           "the fixture is not multi-fragment")
        seen = []
        listener = self._relaying_to(
            lambda body: seen.append(body) or self.crypto.wrap({"ack": True}))

        sock, _ = self._send_frame(listener, big.encode())
        got = self._read_frame(sock)

        self.assertEqual(self.crypto.decrypt(got.decode()), {"ack": True})
        self.assertEqual(self.crypto.unwrap(seen[0])["output"], "x" * 4096)

    def test_an_answer_larger_than_one_fragment_is_fragmented(self):
        # The client reads 1500 bytes at a time, so a long answer must come
        # back in pieces that each fit.
        answer = self.crypto.wrap({"tasks": [{"cmd": "upload",
                                              "data": "y" * 8192}]})
        listener = self._relaying_to(lambda _body: answer)
        sock, _ = self._send_frame(
            listener, self.crypto.encrypt({"action": "beacon"}).encode())
        got = self._read_frame(sock)
        self.assertEqual(
            self.crypto.decrypt(got.decode())["tasks"][0]["data"], "y" * 8192)

    def test_two_senders_sharing_a_stream_id_each_get_their_own_answer(self):
        # stream_id is four random bytes chosen by the sender, so two
        # clients can collide. Reassembly keyed on stream_id alone would
        # splice them together; keyed on (address, stream_id) it cannot.
        def handler(body):
            got = self.crypto.unwrap(body)
            return self.crypto.wrap({"echo": got["who"]})

        listener = self._relaying_to(handler)
        collision = 0x41414141

        # The payloads must span several fragments, or there is nothing to
        # splice: a single-fragment frame completes on arrival and leaves
        # the buffer before the other sender's datagram gets there. A
        # mutation check caught this -- keying on stream_id alone passed the
        # first version of this test, which therefore held nothing.
        socks = []
        for who in ("first", "second"):
            payload = self.crypto.encrypt({"action": "beacon", "who": who,
                                           "pad": who * 2000})
            self.assertGreater(len(payload), self.FRAG,
                               "the fixture is not multi-fragment")
            sock, _ = self._send_frame(listener, payload.encode(),
                                       stream_id=collision, interleave=True)
            socks.append((who, sock))

        self._flush_deferred()

        for who, sock in socks:
            got = self.crypto.decrypt(self._read_frame(sock).decode())
            self.assertEqual(got["echo"], who,
                             "%s received %s's answer" % (who, got["echo"]))

    # ── traffic that is not a client ──

    def test_stray_datagrams_reach_nothing_and_do_not_stop_the_listener(self):
        relayed = []
        listener = self._relaying_to(
            lambda body: relayed.append(body) or self.crypto.wrap({}))

        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.settimeout(1)
        self.addCleanup(probe.close)
        # Detectably malformed: each fails a check the listener can make on
        # the datagram alone, so none of these may leave anything buffered.
        detectable = [
            b"",                                   # empty
            b"\x00",                               # shorter than a header
            b"A" * 7,                              # one byte short
            self.HEADER.pack(1, 0, 0) + b"abc",    # total_frags = 0
            self.HEADER.pack(2, 5, 1) + b"abc",    # index beyond total
            self.HEADER.pack(3, 0, 65535) + b"a",  # absurd total
        ]
        # Indistinguishable from a real first fragment: the first eight
        # bytes of an HTTP request line unpack to total=18516, index=12064,
        # which is arithmetically fine. Buffering these is correct -- the
        # bounded-and-expires test covers the consequence. Asserting zero
        # partials after them was my mistake, not the listener's, and a
        # mutation check is what exposed the muddle.
        plausible = [
            os.urandom(64),
            b"GET / HTTP/1.1\r\n\r\n",
        ]
        before = listener.datagrams_seen()
        for stray in detectable:
            probe.sendto(stray, listener.address)
        # Wait for the listener to have read them, not for a fixed moment.
        # The first version of this used _wait_until(lambda: True, ...),
        # which returns at once and asserted before the service had looked
        # at its input -- three mutations passed because of it.
        _wait_until(
            lambda: listener.datagrams_seen() >= before + len(detectable),
            "the listener to read %d stray datagrams" % len(detectable))
        self.assertEqual(listener.partial_count(), 0,
                         "a detectably malformed datagram was buffered")
        for stray in plausible:
            probe.sendto(stray, listener.address)

        # The listener must still serve a real exchange afterwards.
        sent = self.crypto.encrypt({"action": "beacon"})
        sock, _ = self._send_frame(listener, sent.encode())
        self._read_frame(sock)

        self.assertEqual(len(relayed), 1,
                         "%d stray datagrams reached the HTTP endpoint"
                         % (len(relayed) - 1))
        # Nor may a malformed datagram leave anything buffered: a header
        # claiming total_frags=0 used to be dropped by the index check
        # rather than by its own, which a mutation check exposed -- the
        # endpoint stayed clean either way, so the old assertion held
        # nothing about the buffer.
        self.assertLessEqual(listener.partial_count(), listener.max_partials,
                             "partials grew past the cap")

    def test_a_frame_that_lies_about_its_length_is_dropped(self):
        # One fragment, complete, but the four-byte length header claims
        # more than the body carries. Nothing in the stray set reached this
        # check, so it was untested until a mutation check said so.
        relayed = []
        listener = self._relaying_to(
            lambda body: relayed.append(body) or self.crypto.wrap({}))

        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.settimeout(1)
        self.addCleanup(probe.close)
        for claimed, body in ((9999, b"short"), (0, b"something"),
                              (4, b"ab")):
            frame = struct.pack(">I", claimed) + body
            probe.sendto(self.HEADER.pack(0x5A5A, 0, 1) + frame,
                         listener.address)

        sent = self.crypto.encrypt({"action": "beacon"})
        sock, _ = self._send_frame(listener, sent.encode())
        self._read_frame(sock)

        self.assertEqual(len(relayed), 1,
                         "a frame with a false length was relayed")

    def test_an_incomplete_reassembly_is_bounded_and_expires(self):
        listener = self._listener()
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(probe.close)

        # One fragment of nine, from many ports, over and over: a partial
        # that never completes is one packet from anybody.
        for i in range(400):
            probe.sendto(self.HEADER.pack(i, 0, 9) + b"z" * 1200,
                         listener.address)
        _wait_until(lambda: listener.partial_count() > 0,
                    "the listener to buffer a partial")

        self.assertLessEqual(listener.partial_count(), listener.max_partials,
                             "partials grew past the cap")
        self.assertLessEqual(listener.buffered_bytes(),
                             listener.max_buffered_bytes,
                             "buffered bytes grew past the cap")

        listener.expire_partials(older_than=0.0)
        self.assertEqual(listener.partial_count(), 0,
                         "expiry left partials behind")

    # ── the deliverable ──

    def test_a_real_beacon_completes_a_full_cycle_over_udp_alone(self):
        from tools.listener_rig import run_cycle

        seen = run_cycle("quic")

        self.assertTrue(seen["registered"], "the beacon never registered")
        self.assertEqual(seen["transport"], "quic")
        self.assertTrue(seen["task_id"], "no task was queued")
        self.assertEqual(seen["result_status"], "ok",
                         "result was %r" % (seen.get("result_status"),))
        self.assertIn("raccoon_rig", seen["result_output"],
                      "the command did not run: %r"
                      % (seen.get("result_output"),))


class TestTheDnsTaskingRoute(unittest.TestCase):
    """The server route a DNS listener reads tasking from.

    DNS is the one transport that carries nothing upstream: the beacon
    sends a bare TXT query and the only information that travels is the
    agent id in the query name. So there is no payload for a listener to
    relay, and something has to encrypt the answer -- which needs the key.

    The listener does not get one. Instead the server hands out tasking
    already wrapped, and the listener forwards it verbatim. That keeps the
    key out of a listener container, which is the property the whole
    package rests on.

    The route is internal: the beacon never calls it, only a listener
    does. So it is authenticated the way the team server already
    authenticates its call to the companion service -- a shared token in a
    header, checked per request. Without one, anyone could walk the agent
    names, which come from a fixed word list, and take tasking the real
    beacon would then never see, because the queue hands each task out
    once.
    """

    TOKEN = "listener-token-for-tests"

    def setUp(self):
        self.raw, self.b64 = _key_pair()
        quiet = logging.getLogger("werkzeug")
        previous = quiet.level
        quiet.setLevel(logging.ERROR)
        self.addCleanup(quiet.setLevel, previous)
        self.env = _TaskingServer(self.raw, self.TOKEN)
        self.addCleanup(self.env.stop)
        self.env.start()

    def _get(self, path, *, token=TOKEN, port=None):
        url = "http://127.0.0.1:%d%s" % (port or self.env.agent_port, path)
        request = urllib.request.Request(url)
        if token is not None:
            request.add_header("X-Listener-Token", token)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            return exc.code, None

    def test_tasking_for_a_registered_agent_comes_back_wrapped(self):
        name = self.env.register("probe-one")
        task_id = self.env.queue(name, "shell", "echo dns_route")

        status, body = self._get("/api/v1/dns/%s" % name)

        self.assertEqual(status, 200)
        got = self.env.crypto.unwrap(body)
        self.assertEqual(got["id"], task_id)
        self.assertEqual(got["args"], "echo dns_route")

    def test_an_agent_with_no_tasking_gets_an_empty_wrapped_answer(self):
        name = self.env.register("probe-two")
        status, body = self._get("/api/v1/dns/%s" % name)
        self.assertEqual(status, 200)
        self.assertEqual(self.env.crypto.unwrap(body), {})

    def test_an_unknown_id_gets_the_same_empty_answer(self):
        # Indistinguishable from a known agent with nothing queued, so the
        # route is not an existence oracle even for a token holder.
        status, body = self._get("/api/v1/dns/raccoon-nosuchagent")
        self.assertEqual(status, 200)
        self.assertEqual(self.env.crypto.unwrap(body), {})

    def test_the_task_leaves_the_queue(self):
        # Fire-and-forget: DNS has no result path, so a task that stayed in
        # the queue would be handed out again at every check-in, forever.
        # A `shell reboot` delivered that way would be a loop, not a task.
        name = self.env.register("probe-three")
        self.env.queue(name, "shell", "echo once")

        first = self.env.crypto.unwrap(self._get("/api/v1/dns/%s" % name)[1])
        second = self.env.crypto.unwrap(self._get("/api/v1/dns/%s" % name)[1])

        self.assertEqual(first.get("args"), "echo once")
        self.assertEqual(second, {}, "the task was handed out twice")

    def test_a_dns_only_beacon_is_found_by_its_implant_id(self):
        # The property that makes this route usable at all, and the one I
        # got wrong first: `_beacon_dns` puts `self._agent_id or
        # self._implant_id` into the query name, and a beacon that only
        # speaks DNS is never told its agent name -- nothing over DNS
        # carries one back. So the only identifier it can ever send is the
        # implant id, and a route that accepts agent names alone is
        # unreachable for every real client.
        name = self.env.register("implant-id-probe")
        task_id = self.env.queue(name, "shell", "echo by_implant_id")

        status, body = self._get("/api/v1/dns/implant-id-probe")

        self.assertEqual(status, 200)
        got = self.env.crypto.unwrap(body)
        self.assertEqual(got.get("id"), task_id,
                         "the implant id did not resolve to the agent")

    def test_an_agent_reached_over_dns_is_marked_as_such(self):
        # The interface cannot otherwise know: a check-in over HTTPS, SMB
        # or QUIC all arrive as an HTTP POST on the agent socket and are
        # indistinguishable. This route is the one contact that can be
        # attributed, and it has to be, because an agent reached this way
        # will never report a result -- so an operator queueing a task
        # against it is owed a warning.
        name = self.env.register("channel-probe")
        self.assertNotEqual(self.env.agents()[name].get("last_channel"),
                            "dns")

        self._get("/api/v1/dns/%s" % name)

        self.assertEqual(self.env.agents()[name]["last_channel"], "dns")

    def test_a_later_check_in_clears_the_dns_mark(self):
        # A beacon with DNS as a fallback would otherwise carry the mark
        # for ever, and the interface would warn about a limit that no
        # longer applies.
        name = self.env.register("channel-probe-two")
        self._get("/api/v1/dns/%s" % name)
        self.assertEqual(self.env.agents()[name]["last_channel"], "dns")

        # A check-in, not a registration: `register` asserts a new agent
        # appeared, which is right for a first contact and wrong for every
        # one after it. Both paths clear the mark, and both are tested --
        # a re-registration is a contact over the agent socket too.
        self.env.check_in("channel-probe-two")
        self.assertEqual(self.env.agents()[name]["last_channel"], "http")

        self._get("/api/v1/dns/%s" % name)
        self.assertEqual(self.env.agents()[name]["last_channel"], "dns")
        self.env.check_in("channel-probe-two", action="register")
        self.assertEqual(self.env.agents()[name]["last_channel"], "http")

    def test_without_the_token_it_is_refused(self):
        name = self.env.register("probe-four")
        self.env.queue(name, "shell", "echo secret")
        status, _ = self._get("/api/v1/dns/%s" % name, token=None)
        self.assertEqual(status, 401)

    def test_with_a_wrong_token_it_is_refused(self):
        name = self.env.register("probe-five")
        status, _ = self._get("/api/v1/dns/%s" % name, token="wrong")
        self.assertEqual(status, 401)

    def test_a_server_with_no_listener_token_refuses_everyone(self):
        # The route must add no surface to a deployment that does not use
        # listeners, and that is the default: `create_app` takes the token
        # as an optional argument, so an unconfigured server has nothing to
        # compare against. It refuses rather than accepting the empty
        # string, which is how this kind of check usually fails.
        quiet = logging.getLogger("werkzeug")
        previous = quiet.level
        quiet.setLevel(logging.ERROR)
        self.addCleanup(quiet.setLevel, previous)
        # Both shapes an unconfigured server takes: the argument omitted,
        # and an empty string -- which is what an unset environment
        # variable becomes once configuration reads one, so it is the more
        # likely of the two to reach production.
        for index, configured in enumerate((None, "")):
            bare = _TaskingServer(self.raw, configured)
            self.addCleanup(bare.stop)
            bare.start()
            # A distinct implant id per round. Both servers share the
            # module-level fleet, so re-using one id made the second
            # registration resolve to the agent the first had created, no
            # new name appeared, and the helper reported a registration
            # failure -- in the full suite only, because I checked this
            # test against a mutation and never against itself.
            name = bare.register("unconfigured-probe-%d" % index)
            bare.queue(name, "shell", "echo unreachable")

            for presented in (None, "", self.TOKEN, "anything"):
                with self.subTest(configured=configured, presented=presented):
                    request = urllib.request.Request(
                        "http://127.0.0.1:%d/api/v1/dns/%s"
                        % (bare.agent_port, name))
                    if presented is not None:
                        request.add_header("X-Listener-Token", presented)
                    with self.assertRaises(urllib.error.HTTPError) as caught:
                        urllib.request.urlopen(request, timeout=5)
                    self.assertEqual(caught.exception.code, 401)

    def test_a_refused_identifier_cannot_forge_a_log_line(self):
        # The identifier comes straight out of the URL path, and the
        # refusal is logged. A newline in it would let an unauthenticated
        # caller write its own lines into the server's log -- the same
        # class of defect as the HTML escapes, in a different output.
        from software.c2 import server as server_mod

        with self.assertLogs(server_mod.logger, level="WARNING") as caught:
            status, _ = self._get(
                "/api/v1/dns/x%0aWARNING:raccoon.c2:all%20clear",
                token="wrong")
        self.assertEqual(status, 401)
        for line in caught.output:
            self.assertNotIn("\n", line,
                             "a newline reached the log: %r" % line)

    def test_the_token_comparison_is_constant_time(self):
        # Asserted on this route's own body, not on the file. Searching the
        # whole file for "compare_digest" would pass on a hit anywhere in
        # it -- which is exactly the mistake that made a docs probe report
        # the operator token's `==` fixed when this route was added.
        import ast

        from software.c2 import server as server_mod

        tree = ast.parse(_read_source("software", "c2", "server.py"))
        bodies = [fn for fn in ast.walk(tree)
                  if isinstance(fn, ast.FunctionDef)
                  and fn.name == "api_dns_tasking"]
        self.assertEqual(len(bodies), 1, "api_dns_tasking is not defined once")
        calls = {node.func.attr for node in ast.walk(bodies[0])
                 if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute)}
        self.assertIn("compare_digest", calls,
                      "the listener token must not be compared with ==")
        self.assertNotIn("sha256", calls,
                         "a hardening guard forbids sha256 in this file")
        del server_mod

    def test_the_agent_socket_still_serves_only_the_named_endpoints(self):
        # This route is the first exception added to the agent socket since
        # the hardening pass built that policy, so the test that matters is
        # not "is the new route reachable" but "did adding it widen
        # anything else". Walk every rule and check.
        #
        # It is served on the operator socket too, and that is correct:
        # that socket binds loopback and the policy allows everything
        # there. My first version of this test asserted a refusal there,
        # which would have been a property the code does not have and
        # should not.
        from software.c2 import server as server_mod

        allowed = server_mod._AGENT_SOCKET_ENDPOINTS
        self.assertEqual(allowed, frozenset({"beacon_handler",
                                             "api_dns_tasking"}),
                         "the agent socket's allow-set changed")

        cover = {"status": "ok", "version": "2.1.0"}
        checked = 0
        for rule in self.env.app.url_map.iter_rules():
            if rule.endpoint in allowed or rule.endpoint == "static":
                continue
            if "GET" not in (rule.methods or set()):
                continue
            path = str(rule).replace("<path:path>", "x")
            path = re.sub(r"<[^>]+>", "1", path)
            status, body = self._get(path)
            checked += 1
            self.assertEqual(body, cover,
                             "%s answered on the agent socket" % path)
        self.assertGreater(checked, 10,
                           "only %d routes were checked" % checked)


class TestTheDnsListener(unittest.TestCase):
    """The DNS listener against the client that defines its wire format.

    The client sends `<base32(agent_id) lowercased, unpadded>.b.<zone>` as
    a TXT question and decrypts each record it gets until one works. There
    is no payload in the question, so this listener fetches already-wrapped
    tasking from the team server and forwards it -- it holds no key.
    """

    TOKEN = "listener-token-for-tests"
    ZONE = "c2.test"

    def setUp(self):
        self.raw, self.b64 = _key_pair()
        quiet = logging.getLogger("werkzeug")
        previous = quiet.level
        quiet.setLevel(logging.ERROR)
        self.addCleanup(quiet.setLevel, previous)
        self.env = _TaskingServer(self.raw, self.TOKEN)
        self.addCleanup(self.env.stop)
        self.env.start()
        self.listener = DnsListener(
            "127.0.0.1", 0,
            relay_url="http://127.0.0.1:%d" % self.env.agent_port,
            zone=self.ZONE, listener_token=self.TOKEN)
        self.listener.start()
        self.addCleanup(self.listener.shutdown)

    def _ask(self, name, qtype="TXT"):
        """Query through the client's own resolver code, not a reimplementation."""
        with patch.object(beacon_mod, "_DNS_PORT", self.listener.address[1]):
            return beacon_mod._dns_query(name, qtype, "127.0.0.1", timeout=5)

    @staticmethod
    def _label(agent_id):
        return (base64.b32encode(agent_id.encode()).decode()
                .rstrip("=").lower())

    # ── the deliverable ──

    def test_a_registered_beacon_receives_tasking_over_dns(self):
        name = self.env.register("dns-probe")
        task_id = self.env.queue(name, "shell", "echo over_dns")

        records = self._ask("%s.b.%s" % (self._label(name), self.ZONE))

        self.assertEqual(len(records), 1, "expected one TXT record")
        got = ServerCrypto(self.raw).decrypt(records[0])
        self.assertEqual(got["id"], task_id)
        self.assertEqual(got["args"], "echo over_dns")

    def test_the_query_name_is_decoded_the_way_the_client_encodes_it(self):
        # base32, lower-cased, padding stripped. An agent name of a length
        # that needs padding is the case that breaks a naive decoder, so
        # exercise several.
        for agent in ("raccoon-bandit", "a", "ab", "abcde", "raccoon-x-12"):
            with self.subTest(agent=agent):
                label = self._label(agent)
                decoded = self.listener._agent_of(
                    "%s.b.%s" % (label, self.ZONE))
                self.assertEqual(decoded, agent)

    def test_an_out_of_band_registration_reports_the_real_interval(self):
        # The server sizes its freshness windows from the interval a
        # registration reports, so a helper that understates it makes a
        # healthy agent flap between online and stale. Measured in the
        # local environment: the DNS agent reported 2 and checked in every
        # 10 seconds, and the interface raised Agent Offline on every
        # cycle. The same defect the beacon's own floor caused, put back
        # by a test helper.
        from software.c2.beacon import _MIN_INTERVAL
        from software.c2.server import agents as fleet

        before = set(fleet)
        name = lab.register_out_of_band(self.env.agent_port, self.raw,
                                        "interval-probe")
        self.addCleanup(lambda: fleet.pop(name, None))
        self.assertIn(name, set(fleet) - before)
        self.assertGreaterEqual(fleet[name]["interval"], _MIN_INTERVAL,
                                "the registration claims an interval no "
                                "beacon can honour")

    def test_an_unregistered_id_yields_no_tasking(self):
        # The hard limit of this channel: no registration goes over DNS, so
        # an id the server has never seen has nothing waiting.
        #
        # A record still comes back, and that is correct rather than a
        # leak: the server answers an encrypted empty mapping, and the
        # listener cannot tell that from real tasking because it holds no
        # key. Asserting "no record" would have demanded the listener
        # understand the payload, which is the one thing it must not do.
        # The property that matters is what the beacon then sees.
        records = self._ask("%s.b.%s" % (self._label("raccoon-ghost"),
                                         self.ZONE))
        self.assertEqual(len(records), 1)
        self.assertEqual(ServerCrypto(self.raw).decrypt(records[0]), {})

    def test_an_agent_with_nothing_queued_yields_no_tasking(self):
        name = self.env.register("dns-idle")
        records = self._ask("%s.b.%s" % (self._label(name), self.ZONE))
        self.assertEqual(len(records), 1)
        self.assertEqual(ServerCrypto(self.raw).decrypt(records[0]), {})

    def test_a_known_and_an_unknown_id_are_indistinguishable_to_the_listener(self):
        # Neither the listener nor anyone watching it can tell one from the
        # other without the key, which is what stops the channel being an
        # existence oracle.
        known = self.env.register("dns-known")
        a = self._ask("%s.b.%s" % (self._label(known), self.ZONE))
        b = self._ask("%s.b.%s" % (self._label("raccoon-absent"), self.ZONE))
        self.assertEqual(len(a), len(b), 1)
        self.assertEqual(len(a[0]), len(b[0]),
                         "the answer lengths differ, which leaks existence")

    def test_a_query_outside_the_zone_is_refused(self):
        name = self.env.register("dns-elsewhere")
        self.env.queue(name, "shell", "echo leak")
        for host in ("%s.b.evil.example" % self._label(name),
                     "%s.x.%s" % (self._label(name), self.ZONE),
                     self._label(name),
                     "www.%s" % self.ZONE):
            with self.subTest(host=host):
                self.assertEqual(self._ask(host), [],
                                 "%s was answered" % host)

    def test_a_non_txt_question_gets_no_record(self):
        name = self.env.register("dns-atype")
        self.env.queue(name, "shell", "echo a_record")
        self.assertEqual(
            self._ask("%s.b.%s" % (self._label(name), self.ZONE), "A"), [])

    def test_a_long_payload_is_split_into_character_strings(self):
        # One TXT character-string caps at 255 bytes and the client joins
        # them, which is why it joins rather than taking the first.
        from software.c2.listeners.dns import _txt_chunks
        payload = "p" * 900
        chunks = _txt_chunks(payload)
        self.assertGreater(len(chunks), 3)
        self.assertTrue(all(len(c) <= 255 for c in chunks))
        self.assertEqual(b"".join(chunks).decode(), payload)

    def test_a_malformed_query_does_not_crash_the_listener(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.settimeout(1)
        self.addCleanup(probe.close)
        malformed = [
            b"",
            b"\x00" * 4,
            os.urandom(11),
            struct.pack("!HHHHHH", 1, 0x0100, 0, 0, 0, 0),      # no question
            struct.pack("!HHHHHH", 2, 0x0100, 5, 0, 0, 0),      # five claimed
            struct.pack("!HHHHHH", 3, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c",
            struct.pack("!HHHHHH", 4, 0x0100, 1, 0, 0, 0) + b"\x3fshort",
            struct.pack("!HHHHHH", 5, 0x8400, 1, 0, 0, 0) + b"\x00",
            b"A" * 600,
        ]
        before = self.listener.queries_seen()
        for packet in malformed:
            probe.sendto(packet, self.listener.address)
        _wait_until(
            lambda: self.listener.queries_seen() >= before + len(malformed),
            "the listener to read %d malformed queries" % len(malformed))

        name = self.env.register("dns-after")
        self.env.queue(name, "shell", "echo still_up")
        records = self._ask("%s.b.%s" % (self._label(name), self.ZONE))
        self.assertEqual(len(records), 1,
                         "the listener stopped answering after malformed input")

    # ── properties the deliverable tests did not hold ──
    #
    # The four below exist because a mutation check found the deliverable
    # tests indifferent to them: each mutation stayed green. Three further
    # survivors -- following a compression pointer, allowing a dot in the
    # label, ignoring qdcount -- turned out to be genuinely equivalent,
    # because every one of those paths already collapses to None further
    # along. Those got no test; a test that cannot fail is worse than none.

    def test_the_answer_claims_to_be_an_authoritative_response(self):
        # QR and AA. The client does not check either, so nothing in the
        # deliverable noticed when they were cleared -- but a resolver in
        # the path does, and in production there is always one: the beacon
        # asks a resolver, not this listener. An answer without QR is not a
        # response and gets dropped before it reaches the client.
        from software.c2.listeners.dns import _build_answer

        answer = _build_answer(0x1234, b"\x01a\x00\x00\x10\x00\x01",
                               [b"payload"], 1)
        flags = struct.unpack("!H", answer[2:4])[0]
        self.assertTrue(flags & 0x8000, "QR is not set: this is not a reply")
        self.assertTrue(flags & 0x0400, "AA is not set")
        self.assertEqual(struct.unpack("!H", answer[:2])[0], 0x1234,
                         "the transaction id was not echoed")

    def test_the_record_name_points_at_the_question(self):
        # A TXT record names its owner with a pointer to offset 12, where
        # the question's name starts. The client happens to skip any
        # pointer without reading it, which is why a wrong offset went
        # unnoticed -- a resolver would reject the record.
        from software.c2.listeners.dns import _build_answer

        question = b"\x01a\x00\x00\x10\x00\x01"
        answer = _build_answer(1, question, [b"x"], 1)
        pointer = answer[12 + len(question):14 + len(question)]
        self.assertEqual(pointer, b"\xc0\x0c",
                         "the record points somewhere other than the question")

    def test_an_oversized_query_is_dropped_without_parsing(self):
        # The cap bounds the work one packet can cause. The malformed
        # batch did not hold it: 600 bytes of "A" fail to parse anyway, so
        # removing the cap changed nothing observable. A query that would
        # otherwise parse does hold it.
        name = self.env.register("dns-oversize")
        label = self._label(name)
        padding = ".".join(["a" * 60] * 9)          # pushes it over 512
        question = _dns_question("%s.%s.b.%s" % (label, padding, self.ZONE))
        self.assertGreater(len(question), self.listener.max_query_bytes)
        self.assertIsNone(self.listener._answer_for(question))

    def test_a_dns_response_is_not_answered(self):
        # Answering something that is itself a response is how two
        # nameservers end up talking to each other forever, and how a
        # listener becomes a reflector for a spoofed source address.
        name = self.env.register("dns-reflect")
        self.env.queue(name, "shell", "echo reflected")
        query = _dns_question("%s.b.%s" % (self._label(name), self.ZONE))
        # Bytes 2:4 are the flags. My first attempt put QR into bytes 0:2,
        # which is the transaction id, and the listener rightly answered a
        # perfectly ordinary query.
        response = query[:2] + struct.pack("!H", 0x8400) + query[4:]
        self.assertIsNone(self.listener._answer_for(response),
                          "the listener answered a response")

    def test_no_result_path_is_offered(self):
        # The documented limit must not drift into a half-built upstream:
        # nothing here may accept a result.
        imported, used = _imports_and_names("software", "c2", "listeners",
                                            "dns.py")
        for banned in ("_handle_result", "relay"):
            self.assertNotIn(banned, used,
                             "dns.py reaches for %s; this channel carries "
                             "tasking only" % banned)
        src = _read_source("software", "c2", "listeners", "dns.py")
        self.assertNotIn("action\": \"result", src)

    def test_the_listener_holds_no_key(self):
        imported, used = _imports_and_names("software", "c2", "listeners",
                                            "dns.py")
        self.assertNotIn("cryptography", imported)
        for banned in ("ServerCrypto", "AESGCM", "decode_key"):
            self.assertNotIn(banned, used)


class TestTheSmbListener(unittest.TestCase):
    """The SMB listener driven by the client that defines its wire format.

    Every assertion here goes through the beacon's own methods --
    `_beacon_smb` and `_send_result_smb` -- rather than a reimplementation
    of SMB2. The client is the only specification this protocol has in
    this project, and it is an inconsistent one: it declares a WRITE data
    offset of 70 and puts the payload at 112, and it picks the session,
    tree and file ids up four bytes past where it writes them. A listener
    built from the SMB2 specification alone would not interoperate with
    it, so the listener is built from measurements of it, and these tests
    are those measurements.

    Unlike DNS, this transport is bidirectional and carries registration,
    so a beacon that speaks only SMB is a complete client.
    """

    def setUp(self):
        self.raw, self.b64 = _key_pair()
        quiet = logging.getLogger("werkzeug")
        previous = quiet.level
        quiet.setLevel(logging.ERROR)
        self.addCleanup(quiet.setLevel, previous)
        self.env = _TaskingServer(self.raw, None)
        self.addCleanup(self.env.stop)
        self.env.start()
        self.listener = SmbListener(
            "127.0.0.1", 0,
            relay_url="http://127.0.0.1:%d/api/v1/beacon" % self.env.agent_port)
        self.listener.start()
        self.addCleanup(self.listener.shutdown)

    def _beacon(self, interval=2):
        host, port = self.listener.address
        return Beacon({"c2": {
            "beacon_interval_seconds": interval,
            "jitter_percent": 0,
            "encryption_key": self.b64,
            "proxy": {"mode": "none"},
            "https": {"enabled": False},
            "dns": {"enabled": False, "domain": "", "resolver": "127.0.0.1"},
            "quic": {"enabled": False},
            "smb": {"enabled": True, "server": "%s:%d" % (host, port),
                    "pipe_name": "msrpc_6e2f"},
        }})

    # ── the deliverable ──

    def test_a_beacon_registers_over_smb_alone(self):
        beacon = self._beacon()
        before = set(self.env.agents())

        answer = beacon._beacon_smb()

        self.assertIsNotNone(answer, "the exchange produced nothing")
        self.assertTrue(answer.get("success"), answer)
        new = set(self.env.agents()) - before
        self.assertEqual(len(new), 1, "the beacon did not register")
        self.assertEqual(answer.get("agent_id"), new.pop())

    def test_tasking_comes_back_over_smb(self):
        beacon = self._beacon()
        before = set(self.env.agents())
        beacon._beacon_smb()
        name = (set(self.env.agents()) - before).pop()
        beacon._registered = True
        task_id = self.env.queue(name, "shell", "echo over_smb")

        answer = beacon._beacon_smb()

        self.assertIsNotNone(answer, "no tasking came back")
        # A batch envelope, not a bare task: this client advertises the
        # `batch` capability, so the server wraps tasking in `{"tasks":
        # [..]}`. My first version of this test asserted the bare shape and
        # failed against correct code -- worth pinning, because a listener
        # that reshaped the payload would be reading it, and it must not.
        self.assertEqual(list(answer), ["tasks"], answer)
        self.assertEqual(len(answer["tasks"]), 1)
        task = answer["tasks"][0]
        self.assertEqual(task.get("id"), task_id)
        self.assertEqual(task.get("args"), "echo over_smb")

    def test_a_result_travels_back_over_smb(self):
        # The property DNS cannot have. This transport is bidirectional, so
        # a beacon reached only over SMB is a complete client.
        beacon = self._beacon()
        before = set(self.env.agents())
        beacon._beacon_smb()
        name = (set(self.env.agents()) - before).pop()
        beacon._agent_id = name
        beacon._registered = True
        task_id = self.env.queue(name, "shell", "echo result_path")

        beacon._send_result_smb(task_id, "ok", "result_over_smb")

        _wait_until(lambda: self.env.result(task_id),
                    "the result to reach the server")
        record = self.env.result(task_id)
        self.assertEqual(record.get("status"), "ok")
        self.assertEqual(record.get("output"), "result_over_smb")

    # ── the measurements the listener is built from ──

    def test_the_payload_is_taken_from_where_the_client_puts_it(self):
        # The client declares DataOffset 70 in its WRITE and places the
        # payload at 112. A listener that trusted the declared offset would
        # relay 42 bytes of the request's own body as if it were
        # ciphertext, and the server would answer an error that the beacon
        # would read as a failed exchange -- silently.
        beacon = self._beacon()
        relayed = []
        from software.c2.listeners import smb as smb_mod
        original = smb_mod.relay

        def recording(payload, **kwargs):
            relayed.append(payload)
            return original(payload, **kwargs)

        smb_mod.relay = recording
        self.addCleanup(setattr, smb_mod, "relay", original)
        beacon._beacon_smb()

        self.assertEqual(len(relayed), 1, "the listener relayed %d times"
                         % len(relayed))
        self.assertEqual(ServerCrypto(self.raw).decrypt(relayed[0])["action"],
                         "register",
                         "what was relayed is not what the beacon encrypted")

    def test_the_echoed_ids_are_not_validated(self):
        # Measured: the client reads the session id from offset 44 where it
        # was written at 40, the tree id from 40 where it was written at
        # 36, and the file id from 132 where it was written at 128. So it
        # echoes four bytes of the next field and loses four of its own. A
        # listener that compared those values against what it issued would
        # reject every real beacon.
        beacon = self._beacon()
        self.assertIsNotNone(beacon._beacon_smb())
        self.assertNotEqual(beacon._smb_session_id,
                            self.listener.issued_session_id,
                            "the client echoed the session id unchanged; the "
                            "measurement this listener was built on no "
                            "longer holds")

    def test_two_beacons_do_not_mix_their_exchanges(self):
        # One connection per exchange, several at once. State kept per
        # listener rather than per connection would splice two beacons
        # together and each would decrypt the other's answer.
        first, second = self._beacon(), self._beacon()
        second._implant_id = first._implant_id + "-second"
        answers = {}

        def run(label, beacon):
            answers[label] = beacon._beacon_smb()

        threads = [threading.Thread(target=run, args=("a", first)),
                   threading.Thread(target=run, args=("b", second))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        self.assertIsNotNone(answers.get("a"))
        self.assertIsNotNone(answers.get("b"))
        self.assertNotEqual(answers["a"]["agent_id"], answers["b"]["agent_id"],
                            "both beacons were given the same agent")

    # ── robustness ──

    def test_a_malformed_message_does_not_take_the_listener_down(self):
        malformed = [
            b"",
            b"\x00\x00\x00",
            b"\x00\x00\x00\x04\xfeSMB",
            b"\x00\x00\x00\x40" + b"\xfeSMB" + b"\x00" * 60,
            b"\x00\x00\x00\x10" + b"not an smb message",
            b"\x00\xff\xff\xff" + b"\xfeSMB",
        ]
        for packet in malformed:
            probe = socket.socket()
            probe.settimeout(3)
            try:
                probe.connect(self.listener.address)
                probe.sendall(packet)
                probe.recv(64)
            except (OSError, socket.timeout):
                pass
            finally:
                probe.close()

        beacon = self._beacon()
        self.assertIsNotNone(beacon._beacon_smb(),
                             "the listener stopped serving after malformed "
                             "input")

    def test_an_oversized_message_is_refused(self):
        probe = socket.socket()
        probe.settimeout(5)
        self.addCleanup(probe.close)
        probe.connect(self.listener.address)
        # A length header claiming more than the cap, so the listener must
        # refuse on the header alone rather than reading the body.
        probe.sendall(b"\x00" + struct.pack(">I", self.listener.max_message
                                            + 1)[1:])
        self.assertEqual(probe.recv(16), b"",
                         "the listener kept the connection open")

    # ── properties the deliverable tests did not hold ──
    #
    # A mutation run found seven of these indifferent, and the reason is
    # the same for most: the client checks almost nothing. It reads the
    # command out of the NEGOTIATE response and reads data out of a READ
    # response, and takes everything else on faith. So a listener can get
    # the status, the flags, the echoed command and the field offsets all
    # wrong and still serve this one client perfectly -- which is exactly
    # why those need tests of their own rather than being left to the
    # end-to-end exchange.
    #
    # One survivor is left deliberately: keeping the pending answer after
    # a READ instead of clearing it. The client does one WRITE and one
    # READ per connection and never reads twice, so no test can tell the
    # two apart without driving raw SMB2 through a sequence the client
    # will never send. The reset stays because a second READ returning a
    # stale answer would be worse than nothing.

    def test_a_message_without_the_smb2_magic_is_not_served(self):
        # Reachable only at 64 bytes or more, because shorter messages are
        # refused on the length header. A listener that dispatched on
        # whatever sits at offset 12 would answer arbitrary traffic.
        probe = socket.socket()
        probe.settimeout(5)
        self.addCleanup(probe.close)
        probe.connect(self.listener.address)
        bogus = b"HTTP" + b"\x00" * 8 + struct.pack("<H", 0) + b"\x00" * 50
        self.assertEqual(len(bogus), 64)
        probe.sendall(b"\x00" + struct.pack(">I", len(bogus))[1:] + bogus)
        self.assertEqual(probe.recv(16), b"",
                         "a message with the wrong magic was answered")

    def test_a_write_that_declares_more_than_it_carries_is_refused(self):
        # Without the check the payload is silently short, because slicing
        # past the end of a bytes object does not raise. The server would
        # fail to decrypt it and the beacon would see a failed exchange
        # with nothing anywhere saying why.
        from software.c2.listeners.smb import _write_payload

        message = b"\xfeSMB" + b"\x00" * 60            # header
        message += struct.pack("<HH", 49, 70)
        message += struct.pack("<I", 500)                # declares 500
        message += b"\x00" * 40                         # rest of the body
        message += b"only a little"                     # carries 13
        with self.assertRaises(ValueError):
            _write_payload(message, 16 * 1024 * 1024)

    def test_every_response_echoes_its_request_and_reports_success(self):
        # The client checks the command on the NEGOTIATE response and
        # nothing else, so these went unnoticed. A real client, and anyone
        # reading the traffic, would find a reply that claims to be a
        # different command or carries an error status while the handshake
        # proceeds incoherent.
        from software.c2.listeners.smb import _header

        for command in (0, 1, 3, 5, 8, 9):
            with self.subTest(command=command):
                header = _header(command, 0x4242, self.listener)
                self.assertEqual(struct.unpack_from("<H", header, 12)[0],
                                 command, "the command was not echoed")
                self.assertEqual(struct.unpack_from("<I", header, 8)[0], 0,
                                 "the status is not SUCCESS")
                self.assertEqual(struct.unpack_from("<Q", header, 24)[0],
                                 0x4242, "the message id was not echoed")
                self.assertTrue(struct.unpack_from("<I", header, 16)[0] & 1,
                                "SMB2_FLAGS_SERVER_TO_REDIR is not set")

    def test_the_create_response_puts_the_file_id_where_one_belongs(self):
        # Offset 128 from the start of the header, which is where the SMB2
        # specification puts it. Neither this listener nor this client
        # cares what the value is, so only its position carries meaning --
        # and a position nobody checks is one that rots.
        from software.c2.listeners.smb import _create_body

        file_id = bytes(range(16))
        body = _create_body(file_id)
        self.assertEqual(body[64:80], file_id,
                         "the file id is not at offset 128 of the message")
        self.assertEqual(struct.unpack_from("<H", body, 0)[0], 89,
                         "the declared structure size changed")

    # ── what goes on the wire, and how much of it ──

    def test_the_issued_ids_are_not_a_fixed_string(self):
        # The first version of this listener put b"raccoonpipe00001" in the
        # file id and "RACOON" in the session id. Both travel in clear
        # text in every exchange, so that was the project's name written
        # into every capture of its own traffic.
        other = SmbListener("127.0.0.1", 0, relay_url=self.listener.relay_url)
        other.start()
        self.addCleanup(other.shutdown)
        for field in ("issued_session_id", "issued_tree_id",
                      "issued_file_id"):
            with self.subTest(field=field):
                mine = getattr(self.listener, field)
                theirs = getattr(other, field)
                self.assertNotEqual(mine, theirs,
                                    "%s is the same for two listeners" % field)
                for word in (b"raccoon", b"RACCOON", b"RACOON", b"pipe"):
                    self.assertNotIn(word, mine,
                                     "%s names the project" % field)

    def test_a_listener_that_never_started_can_be_shut_down(self):
        # `BaseServer.shutdown` waits on an event only `serve_forever`
        # sets, so this used to block for ever. Supervision has to tear
        # down a listener whose start failed, and the test above built one
        # without starting it and hung the suite for four hundred seconds.
        built = SmbListener("127.0.0.1", 0, relay_url=self.listener.relay_url)
        done = threading.Event()

        def close():
            built.shutdown()
            done.set()

        threading.Thread(target=close, daemon=True).start()
        self.assertTrue(done.wait(timeout=5),
                        "shutdown blocked on a listener that never served")

    def test_connections_beyond_the_ceiling_are_refused_and_counted(self):
        # A thread per connection with no ceiling is a way to be talked out
        # of memory by anyone who can reach the port. The refusal is
        # counted so a panel can show it rather than leaving an operator
        # wondering why check-ins thinned out.
        held = []
        self.addCleanup(lambda: [s.close() for s in held])
        for _ in range(self.listener.max_connections):
            sock = socket.socket()
            sock.settimeout(5)
            sock.connect(self.listener.address)
            held.append(sock)
        _wait_until(
            lambda: self.listener.connections_seen()
            >= self.listener.max_connections,
            "the listener to take up its ceiling of connections")

        extra = socket.socket()
        extra.settimeout(5)
        held.append(extra)
        extra.connect(self.listener.address)
        self.assertEqual(extra.recv(16), b"",
                         "a connection past the ceiling was served")
        _wait_until(lambda: self.listener.connections_refused() >= 1,
                    "the refusal to be counted")

    # ── the property the package rests on ──

    def test_the_listener_holds_no_key(self):
        imported, used = _imports_and_names("software", "c2", "listeners",
                                            "smb.py")
        self.assertNotIn("cryptography", imported)
        for banned in ("ServerCrypto", "AESGCM", "decode_key"):
            self.assertNotIn(banned, used)


class TestTheListenerRegistry(unittest.TestCase):
    """Turning a config file into listeners, and refusing the ones that lie.

    Two blocks in `configs/raccoon.yaml` look alike and mean opposite
    things. `c2.listeners` is the **server** side: sockets this deployment
    opens for beacons to reach. `c2.fallback.*` is the **beacon** side:
    channels an implant on this host will try. Confusing them would have
    an operator open a listening socket on a drop-box, or configure a
    beacon and wonder why nothing listens.
    """

    def _config(self, **overrides):
        base = {
            "name": "smb-main", "transport": "smb", "enabled": True,
            "bind_host": "0.0.0.0", "bind_port": 445,
            "relay_url": "http://127.0.0.1:8443/api/v1/beacon",
        }
        base.update(overrides)
        return {"c2": {"listeners": [base]}}

    # ── what the shipped file says ──

    def test_the_shipped_config_defines_all_three_disabled(self):
        import yaml

        with open(Path("configs") / "raccoon.yaml") as handle:
            shipped = yaml.safe_load(handle)
        specs = load_listeners(shipped)

        self.assertEqual({spec.transport for spec in specs},
                         {"smb", "quic", "dns"})
        for spec in specs:
            with self.subTest(name=spec.name):
                self.assertFalse(spec.enabled,
                                 "%s ships enabled; a fresh checkout would "
                                 "open a socket nobody asked for" % spec.name)

    def test_the_shipped_fallback_block_documents_smb_and_quic(self):
        # The beacon has read `smb` and `quic` out of its config block
        # since those transports were written, and the shipped file never
        # mentioned either. So the only way to switch them on was to know
        # they existed from the source.
        import yaml

        with open(Path("configs") / "raccoon.yaml") as handle:
            shipped = yaml.safe_load(handle)
        fallback = shipped["c2"]["fallback"]
        for transport in ("https", "dns", "smb", "quic"):
            self.assertIn(transport, fallback,
                          "the fallback block does not mention %s"
                          % transport)

    def test_the_server_side_and_beacon_side_blocks_are_not_confusable(self):
        # The two blocks look alike and mean opposite things, and the key
        # names do not say which is which. So each one states its side in
        # words, once, above itself.
        #
        # My first version of this test searched a 600-character window
        # before `listeners:` for the string "fallback", which passed or
        # failed on how long the surrounding comment happened to be. A
        # marker that is put there to be found is the honest way to check
        # that it is there.
        text = (Path("configs") / "raccoon.yaml").read_text()
        client = "THIS HOST AS A CLIENT"
        server = "THIS HOST AS A SERVER"

        self.assertEqual(text.count(client), 1,
                         "the beacon-side marker is not there exactly once")
        self.assertEqual(text.count(server), 1,
                         "the server-side marker is not there exactly once")
        self.assertLess(text.index(client), text.index("  fallback:"),
                        "the client marker does not precede the fallback "
                        "block it describes")
        self.assertLess(text.index(server), text.index("  listeners:"),
                        "the server marker does not precede the listeners "
                        "block it describes")
        self.assertLess(text.index("  fallback:"), text.index(server),
                        "the two markers do not bracket their own blocks")

    # ── what the registry refuses ──

    def test_an_unknown_transport_is_refused_by_name(self):
        with self.assertRaises(ValueError) as caught:
            load_listeners(self._config(transport="telepathy"))
        self.assertIn("telepathy", str(caught.exception),
                      "the message does not say what was wrong")

    def test_a_missing_relay_url_is_refused(self):
        for value in (None, "", "   "):
            with self.subTest(relay_url=value):
                with self.assertRaises(ValueError) as caught:
                    load_listeners(self._config(relay_url=value))
                self.assertIn("relay_url", str(caught.exception))

    def test_a_listener_with_no_name_is_refused(self):
        # Task 8 starts and stops by name and task 9 shows it. An unnamed
        # listener could be neither controlled nor reported.
        with self.assertRaises(ValueError):
            load_listeners(self._config(name=""))

    def test_two_listeners_with_one_name_are_refused(self):
        config = self._config()
        config["c2"]["listeners"].append(dict(config["c2"]["listeners"][0],
                                              bind_port=446))
        with self.assertRaises(ValueError) as caught:
            load_listeners(config)
        self.assertIn("smb-main", str(caught.exception))

    def test_two_listeners_on_one_port_are_refused(self):
        config = self._config(bind_host="127.0.0.1")
        config["c2"]["listeners"].append(
            dict(config["c2"]["listeners"][0], name="smb-other"))
        with self.assertRaises(ValueError) as caught:
            load_listeners(config)
        self.assertIn("445", str(caught.exception))

    def test_a_listener_that_binds_the_port_it_relays_to_is_refused(self):
        # I shipped exactly this: a QUIC listener on 8443, which is the
        # team server's own beacon port. UDP and TCP do not collide, so it
        # would have bound and worked while reading as a conflict to
        # everyone who saw it -- and the SMB listener next to it, being
        # TCP, would simply have failed at bind time.
        config = self._config(
            bind_port=8443,
            relay_url="http://127.0.0.1:8443/api/v1/beacon")
        with self.assertRaises(ValueError) as caught:
            load_listeners(config)
        self.assertIn("8443", str(caught.exception))
        self.assertIn("relay", str(caught.exception).lower())

    def test_a_different_port_in_the_relay_url_is_fine(self):
        specs = load_listeners(self._config(
            bind_port=445,
            relay_url="http://127.0.0.1:8443/api/v1/beacon"))
        self.assertEqual(specs[0].bind_port, 445)

    def test_a_relay_url_without_a_port_is_fine(self):
        # http and https have default ports, and they are deliberately not
        # filled in: a listener on 80 relaying to an `http://` URL with no
        # port is somebody else's arrangement, not a typo this check can
        # recognise. The ports here are 80 and 443 on purpose -- with
        # anything else the test passes whether the default is substituted
        # or not, which is how the first version of it held nothing.
        for url, port in (("http://team-server/api/v1/beacon", 80),
                          ("https://team-server/api/v1/beacon", 443)):
            with self.subTest(url=url):
                specs = load_listeners(self._config(bind_port=port,
                                                    relay_url=url))
                self.assertEqual(specs[0].relay_url, url)
                self.assertEqual(specs[0].bind_port, port)

    def test_a_wildcard_bind_collides_with_a_specific_one(self):
        # 0.0.0.0:445 and 127.0.0.1:445 are not two free sockets, and the
        # second one to start would fail at bind time with an error an
        # operator would have to go looking for.
        config = self._config(bind_host="0.0.0.0")
        config["c2"]["listeners"].append(
            dict(config["c2"]["listeners"][0], name="smb-local",
                 bind_host="127.0.0.1"))
        with self.assertRaises(ValueError) as caught:
            load_listeners(config)
        self.assertIn("445", str(caught.exception))

    def test_a_disabled_listener_is_still_validated(self):
        # Otherwise a typo sits in the file until the day someone enables
        # it, which is the worst moment to find out.
        with self.assertRaises(ValueError):
            load_listeners(self._config(enabled=False, transport="nonsense"))

    def test_a_port_outside_the_range_is_refused(self):
        for port in (0, -1, 65536, "445", None):
            with self.subTest(port=port):
                with self.assertRaises(ValueError):
                    load_listeners(self._config(bind_port=port))

    def test_a_yaml_boolean_port_is_refused(self):
        # `bind_port: yes` is a plausible thing to type into a YAML file
        # and parses as True, which is 1 in Python -- so without this the
        # listener would bind port 1 and the operator would be looking for
        # a typo in the wrong place. A mutation check found this missing.
        for port in (True, False):
            with self.subTest(port=port):
                with self.assertRaises(ValueError) as caught:
                    load_listeners(self._config(bind_port=port))
                self.assertIn("bind_port", str(caught.exception))

    def test_a_setting_the_transport_does_not_take_is_refused(self):
        # Ignored would be worse: a dropped setting and an applied one look
        # exactly alike from the outside, and `pipe_name` on a QUIC
        # listener means somebody has the wrong model of what they built.
        with self.assertRaises(ValueError) as caught:
            load_listeners(self._config(transport="quic",
                                        settings={"pipe_name": "x"}))
        self.assertIn("pipe_name", str(caught.exception))

    def test_a_dns_listener_without_a_zone_is_refused(self):
        # A DNS listener with no zone answers nothing: every query falls
        # outside the zone it does not have.
        with self.assertRaises(ValueError) as caught:
            load_listeners(self._config(transport="dns", settings={}))
        self.assertIn("zone", str(caught.exception))

    def test_a_listeners_block_that_is_not_a_list_is_refused(self):
        # A mapping would be iterated over its keys, and each key is a
        # string, so the error would arrive as "str is not a mapping" with
        # no hint about the real mistake.
        for block in ({"smb": {}}, "smb", 7):
            with self.subTest(block=block):
                with self.assertRaises(ValueError) as caught:
                    load_listeners({"c2": {"listeners": block}})
                self.assertIn("list", str(caught.exception))

    def test_the_rig_can_drive_every_transport_the_registry_has(self):
        # A transport the registry grows and the lab does not would be
        # invisible to the rig, which is the only place a listener is
        # proven against a real beacon. One list, asserted against the
        # other.
        from software.c2.listeners.registry import transport_names
        from tools import listener_lab as lab

        self.assertEqual(sorted(lab.available_transports()),
                         sorted(transport_names()),
                         "the rig and the registry disagree about which "
                         "transports exist")

    # ── what task 8 will call ──

    def test_a_spec_builds_the_listener_it_describes(self):
        spec = load_listeners(self._config(
            transport="quic", bind_port=_free_port(),
            bind_host="127.0.0.1"))[0]
        listener = spec.build()
        self.addCleanup(listener.shutdown)
        self.assertEqual(listener.address[0], "127.0.0.1")
        self.assertEqual(listener.address[1], spec.bind_port)
        self.assertEqual(listener.relay_url, spec.relay_url)

    def test_a_dns_spec_refuses_to_build_without_the_token(self):
        # It would build happily and then answer every beacon an empty
        # record, because the tasking route would refuse it -- a listener
        # that looks healthy and delivers nothing.
        spec = load_listeners(self._config(
            transport="dns", bind_port=_free_port(), bind_host="127.0.0.1",
            settings={"zone": "c2.test"}))[0]
        with self.assertRaises(ValueError) as caught:
            spec.build()
        self.assertIn("token", str(caught.exception))

        listener = spec.build(listener_token="a-token")
        self.addCleanup(listener.shutdown)
        self.assertEqual(listener.zone, "c2.test")

    def test_no_listeners_block_is_not_an_error(self):
        # Every deployment before this branch has no such block, and must
        # keep starting.
        self.assertEqual(load_listeners({"c2": {}}), [])
        self.assertEqual(load_listeners({}), [])

    # ── the beacon side, which was losing two transports ──

    def test_the_beacon_block_carries_every_transport(self):
        # `main.py` and `beacon_standalone.py` each built this mapping by
        # hand and each listed https and dns only, so a deployment could
        # not switch SMB or QUIC on at all -- the keys never reached the
        # beacon. Two copies of one mapping, both missing the same half.
        fallback = {
            "enabled": True,
            "https": {"enabled": True, "callback_url": "https://x/y"},
            "dns": {"enabled": True, "domain": "d", "resolver": "1.1.1.1"},
            "smb": {"enabled": True, "server": "10.0.0.1:445"},
            "quic": {"enabled": True, "server": "10.0.0.1:8443"},
        }
        built = beacon_config_from_fallback(
            {"beacon_interval_seconds": 60, "jitter_percent": 10,
             "encryption_key": "k", "proxy": {"mode": "none"},
             "fallback": fallback})

        for transport in ("https", "dns", "smb", "quic"):
            with self.subTest(transport=transport):
                self.assertEqual(built["c2"][transport],
                                 fallback[transport],
                                 "%s did not reach the beacon" % transport)

    def test_both_entry_points_use_the_shared_mapping(self):
        # The duplication is what let the two drift in step for as long as
        # it did. Neither file may build the block by hand again.
        for name in ("main.py", "c2/beacon_standalone.py"):
            with self.subTest(file=name):
                source = (Path("software") / name).read_text()
                self.assertIn("beacon_config_from_fallback", source,
                              "%s does not use the shared mapping" % name)
                self.assertNotIn('"https": fallback_cfg.get', source,
                                 "%s still builds the block by hand" % name)


class _SupervisedEnv:
    """A team server, a listener spec per transport, and a supervisor.

    Child processes are real. The whole point of task 8 is that a listener
    is its own process, so a test that supervised threads would be testing
    something else: a thread cannot be killed, cannot die on its own, and
    leaves no pid to assert about.
    """

    def __init__(self, key, *, managed=True, transports=("quic",)):
        self.key = key
        self.managed = managed
        self.transports = transports
        self.env = None
        self.supervisor = None

    def start(self):
        self.env = _TaskingServer(self.key, _CONTROL_TOKEN)
        self.env.start()
        specs = []
        for transport in self.transports:
            settings = {"zone": "c2.test"} if transport == "dns" else {}
            specs.append(ListenerSpec(
                name="probe-%s" % transport, transport=transport,
                enabled=True, bind_host="127.0.0.1",
                bind_port=_free_port(),
                relay_url=lab.relay_url_for(transport, self.env.agent_port),
                settings=settings))
        self.specs = specs
        self.supervisor = Supervisor(specs, managed=self.managed,
                                     listener_token=_CONTROL_TOKEN)
        return self.supervisor

    def stop(self):
        if self.supervisor is not None:
            self.supervisor.stop_all()
        if self.env is not None:
            self.env.stop()


class TestTheSupervisor(unittest.TestCase):
    """Starting, stopping and reporting on listeners that are real processes.

    Every refusal here has to carry a reason. A listener that silently
    fails to start, or a stop that returns and leaves the process running,
    both show up later as a beacon that does not check in -- which is the
    single hardest symptom in this project to attribute, because four
    other faults produce it too.
    """

    def setUp(self):
        self.raw, self.b64 = _key_pair()
        quiet = logging.getLogger("werkzeug")
        previous = quiet.level
        quiet.setLevel(logging.ERROR)
        self.addCleanup(quiet.setLevel, previous)
        self.harness = _SupervisedEnv(self.raw)
        self.addCleanup(self.harness.stop)
        self.supervisor = self.harness.start()

    def test_a_listener_starts_and_reports_running(self):
        record = self.supervisor.start("probe-quic")
        self.assertEqual(record["state"], "running")
        self.assertIsInstance(record["pid"], int)
        self.assertTrue(_pid_alive(record["pid"]),
                        "the reported pid is not a live process")

        status = {entry["name"]: entry for entry in self.supervisor.status()}
        self.assertEqual(status["probe-quic"]["state"], "running")
        self.assertEqual(status["probe-quic"]["pid"], record["pid"])

    def test_a_real_beacon_registers_through_a_supervised_child(self):
        # "running" has to mean the socket answers, not that a process
        # exists: a child that died after forking and before binding would
        # have a pid for a moment too. The only answer that settles it is a
        # beacon that got through, and this is the first test on the branch
        # where the listener is a separate process rather than a thread.
        self.supervisor.start("probe-quic")
        spec = self.specs_by_name()["probe-quic"]
        before = set(self.harness.env.agents())

        beacon = Beacon(lab.beacon_config_for(
            "quic", self.raw, (spec.bind_host, spec.bind_port)))
        beacon.start()
        self.addCleanup(beacon.stop)

        _wait_until(lambda: set(self.harness.env.agents()) - before,
                    "the beacon to register through the supervised listener",
                    timeout=30)
        name = (set(self.harness.env.agents()) - before).pop()
        self.assertTrue(name.startswith("raccoon-"))

    def test_starting_a_running_listener_is_refused_with_a_reason(self):
        first = self.supervisor.start("probe-quic")
        with self.assertRaises(SupervisorError) as caught:
            self.supervisor.start("probe-quic")
        self.assertIn("probe-quic", str(caught.exception))
        self.assertIn(str(first["pid"]), str(caught.exception),
                      "the refusal does not say which process already has it")

        # Not a second socket, and not a silent no-op: the original is
        # still the one running.
        status = self.supervisor.status()[0]
        self.assertEqual(status["pid"], first["pid"])
        self.assertEqual(status["state"], "running")

    def test_starting_a_name_that_is_not_configured_is_refused(self):
        with self.assertRaises(SupervisorError) as caught:
            self.supervisor.start("no-such-listener")
        self.assertIn("no-such-listener", str(caught.exception))

    def test_stop_leaves_no_child_behind(self):
        record = self.supervisor.start("probe-quic")
        pid = record["pid"]

        self.supervisor.stop("probe-quic")

        self.assertFalse(_pid_alive(pid),
                         "stop returned but pid %d is still alive" % pid)
        status = self.supervisor.status()[0]
        self.assertEqual(status["state"], "stopped")
        self.assertIsNone(status["pid"])

    def test_stop_during_an_exchange_closes_cleanly(self):
        # A beacon mid-handshake is the normal case for a stop: the
        # operator does not wait for a quiet moment. SMB, because it is
        # the stateful one -- an open TCP connection with half a message
        # written into it, which is exactly the state a listener could
        # hang in on the way down.
        harness = _SupervisedEnv(self.raw, transports=("smb",))
        self.addCleanup(harness.stop)
        supervisor = harness.start()
        record = supervisor.start("probe-smb")
        spec = harness.specs[0]

        half = socket.socket()
        half.settimeout(10)
        self.addCleanup(half.close)
        half.connect((spec.bind_host, spec.bind_port))
        # A length header announcing a message, and then only part of it.
        half.sendall(b"\x00\x00\x00\x80" + b"\xfeSMB" + b"\x00" * 20)
        _wait_until(
            lambda: (supervisor.status()[0].get("counters") or {})
            .get("connections_seen", 0) >= 1,
            "the child to accept the half-written connection")

        started = time.monotonic()
        supervisor.stop("probe-smb")
        took = time.monotonic() - started

        self.assertFalse(_pid_alive(record["pid"]),
                         "a child was left behind by a stop during an "
                         "exchange")
        self.assertLess(took, 10.0,
                        "the stop took %.1fs, so it waited for the hung "
                        "connection rather than closing it" % took)
        self.assertEqual(supervisor.status()[0]["state"], "stopped")

    def test_stopping_a_listener_that_is_not_running_is_refused(self):
        with self.assertRaises(SupervisorError) as caught:
            self.supervisor.stop("probe-quic")
        self.assertIn("probe-quic", str(caught.exception))

    def test_status_of_a_listener_that_died_says_so(self):
        # A child killed from outside -- a crash, an OOM, an operator with
        # a terminal. The panel must not keep showing it as running.
        record = self.supervisor.start("probe-quic")
        os.kill(record["pid"], signal.SIGKILL)
        _wait_until(lambda: self.supervisor.status()[0]["state"] != "running",
                    "the supervisor to notice the child died")

        status = self.supervisor.status()[0]
        self.assertEqual(status["state"], "died")
        self.assertIn("exit", status["detail"].lower())
        self.assertFalse(_pid_alive(record["pid"]))

    def test_a_died_listener_can_be_started_again(self):
        first = self.supervisor.start("probe-quic")
        os.kill(first["pid"], signal.SIGKILL)
        _wait_until(lambda: self.supervisor.status()[0]["state"] == "died",
                    "the supervisor to notice the child died")

        second = self.supervisor.start("probe-quic")
        self.assertNotEqual(second["pid"], first["pid"])
        self.assertEqual(second["state"], "running")

    def test_status_lists_a_configured_listener_that_never_started(self):
        status = self.supervisor.status()
        self.assertEqual(len(status), 1)
        self.assertEqual(status[0]["name"], "probe-quic")
        self.assertEqual(status[0]["state"], "stopped")
        self.assertEqual(status[0]["transport"], "quic")
        self.assertIsNone(status[0]["pid"])

    def test_no_secret_reaches_the_child_command_line(self):
        # Established before this branch: anything on a command line is
        # visible to every user on the host through ps.
        record = self.supervisor.start("probe-quic")
        command = _command_line_of(record["pid"])
        self.assertTrue(command, "could not read the child's command line")
        self.assertNotIn(_CONTROL_TOKEN, command)
        self.assertNotIn(self.b64, command,
                         "the encryption key is on a listener's command "
                         "line, and a listener must never even have it")

    def specs_by_name(self):
        return {spec.name: spec for spec in self.harness.specs}


class TestSupervisionWhenItIsNotInCharge(unittest.TestCase):
    """`managed=False`: the Docker case, where something else owns the processes.

    The compose file deliberately does not mount the Docker socket, so a
    team server in a container cannot start a sibling. The panel then has
    to show what is configured and say plainly why it cannot act, because
    a control that silently does nothing is the anti-goal this branch was
    written against.
    """

    def setUp(self):
        self.raw, self.b64 = _key_pair()
        quiet = logging.getLogger("werkzeug")
        previous = quiet.level
        quiet.setLevel(logging.ERROR)
        self.addCleanup(quiet.setLevel, previous)
        self.harness = _SupervisedEnv(self.raw, managed=False)
        self.addCleanup(self.harness.stop)
        self.supervisor = self.harness.start()

    def test_status_still_reports_what_is_configured(self):
        status = self.supervisor.status()
        self.assertEqual(len(status), 1)
        self.assertEqual(status[0]["name"], "probe-quic")
        self.assertEqual(status[0]["state"], "unmanaged")
        self.assertFalse(status[0]["can_control"])

    def test_the_reason_is_stated_rather_than_implied(self):
        for entry in self.supervisor.status():
            self.assertTrue(entry["detail"],
                            "an unmanaged listener gives no reason")
            self.assertIn("manage", entry["detail"].lower())

    def test_start_and_stop_refuse_and_say_why(self):
        for action in (self.supervisor.start, self.supervisor.stop):
            with self.subTest(action=action.__name__):
                with self.assertRaises(SupervisorError) as caught:
                    action("probe-quic")
                self.assertIn("manage", str(caught.exception).lower())


def _ask_control(port, payload, *, raw=None, timeout=5.0):
    """Send one line to a child's control socket and read the answer."""
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(raw if raw is not None
                     else json.dumps(payload).encode() + b"\n")
        buffer = b""
        while b"\n" not in buffer and len(buffer) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buffer += chunk
    if not buffer:
        return None
    return json.loads(buffer.split(b"\n", 1)[0])


def _a_non_loopback_address():
    """An address of this host that is not 127.0.0.1, or None.

    Found by asking the routing table where it would send a packet, which
    sends nothing: a connected UDP socket has a local address and no
    traffic.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 53))
        address = probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()
    return None if address.startswith("127.") else address


class TestTheControlSocket(unittest.TestCase):
    """The one new control surface on this branch.

    It can start nothing and stop nothing: the only verb is `status`. A
    listener cannot start itself, and a verb that let it stop itself would
    be a remote kill switch on the most exposed process in the
    arrangement, reachable by anything that learned one token on one host.
    Starting and stopping are things the supervisor does from outside with
    a signal.
    """

    def setUp(self):
        self.raw, self.b64 = _key_pair()
        quiet = logging.getLogger("werkzeug")
        previous = quiet.level
        quiet.setLevel(logging.ERROR)
        self.addCleanup(quiet.setLevel, previous)
        self.harness = _SupervisedEnv(self.raw)
        self.addCleanup(self.harness.stop)
        self.supervisor = self.harness.start()
        self.supervisor.start("probe-quic")
        self.port = self.supervisor._children["probe-quic"].control_port
        self.assertIsNotNone(self.port, "the child opened no control socket")

    def test_it_answers_status_to_the_control_token(self):
        answer = _ask_control(self.port,
                              {"token": self.supervisor.control_token,
                               "verb": "status"})
        self.assertEqual(answer["transport"], "quic")
        self.assertIn("counters", answer)
        self.assertIn("datagrams_seen", answer["counters"])

    def test_it_binds_loopback_only(self):
        # Asserted on the address the child reports, because the obvious
        # test -- fail to connect from another address of this host --
        # skips on a host that has only one, and a test that skips holds
        # nothing. A mutation to 0.0.0.0 survived exactly that way.
        answer = _ask_control(self.port,
                              {"token": self.supervisor.control_token,
                               "verb": "status"})
        self.assertEqual(answer["control_address"][0], "127.0.0.1",
                         "the control socket is bound to %r"
                         % (answer["control_address"],))

        outside = _a_non_loopback_address()
        if outside is not None:
            with self.assertRaises(OSError):
                socket.create_connection((outside, self.port), timeout=3)

    def test_the_token_comparison_is_constant_time(self):
        import ast

        source = _read_source("software", "c2", "listeners", "__main__.py")
        tree = ast.parse(source)
        same = [fn for fn in ast.walk(tree)
                if isinstance(fn, ast.FunctionDef) and fn.name == "_same"]
        self.assertEqual(len(same), 1)
        calls = {node.func.attr for node in ast.walk(same[0])
                 if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute)}
        self.assertIn("compare_digest", calls,
                      "the control token must not be compared with ==")

    def test_it_requires_the_token(self):
        for request in ({"verb": "status"},
                        {"token": None, "verb": "status"},
                        {"token": "", "verb": "status"},
                        {"token": "wrong", "verb": "status"}):
            with self.subTest(request=request):
                answer = _ask_control(self.port, request)
                self.assertEqual(answer, {"error": "unauthorized"})

    def test_the_control_token_is_not_the_operator_token(self):
        # A listener is the most exposed process here. One holding the
        # operator token could task the whole fleet the moment it reached
        # the operator socket, so the supervisor mints its own.
        self.assertNotEqual(self.supervisor.control_token,
                            self.harness.env.operator_token)
        answer = _ask_control(self.port,
                              {"token": self.harness.env.operator_token,
                               "verb": "status"})
        self.assertEqual(answer, {"error": "unauthorized"})

    def test_status_is_the_only_verb(self):
        for verb in ("start", "stop", "shutdown", "exec", "key", "relay",
                     "", None, 7, {"nested": True}):
            with self.subTest(verb=verb):
                answer = _ask_control(
                    self.port, {"token": self.supervisor.control_token,
                                "verb": verb})
                self.assertEqual(answer.get("error"),
                                 "the only verb is status",
                                 "verb %r was not refused" % (verb,))

    def test_a_request_that_is_not_an_object_is_refused(self):
        for raw in (b"not json\n", b"[1,2,3]\n", b'"a string"\n', b"\n"):
            with self.subTest(raw=raw):
                answer = _ask_control(self.port, None, raw=raw)
                self.assertIn("error", answer or {"error": "closed"})

    def test_the_request_read_stops_at_the_cap(self):
        # Driven directly, because over a socket the handler's own
        # five-second timeout ends the connection whether or not the cap
        # is there -- so the end-to-end flood test below passed with the
        # cap deleted. What the cap actually bounds is how many bytes a
        # fast sender can make this process hold inside those five
        # seconds, and that is only visible from inside.
        from software.c2.listeners import __main__ as child_mod

        handler = object.__new__(child_mod._ControlHandler)
        handler.request = _EndlessSocket()

        self.assertIsNone(handler._read_line(),
                          "an endless request was accepted as a line")
        self.assertLess(handler.request.given,
                        child_mod._MAX_REQUEST + 8192,
                        "the read took %d bytes before giving up"
                        % handler.request.given)

    def test_a_flood_without_a_newline_is_dropped_unanswered(self):
        # The read is capped, so a client cannot make this process buffer
        # for ever. Past the cap the connection is dropped with no reply
        # at all -- which is what distinguishes the cap from merely
        # failing to parse what arrived, and a mutation that removed the
        # cap survived a test that only checked the socket still worked
        # afterwards.
        flooded = socket.create_connection(("127.0.0.1", self.port),
                                           timeout=10)
        self.addCleanup(flooded.close)
        try:
            flooded.sendall(b"x" * 200000)
        except OSError:
            pass
        flooded.settimeout(10)
        # Dropped shows up two ways depending on whether unread bytes are
        # still in the buffer when the handler returns: an orderly close,
        # or a reset from the kernel. Both mean the request was refused
        # without being answered. A timeout would mean the opposite -- the
        # handler still waiting for a newline that is never coming -- and
        # a JSON body would mean it answered.
        try:
            answered = flooded.recv(64)
        except ConnectionResetError:
            answered = b""
        except socket.timeout:
            self.fail("the listener is still waiting for the rest of an "
                      "over-long request")
        self.assertEqual(answered, b"",
                         "the listener answered an over-long request")

        # And it is still serving for the supervisor.
        answer = _ask_control(self.port,
                              {"token": self.supervisor.control_token,
                               "verb": "status"})
        self.assertEqual(answer["transport"], "quic")

    def test_the_counters_it_reports_are_the_listener_s_own(self):
        before = _ask_control(self.port,
                              {"token": self.supervisor.control_token,
                               "verb": "status"})["counters"]
        spec = self.harness.specs[0]
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(probe.close)
        for _ in range(3):
            probe.sendto(b"not a frame", (spec.bind_host, spec.bind_port))

        def grew():
            now = _ask_control(self.port,
                               {"token": self.supervisor.control_token,
                                "verb": "status"})["counters"]
            return now["datagrams_seen"] > before["datagrams_seen"]

        _wait_until(grew, "the child's datagram count to rise")


class TestSocketActivation(unittest.TestCase):
    """A privileged port belongs to systemd or dockerd, never to a listener.

    This is what keeps the package out of `cap_add`, `setcap` and sudo:
    the descriptor for port 53 or 445 is bound by something that already
    has the privilege and handed over. The listener process runs
    unprivileged and never calls bind at all.
    """

    def _spawn(self, extra_env, *, sock=None, port=0):
        root = str(Path(__file__).resolve().parents[2])
        command = [sys.executable, "-m", "software.c2.listeners",
                   "--transport", "quic", "--name", "activated",
                   "--bind-host", "127.0.0.1", "--bind-port", str(port),
                   "--relay-url", "http://127.0.0.1:1/api/v1/beacon",
                   "--control-port", "0"]
        environment = dict(os.environ)
        environment["PYTHONPATH"] = root
        environment["PYTHONUNBUFFERED"] = "1"
        environment["RACCOON_CONTROL_TOKEN"] = _CONTROL_TOKEN
        environment.update(extra_env)

        kwargs = {}
        if sock is not None:
            fd = sock.fileno()
            # systemd hands the descriptor over as fd 3. subprocess keeps
            # whatever number it had, so it is moved into place just before
            # the exec -- and 3 has to be listed in `pass_fds` as well,
            # because the close-everything-else pass runs *after*
            # `preexec_fn` and would otherwise close the copy we just made.
            # Measured: without the 3 the child dies with "Socket operation
            # on non-socket", and it passed on the first try only because
            # a fresh process happened to give the socket fd 3 already.
            kwargs["pass_fds"] = (fd, 3)
            kwargs["preexec_fn"] = lambda: os.dup2(fd, 3)

        process = subprocess.Popen(
            command, cwd=root, env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True,
            **kwargs)
        self.addCleanup(_reap, process)
        return process

    def test_an_inherited_descriptor_is_used_instead_of_binding(self):
        bound = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(bound.close)
        bound.bind(("127.0.0.1", 0))
        chosen = bound.getsockname()[1]

        process = self._spawn({"LISTEN_FDS": "1"}, sock=bound,
                              port=chosen + 1)
        control = _control_port_of(process)
        answer = _ask_control(control, {"token": _CONTROL_TOKEN,
                                        "verb": "status"})

        # The port it serves is the inherited one, not the one on its own
        # command line. That is the whole point: bind_port becomes a label
        # the panel shows, and the socket comes from elsewhere.
        self.assertEqual(answer["address"][1], chosen,
                         "the child bound its own socket instead of using "
                         "the one it was handed")

    def test_without_listen_fds_it_binds_for_itself(self):
        process = self._spawn({}, port=_free_port())
        control = _control_port_of(process)
        answer = _ask_control(control, {"token": _CONTROL_TOKEN,
                                        "verb": "status"})
        self.assertEqual(answer["transport"], "quic")

    def test_a_descriptor_meant_for_another_process_is_ignored(self):
        # `$LISTEN_PID` is inherited by grandchildren that were never meant
        # to have the socket. Using it there would steal the descriptor
        # from the process systemd is waiting on.
        bound = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(bound.close)
        bound.bind(("127.0.0.1", 0))
        inherited = bound.getsockname()[1]
        own = _free_port()

        process = self._spawn({"LISTEN_FDS": "1", "LISTEN_PID": "1"},
                              sock=bound, port=own)
        control = _control_port_of(process)
        answer = _ask_control(control, {"token": _CONTROL_TOKEN,
                                        "verb": "status"})
        self.assertEqual(answer["address"][1], own,
                         "the child took a descriptor addressed to pid 1")
        self.assertNotEqual(answer["address"][1], inherited)

    def test_a_descriptor_of_the_wrong_kind_is_refused_with_a_reason(self):
        # A QUIC listener needs a datagram socket. Handed a stream one it
        # must say so and exit, not bind a second socket of its own: the
        # whole point of activation is that the port it should serve is
        # the one it was given.
        stream = socket.socket()
        self.addCleanup(stream.close)
        stream.bind(("127.0.0.1", 0))
        stream.listen(4)

        process = self._spawn({"LISTEN_FDS": "1"}, sock=stream,
                              port=_free_port())
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.fail("the child kept running with the wrong socket kind")
        self.assertEqual(process.returncode, 1)
        complaint = process.stderr.read()
        self.assertIn("stream", complaint)
        self.assertIn("datagram", complaint)

    def test_a_listener_started_by_hand_opens_no_control_socket(self):
        # No control token means no control surface. Same shape as the
        # rest of the branch: the socket policy is inert without
        # `operator_port`, the tasking route refuses everyone without a
        # listener token. A systemd unit with no supervisor to answer
        # should open nothing.
        root = str(Path(__file__).resolve().parents[2])
        environment = dict(os.environ)
        environment["PYTHONPATH"] = root
        environment["PYTHONUNBUFFERED"] = "1"
        environment.pop("RACCOON_CONTROL_TOKEN", None)
        process = subprocess.Popen(
            [sys.executable, "-m", "software.c2.listeners",
             "--transport", "quic", "--bind-host", "127.0.0.1",
             "--bind-port", str(_free_port()),
             "--relay-url", "http://127.0.0.1:1/api/v1/beacon"],
            cwd=root, env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True)
        self.addCleanup(_reap, process)
        line = process.stdout.readline().strip()
        self.assertEqual(line, "control-port none")


def _control_port_of(process, timeout=20.0):
    line = process.stdout.readline().strip()
    if not line.startswith("control-port "):
        raise AssertionError("the child printed %r, and its error output "
                             "was: %s" % (line, process.stderr.read()[:400]))
    value = line.split(" ", 1)[1]
    if value == "none":
        raise AssertionError("the child opened no control socket")
    del timeout
    return int(value)


def _reap(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass


class TestHowAChildIsHandled(unittest.TestCase):
    """The three escalations, driven directly rather than through a listener.

    Each of these is a path a real listener almost never takes, which is
    exactly why none of them had a test: a mutation check found all three
    invisible. A child that ignores SIGTERM, a child that never prints,
    and a child that prints something else are the three ways starting or
    stopping one goes wrong, and each would otherwise end as a process
    left behind or a team server blocked for ever.
    """

    def test_a_child_that_ignores_sigterm_is_killed(self):
        from software.c2.listeners import supervisor as sup

        ignoring = subprocess.Popen(
            [sys.executable, "-c",
             "import signal, time\n"
             "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
             "print('ready', flush=True)\n"
             "time.sleep(300)\n"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.addCleanup(_reap, ignoring)
        # Waited for, and this is the whole test. Without it the SIGTERM
        # arrives during interpreter startup, before SIG_IGN is installed,
        # so the child dies politely and the escalation never runs -- the
        # test passed with the SIGKILL deleted, in six milliseconds, and
        # held nothing at all.
        self.assertEqual(ignoring.stdout.readline().strip(), "ready",
                         "the child never reported itself ready")
        child = sup._Child(ignoring, None, os.devnull)

        with patch.object(sup, "_TERM_GRACE", 1.0):
            started = time.monotonic()
            child.terminate()
            took = time.monotonic() - started

        self.assertFalse(_pid_alive(ignoring.pid),
                         "a child that ignores SIGTERM was left running")
        self.assertLess(took, 10.0,
                        "the escalation took %.1fs" % took)

    def test_a_child_that_never_prints_is_given_up_on(self):
        # The helper moved to `listeners/child.py` when the tunnel
        # supervisor started sharing it, and is driven there rather than
        # through a re-export: a module that no longer calls a function
        # should not keep importing it so that a test can reach it.
        from software.c2.listeners import child as sup

        read_fd, write_fd = os.pipe()
        stream = os.fdopen(read_fd)
        # Cleanups run in reverse, so this registers the stream close
        # first and the write end second, which means the write end is
        # closed *first*. That order matters: the reader thread holds the
        # buffered stream's lock while it blocks, and `close()` waits for
        # that lock -- so closing the stream while nothing has sent EOF
        # deadlocks the cleanup. It hung this test until the pipe was shut
        # from the other side. In production the supervisor kills the
        # child, which closes its stdout and ends the read the same way.
        self.addCleanup(stream.close)
        self.addCleanup(os.close, write_fd)

        started = time.monotonic()
        line = sup.read_line_with_timeout(stream, 0.5)
        took = time.monotonic() - started

        self.assertIsNone(line)
        self.assertLess(took, 5.0,
                        "the read blocked for %.1fs; a child that never "
                        "prints would hold the team server" % took)

    def test_a_child_that_never_prints_is_abandoned_by_start(self):
        # The direct test of `_read_line_with_timeout` above does not cover
        # the call site, so a mutation that replaced it with a blocking
        # readline survived. This one goes through `Supervisor.start` with
        # a stand-in interpreter that prints nothing, which is what a
        # wedged listener looks like from outside.
        from software.c2.listeners import supervisor as sup

        shim = Path(tempfile.mkdtemp()) / "quiet"
        shim.write_text("#!/bin/sh\nsleep 60\n")
        shim.chmod(0o755)

        spec = ListenerSpec(name="quiet", transport="quic", enabled=True,
                            bind_host="127.0.0.1", bind_port=_free_port(),
                            relay_url="http://127.0.0.1:1/api/v1/beacon")
        supervisor = Supervisor([spec], python=str(shim))
        self.addCleanup(supervisor.stop_all)

        with patch.object(sup, "_START_TIMEOUT", 1.0):
            started = time.monotonic()
            with self.assertRaises(SupervisorError) as caught:
                supervisor.start("quiet")
            took = time.monotonic() - started

        self.assertIn("quiet", str(caught.exception))
        self.assertIn("did not come up", str(caught.exception))
        self.assertLess(took, 20.0,
                        "start blocked for %.1fs on a child that never "
                        "printed" % took)
        self.assertEqual(supervisor.status()[0]["state"], "stopped",
                         "the abandoned child is still counted as started")

    def test_a_child_that_prints_something_else_is_refused(self):
        from software.c2.listeners import supervisor as sup

        spec = ListenerSpec(name="noisy", transport="quic", enabled=True,
                            bind_host="127.0.0.1", bind_port=1,
                            relay_url="http://127.0.0.1:1")
        with tempfile.NamedTemporaryFile("w", suffix=".log",
                                         delete=False) as handle:
            handle.write("it printed a banner instead")
            stderr_path = handle.name
        self.addCleanup(os.unlink, stderr_path)

        for printed in ("hello there", "control-port", "control-port abc",
                        "CONTROL-PORT 5"):
            with self.subTest(printed=printed):
                process = _StubProcess(printed)
                with self.assertRaises(SupervisorError) as caught:
                    sup._Child._read_control_port(process, stderr_path, spec)
                self.assertIn("noisy", str(caught.exception))
                self.assertTrue(process.killed,
                                "a child that printed %r was left running"
                                % printed)

    def test_a_child_that_prints_a_port_is_accepted(self):
        # The other half of the claim: the refusals above are not simply
        # refusing everything.
        from software.c2.listeners import supervisor as sup

        spec = ListenerSpec(name="fine", transport="quic", enabled=True,
                            bind_host="127.0.0.1", bind_port=1,
                            relay_url="http://127.0.0.1:1")
        process = _StubProcess("control-port 54321")
        self.assertEqual(
            sup._Child._read_control_port(process, os.devnull, spec), 54321)
        self.assertFalse(process.killed)

        none = _StubProcess("control-port none")
        self.assertIsNone(
            sup._Child._read_control_port(none, os.devnull, spec))


class _StubProcess:
    """Just enough of a Popen to drive `_read_control_port`."""

    def __init__(self, line):
        self.stdout = io.StringIO(line + "\n")
        self.killed = False
        self.returncode = None

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        del timeout
        self.returncode = -9
        return self.returncode

    def poll(self):
        return self.returncode


class _EndlessSocket:
    """A socket that answers every read with bytes and never a newline."""

    def __init__(self):
        self.given = 0

    def recv(self, size):
        self.given += size
        return b"x" * size

    def settimeout(self, _seconds):
        pass

    def sendall(self, _data):
        raise AssertionError("an endless request must not be answered")


class TestTheListenerPanel(unittest.TestCase):
    """The 📡 panel's route, and the properties a new route erodes first.

    The interface is the only reason the listeners are separate processes
    rather than a config file -- goal 4 of the design was runtime listing,
    starting and stopping. So this route exists, and it is the third one
    added to this server on this branch, which makes the two-socket
    property the thing to check hardest.
    """

    def setUp(self):
        self.raw, self.b64 = _key_pair()
        quiet = logging.getLogger("werkzeug")
        previous = quiet.level
        quiet.setLevel(logging.ERROR)
        self.addCleanup(quiet.setLevel, previous)
        spec = ListenerSpec(
            name="panel-quic", transport="quic", enabled=True,
            bind_host="127.0.0.1", bind_port=_free_port(),
            relay_url="http://127.0.0.1:1/api/v1/beacon")
        self.spec = spec
        self.supervisor = Supervisor([spec], listener_token=_CONTROL_TOKEN)
        self.addCleanup(self.supervisor.stop_all)
        self.env = _TaskingServer(self.raw, _CONTROL_TOKEN,
                                  supervisor=self.supervisor)
        self.addCleanup(self.env.stop)
        self.env.start()

    def _get(self, path, *, port=None, token="operator-token-for-tests"):
        return self._call(path, port=port, token=token)

    def _post(self, path, *, port=None, token="operator-token-for-tests"):
        return self._call(path, port=port, token=token, method="POST")

    def _call(self, path, *, port=None, token=None, method="GET"):
        url = "http://127.0.0.1:%d%s" % (port or self.env.operator_port, path)
        request = urllib.request.Request(url, method=method)
        if token is not None:
            request.add_header("Authorization", "Bearer %s" % token)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            body = exc.read()
            try:
                return exc.code, json.loads(body or b"{}")
            except ValueError:
                return exc.code, None

    # ── the route ──

    def test_it_lists_what_is_configured(self):
        status, body = self._get("/api/server/listeners")
        self.assertEqual(status, 200)
        self.assertEqual([entry["name"] for entry in body["listeners"]],
                         ["panel-quic"])
        self.assertEqual(body["listeners"][0]["state"], "stopped")
        self.assertTrue(body["listeners"][0]["can_control"])

    def test_it_starts_and_stops_through_the_route(self):
        status, body = self._post("/api/server/listeners/panel-quic/start")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "running")
        pid = body["pid"]
        self.assertTrue(_pid_alive(pid))

        status, body = self._post("/api/server/listeners/panel-quic/stop")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "stopped")
        self.assertFalse(_pid_alive(pid), "the route returned but pid %d "
                                          "is still alive" % pid)

    def test_a_refusal_comes_back_with_its_reason(self):
        self._post("/api/server/listeners/panel-quic/start")
        status, body = self._post("/api/server/listeners/panel-quic/start")
        self.assertEqual(status, 409)
        self.assertIn("already running", body["error"])

    def test_an_unknown_name_is_refused(self):
        status, body = self._post("/api/server/listeners/nope/start")
        self.assertEqual(status, 404)
        self.assertIn("nope", body["error"])

    def test_an_unknown_action_is_refused(self):
        # No arbitrary verb reaches the supervisor: the route takes start
        # and stop and nothing else.
        for action in ("restart", "exec", "kill", "status", "START"):
            with self.subTest(action=action):
                status, body = self._post(
                    "/api/server/listeners/panel-quic/%s" % action)
                self.assertEqual(status, 404, "action %r was served" % action)
                self.assertIn("start and stop", body["error"])

    def test_nothing_outside_the_two_actions_can_start_a_listener(self):
        # The stronger claim, and the one worth holding: whatever a
        # request looks like, if it is not one of the two actions then no
        # process appears.
        #
        # A path with `..` in it is in here because my first version of
        # the test above expected a 404 for it and got a 200: urllib
        # normalises the path, and what arrives lands on the beacon
        # catch-all, which answers any POST path by design. That is
        # pre-existing cover behaviour and not this route's business --
        # but "no listener started" has to hold for it too.
        for path in ("/api/server/listeners/panel-quic/../start",
                     "/api/server/listeners/panel-quic/start/extra",
                     "/api/server/listeners//start",
                     "/api/server/listeners/panel-quic/sTaRt"):
            with self.subTest(path=path):
                self._post(path)
                self.assertEqual(self.supervisor.status()[0]["state"],
                                 "stopped",
                                 "%s started a listener" % path)

    def test_it_requires_the_operator_token(self):
        for token in (None, "", "wrong"):
            with self.subTest(token=token):
                status, _ = self._get("/api/server/listeners", token=token)
                self.assertEqual(status, 401)
                status, _ = self._post(
                    "/api/server/listeners/panel-quic/start", token=token)
                self.assertEqual(status, 401)

    def test_it_is_refused_on_the_agent_socket(self):
        # The property a new route erodes first. The agent socket serves
        # the beacon endpoint and the DNS tasking route, and nothing else;
        # everything else gets the cover answer.
        cover = {"status": "ok", "version": "2.1.0"}
        status, body = self._get("/api/server/listeners",
                                 port=self.env.agent_port)
        self.assertEqual(status, 200)
        self.assertEqual(body, cover)

        status, body = self._post("/api/server/listeners/panel-quic/start",
                                  port=self.env.agent_port)
        self.assertEqual(body, cover,
                         "a listener could be started from the beacon "
                         "socket")

    def test_no_response_carries_the_encryption_key(self):
        self._post("/api/server/listeners/panel-quic/start")
        for path in ("/api/server/listeners",):
            _status, body = self._get(path)
            blob = json.dumps(body)
            self.assertNotIn(self.b64, blob)
            self.assertNotIn(base64.b64encode(self.raw).decode(), blob)
            self.assertNotIn(self.raw.hex(), blob)
        # And the control token stays between the supervisor and its
        # children: the panel never needs it.
        _status, body = self._get("/api/server/listeners")
        self.assertNotIn(self.supervisor.control_token, json.dumps(body))

    def test_an_unconfigured_server_says_so_rather_than_failing(self):
        # Every deployment before this branch has no supervisor at all.
        bare = _TaskingServer(self.raw, None)
        self.addCleanup(bare.stop)
        bare.start()
        request = urllib.request.Request(
            "http://127.0.0.1:%d/api/server/listeners" % bare.operator_port)
        request.add_header("Authorization", "Bearer %s" % bare.operator_token)
        with urllib.request.urlopen(request, timeout=10) as response:
            body = json.loads(response.read())
        self.assertEqual(body["listeners"], [])
        self.assertIn("detail", body)
        self.assertTrue(body["detail"],
                        "a server with no listeners gives no explanation")

        # And a start button pressed against it refuses with a reason
        # rather than failing. Without this the route calls a method on
        # None and answers 500, which tells an operator nothing.
        action = urllib.request.Request(
            "http://127.0.0.1:%d/api/server/listeners/anything/start"
            % bare.operator_port, method="POST")
        action.add_header("Authorization", "Bearer %s" % bare.operator_token)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(action, timeout=10)
        self.assertEqual(caught.exception.code, 409)
        self.assertIn("no listeners are configured",
                      json.loads(caught.exception.read())["error"])


class TestThePanelMarkup(unittest.TestCase):
    """What the served page says, read out of the page itself."""

    @classmethod
    def setUpClass(cls):
        cls.page = _served_page()

    def test_the_header_has_the_button_between_generator_and_loot(self):
        generator = self.page.index("showBeaconGen()")
        loot = self.page.index("showLootViewer()")
        panel = self.page.index("showListeners()")
        self.assertLess(generator, panel,
                        "the listeners button is before the generator")
        self.assertLess(panel, loot,
                        "the listeners button is after the loot button")
        window = self.page[generator:loot]
        self.assertIn("&#128225;", window,
                      "the button is not the satellite antenna")

    def test_the_panel_states_the_dns_limit_in_words(self):
        # An operator tasking a DNS-only agent must be told, in the place
        # they are doing it, that the task will be delivered once and
        # never reported on.
        for phrase in ("tasking only", "never report"):
            self.assertIn(phrase, self.page.lower(),
                          "the panel does not say %r" % phrase)

    def test_the_controls_are_disabled_with_a_reason_when_unmanaged(self):
        # Not greyed out and silent: the reason is rendered. A control
        # that silently does nothing is the anti-goal of this branch.
        self.assertIn("can_control", self.page)
        self.assertIn("disabled", self.page)
        self.assertIn("entry.detail", self.page,
                      "the panel never renders the reason it was given")

    def test_an_agent_last_reached_over_dns_is_flagged_in_its_header(self):
        self.assertTrue("last_channel === 'dns'" in self.page,
                        "the agent header does not check the channel")
        self.assertIn("VIA DNS", self.page)
        window = self.page[self.page.index("VIA DNS") - 400:
                           self.page.index("VIA DNS") + 400]
        self.assertIn("never reported", window,
                      "the flag does not say what the limit is")

    def test_every_value_a_listener_influences_is_escaped(self):
        # A listener's name and detail come from configuration and from a
        # child process. The hardening pass established that each one goes
        # through esc(), and a handler is attached in JavaScript rather
        # than built into an attribute string.
        start = self.page.index("function showListeners()")
        end = self.page.index("</script>", start)
        body = self.page[start:end]
        for field in ("name", "transport", "state", "detail"):
            self.assertIn("esc(entry.%s)" % field, body,
                          "entry.%s reaches the page unescaped" % field)
        self.assertNotIn('onclick="listener', body,
                         "a handler body is built as a string")


class TestTheServerCommandLine(unittest.TestCase):
    """What `--config` does, and what it refuses.

    A listener that was silently not configured shows up as a beacon that
    never checks in, so every way of getting this wrong is fatal at
    startup with the reason printed.
    """

    def _run(self, *extra, env=None):
        root = str(Path(__file__).resolve().parents[2])
        environment = dict(os.environ)
        environment["PYTHONPATH"] = root
        environment.pop("RACCOON_LISTENER_TOKEN", None)
        environment.update(env or {})
        return subprocess.run(
            [sys.executable, "-m", "software.c2.server", "--help"] + list(extra),
            cwd=root, env=environment, capture_output=True, text=True,
            timeout=60)

    def _start(self, config_path, *extra, env=None):
        root = str(Path(__file__).resolve().parents[2])
        environment = dict(os.environ)
        environment["PYTHONPATH"] = root
        environment.pop("RACCOON_LISTENER_TOKEN", None)
        environment.update(env or {})
        key = base64.b64encode(os.urandom(32)).decode()
        return subprocess.run(
            [sys.executable, "-m", "software.c2.server",
             "--key", key, "--config", str(config_path),
             "--port", str(_free_port()),
             "--operator-port", str(_free_port()),
             "--data-dir", tempfile.mkdtemp()] + list(extra),
            cwd=root, env=environment, capture_output=True, text=True,
            timeout=60)

    def _config(self, text):
        path = Path(tempfile.mkdtemp()) / "raccoon.yaml"
        path.write_text(text)
        return path

    def test_the_flags_are_offered(self):
        done = self._run()
        self.assertIn("--config", done.stdout)
        self.assertIn("--no-manage-listeners", done.stdout)

    def test_a_config_that_cannot_be_read_is_fatal(self):
        done = self._start("/nonexistent/raccoon.yaml")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("could not read", done.stderr)

    def test_a_config_with_a_bad_listener_is_fatal_with_the_reason(self):
        path = self._config(
            "c2:\n"
            "  listeners:\n"
            "    - name: wrong\n"
            "      transport: telepathy\n"
            "      bind_port: 1234\n"
            "      relay_url: http://127.0.0.1:8443/api/v1/beacon\n")
        done = self._start(path)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("telepathy", done.stderr)

    def test_a_dns_listener_without_the_token_is_fatal(self):
        # It would start and look healthy while answering every beacon an
        # empty record, because the tasking route would refuse it.
        path = self._config(
            "c2:\n"
            "  listeners:\n"
            "    - name: dns-53\n"
            "      transport: dns\n"
            "      bind_port: 1053\n"
            "      relay_url: http://127.0.0.1:8443\n"
            "      settings:\n"
            "        zone: c2.example\n")
        done = self._start(path)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("RACCOON_LISTENER_TOKEN", done.stderr)
        self.assertNotIn("--listener-token", done.stderr,
                         "the message suggests putting a secret on the "
                         "command line")

    def test_the_shipped_config_starts_the_server(self):
        # The file this project ships has all three listeners disabled and
        # one of them is DNS, so reading it must not require a token --
        # and it must not stop the server from coming up.
        #
        # Started rather than run to completion: the server runs until it
        # is killed, so `subprocess.run` with a timeout raises, which my
        # first version of this treated as the success case and then did
        # not catch.
        root = str(Path(__file__).resolve().parents[2])
        environment = dict(os.environ)
        environment["PYTHONPATH"] = root
        environment["RACCOON_LISTENER_TOKEN"] = "a-token"
        process = subprocess.Popen(
            [sys.executable, "-m", "software.c2.server",
             "--key", base64.b64encode(os.urandom(32)).decode(),
             "--config", "configs/raccoon.yaml",
             "--port", str(_free_port()),
             "--operator-port", str(_free_port()),
             "--data-dir", tempfile.mkdtemp()],
            cwd=root, env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        self.addCleanup(_reap, process)

        try:
            process.wait(timeout=6)
        except subprocess.TimeoutExpired:
            return                      # still running: it started
        self.fail("the server exited with %d; its error output was: %s"
                  % (process.returncode, process.stderr.read()[:400]))


_LISTENER_SERVICES = ("raccoon-listener-smb", "raccoon-listener-quic",
                      "raccoon-listener-dns")


def _compose():
    import yaml

    with open(Path("software") / "c2" / "docker-compose.yml") as handle:
        return yaml.safe_load(handle)


def _unit(name):
    return (Path("services") / name).read_text()


def _directives(text):
    """The lines that do something, with the prose dropped.

    These files explain at length that they use no capability and no
    setcap, which made three tests fail against their own rationale: a
    check for a directive has to look at directives. The same mistake as
    the docs probe that read "compare_digest appears somewhere in the
    file" as "the token comparison was fixed".
    """
    return "\n".join(line for line in text.splitlines()
                      if line.strip() and not line.lstrip().startswith("#"))


class TestTheListenerContainers(unittest.TestCase):
    """How the compose file runs a listener, and what it refuses to give it.

    The whole argument for separate processes is blast radius. A listener
    container that ran as root, held a capability, or carried the
    encryption key would have given that up -- so each of those is a test
    rather than a comment.
    """

    @classmethod
    def setUpClass(cls):
        cls.compose = _compose()
        cls.services = cls.compose["services"]

    def test_there_is_a_service_per_transport(self):
        from software.c2.listeners.registry import transport_names

        for transport in transport_names():
            name = "raccoon-listener-%s" % transport
            self.assertIn(name, self.services,
                          "%s has no container" % transport)

    def test_they_are_not_on_the_host_network(self):
        # Port mapping does not exist under network_mode: host, and
        # publishing a privileged port is the entire mechanism that keeps
        # these unprivileged. The team server stays on the host network
        # because Responder and the relay tooling need it; a listener
        # needs one port and nothing else.
        for name in _LISTENER_SERVICES:
            with self.subTest(service=name):
                service = self.services[name]
                self.assertNotEqual(service.get("network_mode"), "host",
                                    "%s cannot publish a port" % name)
                self.assertTrue(service.get("ports"),
                                "%s publishes no port" % name)

    def test_the_privileged_ports_are_published_not_bound(self):
        # dockerd holds the privilege. Inside the container the listener
        # binds something above 1024 as an unprivileged user, and the
        # mapping is what makes 445 and 53 answer.
        expected = {"raccoon-listener-smb": ("445", False),
                    "raccoon-listener-dns": ("53", True)}
        for name, (outside, udp) in expected.items():
            with self.subTest(service=name):
                published = self.services[name]["ports"]
                mapping = str(published[0])
                self.assertTrue(mapping.startswith(outside + ":"),
                                "%s publishes %r, not port %s"
                                % (name, mapping, outside))
                inside = mapping.split(":")[1].split("/")[0]
                self.assertGreater(int(inside), 1024,
                                   "%s binds privileged port %s inside the "
                                   "container, which needs privilege it "
                                   "must not have" % (name, inside))
                self.assertEqual(mapping.endswith("/udp"), udp,
                                 "%s has the wrong protocol" % name)

    def test_none_of_them_adds_a_capability(self):
        for name in _LISTENER_SERVICES:
            with self.subTest(service=name):
                service = self.services[name]
                self.assertNotIn("cap_add", service,
                                 "%s adds a capability" % name)
                self.assertNotIn("privileged", service)
                self.assertEqual(service.get("cap_drop"), ["ALL"],
                                 "%s does not drop every capability" % name)

    def test_none_of_them_runs_as_root(self):
        for name in _LISTENER_SERVICES:
            with self.subTest(service=name):
                user = str(self.services[name].get("user", ""))
                self.assertTrue(user, "%s names no user, so it is root"
                                % name)
                self.assertFalse(user.startswith("0:") or user == "0"
                                 or user == "root",
                                 "%s runs as root" % name)

    def test_none_of_them_can_gain_privilege(self):
        for name in _LISTENER_SERVICES:
            with self.subTest(service=name):
                opts = self.services[name].get("security_opt") or []
                self.assertIn("no-new-privileges:true", opts,
                              "%s can gain privilege through a setuid "
                              "binary" % name)

    def test_none_of_them_is_given_the_encryption_key(self):
        # The property the whole package rests on. A listener moves opaque
        # ciphertext; one holding the key could read every beacon and
        # forge any answer.
        for name in _LISTENER_SERVICES:
            with self.subTest(service=name):
                environment = self.services[name].get("environment") or []
                joined = " ".join(str(item) for item in environment)
                for banned in ("RACCOON_KEY", "RACCOON_TOKEN",
                               "encryption_key"):
                    self.assertTrue(banned not in joined,
                                    "%s is given %s" % (name, banned))

    def test_they_reach_the_team_server_through_the_host_gateway(self):
        # The team server is on the host network and these are not, so
        # there is no compose network they share and no service name to
        # resolve. `host-gateway` is the one route between them.
        for name in _LISTENER_SERVICES:
            with self.subTest(service=name):
                service = self.services[name]
                hosts = " ".join(service.get("extra_hosts") or [])
                self.assertIn("host-gateway", hosts,
                              "%s has no route to the team server" % name)
                command = " ".join(str(x) for x in (service.get("command")
                                                    or []))
                if isinstance(service.get("command"), str):
                    command = service["command"]
                self.assertIn("host.docker.internal", command,
                              "%s relays somewhere other than the host"
                              % name)

    def test_a_plain_up_starts_none_of_them(self):
        # A listener is a socket facing the network, and nothing should
        # open one because a file happened to mention it. The compose
        # equivalent of `enabled: false` in raccoon.yaml is a profile, and
        # unlike commenting the services out it leaves them readable and
        # testable.
        for name in _LISTENER_SERVICES:
            with self.subTest(service=name):
                self.assertEqual(self.services[name].get("profiles"),
                                 ["listeners"],
                                 "%s would start on a plain docker compose "
                                 "up" % name)
        for name in ("raccoon-c2", "agent"):
            with self.subTest(service=name):
                self.assertIsNone(self.services[name].get("profiles"),
                                  "%s was put behind a profile" % name)

    def test_they_build_their_own_image_not_the_team_server_s(self):
        # The team server's image carries impacket, NetExec, Responder and
        # a graphical RDP client. A listener is stdlib only, and running it
        # from that image would put all of it one process away from the
        # port that faces the network.
        for name in _LISTENER_SERVICES:
            with self.subTest(service=name):
                build = self.services[name].get("build")
                self.assertIsInstance(build, dict,
                                      "%s does not build its own image"
                                      % name)
                self.assertIn("listeners", build.get("dockerfile", ""),
                              "%s builds from %r" % (name, build))

    def test_the_listener_image_installs_nothing(self):
        # Stdlib only is a property, not an aspiration: a pip install in
        # this image would be the first dependency a listener container
        # ever had.
        text = _directives(
            (Path("software") / "c2" / "listeners" / "Dockerfile").read_text())
        for banned in ("pip install", "apt-get install", "apk add"):
            self.assertTrue(banned not in text,
                            "the listener image runs %r" % banned)

    def test_the_listener_image_does_not_copy_the_team_server(self):
        text = _directives(
            (Path("software") / "c2" / "listeners" / "Dockerfile").read_text())
        self.assertTrue("server.py" not in text,
                        "the listener image carries the team server")
        self.assertTrue("beacon.py" not in text,
                        "the listener image carries the beacon")


class TestTheListenerUnits(unittest.TestCase):
    """The systemd half: socket activation, so no unit needs privilege.

    A `.socket` unit is owned by systemd, which already has the privilege
    to bind 53 and 445. It hands the descriptor to a `.service` unit that
    runs as an unprivileged user and never calls bind. That is why this
    package needs no `cap_add`, no `setcap` and no sudo.
    """

    def test_a_socket_and_a_service_unit_exist_per_transport(self):
        from software.c2.listeners.registry import transport_names

        for transport in transport_names():
            for suffix in (".socket", ".service"):
                name = "raccoon-listener-%s%s" % (transport, suffix)
                with self.subTest(unit=name):
                    self.assertTrue((Path("services") / name).exists(),
                                    "%s is missing" % name)

    def test_the_socket_units_declare_the_privileged_port(self):
        expected = {"smb": "ListenStream=445",
                    "dns": "ListenDatagram=53",
                    "quic": "ListenDatagram="}
        for transport, directive in expected.items():
            with self.subTest(transport=transport):
                text = _unit("raccoon-listener-%s.socket" % transport)
                self.assertIn(directive, text,
                              "the %s socket unit does not declare its port"
                              % transport)

    def test_the_service_units_run_as_an_unprivileged_user(self):
        for transport in ("smb", "dns", "quic"):
            with self.subTest(transport=transport):
                text = _unit("raccoon-listener-%s.service" % transport)
                self.assertIn("User=", text,
                              "the %s service unit names no user, so it is "
                              "root" % transport)
                user = [line.split("=", 1)[1].strip()
                        for line in text.splitlines()
                        if line.startswith("User=")][0]
                self.assertNotIn(user, ("root", "0"),
                                 "the %s listener runs as root" % transport)

    def test_the_service_units_take_the_socket_from_systemd(self):
        for transport in ("smb", "dns", "quic"):
            with self.subTest(transport=transport):
                text = _unit("raccoon-listener-%s.service" % transport)
                self.assertIn("Requires=raccoon-listener-%s.socket"
                              % transport, text,
                              "the %s service does not require its socket"
                              % transport)
                self.assertIn("software.c2.listeners", text,
                              "the %s service starts something else"
                              % transport)

    def test_no_unit_grants_a_capability_or_uses_setcap(self):
        for transport in ("smb", "dns", "quic"):
            for suffix in (".socket", ".service"):
                name = "raccoon-listener-%s%s" % (transport, suffix)
                with self.subTest(unit=name):
                    text = _directives(_unit(name))
                    for banned in ("AmbientCapabilities",
                                   "CapabilityBoundingSet=CAP_NET_BIND",
                                   "setcap", "PermissionsStartOnly"):
                        self.assertTrue(banned not in text,
                                        "%s uses %s" % (name, banned))

    def test_no_unit_carries_a_secret_on_a_command_line(self):
        for transport in ("smb", "dns", "quic"):
            text = _unit("raccoon-listener-%s.service" % transport)
            exec_lines = [line for line in text.splitlines()
                          if line.startswith("ExecStart")]
            self.assertTrue(exec_lines)
            for line in exec_lines:
                with self.subTest(transport=transport):
                    for banned in ("--control-token", "--listener-token",
                                   "RACCOON_KEY=", "--key"):
                        self.assertTrue(banned not in line,
                                        "%s puts a secret where ps can "
                                        "read it" % transport)

    def test_the_dns_unit_reads_its_token_from_a_file(self):
        # It needs one, and a unit file is world-readable: EnvironmentFile
        # points at something that is not.
        text = _directives(_unit("raccoon-listener-dns.service"))
        self.assertIn("EnvironmentFile=", text,
                      "the DNS listener has nowhere to get its token")
        self.assertTrue("RACCOON_LISTENER_TOKEN=" not in text,
                        "the token is written into the unit file")


class TestThePayloadFieldsAgree(unittest.TestCase):
    """The three copies of the field list, held in step.

    `beacon.py` and `server.py` have each carried this list since before
    this branch, with a comment asking them to match and nothing checking
    it. `relay.py` is now a third copy, for a reason recorded in that
    file: importing the beacon's would put the entire implant source --
    persistence, loot, the SMB browser, exfiltration -- into the one
    container that faces the network, and the beacon cannot import a
    shared module because the generator serves it as a single file.

    So: three copies by necessity, one test.
    """

    def _lists(self):
        from software.c2 import beacon as beacon_mod
        from software.c2 import server as server_mod
        from software.c2.listeners import relay as relay_mod

        return {
            "beacon.py": beacon_mod._PAYLOAD_FIELDS,
            "server.py": server_mod._PAYLOAD_FIELDS,
            "listeners/relay.py": relay_mod._PAYLOAD_FIELDS,
        }

    def test_all_three_carry_the_same_names(self):
        lists = self._lists()
        reference = lists["beacon.py"]
        for name, values in lists.items():
            with self.subTest(module=name):
                self.assertEqual(values, reference,
                                 "%s has drifted from beacon.py" % name)

    def test_the_list_is_not_empty_and_has_no_duplicates(self):
        # A field the server never picks is dead cover, and a duplicate
        # would weight the random choice without saying so.
        for name, values in self._lists().items():
            with self.subTest(module=name):
                self.assertGreater(len(values), 5)
                self.assertEqual(len(set(values)), len(values),
                                 "%s repeats a field name" % name)

    def test_the_relay_does_not_import_the_beacon(self):
        # The property the copy exists for. A listener container must not
        # need `beacon.py`, and the Dockerfile does not copy it -- so an
        # import here would be a container that crashes on startup, which
        # is how this was found.
        imported, _used = _imports_and_names("software", "c2", "listeners",
                                             "relay.py")
        self.assertTrue("beacon" not in " ".join(imported),
                        "the relay imports the beacon again")

    def test_no_listener_module_imports_the_beacon_or_the_server(self):
        # Read as imports, not as text. My first version searched the
        # source for "from ..beacon" and failed on the comment in relay.py
        # that quotes the import it replaced -- the third time on this
        # branch that a check for a construct read the prose explaining
        # it. The AST knows the difference.
        for module in ("relay.py", "dns.py", "quic.py", "smb.py",
                       "registry.py", "supervisor.py", "__main__.py",
                       "errors.py", "child.py"):
            with self.subTest(module=module):
                imported, _used = _imports_and_names(
                    "software", "c2", "listeners", module)
                # Exact names. A substring test called `socketserver` a
                # team-server import, which is the fourth variation of the
                # same mistake: a check that is looser than the property
                # it names will eventually fire on something innocent.
                banned = {"beacon", "server", "software.c2.beacon",
                          "software.c2.server"}
                self.assertEqual(banned & set(imported), set(),
                                 "%s imports %s"
                                 % (module, banned & set(imported)))


# New test classes belong above this guard; never append below it.
if __name__ == "__main__":
    unittest.main()
