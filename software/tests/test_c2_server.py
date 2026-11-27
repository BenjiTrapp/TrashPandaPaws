#!/usr/bin/env python3
"""
Integration tests: spins up the C2 server in-process and connects
a real beacon agent against it. Validates the full encrypted protocol:
registration, beacon check-in, task dispatch, result collection,
re-registration, operator API, and evasive URL handling.
"""

import base64
import contextlib
import json
import logging
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.c2.server import (
    ServerCrypto,
    create_app,
    agents,
    task_queues,
    history,
    results,
    _PAYLOAD_FIELDS,
)
from software.c2.beacon import Beacon
from tools.demo_env import key_b64, random_key


def _pick_port() -> int:
    """A free port for this process, honouring RACCOON_TEST_PORT.

    It used to be 19999, written in three places. The Flask thread these
    tests start is a daemon and never gives the port back, so a second
    process that re-runs this module while the first is still alive cannot
    bind it -- and the failure surfaces as "Beacon did not register in
    time", which points at the beacon rather than at the port. That is
    exactly what happened once test_status_quo began re-running these suites
    in a subprocess: the two were green apart and red together.
    """
    override = os.environ.get("RACCOON_TEST_PORT")
    if override:
        return int(override)
    import contextlib
    import socket
    with contextlib.closing(socket.socket()) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


PORT = _pick_port()
# One key for the whole module, minted once and handed to both ends: a key
# mismatch is silent -- the beacon's registration is never accepted and the
# fleet simply stays empty -- so the server and every beacon config take it
# from here rather than each making their own.
KEY = random_key()
DNS_DOMAIN = ""
TEST_TOKEN = "test-operator-token"


def _beacon_config(port: int = None, interval: int = 1) -> dict:
    port = PORT if port is None else port
    return {
        "c2": {
            "beacon_interval_seconds": interval,
            "jitter_percent": 0,
            "encryption_key": key_b64(KEY),
            "proxy": {"mode": "none"},
            "https": {
                "enabled": True,
                "callback_url": f"http://127.0.0.1:{port}/api/v1/beacon",
                "verify_ssl": False,
            },
            "dns": {
                "enabled": False,
                "domain": DNS_DOMAIN,
                "resolver": "8.8.8.8",
            },
        }
    }


@contextlib.contextmanager
def logged_tracebacks():
    """Every log record carrying a traceback while the block runs.

    On the root logger, because Flask reports an unhandled exception on
    the app's own logger, not on `raccoon.c2.server`, and both propagate
    there. Python 3.9 has no `assertNoLogs`.
    """
    seen = []
    handler = logging.Handler(logging.DEBUG)
    handler.emit = lambda record: (seen.append(record)
                                   if record.exc_info else None)
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        yield seen
    finally:
        root.removeHandler(handler)


# Valid JSON that is not an object: each survives `get_json(silent=True)`,
# and each is truthy, so `or {}` let it through to `.get`.
NOT_AN_OBJECT = ([1], "x", 7)


def _reset_server_state():
    import software.c2.server as srv
    agents.clear()
    task_queues.clear()
    history.clear()
    results.clear()
    srv._name_counter = 0


class ServerTestBase(unittest.TestCase):
    """Starts a Flask test client for each test class."""

    port = PORT

    @classmethod
    def setUpClass(cls):
        _reset_server_state()
        cls.crypto = ServerCrypto(KEY)
        cls.data_dir = Path(tempfile.mkdtemp())
        cls.app = create_app(cls.crypto, TEST_TOKEN, cls.data_dir)
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

        cls.flask_thread = threading.Thread(
            target=cls.app.run,
            kwargs={"host": "127.0.0.1", "port": cls.port, "use_reloader": False},
            daemon=True,
        )
        cls.flask_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.data_dir, ignore_errors=True)

    def _operator_get(self, path: str) -> dict:
        r = self.client.get(path, headers={"Authorization": f"Bearer {TEST_TOKEN}"})
        return r.get_json()

    def _operator_post(self, path: str, data: dict) -> dict:
        r = self.client.post(
            path,
            data=json.dumps(data),
            content_type="application/json",
            headers={"Authorization": f"Bearer {TEST_TOKEN}"},
        )
        return r.get_json()

    def _beacon_post(self, path: str, payload: dict) -> dict:
        wrapped = self.crypto.wrap(payload)
        r = self.client.post(
            path,
            data=json.dumps(wrapped),
            content_type="application/json",
        )
        body = r.get_json()
        unwrapped = self.crypto.unwrap(body)
        return unwrapped if unwrapped is not None else body


# ── Crypto unit tests ──


class TestServerCrypto(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        crypto = ServerCrypto(os.urandom(32))
        data = {"action": "register", "id": "abc123"}
        self.assertEqual(crypto.decrypt(crypto.encrypt(data)), data)

    def test_wrap_unwrap_roundtrip(self):
        crypto = ServerCrypto(os.urandom(32))
        data = {"success": True, "agent_id": "raccoon-test"}
        self.assertEqual(crypto.unwrap(crypto.wrap(data)), data)

    def test_unwrap_fails_on_wrong_key(self):
        c1 = ServerCrypto(os.urandom(32))
        c2 = ServerCrypto(os.urandom(32))
        self.assertIsNone(c2.unwrap(c1.wrap({"secret": True})))

    def test_nonce_uniqueness(self):
        crypto = ServerCrypto(os.urandom(32))
        self.assertNotEqual(crypto.encrypt({"x": 1}), crypto.encrypt({"x": 1}))

    def test_wrapped_has_decoy_fields(self):
        crypto = ServerCrypto(os.urandom(32))
        self.assertGreaterEqual(len(crypto.wrap({"d": 1})), 4)

    def test_payload_field_from_known_list(self):
        crypto = ServerCrypto(os.urandom(32))
        wrapped = crypto.wrap({"d": 1})
        found = [k for k in wrapped if k in _PAYLOAD_FIELDS]
        self.assertEqual(len(found), 1)


# ── Registration ──


class TestRegistration(ServerTestBase):
    def test_register_new_agent(self):
        _reset_server_state()
        resp = self._beacon_post("/api/v1/register", {
            "action": "register", "id": "impl-001",
            "hostname": "testbox", "os": "Linux", "arch": "aarch64",
            "user": "root", "pid": 1234, "interval": 10, "uptime": 42,
        })
        self.assertTrue(resp["success"])
        self.assertIn("raccoon-", resp["agent_id"])
        self.assertEqual(len(agents), 1)

    def test_unique_names(self):
        _reset_server_state()
        ids = set()
        for i in range(5):
            resp = self._beacon_post("/r", {
                "action": "register", "id": f"impl-{i}",
                "hostname": f"h{i}", "os": "L", "arch": "x", "user": "u", "pid": i, "interval": 60,
            })
            ids.add(resp["agent_id"])
        self.assertEqual(len(ids), 5)

    def test_re_register_keeps_agent_id(self):
        _reset_server_state()
        payload = {
            "action": "register", "id": "re-reg",
            "hostname": "box1", "os": "L", "arch": "arm64",
            "user": "admin", "pid": 999, "interval": 30,
        }
        aid1 = self._beacon_post("/r", payload)["agent_id"]
        payload["hostname"] = "box1-updated"
        aid2 = self._beacon_post("/r", payload)["agent_id"]
        self.assertEqual(aid1, aid2)
        self.assertEqual(agents[aid1]["hostname"], "box1-updated")
        self.assertEqual(len(agents), 1)

    def test_register_via_evasive_url(self):
        _reset_server_state()
        resp = self._beacon_post("/totally/random/path?_t=123&sid=456", {
            "action": "register", "id": "evasive",
            "hostname": "s", "os": "W", "arch": "A", "user": "u", "pid": 4, "interval": 5,
        })
        self.assertTrue(resp["success"])


# ── Beacon check-in ──


class TestBeaconCheckin(ServerTestBase):
    def _register(self, implant_id="ci-test"):
        self._beacon_post("/r", {
            "action": "register", "id": implant_id,
            "hostname": "h", "os": "L", "arch": "x", "user": "u", "pid": 1, "interval": 5,
        })
        return list(agents.keys())[0]

    def test_no_tasks_returns_empty(self):
        _reset_server_state()
        aid = self._register()
        resp = self._beacon_post("/b", {
            "action": "beacon", "agent_id": aid, "id": "ci-test", "interval": 5, "uptime": 100,
        })
        self.assertEqual(resp, {})

    def test_dispatches_queued_task(self):
        _reset_server_state()
        aid = self._register()
        self._operator_post(f"/api/agents/{aid}/task", {"cmd": "shell", "args": "whoami"})
        resp = self._beacon_post("/b", {
            "action": "beacon", "agent_id": aid, "id": "ci-test", "interval": 5,
        })
        self.assertEqual(resp["cmd"], "shell")
        self.assertEqual(resp["args"], "whoami")

    def test_updates_last_seen(self):
        _reset_server_state()
        aid = self._register()
        ts1 = agents[aid]["_last_seen_ts"]
        time.sleep(0.05)
        self._beacon_post("/b", {
            "action": "beacon", "agent_id": aid, "id": "ci-test", "interval": 5,
        })
        self.assertGreater(agents[aid]["_last_seen_ts"], ts1)

    def test_lookup_by_implant_id(self):
        _reset_server_state()
        aid = self._register("fallback-id")
        self._operator_post(f"/api/agents/{aid}/task", {"cmd": "pwd"})
        resp = self._beacon_post("/b", {
            "action": "beacon", "id": "fallback-id", "interval": 5,
        })
        self.assertEqual(resp["cmd"], "pwd")


# ── Task results ──


class TestTaskResults(ServerTestBase):
    def _register(self):
        _reset_server_state()
        self._beacon_post("/r", {
            "action": "register", "id": "res-test",
            "hostname": "h", "os": "L", "arch": "x", "user": "u", "pid": 1, "interval": 5,
        })
        return list(agents.keys())[0]

    def test_result_stored(self):
        aid = self._register()
        resp = self._beacon_post("/result", {
            "action": "result", "task_id": "t-42",
            "agent_id": aid, "status": "ok", "output": "root\n",
        })
        self.assertTrue(resp.get("ack"))
        self.assertEqual(results["t-42"]["output"], "root\n")

    def test_result_updates_history(self):
        aid = self._register()
        self._operator_post(f"/api/agents/{aid}/task", {"cmd": "shell", "args": "id"})
        tid = history[aid][0]["task_id"]
        self._beacon_post("/result", {
            "action": "result", "task_id": tid,
            "agent_id": aid, "status": "ok", "output": "uid=0(root)",
        })
        self.assertEqual(history[aid][0]["status"], "ok")
        self.assertEqual(history[aid][0]["output"], "uid=0(root)")

    def test_fifo_order(self):
        aid = self._register()
        self._operator_post(f"/api/agents/{aid}/task", {"cmd": "pwd"})
        self._operator_post(f"/api/agents/{aid}/task", {"cmd": "ls", "args": "/tmp"})
        self._operator_post(f"/api/agents/{aid}/task", {"cmd": "shell", "args": "uname"})

        r1 = self._beacon_post("/b", {"action": "beacon", "agent_id": aid, "interval": 5})
        r2 = self._beacon_post("/b", {"action": "beacon", "agent_id": aid, "interval": 5})
        r3 = self._beacon_post("/b", {"action": "beacon", "agent_id": aid, "interval": 5})
        self.assertEqual([r1["cmd"], r2["cmd"], r3["cmd"]], ["pwd", "ls", "shell"])


# ── Operator API ──


class TestOperatorAPI(ServerTestBase):
    def test_list_agents(self):
        _reset_server_state()
        self._beacon_post("/r", {
            "action": "register", "id": "api-1",
            "hostname": "apibox", "os": "Linux", "arch": "arm64",
            "user": "op", "pid": 7777, "interval": 10,
        })
        lst = self._operator_get("/api/agents")
        self.assertEqual(len(lst), 1)
        self.assertEqual(lst[0]["hostname"], "apibox")

    def test_agent_detail(self):
        _reset_server_state()
        self._beacon_post("/r", {
            "action": "register", "id": "det-1",
            "hostname": "detailbox", "os": "W", "arch": "AMD64",
            "user": "admin", "pid": 8888, "interval": 30,
        })
        aid = list(agents.keys())[0]
        d = self._operator_get(f"/api/agents/{aid}")
        self.assertEqual(d["hostname"], "detailbox")

    def test_unauthorized_rejected(self):
        self.assertEqual(self.client.get("/api/agents").status_code, 401)
        r = self.client.get("/api/agents", headers={"Authorization": "Bearer wrong"})
        self.assertEqual(r.status_code, 401)

    def test_create_task(self):
        _reset_server_state()
        self._beacon_post("/r", {
            "action": "register", "id": "tsk-1",
            "hostname": "h", "os": "L", "arch": "x", "user": "u", "pid": 1, "interval": 5,
        })
        aid = list(agents.keys())[0]
        task = self._operator_post(f"/api/agents/{aid}/task", {
            "cmd": "shell", "args": "cat /etc/passwd", "timeout": 60,
        })
        self.assertIn("id", task)
        self.assertEqual(task["cmd"], "shell")
        self.assertEqual(task["status"], "pending")

    def test_task_history(self):
        _reset_server_state()
        self._beacon_post("/r", {
            "action": "register", "id": "hst-1",
            "hostname": "h", "os": "L", "arch": "x", "user": "u", "pid": 1, "interval": 5,
        })
        aid = list(agents.keys())[0]
        self._operator_post(f"/api/agents/{aid}/task", {"cmd": "pwd"})
        self._operator_post(f"/api/agents/{aid}/task", {"cmd": "ls"})
        hist = self._operator_get(f"/api/agents/{aid}/history")
        self.assertEqual(len(hist), 2)

    def test_nonexistent_agent_404(self):
        h = {"Authorization": f"Bearer {TEST_TOKEN}"}
        self.assertEqual(self.client.get("/api/agents/nope", headers=h).status_code, 404)
        r = self.client.post("/api/agents/nope/task",
                             data=json.dumps({"cmd": "pwd"}),
                             content_type="application/json", headers=h)
        self.assertEqual(r.status_code, 404)


# ── Protocol edge cases ──


class TestProtocolEdgeCases(ServerTestBase):
    def test_invalid_json_fake_response(self):
        r = self.client.post("/beacon", data="not json", content_type="text/plain")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "ok")

    def test_wrong_key_fake_response(self):
        bad = ServerCrypto(os.urandom(32))
        wrapped = bad.wrap({"action": "register", "id": "x"})
        r = self.client.post("/beacon", data=json.dumps(wrapped), content_type="application/json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "ok")

    def test_unknown_action_fake_response(self):
        resp = self._beacon_post("/beacon", {"action": "exploit"})
        self.assertEqual(resp["status"], "ok")

    def test_empty_post_fake_response(self):
        r = self.client.post("/any/path", data="{}", content_type="application/json")
        self.assertEqual(r.status_code, 200)

    def test_deep_evasive_url(self):
        _reset_server_state()
        resp = self._beacon_post("/api/v2/telemetry/events/submit?_t=123&sid=999", {
            "action": "register", "id": "deep-path",
            "hostname": "h", "os": "L", "arch": "x", "user": "u", "pid": 1, "interval": 5,
        })
        self.assertTrue(resp["success"])


# ── Agent status ──


class TestAgentStatus(ServerTestBase):
    def test_online_status(self):
        _reset_server_state()
        self._beacon_post("/r", {
            "action": "register", "id": "stat-1",
            "hostname": "h", "os": "L", "arch": "x", "user": "u", "pid": 1, "interval": 5,
        })
        lst = self._operator_get("/api/agents")
        self.assertEqual(lst[0]["status"], "online")

    def test_offline_status(self):
        _reset_server_state()
        self._beacon_post("/r", {
            "action": "register", "id": "stat-off",
            "hostname": "h", "os": "L", "arch": "x", "user": "u", "pid": 1, "interval": 1,
        })
        aid = list(agents.keys())[0]
        agents[aid]["_last_seen_ts"] = time.time() - 100
        lst = self._operator_get("/api/agents")
        self.assertEqual(lst[0]["status"], "offline")


# ── Cross-compatibility: server crypto ↔ beacon crypto ──


class TestCrossCompatibility(unittest.TestCase):
    def test_server_encrypts_beacon_decrypts(self):
        key = os.urandom(32)
        key_b64 = base64.b64encode(key).decode()

        server = ServerCrypto(key)
        beacon = Beacon({
            "c2": {
                "beacon_interval_seconds": 60, "jitter_percent": 0,
                "encryption_key": key_b64,
                "https": {"enabled": False, "callback_url": "", "verify_ssl": False},
                "dns": {"enabled": False, "domain": "", "resolver": "8.8.8.8"},
            }
        })

        data = {"cmd": "shell", "args": "id", "id": "task-1"}
        wrapped = server.wrap(data)
        unwrapped = beacon._unwrap_response(wrapped)
        self.assertEqual(unwrapped, data)

    def test_beacon_encrypts_server_decrypts(self):
        key = os.urandom(32)
        key_b64 = base64.b64encode(key).decode()

        server = ServerCrypto(key)
        beacon = Beacon({
            "c2": {
                "beacon_interval_seconds": 60, "jitter_percent": 0,
                "encryption_key": key_b64,
                "https": {"enabled": False, "callback_url": "", "verify_ssl": False},
                "dns": {"enabled": False, "domain": "", "resolver": "8.8.8.8"},
            }
        })

        data = {"action": "register", "id": "test-implant", "hostname": "box"}
        wrapped = beacon._wrap_payload(data)
        unwrapped = server.unwrap(wrapped)
        self.assertEqual(unwrapped, data)


# ── Live beacon integration ──


class TestLiveBeaconIntegration(ServerTestBase):
    def test_beacon_registers_and_checks_in(self):
        _reset_server_state()
        beacon = Beacon(_beacon_config(port=self.port, interval=1))
        beacon.start()
        try:
            time.sleep(3)
            self.assertGreaterEqual(len(agents), 1)
            aid = list(agents.keys())[0]
            self.assertIn("raccoon-", aid)
            self.assertTrue(agents[aid]["hostname"])
        finally:
            beacon.stop()

    def _wait_for_agent(self, timeout=30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if agents:
                return list(agents.keys())[0]
            time.sleep(0.2)
        self.fail("Beacon did not register in time")

    def _wait_for_result(self, agent_id, timeout=30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            hist = self._operator_get(f"/api/agents/{agent_id}/history")
            completed = [h for h in hist if h["status"] not in ("pending", None)]
            if completed:
                return completed
            time.sleep(0.3)
        return []

    def test_beacon_executes_task(self):
        _reset_server_state()
        beacon = Beacon(_beacon_config(port=self.port, interval=1))
        beacon.start()
        try:
            aid = self._wait_for_agent()
            self._operator_post(f"/api/agents/{aid}/task", {"cmd": "pwd"})
            ok = self._wait_for_result(aid)
            self.assertGreaterEqual(len(ok), 1)
            self.assertTrue(ok[0]["output"])
        finally:
            beacon.stop()

    def test_beacon_shell_command(self):
        _reset_server_state()
        beacon = Beacon(_beacon_config(port=self.port, interval=1))
        beacon.start()
        try:
            aid = self._wait_for_agent()
            self._operator_post(f"/api/agents/{aid}/task", {
                "cmd": "shell", "args": "echo raccoon_e2e_test",
            })
            completed = self._wait_for_result(aid)
            found = [h for h in completed if h.get("output") and "raccoon_e2e_test" in h["output"]]
            self.assertGreaterEqual(len(found), 1)
        finally:
            beacon.stop()

    def test_beacon_sleep_command(self):
        _reset_server_state()
        beacon = Beacon(_beacon_config(port=self.port, interval=1))
        beacon.start()
        try:
            aid = self._wait_for_agent()
            self._operator_post(f"/api/agents/{aid}/task", {"cmd": "sleep", "args": "30 50"})
            deadline = time.time() + 10
            while time.time() < deadline:
                if beacon.interval == 30:
                    break
                time.sleep(0.3)
            self.assertEqual(beacon.interval, 30)
            self.assertAlmostEqual(beacon.jitter, 0.5, places=1)
        finally:
            beacon.stop()

    def test_beacon_kill_command(self):
        _reset_server_state()
        beacon = Beacon(_beacon_config(port=self.port, interval=1))
        beacon.start()
        try:
            aid = self._wait_for_agent()
            self._operator_post(f"/api/agents/{aid}/task", {"cmd": "kill"})
            deadline = time.time() + 10
            while time.time() < deadline:
                if not beacon._running:
                    break
                time.sleep(0.3)
            self.assertFalse(beacon._running)
        finally:
            beacon.stop()


# ── Beacon generator: the gsocket leg it cannot deliver ──


class TestBeaconGenGsocketLeg(unittest.TestCase):
    """`/api/server/beacon-gen` and the fifth leg it has no binary for.

    The gsocket leg reaches the team server through a `gs-netcat` child
    process, so it needs that binary on disk beside the beacon. A
    generated build is a single file of obfuscated source and carries no
    binary at all, which makes an enabled gsocket leg undeliverable here
    no matter what the config says. Refused at generation rather than
    shipped dead: a channel that looks configured and delivers nothing is
    this repository's most-repeated failure, and the operator's next move
    after a silent one is a bug report about the leg rather than about the
    build they asked for.

    Not a `ServerTestBase` subclass: this route is driven entirely
    through the test client, and that base also starts a live listener on
    the module's single port -- which the second class to want it cannot
    bind, so each one that inherits it prints a port-in-use error nobody
    is meant to read. Nothing here needs a socket.
    """

    @classmethod
    def setUpClass(cls):
        cls.data_dir = Path(tempfile.mkdtemp())
        cls.app = create_app(ServerCrypto(KEY), TEST_TOKEN, cls.data_dir)
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.data_dir, ignore_errors=True)

    def post_gen(self, protocols):
        return self.client.post(
            "/api/server/beacon-gen",
            json={"c2_url": "http://127.0.0.1:1/api/v1/beacon",
                  "layers": 1, "protocols": protocols},
            headers={"Authorization": "Bearer %s" % TEST_TOKEN},
        )

    def test_beacon_gen_refuses_an_enabled_gsocket_leg(self):
        # A generated build is a single file with no binary beside it, so
        # the leg could never work. Refused at generation, naming the
        # reason, rather than emitting a build with a dead fifth leg.
        response = self.post_gen({
            "https": {"enabled": True,
                      "callback_url": "http://127.0.0.1:1/api/v1/beacon"},
            "gsocket": {"enabled": True},
        })
        self.assertEqual(response.status_code, 400)
        error = response.get_json()["error"]
        # The message has to say what to do instead, not merely that it
        # refused: the leg is a hardware-implant feature because the
        # image is what carries `gs-netcat`.
        self.assertIn("gs-netcat", error)
        self.assertIn("hardware implant", error)
        # And no build came back alongside the refusal.
        self.assertNotIn("oneliner_unix", response.get_json())

    def test_beacon_gen_ignores_a_disabled_gsocket_leg(self):
        # `enabled: false` is what every config in this repository
        # carries, including the ones an operator pastes into the
        # generator. It is not an error, and a request carrying one still
        # gets the build it asked for.
        response = self.post_gen({
            "https": {"enabled": True,
                      "callback_url": "http://127.0.0.1:1/api/v1/beacon"},
            "gsocket": {"enabled": False},
        })
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["oneliner_unix"])


class TestHowNineRoutesReadABodyThatIsNotAnObject(unittest.TestCase):
    """Nine of the twelve `get_json(silent=True) or {}` routes, given a body
    that parses but is not an object.

    `request.get_json(silent=True) or {}` only catches JSON that does not
    parse. `[1]`, `"x"` and `7` parse, are truthy, and reached `.get`,
    which raised `AttributeError`: a 500 and a traceback in the log for a
    request that is merely malformed; those are refused with 400. A falsy
    one -- `[]`, `0`, `""`, `false` -- never crashed and still reads as an
    empty body. The shell's three routes are covered
    in `test_operator_shell.py`; `TestTheTwelveBodyReadersUseTheHelper` in
    `test_c2_hardening.py` proves all twelve sites are converted. Not every
    operator route: `/api/agents/<id>/task` reads `request.json`, a
    different reader, and is not one of the twelve.

    `TESTING` stays off, as in production: with it on Flask re-raises,
    and the 500 and its logged traceback would never be observed.
    """

    ROUTES = ("/api/server/exec",
              "/api/server/avenum",
              "/api/server/rdp",
              "/api/server/beacon-gen",
              "/api/server/beacon-gist",
              "/api/server/c2-profile/from-burp",
              "/api/server/c2-profile/lint",
              "/api/server/c2-profile/save",
              "/api/server/c2-profile/push")

    @classmethod
    def setUpClass(cls):
        cls.data_dir = Path(tempfile.mkdtemp())
        cls.app = create_app(ServerCrypto(KEY), TEST_TOKEN, cls.data_dir)
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.data_dir, ignore_errors=True)

    def setUp(self):
        _reset_server_state()
        agents["raccoon-1"] = {"id": "impl-1", "agent_id": "raccoon-1"}
        # `beacon-gist` asks `gh` whether it is logged in before it reads
        # the body. Answered here, so the body is what gets tested.
        authed = mock.patch("software.c2.server.subprocess.run",
                            return_value=mock.Mock(returncode=0))
        authed.start()
        self.addCleanup(authed.stop)

    def test_each_route_answers_400_and_logs_no_traceback(self):
        import software.c2.server as srv
        with mock.patch.object(srv, "_active_c2_profile", {"mode": "x"}):
            for route in self.ROUTES:
                for body in NOT_AN_OBJECT:
                    with self.subTest(route=route, body=body), \
                            logged_tracebacks() as tracebacks:
                        answer = self.client.post(
                            route, json=body,
                            headers={"Authorization": "Bearer %s"
                                     % TEST_TOKEN})
                        self.assertEqual(answer.status_code, 400)
                        self.assertIn("error", answer.get_json())
                        self.assertEqual(tracebacks, [])
        # Refused before acting: `push` with an empty body pushes to the
        # whole fleet, so a coerced body would have queued a task here.
        self.assertEqual(task_queues, {})

    def test_a_falsy_non_object_still_means_an_empty_body(self):
        # Only a truthy non-object ever crashed: `or {}` already read `[]`,
        # `0`, `""` and `false` as an empty body, and they keep that
        # meaning. Each answers exactly what an absent body answers. `push`
        # is left out on purpose: an empty body there means the whole fleet.
        routes = ("/api/server/exec", "/api/server/c2-profile/lint",
                  "/api/server/c2-profile/save", "/api/opshell/open",
                  "/api/opshell/close", "/api/opshell/keys")
        headers = {"Authorization": "Bearer %s" % TEST_TOKEN}
        for route in routes:
            absent = self.client.post(route, headers=headers)
            for data in ("[]", "0", '""', "false"):
                with self.subTest(route=route, data=data), \
                        logged_tracebacks() as tracebacks:
                    answer = self.client.post(
                        route, data=data, content_type="application/json",
                        headers=headers)
                    self.assertEqual(answer.status_code, absent.status_code)
                    self.assertEqual(answer.get_json(), absent.get_json())
                    self.assertEqual(tracebacks, [])

    def test_a_missing_or_unparseable_body_still_means_an_empty_one(self):
        # Only a *parsed* non-object is refused. No body, or one that does
        # not parse, still reaches the route as `{}`, exactly as before:
        # the linter's own answer for an empty source.
        for data in (None, "{not json"):
            with self.subTest(data=data):
                answer = self.client.post(
                    "/api/server/c2-profile/lint", data=data,
                    content_type="application/json",
                    headers={"Authorization": "Bearer %s" % TEST_TOKEN})
                self.assertEqual(answer.status_code, 200)
                self.assertEqual(answer.get_json(),
                                 {"errors": [], "warnings": [], "info": []})


if __name__ == "__main__":
    unittest.main()
