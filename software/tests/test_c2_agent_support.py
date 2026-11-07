#!/usr/bin/env python3
"""
C2 server support for the agent layer: task lanes, batched dispatch,
capability storage, isolated tool runs, argv execution and the /api/ai proxy.

Half of this file pins the status quo. The existing operator GUI and the
existing beacons must behave identically with the agent layer absent, so the
legacy forms (string cmd, parameterless result endpoint, no caps, one task per
check-in) are tested next to the new ones.
"""

import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import software.c2.server as srv
from software.c2.server import ServerCrypto, create_app, agents, task_queues
from software.tests.test_c2_server import (
    KEY,
    TEST_TOKEN,
    ServerTestBase as _Harness,
    _reset_server_state,
)


_AUTH = {"Authorization": f"Bearer {TEST_TOKEN}"}


class ServerTestBase(_Harness):
    """The shared harness, minus the live Flask thread on a fixed port.

    These tests only use the Flask test client, so binding port 19999 would
    just collide with the other suites.
    """

    @classmethod
    def setUpClass(cls):
        _reset_server_state()
        cls.crypto = ServerCrypto(KEY)
        cls.data_dir = Path(tempfile.mkdtemp())
        cls.app = create_app(cls.crypto, TEST_TOKEN, cls.data_dir)
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

    def setUp(self):
        _reset_server_state()
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("AGENT_URL", None)
        os.environ.pop("RACCOON_AGENT_TOKEN", None)

    def _register_agent(self, caps=None, implant_id="impl-lane"):
        payload = {
            "action": "register", "id": implant_id, "hostname": "h",
            "os": "L", "arch": "x", "user": "u", "pid": 1, "interval": 5,
        }
        if caps is not None:
            payload["caps"] = caps
        self.implant_id = implant_id
        self.aid = self._beacon_post("/r", payload)["agent_id"]
        return self.aid

    def _checkin(self, agent_id=None):
        return self._beacon_post("/b", {
            "action": "beacon", "agent_id": agent_id or self.aid, "interval": 5,
        })

    def _queue_task(self, cmd, lane=None):
        body = {"cmd": cmd}
        if lane is not None:
            body["lane"] = lane
        return self._operator_post(f"/api/agents/{self.aid}/task", body)

    def _operator_get_raw(self, path):
        return self.client.get(path, headers=_AUTH)

    def _operator_post_raw(self, path, data):
        return self.client.post(path, data=json.dumps(data),
                                content_type="application/json", headers=_AUTH)

    def _wait_tool(self, run_id, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            res = self._operator_get(f"/api/server/exec/result/{run_id}")
            if res["status"] != "running":
                return res
            time.sleep(0.05)
        self.fail(f"tool run {run_id} still running after {timeout}s")

    def _wait_legacy(self, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            res = self._operator_get("/api/server/exec/result")
            if res["status"] != "running":
                return res
            time.sleep(0.05)
        self.fail("legacy result still running")


@contextmanager
def _stub_agent(payload, status=200, seen=None):
    """A loopback HTTP server standing in for the agent service."""

    class Handler(BaseHTTPRequestHandler):
        def _answer(self):
            length = int(self.headers.get("Content-Length") or 0)
            if seen is not None:
                seen.append({
                    "method": self.command,
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": self.rfile.read(length) if length else b"",
                })
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = _answer

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _closed_loopback_url():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"


class TestTaskLanes(ServerTestBase):
    def test_lane_defaults_to_operator(self):
        self._register_agent()
        t = self._queue_task("whoami")
        self.assertEqual(t["lane"], "operator")

    def test_lane_is_recorded_in_history(self):
        self._register_agent()
        self._queue_task("whoami", lane="agent")
        hist = self._operator_get(f"/api/agents/{self.aid}/history")
        self.assertEqual(hist[0]["lane"], "agent")

    def test_unknown_lane_is_a_400_and_queues_nothing(self):
        self._register_agent()
        resp = self._operator_post_raw(f"/api/agents/{self.aid}/task",
                                       {"cmd": "x", "lane": "root"})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(task_queues[self.aid], [])

    def test_operator_task_wins_over_older_agent_task(self):
        self._register_agent()
        self._queue_task("agent_first", lane="agent")
        self._queue_task("operator_second", lane="operator")
        self.assertEqual(self._checkin()["cmd"], "operator_second")

    def test_agent_tasks_served_fifo_once_operator_queue_is_empty(self):
        self._register_agent()
        for n in ("a1", "a2"):
            self._queue_task(n, lane="agent")
        self.assertEqual(self._checkin()["cmd"], "a1")
        self.assertEqual(self._checkin()["cmd"], "a2")

    def test_operator_only_queue_behaves_exactly_as_before(self):
        """Status quo: identical order to the old queue.pop(0)."""
        self._register_agent()
        for n in ("c1", "c2", "c3"):
            self._queue_task(n)
        self.assertEqual([self._checkin()["cmd"] for _ in range(3)],
                         ["c1", "c2", "c3"])

    def test_c2_profile_push_task_is_an_operator_task(self):
        self._register_agent()
        with mock.patch.object(srv, "_active_c2_profile", {"mode": "x"}):
            self._operator_post("/api/server/c2-profile/push", {})
        self.assertEqual(task_queues[self.aid][0]["lane"], "operator")

    def test_task_without_lane_key_cannot_break_checkin(self):
        """A KeyError here would fail every beacon's check-in."""
        self._register_agent()
        task_queues[self.aid].append({
            "id": "legacy1", "cmd": "legacy", "args": "", "data": "",
            "timeout": 60, "queued": "t", "status": "pending",
        })
        self._queue_task("newer_agent", lane="agent")
        self.assertEqual(self._checkin()["cmd"], "legacy")
        self.assertEqual(self._checkin()["cmd"], "newer_agent")


class TestBatching(ServerTestBase):
    def test_beacon_without_caps_gets_single_task_dict(self):
        self._register_agent(caps=None)
        for n in ("t1", "t2"):
            self._queue_task(n, lane="agent")
        resp = self._checkin()
        self.assertNotIn("tasks", resp)
        self.assertEqual(resp["cmd"], "t1")

    def test_beacon_with_batch_cap_gets_task_list(self):
        self._register_agent(caps=["batch"])
        for n in ("t1", "t2", "t3"):
            self._queue_task(n, lane="agent")
        resp = self._checkin()
        self.assertEqual([t["cmd"] for t in resp["tasks"]], ["t1", "t2", "t3"])
        self.assertEqual({t["status"] for t in resp["tasks"]}, {"dispatched"})
        self.assertEqual(task_queues[self.aid], [])

    def test_batch_respects_the_cap_limit(self):
        self._register_agent(caps=["batch"])
        for i in range(12):
            self._queue_task(f"t{i}", lane="agent")
        resp = self._checkin()
        self.assertEqual(len(resp["tasks"]), 8)
        self.assertEqual(len(task_queues[self.aid]), 4)
        self.assertEqual(self._checkin()["tasks"][0]["cmd"], "t8")

    def test_batch_puts_operator_tasks_first(self):
        self._register_agent(caps=["batch"])
        self._queue_task("ag", lane="agent")
        self._queue_task("op", lane="operator")
        self.assertEqual(self._checkin()["tasks"][0]["cmd"], "op")

    def test_mixed_queue_at_the_cap_keeps_operator_tasks_and_defers_agent_tasks(self):
        self._register_agent(caps=["batch"])
        for i in range(6):
            self._queue_task(f"ag{i}", lane="agent")
        for i in range(3):
            self._queue_task(f"op{i}")
        first = [t["cmd"] for t in self._checkin()["tasks"]]
        self.assertEqual(first, ["op0", "op1", "op2",
                                 "ag0", "ag1", "ag2", "ag3", "ag4"])
        self.assertEqual([t["cmd"] for t in self._checkin()["tasks"]], ["ag5"])

    def test_batch_beacon_with_empty_queue_still_gets_empty_dict(self):
        self._register_agent(caps=["batch"])
        self.assertEqual(self._checkin(), {})

    def test_beacon_with_other_caps_but_no_batch_gets_single_dict(self):
        self._register_agent(caps=["sniffer"])
        for n in ("t1", "t2"):
            self._queue_task(n)
        self.assertEqual(self._checkin()["cmd"], "t1")


class TestCapabilityStorage(ServerTestBase):
    def test_caps_are_stored_on_the_agent_record(self):
        self._register_agent(caps=["batch", "sniffer"])
        a = self._operator_get(f"/api/agents/{self.aid}")
        self.assertEqual(sorted(a["caps"]), ["batch", "sniffer"])

    def test_registration_without_caps_still_succeeds(self):
        """Status quo: an old beacon against the new server."""
        self._register_agent(caps=None)
        self.assertEqual(self._operator_get(f"/api/agents/{self.aid}")["caps"], [])

    def test_reregistration_updates_caps(self):
        self._register_agent(caps=None)
        self._register_agent(caps=["batch"])
        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[self.aid]["caps"], ["batch"])

    def test_uplink_iface_is_stored(self):
        payload = {"action": "register", "id": "i", "hostname": "h", "os": "L",
                   "arch": "x", "user": "u", "pid": 1, "interval": 5,
                   "uplink_iface": "eth1"}
        aid = self._beacon_post("/r", payload)["agent_id"]
        self.assertEqual(agents[aid]["uplink_iface"], "eth1")


class TestStateFromBeforeTheUpgrade(ServerTestBase):
    """agents is persisted, so a record written by today's server has no caps."""

    def _load_old_state(self):
        old_agent = {
            "id": "impl-old", "agent_id": "raccoon-bandit", "hostname": "oldbox",
            "os": "Linux", "arch": "x86_64", "user": "root", "pid": 7,
            "interval": 5, "local_ips": [], "registered": "2026-01-01T00:00:00Z",
            "last_seen": "2026-01-01T00:00:00Z", "_last_seen_ts": 0,
        }
        state_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, state_dir, True)
        (state_dir / "state.json").write_text(json.dumps({
            "agents": {"raccoon-bandit": old_agent},
            "history": {"raccoon-bandit": []},
            "scan_store": {},
            "name_counter": 1,
        }))
        srv._load_state(state_dir)
        self.assertNotIn("caps", agents["raccoon-bandit"])
        self.aid = "raccoon-bandit"

    def test_detail_endpoint_reports_empty_caps(self):
        self._load_old_state()
        self.assertEqual(self._operator_get("/api/agents/raccoon-bandit")["caps"], [])

    def test_list_endpoint_reports_empty_caps(self):
        self._load_old_state()
        listed = self._operator_get("/api/agents")
        self.assertEqual(listed[0]["caps"], [])

    def test_checkin_with_batching_logic_active_returns_single_dict(self):
        self._load_old_state()
        self._queue_task("op1")
        self._queue_task("ag1", lane="agent")
        self._queue_task("op2")
        resp = self._checkin()
        self.assertNotIn("tasks", resp)
        self.assertEqual(resp["cmd"], "op1")
        self.assertEqual(self._checkin()["cmd"], "op2")
        self.assertEqual(self._checkin()["cmd"], "ag1")


class TestToolRuns(ServerTestBase):
    def test_exec_returns_a_run_id(self):
        r = self._operator_post("/api/server/exec",
                                {"argv": ["echo", "hallo"], "tool": "echo"})
        self.assertEqual(r["status"], "started")
        self.assertEqual(r["tool"], "echo")
        self.assertIn("run_id", r)

    def test_parallel_runs_do_not_overwrite_each_other(self):
        a = self._operator_post("/api/server/exec",
                                {"argv": ["echo", "aaa"], "tool": "echo"})["run_id"]
        b = self._operator_post("/api/server/exec",
                                {"argv": ["echo", "bbb"], "tool": "echo"})["run_id"]
        self._wait_tool(a)
        self._wait_tool(b)
        self.assertIn("aaa", self._operator_get(f"/api/server/exec/result/{a}")["output"])
        self.assertIn("bbb", self._operator_get(f"/api/server/exec/result/{b}")["output"])

    def test_result_carries_the_documented_fields(self):
        r = self._operator_post("/api/server/exec",
                                {"argv": ["echo", "x"], "tool": "echo",
                                 "origin": "agent"})
        res = self._wait_tool(r["run_id"])
        self.assertEqual(set(res), {"status", "output", "tool", "origin", "truncated"})
        self.assertEqual((res["status"], res["tool"], res["origin"], res["truncated"]),
                         ("ok", "echo", "agent", False))

    def test_legacy_endpoint_returns_latest_operator_run_only(self):
        ag = self._operator_post("/api/server/exec",
                                 {"argv": ["echo", "agentrun"], "tool": "nmap",
                                  "origin": "agent"})["run_id"]
        op = self._operator_post("/api/server/exec",
                                 {"cmd": "echo operatorrun", "tool": "custom"})["run_id"]
        self._wait_tool(ag)
        self._wait_tool(op)
        res = self._operator_get("/api/server/exec/result")
        self.assertIn("operatorrun", res["output"])
        self.assertEqual(res["origin"], "operator")

    def test_agent_run_started_later_does_not_hide_the_operator_run(self):
        op = self._operator_post("/api/server/exec",
                                 {"cmd": "echo operatorrun", "tool": "custom"})["run_id"]
        self._wait_tool(op)
        ag = self._operator_post("/api/server/exec",
                                 {"argv": ["echo", "agentrun"], "tool": "nmap",
                                  "origin": "agent"})["run_id"]
        self._wait_tool(ag)
        self.assertIn("operatorrun",
                      self._operator_get("/api/server/exec/result")["output"])

    def test_legacy_poll_right_after_start_sees_running_not_the_previous_run(self):
        """The GUI polls for status != running; a stale 'ok' would end the poll."""
        old = self._operator_post("/api/server/exec",
                                  {"cmd": "echo stale", "tool": "custom"})["run_id"]
        self._wait_tool(old)
        new = self._operator_post("/api/server/exec",
                                  {"cmd": "sleep 1; echo fresh", "tool": "custom"})["run_id"]
        res = self._operator_get("/api/server/exec/result")
        self.assertEqual(res["status"], "running")
        self.assertNotIn("stale", res["output"])
        self.assertIn("fresh", self._wait_tool(new)["output"])

    def test_run_is_visible_by_id_before_the_response_returns(self):
        r = self._operator_post("/api/server/exec",
                                {"cmd": "sleep 1", "tool": "custom"})
        res = self._operator_get(f"/api/server/exec/result/{r['run_id']}")
        self.assertEqual(res["status"], "running")
        self._wait_tool(r["run_id"])

    def test_string_cmd_form_still_works(self):
        """Status quo: the existing GUI posts cmd strings."""
        r = self._operator_post("/api/server/exec",
                                {"cmd": "echo via-shell", "tool": "custom"})
        self._wait_tool(r["run_id"])
        self.assertIn("via-shell",
                      self._operator_get(f"/api/server/exec/result/{r['run_id']}")["output"])

    def test_cmd_form_still_uses_a_shell(self):
        r = self._operator_post("/api/server/exec",
                                {"cmd": "echo one && echo two", "tool": "custom"})
        out = self._wait_tool(r["run_id"])["output"]
        self.assertIn("one", out)
        self.assertIn("two", out)

    def test_nonzero_exit_is_an_error_and_stderr_is_appended(self):
        r = self._operator_post("/api/server/exec",
                                {"cmd": "echo out; echo err >&2; exit 3", "tool": "custom"})
        res = self._wait_tool(r["run_id"])
        self.assertEqual(res["status"], "error")
        self.assertIn("--- STDERR ---", res["output"])
        self.assertIn("err", res["output"])

    def test_argv_form_does_not_interpret_shell_syntax(self):
        r = self._operator_post("/api/server/exec",
                                {"argv": ["echo", "a; whoami"], "tool": "echo"})
        out = self._wait_tool(r["run_id"])["output"]
        self.assertIn("a; whoami", out)

    def test_argv_with_missing_binary_is_an_error_result_not_a_crash(self):
        r = self._operator_post("/api/server/exec",
                                {"argv": ["definitely-not-a-binary-xyz"], "tool": "x"})
        res = self._wait_tool(r["run_id"])
        self.assertEqual(res["status"], "error")
        self.assertIn("[error:", res["output"])

    def test_timeout_keeps_partial_output(self):
        r = self._operator_post(
            "/api/server/exec",
            {"argv": ["sh", "-c", "echo teil; sleep 5"], "tool": "custom",
             "timeout": 1})
        res = self._wait_tool(r["run_id"], timeout=10)
        self.assertEqual(res["status"], "error")
        self.assertIn("teil", res["output"])
        self.assertIn("timeout", res["output"].lower())

    def test_timeout_keeps_partial_output_for_the_shell_form_too(self):
        r = self._operator_post(
            "/api/server/exec",
            {"cmd": "echo teil; sleep 5", "tool": "custom", "timeout": 1})
        res = self._wait_tool(r["run_id"], timeout=10)
        self.assertIn("teil", res["output"])
        self.assertIn("timeout", res["output"].lower())

    def test_timeout_with_no_output_at_all_still_reports_the_timeout(self):
        r = self._operator_post(
            "/api/server/exec",
            {"argv": ["sleep", "5"], "tool": "custom", "timeout": 1})
        res = self._wait_tool(r["run_id"], timeout=10)
        self.assertEqual(res["status"], "error")
        self.assertIn("timeout after 1s", res["output"])

    def test_output_over_the_limit_is_truncated_and_flagged(self):
        r = self._operator_post(
            "/api/server/exec",
            {"argv": ["sh", "-c", "head -c 70000 /dev/zero | tr '\\0' 'x'"],
             "tool": "custom"})
        res = self._wait_tool(r["run_id"])
        self.assertEqual(len(res["output"]), 65536)
        self.assertTrue(res["truncated"])

    def test_only_the_50_newest_runs_are_kept(self):
        ids = [self._operator_post("/api/server/exec",
                                   {"argv": ["true"], "tool": "t"})["run_id"]
               for _ in range(55)]
        self._wait_tool(ids[-1])
        self.assertEqual(
            self._operator_get_raw(f"/api/server/exec/result/{ids[0]}").status_code, 404)
        self.assertEqual(
            self._operator_get_raw(f"/api/server/exec/result/{ids[-1]}").status_code, 200)

    def test_unknown_run_id_is_a_404(self):
        self.assertEqual(
            self._operator_get_raw("/api/server/exec/result/nope").status_code, 404)

    def test_missing_command_is_a_400(self):
        resp = self._operator_post_raw("/api/server/exec", {"tool": "x"})
        self.assertEqual(resp.status_code, 400)

    def test_argv_and_cmd_together_are_a_400(self):
        resp = self._operator_post_raw("/api/server/exec",
                                       {"argv": ["echo"], "cmd": "echo"})
        self.assertEqual(resp.status_code, 400)

    def test_malformed_argv_is_a_400(self):
        for bad in ([], "echo hi", ["echo", 3], [""]):
            resp = self._operator_post_raw("/api/server/exec", {"argv": bad})
            self.assertEqual(resp.status_code, 400, bad)

    def test_bad_origin_and_bad_timeout_are_400s(self):
        self.assertEqual(self._operator_post_raw(
            "/api/server/exec", {"cmd": "true", "origin": "root"}).status_code, 400)
        for bad in (0, -1, "soon"):
            self.assertEqual(self._operator_post_raw(
                "/api/server/exec", {"cmd": "true", "timeout": bad}).status_code,
                400, bad)

    def test_exec_requires_operator_auth(self):
        resp = self.client.post("/api/server/exec", json={"cmd": "true"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.client.get("/api/server/exec/result/x").status_code, 401)


class TestAvEnumerationStillReportsThroughTheLegacyEndpoint(ServerTestBase):
    """_run_av_enum was the second writer of the old server_exec_state."""

    @contextmanager
    def _fake_impacket(self, login=None):
        smb = mock.MagicMock()
        if login is not None:
            smb.login.side_effect = login
        smbconnection = mock.MagicMock()
        smbconnection.SMBConnection.return_value = smb
        names = ["impacket", "impacket.dcerpc", "impacket.dcerpc.v5",
                 "impacket.dcerpc.v5.dtypes"]
        fakes = {n: mock.MagicMock() for n in names}
        fakes["impacket.smbconnection"] = smbconnection
        with mock.patch.dict(sys.modules, fakes):
            yield

    def test_success_is_reported_as_ok_for_tool_avenum(self):
        with self._fake_impacket():
            resp = self._operator_post_raw("/api/server/avenum", {"target": "10.0.0.5"})
            self.assertEqual(resp.status_code, 200)
            res = self._wait_legacy()
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["tool"], "avenum")
        self.assertEqual(res["origin"], "operator")
        self.assertIn("Target: 10.0.0.5", res["output"])

    def test_failure_is_reported_as_error(self):
        with self._fake_impacket(login=RuntimeError("logon refused")):
            self._operator_post("/api/server/avenum", {"target": "10.0.0.5"})
            res = self._wait_legacy()
        self.assertEqual(res["status"], "error")
        self.assertIn("logon refused", res["output"])

    def test_poll_after_start_sees_running_not_the_previous_result(self):
        old = self._operator_post("/api/server/exec",
                                  {"cmd": "echo stale", "tool": "custom"})["run_id"]
        self._wait_tool(old)
        gate = threading.Event()
        self.addCleanup(gate.set)
        with self._fake_impacket(login=lambda *a, **k: gate.wait(5)):
            self._operator_post("/api/server/avenum", {"target": "10.0.0.5"})
            res = self._operator_get("/api/server/exec/result")
            self.assertEqual((res["status"], res["tool"]), ("running", "avenum"))
            gate.set()
            self.assertEqual(self._wait_legacy()["status"], "ok")

    def test_missing_target_is_still_a_400(self):
        self.assertEqual(
            self._operator_post_raw("/api/server/avenum", {}).status_code, 400)


class TestRunEvictionNeverDropsALiveRun(ServerTestBase):
    """The 50-run cap must not evict a run that is still executing.

    The agent generates tool runs continuously, so without this an operator's
    long-running command would be pushed out while still going: its own
    result endpoint would 404, the legacy endpoint would report the next
    newest operator run or idle, and the GUI panel — which stops polling at
    the first status that is not "running" — would render an error over a
    command that had not finished.
    """

    def _slow_run(self, origin="operator"):
        return self._operator_post(
            "/api/server/exec",
            {"argv": ["sh", "-c", "sleep 30"], "tool": "slow",
             "origin": origin, "timeout": 60})["run_id"]

    def test_a_running_operator_tool_survives_a_flood_of_agent_runs(self):
        live = self._slow_run()
        for i in range(srv.TOOL_RUNS_MAX + 10):
            done = self._operator_post(
                "/api/server/exec",
                {"argv": ["echo", "n%d" % i], "tool": "echo",
                 "origin": "agent"})["run_id"]
            self._wait_tool(done)
        still = self._operator_get("/api/server/exec/result/%s" % live)
        self.assertEqual(still["status"], "running")

    def test_the_legacy_endpoint_still_finds_that_run(self):
        live = self._slow_run()
        for i in range(srv.TOOL_RUNS_MAX + 10):
            self._wait_tool(self._operator_post(
                "/api/server/exec",
                {"argv": ["echo", "n%d" % i], "tool": "echo",
                 "origin": "agent"})["run_id"])
        latest = self._operator_get("/api/server/exec/result")
        self.assertEqual(latest["status"], "running")
        self.assertEqual(latest["tool"], "slow")
        self.assertIsNotNone(live)

    def test_finished_runs_are_still_evicted(self):
        # The cap has to do its job; the point is only which entries it takes.
        first = self._operator_post(
            "/api/server/exec",
            {"argv": ["echo", "first"], "tool": "echo"})["run_id"]
        self._wait_tool(first)
        for i in range(srv.TOOL_RUNS_MAX + 5):
            self._wait_tool(self._operator_post(
                "/api/server/exec",
                {"argv": ["echo", "n%d" % i], "tool": "echo"})["run_id"])
        gone = self.client.get(
            "/api/server/exec/result/%s" % first,
            headers={"Authorization": "Bearer %s" % TEST_TOKEN})
        self.assertEqual(gone.status_code, 404)


class TestAiProxy(ServerTestBase):
    def _app_for(self, url):
        app = create_app(self.crypto, TEST_TOKEN, self.data_dir,
                         server_config={"agent_url": url})
        app.config["TESTING"] = True
        return app.test_client()

    def test_returns_503_without_agent_service(self):
        resp = self._operator_get_raw("/api/ai/status")
        self.assertEqual(resp.status_code, 503)
        self.assertIn("unavailable", resp.get_json()["error"])

    def test_returns_503_when_agent_service_is_down(self):
        client = self._app_for(_closed_loopback_url())
        resp = client.get("/api/ai/status", headers=_AUTH)
        self.assertEqual(resp.status_code, 503)
        self.assertIn("unavailable", resp.get_json()["error"])
        self.assertIn("detail", resp.get_json())

    def test_503_detail_does_not_echo_credentials(self):
        os.environ["RACCOON_AGENT_TOKEN"] = "agent-secret-marker"
        client = self._app_for(_closed_loopback_url())
        resp = client.get("/api/ai/status", headers=_AUTH)
        raw = resp.get_data(as_text=True)
        self.assertNotIn("agent-secret-marker", raw)
        self.assertNotIn(TEST_TOKEN, raw)

    def test_an_invalid_agent_url_is_a_503_not_a_500(self):
        resp = self._app_for("not a url").get("/api/ai/status", headers=_AUTH)
        self.assertEqual(resp.status_code, 503)

    def test_agent_url_may_come_from_the_environment(self):
        with _stub_agent({"available": True}) as url:
            os.environ["AGENT_URL"] = url
            resp = self._operator_get_raw("/api/ai/status")
        self.assertTrue(resp.get_json()["available"])

    def test_proxy_requires_operator_auth(self):
        resp = self.client.get("/api/ai/status")
        self.assertEqual(resp.status_code, 401)

    def test_forwards_to_configured_agent_url(self):
        seen = []
        with _stub_agent({"available": True}, seen=seen) as url:
            resp = self._app_for(url).get("/api/ai/status", headers=_AUTH)
            self.assertTrue(resp.get_json()["available"])
        self.assertEqual(seen[0]["path"], "/status")

    def test_forwards_method_body_content_type_and_query(self):
        seen = []
        with _stub_agent({"run_id": "r1"}, seen=seen) as url:
            resp = self._app_for(url).post(
                "/api/ai/campaign/r1/approve?x=1", data=b'{"allow": true}',
                content_type="application/json", headers=_AUTH)
        self.assertEqual(resp.get_json(), {"run_id": "r1"})
        got = seen[0]
        self.assertEqual(got["method"], "POST")
        self.assertEqual(got["path"], "/campaign/r1/approve?x=1")
        self.assertEqual(got["body"], b'{"allow": true}')
        self.assertEqual(got["headers"]["content-type"], "application/json")

    def test_upstream_error_status_and_body_pass_through(self):
        with _stub_agent({"reason": "no provider"}, status=409) as url:
            resp = self._app_for(url).get("/api/ai/status", headers=_AUTH)
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.get_json(), {"reason": "no provider"})

    def test_agent_token_header_is_set_from_the_environment(self):
        os.environ["RACCOON_AGENT_TOKEN"] = "agent-secret-marker"
        seen = []
        with _stub_agent({}, seen=seen) as url:
            self._app_for(url).get("/api/ai/status", headers=_AUTH)
        self.assertEqual(seen[0]["headers"]["x-agent-token"], "agent-secret-marker")

    def test_operator_token_is_never_forwarded(self):
        seen = []
        with _stub_agent({}, seen=seen) as url:
            self._app_for(url).get("/api/ai/status", headers=_AUTH)
        self.assertNotIn("authorization", seen[0]["headers"])
        self.assertNotIn("x-agent-token", seen[0]["headers"])

    def test_does_not_import_the_agent_package(self):
        """Hard rule from spec §19.5: the coupling is HTTP only."""
        src = Path(srv.__file__).read_text()
        self.assertNotIn("software.agent", src)
        self.assertNotIn("from .agent", src)


class TestStatusQuoNames(unittest.TestCase):
    def test_server_exec_state_is_gone(self):
        """Any leftover reader or writer would raise NameError at runtime."""
        self.assertNotIn("server_exec_state", Path(srv.__file__).read_text())

    def test_caps_are_only_ever_read_with_get(self):
        src = Path(srv.__file__).read_text()
        self.assertNotIn('["caps"]', src.replace('["caps"] = ', ""))


if __name__ == "__main__":
    unittest.main()
