#!/usr/bin/env python3
"""End to end: a real C2, a real beacon, real safety machinery, scripted model.

This is the test the six live bugs on this branch argue for. Every one of
them -- a beacon offered under an id that cannot be tasked, a command
language nobody told the model, a platform dropped from the record, phase
labels that named the wrong activity, an all-ports scan that could not
finish, an executor that invented a beacon id out of capability words --
passed roughly fourteen hundred unit tests, because every fake was
self-consistent. A fake cannot notice that the real thing knows something
the code never asked for.

So nothing here is faked except the model. The C2 is the real Flask app on
a real port, the beacon is a real `Beacon` process object checking in over
HTTP, and the campaign drives them through the real Router, Gate, Scope and
store. Only the model's choices are scripted, because a model is the one
component whose output cannot be asserted.

Waiting is condition-based throughout. A fixed sleep long enough to be safe
on an idle machine is also long enough to be wrong on a loaded one, and the
one load-sensitive test already in this repo (TestLiveBeaconIntegration)
is the reason that rule is written down here.
"""

import asyncio
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from software.agent import c2client, config, orchestrator  # noqa: E402
from software.agent.llm import mock  # noqa: E402
from software.agent.store import db, queries  # noqa: E402
from software.c2.beacon import Beacon  # noqa: E402
from software.c2.server import ServerCrypto, create_app  # noqa: E402
from software.tests.test_c2_server import (  # noqa: E402
    DNS_DOMAIN, TEST_TOKEN, _beacon_config, _pick_port, _reset_server_state)

# A free port, not a fixed one, and for the same reason test_c2_server stopped
# using 19999: the Flask thread is a daemon and never releases the port, so a
# second process re-running either suite cannot bind it, and the failure reads
# as "the beacon did not register" rather than as a port conflict.
PORT = _pick_port()


def _key_for_port(port: int) -> bytes:
    """The key the server must hold for a beacon calling back on `port`.

    Derived here rather than imported: test_c2_server's _derive_key hardcodes
    its own port, and a mismatched key does not produce an error -- the
    beacon's registration is simply never accepted and the fleet stays empty.
    That silence cost this suite its first run, and it is the same trap the
    live runs hit.
    """
    import hashlib
    return hashlib.sha256(
        ("http://127.0.0.1:%d/api/v1/beacon:%s" % (port, DNS_DOMAIN)).encode()
    ).digest()

_CAMPAIGN_INTERVAL = 1
# Small on purpose, and not the shipped 300. One beacon is shared by every
# class here, so a restore to 300s would put it to sleep for five minutes
# and every later test's command would sit pending behind that -- which is
# exactly how this value was discovered. The property under test is "the
# interval goes back to the configured one", not "it goes back to 300".
_RESTORE_INTERVAL = 2


class _LiveEnv:
    """A C2 on a port, a beacon checked in to it, and an agent store."""

    def __init__(self, scope_allow=None, scope_deny=None, phases=(1, 2),
                 mode="auto", unattended="decide", agent=None, **form):
        self.scope_allow = list(scope_allow or ["127.0.0.0/8"])
        self.scope_deny = list(scope_deny or [])
        self.phases = list(phases)
        self.mode = mode
        self.unattended = unattended
        self.agent_fields = dict(agent or {})
        self.form = dict(form)
        self.beacon = None
        self.beacon_id = None

    # ── Setup ──

    def start_server(self):
        _reset_server_state()
        self.data_dir = Path(tempfile.mkdtemp())
        self.app = create_app(ServerCrypto(_key_for_port(PORT)), TEST_TOKEN,
                              self.data_dir)
        self.app.config["TESTING"] = True
        self.thread = threading.Thread(
            target=self.app.run,
            kwargs={"host": "127.0.0.1", "port": PORT, "use_reloader": False},
            daemon=True)
        self.thread.start()
        _wait_until(self._server_answers, "the C2 to accept connections")

    def _server_answers(self) -> bool:
        import urllib.error
        import urllib.request
        try:
            urllib.request.urlopen(
                "http://127.0.0.1:%d/api/agents" % PORT, timeout=2)
        except urllib.error.HTTPError:
            return True          # 401 is an answer
        except Exception:
            return False
        return True

    def start_beacon(self):
        self.beacon = Beacon(_beacon_config(port=PORT, interval=1))
        self.beacon.start()
        from software.c2.server import agents
        _wait_until(lambda: bool(agents), "the beacon to register")
        # The addressable name, which is what /api/agents/<id>/task takes --
        # not the raw hash in the record, which is the distinction a live run
        # had to teach this project once already.
        record = list(agents.values())[0]
        self.beacon_id = record.get("agent_id") or record.get("id")

    def build_agent(self):
        self.conn = db.open_store(":memory:")
        self.c2 = c2client.C2Client("http://127.0.0.1:%d" % PORT, TEST_TOKEN,
                                    verify_tls=False)
        agent_fields = {"capability_tier": "full", "approval_timeout": 0.3}
        agent_fields.update(self.agent_fields)
        self.agent_cfg = config.AgentConfig(**agent_fields)
        payload = {"beacons": [self.beacon_id],
                   "scope_allow": self.scope_allow,
                   "scope_deny": self.scope_deny,
                   "phases": self.phases,
                   "mode": self.mode,
                   "unattended_behavior": self.unattended,
                   "campaign_interval": _CAMPAIGN_INTERVAL,
                   "restore_interval": _RESTORE_INTERVAL}
        payload.update(self.form)
        self.campaign_cfg = config.CampaignConfig.from_form(
            payload, tier=self.agent_cfg.capability_tier)

    def campaign(self, client):
        return orchestrator.Campaign(self.agent_cfg, self.campaign_cfg,
                                     self.conn, self.c2, client)

    def stop(self):
        if self.beacon is not None:
            self.beacon.stop()
        import shutil
        shutil.rmtree(getattr(self, "data_dir", ""), ignore_errors=True)

    # ── Reading the C2 directly, not through the agent's client ──

    def restore_tasks(self):
        """The `sleep <restore_interval> ...` tasks the beacon has run.

        The C2's agent record is not the thing to assert on here: its
        `interval` field is filled from the beacon's next check-in, and
        after a restore to 300s that check-in is 300s away, so the record
        reports the campaign's interval for five more minutes. The promise
        in the design is that the restore is issued on the way out and the
        beacon takes it, which is what this reads.
        """
        from software.c2.server import history
        want = str(_RESTORE_INTERVAL)
        return [h for entries in history.values() for h in entries
                if h.get("cmd") == "sleep"
                and str(h.get("args") or "").split()[:1] == [want]]

    def completed_restores(self):
        """Restores the beacon has actually run, not merely been sent.

        Waiting for the queued task and then asserting its status is a race
        against oneself: it exists as "pending" first. Wait for the thing
        being asserted.
        """
        return [h for h in self.restore_tasks()
                if h.get("status") not in (None, "pending")]

    def c2_history(self):
        from software.c2.server import history
        return json.dumps(history, default=str)


def _wait_until(predicate, what, timeout=45.0, every=0.1):
    """Poll until true. Named, so a failure says what never happened."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(every)
    raise AssertionError("timed out after %.0fs waiting for %s"
                         % (timeout, what))


async def _await_until(predicate, what, timeout=45.0, every=0.1):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(every)
    raise AssertionError("timed out after %.0fs waiting for %s"
                         % (timeout, what))


_SHARED = {}


def setUpModule():
    # One C2 and one beacon for every class here. A per-class server would
    # race for the port, and a second bind fails inside a daemon thread
    # where nothing reports it -- the symptom is a beacon that never
    # registers against a server that is answering.
    env = _LiveEnv()
    env.start_server()
    env.start_beacon()
    _SHARED["env"] = env


def tearDownModule():
    env = _SHARED.pop("env", None)
    if env is not None:
        env.stop()


class _LiveCase(unittest.IsolatedAsyncioTestCase):
    """The shared C2 and beacon; a fresh store and campaign per test."""

    ENV_KWARGS = {}

    def setUp(self):
        self.env = _SHARED["env"]
        # The campaign's own configuration is per test; the server and the
        # beacon are not.
        for key, value in self.ENV_KWARGS.items():
            setattr(self.env, {"scope_allow": "scope_allow",
                               "scope_deny": "scope_deny",
                               "phases": "phases", "mode": "mode",
                               "unattended": "unattended"}[key],
                    list(value) if isinstance(value, tuple) else value)
        self.env.build_agent()

    def tearDown(self):
        # Back to the module defaults, so one class cannot leak its scope
        # into the next.
        self.env.scope_allow = ["127.0.0.0/8"]
        self.env.scope_deny = []
        self.env.phases = [1, 2]
        self.env.mode = "auto"
        self.env.unattended = "decide"

    async def _run(self, client, timeout=90):
        camp = self.env.campaign(client)
        run_id = await camp.start()
        report = await asyncio.wait_for(camp.wait(), timeout=timeout)
        return run_id, report, camp


class TestACampaignDrivesALiveBeacon(_LiveCase):
    """The whole chain, with a real beacon on the other end of it."""

    async def test_a_command_reaches_the_beacon_and_the_record_is_complete(self):
        run_id, report, _ = await self._run(mock.MockClient([
            mock.calls(("set_phase", {"phase": 2})),
            mock.calls(("dispatch_task", {"task_name": "identify",
                                          "task_description": "run pwd"})),
            # The executor's turn: a beacon verb, which is the language a
            # beacon command is actually written in.
            mock.calls(("run_command", {"command": "pwd",
                                        "beacon_id": self.env.beacon_id})),
            mock.text("TASK: identify\nSTATUS: success\nFINDINGS:\n  - a path"),
            mock.calls(("remember_finding", {"host": "127.0.0.1",
                                             "finding_type": "note",
                                             "data": "pwd answered"})),
            mock.calls(("log_score", {"action": "host_discovered"})),
            mock.text("campaign finished: one host")]))

        run = queries.get_run(self.env.conn, run_id)
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["phase"], 2)
        self.assertIn("finished", report)

        task = self.env.conn.execute(
            "SELECT name, status, result FROM tasks").fetchone()
        self.assertEqual((task["name"], task["status"]),
                         ("identify", "completed"))

        self.assertEqual(
            len(queries.get_findings_by_host(self.env.conn, "127.0.0.1")), 1)
        self.assertEqual(
            queries.get_score_context(self.env.conn, run_id)["total_score"], 10)

    async def test_the_command_really_ran_on_the_beacon(self):
        # The point of the whole file: the output in the record came back
        # from a process on the other side of an HTTP round trip.
        await self._run(mock.MockClient([
            mock.calls(("dispatch_task", {"task_name": "t",
                                          "task_description": "run pwd"})),
            mock.calls(("run_command", {"command": "pwd",
                                        "beacon_id": self.env.beacon_id})),
            mock.text("TASK: t\nSTATUS: success"),
            mock.text("done")]))
        from software.c2.server import history
        outputs = [h.get("output") or ""
                   for entries in history.values() for h in entries
                   if h.get("cmd") == "pwd"]
        self.assertTrue(outputs, "no pwd task reached the beacon")
        self.assertTrue(any(out.strip().startswith("/") for out in outputs),
                        outputs)

    async def test_the_beacon_interval_is_put_back_afterwards(self):
        await self._run(mock.MockClient([mock.text("nothing to do")]))
        await _await_until(lambda: bool(self.env.completed_restores()),
                           "the beacon to run the restore")
        task = self.env.completed_restores()[-1]
        self.assertEqual(task["status"], "ok")
        self.assertIn(str(_RESTORE_INTERVAL), task["output"])


class TestScopeHoldsAgainstALiveBeacon(_LiveCase):
    ENV_KWARGS = {"scope_allow": ["10.99.0.0/24"]}

    async def test_an_out_of_scope_target_never_reaches_the_beacon(self):
        # Refused before dispatch, so the proof is the absence of the
        # address anywhere in the C2's own task history -- not a return
        # value the agent layer produced about itself.
        await self._run(mock.MockClient([
            mock.calls(("dispatch_task", {"task_name": "sweep",
                                          "task_description": "scan"})),
            mock.calls(("run_command", {"command": "netscan 192.168.50.0/24",
                                        "beacon_id": self.env.beacon_id})),
            mock.text("TASK: sweep\nSTATUS: failed\nERRORS: refused"),
            mock.text("scope refused it")]))
        self.assertNotIn("192.168.50", self.env.c2_history())

    async def test_the_refusal_is_handed_back_as_a_result_not_an_exception(self):
        # A refusal the model can read and correct; an exception would end
        # the turn and the campaign would learn nothing.
        _, report, _ = await self._run(mock.MockClient([
            mock.calls(("dispatch_task", {"task_name": "sweep",
                                          "task_description": "scan"})),
            mock.calls(("run_command", {"command": "nmap 192.168.50.1",
                                        "beacon_id": self.env.beacon_id})),
            mock.text("TASK: sweep\nSTATUS: failed"),
            mock.text("understood")]))
        self.assertEqual(queries.get_run(self.env.conn, 1)["status"],
                         "completed")
        self.assertIn("understood", report)


class TestATierOneActionIsRefusedAgainstALiveBeacon(_LiveCase):
    async def test_the_beacon_never_sees_a_tier_one_command(self):
        # `kill` is a real beacon verb that terminates it, and the gate
        # refuses it in every mode. Worth proving against a live beacon:
        # the whole point of the tier-1 list is that the box survives.
        await self._run(mock.MockClient([
            mock.calls(("dispatch_task", {"task_name": "end",
                                          "task_description": "stop it"})),
            mock.calls(("run_command", {"command": "kill",
                                        "beacon_id": self.env.beacon_id})),
            mock.text("TASK: end\nSTATUS: failed\nERRORS: refused"),
            mock.text("refused, as expected")]))
        self.assertNotIn('"cmd": "kill"', self.env.c2_history())
        from software.c2.server import agents
        self.assertTrue(agents, "the beacon is gone: a tier-1 action ran")


class TestTheOperatorIsNeverBlockedByTheAgent(_LiveCase):
    async def test_an_operator_task_is_answered_while_agent_work_is_queued(self):
        # The design's anti-goal: the operator must not wait behind an
        # agent's plan. Both lanes go to the same beacon.
        for _ in range(5):
            await self.env.c2.queue_task(self.env.beacon_id, "pwd",
                                         lane="agent")
        task_id = await self.env.c2.queue_task(self.env.beacon_id, "whoami",
                                               lane="operator")
        result = await self.env.c2.await_task(task_id, timeout=60)
        self.assertTrue(result)
        self.assertTrue((result.get("output") or "").strip())


class TestAKnockReachesTheOperatorAgainstALiveBeacon(_LiveCase):
    ENV_KWARGS = {"mode": "supervised", "unattended": "skip",
                  "phases": (1, 2, 3, 4, 5)}

    async def test_a_gated_action_asks_and_is_recorded(self):
        # supervised with "skip", so an unanswered knock resolves without a
        # timer this test has to race: the row and its reason are what
        # matter here.
        client = mock.MockClient([
            mock.calls(("dispatch_task", {"task_name": "creds",
                                          "task_description": "dump"})),
            mock.calls(("run_command", {"command": "lsassy -u a -p b 127.0.0.1",
                                        "beacon_id": self.env.beacon_id})),
            mock.text("TASK: creds\nSTATUS: failed\nERRORS: refused"),
            mock.text("the gate said no")])
        await self._run(client)
        row = self.env.conn.execute(
            "SELECT action, decision, decided_by FROM approvals").fetchone()
        self.assertIsNotNone(row, "no approval was recorded")
        self.assertEqual(row["decision"], "refused")
        self.assertNotIn("lsassy", self.env.c2_history())


class TestTheRunSurvivesATruncatedModel(_LiveCase):
    async def test_a_model_that_stops_early_still_closes_the_run(self):
        # A model that answers with no tool call at all: the run completes
        # rather than hanging, and the beacon's interval still goes back.
        run_id, report, _ = await self._run(
            mock.MockClient([mock.text("I have nothing to add")]))
        self.assertEqual(queries.get_run(self.env.conn, run_id)["status"],
                         "completed")
        await _await_until(lambda: bool(self.env.completed_restores()),
                           "the beacon to run the restore")
        self.assertIn("nothing", report)


if __name__ == "__main__":
    unittest.main()
