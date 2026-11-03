#!/usr/bin/env python3
"""
Tests for the campaign orchestrator: lifecycle, dispatch, pause, budgets and
orphan recovery. Nothing here touches the network: the C2 is a FakeC2 that
records what it is asked, and the model is a scripted client.

The assertions that carry the most weight:

  * the three groups of operator settings each have a test that asserts the
    *value arrived* where it is used, not that construction succeeded;
  * a ControlSignal raised inside a nested loop ends the job, and does not
    come back to the model as an error string;
  * nothing is left pending when a test ends. IsolatedAsyncioTestCase would
    quietly cancel a leaked task at teardown, so the base class checks first.
"""

import asyncio
import inspect
import json
import shlex
import sys
import unittest
import unittest.mock
from pathlib import Path
from unittest import IsolatedAsyncioTestCase

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent import orchestrator
from software.agent import config
from software.agent import c2client, config, gate, orchestrator, safety
from software.agent.control import ControlSignal
from software.agent.executor import router
from software.agent.llm import mock
from software.agent.llm.provider import LlmClient, ProviderError
from software.agent.store import db, queries

# Values chosen to be distinguishable from every default, so a setting that
# was dropped on the way shows up as the default and not as a pass.
_SECRETS = {"api_key": "CANARY_apikey_7f3a91c2",
            "c2_token": "CANARY_c2token_41be0d55",
            "agent_token": "CANARY_agenttoken_c08e62a7"}


# ── Fakes ──


class FakeC2:
    """Stands in for C2Client: records every call, answers from a table."""

    def __init__(self, down=False, agents=None, output="22/tcp open ssh"):
        self.down = down
        self.output = output
        self.agents = agents if agents is not None else {
            "raccoon-fox": {"id": "raccoon-fox", "status": "online",
                            "caps": ["batch"], "uplink_iface": "eth0"}}
        self.interval_calls = []
        self.exec_calls = []
        self.queued = []

    def _reachable(self):
        if self.down:
            raise c2client.C2Unavailable("C2 at fake:0 request failed (X)")

    async def get_agent(self, agent_id):
        self._reachable()
        return self.agents.get(agent_id)

    async def set_beacon_interval(self, agent_id, seconds, jitter):
        self._reachable()
        self.interval_calls.append((agent_id, seconds, jitter))

    async def queue_task(self, agent_id, cmd, args="", data="", timeout=300,
                         lane="agent"):
        self._reachable()
        self.queued.append((agent_id, cmd, args))
        return "task%d" % len(self.queued)

    async def await_task(self, task_id, *, timeout, poll_interval=2.0,
                         is_alive=None):
        return {"success": True, "status": "ok", "output": self.output}

    async def exec_server_tool(self, argv, *, tool, timeout, origin="agent"):
        self._reachable()
        self.exec_calls.append(list(argv))
        return "run%d" % len(self.exec_calls)

    async def await_server_tool(self, run_id, *, timeout, poll_interval=2.0):
        return {"success": True, "status": "ok", "output": self.output}

    def intervals(self):
        return [call[1] for call in self.interval_calls]


class _Script(LlmClient):
    """A client that plays steps in order and records what it was shown.

    A step is a Completion, an exception to raise, or a callable
    (client, system, messages, tools) -> Completion (or an awaitable of one)
    for a test that needs to act at the moment the model is asked.
    """
    provider = "mock"
    model = "mock-model"

    def __init__(self, steps):
        self._steps = list(steps)
        self.calls = []

    async def complete(self, system, messages, tools, max_tokens, temperature):
        self.calls.append({"system": system, "messages": list(messages),
                           "tools": [t.name for t in tools]})
        if not self._steps:
            raise AssertionError("script exhausted after %d calls"
                                 % len(self.calls))
        step = self._steps.pop(0)
        if callable(step):
            step = step(self, system, messages, tools)
        if inspect.isawaitable(step):
            step = await step
        if isinstance(step, BaseException):
            raise step
        return step

    def told(self, index):
        """Everything the model was shown on call `index`, as one string."""
        return json.dumps(self.calls[index]["messages"])


class _SlowClient(LlmClient):
    """Turns that take a while, so a test can act between two of them."""
    provider = "mock"
    model = "mock-model"

    def __init__(self, delay=0.03):
        self._delay = delay

    async def complete(self, system, messages, tools, max_tokens, temperature):
        await asyncio.sleep(self._delay)
        return mock.calls(("set_phase", {"phase": 1}))


def _slow_client():
    return _SlowClient()


class _CountingClient(LlmClient):
    """Answers every call with text after a pause, and counts overlap."""
    provider = "mock"
    model = "mock-model"

    def __init__(self, dispatches):
        self._first = mock.calls(*[
            ("dispatch_parallel_tasks", {"tasks": [
                {"name": "t%d" % i, "description": "d%d" % i}
                for i in range(dispatches)]})])
        self._served_first = False
        self.running = 0
        self.peak = 0

    async def complete(self, system, messages, tools, max_tokens, temperature):
        if not self._served_first:
            self._served_first = True
            return self._first
        if any(t.name == "dispatch_parallel_tasks" for t in tools):
            return mock.text("done")
        self.running += 1
        self.peak = max(self.peak, self.running)
        try:
            await asyncio.sleep(0.02)
        finally:
            self.running -= 1
        return mock.text("TASK: x\nSTATUS: success")


# ── Builders ──


def _env(c2_down=False):
    conn = db.open_store(":memory:")
    return conn, FakeC2(down=c2_down)


def _campaign(conn, c2, client, *, max_concurrent=None, max_tokens_total=None,
              max_runtime_seconds=None, raise_from_router=None, agent=None,
              **form):
    """A Campaign over a reduced-tier model, with the tests' scope and beacon.

    `agent` overrides AgentConfig fields; anything else is posted to
    CampaignConfig.from_form like the operator's form would be.
    """
    payload = {"beacons": ["raccoon-fox"], "scope_allow": ["10.0.1.0/24"],
               "mode": "auto", "campaign_interval": 15,
               "restore_interval": 300}
    if max_tokens_total is not None:
        payload["max_tokens_total"] = max_tokens_total
    if max_runtime_seconds is not None:
        payload["max_runtime_seconds"] = max_runtime_seconds
    payload.update(form)
    agent_fields = {"capability_tier": "reduced"}
    if max_concurrent is not None:
        agent_fields["max_concurrent_executors"] = max_concurrent
    agent_fields.update(agent or {})
    agent_cfg = config.AgentConfig(**agent_fields)
    campaign_cfg = config.CampaignConfig.from_form(
        payload, tier=agent_cfg.capability_tier)
    if raise_from_router is not None:
        unittest.mock.patch.object(
            router.Router, "run_command", side_effect=raise_from_router).start()
    return orchestrator.Campaign(agent_cfg, campaign_cfg, conn, c2, client)


def _via_executor(name="t", command="whoami"):
    """The two turns that get an executor to call run_command."""
    return [
        mock.calls(("dispatch_task", {"task_name": name,
                                      "task_description": "d"})),
        mock.calls(("run_command", {"command": command,
                                    "beacon_id": "raccoon-fox"}))]


class _Case(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.addCleanup(unittest.mock.patch.stopall)
        # The module logs a warning where it cannot reach the C2; tests that
        # care read it here instead of letting it print into the run.
        self.log = unittest.mock.patch.object(orchestrator, "logger").start()

    async def asyncTearDown(self):
        # IsolatedAsyncioTestCase cancels what is left at teardown without a
        # word, so a leaked task would pass every test. Look first.
        me = asyncio.current_task()
        left = [t for t in asyncio.all_tasks() if t is not me and not t.done()]
        names = [repr(t.get_coro()) for t in left]
        for t in left:
            t.cancel()
        self.assertEqual(names, [], "tasks still pending at the end of the test")


# ── Lifecycle ──


class TestLifecycle(_Case):
    async def test_run_record_is_created_and_completed(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient(
            [mock.text("Kampagne abgeschlossen")]))
        rid = await camp.start()
        self.assertEqual(await camp.wait(), "Kampagne abgeschlossen")
        row = queries.get_run(conn, rid)
        self.assertEqual(row["status"], "completed")
        self.assertIsNotNone(row["completed_at"])

    async def test_start_returns_the_run_id_without_waiting_for_the_work(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _slow_client())
        rid = await camp.start()
        self.assertEqual(queries.get_run(conn, rid)["status"], "running")
        self.assertEqual(camp.run_id, rid)
        camp.stop()
        await camp.wait()

    async def test_beacon_interval_lowered_at_start_and_restored_at_end(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("fertig")]))
        await camp.start()
        await camp.wait()
        self.assertEqual(c2.interval_calls[0], ("raccoon-fox", 15, 20))
        self.assertEqual(c2.interval_calls[-1], ("raccoon-fox", 300, 20))

    async def test_interval_restored_even_when_the_llm_fails(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.FailingClient("kein Kontakt"))
        rid = await camp.start()
        report = await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "failed")
        self.assertIn("kein Kontakt", report)
        self.assertEqual(c2.intervals(), [15, 300])

    async def test_interval_restored_when_the_client_raises_on_its_first_call(self):
        # Not a ProviderError: any exception out of the first call is the
        # case where a job dies immediately and must not leave the remote
        # record polling every 15 seconds.
        conn, c2 = _env()
        camp = _campaign(conn, c2, _Script([RuntimeError("boom")]))
        rid = await camp.start()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "failed")
        self.assertEqual(c2.intervals(), [15, 300])

    async def test_detection_budget_abort_sets_aborted_and_restores(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _Script(_via_executor()),
                         raise_from_router=router.RouterAborted("budget"))
        rid = await camp.start()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "aborted")
        self.assertEqual(c2.interval_calls[-1][1], 300)

    async def test_an_unreachable_c2_fails_the_run_and_does_not_hang(self):
        conn, c2 = _env(c2_down=True)
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]))
        rid = await camp.start()
        report = await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "failed")
        self.assertIn("C2", report)

    async def test_a_restore_that_fails_is_recorded_and_does_not_hide_the_end(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("fertig")]))
        real = c2.set_beacon_interval

        async def restore_fails(agent_id, seconds, jitter):
            if seconds == 300:
                raise c2client.C2Unavailable("C2 at fake:0 request failed (X)")
            await real(agent_id, seconds, jitter)

        c2.set_beacon_interval = restore_fails
        rid = await camp.start()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "completed")
        self.assertIn("error", {e["kind"] for e in camp.stream()})

    async def test_a_campaign_can_only_be_started_once(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]))
        await camp.start()
        with self.assertRaises(RuntimeError):
            await camp.start()
        await camp.wait()

    async def test_wait_before_start_is_an_error(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([]))
        with self.assertRaises(RuntimeError):
            await camp.wait()

    async def test_a_beacon_the_c2_does_not_know_is_not_lowered(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]),
                         beacons=["raccoon-fox", "raccoon-ghost"])
        await camp.start()
        await camp.wait()
        self.assertEqual({c[0] for c in c2.interval_calls}, {"raccoon-fox"})

    async def test_a_campaign_with_no_known_beacon_fails(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]),
                         beacons=["raccoon-ghost"])
        rid = await camp.start()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "failed")
        self.assertEqual(c2.interval_calls, [])


# ── Control signals ──


class TestControlSignals(_Case):
    def test_budget_exceeded_is_a_control_signal(self):
        self.assertTrue(issubclass(orchestrator.BudgetExceeded, ControlSignal))
        self.assertTrue(issubclass(router.RouterAborted, ControlSignal))
        self.assertTrue(issubclass(gate.GatePauseRequested, ControlSignal))

    async def test_a_signal_in_a_nested_loop_ends_the_job_not_the_model_turn(self):
        conn, c2 = _env()
        client = _Script(_via_executor() + [mock.text("never asked")])
        camp = _campaign(conn, c2, client,
                         raise_from_router=router.RouterAborted("spent"))
        rid = await camp.start()
        report = await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "aborted")
        self.assertIn("spent", report)
        # Orchestrator turn, executor turn: nothing after. Had the signal
        # become an error string, the executor would have been asked again.
        self.assertEqual(len(client.calls), 2)
        self.assertNotIn("[ERROR]", client.told(1))

    async def test_the_task_row_of_an_interrupted_executor_is_closed(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _Script(_via_executor()),
                         raise_from_router=router.RouterAborted("spent"))
        await camp.start()
        await camp.wait()
        row = conn.execute("SELECT status, result FROM tasks").fetchone()
        self.assertEqual(row["status"], "failed")
        self.assertIn("RouterAborted", row["result"])

    async def test_a_signal_in_the_parallel_callback_ends_the_job_too(self):
        conn, c2 = _env()
        client = _Script([
            mock.calls(("dispatch_parallel_tasks", {"tasks": [
                {"name": "a", "description": "d"},
                {"name": "b", "description": "d"}]})),
            mock.calls(("run_command", {"command": "whoami",
                                        "beacon_id": "raccoon-fox"})),
            mock.calls(("run_command", {"command": "whoami",
                                        "beacon_id": "raccoon-fox"}))])
        camp = _campaign(conn, c2, client,
                         raise_from_router=router.RouterAborted("spent"))
        rid = await camp.start()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "aborted")
        statuses = [r[0] for r in conn.execute("SELECT status FROM tasks")]
        self.assertNotIn("running", statuses)

    async def test_gate_pause_in_a_nested_loop_pauses_and_keeps_the_interval(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _Script(_via_executor()),
                         raise_from_router=gate.GatePauseRequested("knock"))
        rid = await camp.start()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "paused")
        self.assertNotIn(300, c2.intervals())

    async def test_an_ordinary_failure_in_a_nested_loop_is_an_error_string(self):
        conn, c2 = _env()
        client = _Script(_via_executor() + [mock.text("x"), mock.text("weiter")])
        camp = _campaign(conn, c2, client,
                         raise_from_router=RuntimeError("tool exploded"))
        rid = await camp.start()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "completed")

    async def test_an_unknown_control_signal_is_a_failure_not_a_pause(self):
        class Strange(ControlSignal):
            pass

        conn, c2 = _env()
        camp = _campaign(conn, c2, _Script(_via_executor()),
                         raise_from_router=Strange("odd"))
        rid = await camp.start()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "failed")
        self.assertEqual(c2.intervals()[-1], 300)


# ── Dispatch ──


class TestDispatch(_Case):
    async def test_dispatch_task_returns_the_executor_result(self):
        conn, c2 = _env()
        client = _Script([
            mock.calls(("dispatch_task", {"task_name": "scan",
                                          "task_description": "scan 10.0.1.5"})),
            mock.text("TASK: scan\nSTATUS: success\nFINDINGS:\n  - 445 offen"),
            mock.text("ergebnis gesehen")])
        camp = _campaign(conn, c2, client)
        await camp.start()
        await camp.wait()
        row = conn.execute("SELECT * FROM tasks").fetchone()
        self.assertEqual(row["status"], "completed")
        self.assertEqual(row["lane"], "agent")
        self.assertIn("445", row["result"])
        # ...and the orchestrator read it back.
        self.assertIn("445", client.told(2))

    async def test_the_executor_is_given_its_task_name(self):
        # The report format asks it to echo the name, so it has to see one.
        conn, c2 = _env()
        client = _Script([
            mock.calls(("dispatch_task", {"task_name": "portscan",
                                          "task_description": "look at .5"})),
            mock.text("r"), mock.text("ok")])
        camp = _campaign(conn, c2, client)
        await camp.start()
        await camp.wait()
        self.assertIn("portscan", client.told(1))
        self.assertIn("look at .5", client.told(1))

    async def test_parallel_dispatch_returns_both_sections(self):
        conn, c2 = _env()
        client = _Script([
            mock.calls(("dispatch_parallel_tasks", {"tasks": [
                {"name": "t1", "description": "d1"},
                {"name": "t2", "description": "d2"}]})),
            mock.text("TASK: t1\nSTATUS: success"),
            mock.text("TASK: t2\nSTATUS: success"),
            mock.text("beide gesehen")])
        camp = _campaign(conn, c2, client)
        await camp.start()
        await camp.wait()
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0], 2)
        seen = client.told(3)
        self.assertIn("=== Task: t1 ===", seen)
        self.assertIn("=== Task: t2 ===", seen)

    async def test_failing_executor_yields_an_error_string_not_an_exception(self):
        conn, c2 = _env()
        client = _Script([
            mock.calls(("dispatch_task", {"task_name": "t",
                                          "task_description": "d"})),
            ProviderError("provider down"),
            mock.text("fehler verstanden")])
        camp = _campaign(conn, c2, client)
        rid = await camp.start()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "completed")
        row = conn.execute("SELECT status, result FROM tasks").fetchone()
        self.assertEqual(row["status"], "failed")
        self.assertIn("[ERROR] Task 't' failed: provider down", row["result"])
        self.assertIn("[ERROR] Task 't' failed", client.told(2))

    async def test_a_setup_failure_in_a_nested_task_is_an_error_string_too(self):
        conn, c2 = _env()
        client = _Script([
            mock.calls(("dispatch_task", {"task_name": "t",
                                          "task_description": "d"})),
            mock.text("ok")])
        camp = _campaign(conn, c2, client)
        with unittest.mock.patch.object(
                orchestrator.registry, "executor_tools",
                side_effect=ValueError("no tools")):
            await camp.start()
            await camp.wait()
        self.assertIn("[ERROR] Task 't' failed: no tools", client.told(1))

    async def test_semaphore_of_one_serialises_without_deadlock(self):
        conn, c2 = _env()
        client = _CountingClient(3)
        camp = _campaign(conn, c2, client, max_concurrent=1)
        await camp.start()
        await asyncio.wait_for(camp.wait(), timeout=10)
        self.assertEqual(client.peak, 1)
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM tasks "
                         "WHERE status = 'completed'").fetchone()[0], 3)

    async def test_the_semaphore_bounds_concurrency_at_its_size(self):
        conn, c2 = _env()
        client = _CountingClient(4)
        camp = _campaign(conn, c2, client, max_concurrent=2)
        await camp.start()
        await asyncio.wait_for(camp.wait(), timeout=10)
        self.assertEqual(client.peak, 2)

    async def test_task_row_records_the_current_phase(self):
        conn, c2 = _env()
        client = mock.MockClient([
            mock.calls(("set_phase", {"phase": 3})),
            mock.calls(("dispatch_task", {"task_name": "t",
                                          "task_description": "d"})),
            mock.text("r"), mock.text("fertig")])
        camp = _campaign(conn, c2, client)
        await camp.start()
        await camp.wait()
        self.assertEqual(
            conn.execute("SELECT phase FROM tasks").fetchone()["phase"], 3)


# ── Budgets ──


class TestBudgets(_Case):
    async def test_token_budget_aborts_the_campaign(self):
        conn, c2 = _env()
        client = mock.MockClient([
            mock.calls(("set_phase", {"phase": 1}), total_tokens=400_000),
            mock.text("y", total_tokens=400_000)])
        camp = _campaign(conn, c2, client, max_tokens_total=500_000)
        rid = await camp.start()
        report = await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "aborted")
        self.assertIn("token", report)
        self.assertEqual(c2.intervals()[-1], 300)

    async def test_the_response_that_crosses_the_line_is_the_one_refused(self):
        # The loop logs a response only after complete() returns, so the
        # check has to count the one it is looking at.
        conn, c2 = _env()
        client = mock.MockClient([mock.text("x", total_tokens=600_000)])
        camp = _campaign(conn, c2, client, max_tokens_total=500_000)
        rid = await camp.start()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "aborted")

    async def test_a_response_under_the_budget_passes(self):
        conn, c2 = _env()
        client = mock.MockClient([mock.text("x", total_tokens=400_000)])
        camp = _campaign(conn, c2, client, max_tokens_total=500_000)
        rid = await camp.start()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "completed")

    async def test_executors_spend_the_same_budget(self):
        conn, c2 = _env()
        client = _Script([
            mock.calls(("dispatch_task", {"task_name": "t",
                                          "task_description": "d"}),
                       total_tokens=100),
            mock.text("big", total_tokens=900_000)])
        camp = _campaign(conn, c2, client, max_tokens_total=500_000)
        rid = await camp.start()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "aborted")
        self.assertEqual(len(client.calls), 2)

    async def test_runtime_budget_aborts_the_campaign(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _slow_client(), max_runtime_seconds=0.1)
        rid = await camp.start()
        report = await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "aborted")
        self.assertIn("runtime", report)
        self.assertEqual(c2.intervals()[-1], 300)

    async def test_status_reports_both_budgets(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient(
            [mock.text("x", total_tokens=1000)]), max_tokens_total=5000,
            max_runtime_seconds=60)
        await camp.start()
        await camp.wait()
        budgets = camp.status()["budgets"]
        self.assertEqual(budgets["tokens"], {"used": 1000, "limit": 5000})
        self.assertEqual(budgets["runtime_seconds"]["limit"], 60)
        self.assertGreaterEqual(budgets["runtime_seconds"]["elapsed"], 0)


# ── Pause and resume ──


class TestPauseResume(_Case):
    async def test_pause_sets_status_and_keeps_the_lowered_interval(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _slow_client())
        rid = await camp.start()
        await asyncio.sleep(0.05)
        camp.pause()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "paused")
        self.assertNotIn(300, [i[1] for i in c2.interval_calls])

    async def test_pause_lets_an_in_flight_executor_finish(self):
        conn, c2 = _env()

        def pause_now(client, system, messages, tools):
            camp.pause()
            return mock.calls(("run_command", {"command": "whoami",
                                               "beacon_id": "raccoon-fox"}))

        # The executor's second turn comes after the pause was requested.
        # Were its guard the orchestrator's, that turn would be refused.
        client = _Script([
            mock.calls(("dispatch_task", {"task_name": "t",
                                          "task_description": "d"})),
            pause_now,
            mock.text("executor fertig"),
            mock.text("never asked")])
        camp = _campaign(conn, c2, client)
        rid = await camp.start()
        await camp.wait()
        row = conn.execute("SELECT status, result FROM tasks").fetchone()
        self.assertEqual(row["status"], "completed")
        self.assertEqual(row["result"], "executor fertig")
        self.assertEqual(queries.get_run(conn, rid)["status"], "paused")
        self.assertEqual(len(client.calls), 3)

    async def test_pause_stops_new_nested_loops_from_starting(self):
        conn, c2 = _env()

        def pause_now(client, system, messages, tools):
            camp.pause()
            return mock.text("erster fertig")

        client = _Script([
            mock.calls(("dispatch_parallel_tasks", {"tasks": [
                {"name": "a", "description": "d"},
                {"name": "b", "description": "d"},
                {"name": "c", "description": "d"}]})),
            pause_now])
        camp = _campaign(conn, c2, client, max_concurrent=1)
        await camp.start()
        await camp.wait()
        rows = conn.execute("SELECT name, status FROM tasks").fetchall()
        self.assertEqual([(r["name"], r["status"]) for r in rows],
                         [("a", "completed")])

    async def test_pause_before_the_first_turn_pauses_without_dispatching(self):
        conn, c2 = _env()
        client = _Script([mock.text("never asked")])
        camp = _campaign(conn, c2, client)
        rid = await camp.start()
        camp.pause()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "paused")
        self.assertEqual(client.calls, [])

    async def test_the_pause_reply_is_the_documented_string(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([]))
        await camp.start()
        camp._pause.set()
        self.assertEqual(await camp._dispatch_single("t", "d"),
                         "[PAUSED] dispatch suspended")
        self.assertEqual(
            await camp._dispatch_parallel([{"name": "t", "description": "d"}]),
            "=== Task: t ===\n[PAUSED] dispatch suspended\n\n")
        await camp.wait()

    async def test_resume_continues_the_same_run_with_fresh_budget(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _slow_client(), max_runtime_seconds=0.2)
        rid = await camp.start()
        await asyncio.sleep(0.05)
        camp.pause()
        await camp.wait()
        # Longer than the whole budget has passed by now.
        await asyncio.sleep(0.25)
        camp.client = mock.MockClient([mock.text("jetzt fertig")])
        await camp.resume()
        self.assertEqual(await camp.wait(), "jetzt fertig")
        self.assertEqual(queries.get_run(conn, rid)["status"], "completed")
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0], 1)
        self.assertEqual(c2.intervals()[-1], 300)

    async def test_resume_lowers_the_interval_again(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _slow_client())
        await camp.start()
        await asyncio.sleep(0.05)
        camp.pause()
        await camp.wait()
        camp.client = mock.MockClient([mock.text("fertig")])
        await camp.resume()
        await camp.wait()
        self.assertEqual(c2.intervals(), [15, 15, 300])

    async def test_resume_tells_the_model_the_conversation_is_not_restored(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _slow_client())
        await camp.start()
        await asyncio.sleep(0.05)
        camp.pause()
        await camp.wait()
        client = _Script([mock.text("fertig")])
        camp.client = client
        await camp.resume()
        await camp.wait()
        self.assertIn("resum", client.told(0).lower())
        self.assertIn("get_run_summary", client.told(0))

    async def test_only_a_paused_campaign_can_be_resumed(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]))
        await camp.start()
        await camp.wait()
        with self.assertRaises(RuntimeError):
            await camp.resume()

    async def test_gate_pause_request_pauses_the_campaign(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _Script(_via_executor()),
                         raise_from_router=gate.GatePauseRequested("knock"))
        rid = await camp.start()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "paused")

    async def test_a_gate_paused_campaign_can_be_resumed(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _Script(_via_executor()),
                         raise_from_router=gate.GatePauseRequested("knock"))
        rid = await camp.start()
        await camp.wait()
        camp.client = mock.MockClient([mock.text("weiter")])
        await camp.resume()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "completed")

    async def test_stop_sets_aborted_and_restores_the_interval(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _slow_client())
        rid = await camp.start()
        await asyncio.sleep(0.05)
        camp.stop()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "aborted")
        self.assertEqual(c2.interval_calls[-1][1], 300)

    async def test_stop_right_after_start_still_ends_the_row(self):
        # Cancelling a task that has not run yet would skip the whole body,
        # and the row would stay "running" for ever.
        conn, c2 = _env()
        camp = _campaign(conn, c2, _slow_client())
        rid = await camp.start()
        camp.stop()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "aborted")

    async def test_stop_cancels_executors_and_closes_their_rows(self):
        conn, c2 = _env()
        gate_open = asyncio.Event()

        async def hang(client, system, messages, tools):
            await gate_open.wait()

        client = _Script([
            mock.calls(("dispatch_task", {"task_name": "t",
                                          "task_description": "d"})),
            hang])
        camp = _campaign(conn, c2, client)
        rid = await camp.start()
        await asyncio.sleep(0.05)
        camp.stop()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "aborted")
        self.assertEqual(
            conn.execute("SELECT status FROM tasks").fetchone()["status"],
            "failed")

    async def test_stop_on_a_paused_campaign_aborts_and_restores(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _slow_client())
        rid = await camp.start()
        await asyncio.sleep(0.05)
        camp.pause()
        await camp.wait()
        camp.stop()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "aborted")
        self.assertEqual(c2.intervals()[-1], 300)

    async def test_pause_and_stop_after_the_end_change_nothing(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]))
        rid = await camp.start()
        await camp.wait()
        camp.pause()
        camp.stop()
        self.assertEqual(queries.get_run(conn, rid)["status"], "completed")

    async def test_cancelling_wait_ends_the_row_instead_of_leaking(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _slow_client())
        rid = await camp.start()
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(camp.wait(), timeout=0.05)
        self.assertEqual(queries.get_run(conn, rid)["status"], "aborted")
        self.assertEqual(c2.intervals()[-1], 300)


# ── The three groups of operator settings ──


class TestSettingsArrive(_Case):
    """Each setting is asserted where it is *used*, not where it is stored."""

    async def test_gate_receives_every_value(self):
        conn, c2 = _env()
        camp = _campaign(
            conn, c2, mock.MockClient([mock.text("x")]),
            agent={"approval_timeout": 42.5},
            ev_threshold=7.5, p_detect_prior=0.33, detection_budget=5,
            risk_coefficient=12.5, unattended_behavior="skip")
        await camp.start()
        g = camp.gate
        self.assertEqual(g.ev_threshold, 7.5)
        self.assertEqual(g.p_detect_prior, 0.33)
        self.assertEqual(g.detection_budget, 5)
        self.assertEqual(g.risk_coefficient, 12.5)
        self.assertEqual(g.unattended_behavior, "skip")
        self.assertEqual(g.approval_timeout, 42.5)
        self.assertEqual(g.mode, "auto")
        await camp.wait()

    async def test_the_router_uses_the_campaigns_gate(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]))
        await camp.start()
        self.assertIs(camp._router.gate, camp.gate)
        await camp.wait()

    async def test_gate_is_not_built_before_the_run_exists(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([]))
        self.assertIsNone(camp.gate)

    async def test_supervised_mode_reaches_the_gate(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]),
                         mode="supervised")
        await camp.start()
        self.assertEqual(camp.gate.mode, "supervised")
        await camp.wait()

    async def test_unattended_pause_takes_effect_through_the_real_gate(self):
        # End to end: the setting reaches the gate, the gate reaches the
        # router, and the router's signal reaches the lifecycle.
        conn, c2 = _env()
        client = _Script([
            mock.calls(("dispatch_task", {"task_name": "t",
                                          "task_description": "d"})),
            mock.calls(("run_command", {"command": "lsassy -u a -p b 10.0.1.5",
                                        "server_side": True}))])
        camp = _campaign(conn, c2, client, unattended_behavior="pause")
        rid = await camp.start()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "paused")
        self.assertEqual(c2.exec_calls, [])

    async def test_ev_threshold_decides_a_gated_command(self):
        async def run_with(threshold):
            conn, c2 = _env()
            client = _Script([
                mock.calls(("dispatch_task", {"task_name": "t",
                                              "task_description": "d"})),
                mock.calls(("run_command", {"command": "lsassy -u a -p b 10.0.1.5",
                                            "server_side": True})),
                mock.text("r"), mock.text("fertig")])
            camp = _campaign(conn, c2, client, ev_threshold=threshold)
            await camp.start()
            await camp.wait()
            return c2.exec_calls

        self.assertEqual(len(await run_with(-1e6)), 1)
        self.assertEqual(await run_with(1e6), [])

    async def test_online_lookups_off_removes_the_lookup_tool(self):
        names = {}
        for online in (True, False):
            conn, c2 = _env()
            client = _Script(_via_executor() + [mock.text("r"), mock.text("x")])
            camp = _campaign(conn, c2, client, online_lookups=online)
            await camp.start()
            await camp.wait()
            names[online] = client.calls[1]["tools"]
        self.assertIn("lookup_cve", names[True])
        self.assertNotIn("lookup_cve", names[False])
        # Only that tool: the rest of the executor's kit is unchanged.
        self.assertEqual(sorted(set(names[True]) - {"lookup_cve"}),
                         sorted(names[False]))

    async def test_opsec_profile_sets_online_lookups_through_the_form(self):
        conn, c2 = _env()
        client = _Script(_via_executor() + [mock.text("r"), mock.text("x")])
        camp = _campaign(conn, c2, client, opsec_profile="quiet")
        await camp.start()
        await camp.wait()
        self.assertNotIn("lookup_cve", client.calls[1]["tools"])

    async def test_limit_scan_rate_decides_what_reaches_the_c2(self):
        command = "nmap -sV 10.0.1.5"
        argv = {}
        for limited in (True, False):
            conn, c2 = _env()
            client = _Script([
                mock.calls(("dispatch_task", {"task_name": "t",
                                              "task_description": "d"})),
                mock.calls(("run_command", {"command": command,
                                            "server_side": True})),
                mock.text("r"), mock.text("fertig")])
            camp = _campaign(conn, c2, client, limit_scan_rate=limited)
            await camp.start()
            await camp.wait()
            self.assertEqual(len(c2.exec_calls), 1)
            argv[limited] = c2.exec_calls[0]
        self.assertEqual(argv[True],
                         shlex.split(safety.enforce_scan_limits(command)))
        self.assertEqual(argv[False], shlex.split(command))
        self.assertNotEqual(argv[True], argv[False])

    async def test_yolo_profile_lifts_the_rate_limit(self):
        conn, c2 = _env()
        client = _Script([
            mock.calls(("dispatch_task", {"task_name": "t",
                                          "task_description": "d"})),
            mock.calls(("run_command", {"command": "nmap -sV 10.0.1.5",
                                        "server_side": True})),
            mock.text("r"), mock.text("fertig")])
        camp = _campaign(conn, c2, client, opsec_profile="yolo")
        await camp.start()
        await camp.wait()
        self.assertEqual(c2.exec_calls[0], ["nmap", "-sV", "10.0.1.5"])

    async def test_the_phases_the_run_may_use_reach_the_router(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]),
                         agent={"capability_tier": "full"}, phases=[1, 2, 5])
        await camp.start()
        self.assertTrue(camp._router._phase5_enabled)
        await camp.wait()
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]),
                         phases=[1, 2])
        await camp.start()
        self.assertFalse(camp._router._phase5_enabled)
        await camp.wait()

    async def test_beacon_capabilities_and_uplink_reach_the_router(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]))
        await camp.start()
        await camp.wait()
        self.assertEqual(camp._router._beacon_ids, ["raccoon-fox"])
        self.assertEqual(camp._router._caps, {"raccoon-fox": ["batch"]})
        self.assertEqual(camp._router._uplinks, {"raccoon-fox": "eth0"})


class TestConfigRecord(_Case):
    async def test_config_json_holds_no_secret_from_the_agent_config(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]),
                         agent=dict(_SECRETS, provider="anthropic",
                                    model="m", base_url="https://example.test"))
        rid = await camp.start()
        await camp.wait()
        stored = queries.get_run(conn, rid)["config_json"]
        for name, value in _SECRETS.items():
            self.assertNotIn(value, stored, name)
        everything = json.dumps([dict(r) for r in conn.execute(
            "SELECT * FROM runs")]) + json.dumps(camp.stream())
        for name, value in _SECRETS.items():
            self.assertNotIn(value, everything, name)

    async def test_config_json_carries_what_orphan_recovery_reads(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]),
                         beacons=["raccoon-fox", "raccoon-pi"],
                         restore_interval=240)
        rid = await camp.start()
        await camp.wait()
        stored = json.loads(queries.get_run(conn, rid)["config_json"])
        self.assertEqual(stored["beacons"], ["raccoon-fox", "raccoon-pi"])
        self.assertEqual(stored["restore_interval"], 240)

    async def test_config_json_is_the_operators_settings_not_the_services(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]),
                         ev_threshold=7.5)
        rid = await camp.start()
        await camp.wait()
        stored = json.loads(queries.get_run(conn, rid)["config_json"])
        self.assertEqual(stored["campaign"]["ev_threshold"], 7.5)
        self.assertEqual(stored["campaign"]["phases"], [1, 2, 3, 4])
        self.assertNotIn("api_key", json.dumps(stored))


# ── Orphans ──


class TestOrphanRecovery(_Case):
    """Review Focus 5: Absturz bei abgesenktem Intervall."""

    def _orphan(self, conn, **extra):
        data = {"beacons": ["raccoon-fox"], "restore_interval": 300}
        data.update(extra)
        return queries.create_run(conn, "campaign", None, "auto",
                                  json.dumps(data))

    async def test_restore_orphans_resets_intervals_of_unfinished_runs(self):
        conn, c2 = _env()
        rid = self._orphan(conn)
        restored = await orchestrator.restore_orphans(conn, c2)
        self.assertIn(rid, restored)
        self.assertEqual(c2.interval_calls[-1], ("raccoon-fox", 300, 20))

    async def test_restore_orphans_marks_running_runs_as_failed(self):
        conn, c2 = _env()
        rid = self._orphan(conn)
        await orchestrator.restore_orphans(conn, c2)
        row = queries.get_run(conn, rid)
        self.assertEqual(row["status"], "failed")
        self.assertIsNotNone(row["completed_at"])

    async def test_paused_runs_keep_their_status_but_get_intervals_restored(self):
        conn, c2 = _env()
        rid = self._orphan(conn)
        queries.set_run_status(conn, rid, "paused")
        await orchestrator.restore_orphans(conn, c2)
        self.assertEqual(queries.get_run(conn, rid)["status"], "paused")
        self.assertEqual(c2.interval_calls[-1][1], 300)

    async def test_finished_runs_are_left_alone(self):
        conn, c2 = _env()
        rid = self._orphan(conn)
        queries.set_run_status(conn, rid, "completed")
        self.assertEqual(await orchestrator.restore_orphans(conn, c2), [])
        self.assertEqual(c2.interval_calls, [])
        self.assertEqual(queries.get_run(conn, rid)["status"], "completed")

    async def test_unreachable_c2_does_not_prevent_startup(self):
        conn, c2 = _env(c2_down=True)
        rid = self._orphan(conn)
        result = await orchestrator.restore_orphans(conn, c2)
        self.assertIsInstance(result, list)
        self.assertEqual(result, [rid])
        # The status was still corrected: the database does not depend on
        # the remote side. And the operator can learn what was left undone.
        self.assertEqual(queries.get_run(conn, rid)["status"], "failed")
        self.assertTrue(self.log.warning.called)

    async def test_unreachable_c2_is_tried_once_not_once_per_beacon(self):
        conn, c2 = _env(c2_down=True)
        self._orphan(conn, beacons=["a", "b", "c"])
        calls = []
        real = c2.set_beacon_interval

        async def counting(*args):
            calls.append(args)
            await real(*args)

        c2.set_beacon_interval = counting
        await orchestrator.restore_orphans(conn, c2)
        self.assertEqual(len(calls), 1)

    async def test_one_gone_beacon_does_not_stop_the_others(self):
        conn, c2 = _env()
        self._orphan(conn, beacons=["a", "b"])
        real = c2.set_beacon_interval

        async def first_is_gone(agent_id, seconds, jitter):
            if agent_id == "a":
                raise c2client.BeaconGone("gone")
            await real(agent_id, seconds, jitter)

        c2.set_beacon_interval = first_is_gone
        await orchestrator.restore_orphans(conn, c2)
        self.assertEqual([c[0] for c in c2.interval_calls], ["b"])

    async def test_a_run_without_a_restore_interval_is_marked_but_not_guessed_at(self):
        conn, c2 = _env()
        rid = queries.create_run(conn, "campaign", None, "auto",
                                 json.dumps({"beacons": ["raccoon-fox"]}))
        await orchestrator.restore_orphans(conn, c2)
        self.assertEqual(queries.get_run(conn, rid)["status"], "failed")
        self.assertEqual(c2.interval_calls, [])

    async def test_unreadable_config_json_still_gets_its_status_fixed(self):
        conn, c2 = _env()
        rid = queries.create_run(conn, "campaign", None, "auto", "{not json")
        self.assertEqual(await orchestrator.restore_orphans(conn, c2), [rid])
        self.assertEqual(queries.get_run(conn, rid)["status"], "failed")

    async def test_a_campaign_this_process_started_is_recoverable_after_a_crash(self):
        # The record a live campaign writes is the one recovery reads.
        conn, c2 = _env()
        camp = _campaign(conn, c2, _slow_client())
        rid = await camp.start()
        await asyncio.sleep(0.05)
        camp.stop()
        await camp.wait()
        queries.set_run_status(conn, rid, "running")
        c2.interval_calls.clear()
        await orchestrator.restore_orphans(conn, c2)
        self.assertEqual(c2.interval_calls, [("raccoon-fox", 300, 20)])


# ── Stream ──


class TestStream(_Case):
    async def test_stream_records_dispatches_and_decisions(self):
        conn, c2 = _env()
        client = mock.MockClient([
            mock.calls(("dispatch_task", {"task_name": "scan",
                                          "task_description": "d"})),
            mock.text("r"), mock.text("fertig")])
        camp = _campaign(conn, c2, client)
        await camp.start()
        await camp.wait()
        kinds = {e["kind"] for e in camp.stream()}
        self.assertIn("dispatch", kinds)

    async def test_stream_since_returns_only_newer_events(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("fertig")]))
        await camp.start()
        await camp.wait()
        all_events = camp.stream()
        self.assertTrue(all_events)
        self.assertEqual(camp.stream(since=len(all_events)), [])
        self.assertEqual(camp.stream(since=1), all_events[1:])

    async def test_events_have_the_documented_shape_and_count_from_one(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("fertig")]))
        await camp.start()
        await camp.wait()
        events = camp.stream()
        self.assertEqual([e["seq"] for e in events],
                         list(range(1, len(events) + 1)))
        for e in events:
            self.assertEqual(set(e), {"seq", "ts", "kind", "text", "detail"})
            self.assertIn(e["kind"], orchestrator.STREAM_KINDS)
            self.assertIsInstance(e["text"], str)
            self.assertIsInstance(e["detail"], dict)
        json.dumps(events)

    async def test_the_caller_cannot_edit_the_stream_through_what_it_got(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("fertig")]))
        await camp.start()
        await camp.wait()
        camp.stream()[0]["text"] = "edited"
        camp.stream()[0]["detail"]["x"] = 1
        self.assertNotEqual(camp.stream()[0]["text"], "edited")
        self.assertNotIn("x", camp.stream()[0]["detail"])

    async def test_phase_score_and_finding_calls_reach_the_stream(self):
        conn, c2 = _env()
        client = mock.MockClient([
            mock.calls(("set_phase", {"phase": 2}),
                       ("log_score", {"action": "host_discovered"}),
                       ("remember_finding", {"host": "10.0.1.5",
                                             "finding_type": "host",
                                             "data": "alive"})),
            mock.text("fertig")])
        camp = _campaign(conn, c2, client)
        await camp.start()
        await camp.wait()
        kinds = [e["kind"] for e in camp.stream()]
        for expected in ("phase", "score", "finding"):
            self.assertIn(expected, kinds)

    async def test_a_reported_detection_is_a_detection_event(self):
        conn, c2 = _env()
        client = mock.MockClient([
            mock.calls(("log_score", {"action": "detection"})),
            mock.text("fertig")])
        camp = _campaign(conn, c2, client)
        await camp.start()
        await camp.wait()
        self.assertIn("detection", [e["kind"] for e in camp.stream()])

    async def test_a_gate_decision_reaches_the_stream(self):
        conn, c2 = _env()
        client = _Script([
            mock.calls(("dispatch_task", {"task_name": "t",
                                          "task_description": "d"})),
            mock.calls(("run_command", {"command": "lsassy -u a -p b 10.0.1.5",
                                        "server_side": True})),
            mock.text("r"), mock.text("fertig")])
        camp = _campaign(conn, c2, client, ev_threshold=-1e6)
        await camp.start()
        await camp.wait()
        ev = [e for e in camp.stream() if e["kind"] == "ev"]
        self.assertEqual(len(ev), 1)
        self.assertIn("lsass_dump", ev[0]["text"])
        self.assertTrue(ev[0]["detail"]["allowed"])

    async def test_a_tool_error_is_an_error_event(self):
        conn, c2 = _env()
        client = mock.MockClient([
            mock.calls(("set_phase", {"phase": 99})), mock.text("fertig")])
        camp = _campaign(conn, c2, client)
        await camp.start()
        await camp.wait()
        self.assertIn("error", [e["kind"] for e in camp.stream()])

    async def test_a_long_text_is_clipped(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]))
        await camp.start()
        camp._emit("info", "y" * 5000)
        await camp.wait()
        self.assertLess(len(camp.stream()[-1]["text"]), 1000)


class TestStatus(_Case):
    async def test_status_reads_run_phase_score_and_stream_length(self):
        conn, c2 = _env()
        client = mock.MockClient([
            mock.calls(("set_phase", {"phase": 2}),
                       ("log_score", {"action": "host_discovered"}),
                       ("log_score", {"action": "detection"})),
            mock.text("fertig")])
        camp = _campaign(conn, c2, client)
        rid = await camp.start()
        await camp.wait()
        status = camp.status()
        self.assertEqual(status["run_id"], rid)
        self.assertEqual(status["status"], "completed")
        self.assertEqual(status["phase"], 2)
        self.assertEqual(status["score"], -90)
        self.assertEqual(status["detections"], 1)
        self.assertEqual(status["stream_length"], len(camp.stream()))

    async def test_status_before_start_does_not_raise(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([]))
        self.assertIsNone(camp.status()["run_id"])

    async def test_status_follows_pause_and_resume(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _slow_client())
        await camp.start()
        self.assertEqual(camp.status()["status"], "running")
        await asyncio.sleep(0.05)
        camp.pause()
        await camp.wait()
        self.assertEqual(camp.status()["status"], "paused")
        camp.stop()
        await camp.wait()


# ── No leaked tasks ──


class TestNoLeaks(_Case):
    async def _nothing_pending(self):
        me = asyncio.current_task()
        return [t for t in asyncio.all_tasks() if t is not me and not t.done()]

    async def test_nothing_is_pending_after_wait(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]))
        await camp.start()
        await camp.wait()
        self.assertEqual(await self._nothing_pending(), [])

    async def test_nothing_is_pending_after_a_parallel_dispatch(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _CountingClient(4), max_concurrent=2)
        await camp.start()
        await camp.wait()
        self.assertEqual(await self._nothing_pending(), [])

    async def test_nothing_is_pending_after_a_signal_cuts_a_parallel_dispatch(self):
        conn, c2 = _env()
        client = _Script([
            mock.calls(("dispatch_parallel_tasks", {"tasks": [
                {"name": n, "description": "d"} for n in "abc"]})),
            mock.calls(("run_command", {"command": "whoami",
                                        "beacon_id": "raccoon-fox"})),
            mock.calls(("run_command", {"command": "whoami",
                                        "beacon_id": "raccoon-fox"})),
            mock.calls(("run_command", {"command": "whoami",
                                        "beacon_id": "raccoon-fox"}))])
        camp = _campaign(conn, c2, client, max_concurrent=2,
                         raise_from_router=router.RouterAborted("spent"))
        await camp.start()
        await camp.wait()
        self.assertEqual(await self._nothing_pending(), [])

    async def test_nothing_is_pending_after_stop_and_after_pause(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _slow_client())
        await camp.start()
        await asyncio.sleep(0.05)
        camp.pause()
        await camp.wait()
        self.assertEqual(await self._nothing_pending(), [])
        camp.stop()
        await camp.wait()
        self.assertEqual(await self._nothing_pending(), [])

    async def test_nothing_is_pending_after_a_failed_start(self):
        conn, c2 = _env(c2_down=True)
        camp = _campaign(conn, c2, mock.MockClient([]))
        await camp.start()
        await camp.wait()
        self.assertEqual(await self._nothing_pending(), [])

    async def test_a_signal_cancels_the_siblings_still_running(self):
        conn, c2 = _env()
        never = asyncio.Event()

        async def hang(client, system, messages, tools):
            await never.wait()

        # Executor "a" is asked first and hangs; "b" is asked second and
        # runs into the signal. "a" must be cut, not waited for.
        client = _Script([
            mock.calls(("dispatch_parallel_tasks", {"tasks": [
                {"name": "a", "description": "d"},
                {"name": "b", "description": "d"}]})),
            hang,
            mock.calls(("run_command", {"command": "whoami",
                                        "beacon_id": "raccoon-fox"}))])
        camp = _campaign(conn, c2, client, max_concurrent=2,
                         raise_from_router=router.RouterAborted("spent"))
        rid = await camp.start()
        await asyncio.wait_for(camp.wait(), timeout=5)
        self.assertEqual(queries.get_run(conn, rid)["status"], "aborted")
        rows = conn.execute("SELECT name, status, result FROM tasks "
                            "ORDER BY id").fetchall()
        self.assertEqual([r["status"] for r in rows], ["failed", "failed"])
        self.assertIn("CancelledError", rows[0]["result"])
        self.assertEqual(await self._nothing_pending(), [])

    async def test_the_semaphore_is_free_again_after_a_cut_dispatch(self):
        conn, c2 = _env()
        client = _Script([
            mock.calls(("dispatch_parallel_tasks", {"tasks": [
                {"name": n, "description": "d"} for n in "ab"]})),
            mock.calls(("run_command", {"command": "whoami",
                                        "beacon_id": "raccoon-fox"})),
            mock.calls(("run_command", {"command": "whoami",
                                        "beacon_id": "raccoon-fox"}))])
        camp = _campaign(conn, c2, client, max_concurrent=2,
                         raise_from_router=router.RouterAborted("spent"))
        await camp.start()
        await camp.wait()
        await asyncio.sleep(0)
        for _ in range(2):
            await asyncio.wait_for(camp._sem.acquire(), timeout=1)
        self.assertTrue(camp._sem.locked())


# ── Manager ──


class TestManager(_Case):
    async def test_active_and_running_ids_follow_the_campaign(self):
        conn, c2 = _env()
        manager = orchestrator.CampaignManager()
        camp = _campaign(conn, c2, _slow_client())
        rid = await camp.start()
        manager.add(camp)
        self.assertEqual(manager.running_run_ids, {rid})
        self.assertEqual([a["run_id"] for a in manager.active()], [rid])
        self.assertIs(manager.get(rid), camp)
        camp.stop()
        await camp.wait()
        self.assertEqual(manager.running_run_ids, set())
        self.assertEqual(manager.active(), [])
        self.assertIs(manager.get(rid), camp)

    async def test_a_paused_campaign_still_counts_as_unfinished(self):
        # The overlap lock exists to keep a second run off the same network,
        # and a paused run is still holding it.
        conn, c2 = _env()
        manager = orchestrator.CampaignManager()
        camp = _campaign(conn, c2, _slow_client())
        rid = await camp.start()
        manager.add(camp)
        await asyncio.sleep(0.05)
        camp.pause()
        await camp.wait()
        self.assertEqual(manager.running_run_ids, {rid})
        camp.stop()
        await camp.wait()

    async def test_add_before_start_registers_once_the_run_exists(self):
        conn, c2 = _env()
        manager = orchestrator.CampaignManager()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]))
        manager.add(camp)
        self.assertEqual(manager.running_run_ids, set())
        rid = await camp.start()
        self.assertEqual(manager.running_run_ids, {rid})
        await camp.wait()

    async def test_old_finished_campaigns_are_dropped(self):
        conn, c2 = _env()
        manager = orchestrator.CampaignManager()
        first = None
        for _ in range(orchestrator.KEEP_FINISHED + 2):
            camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]))
            rid = await camp.start()
            await camp.wait()
            manager.add(camp)
            first = first or rid
        self.assertIsNone(manager.get(first))
        self.assertIsNotNone(manager.get(rid))


if __name__ == "__main__":
    unittest.main()


class TestAnEventCarriesTheCallThatMadeIt(_Case):
    """The detail panel is meant to show the arguments and the raw output.

    It had nothing to show: only a summary line was recorded, so spec
    §17.1's "full tool arguments, raw output, the associated model
    interaction" was unbuildable. The full record now lives on the event,
    the poll clips it, and `event(seq)` serves it whole.
    """

    async def _run(self, calls):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient(calls))
        await camp.start()
        await camp.wait()
        return camp

    async def test_the_poll_carries_the_tool_name_and_a_preview(self):
        camp = await self._run([
            mock.calls(("log_score", {"action": "host_discovered"})),
            mock.text("done")])
        scored = [e for e in camp.stream() if e["kind"] == "score"]
        self.assertTrue(scored)
        self.assertEqual(scored[0]["detail"]["tool"], "log_score")

    async def test_the_poll_does_not_ship_whole_structures(self):
        # Polled every 1.5 seconds, so arguments and results are summarised
        # rather than sent in full.
        camp = await self._run([
            mock.calls(("log_score", {"action": "host_discovered"})),
            mock.text("done")])
        detail = camp.stream()[-1]["detail"]
        for key in ("arguments", "result"):
            if key in detail:
                self.assertIsInstance(detail[key], str)
                self.assertTrue(detail[key].startswith("<"), detail[key])

    async def test_event_returns_the_arguments_and_the_result_whole(self):
        camp = await self._run([
            mock.calls(("log_score", {"action": "host_discovered"})),
            mock.text("done")])
        seq = [e["seq"] for e in camp.stream() if e["kind"] == "score"][0]
        full = camp.event(seq)
        self.assertEqual(full["detail"]["arguments"],
                         {"action": "host_discovered"})
        self.assertIsInstance(full["detail"]["result"], dict)
        self.assertEqual(full["detail"]["tool"], "log_score")

    async def test_event_is_a_copy_so_a_caller_cannot_edit_the_record(self):
        camp = await self._run([
            mock.calls(("log_score", {"action": "host_discovered"})),
            mock.text("done")])
        seq = [e["seq"] for e in camp.stream() if e["kind"] == "score"][0]
        camp.event(seq)["detail"]["arguments"]["action"] = "edited"
        self.assertEqual(camp.event(seq)["detail"]["arguments"]["action"],
                         "host_discovered")

    async def test_an_unknown_sequence_number_is_none(self):
        camp = await self._run([mock.text("done")])
        self.assertIsNone(camp.event(99999))

    async def test_every_tool_call_gets_a_line(self):
        # Previously only five tool names were special-cased, so the panel
        # could not open anything else.
        camp = await self._run([
            mock.calls(("get_score_context", {})),
            mock.text("done")])
        tools = [e["detail"].get("tool") for e in camp.stream()]
        self.assertIn("get_score_context", tools)


class TestTheStreamIsCapped(_Case):
    """A campaign runs for hours and every tool call emits an event."""

    async def test_sequence_numbers_stay_absolute_when_events_are_dropped(self):
        # The GUI holds `since` across polls, so a dropped event must not
        # make an old sequence number point at a new event.
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("done")]))
        await camp.start()
        await camp.wait()
        for i in range(orchestrator._STREAM_MAX + 50):
            camp._emit("info", "line %d" % i)
        events = camp.stream()
        self.assertLessEqual(len(events), orchestrator._STREAM_MAX)
        seqs = [e["seq"] for e in events]
        self.assertEqual(seqs, sorted(seqs))
        self.assertEqual(len(set(seqs)), len(seqs))
        self.assertGreater(seqs[0], 1, "the oldest events should have gone")

    async def test_stream_length_keeps_counting_past_the_cap(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("done")]))
        await camp.start()
        await camp.wait()
        before = camp.status()["stream_length"]
        for i in range(orchestrator._STREAM_MAX + 10):
            camp._emit("info", "line %d" % i)
        self.assertEqual(camp.status()["stream_length"],
                         before + orchestrator._STREAM_MAX + 10)

    async def test_since_past_the_cap_returns_nothing_rather_than_replaying(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("done")]))
        await camp.start()
        await camp.wait()
        for i in range(10):
            camp._emit("info", "line %d" % i)
        last = camp.status()["stream_length"]
        self.assertEqual(camp.stream(since=last), [])


class TestStatusCarriesWhatTheDrawerShows(_Case):
    """Scope, the detection budget and task counts were missing.

    The drawer had rows with nothing to put in them. All of it was already
    in the campaign's own configuration or in get_run_summary.
    """

    async def _status(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([
            mock.calls(("dispatch_task", {"task_name": "t",
                                          "task_description": "d"})),
            mock.text("done"), mock.text("TASK: t\nSTATUS: success")]))
        await camp.start()
        await camp.wait()
        return camp.status()

    async def test_the_scope_is_reported(self):
        scope = (await self._status())["scope"]
        self.assertEqual(scope["allow"], ["10.0.1.0/24"])
        self.assertIn("deny", scope)

    async def test_the_detection_budget_is_reported_with_its_limit(self):
        # A count alone does not say how close the run is to being stopped,
        # and this budget is a hard abort.
        budget = (await self._status())["budgets"]["detections"]
        self.assertIn("used", budget)
        self.assertEqual(budget["limit"], config.RISK_PROFILES["normal"]
                         ["detection_budget"])

    async def test_task_counts_are_reported(self):
        tasks = (await self._status())["tasks"]
        self.assertEqual(tasks["total"], 1)
        self.assertEqual(tasks["completed"], 1)
        self.assertEqual(tasks["failed"], 0)

    async def test_the_chosen_profiles_are_reported(self):
        status = await self._status()
        self.assertEqual(status["risk_profile"], "normal")
        self.assertEqual(status["opsec_profile"], "normal")
        self.assertEqual(status["phases"], [1, 2, 3, 4])


class TestTheTargetPlatformReachesTheModel(_Case):
    """The OS in the C2 record must reach both prompts.

    From a live run against a Darwin beacon: the model burned turns on
    `cat /proc/net/dev` and `cat /proc/sys/kernel/hostname`, a host with no
    /proc, because nothing had told it what it was standing on. The record
    the router already trusts for capabilities carries the OS, and
    `_attach_beacons` was dropping it.
    """

    def _c2(self, **fields):
        conn, c2 = _env()
        c2.agents["raccoon-fox"].update(fields)
        return conn, c2

    def _script(self):
        return _Script([
            mock.calls(("dispatch_task", {"task_name": "look",
                                          "task_description": "look around"})),
            mock.text("TASK: look\nSTATUS: success\nFINDINGS: none\n"
                      "ERRORS: none"),
            mock.text("done")])

    async def test_the_os_is_read_from_the_c2_record(self):
        conn, c2 = self._c2(os="Darwin 25.5.0")
        camp = _campaign(conn, c2, self._script())
        await camp.start()
        await camp.wait()
        self.assertEqual(camp._platforms, {"raccoon-fox": "Darwin 25.5.0"})

    async def test_the_orchestrator_is_told_the_platform(self):
        conn, c2 = self._c2(os="Darwin 25.5.0")
        client = self._script()
        camp = _campaign(conn, c2, client)
        await camp.start()
        await camp.wait()
        self.assertIn("Darwin 25.5.0", client.calls[0]["system"])

    async def test_the_executor_is_told_the_platform(self):
        conn, c2 = self._c2(os="Darwin 25.5.0")
        client = self._script()
        camp = _campaign(conn, c2, client)
        await camp.start()
        await camp.wait()
        # calls[0] is the orchestrator, calls[1] the executor it dispatched.
        self.assertIn("Darwin 25.5.0", client.calls[1]["system"])

    async def test_a_beacon_that_reports_no_os_leaves_it_open(self):
        conn, c2 = self._c2()
        c2.agents["raccoon-fox"].pop("os", None)
        client = self._script()
        camp = _campaign(conn, c2, client)
        await camp.start()
        await camp.wait()
        self.assertEqual(camp._platforms, {"raccoon-fox": ""})
        self.assertNotIn("Platform.", client.calls[1]["system"])
