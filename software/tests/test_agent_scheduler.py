#!/usr/bin/env python3
"""
Tests for the scheduler: cron arithmetic, the schedule table, polling with its
overlap guard, and the schedule endpoints.

Nothing here waits for a schedule to come due. A row is made due by moving its
`next_run` into the past with SQL, and the poll loop is given an interval of
zero. The campaigns that get started are real ones over a scripted model and
the orchestrator tests' FakeC2, so the guard is tested against what the
manager really reports and not against a stand-in for it.

The assertions that carry the most weight:

  * when both day-of-month and day-of-week are set, cron means OR: a schedule
    that fires on the wrong days starts a campaign outside the agreed window;
  * a schedule whose previous run is still going does not start a second one,
    and neither does one whose previous run is paused;
  * a schedule that fails, whatever way, is recorded against its own row and
    the others still run, so one bad row cannot silence the rest;
  * a bad cron expression is a 400 at POST /schedules, not a silence at 2 a.m.;
  * no secret reaches `config_json`;
  * nothing is left pending when a test ends. The base classes check before
    IsolatedAsyncioTestCase can quietly cancel a leaked task.
"""

import asyncio
import json
import sys
import unittest
import unittest.mock
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import IsolatedAsyncioTestCase

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent import config, orchestrator, scheduler, service
from software.agent.llm import mock
from software.agent.llm.provider import ProviderError
from software.agent.store import db, queries
from software.tests import test_agent_orchestrator as _orch
from software.tests import test_agent_service as _svc

# The scheduler imports notifications on first use, and that pulls in
# `requests`. On a Python built against LibreSSL, urllib3 warns when it is
# imported, and the suite runs with warnings as errors: import it once here,
# where the warning is expected, so the scheduler's own import finds it done.
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from software import notifications


# ── Builders ──


def _conn():
    return db.open_store(":memory:")


def _past(minutes=1):
    return queries._iso(datetime.now(timezone.utc) - timedelta(minutes=minutes))


def _make_due(conn, sid=None, minutes=1):
    if sid is None:
        conn.execute("UPDATE scheduled_tasks SET next_run = ?", (_past(minutes),))
    else:
        conn.execute("UPDATE scheduled_tasks SET next_run = ? WHERE id = ?",
                     (_past(minutes), sid))
    conn.commit()


def _cfg_json(**fields):
    """A stored campaign form, built the way POST /schedules builds it."""
    form = _svc._form(mode="auto", **fields)
    return json.dumps(scheduler.campaign_form(
        config.CampaignConfig.from_form(form, tier="reduced")))


def _row(conn, sid):
    return queries.get_schedule(conn, sid)


def _quick_client(_cfg):
    return mock.MockClient([mock.text("done")])


def _slow_client(_cfg):
    return _orch._SlowClient()


def _runs(conn):
    return conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]


def _utc(*parts):
    return datetime(*parts, tzinfo=timezone.utc)


# ── Cron ──


class TestCron(unittest.TestCase):
    def test_valid_five_field_expression_accepted(self):
        self.assertIsNone(scheduler.validate_cron("0 2 * * *"))

    def test_names_and_steps_and_ranges_are_accepted(self):
        for expr in ("*/5 * * * *", "0 9-17 * * mon-fri", "30 4 1,15 * *",
                     "0 0 1 jan *"):
            self.assertIsNone(scheduler.validate_cron(expr), expr)

    def test_invalid_expression_returns_a_reason(self):
        reason = scheduler.validate_cron("nicht cron")
        self.assertIsInstance(reason, str)
        self.assertIn("five fields", reason)

    def test_the_wrong_number_of_fields_is_refused(self):
        # croniter takes six and seven (seconds, years); a schedule that
        # runs every second is not something this service offers.
        for expr in ("", "* * * *", "* * * * * *", "@daily"):
            self.assertIsNotNone(scheduler.validate_cron(expr), repr(expr))

    def test_a_field_out_of_range_is_refused_with_a_reason(self):
        self.assertIn("60 * * * *", scheduler.validate_cron("60 * * * *"))
        self.assertIsNotNone(scheduler.validate_cron("* * * 13 *"))

    def test_an_expression_that_can_never_fire_is_refused(self):
        reason = scheduler.validate_cron("0 0 31 2 *")
        self.assertIn("never", reason)

    def test_a_randomised_expression_is_refused(self):
        # croniter would pick the minute at random on every parse: the
        # schedule would be a different one each time it was read.
        for expr in ("R * * * *", "0 R * * *", "H * * * *"):
            self.assertIsNotNone(scheduler.validate_cron(expr), expr)

    def test_something_that_is_not_text_is_refused(self):
        for expr in (None, 5, ["* * * * *"]):
            self.assertIsNotNone(scheduler.validate_cron(expr), repr(expr))

    def test_next_occurrence_is_in_the_future(self):
        nxt = scheduler.next_occurrence("*/5 * * * *")
        self.assertGreater(nxt, datetime.now(timezone.utc).isoformat())

    def test_next_occurrence_is_rfc3339_utc_like_every_other_timestamp(self):
        nxt = scheduler.next_occurrence("0 2 * * *", _utc(2026, 11, 2, 12, 0))
        self.assertEqual(nxt, "2026-11-03T02:00:00.000000+00:00")

    def test_next_occurrence_is_strictly_after_a_moment_that_is_a_slot(self):
        # Otherwise a schedule would be due again the instant it is advanced.
        nxt = scheduler.next_occurrence("0 2 * * *", _utc(2026, 11, 3, 2, 0))
        self.assertEqual(nxt, "2026-11-04T02:00:00.000000+00:00")

    def test_day_of_month_and_day_of_week_together_mean_or(self):
        # 13 December 2026 is a Sunday. Under OR the schedule fires on every
        # Friday and also on the 13th; under AND it would fire on neither of
        # these and wait for a Friday the 13th.
        moment, fired = _utc(2026, 12, 1, 0, 0), []
        for _ in range(5):
            moment = datetime.fromisoformat(
                scheduler.next_occurrence("0 0 13 * 5", moment))
            fired.append(moment.strftime("%Y-%m-%d %a"))
        self.assertEqual(fired, ["2026-12-04 Fri", "2026-12-11 Fri",
                                 "2026-12-13 Sun", "2026-12-18 Fri",
                                 "2026-12-25 Fri"])

    def test_with_only_one_of_the_two_set_the_other_does_not_widen_it(self):
        moment, fired = _utc(2026, 12, 1, 0, 0), []
        for _ in range(3):
            moment = datetime.fromisoformat(
                scheduler.next_occurrence("0 0 13 * *", moment))
            fired.append(moment.strftime("%Y-%m-%d"))
        self.assertEqual(fired, ["2026-12-13", "2027-01-13", "2027-02-13"])


class TestCampaignForm(unittest.TestCase):
    def _campaign(self, **fields):
        return config.CampaignConfig.from_form(_svc._form(**fields),
                                               tier="reduced")

    def test_the_stored_form_reads_back_as_the_same_campaign(self):
        original = self._campaign(mode="auto", phases=[1, 2],
                                  risk_profile="passive", scope_deny=["10.0.1.5"])
        stored = json.loads(json.dumps(scheduler.campaign_form(original)))
        self.assertEqual(
            config.CampaignConfig.from_form(stored, tier="reduced"), original)

    def test_settings_are_pinned_not_left_to_the_profile(self):
        # The profile's defaults can change between releases; what the
        # operator agreed to when they created the schedule must not.
        stored = scheduler.campaign_form(self._campaign(risk_profile="normal"))
        self.assertIn("ev_threshold", stored)
        self.assertIn("detection_budget", stored)

    def test_only_campaign_settings_are_stored(self):
        stored = scheduler.campaign_form(self._campaign())
        self.assertEqual(set(stored), {
            f for f in config.CampaignConfig.__dataclass_fields__})

    def test_no_agent_secret_can_be_in_it(self):
        agent = _svc._cfg()
        text = json.dumps(scheduler.campaign_form(self._campaign()))
        for secret in (agent.api_key, agent.c2_token, agent.agent_token):
            self.assertNotIn(secret, text)


# ── The table ──


class TestScheduleCrud(unittest.TestCase):
    def test_create_and_list(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "scan the dmz", "{}", "0 2 * * *")
        self.assertEqual([s["id"] for s in queries.list_schedules(conn)], [sid])

    def test_the_id_is_the_tables_integer(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "p", "{}", "0 2 * * *")
        self.assertIsInstance(sid, int)
        self.assertEqual(queries.get_schedule(conn, sid)["id"], sid)

    def test_a_new_schedule_starts_active_with_a_future_next_run(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "p", "{}", "0 2 * * *")
        row = _row(conn, sid)
        self.assertEqual(row["status"], "active")
        self.assertGreater(row["next_run"], queries._now())
        self.assertIsNone(row["last_run"])
        self.assertIsNone(row["running_run_id"])

    def test_an_expression_croniter_rejects_stores_nothing(self):
        conn = _conn()
        with self.assertRaises(ValueError):
            queries.create_schedule(conn, "p", "{}", "nicht cron")
        self.assertEqual(queries.list_schedules(conn), [])

    def test_an_unknown_id_is_none(self):
        self.assertIsNone(queries.get_schedule(_conn(), 99))

    def test_pause_excludes_from_due(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "p", "{}", "* * * * *")
        _make_due(conn)
        queries.pause_schedule(conn, sid)
        self.assertEqual(queries.get_due_schedules(conn), [])

    def test_an_active_schedule_that_is_due_is_listed_due(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "p", "{}", "* * * * *")
        _make_due(conn)
        self.assertEqual([s["id"] for s in queries.get_due_schedules(conn)],
                         [sid])

    def test_pause_and_resume_report_whether_they_applied(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "p", "{}", "0 2 * * *")
        self.assertFalse(queries.resume_schedule(conn, sid))
        self.assertTrue(queries.pause_schedule(conn, sid))
        self.assertFalse(queries.pause_schedule(conn, sid))
        self.assertTrue(queries.resume_schedule(conn, sid))
        self.assertFalse(queries.pause_schedule(conn, 99))
        self.assertFalse(queries.resume_schedule(conn, 99))

    def test_resume_recomputes_next_run(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "p", "{}", "0 2 * * *")
        queries.pause_schedule(conn, sid)
        queries.resume_schedule(conn, sid)
        s = queries.list_schedules(conn)[0]
        self.assertEqual(s["status"], "active")
        self.assertGreater(s["next_run"], datetime.now(timezone.utc).isoformat())

    def test_resume_does_not_make_a_long_paused_schedule_due(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "p", "{}", "0 2 * * *")
        queries.pause_schedule(conn, sid)
        _make_due(conn, minutes=60 * 24 * 7)
        queries.resume_schedule(conn, sid)
        self.assertEqual(queries.get_due_schedules(conn), [])

    def test_advance_moves_next_run_forward_and_stores_result(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "p", "{}", "*/5 * * * *")
        before = queries.list_schedules(conn)[0]["next_run"]
        queries.advance_schedule(conn, sid, "12 findings")
        after = queries.list_schedules(conn)[0]
        self.assertGreater(after["next_run"], before)
        self.assertEqual(after["last_result"], "12 findings")
        self.assertIsNotNone(after["last_run"])

    def test_advance_counts_from_now_so_a_missed_slot_is_not_queued(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "p", "{}", "*/5 * * * *")
        _make_due(conn, minutes=600)
        queries.advance_schedule(conn, sid, "x")
        self.assertGreater(_row(conn, sid)["next_run"], queries._now())

    def test_advance_for_a_passed_over_slot_leaves_last_run_alone(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "p", "{}", "*/5 * * * *")
        queries.advance_schedule(conn, sid, "x", ran=False)
        self.assertIsNone(_row(conn, sid)["last_run"])
        self.assertEqual(_row(conn, sid)["last_result"], "x")

    def test_advance_clips_a_long_result(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "p", "{}", "*/5 * * * *")
        queries.advance_schedule(conn, sid, "y" * 5000)
        self.assertEqual(len(_row(conn, sid)["last_result"]), 200)

    def test_advance_of_a_deleted_schedule_is_harmless(self):
        conn = _conn()
        queries.advance_schedule(conn, 99, "x")

    def test_delete(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "p", "{}", "0 2 * * *")
        self.assertTrue(queries.delete_schedule(conn, sid))
        self.assertFalse(queries.delete_schedule(conn, sid))
        self.assertEqual(queries.list_schedules(conn), [])

    def test_running_mark_is_set_and_cleared(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "p", "{}", "0 2 * * *")
        queries.set_schedule_running(conn, sid, 42)
        self.assertEqual(_row(conn, sid)["running_run_id"], 42)
        queries.set_schedule_running(conn, sid, None)
        self.assertIsNone(_row(conn, sid)["running_run_id"])

    def test_finish_only_applies_to_the_run_the_row_names(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "p", "{}", "0 2 * * *")
        queries.set_schedule_running(conn, sid, 42)
        self.assertFalse(queries.finish_schedule(conn, sid, 41, "late"))
        self.assertEqual(_row(conn, sid)["running_run_id"], 42)
        self.assertTrue(queries.finish_schedule(conn, sid, 42, "done"))
        self.assertIsNone(_row(conn, sid)["running_run_id"])
        self.assertEqual(_row(conn, sid)["last_result"], "done")
        self.assertFalse(queries.finish_schedule(conn, sid, 42, "again"))


# ── Polling ──


class _Case(IsolatedAsyncioTestCase):
    """A store, a C2, a real manager, and a look for leaked tasks."""

    client_factory = staticmethod(_quick_client)

    async def asyncSetUp(self):
        self.addCleanup(unittest.mock.patch.stopall)
        self.log = unittest.mock.patch.object(scheduler, "logger").start()
        unittest.mock.patch.object(orchestrator, "logger").start()
        self.conn = _conn()
        self.c2 = _orch.FakeC2()
        self.mgr = orchestrator.CampaignManager()
        self.cfg = _svc._cfg()

    async def asyncTearDown(self):
        await self.wind_down()
        me = asyncio.current_task()
        left = [t for t in asyncio.all_tasks() if t is not me and not t.done()]
        names = [repr(t.get_coro()) for t in left]
        for t in left:
            t.cancel()
        self.assertEqual(names, [], "tasks still pending at the end of the test")

    async def wind_down(self):
        for run_id in sorted(self.mgr.running_run_ids):
            campaign = self.mgr.get(run_id)
            if campaign is not None:
                campaign.stop()
                await campaign.wait()

    async def poll(self, cfg=None, factory=None):
        return await scheduler.poll_once(
            self.conn, self.mgr, cfg or self.cfg, c2=self.c2,
            client_factory=factory or self.client_factory)

    def schedule(self, expr="* * * * *", due=True, **fields):
        sid = queries.create_schedule(self.conn, "p", _cfg_json(**fields), expr)
        if due:
            _make_due(self.conn, sid)
        return sid

    def campaign_of(self, sid):
        return self.mgr.get(_row(self.conn, sid)["running_run_id"])


class TestPolling(_Case):
    async def test_due_schedule_starts_a_campaign(self):
        sid = self.schedule()
        self.assertEqual(await self.poll(), [sid])
        self.assertEqual(_runs(self.conn), 1)

    async def test_the_campaign_runs_with_the_stored_settings(self):
        sid = self.schedule(beacons=["raccoon-fox"], phases=[1, 2],
                            scope_allow=["10.9.8.0/24"])
        await self.poll()
        campaign = self.campaign_of(sid)
        self.assertEqual(campaign.config.scope_allow, ["10.9.8.0/24"])
        self.assertEqual(campaign.config.phases, {1, 2})
        self.assertEqual(campaign.config.mode, "auto")

    async def test_the_row_records_the_start(self):
        sid = self.schedule("*/5 * * * *")
        before = _row(self.conn, sid)["next_run"]
        await self.poll()
        row = _row(self.conn, sid)
        self.assertIsNotNone(self.mgr.get(row["running_run_id"]))
        self.assertIsNotNone(row["last_run"])
        self.assertIn("started run %d" % row["running_run_id"],
                      row["last_result"])
        self.assertGreater(row["next_run"], before)
        self.assertGreater(row["next_run"], queries._now())

    async def test_future_schedule_is_not_started(self):
        self.schedule("0 2 * * *", due=False)
        self.assertEqual(await self.poll(), [])
        self.assertEqual(_runs(self.conn), 0)

    async def test_a_paused_schedule_is_not_started(self):
        sid = self.schedule()
        queries.pause_schedule(self.conn, sid)
        self.assertEqual(await self.poll(), [])

    async def test_a_started_schedule_is_not_due_again_on_the_next_poll(self):
        self.schedule()
        await self.poll()
        self.assertEqual(await self.poll(), [])
        self.assertEqual(_runs(self.conn), 1)

    async def test_several_due_schedules_all_start(self):
        a = self.schedule(beacons=["raccoon-fox"])
        b = self.schedule(beacons=["raccoon-owl"])
        self.assertEqual(await self.poll(), [a, b])

    async def test_no_provider_is_recorded_not_raised(self):
        sid = self.schedule()
        started = await self.poll(cfg=_svc._cfg(provider=None))
        self.assertEqual(started, [])
        row = _row(self.conn, sid)
        self.assertIn("ERROR", row["last_result"])
        self.assertIn("not available", row["last_result"])
        self.assertGreater(row["next_run"], queries._now())
        self.assertEqual(_runs(self.conn), 0)


class TestOverlapGuard(_Case):
    async def test_overlap_guard_skips_a_still_running_schedule(self):
        sid = self.schedule()
        queries.set_schedule_running(self.conn, sid, 42)
        with unittest.mock.patch.object(
                orchestrator.CampaignManager, "running_run_ids",
                new_callable=unittest.mock.PropertyMock, return_value={42}):
            self.assertEqual(await self.poll(), [])
        self.assertEqual(_runs(self.conn), 0)

    async def test_a_skipped_slot_is_dropped_not_queued(self):
        sid = self.schedule("*/5 * * * *")
        queries.set_schedule_running(self.conn, sid, 42)
        with unittest.mock.patch.object(
                orchestrator.CampaignManager, "running_run_ids",
                new_callable=unittest.mock.PropertyMock, return_value={42}):
            await self.poll()
        row = _row(self.conn, sid)
        self.assertGreater(row["next_run"], queries._now())
        self.assertIn("SKIPPED", row["last_result"])
        self.assertIn("42", row["last_result"])
        self.assertIsNone(row["last_run"])
        self.assertEqual(row["running_run_id"], 42)

    async def test_overlap_guard_clears_when_the_run_has_finished(self):
        sid = self.schedule()
        queries.set_schedule_running(self.conn, sid, 42)
        with unittest.mock.patch.object(
                orchestrator.CampaignManager, "running_run_ids",
                new_callable=unittest.mock.PropertyMock, return_value=set()):
            self.assertEqual(await self.poll(), [sid])

    async def test_a_second_poll_does_not_start_a_second_run(self):
        sid = self.schedule()
        await self.poll(factory=_slow_client)
        _make_due(self.conn)
        self.assertEqual(await self.poll(factory=_slow_client), [])
        self.assertEqual(_runs(self.conn), 1)
        self.assertIn("SKIPPED", _row(self.conn, sid)["last_result"])
        self.assertIn("running", _row(self.conn, sid)["last_result"])

    async def test_it_starts_again_once_the_run_has_ended(self):
        sid = self.schedule()
        await self.poll()
        await self.campaign_of(sid).wait()
        _make_due(self.conn)
        self.assertEqual(await self.poll(), [sid])
        self.assertEqual(_runs(self.conn), 2)

    async def test_a_paused_previous_instance_blocks_a_new_one(self):
        # Paused is not ended: the operator means to resume it, its beacons'
        # polling intervals are still lowered, and a second campaign on them
        # would share the task queue.
        sid = self.schedule()
        await self.poll(factory=_slow_client)
        campaign = self.campaign_of(sid)
        campaign.pause()
        await campaign.wait()
        self.assertEqual(campaign.state, "paused")
        _make_due(self.conn)
        self.assertEqual(await self.poll(factory=_slow_client), [])
        self.assertEqual(_runs(self.conn), 1)
        row = _row(self.conn, sid)
        self.assertIn("paused", row["last_result"])
        self.assertEqual(row["running_run_id"], campaign.run_id)

    async def test_a_paused_run_is_not_settled_as_if_it_had_finished(self):
        sid = self.schedule()
        await self.poll(factory=_slow_client)
        campaign = self.campaign_of(sid)
        campaign.pause()
        await campaign.wait()
        with _fake_notifier() as sent:
            await self.poll()
        self.assertEqual(_row(self.conn, sid)["running_run_id"],
                         campaign.run_id)
        self.assertEqual(sent, [])

    async def test_it_starts_again_when_the_paused_run_is_stopped(self):
        sid = self.schedule()
        await self.poll(factory=_slow_client)
        campaign = self.campaign_of(sid)
        campaign.pause()
        await campaign.wait()
        campaign.stop()
        await campaign.wait()
        _make_due(self.conn)
        self.assertEqual(await self.poll(), [sid])
        self.assertEqual(_runs(self.conn), 2)

    async def test_a_manual_campaign_on_the_same_beacon_blocks_the_schedule(self):
        # The row's own running_run_id knows nothing of a campaign started
        # by hand. The beacons are what would be shared.
        manual = _orch._campaign(self.conn, self.c2, _orch._slow_client())
        await manual.start()
        self.mgr.add(manual)
        sid = self.schedule(beacons=["raccoon-fox"])
        self.assertEqual(await self.poll(), [])
        text = _row(self.conn, sid)["last_result"]
        self.assertIn("SKIPPED", text)
        self.assertIn("raccoon-fox", text)
        self.assertIn(str(manual.run_id), text)
        self.assertEqual(_runs(self.conn), 1)

    async def test_a_manual_campaign_on_another_beacon_does_not(self):
        manual = _orch._campaign(self.conn, self.c2, _orch._slow_client())
        await manual.start()
        self.mgr.add(manual)
        sid = self.schedule(beacons=["raccoon-owl"])
        self.assertEqual(await self.poll(), [sid])

    async def test_two_schedules_on_one_beacon_do_not_both_start(self):
        first = self.schedule(beacons=["raccoon-fox"])
        second = self.schedule(beacons=["raccoon-fox"])
        self.assertEqual(await self.poll(factory=_slow_client), [first])
        self.assertIn("SKIPPED", _row(self.conn, second)["last_result"])


class TestMisfire(_Case):
    async def test_a_slot_missed_by_hours_is_not_run_late(self):
        # The service was down over the slot. Running it now is running it
        # outside the window it was agreed for.
        sid = self.schedule("0 2 * * *", due=False)
        _make_due(self.conn, sid, minutes=180)
        self.assertEqual(await self.poll(), [])
        row = _row(self.conn, sid)
        self.assertIn("SKIPPED", row["last_result"])
        self.assertIn("missed", row["last_result"])
        self.assertGreater(row["next_run"], queries._now())
        self.assertIsNone(row["last_run"])
        self.assertEqual(_runs(self.conn), 0)

    async def test_a_slot_a_poll_late_still_runs(self):
        sid = self.schedule(due=False)
        _make_due(self.conn, sid, minutes=2)
        self.assertEqual(await self.poll(), [sid])


class TestOneFailureDoesNotStopTheOthers(_Case):
    async def test_a_failing_start_still_advances_next_run(self):
        def refuse(_cfg):
            raise ProviderError("the provider is down")

        sid = self.schedule("*/5 * * * *")
        before = _row(self.conn, sid)["next_run"]
        self.assertEqual(await self.poll(factory=refuse), [])
        after = _row(self.conn, sid)
        self.assertGreater(after["next_run"], before)
        self.assertIn("ERROR", after["last_result"])
        self.assertIn("the provider is down", after["last_result"])
        self.assertIsNone(after["running_run_id"])

    async def test_an_unexpected_exception_is_recorded_by_class_only(self):
        # Its message could be anything the layer below chose to put in it.
        def explode(_cfg):
            raise RuntimeError("https://c2.internal/?token=LEAK")

        sid = self.schedule()
        await self.poll(factory=explode)
        text = _row(self.conn, sid)["last_result"]
        self.assertIn("ERROR: RuntimeError", text)
        self.assertNotIn("LEAK", text)

    async def test_a_bad_config_json_is_recorded_and_the_next_schedule_runs(self):
        bad = queries.create_schedule(self.conn, "bad", "{not json", "* * * * *")
        good = self.schedule(beacons=["raccoon-owl"])
        _make_due(self.conn, bad)
        self.assertEqual(await self.poll(), [good])
        self.assertIn("ERROR", _row(self.conn, bad)["last_result"])
        self.assertGreater(_row(self.conn, bad)["next_run"], queries._now())

    async def test_a_form_the_tier_refuses_is_recorded(self):
        sid = queries.create_schedule(
            self.conn, "p", json.dumps({"beacons": [], "scope_allow": []}),
            "* * * * *")
        _make_due(self.conn, sid)
        self.assertEqual(await self.poll(), [])
        self.assertIn("ERROR", _row(self.conn, sid)["last_result"])
        self.assertIn("beacons", _row(self.conn, sid)["last_result"])

    async def test_a_config_that_is_not_an_object_is_recorded(self):
        sid = queries.create_schedule(self.conn, "p", "[1, 2]", "* * * * *")
        _make_due(self.conn, sid)
        self.assertEqual(await self.poll(), [])
        self.assertIn("ERROR", _row(self.conn, sid)["last_result"])

    async def test_the_first_failing_does_not_skip_the_second(self):
        calls = []

        def factory(cfg):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("only the first")
            return mock.MockClient([mock.text("done")])

        first = self.schedule(beacons=["raccoon-fox"])
        second = self.schedule(beacons=["raccoon-owl"])
        self.assertEqual(await self.poll(factory=factory), [second])
        self.assertIn("ERROR", _row(self.conn, first)["last_result"])
        self.assertIn("started", _row(self.conn, second)["last_result"])

    async def test_a_failure_nothing_anticipated_does_not_skip_the_rest(self):
        # The per-schedule handler covers what starting can raise. This is
        # for the rest: the store failing on one row, say.
        self.schedule(beacons=["raccoon-fox"])
        second = self.schedule(beacons=["raccoon-owl"])
        real = scheduler._fire
        calls = []

        async def flaky(*args, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("the store")
            return await real(*args, **kwargs)

        with unittest.mock.patch.object(scheduler, "_fire", flaky):
            self.assertEqual(await self.poll(), [second])
        self.log.warning.assert_called()
        self.assertIn("RuntimeError", str(self.log.warning.call_args))
        self.assertEqual(len(calls), 2)

    async def test_a_failing_settle_does_not_stop_the_due_schedules(self):
        done = self.schedule(beacons=["raccoon-fox"])
        await self.poll()
        await self.campaign_of(done).wait()
        due = self.schedule(beacons=["raccoon-owl"])
        with unittest.mock.patch.object(
                scheduler, "_describe_run", side_effect=RuntimeError("x")):
            self.assertEqual(await self.poll(), [due])


class TestSettling(_Case):
    async def _finished(self):
        sid = self.schedule()
        await self.poll()
        run_id = _row(self.conn, sid)["running_run_id"]
        await self.mgr.get(run_id).wait()
        return sid, run_id

    async def test_a_finished_run_clears_the_mark_and_records_how_it_ended(self):
        sid, run_id = await self._finished()
        await self.poll()
        row = _row(self.conn, sid)
        self.assertIsNone(row["running_run_id"])
        self.assertIn("run %d completed" % run_id, row["last_result"])

    async def test_a_run_that_is_still_going_keeps_the_mark(self):
        sid = self.schedule()
        await self.poll(factory=_slow_client)
        await self.poll()
        self.assertIsNotNone(_row(self.conn, sid)["running_run_id"])

    async def test_a_run_the_process_lost_is_settled_by_what_the_store_says(self):
        # The service restarted: restore_orphans marked the run failed, and
        # the manager has never heard of it.
        sid = self.schedule(due=False)
        run_id = queries.create_run(self.conn, "campaign", None, "auto", "{}")
        queries.set_run_status(self.conn, run_id, "failed")
        queries.set_schedule_running(self.conn, sid, run_id)
        await self.poll()
        row = _row(self.conn, sid)
        self.assertIsNone(row["running_run_id"])
        self.assertIn("failed", row["last_result"])

    async def test_a_run_with_no_record_is_settled_too(self):
        sid = self.schedule(due=False)
        queries.set_schedule_running(self.conn, sid, 4242)
        await self.poll()
        self.assertIsNone(_row(self.conn, sid)["running_run_id"])
        self.assertIn("4242", _row(self.conn, sid)["last_result"])

    async def test_completed_schedule_pushes_a_notification(self):
        sid, run_id = await self._finished()
        with _fake_notifier() as sent:
            await self.poll()
        self.assertEqual(len(sent), 1)
        event, text, details = sent[0]
        self.assertEqual(event, "schedule")
        self.assertIn("completed", text)
        self.assertEqual(details["schedule"], sid)
        self.assertEqual(details["run"], run_id)

    async def test_it_is_told_once(self):
        await self._finished()
        with _fake_notifier() as sent:
            await self.poll()
            await self.poll()
        self.assertEqual(len(sent), 1)

    async def test_missing_notifier_is_not_an_error(self):
        sid, _ = await self._finished()
        with _no_notifier():
            await self.poll()
        self.assertIsNone(_row(self.conn, sid)["running_run_id"])

    async def test_a_notifier_that_raises_does_not_unsettle_the_row(self):
        sid, _ = await self._finished()
        with _fake_notifier(raises=RuntimeError("webhook down")):
            await self.poll()
        self.assertIsNone(_row(self.conn, sid)["running_run_id"])

    async def test_a_deleted_schedule_is_not_settled_into_nothing(self):
        sid, _ = await self._finished()
        queries.delete_schedule(self.conn, sid)
        with _fake_notifier() as sent:
            await self.poll()
        self.assertEqual(sent, [])


# ── The loop ──


class TestLoop(_Case):
    async def _stop(self, task):
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def test_it_returns_a_task_that_polls_repeatedly(self):
        seen, enough = [], asyncio.Event()

        async def fake(conn, manager, cfg, **kwargs):
            seen.append((conn, manager, cfg, kwargs))
            if len(seen) == 3:
                enough.set()
            return []

        with unittest.mock.patch.object(scheduler, "poll_once", fake):
            task = scheduler.start_loop(self.conn, self.mgr, self.cfg,
                                        c2=self.c2, interval=0)
            self.assertIsInstance(task, asyncio.Task)
            await asyncio.wait_for(enough.wait(), 5)
            await self._stop(task)
        conn, manager, cfg, kwargs = seen[0]
        self.assertIs(conn, self.conn)
        self.assertIs(manager, self.mgr)
        self.assertIs(cfg, self.cfg)
        self.assertIs(kwargs["c2"], self.c2)

    async def test_a_poll_that_raises_does_not_end_the_loop(self):
        calls, enough = [], asyncio.Event()

        async def fake(conn, manager, cfg, **kwargs):
            calls.append(1)
            if len(calls) < 3:
                raise RuntimeError("the store went away")
            enough.set()
            return []

        with unittest.mock.patch.object(scheduler, "poll_once", fake):
            task = scheduler.start_loop(self.conn, self.mgr, self.cfg,
                                        c2=self.c2, interval=0)
            await asyncio.wait_for(enough.wait(), 5)
            self.assertFalse(task.done())
            await self._stop(task)
        self.log.warning.assert_called()
        self.assertIn("RuntimeError", str(self.log.warning.call_args))

    async def test_cancelling_it_ends_it_cleanly(self):
        started = asyncio.Event()

        async def fake(conn, manager, cfg, **kwargs):
            started.set()
            return []

        with unittest.mock.patch.object(scheduler, "poll_once", fake):
            task = scheduler.start_loop(self.conn, self.mgr, self.cfg,
                                        c2=self.c2, interval=3600)
            await asyncio.wait_for(started.wait(), 5)
            await self._stop(task)
        self.assertTrue(task.cancelled())

    async def test_a_real_poll_through_the_loop_starts_a_due_schedule(self):
        sid = self.schedule()
        task = scheduler.start_loop(self.conn, self.mgr, self.cfg, c2=self.c2,
                                    client_factory=_quick_client, interval=0)
        try:
            while _row(self.conn, sid)["running_run_id"] is None:
                await asyncio.sleep(0)
            await self.campaign_of(sid).wait()
        finally:
            await self._stop(task)
        self.assertEqual(_runs(self.conn), 1)


# ── Notifier doubles ──


class _fake_notifier:
    """get_notifier() returns an object that records notify() calls."""

    def __init__(self, raises=None):
        self.sent = []
        self._raises = raises

    def _notify(self, event, text, **details):
        if self._raises is not None:
            raise self._raises
        self.sent.append((event, text, details))

    def __enter__(self):
        notifier = unittest.mock.Mock()
        notifier.notify.side_effect = self._notify
        self._patch = unittest.mock.patch.object(
            notifications, "get_notifier", return_value=notifier)
        self._patch.start()
        return self.sent

    def __exit__(self, *exc):
        self._patch.stop()


def _no_notifier():
    return unittest.mock.patch.object(
        notifications, "get_notifier", return_value=None)


# ── Endpoints ──


def _body(**over):
    body = {"schedule": "0 2 * * *", "prompt": "scan the dmz",
            "campaign": _svc._form(mode="auto")}
    body.update(over)
    return body


class _ScheduleCase(_svc._ServiceCase):
    async def get_application(self):
        self.rig = _svc._rig(client=mock.MockClient([mock.text("done")]))
        return self.rig.app

    async def create(self, **over):
        resp = await self.post("/schedules", _body(**over))
        self.assertEqual(resp.status, 200, await resp.text())
        return (await resp.json())["id"]

    def stored(self):
        return queries.list_schedules(self.rig.conn)


class TestScheduleEndpoints(_ScheduleCase):
    async def test_create_returns_the_id_and_the_first_run(self):
        body = await (await self.post("/schedules", _body())).json()
        self.assertIsInstance(body["id"], int)
        self.assertGreater(body["next_run"], queries._now())

    async def test_list_shows_what_was_stored(self):
        sid = await self.create()
        body = await (await self.get("/schedules")).json()
        [entry] = body["schedules"]
        self.assertEqual(entry["id"], sid)
        self.assertEqual(entry["prompt"], "scan the dmz")
        self.assertEqual(entry["schedule"], "0 2 * * *")
        self.assertEqual(entry["status"], "active")
        self.assertEqual(entry["campaign"]["beacons"], ["raccoon-fox"])
        self.assertIsNone(entry["running_run_id"])

    async def test_an_empty_list_is_an_empty_list(self):
        self.assertEqual(
            await (await self.get("/schedules")).json(), {"schedules": []})

    async def test_the_expression_is_stored_with_its_spacing_tidied(self):
        await self.create(schedule="  0   2 * * *\n")
        self.assertEqual(self.stored()[0]["schedule"], "0 2 * * *")

    async def test_a_bad_cron_expression_is_a_400_that_names_the_problem(self):
        resp = await self.post("/schedules", _body(schedule="nicht cron"))
        self.assertEqual(resp.status, 400)
        self.assertIn("five fields", (await resp.json())["error"])
        self.assertEqual(self.stored(), [])

    async def test_an_expression_that_never_fires_is_a_400(self):
        resp = await self.post("/schedules", _body(schedule="0 0 31 2 *"))
        self.assertEqual(resp.status, 400)
        self.assertIn("never", (await resp.json())["error"])

    async def test_a_missing_expression_is_a_400(self):
        body = _body()
        del body["schedule"]
        self.assertEqual((await self.post("/schedules", body)).status, 400)

    async def test_a_bad_campaign_form_is_a_400_and_stores_nothing(self):
        resp = await self.post("/schedules", _body(
            campaign=_svc._form(scope_allow=[])))
        self.assertEqual(resp.status, 400)
        self.assertIn("scope_allow", (await resp.json())["error"])
        self.assertEqual(self.stored(), [])

    async def test_a_missing_campaign_form_is_a_400(self):
        body = _body()
        del body["campaign"]
        self.assertEqual((await self.post("/schedules", body)).status, 400)

    async def test_a_missing_or_blank_prompt_is_a_400(self):
        for prompt in (None, "", "   ", 5):
            resp = await self.post("/schedules", _body(prompt=prompt))
            self.assertEqual(resp.status, 400, repr(prompt))

    async def test_a_body_that_is_not_json_is_a_400(self):
        resp = await self.client.post("/schedules", data=b"{not json",
                                      headers=_svc._H)
        self.assertEqual(resp.status, 400)

    async def test_a_body_that_is_not_an_object_is_a_400(self):
        self.assertEqual((await self.post("/schedules", [1, 2])).status, 400)

    async def test_the_form_is_checked_against_the_agents_tier(self):
        # reduced allows up to phase 4; a form that asks only for 5 has
        # nothing left, and that is refused now rather than at 2 a.m.
        resp = await self.post("/schedules", _body(
            campaign=_svc._form(phases=[5])))
        self.assertEqual(resp.status, 400)

    async def test_nothing_but_campaign_settings_is_stored(self):
        smuggled = "ZZ-smuggled-in-the-form"
        form = _svc._form(api_key=smuggled, agent_token=smuggled,
                          c2_token=smuggled, password=smuggled)
        await self.create(campaign=form)
        raw = self.stored()[0]["config_json"]
        self.assertNotIn(smuggled, raw)
        self.assertLessEqual(
            set(json.loads(raw)), set(config.CampaignConfig.__dataclass_fields__))
        for secret in _svc._SECRETS:
            self.assertNotIn(secret, raw)

    async def test_no_response_carries_a_secret(self):
        await self.create()
        text = await (await self.get("/schedules")).text()
        for secret in _svc._SECRETS:
            self.assertNotIn(secret, text)

    async def test_pause_then_resume(self):
        sid = await self.create()
        resp = await self.post("/schedules/%d/pause" % sid)
        self.assertEqual(resp.status, 200)
        self.assertEqual((await resp.json())["status"], "paused")
        self.assertEqual(self.stored()[0]["status"], "paused")
        resp = await self.post("/schedules/%d/resume" % sid)
        self.assertEqual(resp.status, 200)
        body = await resp.json()
        self.assertEqual(body["status"], "active")
        self.assertGreater(body["next_run"], queries._now())

    async def test_pause_of_a_paused_schedule_is_a_409(self):
        sid = await self.create()
        await self.post("/schedules/%d/pause" % sid)
        resp = await self.post("/schedules/%d/pause" % sid)
        self.assertEqual(resp.status, 409)
        self.assertIn("paused", (await resp.json())["error"])

    async def test_resume_of_an_active_schedule_is_a_409(self):
        sid = await self.create()
        resp = await self.post("/schedules/%d/resume" % sid)
        self.assertEqual(resp.status, 409)
        self.assertIn("active", (await resp.json())["error"])

    async def test_delete(self):
        sid = await self.create()
        resp = await self.client.delete("/schedules/%d" % sid, headers=_svc._H)
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.stored(), [])

    async def test_unknown_schedules_are_404(self):
        for method, path in (("delete", "/schedules/99"),
                             ("post", "/schedules/99/pause"),
                             ("post", "/schedules/99/resume")):
            resp = await getattr(self.client, method)(path, headers=_svc._H)
            self.assertEqual(resp.status, 404, path)

    async def test_an_id_that_is_not_a_number_is_404(self):
        resp = await self.client.delete("/schedules/abc", headers=_svc._H)
        self.assertEqual(resp.status, 404)


class TestSchedulesAreBehindTheMiddleware(_ScheduleCase):
    async def test_no_token_is_a_401(self):
        self.assertEqual((await self.client.get("/schedules")).status, 401)
        resp = await self.client.post("/schedules", json=_body())
        self.assertEqual(resp.status, 401)
        self.assertEqual(self.stored(), [])

    async def test_a_browser_is_refused_on_every_verb(self):
        sid = await self.create()
        headers = dict(_svc._H, Origin="http://evil.example")
        for method, path in (("get", "/schedules"), ("post", "/schedules"),
                             ("delete", "/schedules/%d" % sid),
                             ("post", "/schedules/%d/pause" % sid)):
            resp = await getattr(self.client, method)(path, headers=headers)
            self.assertEqual(resp.status, 403, (method, path))
        self.assertEqual(self.stored()[0]["status"], "active")

    async def test_a_form_shaped_post_is_refused(self):
        resp = await self.client.post(
            "/schedules", data={"schedule": "* * * * *"}, headers=_svc._H)
        self.assertEqual(resp.status, 415)
        self.assertEqual(self.stored(), [])


class TestTheServiceRunsTheLoop(IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        self.assertEqual(await _svc._pending_tasks(), [])

    async def test_startup_starts_it_and_cleanup_ends_it(self):
        rig = _svc._rig()
        seen, ran = [], asyncio.Event()

        async def fake(conn, manager, cfg, **kwargs):
            seen.append((conn, manager, cfg, kwargs))
            ran.set()
            return []

        rig.app.freeze()
        with unittest.mock.patch.object(service.scheduler, "poll_once", fake):
            await rig.app.startup()
            try:
                await asyncio.wait_for(ran.wait(), 5)
            finally:
                await rig.app.cleanup()
        conn, manager, cfg, kwargs = seen[0]
        self.assertIs(conn, rig.conn)
        self.assertIs(manager, rig.manager)
        self.assertIs(cfg, rig.cfg)
        self.assertIs(kwargs["c2"], rig.c2)
        self.assertIn("client_factory", kwargs)

    async def test_orphans_are_recovered_before_the_first_poll(self):
        rig = _svc._rig()
        order = []

        async def recover(*args):
            order.append("recover")
            return []

        async def poll(*args, **kwargs):
            order.append("poll")
            return []

        rig.app.freeze()
        with unittest.mock.patch.object(service, "restore_orphans", recover), \
                unittest.mock.patch.object(service.scheduler, "poll_once", poll):
            await rig.app.startup()
            try:
                while "poll" not in order:
                    await asyncio.sleep(0)
            finally:
                await rig.app.cleanup()
        self.assertEqual(order[:2], ["recover", "poll"])

    async def test_cleanup_without_a_startup_is_harmless(self):
        rig = _svc._rig()
        rig.app.freeze()
        await rig.app.cleanup()


# ── POST /campaign: the same beacon is not shared ──


class TestCampaignOverlap(_svc._ServiceCase):
    async def get_application(self):
        self.rig = _svc._rig(client=_svc._slow_client())
        self.rig.c2.agents["raccoon-owl"] = {
            "id": "raccoon-owl", "status": "online", "caps": ["batch"],
            "uplink_iface": "eth0"}
        return self.rig.app

    async def test_a_second_campaign_on_the_same_beacon_is_a_409(self):
        first = await self.start_campaign()
        resp = await self.post("/campaign", _svc._form())
        self.assertEqual(resp.status, 409)
        body = await resp.json()
        self.assertIn("raccoon-fox", body["error"])
        self.assertEqual(body["run_id"], first)

    async def test_the_refusal_leaves_no_run_behind(self):
        await self.start_campaign()
        await self.post("/campaign", _svc._form())
        self.assertEqual(len(queries.list_unfinished_runs(self.rig.conn)), 1)

    async def test_a_campaign_on_another_beacon_is_fine(self):
        await self.start_campaign()
        resp = await self.post("/campaign", _svc._form(beacons=["raccoon-owl"]))
        self.assertEqual(resp.status, 200)

    async def test_one_shared_beacon_among_several_is_enough(self):
        await self.start_campaign(beacons=["raccoon-fox"])
        resp = await self.post("/campaign", _svc._form(
            beacons=["raccoon-owl", "raccoon-fox"]))
        self.assertEqual(resp.status, 409)

    async def test_a_paused_campaign_still_holds_its_beacons(self):
        first = await self.start_campaign()
        await self.post("/campaign/%d/pause" % first)

        async def paused():
            return (await self.campaign_states()).get(first) == "paused"

        await _svc._until(paused, "the campaign to pause")
        resp = await self.post("/campaign", _svc._form())
        self.assertEqual(resp.status, 409)

    async def test_the_beacons_are_free_again_when_the_campaign_ends(self):
        first = await self.start_campaign()
        await self.post("/campaign/%d/stop" % first)

        async def ended():
            return first not in await self.campaign_states()

        await _svc._until(ended, "the campaign to end")
        await self.start_campaign()

    async def test_a_bad_form_is_a_400_even_when_the_beacon_is_busy(self):
        await self.start_campaign()
        resp = await self.post("/campaign", _svc._form(scope_allow=[]))
        self.assertEqual(resp.status, 400)


if __name__ == "__main__":
    unittest.main()
