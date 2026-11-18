#!/usr/bin/env python3
"""Tests for the operator shell's server-side logic.

The feature's anti-goal is a channel left open on the target device while
the operator believes it closed. The claim tests below are about exactly
that: every way the bookkeeping could forget a stop it owes.
"""

import ast
import json
import os
import stat
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.c2 import opshell


class _ClaimsCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "opshell-owned.json"


class TestTheClaimCounts(_ClaimsCase):
    def test_the_last_session_out_is_the_one_that_closes(self):
        c = opshell.Claims(self.path)
        a, b = c.open("raccoon-bandit"), c.open("raccoon-bandit")
        self.assertFalse(c.close("raccoon-bandit", a))
        self.assertTrue(c.close("raccoon-bandit", b))

    def test_a_second_browser_does_not_lose_the_first_ones_channel(self):
        # Review Focus 3. One bearer token, two views: the refcount is the
        # only thing standing between `exit` in one tab and a dead session
        # in the other.
        c = opshell.Claims(self.path)
        first = c.open("raccoon-bandit")
        c.open("raccoon-bandit")
        c.close("raccoon-bandit", first)
        self.assertEqual(c.sessions("raccoon-bandit"), 1)

    def test_a_silent_browser_lapses_and_a_beating_one_does_not(self):
        # The beat is made part-way through the grace, with the clock
        # pinned: a beat made "now" and a check made "now + 11" would
        # leave both sessions equally stale.
        c = opshell.Claims(self.path, grace=10.0)
        with unittest.mock.patch.object(opshell.time, "time", return_value=1000.0):
            c.open("quiet-one")
            alive = c.open("alive-one")
        with unittest.mock.patch.object(opshell.time, "time", return_value=1008.0):
            c.beat("alive-one", alive)
        self.assertEqual(c.lapsed(now=1011.0), ["quiet-one"])
        self.assertEqual(c.sessions("alive-one"), 1)

    def test_a_session_exactly_at_the_grace_has_not_lapsed(self):
        c = opshell.Claims(self.path, grace=10.0)
        with unittest.mock.patch.object(opshell.time, "time", return_value=1000.0):
            c.open("raccoon-bandit")
        self.assertEqual(c.lapsed(now=1010.0), [])
        self.assertEqual(c.lapsed(now=1010.5), ["raccoon-bandit"])

    def test_a_stale_session_beside_a_live_one_is_not_left_in_the_count(self):
        # A browser that died while another tab stays open. If the ghost
        # stayed in the count, the live tab's `exit` would answer "not the
        # last", no stop would be queued, and the channel would stand.
        c = opshell.Claims(self.path, grace=10.0)
        with unittest.mock.patch.object(opshell.time, "time", return_value=1000.0):
            c.open("raccoon-bandit")
            live = c.open("raccoon-bandit")
        with unittest.mock.patch.object(opshell.time, "time", return_value=1008.0):
            c.beat("raccoon-bandit", live)
        self.assertEqual(c.lapsed(now=1012.0), [])
        self.assertEqual(c.sessions("raccoon-bandit"), 1)
        self.assertTrue(c.close("raccoon-bandit", live))

    def test_a_lapsed_claim_is_reported_once_and_not_revived_by_a_late_beat(self):
        c = opshell.Claims(self.path, grace=10.0)
        with unittest.mock.patch.object(opshell.time, "time", return_value=1000.0):
            sid = c.open("raccoon-bandit")
        self.assertEqual(c.lapsed(now=1020.0), ["raccoon-bandit"])
        self.assertEqual(c.lapsed(now=1021.0), [])
        c.beat("raccoon-bandit", sid)
        self.assertEqual(c.sessions("raccoon-bandit"), 0)
        self.assertFalse(c.close("raccoon-bandit", sid))

    def test_closing_a_session_that_is_not_held_is_not_a_last_close(self):
        c = opshell.Claims(self.path)
        c.open("raccoon-bandit")
        self.assertFalse(c.close("raccoon-bandit", "not-a-session"))
        self.assertFalse(c.close("never-opened", "x"))
        self.assertEqual(c.sessions("raccoon-bandit"), 1)


class TestOwnershipIsPersisted(_ClaimsCase):
    def test_ownership_survives_a_restart_and_reconciles(self):
        # The anti-goal: a restart between start and stop must not leave a
        # channel with nobody to close it.
        opshell.Claims(self.path).open("raccoon-bandit")
        fresh = opshell.Claims(self.path)          # a new process
        self.assertEqual(fresh.owned(), ["raccoon-bandit"])
        self.assertEqual(opshell.reconcile(fresh, ["raccoon-bandit"]),
                         ["raccoon-bandit"])

    def test_an_agent_that_vanished_is_forgotten_not_reported_closed(self):
        # Review Focus 1. No agent, no task, no honest claim of closure.
        c = opshell.Claims(self.path)
        c.open("gone-raccoon")
        self.assertEqual(opshell.reconcile(c, []), [])
        self.assertEqual(c.owned(), [])
        self.assertEqual(opshell.Claims(self.path).owned(), [])

    def test_closing_the_last_session_keeps_ownership_until_the_stop_is_seen(self):
        # Closing only queues the stop. If ownership went with the last
        # session, a restart before the beacon's next check-in would find
        # nothing owed and the stop would never be re-queued.
        c = opshell.Claims(self.path)
        sid = c.open("raccoon-bandit")
        self.assertTrue(c.close("raccoon-bandit", sid))
        fresh = opshell.Claims(self.path)
        self.assertEqual(opshell.reconcile(fresh, ["raccoon-bandit"]),
                         ["raccoon-bandit"])
        self.assertTrue(fresh.release("raccoon-bandit"))
        self.assertEqual(opshell.Claims(self.path).owned(), [])

    def test_release_after_the_stop_is_seen_drops_ownership(self):
        c = opshell.Claims(self.path)
        sid = c.open("raccoon-bandit")
        c.close("raccoon-bandit", sid)
        self.assertTrue(c.release("raccoon-bandit"))
        self.assertEqual(c.owned(), [])
        self.assertEqual(opshell.Claims(self.path).owned(), [])

    def test_a_view_opened_after_the_stop_keeps_its_claim_through_the_release(self):
        # The start-after-stop race. The last view closes (stop queued),
        # another opens (start queued after it), then the stop is
        # acknowledged. Releasing ownership there would leave a channel
        # open with no owner and no pending stop: the live view's `exit`
        # would answer "not the last" and a restart would reconcile to
        # nothing.
        c = opshell.Claims(self.path)
        old = c.open("raccoon-bandit")
        self.assertTrue(c.close("raccoon-bandit", old))
        new = c.open("raccoon-bandit")
        self.assertFalse(c.release("raccoon-bandit"))
        self.assertEqual(c.sessions("raccoon-bandit"), 1)
        self.assertEqual(c.owned(), ["raccoon-bandit"])
        self.assertEqual(opshell.Claims(self.path).owned(), ["raccoon-bandit"])
        self.assertTrue(c.close("raccoon-bandit", new))

    def test_releasing_a_channel_that_is_not_owned_is_not_a_release(self):
        c = opshell.Claims(self.path)
        self.assertFalse(c.release("never-opened"))

    def test_forget_is_for_an_agent_that_is_gone_and_takes_its_claims_with_it(self):
        c = opshell.Claims(self.path)
        c.open("gone-raccoon")
        c.forget("gone-raccoon")
        self.assertEqual(c.sessions("gone-raccoon"), 0)
        self.assertEqual(c.owned(), [])

    def test_a_live_claim_is_not_owed_a_stop(self):
        c = opshell.Claims(self.path)
        c.open("raccoon-bandit")
        self.assertEqual(opshell.reconcile(c, ["raccoon-bandit"]), [])
        self.assertEqual(c.owned(), ["raccoon-bandit"])

    def test_a_channel_this_view_did_not_start_is_not_owned(self):
        c = opshell.Claims(self.path)
        c.open("raccoon-bandit")
        self.assertEqual(opshell.reconcile(c, ["raccoon-bandit", "other-one"]), [])
        self.assertEqual(c.owned(), ["raccoon-bandit"])

    def test_the_record_is_private_and_says_only_whose_channel_it_is(self):
        opshell.Claims(self.path).open("raccoon-bandit")
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        record = json.loads(self.path.read_text())
        self.assertEqual(list(record), ["raccoon-bandit"])
        self.assertEqual(list(record["raccoon-bandit"]), ["since"])

    def test_the_record_stays_private_when_rewritten_under_a_loose_umask(self):
        c = opshell.Claims(self.path)
        c.open("one")
        old = os.umask(0)
        try:
            c.open("two")
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_opening_again_does_not_move_the_ownership_date(self):
        c = opshell.Claims(self.path)
        c.open("raccoon-bandit")
        first = json.loads(self.path.read_text())["raccoon-bandit"]["since"]
        with unittest.mock.patch.object(opshell, "_now_iso", return_value="2999-01-01T00:00:00+00:00"):
            c.open("raccoon-bandit")
        self.assertEqual(json.loads(self.path.read_text())["raccoon-bandit"]["since"], first)

    def test_a_claim_is_not_taken_when_the_record_cannot_be_written(self):
        # Starting a channel on the strength of a record that was never
        # saved is the anti-goal with a delay.
        c = opshell.Claims(self.path)
        with unittest.mock.patch.object(opshell.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                c.open("raccoon-bandit")
        self.assertEqual(c.sessions("raccoon-bandit"), 0)
        self.assertEqual(c.owned(), [])
        self.assertEqual([p.name for p in self.path.parent.iterdir()], [])

    def test_a_damaged_record_is_an_error_not_an_empty_fleet(self):
        # Treating a damaged file as "owns nothing" would drop every stop
        # that was owed without anyone being told.
        self.path.write_text("{not json")
        with self.assertRaises(opshell.OwnershipRecordError) as raised:
            opshell.Claims(self.path)
        self.assertIn(str(self.path), str(raised.exception))
        self.assertEqual(raised.exception.path, self.path)

    def test_a_record_that_is_not_an_object_is_the_same_error(self):
        self.path.write_text("[]")
        with self.assertRaises(opshell.OwnershipRecordError) as raised:
            opshell.Claims(self.path)
        self.assertIn(str(self.path), str(raised.exception))

    def test_a_record_that_cannot_be_read_is_the_same_error(self):
        # One `except` for the caller: damaged and unreadable both mean
        # "do not guess what was owned".
        self.path.write_text("{}")
        with unittest.mock.patch.object(Path, "read_text", side_effect=PermissionError("denied")):
            with self.assertRaises(opshell.OwnershipRecordError) as raised:
                opshell.Claims(self.path)
        self.assertIn(str(self.path), str(raised.exception))

    def test_the_record_error_is_a_value_error(self):
        self.assertTrue(issubclass(opshell.OwnershipRecordError, ValueError))


def _route_dict_keys():
    """Key sets of the dict literals `api_create_task` builds in server.py.

    Returns (task_keys, history_keys) read from the source, so a test can
    hold `queue_tunnel` to the route's shape without importing the server.
    """
    source = (Path(__file__).parent.parent / "c2" / "server.py").read_text()
    route = next(n for n in ast.walk(ast.parse(source))
                 if isinstance(n, ast.FunctionDef) and n.name == "api_create_task")
    task_keys = history_keys = None
    for node in ast.walk(route):
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict)
                and [t.id for t in node.targets if isinstance(t, ast.Name)] == ["task"]):
            task_keys = [k.value for k in node.value.keys]
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "append" and node.args
                and isinstance(node.args[0], ast.Dict)):
            history_keys = [k.value for k in node.args[0].keys]
    return task_keys, history_keys


class TestRaisingAndDroppingTheChannel(unittest.TestCase):
    def test_start_is_queued_as_an_operator_lane_tunnel_task(self):
        queues, hist = {}, {}
        task = opshell.queue_tunnel("raccoon-bandit", "start", queues, hist, "now")
        self.assertEqual((task["cmd"], task["args"], task["lane"]),
                         ("tunnel", "start", "operator"))
        self.assertEqual(queues["raccoon-bandit"], [task])

    def test_a_live_socks_session_forbids_the_stop(self):
        ok, why = opshell.may_stop({"socks": {"sessions": 1}}, owned=True)
        self.assertFalse(ok)
        self.assertIn("socks", why.lower())

    def test_a_channel_this_view_did_not_start_is_left_alone(self):
        ok, why = opshell.may_stop({"socks": {"sessions": 0}}, owned=False)
        self.assertFalse(ok)

    def test_an_owned_idle_channel_may_be_stopped(self):
        ok, _ = opshell.may_stop({"socks": {"sessions": 0}}, owned=True)
        self.assertTrue(ok)

    def test_the_expected_checkin_counts_down_from_the_last_one(self):
        agent = {"_last_seen_ts": 1000.0, "interval": 300}
        self.assertEqual(opshell.expected_checkin(agent, now=1100.0), 200.0)
        self.assertIsNone(opshell.expected_checkin({}, now=1100.0))

    # -- beyond the brief's five ------------------------------------------

    def test_the_task_has_exactly_the_keys_the_route_gives_its_tasks(self):
        # A task missing a key the dispatcher reads is a task the implant
        # never runs, and a channel that never rises. The route's own source
        # is the reference, so the two cannot drift apart unnoticed.
        task_keys, _ = _route_dict_keys()
        task = opshell.queue_tunnel("raccoon-bandit", "start", {}, {}, "now")
        self.assertEqual(sorted(task), sorted(task_keys))
        self.assertEqual((task["data"], task["timeout"], task["status"], task["queued"]),
                         ("", 300, "pending", "now"))
        self.assertTrue(task["id"])

    def test_the_task_is_recorded_in_the_agents_history_as_the_route_records_it(self):
        # The operator must be able to see in the history that this
        # feature queued a task, in the shape the history view reads.
        _, history_keys = _route_dict_keys()
        queues, hist = {}, {}
        task = opshell.queue_tunnel("raccoon-bandit", "stop", queues, hist, "now")
        entry, = hist["raccoon-bandit"]
        self.assertEqual(sorted(entry), sorted(history_keys))
        self.assertEqual(entry, {"task_id": task["id"], "cmd": "tunnel",
                                 "args": "stop", "lane": "operator",
                                 "timestamp": "now", "status": "pending",
                                 "output": None})

    def test_a_queued_task_goes_behind_what_is_already_waiting(self):
        # Replacing the agent's queue would silently drop another task.
        waiting = {"id": "old", "cmd": "ls"}
        queues, hist = {"raccoon-bandit": [waiting]}, {"raccoon-bandit": [{"task_id": "old"}]}
        task = opshell.queue_tunnel("raccoon-bandit", "start", queues, hist, "now")
        self.assertEqual(queues["raccoon-bandit"], [waiting, task])
        self.assertEqual(len(hist["raccoon-bandit"]), 2)

    def test_only_start_and_stop_can_be_queued(self):
        # The feature's tasks are `tunnel start` and `tunnel stop`. Anything
        # else, `sleep` above all, is not this module's to queue.
        queues, hist = {}, {}
        for action in ("sleep", "restart", "", "START"):
            with self.assertRaises(ValueError):
                opshell.queue_tunnel("raccoon-bandit", action, queues, hist, "now")
        self.assertEqual((queues, hist), ({}, {}))

    def test_two_queued_tasks_do_not_share_an_id(self):
        queues = {}
        a = opshell.queue_tunnel("raccoon-bandit", "start", queues, {}, "now")
        b = opshell.queue_tunnel("raccoon-bandit", "stop", queues, {}, "now")
        self.assertNotEqual(a["id"], b["id"])

    def test_an_endpoint_that_is_not_connected_cannot_be_checked_so_no_stop(self):
        # No row means no report of SOCKS sessions, and the stop rule asks
        # for that report. The reason says why, so the view can show it.
        ok, why = opshell.may_stop(None, owned=True)
        self.assertFalse(ok)
        self.assertIn("connected", why)

    def test_a_row_that_does_not_say_how_many_socks_sessions_is_not_idle(self):
        # Absence of a number is not a zero.
        for row in ({}, {"socks": {}}, {"socks": {"sessions": None}},
                    {"socks": {"sessions": "0"}}, {"socks": {"sessions": True}},
                    {"socks": "up"}):
            ok, why = opshell.may_stop(row, owned=True)
            self.assertFalse(ok, row)
            self.assertIn("socks", why.lower())

    def test_an_endpoint_with_no_socks_port_open_has_no_session_to_protect(self):
        # The tunnel server's row says `socks: None` when no SOCKS port is
        # open. A shell-only channel must still be closable.
        ok, _ = opshell.may_stop({"socks": None}, owned=True)
        self.assertTrue(ok)

    def test_being_unowned_wins_over_an_idle_socks_port(self):
        ok, why = opshell.may_stop({"socks": None}, owned=False)
        self.assertFalse(ok)
        self.assertNotIn("socks", why.lower())

    def test_an_overdue_beacon_is_a_negative_number_not_an_error(self):
        agent = {"_last_seen_ts": 1000.0, "interval": 300}
        self.assertEqual(opshell.expected_checkin(agent, now=1400.0), -100.0)

    def test_an_agent_that_never_reported_an_interval_is_taken_at_the_default(self):
        # The server's own default, 300 s, applies where `interval` is absent.
        self.assertEqual(opshell.expected_checkin({"_last_seen_ts": 1000.0}, now=1100.0), 200.0)
        for junk in (None, "soon", True, [5]):
            agent = {"_last_seen_ts": 1000.0, "interval": junk}
            self.assertEqual(opshell.expected_checkin(agent, now=1100.0), 200.0, junk)

    def test_an_agent_with_a_timestamp_that_is_not_a_number_has_not_been_seen(self):
        self.assertIsNone(opshell.expected_checkin({"_last_seen_ts": None, "interval": 60}, now=5.0))
        self.assertIsNone(opshell.expected_checkin({"_last_seen_ts": "x", "interval": 60}, now=5.0))

    def test_reading_the_expected_checkin_never_writes_the_agent(self):
        # Nothing here may change a beacon's interval.
        agent = {"_last_seen_ts": 1000.0, "interval": 300}
        opshell.expected_checkin(agent, now=1100.0)
        self.assertEqual(agent, {"_last_seen_ts": 1000.0, "interval": 300})
        # The default is a reading, not something written back: an agent
        # that reported no interval must not be handed one.
        bare = {"_last_seen_ts": 1000.0}
        opshell.expected_checkin(bare, now=1100.0)
        self.assertEqual(bare, {"_last_seen_ts": 1000.0})


if __name__ == "__main__":
    unittest.main()
