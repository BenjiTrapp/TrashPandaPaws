#!/usr/bin/env python3
"""
Tests for the approval gate: tier routing, the EV arbiter, operator approvals
with timeout, and detection tracking. The tier-1 and tier-3 tests assert on
the approvals table itself, not only on the verdict, because the safety
property is that no answerable row exists. Everything runs against a real
in-memory SQLite database.
"""

import asyncio
import json
import sqlite3
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent import gate, safety
from software.agent.store import db, queries


def _fresh_run():
    conn = db.open_store(":memory:")
    return conn, queries.create_run(conn, "campaign", None, "auto", "{}")


def _cls(tier=safety.TIER_KNOCK, points=50, p_success=0.5, p_detect=0.7,
         action_key="lsass_dump"):
    return safety.Classification(
        tier=tier, action_key=action_key, action_class="credential_access",
        points=points, p_success=p_success, p_detect=p_detect, phase=4,
        reason="LSASS access")


def _gate(conn, rid, **kw):
    kw.setdefault("mode", "auto")
    kw.setdefault("ev_threshold", 0.0)
    kw.setdefault("p_detect_prior", 0.15)
    kw.setdefault("detection_budget", 3)
    kw.setdefault("unattended_behavior", "decide")
    kw.setdefault("approval_timeout", 0.2)
    return gate.Gate(conn, rid, **kw)


def _rows(conn):
    return conn.execute(
        "SELECT id, action, decision, decided_by, ev_json FROM approvals "
        "ORDER BY id").fetchall()


async def _wait_for_pending(g, count=1):
    for _ in range(200):
        if len(g.pending()) >= count:
            return g.pending()
        await asyncio.sleep(0.005)
    raise AssertionError("request never registered a pending approval")


# ── Tier routing ──

class TestTierRouting(unittest.IsolatedAsyncioTestCase):
    async def test_tier_three_passes_without_approval_row(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid).request(_cls(tier=safety.TIER_FREE))
        self.assertTrue(d.allowed)
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM approvals").fetchone()[0], 0)

    async def test_tier_three_passes_in_every_mode_and_unattended_setting(self):
        for mode in ("auto", "supervised"):
            for behaviour in ("decide", "skip", "pause"):
                conn, rid = _fresh_run()
                g = _gate(conn, rid, mode=mode, unattended_behavior=behaviour)
                d = await g.request(_cls(tier=safety.TIER_FREE))
                self.assertTrue(d.allowed, (mode, behaviour))
                self.assertEqual(_rows(conn), [], (mode, behaviour))

    async def test_tier_one_is_refused_even_in_auto_mode(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid).request(_cls(tier=safety.TIER_HARD))
        self.assertFalse(d.allowed)
        self.assertEqual(d.decided_by, "hard")

    async def test_tier_one_creates_no_approval_row(self):
        for mode in ("auto", "supervised"):
            conn, rid = _fresh_run()
            await _gate(conn, rid, mode=mode).request(
                _cls(tier=safety.TIER_HARD))
            self.assertEqual(_rows(conn), [], mode)

    async def test_tier_one_cannot_be_approved_by_operator(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised")
        d = await g.request(_cls(tier=safety.TIER_HARD))
        self.assertFalse(d.allowed)
        self.assertEqual(g.pending(), [])
        # No row exists, so no id can be answered — in particular not the
        # first id the table would have handed out.
        self.assertFalse(g.answer(1, True))
        self.assertEqual(_rows(conn), [])

    async def test_tier_one_is_refused_whatever_the_ev_or_the_override(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid, ev_threshold=-1000.0).request(
            _cls(tier=safety.TIER_HARD, points=100000, p_success=0.99,
                 p_detect=0.0), p_success_override=0.99)
        self.assertFalse(d.allowed)
        self.assertEqual(d.decided_by, "hard")
        self.assertIsNone(d.ev)

    async def test_tier_one_is_refused_before_unattended_behaviour_applies(self):
        # Pausing a campaign over an action that can never run would stall
        # it for nothing, and "skip" must not be the label on a hard refusal.
        conn, rid = _fresh_run()
        for behaviour in ("skip", "pause"):
            d = await _gate(conn, rid, unattended_behavior=behaviour).request(
                _cls(tier=safety.TIER_HARD))
            self.assertEqual(d.decided_by, "hard", behaviour)

    async def test_tier_one_reason_is_the_classifications_reason(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid).request(_cls(tier=safety.TIER_HARD))
        self.assertIn("LSASS access", d.reason)

    async def test_unrecognised_tier_fails_closed_without_a_row(self):
        for tier in (0, 4, None, "2"):
            conn, rid = _fresh_run()
            d = await _gate(conn, rid).request(_cls(tier=tier))
            self.assertFalse(d.allowed, tier)
            self.assertEqual(d.decided_by, "hard", tier)
            self.assertEqual(_rows(conn), [], tier)


# ── EV arbiter ──

class TestMissingDetectionProbability(unittest.IsolatedAsyncioTestCase):
    """`p_detect_prior` substitutes for a missing p_detect; it is not a floor.

    `safety._row` defaults `p_detect` to 0.0, so a risk-table row that omits
    it would yield `ev = points * p_success - 100 * 0` — a risk-free expected
    value for an action that is meant to knock. Substituting is the narrow
    fix; flooring would silently overrule a low-but-deliberate table value.
    """

    async def test_a_missing_p_detect_is_not_risk_free(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid, p_detect_prior=0.15).request(
            _cls(points=200, p_success=0.9, p_detect=0.0))
        self.assertAlmostEqual(d.ev, 200 * 0.9 - 100 * 0.15)

    async def test_a_low_but_real_p_detect_is_left_alone(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid, p_detect_prior=0.15).request(
            _cls(points=200, p_success=0.9, p_detect=0.01))
        self.assertAlmostEqual(d.ev, 200 * 0.9 - 100 * 0.01)

    async def test_the_substitution_is_stated_in_the_reason(self):
        conn, rid = _fresh_run()
        substituted = await _gate(conn, rid, p_detect_prior=0.15).request(
            _cls(points=200, p_success=0.9, p_detect=0.0))
        self.assertIn("no p_detect", substituted.reason)
        present = await _gate(conn, rid, p_detect_prior=0.15).request(
            _cls(points=200, p_success=0.9, p_detect=0.01))
        self.assertNotIn("no p_detect", present.reason)

    async def test_the_substitution_is_recorded(self):
        conn, rid = _fresh_run()
        await _gate(conn, rid).request(_cls(p_detect=0.0))
        self.assertTrue(json.loads(_rows(conn)[0]["ev_json"])
                        ["p_detect_substituted"])

    async def test_the_configured_prior_is_what_gets_used(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid, p_detect_prior=0.40).request(
            _cls(points=200, p_success=0.9, p_detect=0.0))
        self.assertAlmostEqual(d.ev, 200 * 0.9 - 100 * 0.40)

    async def test_detection_tracking_still_applies_to_a_substituted_value(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, p_detect_prior=0.15, detection_budget=99)
        g.note_detection("reset")
        d = await g.request(_cls(points=200, p_success=0.9, p_detect=0.0))
        self.assertAlmostEqual(d.ev, 200 * 0.9 - 100 * 0.30)


class TestEvArbiter(unittest.IsolatedAsyncioTestCase):
    async def test_positive_ev_proceeds(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid).request(
            _cls(points=200, p_success=0.6, p_detect=0.3))
        self.assertTrue(d.allowed)
        self.assertEqual(d.decided_by, "ev")
        self.assertAlmostEqual(d.ev, 200 * 0.6 - 100 * 0.3)

    async def test_negative_ev_is_refused(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid).request(
            _cls(points=50, p_success=0.5, p_detect=0.7))
        self.assertFalse(d.allowed)
        self.assertEqual(d.decided_by, "ev")
        self.assertAlmostEqual(d.ev, 50 * 0.5 - 100 * 0.7)

    async def test_threshold_is_respected(self):
        conn, rid = _fresh_run()
        c = _cls(points=100, p_success=0.5, p_detect=0.4)   # EV = 10
        self.assertTrue(
            (await _gate(conn, rid, ev_threshold=5.0).request(c)).allowed)
        self.assertFalse(
            (await _gate(conn, rid, ev_threshold=20.0).request(c)).allowed)

    async def test_ev_exactly_at_threshold_is_refused(self):
        # The spec says EV > threshold, so equality does not pass.
        conn, rid = _fresh_run()
        c = _cls(points=100, p_success=0.5, p_detect=0.5)   # EV = 0
        self.assertFalse((await _gate(conn, rid).request(c)).allowed)

    async def test_llm_p_success_override_is_clamped(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid).request(
            _cls(points=50, p_success=0.5, p_detect=0.1), p_success_override=0.99)
        self.assertAlmostEqual(d.ev, 50 * 0.7 - 100 * 0.1)

    async def test_llm_override_can_only_lower_as_far_as_the_clamp(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid).request(
            _cls(points=50, p_success=0.5, p_detect=0.1), p_success_override=0.0)
        self.assertAlmostEqual(d.ev, 50 * 0.3 - 100 * 0.1)

    async def test_non_numeric_override_falls_back_to_the_prior(self):
        conn, rid = _fresh_run()
        for bad in ("high", float("nan"), None):
            d = await _gate(conn, rid).request(
                _cls(points=50, p_success=0.5, p_detect=0.1),
                p_success_override=bad)
            self.assertAlmostEqual(d.ev, 50 * 0.5 - 100 * 0.1, msg=repr(bad))

    async def test_ev_uses_the_tracked_detection_probability(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid)
        c = _cls(points=100, p_success=0.5, p_detect=0.3)
        before = await g.request(c)
        self.assertAlmostEqual(before.ev, 100 * 0.5 - 100 * 0.30)
        self.assertTrue(before.allowed)
        g.note_detection("reset")
        g.note_detection("reset")
        after = await g.request(c)
        # 0.30 + 2 * 0.15 = 0.60, not the classification's 0.30.
        self.assertAlmostEqual(after.ev, 100 * 0.5 - 100 * 0.60)
        self.assertFalse(after.allowed)

    async def test_detections_reported_outside_note_detection_also_count(self):
        # The model can report a detection through log_score; the gate has
        # to see it, or the leash only tightens for pattern-matched ones.
        conn, rid = _fresh_run()
        queries.log_score(conn, rid, "detection", -100, "high", True)
        d = await _gate(conn, rid).request(
            _cls(points=100, p_success=0.5, p_detect=0.3))
        self.assertAlmostEqual(d.ev, 100 * 0.5 - 100 * 0.45)

    async def test_a_rebuilt_gate_remembers_the_runs_detections(self):
        conn, rid = _fresh_run()
        _gate(conn, rid).note_detection("reset")
        again = _gate(conn, rid)
        self.assertEqual(again.detection_count, 1)
        self.assertAlmostEqual(again.effective_p_detect(0.30), 0.45)

    async def test_detections_of_another_run_do_not_count(self):
        conn, rid = _fresh_run()
        other = queries.create_run(conn, "campaign", None, "auto", "{}")
        _gate(conn, other).note_detection("reset")
        self.assertEqual(_gate(conn, rid).detection_count, 0)

    async def test_decision_is_persisted(self):
        conn, rid = _fresh_run()
        await _gate(conn, rid).request(_cls())
        row = conn.execute(
            "SELECT decision, decided_by FROM approvals").fetchone()
        self.assertEqual(row["decided_by"], "ev")

    async def test_decision_text_matches_the_store_vocabulary(self):
        conn, rid = _fresh_run()
        await _gate(conn, rid).request(
            _cls(points=200, p_success=0.6, p_detect=0.3))
        await _gate(conn, rid).request(
            _cls(points=50, p_success=0.5, p_detect=0.7))
        self.assertEqual([r["decision"] for r in _rows(conn)],
                         ["approved", "refused"])

    async def test_row_records_the_numbers_the_arbiter_used(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid)
        g.note_detection("reset")
        await g.request(_cls(points=100, p_success=0.5, p_detect=0.3),
                        p_success_override=0.6)
        row = _rows(conn)[0]
        ev = json.loads(row["ev_json"])
        self.assertAlmostEqual(ev["ev"], 100 * 0.6 - 100 * 0.45)
        self.assertAlmostEqual(ev["p_detect_effective"], 0.45)
        self.assertAlmostEqual(ev["p_success_effective"], 0.6)
        self.assertAlmostEqual(ev["p_success_prior"], 0.5)
        self.assertEqual(row["action"], "lsass_dump")


class TestOverrideIsLoud(unittest.IsolatedAsyncioTestCase):
    # A third verdict between "allowed" and "refused": allowed, but only
    # because the model's own advisory number tipped it.

    async def test_override_that_flips_a_refusal_is_flagged(self):
        conn, rid = _fresh_run()
        c = _cls(points=50, p_success=0.5, p_detect=0.3)   # prior EV = -5
        d = await _gate(conn, rid).request(c, p_success_override=0.99)
        self.assertTrue(d.allowed)
        self.assertTrue(d.override_decisive)
        self.assertAlmostEqual(d.ev, 50 * 0.7 - 100 * 0.3)   # +5
        self.assertIn("override", d.reason)
        self.assertIn("-5.0", d.reason)

    async def test_flag_is_persisted_with_the_row(self):
        conn, rid = _fresh_run()
        await _gate(conn, rid).request(
            _cls(points=50, p_success=0.5, p_detect=0.3), p_success_override=0.99)
        self.assertTrue(json.loads(_rows(conn)[0]["ev_json"])["override_decisive"])

    async def test_override_that_changes_nothing_is_not_flagged(self):
        conn, rid = _fresh_run()
        c = _cls(points=200, p_success=0.6, p_detect=0.3)   # allowed anyway
        d = await _gate(conn, rid).request(c, p_success_override=0.7)
        self.assertTrue(d.allowed)
        self.assertFalse(d.override_decisive)

    async def test_override_that_still_leaves_a_refusal_is_not_flagged(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid).request(
            _cls(points=50, p_success=0.5, p_detect=0.7), p_success_override=0.99)
        self.assertFalse(d.allowed)
        self.assertFalse(d.override_decisive)

    async def test_no_override_is_never_flagged(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid).request(
            _cls(points=200, p_success=0.6, p_detect=0.3))
        self.assertFalse(d.override_decisive)


# ── Detection tracking ──

class TestDetectionTracking(unittest.TestCase):
    def test_p_detect_rises_by_fifteen_hundredths_per_detection(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid)
        self.assertAlmostEqual(g.effective_p_detect(0.30), 0.30)
        g.note_detection("reset")
        self.assertAlmostEqual(g.effective_p_detect(0.30), 0.45)
        g.note_detection("reset")
        self.assertAlmostEqual(g.effective_p_detect(0.30), 0.60)

    def test_p_detect_is_capped(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, detection_budget=99)
        for _ in range(20):
            g.note_detection("reset")
        self.assertAlmostEqual(g.effective_p_detect(0.30), 0.95)

    def test_cap_never_lowers_a_prior_that_is_already_higher(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid)
        self.assertAlmostEqual(g.effective_p_detect(0.99), 0.99)
        g.note_detection("reset")
        self.assertAlmostEqual(g.effective_p_detect(0.99), 0.99)

    def test_budget_exhaustion_is_reported(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, detection_budget=2)
        self.assertFalse(g.note_detection("reset"))
        self.assertTrue(g.note_detection("reset"))

    def test_detection_count_follows_note_detection(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid)
        self.assertEqual(g.detection_count, 0)
        g.note_detection("reset")
        self.assertEqual(g.detection_count, 1)

    def test_detection_is_scored_as_minus_hundred(self):
        conn, rid = _fresh_run()
        _gate(conn, rid).note_detection("reset")
        self.assertEqual(
            queries.get_score_context(conn, rid)["total_score"], -100)

    def test_detection_event_carries_the_agreed_fields(self):
        conn, rid = _fresh_run()
        _gate(conn, rid).note_detection("reset")
        event = queries.get_score_context(conn, rid)["recent_events"][0]
        self.assertEqual(event["action"], "detection:reset")
        self.assertEqual(event["points"], -100)
        self.assertEqual(event["risk_level"], "high")
        self.assertTrue(event["detected"])

    def test_the_signal_that_fired_is_recoverable_from_the_record(self):
        # A detection costs 100 points, raises p_detect for every later
        # decision and can end the run. Which signal fired has to survive
        # into the audit trail or the operator cannot review the decision.
        conn, rid = _fresh_run()
        g = _gate(conn, rid, detection_budget=99)
        for source in ("reset", "policy_block", "no_route"):
            g.note_detection(source)
        actions = [e["action"]
                   for e in queries.get_score_context(conn, rid)["recent_events"]]
        for source in ("reset", "policy_block", "no_route"):
            self.assertIn("detection:" + source, actions)

    def test_an_untrusted_source_name_cannot_poison_the_record(self):
        # The name arrives from scanned tool output, so it is attacker-shaped.
        conn, rid = _fresh_run()
        g = _gate(conn, rid, detection_budget=99)
        for source in ("A" * 500, "drop'; DELETE FROM approvals; --",
                       "with spaces\nand\tcontrol", "", "   ", None, 7, b"x"):
            g.note_detection(source)
        for event in queries.get_score_context(conn, rid)["recent_events"]:
            action = event["action"]
            self.assertTrue(action.startswith("detection:"), action)
            self.assertLessEqual(len(action), len("detection:") + 40, action)
            self.assertRegex(action, r"^detection:[a-z0-9_]+$")
        # The injection attempt did not run.
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM score_events").fetchone()[0], 8)


class TestDetectionScanner(unittest.TestCase):
    def test_recognises_known_patterns(self):
        for out in ("connection reset by peer", "blocked by policy",
                    "denied by policy", "Connection closed by remote host"):
            self.assertIsNotNone(
                gate.scan_for_detection(out, host_was_responsive=True), out)

    def test_each_signal_is_named(self):
        cases = {
            "recv failure: Connection reset by peer": "connection_reset",
            "read tcp: ECONNRESET": "connection_reset",
            "An existing connection was forcibly closed by the remote host":
                "connection_reset",
            "Connection closed by remote host": "connection_closed",
            "request blocked by firewall": "policy_block",
            "Access denied by policy": "policy_block",
        }
        for out, name in cases.items():
            self.assertEqual(
                gate.scan_for_detection(out, host_was_responsive=True), name, out)

    def test_matching_is_case_insensitive(self):
        self.assertEqual(
            gate.scan_for_detection("CONNECTION RESET BY PEER",
                                    host_was_responsive=False),
            "connection_reset")

    def test_signal_is_found_inside_longer_output(self):
        out = "Starting scan\n[!] ssh: Connection reset by peer\nDone.\n"
        self.assertEqual(
            gate.scan_for_detection(out, host_was_responsive=False),
            "connection_reset")

    def test_no_route_only_counts_after_prior_contact(self):
        out = "No route to host"
        self.assertIsNotNone(
            gate.scan_for_detection(out, host_was_responsive=True))
        self.assertIsNone(
            gate.scan_for_detection(out, host_was_responsive=False))

    def test_host_down_only_counts_after_prior_contact(self):
        out = "Note: Host seems down. If it is really up, but blocking our ping"
        self.assertEqual(gate.scan_for_detection(out, host_was_responsive=True),
                         "host_vanished")
        self.assertIsNone(gate.scan_for_detection(out, host_was_responsive=False))

    def test_an_unconditional_signal_still_fires_beside_a_gated_one(self):
        out = "No route to host\nconnection reset by peer"
        self.assertEqual(
            gate.scan_for_detection(out, host_was_responsive=False),
            "connection_reset")

    def test_clean_output_is_not_a_detection(self):
        self.assertIsNone(gate.scan_for_detection(
            "445/tcp open microsoft-ds", host_was_responsive=True))

    def test_ordinary_failures_are_not_detections(self):
        # Each of these is a bad target or a bad credential, not a defence
        # reacting; counting them would spend detection budget on noise.
        for out in ("Connection refused", "Connection timed out",
                    "Permission denied (publickey)", "Access denied",
                    "Name or service not known", "0 blocked ports",
                    "unblocked 3 hosts", "", "Nmap done: 0 hosts up"):
            self.assertIsNone(
                gate.scan_for_detection(out, host_was_responsive=True), out)

    def test_non_string_output_is_not_a_detection(self):
        for out in (None, b"connection reset by peer", 42):
            self.assertIsNone(
                gate.scan_for_detection(out, host_was_responsive=True), out)


# ── Supervised mode ──

class TestSupervisedMode(unittest.IsolatedAsyncioTestCase):
    async def test_operator_approval_releases_the_waiter(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised", approval_timeout=5.0)
        task = asyncio.create_task(g.request(_cls()))
        pending = await _wait_for_pending(g)
        self.assertEqual(len(pending), 1)
        self.assertTrue(g.answer(pending[0]["id"], True))
        d = await task
        self.assertTrue(d.allowed)
        self.assertEqual(d.decided_by, "operator")
        self.assertEqual(g.pending(), [])
        row = _rows(conn)[0]
        self.assertEqual((row["decision"], row["decided_by"]),
                         ("approved", "operator"))

    async def test_operator_refusal_returns_reason_for_the_llm(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised", approval_timeout=5.0)
        task = asyncio.create_task(g.request(_cls()))
        pending = await _wait_for_pending(g)
        self.assertTrue(g.answer(pending[0]["id"], False))
        d = await task
        self.assertFalse(d.allowed)
        self.assertEqual(d.decided_by, "operator")
        self.assertTrue(d.reason)
        self.assertEqual(_rows(conn)[0]["decision"], "refused")

    async def test_supervised_decision_still_reports_the_ev(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised", approval_timeout=5.0)
        task = asyncio.create_task(
            g.request(_cls(points=50, p_success=0.5, p_detect=0.7)))
        pending = await _wait_for_pending(g)
        g.answer(pending[0]["id"], True)
        d = await task
        self.assertAlmostEqual(d.ev, 50 * 0.5 - 100 * 0.7)

    async def test_operator_may_approve_what_the_ev_would_refuse(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised", approval_timeout=5.0)
        task = asyncio.create_task(
            g.request(_cls(points=50, p_success=0.5, p_detect=0.7)))
        pending = await _wait_for_pending(g)
        g.answer(pending[0]["id"], True)
        self.assertTrue((await task).allowed)

    async def test_supervised_mode_ignores_the_unattended_setting(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised", unattended_behavior="pause",
                  approval_timeout=5.0)
        task = asyncio.create_task(g.request(_cls()))
        pending = await _wait_for_pending(g)
        g.answer(pending[0]["id"], True)
        self.assertTrue((await task).allowed)

    async def test_timeout_records_timeout_as_decider(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid, mode="supervised",
                        approval_timeout=0.1).request(_cls())
        self.assertFalse(d.allowed)
        self.assertEqual(d.decided_by, "timeout")
        row = _rows(conn)[0]
        self.assertEqual((row["decision"], row["decided_by"]),
                         ("refused", "timeout"))

    async def test_timeout_leaves_nothing_pending_or_waiting(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised", approval_timeout=0.05)
        await g.request(_cls())
        self.assertEqual(g.pending(), [])
        self.assertEqual(g._waiting, {})

    async def test_each_request_gets_its_own_row_and_future(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised", approval_timeout=5.0)
        first = asyncio.create_task(g.request(_cls()))
        second = asyncio.create_task(g.request(_cls()))
        pending = await _wait_for_pending(g, 2)
        self.assertNotEqual(pending[0]["id"], pending[1]["id"])
        g.answer(pending[1]["id"], True)
        g.answer(pending[0]["id"], False)
        self.assertFalse((await first).allowed)
        self.assertTrue((await second).allowed)

    async def test_approval_for_one_action_key_does_not_release_another(self):
        # The gate keys approvals on action_key; two lateral actions must not
        # share an answer.
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised", approval_timeout=5.0)
        relay = asyncio.create_task(g.request(_cls(action_key="ntlm_relay")))
        pending = await _wait_for_pending(g)
        execute = asyncio.create_task(g.request(_cls(action_key="remote_exec")))
        pending = await _wait_for_pending(g, 2)
        by_action = {p["action"]: p["id"] for p in pending}
        self.assertEqual(set(by_action), {"ntlm_relay", "remote_exec"})
        g.answer(by_action["ntlm_relay"], True)
        self.assertTrue((await relay).allowed)
        self.assertFalse(execute.done())
        self.assertEqual([p["action"] for p in g.pending()], ["remote_exec"])
        g.answer(by_action["remote_exec"], False)
        self.assertFalse((await execute).allowed)

    async def test_pending_lists_only_this_runs_open_approvals(self):
        conn, rid = _fresh_run()
        other = queries.create_run(conn, "campaign", None, "auto", "{}")
        queries.create_approval(conn, other, "persist", "{}", "{}")
        g = _gate(conn, rid, mode="supervised", approval_timeout=5.0)
        task = asyncio.create_task(g.request(_cls()))
        pending = await _wait_for_pending(g)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["run_id"], rid)
        g.answer(pending[0]["id"], False)
        await task


# ── A decided approval stays decided ──

class TestAnswerIsFinal(unittest.IsolatedAsyncioTestCase):
    async def test_unknown_id_is_not_answerable(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised")
        self.assertFalse(g.answer(999, True))

    async def test_answering_twice_returns_false_and_keeps_the_first_answer(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised", approval_timeout=5.0)
        task = asyncio.create_task(g.request(_cls()))
        approval_id = (await _wait_for_pending(g))[0]["id"]
        self.assertTrue(g.answer(approval_id, True))
        self.assertFalse(g.answer(approval_id, False))
        self.assertTrue((await task).allowed)
        self.assertEqual(_rows(conn)[0]["decision"], "approved")

    async def test_refusal_cannot_be_reversed_by_a_later_approval(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised", approval_timeout=5.0)
        task = asyncio.create_task(g.request(_cls()))
        approval_id = (await _wait_for_pending(g))[0]["id"]
        g.answer(approval_id, False)
        self.assertFalse(g.answer(approval_id, True))
        self.assertFalse((await task).allowed)
        self.assertEqual(_rows(conn)[0]["decision"], "refused")

    async def test_answer_after_timeout_cannot_resurrect_the_action(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised", approval_timeout=0.05)
        task = asyncio.create_task(g.request(_cls()))
        approval_id = (await _wait_for_pending(g))[0]["id"]
        d = await task
        self.assertEqual(d.decided_by, "timeout")
        self.assertFalse(g.answer(approval_id, True))
        row = _rows(conn)[0]
        self.assertEqual((row["decision"], row["decided_by"]),
                         ("refused", "timeout"))

    async def test_ev_decided_approval_cannot_be_answered(self):
        # Auto-mode rows exist and are decided at once; the operator's click
        # on a stale id must not overturn the arbiter.
        conn, rid = _fresh_run()
        g = _gate(conn, rid)
        await g.request(_cls(points=50, p_success=0.5, p_detect=0.7))
        approval_id = _rows(conn)[0]["id"]
        self.assertFalse(g.answer(approval_id, True))
        self.assertEqual(_rows(conn)[0]["decision"], "refused")
        self.assertEqual(_rows(conn)[0]["decided_by"], "ev")

    async def test_answer_arriving_in_the_instant_of_the_timeout_wins_once(self):
        # Force the interleaving: the operator's answer lands, then the wait
        # reports a timeout anyway. The timeout path must see that the
        # answer got there first and neither overwrite nor contradict it.
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised", approval_timeout=5.0)

        async def answered_then_timed_out(awaitable, timeout):
            g.answer(g.pending()[0]["id"], True)
            raise asyncio.TimeoutError()

        with unittest.mock.patch.object(
                gate.asyncio, "wait_for", answered_then_timed_out):
            d = await g.request(_cls())
        self.assertTrue(d.allowed)
        self.assertEqual(d.decided_by, "operator")
        row = _rows(conn)[0]
        self.assertEqual((row["decision"], row["decided_by"]),
                         ("approved", "operator"))
        self.assertFalse(g.answer(row["id"], False))

    async def test_timeout_arriving_first_wins_over_a_late_answer_in_the_same_tick(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised", approval_timeout=5.0)
        seen = {}

        async def timed_out(awaitable, timeout):
            seen["id"] = g.pending()[0]["id"]
            raise asyncio.TimeoutError()

        with unittest.mock.patch.object(gate.asyncio, "wait_for", timed_out):
            d = await g.request(_cls())
        self.assertEqual(d.decided_by, "timeout")
        self.assertFalse(g.answer(seen["id"], True))
        self.assertEqual(_rows(conn)[0]["decision"], "refused")

    async def test_cancelled_request_closes_its_row(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised", approval_timeout=5.0)
        task = asyncio.create_task(g.request(_cls()))
        approval_id = (await _wait_for_pending(g))[0]["id"]
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(g.pending(), [])
        self.assertFalse(g.answer(approval_id, True))
        row = _rows(conn)[0]
        self.assertEqual((row["decision"], row["decided_by"]),
                         ("refused", "timeout"))

    async def test_non_boolean_answer_is_rejected_and_the_request_stays_open(self):
        # "false" is truthy; an approval must be an unmistakable True.
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised", approval_timeout=5.0)
        task = asyncio.create_task(g.request(_cls()))
        approval_id = (await _wait_for_pending(g))[0]["id"]
        for bad in ("false", 1, None):
            with self.assertRaises(TypeError):
                g.answer(approval_id, bad)
        self.assertEqual(len(g.pending()), 1)
        g.answer(approval_id, False)
        self.assertFalse((await task).allowed)


# ── Unattended behaviour ──

class TestUnattendedBehaviour(unittest.IsolatedAsyncioTestCase):
    async def test_skip_refuses_without_ev(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid, unattended_behavior="skip").request(
            _cls(points=200, p_success=0.9, p_detect=0.1))
        self.assertFalse(d.allowed)
        self.assertIsNone(d.ev)
        self.assertEqual(d.decided_by, "skip")
        self.assertTrue(d.reason)

    async def test_skip_is_audited_but_not_answerable(self):
        # The property this pins is unchanged — a skip must not be
        # answerable — but it is now reached by writing an already-decided
        # row rather than by writing none, because a refusal with no trace
        # breaks the rule that everything the agent does is logged.
        conn, rid = _fresh_run()
        g = _gate(conn, rid, unattended_behavior="skip")
        await g.request(_cls(points=200, p_success=0.9, p_detect=0.1))
        rows = _rows(conn)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["decision"], "refused")
        self.assertEqual(rows[0]["decided_by"], "skip")
        self.assertEqual(rows[0]["action"], "lsass_dump")
        # Decided on arrival, so it is invisible to the operator queue and
        # cannot be flipped open again.
        self.assertEqual(g.pending(), [])
        self.assertFalse(g.answer(rows[0]["id"], True))

    async def test_a_skipped_row_records_why_rather_than_numbers(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, unattended_behavior="skip")
        await g.request(_cls())
        stored = json.loads(_rows(conn)[0]["ev_json"])
        self.assertTrue(stored["skipped"])
        self.assertNotIn("ev", stored)

    async def test_pause_raises_for_the_lifecycle(self):
        conn, rid = _fresh_run()
        with self.assertRaises(gate.GatePauseRequested):
            await _gate(conn, rid, unattended_behavior="pause").request(_cls())

    async def test_pause_leaves_no_answerable_row(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, unattended_behavior="pause")
        with self.assertRaises(gate.GatePauseRequested):
            await g.request(_cls())
        self.assertEqual(_rows(conn), [])


# ── Construction ──

class TestConstruction(unittest.TestCase):
    def test_unknown_mode_is_rejected(self):
        conn, rid = _fresh_run()
        with self.assertRaises(ValueError):
            _gate(conn, rid, mode="yolo")

    def test_unknown_unattended_behaviour_is_rejected(self):
        conn, rid = _fresh_run()
        with self.assertRaises(ValueError):
            _gate(conn, rid, unattended_behavior="allow")


if __name__ == "__main__":
    unittest.main()
