#!/usr/bin/env python3
"""The ladder is arithmetic, and both paths go through it.

The first draft of this design had `points` fixed per rung and the
probability pair doing the ordering, and that was wrong: with the priors
written into the table, `points * p_success > R * p_detect` is a *constant*
per rung, decided when the table is authored. Either it is set high enough
that the loudest rung always passes -- in which case the gate orders
nothing -- or low enough that it never fires, which contradicts the
appetite the human stated. The term that varies on a server run,
`effective_p_detect`, climbs with a campaign's detection count and has no
analogue on a dark implant.

So two terms move, and both are honest:

  * **`points` grows with time dark.** `points` is the value of what the
    action unlocks, and the value of a restored channel is not constant: a
    channel back in the first hour is worth a check-in, and one back after
    a week is the difference between an operation and a dead device in a
    rack.
  * **`p_detect` moves with the evidence.** `dot1x_seen` raises the
    identity rung's, because a port that authenticates is a port somebody
    configured and therefore watches. `portal_answered` lowers the borrow
    rung's, because a network that redirects every browser sees credential
    prompts answered all day.

Together: the quiet rungs are allowed almost immediately, the loud ones
cross later, and the evidence moves the crossing. **Both paths go through
it** -- the policy evaluator and the model's recommendation alike -- which
is what stops the no-model fallback reaching the loud rungs ungated.

**Where the arithmetic runs, and why it is a copy.** Not in `gate.Gate`:
that needs a SQLite connection, a `run_id`, an approvals table and an
event loop, none of which exists on an implant with no channel. The rows
and the inequality are a stdlib copy inside `beacon.py`, following the
pattern that file already uses for the rescue record, and the first class
below holds the copy against `safety.py`'s own table.

**Nothing changes on a build with no scout.** With `c2.way_out` off the
three verbs the decider has always had behave exactly as they do today --
no arithmetic, no new refusal -- and the two loud rungs are refused with
a reason. That is the distribution rule: the ladder arrives with the
scout.
"""

import base64
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.agent import safety
from software.c2 import beacon as beacon_mod
from software.c2.beacon import read_egress_policy, read_way_out_policy
from software.tests import test_egress_decider as _decider

_KEY = b"\x24" * 32
# The shipped beacon interval, which is how a cycle count becomes an hour.
_INTERVAL = 300
_CYCLES_PER_HOUR = 3600 // _INTERVAL


class TestTheCopyIsHeldAgainstSafetysTable(unittest.TestCase):
    """One authority for the numbers, and a copy that cannot drift."""

    def test_every_row_matches_safetys(self):
        self.assertTrue(beacon_mod._WAY_OUT_ROWS)
        for key, (points, p_success, p_detect) in \
                beacon_mod._WAY_OUT_ROWS.items():
            row = safety.WAY_OUT_TABLE[key]
            self.assertEqual((row.points, row.p_success, row.p_detect),
                             (points, p_success, p_detect), key)
            self.assertEqual(row.action_key, key)
            self.assertEqual(row.tier, safety.TIER_KNOCK, key)
            self.assertTrue(row.reason.strip(), key)

    def test_the_two_tables_hold_the_same_keys(self):
        self.assertEqual(set(beacon_mod._WAY_OUT_ROWS),
                         set(safety.WAY_OUT_TABLE))

    def test_each_rung_above_the_first_has_exactly_one_row(self):
        # Rung 1 is evidence only: it has no verb and no row, which is why
        # there are three rows and four rungs.
        self.assertEqual(sorted(beacon_mod._WAY_OUT_ROW_OF), [2, 3, 4])
        self.assertEqual(sorted(beacon_mod._WAY_OUT_ROW_OF.values()),
                         sorted(beacon_mod._WAY_OUT_ROWS))

    def test_every_verb_the_policy_may_name_has_a_rung(self):
        # A verb with no rung could not be priced, so it would reach the
        # implant's own decision ungated -- the hole this whole section
        # exists to close.
        for verb in beacon_mod.EGRESS_VERBS:
            self.assertIn(verb, beacon_mod._WAY_OUT_RUNG_OF, verb)
            self.assertIn(beacon_mod._WAY_OUT_RUNG_OF[verb],
                          beacon_mod._WAY_OUT_ROW_OF, verb)

    def test_the_rows_are_not_in_the_servers_own_risk_table(self):
        # They price *the implant's* autonomous move, whose `points` grows
        # with time dark -- a term the server's gate has no way to know.
        # `classify()` can never return one, and a row the server could
        # never reach would make the operator's gate lists and the
        # measured "reachable unattended" counts in docs/AGENT.md wrong.
        for key in safety.WAY_OUT_TABLE:
            self.assertNotIn(key, safety.RISK_TABLE, key)

    def test_the_campaign_models_refusal_of_egress_has_not_changed(self):
        self.assertEqual(safety.RISK_TABLE["egress_control"].tier,
                         safety.TIER_HARD)


class GateCase(_decider.DeciderCase):
    """A beacon whose stuck window is as long as a test needs."""

    def beacon(self, hours_dark=0.0, flags=(), policy=None, way_out=True,
               **extra):
        block = {"enabled": True, "state_dir": "/opt/raccoon/state"} \
            if way_out is True else way_out
        beacon = self.a_beacon(
            policy=policy,
            way_out=read_way_out_policy(block) if block else
            read_way_out_policy(None),
            **extra)
        beacon._stuck_cycles = int(round(hours_dark * _CYCLES_PER_HOUR))
        for name in flags:
            beacon._rescue_flags |= beacon_mod._EGRESS_FLAG_BITS[name]
        return beacon

    def allows(self, verb, **kwargs):
        allowed, _ = self.beacon(**kwargs)._way_out_allows(verb)
        return allowed

    def numbers(self, verb, p_success=None, **kwargs):
        return self.beacon(**kwargs)._way_out_allows(verb,
                                                     p_success=p_success)


class TestTheCurve(GateCase):
    """`points` grows with time dark, from the beacon's own cycle count."""

    def test_the_first_hour_is_the_tables_own_points(self):
        self.assertEqual(self.beacon(hours_dark=0)._way_out_points(), 20)

    def test_it_grows_by_the_configured_step_each_whole_hour(self):
        for hours, points in ((0, 20), (1, 25), (2, 30), (5, 45), (16, 100)):
            with self.subTest(hours=hours):
                self.assertEqual(
                    self.beacon(hours_dark=hours)._way_out_points(), points)

    def test_it_is_capped(self):
        self.assertEqual(self.beacon(hours_dark=1000)._way_out_points(), 100)

    def test_a_part_hour_does_not_count(self):
        # Floored, not rounded: the curve is a statement about how long the
        # implant has been useless, and half an hour is not an hour.
        self.assertEqual(self.beacon(hours_dark=0.9)._way_out_points(), 20)

    def test_it_is_read_from_the_cycle_count_and_not_a_clock(self):
        # A wall clock would make the curve depend on an NTP a dropped
        # implant cannot reach.
        beacon = self.beacon(hours_dark=0)
        beacon._stuck_cycles = 3 * _CYCLES_PER_HOUR
        self.assertEqual(beacon._way_out_points(), 35)


class TestTheLadderIsArithmetic(GateCase):
    """Quiet first, loud later, and the evidence moves the crossing."""

    def test_the_borrow_rung_is_allowed_in_the_first_hour_dark(self):
        self.assertFalse(self.allows("proxy", hours_dark=0))
        self.assertTrue(self.allows("proxy", hours_dark=1))

    def test_the_radio_rung_waits_for_the_curve(self):
        self.assertFalse(self.allows("radio", hours_dark=4))
        self.assertTrue(self.allows("radio", hours_dark=5))

    def test_the_identity_rung_is_last(self):
        self.assertFalse(self.allows("identity", hours_dark=6))
        self.assertTrue(self.allows("identity", hours_dark=7))

    def test_the_rungs_cross_in_cost_order(self):
        # The property, not three numbers: whatever the table says, a
        # louder rung may never become available before a quieter one.
        first = {}
        for verb in ("proxy", "radio", "identity"):
            for hours in range(0, 40):
                if self.allows(verb, hours_dark=hours):
                    first[verb] = hours
                    break
        self.assertEqual(sorted(first), ["identity", "proxy", "radio"])
        self.assertLess(first["proxy"], first["radio"])
        self.assertLess(first["radio"], first["identity"])

    def test_dot1x_seen_pushes_the_identity_rung_later(self):
        self.assertFalse(self.allows("identity", hours_dark=8,
                                     flags=["dot1x_seen"]))
        self.assertTrue(self.allows("identity", hours_dark=9,
                                    flags=["dot1x_seen"]))

    def test_portal_answered_brings_the_borrow_rung_earlier(self):
        self.assertFalse(self.allows("proxy", hours_dark=0))
        self.assertTrue(self.allows("proxy", hours_dark=0,
                                    flags=["portal_answered"]))

    def test_a_modifier_only_moves_its_own_rung(self):
        self.assertFalse(self.allows("radio", hours_dark=4,
                                     flags=["portal_answered"]))
        self.assertFalse(self.allows("proxy", hours_dark=0,
                                     flags=["dot1x_seen"]))

    def test_the_probability_stays_inside_its_bounds(self):
        # 0.8 + 0.15 is fine; a table or a configuration that pushed it
        # past 1 would make the inequality meaningless rather than strict.
        _, numbers = self.numbers("identity", hours_dark=7,
                                  flags=["dot1x_seen"])
        self.assertTrue(0.0 < numbers["p_detect"] <= 0.99)

    def test_the_numbers_say_everything_a_reader_needs(self):
        _, numbers = self.numbers("identity", hours_dark=7)
        self.assertEqual(numbers["rung"], 4)
        self.assertEqual(numbers["row"], "way_out_identity")
        self.assertEqual(numbers["points"], 55)
        self.assertEqual(numbers["p_success"], 0.5)
        self.assertEqual(numbers["p_detect_prior"], 0.8)
        self.assertEqual(numbers["p_detect"], 0.8)
        self.assertEqual(numbers["risk_coefficient"], 33)
        self.assertEqual(numbers["threshold"], 0)
        self.assertAlmostEqual(numbers["ev"], 55 * 0.5 - 33 * 0.8)
        self.assertTrue(numbers["allowed"])
        self.assertFalse(numbers["override_decisive"])


class TestAModelsEstimateIsAdvisory(GateCase):
    """Clamped to the prior, and marked when it is the only reason."""

    def test_it_is_clamped_to_plus_or_minus_two_tenths(self):
        for proposed, effective in ((0.99, 0.7), (0.01, 0.3), (0.55, 0.55)):
            with self.subTest(proposed=proposed):
                _, numbers = self.numbers("identity", hours_dark=7,
                                          p_success=proposed)
                self.assertAlmostEqual(numbers["p_success"], effective)

    def test_a_proposal_that_is_not_a_number_leaves_the_prior(self):
        for proposed in ("high", None, [], float("nan")):
            with self.subTest(proposed=proposed):
                _, numbers = self.numbers("identity", hours_dark=7,
                                          p_success=proposed)
                self.assertEqual(numbers["p_success"], 0.5)

    def test_a_decision_that_passed_only_on_the_override_is_marked(self):
        allowed, numbers = self.numbers("identity", hours_dark=6,
                                        p_success=0.99)
        self.assertTrue(allowed)
        self.assertTrue(numbers["override_decisive"])
        self.assertLessEqual(numbers["ev_prior"], 0)

    def test_it_cannot_rescue_a_rung_the_curve_has_not_reached(self):
        # ±0.2 is the whole latitude: a model cannot talk the implant into
        # the identity rung in the first hour.
        self.assertFalse(self.allows("identity", hours_dark=0))
        allowed, _ = self.numbers("identity", hours_dark=0, p_success=0.99)
        self.assertFalse(allowed)


class TestTheOperatorDoesNotSetTheClock(GateCase):
    """A long beacon interval must not hand the loud rungs the first cycle.

    "A rescue that starts loud" is a named anti-goal, and the whole
    quiet-first argument rests on `points` growing with time dark. Time
    dark was `stuck_cycles * interval`, and `interval` has a floor but no
    ceiling and is settable from the config *and* from the `sleep` task
    verb -- so `beacon_interval_seconds: 86400` made two stuck cycles
    read as 48 hours dark and the identity rung passed on the first cycle
    the decider may act. The design's analysis of why `points` must move
    never noticed that the operator controls the clock it moves on.
    """

    def beacon_at(self, interval, cycles):
        beacon = self.beacon(hours_dark=0)
        beacon.interval = interval
        beacon._stuck_cycles = cycles
        return beacon

    def test_a_long_interval_does_not_buy_the_identity_rung(self):
        for interval in (300, 3600, 86400, 10 ** 7):
            with self.subTest(interval=interval):
                beacon = self.beacon_at(interval, 2)
                self.assertFalse(beacon._way_out_allows("identity")[0],
                                 "two stuck cycles reached the irreversible "
                                 "rung at interval %d" % interval)

    def test_the_curve_is_bounded_by_cycles_as_well_as_by_hours(self):
        # Whichever is the slower clock. An hour of wall time is an hour,
        # and a cycle is at most one step of the curve -- so the ladder
        # needs both time *and* evidence of repeated failure.
        beacon = self.beacon_at(86400, 2)
        self.assertEqual(beacon._way_out_points(), 30)
        self.assertEqual(self.beacon_at(300, 2)._way_out_points(), 20)

    def test_a_short_interval_still_reaches_the_loud_rungs(self):
        # The other direction: a 60 s interval must not make the ladder
        # unreachable. Nine hours dark is 540 cycles either way.
        beacon = self.beacon_at(60, 9 * 60)
        self.assertTrue(beacon._way_out_allows("identity")[0])


class TestWithNoScoutNothingChanges(GateCase):
    """Today's behaviour exactly, and the loud rungs out of reach."""

    OFF = {"enabled": False, "state_dir": "/opt/raccoon/state"}

    def test_the_three_old_verbs_are_not_gated_at_all(self):
        for verb in ("proxy", "rediscover", "gsocket"):
            with self.subTest(verb=verb):
                self.assertTrue(self.allows(verb, hours_dark=0,
                                            way_out=self.OFF))

    def test_the_loud_rungs_are_refused_with_the_reason(self):
        for verb in ("radio", "identity"):
            with self.subTest(verb=verb):
                allowed, numbers = self.numbers(verb, hours_dark=100,
                                                way_out=self.OFF)
                self.assertFalse(allowed)
                self.assertIn("c2.way_out", numbers["why"])

    def test_a_borrow_verb_that_needs_the_scout_is_dropped(self):
        # `credential` and `portal` are rung 2, so the arithmetic lets
        # them through on a build with no scout -- and then every attempt
        # is a refusal the build *guarantees*, which spends the whole
        # budget and suppresses the gsocket latch with it. Dropped when
        # the policy is read, the way a proxy verb is dropped on a build
        # whose `c2.proxy.mode` is none, and for the same reason.
        for verb in ("credential", "portal"):
            with self.subTest(verb=verb):
                beacon = self.beacon(
                    hours_dark=5, way_out=self.OFF,
                    policy=self.policy([{"when": {"https": ["not_attempted"]},
                                         "try": verb}]))
                self.assertEqual(beacon._egress_rules, [])
                self.assertTrue(
                    any(verb in message and "c2.way_out" in message
                        for message in self.logged.warnings),
                    "nothing said why rule 1 will never fire: %r"
                    % (self.logged.warnings,))

    def test_a_dropped_borrow_verb_does_not_renumber_the_rest(self):
        beacon = self.beacon(
            hours_dark=5, way_out=self.OFF,
            policy=self.policy([
                {"when": {"https": ["not_attempted"]}, "try": "portal"},
                {"when": {"https": ["not_attempted"]}, "try": "gsocket"}]))
        self.assertEqual([number for number, _ in beacon._egress_rules], [2])

    def test_a_dropped_verb_costs_no_budget(self):
        beacon = self.beacon(
            hours_dark=5, way_out=self.OFF,
            policy=self.policy([{"when": {"https": ["not_attempted"]},
                                 "try": "credential"}]))
        asked = self.record_attempts(beacon)
        for _ in range(5):
            beacon._egress_act()
        self.assertEqual(asked, [])
        self.assertEqual(beacon._egress_spent, 0)

    def test_with_a_scout_those_verbs_are_kept(self):
        beacon = self.beacon(
            hours_dark=5,
            policy=self.policy([{"when": {"https": ["not_attempted"]},
                                 "try": "portal"}]))
        self.assertEqual([number for number, _ in beacon._egress_rules], [1])

    def test_a_policy_rule_naming_a_loud_verb_never_fires(self):
        beacon = self.beacon(
            hours_dark=5, way_out=self.OFF,
            policy=self.policy([{"when": {"https": ["not_attempted"]},
                                 "try": "radio"}]))
        asked = self.record_attempts(beacon)
        self.assertFalse(beacon._egress_act())
        self.assertEqual(asked, [])
        self.assertTrue(any("c2.way_out" in message
                            for message in self.logged.warnings),
                        "nothing said why: %r" % (self.logged.warnings,))


class TestBothPathsGoThroughIt(GateCase):
    """A policy rule and a model recommendation are priced the same way."""

    def rule(self, verb):
        return {"when": {"https": ["not_attempted"]}, "try": verb}

    def test_a_policy_rule_is_refused_until_the_curve_reaches_it(self):
        beacon = self.beacon(hours_dark=4,
                             policy=self.policy([self.rule("radio")]))
        asked = self.record_attempts(beacon)
        self.assertFalse(beacon._egress_act())
        self.assertEqual(asked, [])

    def test_the_same_rule_fires_once_the_curve_reaches_it(self):
        beacon = self.beacon(hours_dark=5,
                             policy=self.policy([self.rule("radio")]))
        asked = self.record_attempts(beacon)
        self.assertTrue(beacon._egress_act())
        self.assertEqual(asked, ["radio"])

    def test_a_refused_rung_costs_no_budget(self):
        # An attempt spent on a refusal the arithmetic guarantees is an
        # attempt the quieter rungs do not get.
        beacon = self.beacon(hours_dark=4,
                             policy=self.policy([self.rule("radio")]))
        self.record_attempts(beacon)
        for _ in range(5):
            beacon._egress_act()
        self.assertEqual(beacon._egress_spent, 0)

    def test_a_refusal_is_logged_with_its_numbers(self):
        beacon = self.beacon(hours_dark=4,
                             policy=self.policy([self.rule("radio")]))
        self.record_attempts(beacon)
        beacon._egress_act()
        message = "\n".join(self.logged.warnings)
        for needle in ("radio", "rung 3", "way_out_radio"):
            self.assertIn(needle, message)

    def test_an_allowed_attempt_is_logged_with_its_numbers_too(self):
        beacon = self.beacon(hours_dark=5,
                             policy=self.policy([self.rule("radio")]))
        self.record_attempts(beacon)
        beacon._egress_act()
        message = "\n".join(self.logged.warnings)
        for needle in ("rung 3", "way_out_radio", "policy"):
            self.assertIn(needle, message)


if __name__ == "__main__":
    unittest.main()
