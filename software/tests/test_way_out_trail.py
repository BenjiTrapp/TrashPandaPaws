#!/usr/bin/env python3
"""The trail, written by the one process that knows an attempt happened.

It was the scout's: the beacon recorded each attempt into the window's own
file, and the scout copied new lines onto an append-only trail on its own
clock. A review measured what that cost -- **every attempt in the last
publishing interval of a window was lost for ever**, because a leg
delivering removes the window's file before the next publish, and the lost
line is the last one, which on a recovered implant is the attempt that
worked. A scout restart mid-window duplicated the lines it had already
copied.

So the beacon appends the trail line itself, in the same call that records
the attempt. It is the only process that knows an attempt was made, it is
already writing in that directory, and the file is append-only -- which
makes a restart of either side harmless.

What the scout still does with the trail: nothing. It reads the window for
its own evidence and publishes; the trail is not its business any more.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.c2.beacon import read_way_out_policy
from software.scout import handoff
from software.scout.scout import Scout
from software.tests import test_egress_decider as _decider
from software.tests import way_out_scratch as _scratch


class TrailCase(_decider.DeciderCase):
    POLICY = {"enabled": True, "budget": 4,
              "rules": [{"when": {"https": ["not_attempted"]},
                         "try": "gsocket"}]}

    def setUp(self):
        super().setUp()
        self.state = _scratch.scratch(self, "raccoon-trail-")

    def beacon(self, hours_dark=24.0, policy=None):
        # The carrier on, because this class's policy names `gsocket`
        # and a `gsocket` rule on a build with no carrier is dropped when
        # the policy is read -- the refusal is one the build guarantees,
        # and it would have cost an attempt of the budget every cycle.
        beacon = _scratch.assert_live(self, self.a_beacon(
            policy=policy if policy is not None else self.POLICY,
            gsocket=True,
            way_out=read_way_out_policy({"enabled": True,
                                         "state_dir": self.state})))
        beacon._stuck_cycles = int(hours_dark * 12)
        beacon._exec_egress = lambda task: "recorded"
        return beacon

    def trail(self):
        path = handoff.trail_path(self.state)
        if not os.path.exists(path):
            return []
        return [json.loads(line)
                for line in Path(path).read_text().splitlines()]


class TestTheBeaconKeepsIt(TrailCase):
    def test_an_attempt_is_on_the_trail_the_moment_it_is_made(self):
        beacon = self.beacon()
        beacon._way_out_publish_state()
        self.assertTrue(beacon._egress_act())
        self.assertEqual([line["verb"] for line in self.trail()], ["gsocket"])

    def test_a_leg_delivering_does_not_take_the_last_line_with_it(self):
        # The loss the scout's copy could not avoid: the window's file is
        # removed when a leg delivers, and on a recovered implant the
        # line that was about to be copied is the attempt that worked.
        beacon = self.beacon()
        beacon._way_out_publish_state()
        beacon._egress_act()
        beacon._leg_recovered()

        self.assertIsNone(handoff.read_state(self.state))
        self.assertEqual([line["verb"] for line in self.trail()], ["gsocket"])

    def test_every_attempt_of_a_window_is_there_once(self):
        beacon = self.beacon(policy={
            "enabled": True, "budget": 4,
            "rules": [{"when": {"https": ["not_attempted"]},
                       "try": "gsocket"},
                      {"when": {"https": ["not_attempted"]},
                       "try": "rediscover"}]})
        beacon._way_out_publish_state()
        for _ in range(3):
            beacon._egress_act()
        self.assertEqual([line["verb"] for line in self.trail()],
                         ["gsocket", "gsocket", "gsocket"])

    def test_a_restart_of_the_beacon_appends_rather_than_repeats(self):
        first = self.beacon()
        first._way_out_publish_state()
        first._egress_act()

        restarted = self.beacon()
        restarted._way_out_publish_state()
        restarted._egress_act()
        self.assertEqual([line["verb"] for line in self.trail()],
                         ["gsocket", "gsocket"])

    def test_each_line_says_what_drove_it(self):
        beacon = self.beacon()
        beacon._way_out_publish_state()
        beacon._egress_act()
        line = self.trail()[0]
        for key in ("at", "verb", "argument", "task", "chose", "rule",
                    "why", "gate", "spent", "budget", "evidence", "outcome"):
            self.assertIn(key, line, key)
        self.assertEqual(line["chose"], "policy")
        self.assertEqual(line["gate"]["row"], "way_out_borrow")

    def test_the_trail_is_private(self):
        beacon = self.beacon()
        beacon._way_out_publish_state()
        beacon._egress_act()
        self.assertEqual(
            os.stat(handoff.trail_path(self.state)).st_mode & 0o777, 0o600)

    def test_it_holds_no_secret(self):
        beacon = self.beacon()
        handoff.write_borrow(self.state, {"credentials": [
            {"kind": "proxy-basic", "user": "corp\\alice",
             "secret": "s3cret", "where": "10.0.0.1:3128"}]})
        beacon._exec_egress = lambda task: beacon.__class__._exec_egress(
            beacon, task)
        beacon._way_out_publish_state()
        beacon._egress_act()
        text = Path(handoff.trail_path(self.state)).read_text()
        self.assertNotIn("s3cret", text)

    def test_a_trail_that_cannot_be_written_costs_the_attempt_nothing(self):
        beacon = self.beacon(policy=self.POLICY)
        beacon._way_out_publish_state()
        # A path that is a file, so every write below it fails.
        broken = os.path.join(self.state, handoff.TRAIL_NAME)
        os.makedirs(broken)
        self.assertTrue(beacon._egress_act())
        self.assertEqual(beacon._egress_spent, 1)

    def test_with_the_feature_off_there_is_no_trail(self):
        beacon = self.a_beacon(
            policy=self.POLICY,
            way_out=read_way_out_policy({"enabled": False,
                                         "state_dir": self.state}))
        beacon._exec_egress = lambda task: "recorded"
        beacon._stuck_cycles = 2
        beacon._egress_act()
        self.assertEqual(os.listdir(self.state), [])


class TestTheScoutNoLongerCopiesIt(TrailCase):
    def test_a_publish_adds_no_trail_line(self):
        beacon = self.beacon()
        beacon._way_out_publish_state()
        beacon._egress_act()
        before = self.trail()

        scout = Scout({"network": {"bridge_name": "br0"},
                       "c2": {"way_out": {"enabled": True,
                                          "state_dir": self.state}}},
                      self.state)
        self.addCleanup(scout.stop)
        scout._scan_ssids = lambda: []
        self.assertIsNotNone(scout.publish_once())
        self.assertEqual(self.trail(), before)

    def test_a_scout_restart_cannot_duplicate_anything(self):
        beacon = self.beacon()
        beacon._way_out_publish_state()
        beacon._egress_act()
        for _ in range(3):
            scout = Scout({"network": {"bridge_name": "br0"},
                           "c2": {"way_out": {"enabled": True,
                                              "state_dir": self.state}}},
                          self.state)
            self.addCleanup(scout.stop)
            scout._scan_ssids = lambda: []
            scout.publish_once()
        self.assertEqual(len(self.trail()), 1)


if __name__ == "__main__":
    unittest.main()
