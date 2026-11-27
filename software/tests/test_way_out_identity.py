#!/usr/bin/env python3
"""Rung 4: take an identity -- which this repository already does.

`software/nac_bypass.py` forwards EAPOL so the downstream device stays
authenticated, learns its MAC, IP and the gateway's MAC from the bridge,
and then originates the implant's own traffic under that identity. It
ships `enabled: false` and is started as a component of `main.py`.

So rung 4 is **a trigger, not an implementation**. The predecessor design
ruled a NAC verb out because *"a cross-process trigger is a mechanism this
repository does not have"*; this project builds that mechanism for its own
reasons, which is what makes the rung affordable.

Three properties, and each is a test here:

  * **One-shot per deployment.** A move that can turn the port off does
    not get retried on a hunch, however the arithmetic looks next cycle.
    A delivering leg does **not** re-arm it.
  * **Pre-spent when the operator already enabled the bypass.** With
    `nac_bypass.enabled: true` the identity was taken at boot, and the
    scout reads that rather than letting the rung be offered twice.
  * **Not offered at all without a fresh scout document**, because the
    pre-spent fact lives in it. The safe default of an unknown is not to
    make the one irreversible move.

This is still the rung that can **turn the port off**: sticky MAC, port
security or a NAC violation ends this implant's connectivity for good,
with nobody's hand on the device. The human chose that trade explicitly:
dark is useless.
"""

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.c2 import beacon as beacon_mod
from software.c2.beacon import read_way_out_policy
from software.scout import handoff
from software.scout.trigger import IdentityTrigger
from software.tests import test_egress_decider as _decider
from software.tests import way_out_scratch


class IdentityCase(_decider.DeciderCase):
    def setUp(self):
        super().setUp()
        self.state = way_out_scratch("raccoon-identity-")
        self.addCleanup(shutil.rmtree, self.state, ignore_errors=True)

    def beacon(self, hours_dark=24.0, document=True, pre_spent=False,
               **extra):
        beacon = self.a_beacon(
            way_out=read_way_out_policy({"enabled": True,
                                         "state_dir": self.state}),
            **extra)
        beacon._stuck_cycles = int(hours_dark * 12)
        if document:
            handoff.write_document(self.state, {
                "version": handoff.DOCUMENT_VERSION,
                "published": time.time(),
                "evidence": beacon._egress_state(),
                "tap": {"flags": []},
                "identity_pre_spent": pre_spent,
                "recommendation": None})
        return beacon

    def request(self):
        return handoff.read_document_at(handoff.identity_path(self.state), 1)


class TestTheVerb(IdentityCase):
    def test_it_writes_one_request_and_says_what_it_asked_for(self):
        beacon = self.beacon()
        answer = beacon._exec_egress("identity")

        self.assertNotIn("[error]", answer)
        request = self.request()
        self.assertIsNotNone(request, "no request file was written")
        self.assertIn("requested", request)
        self.assertIn("nac_bypass", answer)
        self.assertIn("Not a test", answer)

    def test_the_request_file_is_private(self):
        self.beacon()._exec_egress("identity")
        self.assertEqual(
            os.stat(handoff.identity_path(self.state)).st_mode & 0o777,
            0o600)

    def test_a_second_attempt_is_refused_as_spent(self):
        beacon = self.beacon()
        self.assertNotIn("[error]", beacon._exec_egress("identity"))
        answer = beacon._exec_egress("identity")
        self.assertIn("[error]", answer)
        self.assertIn("once", answer)

    def test_a_delivering_leg_does_not_re_arm_it(self):
        beacon = self.beacon()
        beacon._exec_egress("identity")
        beacon._leg_recovered()
        self.assertIn("[error]", beacon._exec_egress("identity"))

    def test_an_operator_who_already_enabled_the_bypass_has_spent_it(self):
        beacon = self.beacon(pre_spent=True)
        answer = beacon._exec_egress("identity")
        self.assertIn("[error]", answer)
        self.assertIn("nac_bypass.enabled", answer)
        self.assertIsNone(self.request())

    def test_without_a_fresh_document_it_is_not_offered(self):
        beacon = self.beacon(document=False)
        answer = beacon._exec_egress("identity")
        self.assertIn("[error]", answer)
        self.assertIn("scout", answer)
        self.assertIsNone(self.request())

    def test_a_stale_document_is_no_document(self):
        beacon = self.beacon(document=False)
        handoff.write_document(self.state, {
            "version": handoff.DOCUMENT_VERSION,
            "published": time.time() - 100000,
            "evidence": beacon._egress_state(), "tap": {"flags": []},
            "identity_pre_spent": False, "recommendation": None})
        self.assertIn("[error]", beacon._exec_egress("identity"))

    def test_the_gate_still_decides_whether_it_may_be_taken(self):
        # The verb's own latch is about *how often*; the arithmetic is
        # about *when*. One does not stand in for the other.
        beacon = self.beacon(hours_dark=1)
        allowed, numbers = beacon._way_out_allows("identity")
        self.assertFalse(allowed)
        self.assertEqual(numbers["rung"], 4)


class TestTheTrigger(IdentityCase):
    """`main.py`'s side: the component that owns `NACBypass`."""

    def test_nothing_pending_answers_none(self):
        self.assertIsNone(IdentityTrigger(self.state).pending())

    def test_a_request_is_pending_until_it_is_taken(self):
        beacon = self.beacon()
        beacon._exec_egress("identity")
        trigger = IdentityTrigger(self.state)

        self.assertIsNotNone(trigger.pending())
        # Still pending on a second look: `main.py` could be restarted
        # between reading the request and acting on it, and a request that
        # cleared itself on being read would be a rung spent on nothing.
        self.assertIsNotNone(trigger.pending())

        trigger.taken("the bypass was started")
        self.assertIsNone(trigger.pending())
        self.assertIsNone(IdentityTrigger(self.state).pending())

    def test_what_happened_is_recorded_for_the_scout_to_read(self):
        self.beacon()._exec_egress("identity")
        trigger = IdentityTrigger(self.state)
        trigger.taken("the bypass was started")
        record = handoff.read_document_at(handoff.identity_path(self.state), 1)
        self.assertEqual(record["detail"], "the bypass was started")
        self.assertIn("taken", record)

    def test_rubbish_in_the_request_file_is_nothing_pending(self):
        for text in ("", "{not json", "[]", '{"version": 99}'):
            with self.subTest(text=text):
                Path(handoff.identity_path(self.state)).write_text(text)
                self.assertIsNone(IdentityTrigger(self.state).pending())

    def test_an_unwritable_directory_is_nothing_pending(self):
        trigger = IdentityTrigger(os.path.join(self.state, "nope", "deeper"))
        self.assertIsNone(trigger.pending())
        trigger.taken("nothing to record")


class TestMainStartsTheBypassOnRequest(IdentityCase):
    """The poll in `software/main.py`, which owns the component."""

    def config(self, enabled=True, nac=False):
        return {
            "network": {"upstream_iface": "eth0", "downstream_iface": "eth1",
                        "bridge_name": "br0"},
            "nac_bypass": {"enabled": nac},
            "c2": {"way_out": {"enabled": enabled, "state_dir": self.state}},
        }

    def test_a_pending_request_starts_the_bypass_once(self):
        from software import main as main_mod
        self.beacon()._exec_egress("identity")
        started = []

        class FakeBypass(object):
            def __init__(self, config):
                started.append(config)

            def start(self):
                started.append("start")

            def stop(self):
                pass

        with mock.patch.object(main_mod, "NACBypass", FakeBypass,
                               create=True):
            poller = main_mod.way_out_identity_poller(self.config())
            self.assertIsNotNone(poller)
            component = poller()
            self.assertIsNotNone(component)
            self.assertIsNone(poller(), "the bypass was started twice")

        self.assertIn("start", started)
        record = handoff.read_document_at(handoff.identity_path(self.state), 1)
        self.assertIn("taken", record)

    def test_with_the_way_out_off_there_is_no_poller_at_all(self):
        from software import main as main_mod
        self.assertIsNone(main_mod.way_out_identity_poller(
            self.config(enabled=False)))

    def test_with_the_bypass_already_configured_there_is_no_poller(self):
        # It is running as a component of this process already, so the
        # identity is taken and the rung is pre-spent.
        from software import main as main_mod
        self.assertIsNone(main_mod.way_out_identity_poller(
            self.config(nac=True)))

    def test_no_request_starts_nothing(self):
        from software import main as main_mod
        with mock.patch.object(main_mod, "NACBypass",
                               mock.Mock(side_effect=AssertionError),
                               create=True):
            poller = main_mod.way_out_identity_poller(self.config())
            self.assertIsNone(poller())

    def test_a_bypass_that_raises_is_recorded_and_does_not_escape(self):
        # This runs in `main.py`'s one-second loop, which has no guard: an
        # exception here would take the whole implant down.
        from software import main as main_mod
        self.beacon()._exec_egress("identity")
        with mock.patch.object(main_mod, "NACBypass",
                               mock.Mock(side_effect=OSError("no ebtables")),
                               create=True):
            poller = main_mod.way_out_identity_poller(self.config())
            self.assertIsNone(poller())
        record = handoff.read_document_at(handoff.identity_path(self.state), 1)
        self.assertIn("no ebtables", record["detail"])


if __name__ == "__main__":
    unittest.main()
