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
from software.tests import way_out_scratch as _scratch


class IdentityCase(_decider.DeciderCase):
    def setUp(self):
        super().setUp()
        self.state = _scratch.scratch(self, "raccoon-identity-")

    def beacon(self, hours_dark=24.0, document=True, pre_spent=False,
               **extra):
        beacon = _scratch.assert_live(self, self.a_beacon(
            way_out=read_way_out_policy({"enabled": True,
                                         "state_dir": self.state}),
            **extra))
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

    def test_a_restart_of_the_beacon_does_not_re_arm_it(self):
        # The latch lived only in memory, on a unit with `Restart=always`,
        # for the one move the page says in bold ends this implant's
        # connectivity **for good**. The window's budget was made durable
        # and this was not.
        first = self.beacon()
        self.assertNotIn("[error]", first._exec_egress("identity"))

        restarted = self.beacon()
        answer = restarted._exec_egress("identity")
        self.assertIn("[error]", answer)
        self.assertIn("once", answer)

    def test_a_second_ask_does_not_erase_what_came_of_the_first(self):
        # The second write was a fresh dict over the same path, so it
        # deleted the `taken` and `detail` keys `main.py` had written --
        # destroying the only durable record that the bypass had already
        # been started, which is what an operator reads on a recovered
        # device, and making the scout publish `identity_pre_spent: false`
        # for the rest of the deployment.
        from software.scout.trigger import IdentityTrigger

        self.beacon()._exec_egress("identity")
        IdentityTrigger(self.state).taken("nac_bypass was started")

        self.beacon()._exec_egress("identity")
        record = self.request()
        self.assertEqual(record["detail"], "nac_bypass was started")
        self.assertIn("taken", record)
        self.assertIsNone(IdentityTrigger(self.state).pending())

    def test_a_request_that_could_not_be_written_is_still_spent(self):
        # The file is the latch across restarts, and the flag is the latch
        # when there is no file: a read-only /opt or a full disk must not
        # turn the one irreversible move into one this implant retries
        # every cycle for as long as the outage lasts. Failed for real
        # rather than patched -- a directory at the request's own name,
        # which `os.replace` cannot move a file onto -- because
        # `_way_out_write` raises nothing, so a silent failure and a
        # no-op are the same thing to every caller.
        os.mkdir(handoff.identity_path(self.state))
        beacon = self.beacon()

        self.assertNotIn("[error]", beacon._exec_egress("identity"))
        self.assertIsNone(self.request(), "the write was supposed to fail")

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
    """The poll in `software/main.py`, which owns the component.

    `NACBypass` is patched on **its own module** and not on `main`'s
    namespace, because `main.py` imports it inside the branch that uses
    it -- every component there is imported that way, and this one pulls
    in scapy, so a module-level import would make a build that never
    touches this rung fail to start without it. These tests used
    `create=True` on `main`, which is what let that import be hoisted to
    the top of the file without any of them noticing.
    """

    def config(self, enabled=True, nac=False):
        return {
            "network": {"upstream_iface": "eth0", "downstream_iface": "eth1",
                        "bridge_name": "br0"},
            "nac_bypass": {"enabled": nac},
            "c2": {"way_out": {"enabled": enabled, "state_dir": self.state}},
        }

    def test_importing_main_does_not_import_the_bypass(self):
        # The cost this lazy import exists for, measured rather than
        # asserted about the source: `nac_bypass` pulls in scapy, every
        # other component in `main.py` is imported inside the branch that
        # uses it, and a module-level import would make a build that never
        # touches rung 4 pay for it at startup -- and fail to start at all
        # on an image without scapy. A fresh interpreter, because this one
        # has imported it already.
        import subprocess

        source = ("import sys; import software.main; "
                  "print('software.nac_bypass' in sys.modules)")
        done = subprocess.run(
            [sys.executable, "-c", source], capture_output=True, text=True,
            cwd=str(REPO_ROOT), timeout=120)
        self.assertEqual(done.returncode, 0, done.stderr[-2000:])
        self.assertEqual(done.stdout.strip(), "False",
                         "importing software.main imported nac_bypass, and "
                         "with it scapy, on every build there is")

    def test_a_pending_request_starts_the_bypass_once(self):
        from software import main as main_mod
        from software import nac_bypass as nac_mod
        self.beacon()._exec_egress("identity")
        started = []

        class FakeBypass(object):
            def __init__(self, config):
                started.append(config)

            def start(self):
                started.append("start")

            def stop(self):
                pass

        with mock.patch.object(nac_mod, "NACBypass", FakeBypass):
            poller = main_mod.way_out_identity_poller(self.config())
            self.assertIsNotNone(poller)
            component = poller()
            self.assertIsNotNone(component)
            self.assertIsNone(poller(), "the bypass was started twice")

        self.assertIn("start", started)
        record = handoff.read_document_at(handoff.identity_path(self.state), 1)
        self.assertIn("taken", record)

    def test_a_restart_of_this_process_restores_the_identity(self):
        # `main.py` stops its components on shutdown and `NACBypass.stop()`
        # puts this implant's own MAC back on the bridge, so a reboot, a
        # config change or a `systemctl restart` released an identity the
        # rung had already paid the irreversible price for -- and the
        # one-shot latch kept it from ever being taken again. The implant
        # kept none of the benefit and all of the cost, and going back to
        # its own MAC is the louder of the two states on a port with
        # sticky MAC: a second address on a port that has seen one is what
        # a NAC violation is.
        from software import main as main_mod
        from software import nac_bypass as nac_mod
        self.beacon()._exec_egress("identity")
        started = []

        class FakeBypass(object):
            def __init__(self, config):
                started.append("constructed")

            def start(self):
                started.append("started")

            def stop(self):
                started.append("stopped")

        with mock.patch.object(nac_mod, "NACBypass", FakeBypass):
            first = main_mod.way_out_identity_poller(self.config())
            component = first()
            self.assertIsNotNone(component)
            component.stop()                      # what shutdown does

            del started[:]
            restarted = main_mod.way_out_identity_poller(self.config())
            self.assertIsNotNone(restarted)
            self.assertIsNotNone(restarted(),
                                 "the restarted process left the identity "
                                 "released and the rung spent")

        self.assertEqual(started, ["constructed", "started"])
        # And once per run of this process, not once per second.
        self.assertIsNone(restarted())

    def test_a_request_that_never_started_is_not_retried_on_a_restart(self):
        # The other direction: a taken record whose detail is a failure is
        # not a fact about the switch, and retrying it on every boot is
        # the per-cycle retry the one-shot exists to prevent.
        from software import main as main_mod
        from software import nac_bypass as nac_mod
        self.beacon()._exec_egress("identity")
        with mock.patch.object(nac_mod, "NACBypass",
                               mock.Mock(side_effect=OSError("no ebtables"))):
            main_mod.way_out_identity_poller(self.config())()

        asked = []
        with mock.patch.object(nac_mod, "NACBypass",
                               lambda config: asked.append(1)):
            self.assertIsNone(main_mod.way_out_identity_poller(
                self.config())())
        self.assertEqual(asked, [])
        self.assertIn("no ebtables", self.request()["detail"])

    def test_a_restore_that_fails_does_not_erase_what_was_recorded(self):
        # The record says the identity *was* taken, which is a fact about
        # the switch. A restore that cannot run -- scapy gone, ebtables
        # gone -- must not overwrite it with a failure, or the next run
        # would read "it never started" and the one durable statement
        # about an irreversible move would be lost.
        from software import main as main_mod
        from software import nac_bypass as nac_mod
        self.beacon()._exec_egress("identity")
        IdentityTrigger(self.state).taken("it was started", started=True)

        with mock.patch.object(nac_mod, "NACBypass",
                               mock.Mock(side_effect=OSError("no ebtables"))):
            self.assertIsNone(main_mod.way_out_identity_poller(
                self.config())())

        record = self.request()
        self.assertEqual(record["detail"], "it was started")
        self.assertTrue(record["started"])
        self.assertTrue(IdentityTrigger(self.state).was_started())

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
        from software import nac_bypass as nac_mod
        with mock.patch.object(nac_mod, "NACBypass",
                               mock.Mock(side_effect=AssertionError)):
            poller = main_mod.way_out_identity_poller(self.config())
            self.assertIsNone(poller())

    def test_a_bypass_that_raises_is_recorded_and_does_not_escape(self):
        # This runs in `main.py`'s one-second loop, which has no guard: an
        # exception here would take the whole implant down.
        from software import main as main_mod
        from software import nac_bypass as nac_mod
        self.beacon()._exec_egress("identity")
        with mock.patch.object(nac_mod, "NACBypass",
                               mock.Mock(side_effect=OSError("no ebtables"))):
            poller = main_mod.way_out_identity_poller(self.config())
            self.assertIsNone(poller())
        record = handoff.read_document_at(handoff.identity_path(self.state), 1)
        self.assertIn("no ebtables", record["detail"])


if __name__ == "__main__":
    unittest.main()
