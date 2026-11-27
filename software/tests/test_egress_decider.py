#!/usr/bin/env python3
"""The decider: what an implant that cannot get out tries on its own.

`software/agent/tools/egress.py` is what decides which attempt a stuck
beacon should make next, and it sits on the far side of exactly the
connection that attempt is trying to establish. Today the hole is covered
by DNS -- the rescue record goes out as a TXT query and the answer comes
back the same way -- which needs a resolver that answers and somebody, or
some model, watching. This file is about the case where neither is true:
the implant choosing one of its three `egress` verbs for itself, from the
same evidence, inside a boundary it cannot leave.

The boundary is four things, and each has a test below:

  * **the verbs are the three the beacon has and nothing else.** The
    policy chooses from a fixed list and orders it; it cannot add to it,
    and a build whose `c2.proxy.mode` is `none` has two of the three
    refused to its decider as they are to its tasking.
  * **never on the first stuck cycle.** The operator's decision: when the
    team server can be reached, the team server decides. An implant that
    acted immediately would always have moved before the server had even
    been told it was stuck.
  * **one attempt per cycle, never a sweep** -- `egress.py`'s own rule,
    for its own reason: a dozen attempts from a device impersonating an
    IP phone is louder than the single short query that reported the
    problem.
  * **a budget per stuck window**, after which the implant is silent and
    the rescue record does its job. Going quiet is not giving up; it is
    handing the decision back.

What these tests are careful about.

**The default is a test too.** The decider ships disabled, and with it
disabled the gsocket leg's latch has to start the carrier on the first
stuck cycle exactly as it does today -- a latch sitting behind a disabled
decider would simply stop that leg working in the shipped configuration.
`test_gsocket_leg.py`'s latch assertions describe that case and are left
untouched; the two tests here about the disabled path are a second,
narrower reading of the same promise.

**The policy comes through the real reader.** Every block below is passed
through `read_egress_policy`, which is what `beacon_config_from_fallback`
does, so these tests fail if the shape that reader produces and the shape
the decider consumes ever stop being the same shape.

**The verbs are recorded, not run, except where the carrier is the
subject.** `test_egress_verbs.py` drives all three against a real proxy
and a real child; what is under test *here* is which verb a policy picks,
on which cycle, and how many times -- so most tests record what the
decider asked `egress` to do. The latch tests are the exception: they
spawn the shipped stand-in, `software/tests/data/fake_gs_netcat.sh`,
because whether a carrier came up is the behaviour they are about.

**Nothing here reaches a network and nothing joins the Global Socket Relay
Network.** Every leg is off unless a test turns one on, the one DNS
resolver is a stand-in for `_dns_query`, and discovery is never run: the
candidates a proxy rule selects from are written into `ProxyDiscovery`'s
own list.

**No orphans.** Every beacon is torn down through `_gsocket_stop`, which
takes the carrier's child with it.
"""

import base64
import logging
import os
import shutil
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.c2 import beacon as beacon_mod
from software.c2.beacon import Beacon, read_egress_policy

FAKE_GS_NETCAT = Path(__file__).resolve().parent / "data" / "fake_gs_netcat.sh"

_KEY = b"\x24" * 32
_CLASSES = beacon_mod._RESCUE_CLASSES

# A rule that holds on every beacon built below: nothing tried the HTTPS
# leg, and the record carries `not_attempted` for a leg nothing tried --
# which is what `_rescue_pack` packs for it and what the team server
# renders in the panel.
_HOLDS = {"when": {"https": ["not_attempted"]}, "try": "rediscover"}
# ...and one that cannot hold on such a beacon: a leg nothing tried cannot
# have been refused credentials.
_NEVER = {"when": {"https": ["auth_required"]}, "try": "proxy"}


def _free_port() -> int:
    """A port that was free a moment ago."""
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def _alive(pid: int) -> bool:
    """Whether `pid` exists, without reaping or signalling it."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class _Collected(logging.Handler):
    """Every record the beacon's logger emitted, in order.

    The idiom `test_egress_policy.py` uses, here for one further reason:
    an attempt is reported as a warning, and a suite that let those
    propagate would print an implant's autonomous decisions into its own
    output. `assertLogs` also cannot say "and nothing more was logged" --
    it fails when nothing was logged at all, and `assertNoLogs` arrived in
    3.10 while this repository is on 3.9 -- and "the disabled decider said
    nothing" is a claim about the count zero.
    """

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)

    @property
    def warnings(self):
        return [record.getMessage() for record in self.records
                if record.levelno >= logging.WARNING]


class DeciderCase(unittest.TestCase):
    """A beacon with a policy, driven through the real `_beacon_loop`."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="raccoon-egress-decider-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self._beacons = []
        self.addCleanup(self._stop_beacons)

        self.secret_file = os.path.join(self.root, "gsocket-secret")
        with open(self.secret_file, "w") as handle:
            handle.write("Th1s-Is-N0t-A-Real-Secret\n")
        os.chmod(self.secret_file, 0o600)

        # Copied rather than referenced, as the leg's own suite does: a
        # test that edited the file in the repository would be a test that
        # broke the next one.
        self.binary = os.path.join(self.root, "gs-netcat")
        shutil.copy(FAKE_GS_NETCAT, self.binary)
        os.chmod(self.binary, 0o755)

        # So that "no carrier at all" can be asserted as "nothing was ever
        # spawned" rather than as "something was spawned and not used".
        self.argv_file = os.path.join(self.root, "argv.txt")
        recording = mock.patch.dict(
            os.environ, {"FAKE_GS_NETCAT_ARGV_FILE": self.argv_file})
        recording.start()
        self.addCleanup(recording.stop)

        self.logged = _Collected()
        logger = beacon_mod.logger
        propagate = logger.propagate
        logger.addHandler(self.logged)
        logger.propagate = False

        def restore():
            logger.removeHandler(self.logged)
            logger.propagate = propagate

        self.addCleanup(restore)

    # ── the beacons ──

    def policy(self, rules, budget=3, enabled=True) -> dict:
        """The block an operator writes, as `c2.egress_decider`."""
        return {"enabled": enabled, "budget": budget, "rules": list(rules)}

    def a_beacon(self, policy=None, gsocket=False, proxy_mode="auto",
                 **transports) -> Beacon:
        """A beacon with every leg off but what a test turns on.

        `policy` is the operator's block and goes through the reader the
        config loader uses, so what the decider gets here is what it gets
        on a drop-box. None is a deployment that predates the feature.
        """
        leg = {"enabled": False}
        if gsocket:
            leg = {"enabled": True, "secret_file": self.secret_file,
                   "binary_path": self.binary, "local_port": _free_port()}
        config = {"c2": {
            "beacon_interval_seconds": 300,
            "jitter_percent": 0,
            "encryption_key": base64.b64encode(_KEY).decode(),
            "proxy": {"mode": proxy_mode},
            "https": {"enabled": False},
            "dns": {"enabled": False, "domain": "rescue.example",
                    "resolver": "127.0.0.1"},
            "smb": {"enabled": False},
            "quic": {"enabled": False},
            "gsocket": leg,
            "egress_decider": read_egress_policy(policy),
        }}
        config["c2"].update(transports)
        beacon = Beacon(config)
        self._beacons.append(beacon)
        return beacon

    def _stop_beacons(self):
        for beacon in self._beacons:
            beacon._running = False
            beacon._gsocket_stop()

    # ── driving it ──

    def run_cycles(self, beacon: Beacon, count: int = 1, query=None):
        """Run `count` real passes of `_beacon_loop`.

        The loop is not stood in for: only the two sleeps at the bottom of
        it are, which is how the leg's suite and `test_dns_rescue.py` each
        drive a check-in. `query` stands in for `_dns_query` where a test
        needs a resolver that answers.
        """
        seen = {"n": 0}

        def sleep(*_args, **_kwargs):
            seen["n"] += 1
            if seen["n"] >= count:
                beacon._running = False

        patches = [
            mock.patch.object(beacon, "_jittered_sleep", side_effect=sleep),
            mock.patch.object(beacon, "_backoff_sleep", side_effect=sleep),
        ]
        if query is not None:
            patches.append(mock.patch.object(beacon_mod, "_dns_query", query))
        beacon._running = True
        for patcher in patches:
            patcher.start()
        try:
            beacon._beacon_loop()
        finally:
            for patcher in patches:
                patcher.stop()

    def record_attempts(self, beacon: Beacon, answer="recorded") -> list:
        """What the decider asked `egress` to do, without doing it.

        The dispatch boundary and not an internal one: what is recorded is
        the task string an operator would have typed, which is the whole
        of what the decider decided.
        """
        asked = []

        def record(args):
            asked.append(args)
            return answer

        patcher = mock.patch.object(beacon, "_exec_egress", record)
        patcher.start()
        self.addCleanup(patcher.stop)
        return asked

    def a_resolver_that_answers(self, rescue_answer=None):
        """A `_dns_query` stand-in: the resolver answers, the rescue may too.

        The pattern `test_dns_rescue.py` uses for the same purpose. The
        ordinary tasking query answers with nothing queued, which is what
        sets `dns_answered` and therefore the one condition `_maybe_rescue`
        insists on; the rescue query answers with `rescue_answer`.
        """
        sent = []

        def query(name, qtype, server, timeout=10, status=None,
                  source=""):
            if status is not None:
                status["rcode"] = 0
            if "." + beacon_mod._RESCUE_MARKER + "." in name:
                sent.append(name)
                return [rescue_answer] if rescue_answer else []
            return []

        return query, sent

    # ── readings ──

    def child_pid(self, beacon: Beacon) -> int:
        proc = beacon._gsocket_proc
        self.assertIsNotNone(proc, "no carrier was started")
        return proc.pid

    def assertNoCarrier(self, beacon: Beacon):
        self.assertIsNone(beacon._gsocket_proc,
                          "a carrier was started")
        self.assertFalse(os.path.exists(self.argv_file),
                         "a gs-netcat was spawned")

    def assertCarrierUp(self, beacon: Beacon):
        self.assertTrue(_alive(self.child_pid(beacon)),
                        "the carrier's child is not running")


class TestWhenItMayAct(DeciderCase):
    """The operator's decision: the server decides while it can be reached."""

    def test_it_does_not_act_on_the_first_stuck_cycle(self):
        # The operator's decision, and the reason is the non-goal: when the
        # server can be reached, the server decides. An implant that acted
        # on the cycle that discovered the outage would always have moved
        # before the team server had even been told, and the two deciders
        # would race on every drop.
        beacon = self.a_beacon(policy=self.policy([_HOLDS]))
        asked = self.record_attempts(beacon)

        self.run_cycles(beacon, 1)

        self.assertEqual(asked, [])
        self.assertEqual(beacon._stuck_cycles, 1)
        self.assertEqual(beacon._egress_spent, 0)
        self.assertEqual(self.logged.warnings, [])

    def test_it_acts_from_the_second_stuck_cycle(self):
        beacon = self.a_beacon(policy=self.policy([_HOLDS]))
        asked = self.record_attempts(beacon)

        self.run_cycles(beacon, 2)

        self.assertEqual(asked, ["rediscover"])
        self.assertEqual(beacon._stuck_cycles, 2)
        self.assertEqual(beacon._egress_spent, 1)

    def test_it_does_not_act_while_rescue_tasking_arrived_in_this_window(self):
        # `_maybe_rescue` brought something back, so the server is
        # reachable and it is deciding. For the whole window and not only
        # for that cycle: the rescue is one query per window, so the answer
        # it carried is the team server's instruction for all of it.
        beacon = self.a_beacon(
            policy=self.policy([_HOLDS]),
            dns={"enabled": True, "domain": "rescue.example",
                 "resolver": "127.0.0.1"})
        asked = self.record_attempts(beacon)
        ran = []
        query, sent = self.a_resolver_that_answers(
            rescue_answer=beacon._encrypt({"cmd": "shell id"}))

        with mock.patch.object(beacon, "_process_tasking_batch", ran.append):
            self.run_cycles(beacon, 3, query=query)

        self.assertEqual(len(sent), 1, "no rescue went out, so this proves "
                                       "nothing")
        self.assertEqual(ran, [{"cmd": "shell id"}],
                         "the rescue's answer never reached the loop")
        self.assertEqual(asked, [])
        self.assertEqual(beacon._egress_spent, 0)

    def test_it_acts_when_the_rescue_could_not_even_be_sent(self):
        # The case this whole feature exists for: nothing can leave, so
        # there is nothing to be told what to try. `_maybe_rescue` returns
        # None on every cycle without sending anything -- with no DNS leg
        # at all, or with a resolver that never answered -- and
        # `beacon.py`'s own comment says that is precisely the state a
        # decider on the drop-box would be for.
        #
        # Still the *second* stuck cycle. A cycle has to have passed
        # without an answer, and a cycle on which the rescue could not even
        # be sent is such a cycle.
        cases = {
            "no dns leg to carry it": {},
            "a resolver that says SERVFAIL": {
                "dns": {"enabled": True, "domain": "rescue.example",
                        "resolver": "127.0.0.1"}},
        }

        def servfail(name, qtype, server, timeout=10, status=None):
            if status is not None:
                status["rcode"] = 2
            return []

        for label, transports in cases.items():
            with self.subTest(case=label):
                beacon = self.a_beacon(policy=self.policy([_HOLDS]),
                                       **transports)
                asked = self.record_attempts(beacon)

                self.run_cycles(beacon, 1, query=servfail)
                self.assertEqual(asked, [], "it acted on the first cycle")

                self.run_cycles(beacon, 1, query=servfail)
                self.assertEqual(asked, ["rediscover"])
                self.assertFalse(beacon._rescue_sent,
                                 "a rescue went out, so this is not the case "
                                 "the test is about")

    def test_it_acts_when_the_reachable_server_answered_the_rescue_empty(self):
        # The one boundary the whole design turns on, and the only reading
        # of "the server decides" that is a decision. The resolver answers
        # and the rescue reaches a server that has nothing queued, so the
        # tasking route hands back an encrypted body that decrypts to `{}`
        # on purpose -- the route is not an existence oracle. That body is
        # falsy, so `_rescue_answered` stays False and the decider acts
        # from the second stuck cycle, exactly as it does when the rescue
        # could not be sent at all.
        #
        # This is the correct semantics, not a gap: an answer that carries
        # no instruction *is* nothing brought back, and a server with an
        # empty queue has decided nothing -- while `try_egress` can still
        # override the moment it decides something. The sibling test above
        # pins the opposite side, a non-empty answer that holds the window;
        # between the two this case had no test, and it is the one an
        # off-by-one in the falsiness check would silently flip.
        beacon = self.a_beacon(
            policy=self.policy([_HOLDS]),
            dns={"enabled": True, "domain": "rescue.example",
                 "resolver": "127.0.0.1"})
        asked = self.record_attempts(beacon)
        query, sent = self.a_resolver_that_answers(
            rescue_answer=beacon._encrypt({}))

        self.run_cycles(beacon, 1, query=query)
        self.assertEqual(asked, [], "it acted on the first stuck cycle")
        self.assertEqual(len(sent), 1, "no rescue went out, so this proves "
                                       "nothing")
        self.assertFalse(beacon._rescue_answered,
                         "an empty answer was read as the server deciding")

        self.run_cycles(beacon, 1, query=query)
        self.assertEqual(asked, ["rediscover"])
        self.assertEqual(beacon._egress_spent, 1)
        self.assertEqual(beacon._stuck_cycles, 2)


class TestHowMuchItMayDo(DeciderCase):
    """One attempt per cycle, and a budget per stuck window."""

    def test_one_attempt_per_cycle_and_never_a_sweep(self):
        # `egress.py`'s rule and its reason: a dozen attempts from a device
        # impersonating an IP phone is louder than the single short query
        # that reported the problem. Three rules hold here, and a cycle
        # takes the first one of them and stops.
        rules = [_HOLDS,
                 {"when": {"any": ["not_attempted"]}, "try": "gsocket"},
                 {"when": {"https": ["not_attempted"]}, "try": "proxy"}]
        beacon = self.a_beacon(policy=self.policy(rules))
        asked = self.record_attempts(beacon)

        self.run_cycles(beacon, 2)
        self.assertEqual(asked, ["rediscover"], "a cycle swept the policy")

        self.run_cycles(beacon, 1)
        self.assertEqual(asked, ["rediscover", "rediscover"],
                         "the next cycle did not get its one attempt")

    def test_the_budget_is_spent_and_then_it_is_silent(self):
        # And silent is not the same as giving up: the rescue record still
        # reports a stuck implant, so `try_egress` on the server can still
        # act the moment DNS reaches it. The implant has handed the
        # decision back.
        beacon = self.a_beacon(policy=self.policy([_HOLDS], budget=2))
        asked = self.record_attempts(beacon)

        self.run_cycles(beacon, 6)

        self.assertEqual(asked, ["rediscover", "rediscover"])
        self.assertEqual(beacon._egress_spent, 2)
        self.assertEqual(beacon._stuck_cycles, 6)

    def test_an_upstream_leg_delivering_closes_the_window(self):
        # The stuck counter and the budget both reset, so the next window
        # starts unspent and still may not act on its own first cycle. The
        # budget is one, so a spend that survived the recovery would leave
        # the second window silent for ever.
        beacon = self.a_beacon(
            policy=self.policy([_HOLDS], budget=1),
            https={"enabled": True,
                   "callback_url": "http://127.0.0.1:1/api/v1/beacon"})
        # Registration is not what this test is about, and an HTTPS leg
        # that cannot register walks ten attempts through the same sleep
        # the cycle counter watches.
        beacon._registered = True
        asked = self.record_attempts(beacon)
        cycle = {"n": 0}

        def https():
            # Delivers on the third cycle and on no other.
            return {} if cycle["n"] == 2 else None

        def sleep(*_args, **_kwargs):
            cycle["n"] += 1
            if cycle["n"] >= 5:
                beacon._running = False

        beacon._running = True
        with mock.patch.object(beacon, "_beacon_https", https), \
                mock.patch.object(beacon, "_jittered_sleep", side_effect=sleep), \
                mock.patch.object(beacon, "_backoff_sleep", side_effect=sleep):
            beacon._beacon_loop()

        # Cycle 2 spent the window's one attempt; cycle 3 delivered and
        # closed it; cycle 4 is the new window's first and may not act;
        # cycle 5 may, and has an unspent budget to do it with.
        self.assertEqual(asked, ["rediscover", "rediscover"])
        self.assertEqual(beacon._stuck_cycles, 2)
        self.assertEqual(beacon._egress_spent, 1)


class TestTheRuleThatWins(DeciderCase):
    """The policy is the operator's order, and the first match is it."""

    def _evidence(self, beacon):
        """What the loop's stuck branch sees after a dead cycle."""
        beacon._start_cycle()
        beacon._record_leg("https", _CLASSES["auth_required"], 407)
        beacon._record_leg("quic", _CLASSES["timed_out"])
        beacon._rescue_flags |= beacon_mod._RESCUE_FLAG_PROXY_FOUND

    def test_the_first_matching_rule_wins(self):
        rules = [
            {"when": {"https": ["timed_out"]}, "try": "gsocket"},
            {"when": {"flags": ["proxy_found"]}, "try": "proxy"},
            {"when": {"https": ["auth_required"]}, "try": "rediscover"},
        ]
        beacon = self.a_beacon(policy=self.policy(rules))
        self._evidence(beacon)

        self.assertEqual(beacon._egress_decide(), "proxy")

        # The operator's order and not a preference between verbs: the same
        # three rules, the last two swapped, answer with the other one.
        reordered = self.a_beacon(
            policy=self.policy([rules[0], rules[2], rules[1]]))
        self._evidence(reordered)
        self.assertEqual(reordered._egress_decide(), "rediscover")

    def test_no_matching_rule_means_no_attempt(self):
        # Which is the same as being disabled for that cycle, and says so
        # by doing nothing at all rather than by falling back to a verb.
        beacon = self.a_beacon(policy=self.policy([_NEVER]))
        asked = self.record_attempts(beacon)

        self.assertIsNone(beacon._egress_decide())
        self.run_cycles(beacon, 3)

        self.assertEqual(asked, [])
        self.assertEqual(beacon._egress_spent, 0)

    def test_a_rule_holds_only_when_every_key_of_its_when_does(self):
        # `read_egress_policy`'s reading, which is this matcher's contract:
        # several keys at once are all of them, because adding a key can
        # then only narrow -- the reading that cannot surprise somebody who
        # is not there to be surprised.
        both = {"when": {"https": ["auth_required"], "quic": ["timed_out"]},
                "try": "gsocket"}
        one_wrong = {"when": {"https": ["auth_required"], "quic": ["refused"]},
                     "try": "proxy"}
        beacon = self.a_beacon(policy=self.policy([one_wrong, both]))
        self._evidence(beacon)

        self.assertEqual(beacon._egress_decide(), "gsocket")


class TestTheGateTheOperatorCannotWiden(DeciderCase):
    """`c2.proxy.mode: none` is an instruction, not an absence of one."""

    def test_a_build_that_forbids_proxies_drops_the_rules_naming_them(self):
        # The same prohibition the two verbs enforce against tasking, here
        # against the decider's budget: an attempt spent on a refusal the
        # build guarantees is an attempt the carrier does not get. Said
        # once, when the policy is read, because that is while an operator
        # may still have a connection to read it over.
        rules = [{"when": {"https": ["not_attempted"]}, "try": "proxy"},
                 _HOLDS,
                 {"when": {"https": ["not_attempted"]}, "try": "gsocket"}]
        beacon = self.a_beacon(policy=self.policy(rules), proxy_mode="none")

        self.assertEqual([rule["try"] for _number, rule
                          in beacon._egress_rules], ["gsocket"])
        self.assertEqual(len(self.logged.warnings), 2,
                         self.logged.warnings)
        for message in self.logged.warnings:
            self.assertIn("none", message)
        self.assertEqual(beacon._egress_decide(), "gsocket")

    def test_a_dropped_rule_does_not_renumber_the_ones_below_it(self):
        # The number in an attempt's log line is the rule's place in the
        # operator's file, which is the only place they can act on it.
        survives = {"when": {"https": ["not_attempted"]}, "try": "gsocket"}
        beacon = self.a_beacon(
            policy=self.policy([_NEVER, _HOLDS, survives]),
            proxy_mode="none")

        self.assertEqual(beacon._egress_rules, [(3, survives)])


class TestTheLatchMovesBehindIt(DeciderCase):
    """The carrier's start, in both configurations, as behaviour."""

    def test_with_the_decider_disabled_the_latch_is_exactly_todays_behaviour(self):
        # The default case, and the one `test_gsocket_leg.py` describes:
        # the carrier comes up on the first stuck cycle. A latch behind a
        # disabled decider would mean a stuck implant never started its
        # carrier at all, which is the gsocket leg not working in the
        # shipped configuration.
        cases = {
            "no block at all": None,
            # The shipped shape: disabled, and carrying the operator's
            # rules so that enabling it is one word. Its rules are a draft
            # and not permission.
            "disabled with rules": self.policy(
                [{"when": {"https": ["not_attempted"]}, "try": "gsocket"}],
                enabled=False),
        }
        for label, policy in cases.items():
            with self.subTest(policy=label):
                beacon = self.a_beacon(policy=policy, gsocket=True)
                asked = self.record_attempts(beacon)

                self.run_cycles(beacon, 1)

                self.assertCarrierUp(beacon)
                self.assertEqual(
                    beacon._leg_status.get("gsocket"),
                    (_CLASSES["carrier_failed"], 0),
                    "the record no longer says the leg was reached and "
                    "produced nothing")
                self.assertEqual(asked, [])
                self.assertEqual(beacon._egress_spent, 0)
                self.assertEqual(beacon._egress_rules, [])
                self.assertEqual(self.logged.warnings, [])

    def test_with_the_decider_enabled_the_carrier_waits_for_the_decision(self):
        # The cost the documentation has to state: the first stuck cycle
        # starts no carrier, because the decider may not act on it and the
        # latch is behind the decider now. One cycle traded for the chance
        # to try something else first.
        beacon = self.a_beacon(policy=self.policy([_HOLDS]), gsocket=True)
        self.record_attempts(beacon)

        self.run_cycles(beacon, 1)

        self.assertNoCarrier(beacon)
        self.assertEqual(beacon._stuck_cycles, 1)

    def test_a_policy_whose_first_rule_is_gsocket_restores_the_old_timing(self):
        # As nearly as the operator's own timing rule allows: the carrier
        # comes up on the first cycle the decider may act, with no cycle
        # spent on another verb first. The verb is not recorded here -- the
        # child is real, because whether a carrier came up is the whole
        # question.
        beacon = self.a_beacon(
            policy=self.policy(
                [{"when": {"https": ["not_attempted"]}, "try": "gsocket"}]),
            gsocket=True)

        self.run_cycles(beacon, 1)
        self.assertNoCarrier(beacon)

        self.run_cycles(beacon, 1)
        self.assertCarrierUp(beacon)
        self.assertEqual(beacon._egress_spent, 1,
                         "the latch started it, not the decider")
        self.assertEqual(len(self.logged.warnings), 1, self.logged.warnings)
        self.assertIn("Carrier started", self.logged.warnings[0])

    def test_the_latch_is_the_fallback_when_the_decider_did_not_act(self):
        # Declined, no match, or budget spent: the carrier still comes up,
        # on the first cycle the decider may act. The policy decides what
        # is tried, never whether the implant keeps a way back.
        with self.subTest(case="no rule matched"):
            beacon = self.a_beacon(policy=self.policy([_NEVER]),
                                   gsocket=True)
            self.run_cycles(beacon, 2)
            self.assertCarrierUp(beacon)
            self.assertEqual(beacon._egress_spent, 0)

        with self.subTest(case="nothing to select"):
            # A matching `proxy` rule on a host where discovery found
            # nothing: the rule is right and there is no candidate, so the
            # attempt is declined rather than spent on a refusal.
            declined = self.a_beacon(
                policy=self.policy(
                    [{"when": {"https": ["not_attempted"]}, "try": "proxy"}]),
                gsocket=True)
            self.run_cycles(declined, 2)
            self.assertCarrierUp(declined)
            self.assertEqual(declined._egress_spent, 0)

        with self.subTest(case="budget spent"):
            spent = self.a_beacon(policy=self.policy([_HOLDS], budget=1),
                                  gsocket=True)
            asked = self.record_attempts(spent)
            self.run_cycles(spent, 3)
            self.assertEqual(asked, ["rediscover"])
            self.assertCarrierUp(spent)


class TestWhatTheOperatorLearns(DeciderCase):
    """There is no DNS-borne signal, so the log is the whole report."""

    def test_every_attempt_is_logged_with_its_rule_and_its_outcome(self):
        # The record is already sent by the time the decider may act --
        # `_maybe_rescue` is one query per window -- so there is no message
        # to attach the news to. The operator reads this with the `cat`
        # verb once there is a connection, or on a recovered device, which
        # is the only state in which the detail could reach them anyway.
        beacon = self.a_beacon(policy=self.policy([_NEVER, _HOLDS]))
        self.record_attempts(beacon, answer="Proxy discovery re-run: 0 "
                                            "candidate(s)")

        self.run_cycles(beacon, 2)

        self.assertEqual(len(self.logged.warnings), 1, self.logged.warnings)
        line = self.logged.warnings[0]
        for expected in ("rule 2",                      # which rule it was
                         "not_attempted",               # and what it says
                         "rediscover",                  # the verb it chose
                         "1 of 3",                      # what it has spent
                         "Proxy discovery re-run: 0 candidate(s)"):
            self.assertIn(expected, line)

    def test_a_verb_that_raises_is_reported_and_still_costs_its_attempt(self):
        # `_beacon_loop` has no guard around its body, so an exception out
        # of a verb would cost the implant its loop -- the one outcome
        # worse than a failed attempt. The attempt is still spent, because
        # a verb that raises on every cycle would otherwise be an
        # unbounded one.
        beacon = self.a_beacon(policy=self.policy([_HOLDS]))

        def explode(_args):
            raise RuntimeError("the host said no")

        with mock.patch.object(beacon, "_exec_egress", explode):
            self.run_cycles(beacon, 2)

        self.assertEqual(beacon._egress_spent, 1)
        self.assertEqual(len(self.logged.warnings), 1, self.logged.warnings)
        self.assertIn("the host said no", self.logged.warnings[0])


class TestTheSeam(DeciderCase):
    """`_egress_decide` reads the evidence and the policy, and nothing else."""

    def test_the_decision_reads_the_record_as_the_server_renders_it(self):
        # One class per transport, with a leg that recorded nothing reading
        # as `not_attempted`: what `_rescue_pack` packs for it, so a rule
        # is written against the same five lines an operator reads in the
        # panel rather than against a second, narrower vocabulary.
        beacon = self.a_beacon(policy=self.policy([_HOLDS]))
        beacon._start_cycle()
        beacon._record_leg("quic", _CLASSES["timed_out"])
        beacon._rescue_flags |= beacon_mod._RESCUE_FLAG_DNS_ANSWERED

        state = beacon._egress_state()

        self.assertEqual(state["legs"], {
            "https": "not_attempted", "dns": "not_attempted",
            "smb": "not_attempted", "quic": "timed_out",
            "gsocket": "not_attempted",
        })
        self.assertEqual(state["flags"], ["dns_answered"])

    def test_the_decision_is_the_evidence_and_the_policy_and_no_more(self):
        # The narrowness is what makes it the seam the design names for a
        # later decision engine: a thing handed this evidence and these
        # options answers with one of them. Anything else a decision
        # depended on -- the clock, the budget, which legs are configured
        # -- would be state a replacement could not be given.
        beacon = self.a_beacon(policy=self.policy([_HOLDS]))
        beacon._start_cycle()

        self.assertEqual(beacon._egress_decide(), "rediscover")
        # Neither of the two things that stop an *attempt* changes the
        # decision itself; `_egress_act` is where they are weighed.
        beacon._egress_spent = 99
        beacon._stuck_cycles = 0
        self.assertEqual(beacon._egress_decide(), "rediscover")


if __name__ == "__main__":
    unittest.main()
