#!/usr/bin/env python3
"""The operator's egress policy, as the implant reads it.

`c2.egress_decider` of `configs/raccoon.yaml` is what an implant that
cannot reach its team server may try on its own, in the operator's order,
when nobody can be reached to be asked. This file is about **reading** that
block and **refusing** one that cannot work. Choosing a rule from it is the
next piece of work and is deliberately absent here: there is no evaluator,
no matcher against a rescue record and nothing that spends the budget.

**No refusal raises, and that is the property under test.** This code runs
on an implant, where the beacon is the access and everything else is a
convenience. `tunnel_config_from_yaml` can afford to raise because
`beacon_config_from_fallback` catches it and the beacon still starts; there
is nothing below the beacon to catch a policy that stopped it. A refusal
that cost the access in order to protect the policy would be the worst
trade available, so a block that is absent, incomplete or unusable reads as
**off, with the reason logged once** -- which is how the five transports
already behave. Every test below therefore asserts both halves: the shape
that comes back is off, and the reason reached the log naming the offending
value.

**The refusals happen when the block is read**, not when a rule would have
fired. The moment a rule would fire is a stuck cycle on a host nobody can
reach, which is the worst possible moment for a policy to turn out to be
unusable. `tunnel_config_from_yaml` made the same call about a `psk` in the
file -- refused whether the tunnel is enabled or not -- and the rules here
are validated whether the decider is enabled or not for the same reason: a
trap in a disabled block is a trap waiting for the day somebody enables it.

**Why the copy-comparison test is here and not in `test_dns_rescue.py`.**
`beacon.py` is served to a target as source text and may import only the
standard library, so the class names and the flag names a rule may use are
a copy of `dns_rescue.py`'s, like `_RESCUE_CLASSES` above them. That file
holds the comparisons about the record's *bytes*; what is pinned here is
the policy's *vocabulary* -- which names a rule may say -- and it is
asserted through `read_egress_policy` itself, so it fails when the copy
drifts *or* when the reader stops consulting it.

Nothing here reaches a network, spawns a process or writes a file. One
`Beacon` is constructed, with every leg off, to ask its own dispatch which
sub-verbs it has.
"""

import base64
import logging
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

import yaml

from software.c2 import beacon as beacon_mod
from software.c2 import dns_rescue
from software.c2.beacon import Beacon

SHIPPED_CONFIG = REPO_ROOT / "configs" / "raccoon.yaml"
BEACON_SOURCE = REPO_ROOT / "software" / "c2" / "beacon.py"

# What a refusal returns, written out rather than imported so that a change
# to the shape fails here. `budget` is 0 and `rules` is empty on purpose: a
# refused policy that carried the operator's rules and number would leave a
# later reader which forgot to check `enabled` with something to choose
# from and something to spend.
DISABLED = {"enabled": False, "budget": 0, "rules": []}

# A rule that is valid in every respect, so that a test about one bad field
# is not passing because of a second one.
A_GOOD_RULE = {"when": {"flags": ["proxy_found"]}, "try": "proxy"}


class _Warnings(logging.Handler):
    """Every record the beacon's logger emitted, in order.

    `assertLogs` cannot say "and nothing further was logged": it fails when
    nothing was logged at all, and `assertNoLogs` arrived in 3.10 while
    this repository is on 3.9. "One log line, not one per cycle" and "an
    absent block says nothing" are both claims about a count, including the
    count zero, so the handler is explicit.
    """

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)

    @property
    def messages(self):
        return [record.getMessage() for record in self.records]


class PolicyCase(unittest.TestCase):
    """A test that can count what the reader logged, and read nothing else."""

    def warnings(self) -> _Warnings:
        handler = _Warnings()
        logger = beacon_mod.logger
        propagate = logger.propagate
        logger.addHandler(handler)
        # Not propagated while this handler is attached: a full-suite run
        # may leave a handler on the root logger, and a refusal a test
        # *expects* must not print itself into the suite's output.
        logger.propagate = False

        def restore():
            logger.removeHandler(handler)
            logger.propagate = propagate

        self.addCleanup(restore)
        return handler

    def refused(self, block, expected_lines: int = 1):
        """Read `block`, assert it was refused, and return the one message."""
        logged = self.warnings()
        policy = beacon_mod.read_egress_policy(block)
        self.assertEqual(policy, DISABLED,
                         "a block that cannot work did not read as off")
        self.assertEqual(len(logged.records), expected_lines,
                         "expected %d log line, got %r"
                         % (expected_lines, logged.messages))
        return logged.messages[0]


class TestAPolicyThatIsNotThere(PolicyCase):
    """The default, and the deployments that predate this feature."""

    def test_an_absent_block_reads_as_disabled(self):
        # And says nothing at all. Every drop-box deployed before this
        # feature existed has no such block and all of them have to keep
        # starting, so an absent block is not a refusal: there is nothing
        # for an operator to fix and nothing to tell them.
        logged = self.warnings()
        self.assertEqual(beacon_mod.read_egress_policy(None), DISABLED)
        self.assertEqual(logged.messages, [])

    def test_an_empty_block_reads_as_disabled_and_says_nothing(self):
        # `c2.egress_decider:` with nothing under it. YAML hands that over
        # as None; an explicit empty mapping is the same statement.
        logged = self.warnings()
        policy = beacon_mod.read_egress_policy({})
        self.assertFalse(policy["enabled"])
        self.assertEqual(policy["rules"], [])
        self.assertEqual(logged.messages, [])

    def test_a_disabled_block_is_off_and_still_carries_what_it_says(self):
        # Off is not the same as refused: the operator wrote a policy and
        # switched it off, so what comes back is what they wrote, with
        # `enabled` false. A refusal is the shape with nothing in it.
        logged = self.warnings()
        policy = beacon_mod.read_egress_policy(
            {"enabled": False, "budget": 2, "rules": [A_GOOD_RULE]})
        self.assertFalse(policy["enabled"])
        self.assertEqual(policy["budget"], 2)
        self.assertEqual(policy["rules"], [A_GOOD_RULE])
        self.assertEqual(logged.messages, [])


class TestABlockThatCannotBeUsed(PolicyCase):
    """Off, with the reason logged once, and never an exception."""

    def test_an_unusable_block_reads_as_disabled_and_logs_once(self):
        # The five transports' own behaviour. Each shape here is something
        # a hand-edited YAML file really produces: a scalar where a
        # mapping belongs, the rules list written where the block belongs,
        # and a `true` left over from copying the line above.
        logged = self.warnings()
        for block in ("rediscover", [A_GOOD_RULE], 3, True):
            with self.subTest(block=block):
                logged.records.clear()
                # Never by raising. Asserted as the call itself: a
                # `ValueError` out of here would reach `main.py` through
                # `beacon_config_from_fallback` and cost the access.
                policy = beacon_mod.read_egress_policy(block)
                self.assertEqual(policy, DISABLED)
                self.assertEqual(len(logged.records), 1, logged.messages)
                self.assertIn(repr(block), logged.messages[0],
                              "the refusal does not name the value")

        # Two cycles, one log line. The block is read once, where the
        # config is built, and what the loop is handed afterwards is the
        # inert shape above -- there is nothing lazy in it for a later
        # cycle to ask again, so the count of refusals is the count of
        # config builds and not of stuck cycles. The test below holds the
        # structure that makes that true; this is the one build.
        logged.records.clear()
        built = beacon_mod.beacon_config_from_fallback(
            {"fallback": {"enabled": True}, "egress_decider": "rediscover"},
            env={})
        self.assertEqual(built["c2"]["egress_decider"], DISABLED)
        self.assertEqual(len(logged.records), 1, logged.messages)

    def test_the_block_is_read_in_one_place_so_no_cycle_can_relog_it(self):
        # "Logged once" is a claim about the whole run of a beacon, and
        # the thing that makes it true is that nothing rereads the block:
        # `beacon_config_from_fallback` runs once per start, and the loop
        # is handed its result. The gsocket leg says the same of its own
        # latched reason -- "nothing rereads the config block".
        #
        # Held as the structure rather than by driving cycles, because the
        # consumer of this policy does not exist yet: a test that ran two
        # stuck cycles today would pass because nothing reads the policy
        # at all, which is passing for the wrong reason. Parsed rather
        # than grepped so that a mention in a docstring is not a call.
        #
        # When whatever chooses from this policy is written, it reads the
        # block out of the config it was handed. If it calls this reader
        # per cycle instead, this test fails -- which is the moment to
        # decide what a per-cycle refusal would do to the log on a host
        # nobody can read.
        import ast

        tree = ast.parse(BEACON_SOURCE.read_text(encoding="utf-8"))
        callers = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for inner in ast.walk(node):
                if (isinstance(inner, ast.Call)
                        and isinstance(inner.func, ast.Name)
                        and inner.func.id == "read_egress_policy"):
                    callers.append(node.name)
        self.assertEqual(callers, ["beacon_config_from_fallback"],
                         "the policy is read somewhere other than where the "
                         "config is built, so its refusal can be logged more "
                         "than once")

    def test_a_setting_the_block_does_not_have_is_refused_by_name(self):
        # The typo that would otherwise be silent: `budgte: 3` leaves the
        # budget at its default and nothing says so. Named, with the three
        # settings that do exist, because the operator cannot read this
        # log from the host they would have to fix it on.
        message = self.refused({"enabled": True, "budgte": 3,
                                "rules": [A_GOOD_RULE]})
        self.assertIn("budgte", message)
        for setting in ("enabled", "budget", "rules"):
            self.assertIn(setting, message)

    def test_an_enabled_that_is_not_a_boolean_is_refused(self):
        # `enabled: "false"` -- YAML does not unquote a quoted scalar and
        # `bool("false")` is True, so a reader that took this with
        # `bool(...)` would switch an autonomous decider on out of a file
        # that says the opposite. The gsocket leg reads its own `enabled`
        # by value for the same reason.
        for value in ("false", "true", 1, 0, "yes"):
            with self.subTest(enabled=value):
                message = self.refused({"enabled": value,
                                        "rules": [A_GOOD_RULE]})
                self.assertIn("enabled is %r" % (value,), message)

    def test_rules_that_are_not_a_list_are_refused(self):
        message = self.refused({"enabled": True, "rules": A_GOOD_RULE})
        self.assertIn("rules", message)

    def test_enabled_with_no_rules_is_refused(self):
        # An empty rules list is not a quiet "decide nothing": it is a
        # decider that looks switched on in the file and can never fire,
        # which is the trap this reader exists to name. `enabled: false`
        # is how an operator says they want none of it.
        for rules in ([], None):
            with self.subTest(rules=rules):
                message = self.refused({"enabled": True, "rules": rules})
                self.assertIn("rules", message)
                self.assertIn("enabled: false", message)


class TestTheVerbsAPolicyMayName(PolicyCase):
    """Three, and a policy may order them and choose from them, not add."""

    def test_the_allowed_verbs_are_exactly_three(self):
        self.assertEqual(beacon_mod.EGRESS_VERBS,
                         ("proxy", "rediscover", "gsocket"))

    def test_a_rule_naming_a_verb_the_gate_refuses_is_refused_when_read(self):
        # `sleep` is the one that matters: it is a verb the beacon really
        # dispatches, and the one the server-side model reaches for on a
        # stuck beacon. `safety.py` hard-refuses `sleep_too_long` on the
        # team server, *with* an operator present to be asked; on the
        # implant there is nobody, so a decider that could slow its own
        # check-ins could talk itself into silence. `persist` stands for
        # the other family the gate refuses outright -- persistence, the
        # watchdog and the tunnel are how a device is recovered.
        #
        # Refused when the block is read, which is the point of this test
        # being here rather than beside a matcher: the moment the rule
        # would have fired is a stuck cycle on a host nobody can reach.
        for verb in ("sleep", "persist"):
            with self.subTest(verb=verb):
                message = self.refused(
                    {"enabled": True, "budget": 1,
                     "rules": [{"when": {"flags": ["proxy_found"]},
                                "try": verb}]})
                self.assertIn(repr(verb), message)
                # And what does exist, in full: an operator reading this
                # on a recovered device needs the list, not only the word
                # they got wrong.
                for allowed in beacon_mod.EGRESS_VERBS:
                    self.assertIn(allowed, message)

    def test_a_rule_naming_no_verb_at_all_is_refused(self):
        message = self.refused({"enabled": True,
                                "rules": [{"when": {"any": ["timed_out"]}}]})
        self.assertIn("try", message)

    def test_the_three_verbs_are_the_three_the_beacon_dispatches(self):
        # `EGRESS_VERBS` and `_exec_egress`'s dispatch are two places that
        # have to agree. A fourth sub-verb added there and not here would
        # be unreachable to the decider; a verb here the dispatch does not
        # have would be a rule that can never fire, which is the same trap
        # as the two dead flag names below. Asked of the dispatch's own
        # refusal, which names the three forms in full.
        beacon = Beacon({"c2": {
            "beacon_interval_seconds": 300,
            "jitter_percent": 0,
            # A real key because `decode_key` refuses an empty one, and
            # a fixed one because nothing here encrypts anything.
            "encryption_key": base64.b64encode(b"\x2a" * 32).decode(),
            "proxy": {"mode": "auto"},
            "https": {"enabled": False},
            "dns": {"enabled": False},
            "smb": {"enabled": False},
            "quic": {"enabled": False},
        }})
        self.addCleanup(beacon.stop)

        # The unknown-action arm, so nothing is discovered, spawned or
        # selected by asking this question.
        offered = beacon._exec_egress("nonesuch")
        for verb in beacon_mod.EGRESS_VERBS:
            with self.subTest(verb=verb):
                self.assertIn("'egress %s" % verb, offered)


class TestTheConditionsARuleMayName(PolicyCase):
    """What a `when` may say, and the two names it may not."""

    def test_proxy_found_and_dns_answered_are_accepted(self):
        # The two flags the beacon really sets. The refusal below is about
        # those two being the only live ones, not about flags being
        # unwelcome.
        logged = self.warnings()
        policy = beacon_mod.read_egress_policy({
            "enabled": True, "budget": 2,
            "rules": [{"when": {"flags": ["proxy_found"]}, "try": "proxy"},
                      {"when": {"flags": ["dns_answered"]},
                       "try": "gsocket"}]})

        self.assertEqual(logged.messages, [])
        self.assertTrue(policy["enabled"])
        # In the operator's order, which is the policy: the first matching
        # rule is the attempt, so an order the reader sorted or de-duped
        # would be a different policy from the one in the file.
        self.assertEqual([rule["try"] for rule in policy["rules"]],
                         ["proxy", "gsocket"])
        self.assertEqual(policy["rules"][0]["when"],
                         {"flags": ["proxy_found"]})
        self.assertEqual(policy["rules"][1]["when"],
                         {"flags": ["dns_answered"]})

    def test_dot1x_seen_and_portal_answered_are_refused_as_flag_names(self):
        # Both are declared in `dns_rescue.py` and both are rendered by
        # the team server, so an operator reading the panel has every
        # reason to think they are usable. Nothing in the beacon sets
        # them: `_rescue_flags` ORs in `proxy_found` and `dns_answered`
        # and nothing else, because no 802.1X sensing and no
        # captive-portal detection exists on this implant. A rule naming
        # one could never match, and a rule that can never fire is a trap
        # in the one file nobody can debug remotely.
        for flag in ("dot1x_seen", "portal_answered"):
            with self.subTest(flag=flag):
                message = self.refused(
                    {"enabled": True,
                     "rules": [{"when": {"flags": [flag]},
                                "try": "gsocket"}]})
                self.assertIn(flag, message)
                # The reason, not only the refusal: an operator who reads
                # "not a flag" will look for a typo and find none.
                self.assertIn("proxy_found", message)
                self.assertIn("dns_answered", message)

    def test_the_premise_nothing_in_the_beacon_sets_those_two_flags(self):
        # The refusal above is only right while this holds. A rescue flag
        # is only ever set by an `|=` on `_rescue_flags`, so the premise is
        # checked as the text of the file: the behavioural alternative is
        # driving all five legs of a beacon through every failure and
        # asserting a byte, which would test the legs and not this.
        source = BEACON_SOURCE.read_text(encoding="utf-8")
        for live in ("_RESCUE_FLAG_PROXY_FOUND", "_RESCUE_FLAG_DNS_ANSWERED"):
            self.assertIn("|= " + live, source,
                          "%s is no longer set; the policy's live flag names "
                          "are out of date" % live)
        for dead in ("_RESCUE_FLAG_DOT1X_SEEN",
                     "_RESCUE_FLAG_PORTAL_ANSWERED"):
            self.assertNotIn(
                "|= " + dead, source,
                "%s is set now, so it is a flag a rule could match and the "
                "refusal of its name is wrong" % dead)

    def test_an_unknown_flag_name_is_refused(self):
        message = self.refused({"enabled": True,
                                "rules": [{"when": {"flags": ["vpn_seen"]},
                                           "try": "gsocket"}]})
        self.assertIn("vpn_seen", message)

    def test_a_transport_and_a_class_name_are_accepted(self):
        logged = self.warnings()
        policy = beacon_mod.read_egress_policy({
            "enabled": True,
            "rules": [{"when": {"https": ["auth_required", "http_status"]},
                       "try": "rediscover"}]})

        self.assertEqual(logged.messages, [])
        self.assertEqual(policy["rules"][0]["when"],
                         {"https": ["auth_required", "http_status"]})

    def test_any_takes_class_names_too(self):
        logged = self.warnings()
        policy = beacon_mod.read_egress_policy({
            "enabled": True,
            "rules": [{"when": {"any": ["timed_out", "unreachable"]},
                       "try": "gsocket"}]})

        self.assertEqual(logged.messages, [])
        self.assertEqual(policy["rules"][0]["when"],
                         {"any": ["timed_out", "unreachable"]})

    def test_one_class_may_be_written_without_a_list(self):
        # `when: {https: refused}` is what a hand gets written as, and the
        # one-element list is noise. Normalised to a list so that whatever
        # reads these rules next has one shape to read.
        logged = self.warnings()
        policy = beacon_mod.read_egress_policy({
            "enabled": True,
            "rules": [{"when": {"https": "refused",
                                "flags": "proxy_found"}, "try": "proxy"}]})

        self.assertEqual(logged.messages, [])
        self.assertEqual(policy["rules"][0]["when"],
                         {"https": ["refused"], "flags": ["proxy_found"]})

    def test_several_keys_in_one_when_are_accepted(self):
        # Several conditions in one rule, which the design left to the
        # builder. Accepted rather than refused, because `{https: [...],
        # flags: [...]}` is the first thing an operator writes; what they
        # mean by it -- every key has to hold -- is the chooser's reading
        # and is recorded with the reader so it is not guessed later.
        logged = self.warnings()
        policy = beacon_mod.read_egress_policy({
            "enabled": True,
            "rules": [{"when": {"https": ["auth_required"],
                                "any": ["refused"],
                                "flags": ["proxy_found"]},
                       "try": "proxy"}]})

        self.assertEqual(logged.messages, [])
        self.assertEqual(sorted(policy["rules"][0]["when"]),
                         ["any", "flags", "https"])

    def test_an_unknown_class_name_is_refused_with_the_name_in_the_message(self):
        # Class names and not numbers, which is what makes this the typo
        # an operator makes: `timedout` for `timed_out`, and
        # `auth_requried` for the one that matters most on a proxied host.
        for when, offending in (({"https": ["auth_requried"]},
                                 "auth_requried"),
                                ({"any": ["timedout"]}, "timedout"),
                                ({"gsocket": ["binary-missing"]},
                                 "binary-missing")):
            with self.subTest(when=when):
                message = self.refused(
                    {"enabled": True,
                     "rules": [{"when": when, "try": "rediscover"}]})
                self.assertIn(offending, message)
                # And a class that does exist, so the message is a
                # correction and not only a complaint.
                self.assertIn("timed_out", message)

    def test_a_when_key_that_is_not_a_transport_any_or_flags_is_refused(self):
        # `htps` is the typo; `tunnel` is the plausible wrong idea, and it
        # is a thing the gate refuses to touch at all. `proxy_found` is
        # the one an operator reaches for after reading the row above it:
        # a flag name belongs under `flags`, not beside it.
        for key in ("htps", "tunnel", "proxy_found"):
            with self.subTest(key=key):
                message = self.refused(
                    {"enabled": True,
                     "rules": [{"when": {key: ["timed_out"]},
                                "try": "gsocket"}]})
                self.assertIn(key, message)

    def test_a_rule_with_no_condition_is_refused(self):
        # An empty or absent `when` would match every stuck cycle. An
        # unconditional autonomous action is exactly the thing this design
        # requires to be spelled out rather than fallen into, so it is
        # refused instead of read as a catch-all.
        for rule in ({"try": "gsocket"},
                     {"when": {}, "try": "gsocket"},
                     {"when": None, "try": "gsocket"}):
            with self.subTest(rule=rule):
                message = self.refused({"enabled": True, "rules": [rule]})
                self.assertIn("when", message)

    def test_a_condition_naming_no_classes_is_refused(self):
        # `when: {https: []}` can never match. Same family as the dead
        # flags: a rule that cannot fire is refused, not carried.
        message = self.refused({"enabled": True,
                                "rules": [{"when": {"https": []},
                                           "try": "rediscover"}]})
        self.assertIn("https", message)

    def test_a_rule_that_is_not_a_mapping_is_refused(self):
        message = self.refused({"enabled": True, "rules": ["gsocket"]})
        self.assertIn("is 'gsocket'", message)

    def test_the_refused_rule_is_named_by_its_position(self):
        # Three rules in the file and one of them wrong: an operator
        # reading this on a recovered device needs to know which.
        message = self.refused({
            "enabled": True,
            "rules": [A_GOOD_RULE,
                      {"when": {"any": ["timed_out"]}, "try": "gsocket"},
                      {"when": {"any": ["timed_out"]}, "try": "sleep"}]})
        self.assertIn("rules[3]", message)


class TestTheBudget(PolicyCase):
    """How many attempts a stuck window may spend, and what is not a number."""

    def test_a_budget_below_one_is_refused(self):
        # A policy with nothing to spend is a decider that is off while
        # the file says it is on. `enabled: false` is how that is said,
        # and the message says so.
        for budget in (0, -1, -3):
            with self.subTest(budget=budget):
                message = self.refused({"enabled": True, "budget": budget,
                                        "rules": [A_GOOD_RULE]})
                self.assertIn("budget is %r" % (budget,), message)
                self.assertIn("enabled: false", message)

    def test_a_budget_that_is_not_a_whole_number_is_refused(self):
        # `budget: true` is the one worth the test: `isinstance(True, int)`
        # is True in Python, so a stray YAML boolean would have read as
        # one attempt out of a file that names no number at all.
        for budget in (True, False, 1.5, "3", "", [3]):
            with self.subTest(budget=budget):
                message = self.refused({"enabled": True, "budget": budget,
                                        "rules": [A_GOOD_RULE]})
                self.assertIn("budget is %r" % (budget,), message)

    def test_an_absent_budget_takes_the_documented_default(self):
        # Defaulted rather than refused: a forgotten line should not turn
        # a policy into a dead one. Three, because there are three verbs,
        # so the default is one attempt each.
        logged = self.warnings()
        policy = beacon_mod.read_egress_policy({"enabled": True,
                                                "rules": [A_GOOD_RULE]})
        self.assertEqual(logged.messages, [])
        self.assertEqual(policy["budget"], 3)
        self.assertEqual(policy["budget"], beacon_mod._EGRESS_DEFAULT_BUDGET)

    def test_a_budget_the_operator_wrote_is_carried_as_written(self):
        logged = self.warnings()
        policy = beacon_mod.read_egress_policy(
            {"enabled": True, "budget": 1, "rules": [A_GOOD_RULE]})
        self.assertEqual(logged.messages, [])
        self.assertEqual(policy["budget"], 1)


class TestWhereThePolicyLands(PolicyCase):
    """`beacon_config_from_fallback` carries it at `c2.egress_decider`."""

    def test_the_block_reaches_the_beacons_own_config(self):
        # The function lifts each transport out of `c2.fallback` to the
        # top of the block the beacon reads. This is not a transport, so
        # it lands beside `c2.tunnel`, which that function already handles
        # the same way. Asserted and not assumed: `smb` and `quic` never
        # reached the beacon for a year because nothing asserted it.
        logged = self.warnings()
        built = beacon_mod.beacon_config_from_fallback(
            {"fallback": {"enabled": True},
             "egress_decider": {"enabled": True, "budget": 2,
                                "rules": [A_GOOD_RULE]}}, env={})

        self.assertEqual(logged.messages, [])
        self.assertEqual(built["c2"]["egress_decider"],
                         {"enabled": True, "budget": 2,
                          "rules": [A_GOOD_RULE]})

    def test_a_config_with_no_decider_still_carries_the_disabled_shape(self):
        # Always present, unlike `c2.tunnel`, which is left out when there
        # is none: the reader cannot fail, so a key that was sometimes
        # absent would only make every later reader write `.get(...) or
        # {}` and get the default wrong once.
        logged = self.warnings()
        built = beacon_mod.beacon_config_from_fallback(
            {"fallback": {"enabled": True}}, env={})

        self.assertEqual(logged.messages, [])
        self.assertEqual(built["c2"]["egress_decider"], DISABLED)

    def test_the_decider_is_read_from_c2_and_not_from_c2_fallback(self):
        # `c2.fallback` is the five legs, and the loop over them ignores
        # anything else under it. A policy written there is therefore not
        # read, and that reading must not change: taking the block from
        # either place would make the file's own structure meaningless.
        #
        # But it is said out loud. This is the one unusable policy
        # `read_egress_policy` never sees -- the operator reads a
        # complete, plausible block in the file and the decider is off --
        # and a typo one key wide, `budgte: 3`, is refused by name, so a
        # whole policy one level too deep cannot be the quiet one. It is
        # also the likely mistake: the decider is *about* fallback
        # behaviour and `c2.fallback` sits immediately beside it.
        logged = self.warnings()
        built = beacon_mod.beacon_config_from_fallback(
            {"fallback": {"enabled": True,
                          "egress_decider": {"enabled": True,
                                             "rules": [A_GOOD_RULE]}}},
            env={})

        self.assertEqual(len(logged.records), 1, logged.messages)
        message = logged.messages[0]
        # Where it was found and where it belongs, because the operator
        # fixing it is reading this and not the file.
        self.assertIn("c2.fallback.egress_decider", message)
        self.assertIn("c2.egress_decider", message)
        self.assertIn("The decider is off", message)
        # And the reading is unchanged: the misplaced block is not used.
        self.assertEqual(built["c2"]["egress_decider"], DISABLED)

    def test_a_stray_fallback_block_does_not_claim_the_decider_is_off(self):
        # With a good policy at `c2.egress_decider` as well, the stray one
        # is still named -- a leftover nobody is told about is how the
        # file drifts from what runs -- but the line must not say the
        # decider is off, because it is not. A false sentence on the one
        # channel the operator has is the failure this whole reader is
        # about.
        logged = self.warnings()
        built = beacon_mod.beacon_config_from_fallback(
            {"fallback": {"enabled": True,
                          "egress_decider": {"enabled": True,
                                             "rules": [A_GOOD_RULE]}},
             "egress_decider": {"enabled": True, "budget": 2,
                                "rules": [A_GOOD_RULE]}},
            env={})

        self.assertEqual(len(logged.records), 1, logged.messages)
        message = logged.messages[0]
        self.assertIn("c2.fallback.egress_decider", message)
        self.assertNotIn("The decider is off", message)
        # The policy in force is the one at the top level, read in full.
        self.assertEqual(built["c2"]["egress_decider"],
                         {"enabled": True, "budget": 2,
                          "rules": [A_GOOD_RULE]})


class TestTheBeaconsCopyOfTheVocabulary(PolicyCase):
    """The names a rule may say are a copy of `dns_rescue.py`'s.

    `beacon.py` is served to a target as source text and may import only
    the standard library, so it carries the class names and the flag names
    the way it already carries `_RESCUE_CLASSES`. A copy that drifts is the
    failure this arrangement buys, and these are the tests that make the
    drift loud -- through the reader, so that a copy which stayed correct
    while the reader stopped consulting it also fails.
    """

    def test_every_class_dns_rescue_declares_can_be_named_in_a_rule(self):
        for name in dns_rescue.CLASSES:
            with self.subTest(klass=name):
                logged = _Warnings()
                beacon_mod.logger.addHandler(logged)
                try:
                    policy = beacon_mod.read_egress_policy(
                        {"enabled": True,
                         "rules": [{"when": {"any": [name]},
                                    "try": "gsocket"}]})
                finally:
                    beacon_mod.logger.removeHandler(logged)
                self.assertTrue(
                    policy["enabled"],
                    "%r is a rescue class and a rule may not name it: %r"
                    % (name, logged.messages))

    def test_the_classes_are_the_same_mapping_the_module_declares(self):
        self.assertEqual(beacon_mod._RESCUE_CLASSES, dns_rescue.CLASSES)

    def test_the_flag_names_are_dns_rescues_four_split_in_two(self):
        # Two live, two dead, and the bit each one is, so that whatever
        # matches a rule next has one mapping to read rather than a second
        # copy of these names.
        both = dict(beacon_mod._EGRESS_FLAG_BITS)
        both.update(beacon_mod._EGRESS_DEAD_FLAGS)
        self.assertEqual(both, {
            "proxy_found": dns_rescue.FLAG_PROXY_FOUND,
            "dns_answered": dns_rescue.FLAG_DNS_ANSWERED,
            "dot1x_seen": dns_rescue.FLAG_DOT1X_SEEN,
            "portal_answered": dns_rescue.FLAG_PORTAL_ANSWERED})

    def test_a_fifth_flag_in_the_module_has_to_be_decided_here(self):
        # A new flag in `dns_rescue.py` is a decision this file has to
        # make -- does the beacon set it, so a rule may name it? -- and
        # the answer has to be written down rather than defaulting to
        # "unnameable in a policy, and nothing says why".
        declared = {name for name in vars(dns_rescue)
                    if name.startswith("FLAG_")}
        self.assertEqual(declared, {"FLAG_PROXY_FOUND", "FLAG_DOT1X_SEEN",
                                    "FLAG_PORTAL_ANSWERED",
                                    "FLAG_DNS_ANSWERED"})

    def test_the_transports_a_when_may_name_are_the_five_legs(self):
        self.assertEqual(beacon_mod._FALLBACK_TRANSPORTS,
                         beacon_mod._RESCUE_TRANSPORTS)
        for transport in beacon_mod._RESCUE_TRANSPORTS:
            with self.subTest(transport=transport):
                logged = self.warnings()
                policy = beacon_mod.read_egress_policy(
                    {"enabled": True,
                     "rules": [{"when": {transport: ["timed_out"]},
                                "try": "gsocket"}]})
                self.assertEqual(logged.messages, [])
                self.assertTrue(policy["enabled"])


class TestTheShippedPolicy(PolicyCase):
    """What `configs/raccoon.yaml` ships has to read on the implant."""

    def test_the_policy_shipped_in_raccoon_yaml_reads(self):
        config = yaml.safe_load(SHIPPED_CONFIG.read_text(encoding="utf-8"))
        block = config["c2"]["egress_decider"]

        logged = self.warnings()
        policy = beacon_mod.read_egress_policy(block)
        self.assertEqual(logged.messages, [],
                         "the shipped policy is refused by the implant that "
                         "has to read it")

        # Everything ships disabled: a fresh checkout decides nothing.
        self.assertFalse(policy["enabled"])
        # And the rules are really read rather than skipped because the
        # block is off -- which is the whole reason they are validated
        # whether it is enabled or not.
        self.assertTrue(policy["rules"],
                        "the shipped block has no rules, so enabling it "
                        "would refuse it")
        self.assertGreaterEqual(policy["budget"], 1)
        for index, rule in enumerate(policy["rules"], 1):
            with self.subTest(rule=index):
                self.assertIn(rule["try"], beacon_mod.EGRESS_VERBS)
                self.assertTrue(rule["when"])


if __name__ == "__main__":
    unittest.main()
