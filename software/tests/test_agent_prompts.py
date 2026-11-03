#!/usr/bin/env python3
"""
Tests for the campaign preambles. A preamble is the model's whole picture of
its situation, so the properties pinned here are about what it must not get
wrong: a locked phase must not be mentioned, the tier lists must be the
classifier's own, and the scan flags must be the ones the rewriter forces.
"""

import re
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent import config, prompts, safety
from software.agent import safety
from software.agent.executor import beacon as beacon_exec
from software.agent.tools import scoring


def _scope(allow=("10.0.1.0/24", "10.0.9.0/24"), deny=("10.0.1.254/32",)):
    return config.CampaignConfig.from_form(
        {"beacons": ["raccoon-fox"], "scope_allow": list(allow),
         "scope_deny": list(deny)}, tier="full")


def _orch(caps=None, phases=(1, 2, 3), tier="full", scope=None):
    return prompts.orchestrator(caps or {"raccoon-fox": ["batch"]},
                                scope=scope or _scope(), phases=set(phases),
                                tier=tier)


class TestCapabilitySection(unittest.TestCase):
    def test_capability_section_lists_each_beacon(self):
        s = prompts.capability_section({"raccoon-fox": ["batch", "posix"],
                                        "raccoon-pi": ["batch", "sniffer"]})
        self.assertIn("raccoon-fox", s)
        self.assertIn("sniffer", s)

    def test_a_capability_is_explained_once_it_is_present(self):
        s = prompts.capability_section({"raccoon-pi": ["sniffer"]})
        self.assertIn("capture", s.lower())

    def test_an_absent_capability_is_not_explained(self):
        s = prompts.capability_section({"raccoon-fox": ["batch"]})
        self.assertNotIn("sniffer", s)
        self.assertNotIn("wifi", s)

    def test_an_unknown_capability_is_listed_without_an_explanation(self):
        self.assertIn("quantum", prompts.capability_section(
            {"raccoon-fox": ["quantum"]}))

    def test_no_beacons_is_stated(self):
        self.assertIn("no beacon", prompts.capability_section({}).lower())

    def test_beacons_are_listed_in_a_stable_order(self):
        a = prompts.capability_section({"b": ["x"], "a": ["y"]})
        self.assertLess(a.index("- a:"), a.index("- b:"))


class TestOrchestratorPrompt(unittest.TestCase):
    def test_orchestrator_prompt_contains_scope_and_phases(self):
        p = _orch()
        self.assertIn("10.0.1.0/24", p)
        self.assertIn("10.0.9.0/24", p)
        self.assertIn("10.0.1.254/32", p)
        self.assertIn("Phase 2", p)

    def test_orchestrator_prompt_lists_every_score_action(self):
        p = _orch(phases=(1, 2, 3, 4, 5))
        for action, points in scoring.SCORE_ACTIONS.items():
            self.assertIn(action, p)
            self.assertIn("%+d" % points, p)
        self.assertEqual(len(scoring.SCORE_ACTIONS), 16)

    def test_orchestrator_prompt_lists_the_wifi_actions_without_wifi(self):
        # Spec §10.8: the model must not have to discover them from errors.
        p = _orch(phases=(1, 2))
        for a in ("ap_discovered", "handshake_captured", "pmkid_captured",
                  "wps_pin_found", "psk_cracked"):
            self.assertIn(a, p)

    def test_orchestrator_prompt_states_the_scan_rate_limits(self):
        p = _orch()
        self.assertIn("-T2", p)
        self.assertIn("--max-rate 50", p)
        self.assertIn("--rate 50", p)

    def test_the_scan_flags_are_the_ones_the_rewriter_forces(self):
        # Derived from enforce_scan_limits, so they cannot drift from it.
        forced = safety.enforce_scan_limits("nmap 10.0.1.5")
        self.assertIn("-T2 --max-rate 50", forced)
        with mock.patch.object(
                safety, "enforce_scan_limits",
                lambda c: c.replace(c.split()[0], c.split()[0] + " -T1 --max-rate 7")):
            self.assertIn("--max-rate 7", _orch())

    def test_orchestrator_prompt_demands_individual_targets(self):
        p = _orch(phases=(1, 2))
        self.assertRegex(p.lower(), r"einzeln|individually|one target per")

    def test_the_prompt_says_how_a_hostname_becomes_a_target(self):
        self.assertIn("log_discovery", _orch())

    def test_orchestrator_prompt_warns_about_the_gate(self):
        p = _orch(phases=(1, 2))
        self.assertRegex(p.lower(), r"gate|freigabe|approval")
        self.assertIn("refused", p.lower())

    def test_ev_gating_and_cvss_guidance_are_present(self):
        p = _orch()
        self.assertIn("EV", p)
        self.assertIn("CVSS", p)
        self.assertIn("9.0", p)
        self.assertIn("p_success_estimate", p)

    def test_the_prompt_lists_the_orchestrators_tools_and_not_the_executors(self):
        p = _orch()
        self.assertIn("dispatch_task", p)
        self.assertIn("log_score", p)
        self.assertNotIn("run_command", p)
        self.assertNotIn("lookup_cve", p)

    def test_the_prompt_follows_the_tier_tool_set(self):
        self.assertIn("dispatch_parallel_tasks", _orch(tier="full"))
        self.assertNotIn("dispatch_parallel_tasks", _orch(tier="minimal"))

    # ── Phases ──

    def test_disabled_phases_are_not_advertised(self):
        p = _orch(phases=(1, 2, 3))
        self.assertNotIn("Phase 5", p)
        self.assertNotIn("Phase 4", p)

    def test_a_locked_exploitation_phase_is_not_hinted_at_either(self):
        p = _orch(phases=(1, 2, 3, 4)).lower()
        self.assertNotIn("exploit", p)
        self.assertNotIn("phase 5", p)

    def test_an_enabled_exploitation_phase_is_described(self):
        p = _orch(phases=(1, 2, 3, 4, 5))
        self.assertIn("Phase 5", p)
        self.assertIn("exploit_known_poc", p)

    def test_wire_phase_only_with_sniffer_cap(self):
        with_pi = _orch({"raccoon-pi": ["sniffer"]}, phases=(1, 2))
        without = _orch({"raccoon-fox": ["batch"]}, phases=(1, 2))
        self.assertIn("Wire Intel", with_pi)
        self.assertNotIn("Wire Intel", without)

    def test_wire_phase_is_absent_when_phase_one_is_disabled(self):
        self.assertNotIn("Wire Intel", _orch({"raccoon-pi": ["sniffer"]},
                                             phases=(2, 3)))

    def test_wifi_phases_only_with_monitor_capability(self):
        phases = (1, 2, 6, 7, 8)
        on = _orch({"raccoon-pi": ["wifi:monitor"]}, phases=phases)
        scan_only = _orch({"raccoon-pi": ["wifi:scan"]}, phases=phases)
        self.assertIn("Phase 6", on)
        self.assertNotIn("Phase 6", scan_only)
        self.assertNotIn("Phase 6", _orch(phases=phases))

    def test_wifi_phases_forbid_parallel_wifi_tasks(self):
        p = _orch({"raccoon-pi": ["wifi:monitor"]}, phases=(1, 6)).lower()
        self.assertRegex(p, r"never[^.]*parallel")

    def test_wifi_only_gated_action_is_listed_with_the_wifi_phases(self):
        on = _orch({"raccoon-pi": ["wifi:monitor"]}, phases=(1, 6))
        off = _orch({"raccoon-fox": ["batch"]}, phases=(1, 2))
        self.assertIn("deauth", on)
        self.assertNotIn("deauth", off)

    # ── Tier lists ──

    def test_tier_lists_are_generated_from_the_risk_table(self):
        p = _orch(phases=(1, 2, 3, 4, 5))
        for key, row in safety.RISK_TABLE.items():
            if row.action_class == "wifi":
                continue
            self.assertIn(key, p, key)
            self.assertIn(row.reason, p, key)

    def test_a_new_risk_table_row_reaches_the_prompt(self):
        hard = safety._row(safety.TIER_HARD, "test_hard_row", "lifecycle",
                           "a refusal invented by this test")
        knock = safety._row(safety.TIER_KNOCK, "test_knock_row", "lateral",
                            "a gated action invented by this test",
                            points=10, p_success=0.5, p_detect=0.5)
        with mock.patch.dict(safety.RISK_TABLE,
                             {"test_hard_row": hard, "test_knock_row": knock}):
            p = _orch()
        self.assertIn("a refusal invented by this test", p)
        self.assertIn("a gated action invented by this test", p)

    def test_the_tiers_are_listed_under_the_right_heading(self):
        p = _orch(phases=(1, 2, 3, 4, 5))
        hard_at = p.index("Never allowed")
        gated_at = p.index("Gated")
        for key, row in safety.RISK_TABLE.items():
            if row.action_class == "wifi":
                continue
            at = p.index(key + ":")
            if row.tier == safety.TIER_HARD:
                self.assertTrue(hard_at < at < gated_at, key)
            else:
                self.assertGreater(at, gated_at, key)

    def test_tier_one_is_not_negotiable_and_tier_two_can_be_refused(self):
        p = _orch().lower()
        self.assertRegex(p, r"never[^.]*(?:allowed|permitted)")
        self.assertRegex(p, r"gate[^.]*(?:refus|declin)")

    def test_a_scope_is_read_from_the_campaign_config(self):
        p = _orch(scope=_scope(allow=("172.16.4.0/24",), deny=()))
        self.assertIn("172.16.4.0/24", p)
        self.assertNotIn("10.0.1.0/24", p)

    def test_an_empty_deny_list_is_not_printed_as_a_list(self):
        p = _orch(scope=_scope(deny=()))
        self.assertNotIn("Never target", p)


class TestExecutorPrompt(unittest.TestCase):
    def test_executor_prompt_forbids_scope_expansion(self):
        p = prompts.executor(["batch"], scope=_scope(), tier="full")
        self.assertRegex(p.lower(), r"nicht ausweiten|do not expand|nicht abschweifen")

    def test_executor_prompt_fixes_the_output_format(self):
        p = prompts.executor(["batch"], scope=_scope(), tier="full")
        for marker in ("TASK:", "STATUS:", "FINDINGS:", "ERRORS:"):
            self.assertIn(marker, p)

    def test_executor_prompt_names_the_scope(self):
        p = prompts.executor(["batch"], scope=_scope(), tier="full")
        self.assertIn("10.0.1.0/24", p)

    def test_executor_prompt_lists_its_tools_for_the_tier(self):
        full = prompts.executor(["batch"], scope=_scope(), tier="full")
        mini = prompts.executor(["batch"], scope=_scope(), tier="minimal")
        self.assertIn("lookup_cve", full)
        self.assertNotIn("lookup_cve", mini)
        self.assertIn("run_command", mini)
        self.assertNotIn("dispatch_task", full)
        self.assertNotIn("log_score", full)

    def test_executor_prompt_names_targets_individually(self):
        p = prompts.executor(["batch"], scope=_scope(), tier="full")
        self.assertRegex(p.lower(), r"individually|one target per")

    def test_executor_prompt_states_the_forced_scan_limits(self):
        self.assertIn("--max-rate 50",
                      prompts.executor(["batch"], scope=_scope(), tier="full"))

    def test_executor_prompt_does_not_mention_phases(self):
        p = prompts.executor(["batch"], scope=_scope(), tier="full")
        self.assertIsNone(re.search(r"[Pp]hase \d", p))

    def test_executor_prompt_says_a_refusal_is_not_to_be_retried(self):
        p = prompts.executor(["batch"], scope=_scope(), tier="full").lower()
        self.assertRegex(p, r"blocked_reason|refus")

    def test_executor_prompt_is_shorter_than_the_orchestrator_prompt(self):
        self.assertLess(
            len(prompts.executor(["batch"], scope=_scope(), tier="full")),
            len(_orch(phases=(1, 2, 3, 4, 5))))


if __name__ == "__main__":
    unittest.main()


class TestThePromptNamesTheTargetPlatform(unittest.TestCase):
    """The beacon's OS belongs in the prompt, because the C2 already knows it.

    Found in a live run against a Darwin beacon: the model spent turns
    guessing the platform -- `cat /proc/net/dev`, `cat /proc/sys/kernel/
    hostname`, `cat /proc/net/route`, `ls /usr/bin/python` -- on a host with
    no /proc at all. Three discovery tasks reached 11 of their 16 turns
    without converging and the run hit its token budget.

    The `posix` capability does not help here: it separates Windows from
    the rest and leaves Linux and macOS indistinguishable, which is exactly
    the guess being made. The OS string is free information sitting in the
    record the router already trusts for capabilities.
    """

    def test_the_os_is_named_next_to_the_beacon(self):
        s = prompts.capability_section(
            {"raccoon-fox": ["batch", "posix"]},
            os_by_beacon={"raccoon-fox": "Darwin 25.5.0"})
        self.assertIn("Darwin 25.5.0", s)

    def test_each_beacon_gets_its_own_platform(self):
        s = prompts.capability_section(
            {"raccoon-fox": ["posix"], "raccoon-pi": ["posix"]},
            os_by_beacon={"raccoon-fox": "Darwin 25.5.0",
                          "raccoon-pi": "Linux 6.1.0"})
        self.assertIn("Darwin 25.5.0", s)
        self.assertIn("Linux 6.1.0", s)

    def test_a_beacon_with_no_reported_os_is_not_given_one(self):
        # Inventing a platform would be worse than leaving it open: the
        # model would run Linux commands on a host nobody vouched for.
        s = prompts.capability_section({"raccoon-fox": ["posix"]},
                                       os_by_beacon={})
        self.assertNotIn("Linux", s)
        self.assertNotIn("Darwin", s)

    def test_the_section_still_works_without_any_platform_data(self):
        s = prompts.capability_section({"raccoon-fox": ["batch"]})
        self.assertIn("raccoon-fox", s)

    def test_the_executor_is_told_what_it_is_standing_on(self):
        p = prompts.executor(["posix"], scope=_scope(), tier="full",
                             caps_by_beacon={"raccoon-fox": ["posix"]},
                             os_by_beacon={"raccoon-fox": "Darwin 25.5.0"})
        self.assertIn("Darwin 25.5.0", p)

    def test_the_executor_sees_every_platform_it_may_reach(self):
        # An executor may use any of the campaign's beacons, so one
        # platform line would be a lie in a mixed fleet.
        p = prompts.executor(["posix"], scope=_scope(), tier="full",
                             caps_by_beacon={"fox": ["posix"],
                                             "pi": ["posix"]},
                             os_by_beacon={"fox": "Darwin 25.5.0",
                                           "pi": "Linux 6.1.0"})
        self.assertIn("Darwin 25.5.0", p)
        self.assertIn("Linux 6.1.0", p)

    def test_the_executor_prompt_still_works_without_platforms(self):
        p = prompts.executor(["batch"], scope=_scope(), tier="full")
        self.assertIn("executor", p.lower())


class TestTheBeaconCommandLanguageIsStated(unittest.TestCase):
    """A beacon command's first word is a beacon verb, not a program.

    Found in a live run, and it cost the whole campaign: the executor was
    told to give "one plain command", so it sent `arp -a`, `ifconfig -a`,
    `netstat -an`. The beacon answers every one of those with

        {"success": false, "output": "Unknown command: arp", "exit_code": -1}

    because it dispatches on a fixed verb set and `arp` is not in it. With
    no verb list and no rule, the model retried variants until the token
    budget was gone: four tasks, 39 model calls, zero findings.

    `cat`, `ls` and `pwd` *are* verbs, which is why a handful of commands in
    that run appeared to work and hid the pattern.

    Verified live: `shell arp -a` returns the ARP table; `arp -a` does not.
    """

    def test_the_shell_verb_rule_is_stated(self):
        # The prefix form itself, not the word "shell": the prompt already
        # said "no shell syntax", which is what made the old wording look
        # like it covered this.
        p = prompts.executor(["batch"], scope=_scope(), tier="full")
        self.assertIn("shell <command>", p)

    def test_a_representative_native_verb_is_offered(self):
        # The beacon has its own arptable and netscan; a model that knows
        # them does not need to reach for a program at all.
        p = prompts.executor(["batch"], scope=_scope(), tier="full")
        self.assertIn("arptable", p)
        self.assertIn("netscan", p)

    def test_every_verb_the_beacon_accepts_is_named(self):
        p = prompts.executor(["batch"], scope=_scope(), tier="full")
        missing = [v for v in beacon_exec.BEACON_VERBS if v not in p]
        self.assertEqual(missing, [])

    def test_the_verb_list_matches_the_beacon_itself(self):
        # The list is the agent's copy of another module's dispatch table,
        # so it can drift. This is the test that notices.
        import pathlib
        import re
        src = pathlib.Path(__file__).resolve().parents[1] / "c2" / "beacon.py"
        actual = set(re.findall(r'^\s*(?:el)?if cmd == "([a-z_]+)"',
                                src.read_text(), re.M))
        self.assertEqual(set(beacon_exec.BEACON_VERBS), actual)

    def test_the_rule_is_not_in_the_orchestrator_prompt(self):
        # The orchestrator never runs a command, so the verb set is noise
        # in a prompt that is already long.
        p = prompts.orchestrator({"raccoon-fox": ["batch"]}, _scope(),
                                 {1, 2}, "full")
        self.assertNotIn("arptable", p)


class TestTheCostOfARateLimitedScanIsStated(unittest.TestCase):
    """A rate limit turns a port range into a duration, and nothing said so.

    From the live run: the model asked for `nmap -p- 127.0.0.1` with
    `timeout: 300`. The limiter made that `nmap -T2 --max-rate 50 -p-`,
    which is 65535 ports at 50 packets a second -- about 22 minutes. It
    timed out at 300s with partial output and `success: false`, and the
    model asked again.

    Two facts the system had and the model did not: the built-in per-program
    timeout (900s for nmap, better informed than any guess the model makes),
    and what the enforced rate means for a full-port scan.
    """

    def test_the_scan_section_says_what_a_full_port_scan_costs(self):
        section = prompts._scan_section()
        self.assertIn("-p-", section)

    def test_the_executor_is_told_not_to_guess_a_timeout(self):
        p = prompts.executor(["batch"], scope=_scope(), tier="full")
        self.assertIn("timeout", p)

    def test_the_built_in_nmap_timeout_is_named_from_the_real_table(self):
        # Read back from the executor, not written twice: a change there
        # must not leave the prompt quoting an old number.
        from software.agent.executor import server_tool
        section = prompts._scan_section()
        self.assertIn(str(server_tool._TOOL_TIMEOUTS["nmap"]), section)


class TestTheExecutorKnowsWhichBeaconsExist(unittest.TestCase):
    """run_command needs a beacon_id and nothing told the executor any.

    From the live run against the VM. The executor sent

        {"command": "shell ip neigh show", "beacon_id": "batch-posix-smbloot"}
        blocked_reason: "unknown beacon 'batch-posix-smbloot'"

    -- it had built an id out of the capability words it was shown, because
    those were the only beacon-ish strings in its prompt. Every beacon-path
    command then failed, so it fell back to server_side, and `route -n` ran
    on the macOS C2 host with Linux syntax. One cause, both symptoms.

    It worked in an earlier run only by luck: the orchestrator is told to
    put the targets in the task description, and nothing makes it name the
    beacon. None of the three descriptions in this run did.

    The beacons are rendered with capability_section, the same table the
    orchestrator gets, so the id, the platform and the capabilities are one
    description in one place rather than three parameters that can disagree.
    """

    CAPS = {"raccoon-fox": ["batch", "posix"]}
    OSES = {"raccoon-fox": "Linux 7.0.0-34-generic"}

    def _executor(self, caps_by_beacon=None, os_by_beacon=None):
        return prompts.executor(
            ["batch", "posix"], scope=_scope(), tier="full",
            caps_by_beacon=self.CAPS if caps_by_beacon is None
            else caps_by_beacon,
            os_by_beacon=self.OSES if os_by_beacon is None else os_by_beacon)

    def test_the_beacon_id_is_named(self):
        self.assertIn("raccoon-fox", self._executor())

    def test_the_platform_sits_with_the_id_it_belongs_to(self):
        # Two beacons, two platforms: a flat list of platforms cannot say
        # which is which, and the executor has to choose a beacon.
        text = prompts.executor(
            ["batch"], scope=_scope(), tier="full",
            caps_by_beacon={"fox": ["batch"], "pi": ["batch"]},
            os_by_beacon={"fox": "Linux 6.1", "pi": "Darwin 25.5"})
        self.assertRegex(text, r"fox \(Linux 6\.1\)")
        self.assertRegex(text, r"pi \(Darwin 25\.5\)")

    def test_the_executor_is_told_to_use_one_of_those_ids(self):
        self.assertIn("beacon_id", self._executor())

    def test_no_beacons_is_not_a_crash(self):
        text = prompts.executor(["batch"], scope=_scope(), tier="full")
        self.assertIn("executor", text.lower())

    def test_the_capability_meanings_are_not_printed_twice(self):
        # capability_section already explains each capability, so the old
        # "What your beacon can do" block would repeat it.
        text = self._executor()
        self.assertEqual(text.count("accepts several tasks in one check-in"), 1)


class TestTheScanSectionDescribesWhatActuallyHappens(unittest.TestCase):
    """The prompt has to match the limiter, not the limiter's old plan.

    The first attempt at this was prose only -- "a full-port scan will not
    finish, name the ports instead" -- and the model asked for `-p-` twice
    anyway. The limiter now narrows it. Prose that still says the scan comes
    back partial would describe behaviour that no longer exists.
    """

    def test_the_narrowing_is_stated_with_the_real_number(self):
        section = prompts._scan_section()
        self.assertIn(str(safety.SCAN_TOP_PORTS), section)

    def test_the_section_no_longer_promises_a_partial_result(self):
        self.assertNotIn("partial result", prompts._scan_section())

    def test_the_executor_is_told_to_report_what_ran(self):
        p = prompts.executor(["batch"], scope=_scope(), tier="full")
        self.assertIn("effective_command", p)
