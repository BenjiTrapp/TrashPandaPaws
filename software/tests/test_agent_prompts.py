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
