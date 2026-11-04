#!/usr/bin/env python3
"""The documentation's factual tables, checked against the code.

docs/AGENT.md states numbers: capability tiers, risk profile values, the
forced scan flags, the eight actions that are never permitted, the eleven
that are gated. Those are the parts a reader will rely on and the parts
that go stale silently -- a renamed action or a changed default leaves prose
that is confidently wrong, which is worse than prose that is vague.

So this does for the documentation what test_c2_agent_gui does for the GUI's
JavaScript tables: compares them to the source of truth, and fails when they
drift. It asserts that every key and every number is *present*, not that the
surrounding sentences are unchanged -- the prose is free, the facts are not.
"""

import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from software.agent import config, prompts, safety  # noqa: E402
from software.agent.executor import server_tool  # noqa: E402
from software.agent.llm import provider  # noqa: E402

AGENT_DOC = REPO / "docs" / "AGENT.md"
DEMO_DOC = REPO / "docs" / "C2_DEMO.md"
README = REPO / "README.md"


def _rows_under(text, heading):
    """Markdown table rows in the section introduced by `heading`."""
    body = text.split(heading, 1)
    if len(body) < 2:
        raise AssertionError("no section %r" % heading)
    out = []
    for line in body[1].splitlines():
        # Any heading ends the section, not only a level-two one: a "###"
        # below it would otherwise pull the next table's rows in.
        if line.startswith("#") and out:
            break
        if line.startswith("|") and not set(line) <= set("|- :"):
            out.append(line)
    return out


class _DocCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = AGENT_DOC.read_text()

    def present(self, needle, what):
        """assertIn without printing the haystack, and across line wraps.

        Prose wraps, so a phrase that reads as one sentence is two lines in
        the file. Comparing against a whitespace-normalised copy keeps the
        test about the sentence rather than about the column it broke at.
        """
        # Case-insensitive as well: the same sentence is capitalised at the
        # start of a line and lowercase mid-sentence, and the test is about
        # the claim, not about where it happened to land.
        flat = " ".join(self.doc.split()).lower()
        self.assertTrue(" ".join(needle.split()).lower() in flat,
                        "%s: %r is not in AGENT.md" % (what, needle))

    def absent(self, needle, what):
        self.assertTrue(needle not in self.doc, "%s: %r should not be in "
                        "AGENT.md" % (what, needle))


class TestTheCapabilityTiersAreStatedCorrectly(_DocCase):
    def test_every_tier_is_named(self):
        for tier in provider.TIER_LIMITS:
            self.present("`%s`" % tier, "capability tier")

    def test_each_tiers_turn_limits_appear_in_its_row(self):
        for tier, limits in provider.TIER_LIMITS.items():
            row = self._row_for(tier)
            for field in ("orchestrator_turns", "executor_turns",
                          "truncate_chars", "max_phase"):
                self.assertIn(str(limits[field]), row,
                              "%s: %s" % (tier, field))

    def _row_for(self, tier):
        for line in self.doc.splitlines():
            if line.startswith("|") and ("`%s`" % tier) in line:
                return line
        self.fail("no table row for tier %r" % tier)


class TestThePhasesAreStatedCorrectly(_DocCase):
    def test_every_phase_name_appears(self):
        for number, name in prompts.PHASE_NAMES.items():
            self.present(name, "phase %d" % number)

    def test_the_phase_table_uses_no_invented_name(self):
        # The GUI once called phase 3 "Credential access" and phase 4
        # "Lateral movement". Neither is a phase of this agent. The prose
        # may mention them -- the page explains that mistake on purpose --
        # but the table must not, which is why this reads the table.
        table = "\n".join(_rows_under(self.doc, "## Phases"))
        for ghost in ("Credential access", "Lateral movement"):
            self.assertNotIn(ghost, table, ghost)


class TestTheRiskProfilesAreStatedCorrectly(_DocCase):
    def test_every_profile_and_every_number_appears(self):
        rows = _rows_under(self.doc, "## Risk profiles")
        for name, values in config.RISK_PROFILES.items():
            row = next((r for r in rows
                        if r.split("|")[1].strip().strip("`") == name), None)
            self.assertIsNotNone(row, "no row for risk profile %r" % name)
            for field, value in values.items():
                # Written for a reader: 20.0 appears as "+20", -5.0 as a
                # minus sign, 0.25 as "0.25". Compare on the number.
                shown = ("%g" % value)
                candidates = {shown, "+" + shown, shown.replace("-", "\u2212")}
                self.assertTrue(any(c in row for c in candidates),
                                "%s/%s: %s not in its row" % (name, field, shown))


class TestTheOpsecProfilesAreStatedCorrectly(_DocCase):
    def test_every_profile_is_named(self):
        for name in config.OPSEC_PROFILES:
            self.present("`%s`" % name, "opsec profile")

    def test_the_yolo_promise_is_written_down(self):
        # The one sentence in this file that is load-bearing: the name
        # invites "safety off", and nine tests exist to refuse that reading.
        self.present("lifts the scan rate limits and nothing else",
                     "what yolo does")
        self.present("tier-1 actions stay blocked", "what yolo does not")


class TestTheGateListsMatchTheRiskTable(_DocCase):
    def _keys(self, tier):
        return {k for k, row in safety.RISK_TABLE.items() if row.tier == tier}

    def test_every_never_permitted_action_is_listed(self):
        for key in self._keys(safety.TIER_HARD):
            self.present("`%s`" % key, "tier-1 action")

    def test_every_gated_action_is_listed(self):
        for key in self._keys(safety.TIER_KNOCK):
            self.present("`%s`" % key, "gated action")

    def test_the_tier_one_table_has_exactly_the_tier_one_rows(self):
        # Counting the table, not parsing the prose: the sentence may be
        # rewritten, the table may not gain or lose a row silently.
        rows = _rows_under(self.doc, "### Never permitted, in any mode")
        # rows[0] is the header; the separator line is already filtered out.
        keys = {r.split("|")[1].strip().strip("`") for r in rows[1:]}
        self.assertEqual(keys, self._keys(safety.TIER_HARD))

    def test_a_tier_one_action_is_never_described_as_approvable(self):
        # The distinction the whole page rests on.
        self.present("cannot be approved", "the tier-1 promise")


class TestTheScanLimitsAreStatedCorrectly(_DocCase):
    def test_the_forced_flags_are_read_back_from_the_limiter(self):
        for program in ("nmap", "masscan", "netdiscover"):
            tokens = safety.enforce_scan_limits(
                "%s 192.0.2.1" % program).split()
            self.present(" ".join(tokens[1:-1]), "forced flags for " + program)

    def test_the_port_cap_and_the_nmap_timeout_are_the_real_numbers(self):
        self.present(str(safety.SCAN_TOP_PORTS), "the port cap")
        self.present(str(server_tool._TOOL_TIMEOUTS["nmap"]), "nmap's timeout")


class TestTheProvidersAreStatedCorrectly(_DocCase):
    def test_every_provider_the_code_accepts_is_documented(self):
        for name in provider._PROVIDERS:
            self.present("`%s`" % name, "provider")

    def test_the_shipped_config_lists_them_too(self):
        text = (REPO / "configs" / "raccoon.yaml").read_text()
        for name in provider._PROVIDERS:
            self.assertIn(name, text, name)


class TestTheUnattendedDefaultsAreStatedCorrectly(_DocCase):
    def test_every_behaviour_is_described(self):
        for name in config._UNATTENDED:
            self.present("`%s`" % name, "unattended behaviour")

    def test_the_asymmetric_default_is_explained(self):
        # Two defaults for one field is surprising, so the page has to say
        # which is which rather than leave a reader to find out.
        self.present("supervised \u2192 `pause`", "the supervised default")
        self.present("Full Automated \u2192\n`decide`",
                     "the Full Automated default")


class TestTheBudgetDefaultsAreStatedCorrectly(_DocCase):
    def test_the_numbers_match_the_form(self):
        form = config.CampaignConfig.from_form(
            {"beacons": ["b"], "scope_allow": ["10.0.0.0/24"],
             "mode": "auto"}, tier="full")
        for value in (form.max_runtime_seconds, form.max_tokens_total,
                      form.campaign_interval, form.restore_interval):
            number = int(value)
            # 500000 is written 500 000 for a reader.
            spaced = "{:,}".format(number).replace(",", " ")
            self.assertTrue(str(number) in self.doc or spaced in self.doc,
                            number)

    def test_the_approval_timeout_default_is_stated(self):
        self.present(str(int(config.AgentConfig().approval_timeout)),
                     "the approval timeout default")


class TestTheFiguresExist(unittest.TestCase):
    """A broken image is a broken promise in a document about evidence."""

    def _links(self, text):
        return re.findall(r"!\[[^\]]*\]\(([^)]+)\)", text)

    def test_every_figure_in_the_agent_page_resolves(self):
        for link in self._links(AGENT_DOC.read_text()):
            self.assertTrue((AGENT_DOC.parent / link).exists(), link)

    def test_every_figure_in_the_demo_page_resolves(self):
        for link in self._links(DEMO_DOC.read_text()):
            self.assertTrue((DEMO_DOC.parent / link).exists(), link)

    def test_every_figure_in_the_readme_resolves(self):
        # The front page, where a broken image is seen first. It uses HTML
        # <img> tags as well as markdown links.
        import re as _re
        text = README.read_text()
        links = self._links(text) + _re.findall(r'<img src="([^"]+)"', text)
        for link in links:
            if link.startswith(("http://", "https://")):
                continue
            self.assertTrue((README.parent / link).exists(), link)

    def test_the_agent_page_shows_at_least_the_knock_card(self):
        # The one figure the design's own mockup is about.
        links = self._links(AGENT_DOC.read_text())
        self.assertTrue(any("knock" in link for link in links), links)


class TestTheDocumentationIsReachable(unittest.TestCase):
    def test_the_readme_points_at_the_agent_page(self):
        self.assertTrue("docs/AGENT.md" in README.read_text(),
                        "README.md does not link docs/AGENT.md")

    def test_the_demo_page_points_at_the_agent_page(self):
        self.assertTrue("AGENT.md" in DEMO_DOC.read_text(),
                        "C2_DEMO.md does not link AGENT.md")

    def test_the_agent_page_points_back_at_the_demo(self):
        self.assertTrue("C2_DEMO.md" in AGENT_DOC.read_text(),
                        "AGENT.md does not link C2_DEMO.md")


class TestTheStatusQuoPromiseIsStated(_DocCase):
    def test_the_page_says_the_c2_runs_without_a_model(self):
        # The promise an evaluator checks first, and the one the whole
        # separate-service architecture exists to keep.
        self.present("run exactly as they do today", "the status-quo promise")
        self.present("test_status_quo.py", "where to verify it")


if __name__ == "__main__":
    unittest.main()
