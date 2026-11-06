#!/usr/bin/env python3
"""The deliverable a campaign leaves behind.

A run used to end with the model's closing prose and some counters in
the drawer. There was no artefact: an operator who ran a campaign had
nothing to hand to the person who authorised it, and the findings sat in
SQLite behind a tool call.

What is pinned here is what makes a report usable rather than merely
present: it is honest about a campaign that found nothing, it does not
present an inferred finding as a reproduced one, and it never grows
without bound no matter how much output a finding cites.
"""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))

from software.agent import report
from software.agent.store import db, queries


def _store():
    conn = db.open_store(":memory:")
    run_id = queries.create_run(conn, "campaign", None, "auto", "{}")
    return conn, run_id


def _finding(conn, run_id, **kw):
    kw.setdefault("host", "10.0.1.5")
    kw.setdefault("finding_type", "service")
    kw.setdefault("data", "vsftpd 2.3.4 on 2121")
    kw.setdefault("source", "executor")
    return queries.log_finding(conn, run_id, **kw)


class TestAnEmptyCampaignStillProducesAReport(unittest.TestCase):
    """The case that decides whether the report is trusted.

    A report that is only written when something was found teaches the
    reader that its absence means "nothing ran". The preamble tells the
    model that finding nothing is a valid outcome; a report that cannot
    express that contradicts it.
    """

    def _findings_section(self, text):
        body = text.split("## Findings", 1)[1]
        return body.split("## ", 1)[0].strip()

    def test_a_run_with_no_findings_says_so_in_the_findings_section(self):
        # The first version allowed `"0" in text`, which the summary's
        # "Findings: **0**" satisfies -- so deleting the sentence
        # entirely left the test green. The section has to carry a
        # statement of its own.
        conn, run_id = _store()
        section = self._findings_section(report.render(conn, run_id))
        self.assertGreater(len(section), 60,
                           "the findings section says nothing at all")
        self.assertIn("no findings", section.lower())

    def test_it_distinguishes_nothing_found_from_nothing_run(self):
        # The two are not the same result, and only the task count tells
        # them apart -- so the count has to be the real one. Asserting
        # the word "task" alone left the number mutable: with no tasks
        # the true value is also 0, so a hardcoded 0 was invisible.
        conn, run_id = _store()
        for name in ("recon", "enumerate", "verify"):
            task_id = queries.create_task(conn, run_id, name, "do it", "agent", 2)
            queries.update_task(conn, task_id, "completed", "done")
        section = self._findings_section(report.render(conn, run_id))
        self.assertIn("3 task", section)

    def test_it_does_not_claim_the_campaign_failed(self):
        conn, run_id = _store()
        text = report.render(conn, run_id).lower()
        self.assertNotIn("error", text)


class TestTheFindingsAreGroupedAndLabelled(unittest.TestCase):
    def setUp(self):
        self.conn, self.run_id = _store()

    def test_a_finding_appears_with_its_host_and_type(self):
        _finding(self.conn, self.run_id)
        text = report.render(self.conn, self.run_id)
        self.assertIn("10.0.1.5", text)
        self.assertIn("vsftpd 2.3.4 on 2121", text)

    def test_the_evidence_is_quoted_in_a_block(self):
        _finding(self.conn, self.run_id,
                 evidence="2121/tcp open ftp vsftpd 2.3.4")
        text = report.render(self.conn, self.run_id)
        self.assertIn("```", text)
        self.assertIn("2121/tcp open ftp", text)

    def test_an_inferred_finding_is_marked_as_inferred(self):
        # The whole point of the proof basis: a reader must not have to
        # guess whether the agent reproduced this or read it off a banner.
        _finding(self.conn, self.run_id, proof_basis="inferred")
        text = report.render(self.conn, self.run_id)
        self.assertIn("inferred", text.lower())

    def test_an_executed_finding_is_marked_too(self):
        _finding(self.conn, self.run_id, proof_basis="executed-live")
        self.assertIn("executed-live", report.render(self.conn, self.run_id))

    def test_a_finding_with_no_basis_is_not_given_one(self):
        # Silence is better than a default that upgrades a guess.
        _finding(self.conn, self.run_id)
        text = report.render(self.conn, self.run_id)
        self.assertNotIn("executed-live", text)
        self.assertNotIn("inferred", text.lower())

    def test_findings_are_grouped_by_host(self):
        _finding(self.conn, self.run_id, host="10.0.1.5", data="one")
        _finding(self.conn, self.run_id, host="10.0.1.9", data="two")
        _finding(self.conn, self.run_id, host="10.0.1.5", data="three")
        text = report.render(self.conn, self.run_id)
        # Each host heads its own section, named once.
        self.assertEqual(text.count("### 10.0.1.5"), 1)
        self.assertEqual(text.count("### 10.0.1.9"), 1)

    def test_findings_with_no_host_are_not_filed_under_a_fake_one(self):
        _finding(self.conn, self.run_id, host=queries_no_host(), data="x")
        text = report.render(self.conn, self.run_id)
        self.assertNotIn("### (none)", text)


def queries_no_host():
    from software.agent.tools.recon import NO_HOST
    return NO_HOST


class TestTheReportStatesWhatTheCampaignWas(unittest.TestCase):
    """A deliverable without its scope is not evidence of anything."""

    def test_the_scope_is_named(self):
        conn = db.open_store(":memory:")
        run_id = queries.create_run(
            conn, "campaign", None, "auto",
            '{"campaign": {"scope_allow": ["10.0.1.0/24"], '
            '"scope_deny": ["10.0.1.254/32"], "phases": [1, 2, 3], '
            '"opsec_profile": "normal", "mode": "auto"}}')
        text = report.render(conn, run_id)
        self.assertIn("10.0.1.0/24", text)
        self.assertIn("10.0.1.254/32", text)

    def test_the_mode_is_named_because_it_decided_the_knocks(self):
        conn = db.open_store(":memory:")
        run_id = queries.create_run(
            conn, "campaign", None, "auto",
            '{"campaign": {"scope_allow": ["10.0.1.0/24"], "mode": "auto", '
            '"unattended_behavior": "decide"}}')
        text = report.render(conn, run_id).lower()
        self.assertIn("full automated", text)

    def test_a_config_that_cannot_be_read_does_not_break_the_report(self):
        # The report is the last thing a campaign does. Losing it to a
        # malformed config row would lose the findings with it.
        conn = db.open_store(":memory:")
        run_id = queries.create_run(conn, "campaign", None, "auto", "not json")
        text = report.render(conn, run_id)
        self.assertIn("# ", text)


class TestTheDecisionsAreOnTheRecord(unittest.TestCase):
    """What was refused is part of the deliverable, not an aside.

    A report listing only what the agent did invites the reader to assume
    it did everything it wanted. The gated actions and their verdicts are
    the evidence that it did not.
    """

    def test_a_refused_action_appears_with_who_refused_it(self):
        conn, run_id = _store()
        approval_id = queries.create_approval(
            conn, run_id, "exploit_known_poc", "{}", '{"ev": 110.1}')
        queries.decide_approval(conn, approval_id, "refused", "operator")
        text = report.render(conn, run_id)
        # The row itself, not the word anywhere in the document: the
        # closing sentence also contains "refused", so the first version
        # passed with the decision column blanked out.
        row = [line for line in text.splitlines()
               if line.startswith("| `exploit_known_poc`")]
        self.assertEqual(len(row), 1, text)
        self.assertIn("refused", row[0])
        self.assertIn("operator", row[0])
        self.assertIn("110.1", row[0])

    def test_a_campaign_with_no_approvals_says_so(self):
        conn, run_id = _store()
        text = report.render(conn, run_id).lower()
        self.assertIn("no gated", text)


class TestTheReportCannotGrowWithoutBound(unittest.TestCase):
    def test_a_long_evidence_block_is_capped_by_the_report_itself(self):
        # Written straight into the table, past queries.log_finding's own
        # cap. The first version went through it, so the report's clip
        # could be removed with the test still green -- it was measuring
        # the writer's guard, not the reader's.
        conn, run_id = _store()
        conn.execute(
            "INSERT INTO findings (run_id, host, finding_type, data, source, "
            "evidence, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (run_id, "10.0.1.5", "service", "something",
             "executor", "\n".join("line %d" % i for i in range(5000)),
             "2026-01-01T00:00:00Z"))
        conn.commit()
        text = report.render(conn, run_id)
        self.assertLess(len(text), 8000)
        self.assertIn("[...]", text)

    def test_one_very_long_line_is_capped_too(self):
        # The two guards cover different shapes: five thousand short
        # lines are caught by the line cap, one unbroken forty-thousand
        # character line only by the character cap. `xxd` and a base64
        # blob both produce the second shape.
        conn, run_id = _store()
        conn.execute(
            "INSERT INTO findings (run_id, host, finding_type, data, source, "
            "evidence, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (run_id, "10.0.1.5", "service", "something", "executor",
             "A" * 40000, "2026-01-01T00:00:00Z"))
        conn.commit()
        text = report.render(conn, run_id)
        self.assertLess(len(text), 8000)
        self.assertIn("[...]", text)

    def test_many_findings_do_not_produce_an_unreadable_wall(self):
        conn, run_id = _store()
        for i in range(500):
            _finding(conn, run_id, host="10.0.1.%d" % (i % 254),
                     data="finding %d" % i)
        text = report.render(conn, run_id)
        self.assertLess(len(text), 200000)
        # And it says it truncated rather than silently dropping them.
        self.assertIn("500", text)


if __name__ == "__main__":
    unittest.main()
