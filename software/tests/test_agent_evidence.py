#!/usr/bin/env python3
"""Evidence on a finding, and how the finding was proven.

`findings` held host, type, data, source and a timestamp -- and not the
output that proved any of it. The report this feeds would have had an
evidence block with nothing to put in it, and an operator reading
"vsftpd 2.3.4 on 2121" had no way to see what the agent actually saw.

The proof basis is the second half and the more important one. ARTEX's
wording is the reference: "an executed proof outranks a static
conclusion; anything never actually triggered is potential/suspect,
never confirmed." Without it, a finding the model inferred from a
version string reads exactly like one it reproduced.
"""

import pathlib
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))

from software.agent.store import db, queries


def _conn():
    return db.open_store(":memory:")


def _run(conn):
    return queries.create_run(conn, "test", None, "auto", "{}")


class TestAFindingCarriesItsEvidence(unittest.TestCase):
    def setUp(self):
        self.conn = _conn()
        self.run_id = _run(self.conn)

    def test_the_output_that_proved_it_is_kept(self):
        queries.log_finding(
            self.conn, self.run_id, "10.0.1.5", "service",
            "vsftpd 2.3.4 on 2121", "executor",
            evidence="2121/tcp open ftp vsftpd 2.3.4",
            proof_basis="executed-live")
        row = list(self.conn.execute("SELECT * FROM findings"))[0]
        self.assertEqual(row["evidence"], "2121/tcp open ftp vsftpd 2.3.4")
        self.assertEqual(row["proof_basis"], "executed-live")

    def test_a_finding_without_evidence_is_still_accepted(self):
        # Not every finding has a quotable line -- "this host answers at
        # all" is a finding -- and refusing those would push the model
        # into inventing evidence to get past the tool.
        queries.log_finding(self.conn, self.run_id, "10.0.1.5", "host",
                            "answers ICMP", "executor")
        row = list(self.conn.execute("SELECT * FROM findings"))[0]
        self.assertIsNone(row["evidence"])

    def test_an_unknown_proof_basis_is_refused(self):
        # The three values are the whole point: a free-text field would
        # fill up with "probably" and "seems to", which is what the
        # column exists to stop.
        with self.assertRaises(ValueError) as caught:
            queries.log_finding(self.conn, self.run_id, "10.0.1.5", "vuln",
                                "something", "executor",
                                proof_basis="pretty sure")
        self.assertIn("executed-live", str(caught.exception))

    def test_the_three_bases_are_all_accepted(self):
        for basis in queries.PROOF_BASES:
            queries.log_finding(self.conn, self.run_id, "h", "t", "d", "s",
                                proof_basis=basis)
        stored = [r["proof_basis"] for r in
                  self.conn.execute("SELECT proof_basis FROM findings")]
        self.assertEqual(sorted(stored), sorted(queries.PROOF_BASES))

    def test_evidence_is_truncated_rather_than_storing_a_whole_scan(self):
        # A finding can cite the output of `nmap -sV`, and a report that
        # inlines forty kilobytes of it is not a report. The cap is
        # generous enough for the lines that matter.
        queries.log_finding(self.conn, self.run_id, "h", "t", "d", "s",
                            evidence="x" * 50000)
        row = list(self.conn.execute("SELECT * FROM findings"))[0]
        self.assertLessEqual(len(row["evidence"]), queries.EVIDENCE_LIMIT)
        self.assertIn("truncated", row["evidence"])


class TestAnOlderDatabaseStillOpens(unittest.TestCase):
    """schema.sql is `CREATE TABLE IF NOT EXISTS`, so a database made
    before these columns existed keeps its old table and every insert
    would fail on the new names. An agent that cannot open its own store
    is an agent that cannot start, and the operator's history is in
    there."""

    def test_the_missing_columns_are_added_on_open(self):
        path = pathlib.Path(tempfile.mkdtemp()) / "old.db"
        old = sqlite3.connect(str(path))
        old.executescript("""
            CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT,
                trigger_type TEXT, trigger_data TEXT, mode TEXT,
                status TEXT DEFAULT 'running', phase INTEGER DEFAULT 1,
                config_json TEXT, started_at TEXT, completed_at TEXT);
            CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL, host TEXT NOT NULL,
                finding_type TEXT NOT NULL, data TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT '', timestamp TEXT NOT NULL);
            INSERT INTO runs (trigger_type, mode, config_json, started_at)
                VALUES ('old', 'auto', '{}', '2026-01-01T00:00:00Z');
            INSERT INTO findings (run_id, host, finding_type, data, source,
                timestamp) VALUES
                (1, '10.0.1.5', 'service', 'an older finding', 'executor',
                 '2026-01-01T00:00:00Z');
        """)
        old.commit()
        old.close()

        conn = db.open_store(str(path))
        columns = {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
        self.assertIn("evidence", columns)
        self.assertIn("proof_basis", columns)

    def test_the_rows_that_were_already_there_survive(self):
        path = pathlib.Path(tempfile.mkdtemp()) / "old.db"
        old = sqlite3.connect(str(path))
        old.executescript("""
            CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT,
                trigger_type TEXT, trigger_data TEXT, mode TEXT,
                status TEXT DEFAULT 'running', phase INTEGER DEFAULT 1,
                config_json TEXT, started_at TEXT, completed_at TEXT);
            CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL, host TEXT NOT NULL,
                finding_type TEXT NOT NULL, data TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT '', timestamp TEXT NOT NULL);
            INSERT INTO runs (trigger_type, mode, config_json, started_at)
                VALUES ('old', 'auto', '{}', '2026-01-01T00:00:00Z');
            INSERT INTO findings (run_id, host, finding_type, data, source,
                timestamp) VALUES
                (1, '10.0.1.5', 'service', 'an older finding', 'executor',
                 '2026-01-01T00:00:00Z');
        """)
        old.commit()
        old.close()

        conn = db.open_store(str(path))
        row = list(conn.execute("SELECT * FROM findings"))[0]
        self.assertEqual(row["data"], "an older finding")
        self.assertIsNone(row["evidence"])

    def test_opening_twice_is_not_an_error(self):
        # The migration runs on every open, so it has to be a no-op the
        # second time rather than failing on a duplicate column.
        path = pathlib.Path(tempfile.mkdtemp()) / "fresh.db"
        db.open_store(str(path)).close()
        conn = db.open_store(str(path))
        columns = {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
        self.assertIn("evidence", columns)


if __name__ == "__main__":
    unittest.main()
