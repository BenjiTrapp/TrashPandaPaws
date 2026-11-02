#!/usr/bin/env python3
"""
Tests for the agent SQLite store: schema, foreign keys, run lifecycle,
scoring, memory with salience decay and FTS5/LIKE search, script upsert,
and LLM interaction accounting. All tests run against a real in-memory
SQLite database.
"""

import re
import sqlite3
import sys
import tempfile
import unittest
import unittest.mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent.store import db, queries


RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00$")


def _iso_days_ago(days: float) -> str:
    moment = datetime.now(timezone.utc) - timedelta(days=days)
    return moment.isoformat(timespec="microseconds")


def _conn() -> sqlite3.Connection:
    return db.open_store(":memory:")


def _fresh_run(conn: sqlite3.Connection) -> int:
    return queries.create_run(conn, "campaign", None, "auto", "{}")


def _llm_fields(**overrides) -> dict:
    fields = {
        "provider": "anthropic",
        "model": "claude-test",
        "caller_context": "orchestrator",
        "input_tokens": 100,
        "output_tokens": 20,
        "total_tokens": 120,
        "latency_ms": 350,
        "status": "success",
    }
    fields.update(overrides)
    return fields


# ── Schema ──

class TestSchema(unittest.TestCase):
    def test_open_store_creates_all_tables(self):
        conn = _conn()
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for t in ("runs", "tasks", "findings", "score_events", "approvals",
                  "memories", "scripts", "scheduled_tasks", "cve_cache",
                  "llm_interactions"):
            self.assertIn(t, names)

    def test_wire_and_wifi_tables_are_not_created(self):
        conn = _conn()
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for t in ("wire_intel", "wifi_aps", "wifi_clients", "wifi_credentials"):
            self.assertNotIn(t, names)

    def test_foreign_keys_enforced(self):
        conn = _conn()
        self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        with self.assertRaises(sqlite3.IntegrityError):
            queries.create_task(conn, 9999, "t", "d", "agent", 1)

    def test_pragmas_applied(self):
        conn = _conn()
        self.assertEqual(conn.execute("PRAGMA synchronous").fetchone()[0], 1)
        self.assertEqual(conn.execute("PRAGMA temp_store").fetchone()[0], 2)

    def test_wal_enabled_on_file_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.open_store(str(Path(tmp) / "agent.db"))
            try:
                mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            finally:
                conn.close()
        self.assertEqual(mode, "wal")

    def test_check_constraints_reject_bad_enum_values(self):
        conn = _conn()
        rid = _fresh_run(conn)
        with self.assertRaises(sqlite3.IntegrityError):
            queries.create_task(conn, rid, "t", "d", "bogus-lane", 1)
        with self.assertRaises(sqlite3.IntegrityError):
            queries.set_run_status(conn, rid, "exploded")
        with self.assertRaises(sqlite3.IntegrityError):
            queries.save_memory(conn, "s", None, "x", "procedural")

    def test_has_fts5_reports_a_bool(self):
        self.assertIsInstance(db.has_fts5(_conn()), bool)

    def test_store_opens_without_fts5_and_skips_virtual_tables(self):
        with unittest.mock.patch.object(db, "has_fts5", return_value=False):
            with self.assertLogs(db.logger, level="WARNING"):
                conn = _conn()
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("memories", names)
        self.assertNotIn("memories_fts", names)
        queries.save_memory(conn, "s", None, "works without fts", "semantic")

    def test_reopening_with_fts5_indexes_rows_written_without_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "agent.db")
            with unittest.mock.patch.object(db, "has_fts5", return_value=False):
                with self.assertLogs(db.logger, level="WARNING"):
                    conn = db.open_store(path)
            queries.save_memory(conn, "s", None, "kerberoasting candidate", "semantic")
            queries.save_script(conn, "sweep", "echo a", "bash", "ping sweep", "[]")
            conn.close()
            conn = db.open_store(path)
            hits = queries.search_memory(conn, "s", "kerberoasting", 10)
            scripts = queries.search_scripts(conn, "ping", 10)
            conn.close()
        self.assertEqual([h["content"] for h in hits], ["kerberoasting candidate"])
        self.assertEqual([r["name"] for r in scripts], ["sweep"])


# ── Run lifecycle ──

class TestRunLifecycle(unittest.TestCase):
    def test_run_status_and_phase_roundtrip(self):
        conn = _conn()
        rid = queries.create_run(conn, "campaign", "10.0.1.0/24", "supervised", "{}")
        queries.set_run_phase(conn, rid, 3)
        queries.set_run_status(conn, rid, "paused")
        run = queries.get_run(conn, rid)
        self.assertEqual(run["phase"], 3)
        self.assertEqual(run["status"], "paused")

    def test_new_run_is_running_with_no_completion_time(self):
        conn = _conn()
        run = queries.get_run(conn, _fresh_run(conn))
        self.assertEqual(run["status"], "running")
        self.assertIsNone(run["completed_at"])
        self.assertRegex(run["started_at"], RFC3339_UTC)

    def test_terminal_status_stamps_completed_at(self):
        conn = _conn()
        rid = _fresh_run(conn)
        queries.set_run_status(conn, rid, "completed")
        self.assertRegex(queries.get_run(conn, rid)["completed_at"], RFC3339_UTC)

    def test_get_run_unknown_id_returns_none(self):
        self.assertIsNone(queries.get_run(_conn(), 4242))

    def test_list_unfinished_runs_includes_running_and_paused_only(self):
        conn = _conn()
        a = _fresh_run(conn)
        b = _fresh_run(conn)
        c = _fresh_run(conn)
        d = _fresh_run(conn)
        queries.set_run_status(conn, b, "paused")
        queries.set_run_status(conn, c, "completed")
        queries.set_run_status(conn, d, "aborted")
        self.assertEqual({r["id"] for r in queries.list_unfinished_runs(conn)}, {a, b})


# ── Tasks, findings, summary ──

class TestTasksAndFindings(unittest.TestCase):
    def test_update_task_stores_status_and_result(self):
        conn = _conn()
        rid = _fresh_run(conn)
        tid = queries.create_task(conn, rid, "scan", "nmap sweep", "agent", 2)
        queries.update_task(conn, tid, "completed", "3 hosts up")
        row = conn.execute(
            "SELECT status, result, completed_at FROM tasks WHERE id = ?", (tid,)
        ).fetchone()
        self.assertEqual((row["status"], row["result"]), ("completed", "3 hosts up"))
        self.assertRegex(row["completed_at"], RFC3339_UTC)

    def test_findings_by_host_spans_runs_and_filters_host(self):
        conn = _conn()
        r1, r2 = _fresh_run(conn), _fresh_run(conn)
        queries.log_finding(conn, r1, "10.0.1.5", "service", "SMB 3.1.1", "exec")
        queries.log_finding(conn, r2, "10.0.1.5", "service", "RDP", "exec")
        queries.log_finding(conn, r1, "10.0.1.6", "service", "SSH", "exec")
        found = queries.get_findings_by_host(conn, "10.0.1.5")
        self.assertEqual([f["data"] for f in found], ["SMB 3.1.1", "RDP"])

    def test_run_summary_counts(self):
        conn = _conn()
        rid = _fresh_run(conn)
        other = _fresh_run(conn)
        queries.set_run_phase(conn, rid, 4)
        t1 = queries.create_task(conn, rid, "a", "d", "agent", 1)
        t2 = queries.create_task(conn, rid, "b", "d", "agent", 1)
        queries.create_task(conn, rid, "c", "d", "operator", 1)
        queries.create_task(conn, other, "x", "d", "agent", 1)
        queries.update_task(conn, t1, "completed", "ok")
        queries.update_task(conn, t2, "failed", "boom")
        queries.log_finding(conn, rid, "h", "t", "d", "s")
        queries.log_score(conn, rid, "service_identified", 15, "low", False)
        queries.log_score(conn, rid, "detection", -100, "high", True)
        queries.log_score(conn, other, "detection", -100, "high", True)
        self.assertEqual(queries.get_run_summary(conn, rid), {
            "task_count": 3,
            "completed_task_count": 1,
            "failed_task_count": 1,
            "finding_count": 1,
            "total_score": -85,
            "detection_count": 1,
            "phase": 4,
        })


# ── Scoring ──

class TestScoring(unittest.TestCase):
    def test_score_context_totals_and_detection_count(self):
        conn = _conn()
        rid = _fresh_run(conn)
        queries.log_score(conn, rid, "service_identified", 15, "low", False)
        queries.log_score(conn, rid, "detection", -100, "high", True)
        ctx = queries.get_score_context(conn, rid)
        self.assertEqual(ctx["total_score"], -85)
        self.assertEqual(ctx["detection_count"], 1)

    def test_score_context_empty_run_is_zero(self):
        ctx = queries.get_score_context(_conn(), 1)
        self.assertEqual(ctx["total_score"], 0)
        self.assertEqual(ctx["detection_count"], 0)
        self.assertEqual(ctx["recent_events"], [])

    def test_recent_events_capped_at_five_newest_first(self):
        conn = _conn()
        rid = _fresh_run(conn)
        for i in range(7):
            queries.log_score(conn, rid, "port_found_%d" % i, 5, "low", False)
        ctx = queries.get_score_context(conn, rid)
        self.assertEqual(len(ctx["recent_events"]), 5)
        self.assertEqual(ctx["recent_events"][0]["action"], "port_found_6")
        self.assertEqual(ctx["recent_events"][-1]["action"], "port_found_2")

    def test_detected_is_returned_as_bool(self):
        conn = _conn()
        rid = _fresh_run(conn)
        queries.log_score(conn, rid, "detection", -100, "high", True)
        event = queries.get_score_context(conn, rid)["recent_events"][0]
        self.assertIs(event["detected"], True)


# ── Approvals ──

class TestApprovals(unittest.TestCase):
    def test_pending_until_decided(self):
        conn = _conn()
        rid = _fresh_run(conn)
        aid = queries.create_approval(conn, rid, "lsass_dump", "{}", "{}")
        self.assertEqual([a["id"] for a in queries.get_pending_approvals(conn, rid)], [aid])
        queries.decide_approval(conn, aid, "approved", "operator")
        self.assertEqual(queries.get_pending_approvals(conn, rid), [])
        row = conn.execute("SELECT decision, decided_by, decided_at FROM approvals").fetchone()
        self.assertEqual((row["decision"], row["decided_by"]), ("approved", "operator"))
        self.assertRegex(row["decided_at"], RFC3339_UTC)

    def test_pending_scoped_to_run(self):
        conn = _conn()
        r1, r2 = _fresh_run(conn), _fresh_run(conn)
        queries.create_approval(conn, r1, "deauth", "{}", "{}")
        self.assertEqual(queries.get_pending_approvals(conn, r2), [])

    def test_decided_by_accepts_exactly_the_four_deciders(self):
        conn = _conn()
        rid = _fresh_run(conn)
        for decider in ("operator", "ev", "timeout", "hard"):
            aid = queries.create_approval(conn, rid, "deauth", "{}", "{}")
            queries.decide_approval(conn, aid, "denied", decider)
            stored = conn.execute(
                "SELECT decided_by FROM approvals WHERE id = ?", (aid,)).fetchone()[0]
            self.assertEqual(stored, decider)

    def test_decided_by_rejects_unknown_decider(self):
        conn = _conn()
        aid = queries.create_approval(conn, _fresh_run(conn), "deauth", "{}", "{}")
        with self.assertRaises(sqlite3.IntegrityError):
            queries.decide_approval(conn, aid, "approved", "nobody")


# ── Memory ──

class TestMemory(unittest.TestCase):
    def test_search_reinforces_salience(self):
        conn = _conn()
        queries.save_memory(conn, "run:1", None, "SMB signing disabled on dc01", "semantic")
        queries.search_memory(conn, "run:1", "smb signing", 10)
        row = conn.execute("SELECT salience FROM memories").fetchone()
        self.assertAlmostEqual(row[0], 1.1, places=5)

    def test_salience_reinforcement_capped_at_five(self):
        conn = _conn()
        queries.save_memory(conn, "run:1", None, "target host", "semantic")
        conn.execute("UPDATE memories SET salience = 4.95")
        queries.search_memory(conn, "run:1", "target", 10)
        self.assertAlmostEqual(
            conn.execute("SELECT salience FROM memories").fetchone()[0], 5.0, places=5)

    def test_search_is_scoped_by_scope_key(self):
        conn = _conn()
        queries.save_memory(conn, "run:1", None, "kerberos ticket seen", "semantic")
        queries.save_memory(conn, "run:2", None, "kerberos ticket other run", "semantic")
        hits = queries.search_memory(conn, "run:1", "kerberos", 10)
        self.assertEqual([h["content"] for h in hits], ["kerberos ticket seen"])
        untouched = conn.execute(
            "SELECT salience FROM memories WHERE scope_key = 'run:2'").fetchone()[0]
        self.assertAlmostEqual(untouched, 1.0, places=5)

    def test_search_matches_prefixes_and_orders_by_salience(self):
        conn = _conn()
        low = queries.save_memory(conn, "s", None, "kerberoasting candidate", "semantic")
        high = queries.save_memory(conn, "s", None, "kerberos realm EXAMPLE", "semantic")
        conn.execute("UPDATE memories SET salience = 3.0 WHERE id = ?", (high,))
        hits = queries.search_memory(conn, "s", "kerb", 10)
        self.assertEqual([h["id"] for h in hits], [high, low])

    def test_search_respects_limit(self):
        conn = _conn()
        for i in range(4):
            queries.save_memory(conn, "s", None, "host %d alive" % i, "episodic")
        self.assertEqual(len(queries.search_memory(conn, "s", "host", 2)), 2)

    def test_search_survives_fts_syntax_in_query(self):
        conn = _conn()
        queries.save_memory(conn, "s", None, "admin and guest accounts", "semantic")
        for q in ('"unbalanced', "AND", "foo AND (bar", "a:b*c", "NOT OR NEAR"):
            queries.search_memory(conn, "s", q, 10)
        hits = queries.search_memory(conn, "s", "and", 10)
        self.assertEqual([h["content"] for h in hits], ["admin and guest accounts"])

    def test_search_with_only_punctuation_returns_empty(self):
        conn = _conn()
        queries.save_memory(conn, "s", None, "anything", "semantic")
        self.assertEqual(queries.search_memory(conn, "s", "!!! ???", 10), [])

    def test_search_reflects_content_updated_in_place(self):
        conn = _conn()
        mid = queries.save_memory(conn, "s", None, "alpha finding", "semantic")
        conn.execute("UPDATE memories SET content = 'bravo finding' WHERE id = ?", (mid,))
        self.assertEqual(queries.search_memory(conn, "s", "alpha", 10), [])
        self.assertEqual(len(queries.search_memory(conn, "s", "bravo", 10)), 1)

    def test_deleted_memory_leaves_the_index(self):
        conn = _conn()
        mid = queries.save_memory(conn, "s", None, "ephemeral note", "episodic")
        conn.execute("DELETE FROM memories WHERE id = ?", (mid,))
        self.assertEqual(queries.search_memory(conn, "s", "ephemeral", 10), [])

    def test_decay_sweep_only_touches_entries_older_than_a_day(self):
        conn = _conn()
        old = queries.save_memory(conn, "s", None, "old entry", "episodic")
        new = queries.save_memory(conn, "s", None, "new entry", "episodic")
        conn.execute("UPDATE memories SET created_at = ? WHERE id = ?",
                     (_iso_days_ago(3), old))
        queries.run_decay_sweep(conn)
        sal = dict(conn.execute("SELECT id, salience FROM memories").fetchall())
        self.assertAlmostEqual(sal[old], 0.98, places=5)
        self.assertAlmostEqual(sal[new], 1.0, places=5)

    def test_decay_sweep_prunes_below_threshold(self):
        conn = _conn()
        queries.save_memory(conn, "s", None, "faded", "episodic")
        conn.execute("UPDATE memories SET salience = 0.05, created_at = ?",
                     (_iso_days_ago(3),))
        self.assertEqual(queries.run_decay_sweep(conn), 1)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0], 0)

    def test_decay_sweep_returns_zero_when_nothing_pruned(self):
        conn = _conn()
        queries.save_memory(conn, "s", None, "fresh", "semantic")
        self.assertEqual(queries.run_decay_sweep(conn), 0)

    def test_stored_timestamps_share_one_uniform_format(self):
        conn = _conn()
        queries.save_memory(conn, "s", None, "stamp check", "semantic")
        row = conn.execute("SELECT created_at, accessed_at FROM memories").fetchone()
        self.assertRegex(row["created_at"], RFC3339_UTC)
        self.assertRegex(row["accessed_at"], RFC3339_UTC)

    def test_search_falls_back_to_like_without_fts5(self):
        conn = _conn()
        queries.save_memory(conn, "s", None, "kerberoasting candidate found", "semantic")
        with unittest.mock.patch.object(db, "has_fts5", return_value=False):
            hits = queries.search_memory(conn, "s", "kerberoasting", 10)
        self.assertEqual(len(hits), 1)

    def test_like_fallback_is_scoped_and_reinforces(self):
        conn = _conn()
        queries.save_memory(conn, "s", None, "kerberoasting here", "semantic")
        queries.save_memory(conn, "other", None, "kerberoasting there", "semantic")
        with unittest.mock.patch.object(db, "has_fts5", return_value=False):
            hits = queries.search_memory(conn, "s", "kerbero", 10)
        self.assertEqual([h["content"] for h in hits], ["kerberoasting here"])
        sal = conn.execute(
            "SELECT salience FROM memories WHERE scope_key = 's'").fetchone()[0]
        self.assertAlmostEqual(sal, 1.1, places=5)

    def test_like_fallback_treats_wildcards_literally(self):
        conn = _conn()
        queries.save_memory(conn, "s", None, "plain text", "semantic")
        with unittest.mock.patch.object(db, "has_fts5", return_value=False):
            self.assertEqual(queries.search_memory(conn, "s", "%", 10), [])
            self.assertEqual(queries.search_memory(conn, "s", "_____", 10), [])


# ── Scripts ──

class TestScripts(unittest.TestCase):
    def test_save_script_upserts_on_name(self):
        conn = _conn()
        queries.save_script(conn, "sweep", "echo a", "bash", "first", "[]")
        queries.save_script(conn, "sweep", "echo b", "bash", "second", "[]")
        rows = conn.execute("SELECT code, description FROM scripts").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "echo b")

    def test_upsert_returns_stable_id_and_keeps_created_at(self):
        conn = _conn()
        first = queries.save_script(conn, "sweep", "echo a", "bash", "first", "[]")
        created = queries.get_script_by_name(conn, "sweep")["created_at"]
        second = queries.save_script(conn, "sweep", "echo b", "bash", "second", "[]")
        self.assertEqual(first, second)
        self.assertEqual(queries.get_script_by_name(conn, "sweep")["created_at"], created)

    def test_get_script_by_name(self):
        conn = _conn()
        queries.save_script(conn, "sweep", "echo a", "bash", "ping sweep", '["net"]')
        script = queries.get_script_by_name(conn, "sweep")
        self.assertEqual(script["code"], "echo a")
        self.assertEqual(script["language"], "bash")
        self.assertEqual(script["use_count"], 0)
        self.assertIsNone(queries.get_script_by_name(conn, "missing"))

    def test_search_scripts_by_description_and_updated_text(self):
        conn = _conn()
        queries.save_script(conn, "sweep", "echo a", "bash", "ping sweep of subnet", "[]")
        queries.save_script(conn, "dump", "echo b", "bash", "credential harvest", "[]")
        self.assertEqual([s["name"] for s in queries.search_scripts(conn, "ping", 10)],
                         ["sweep"])
        queries.save_script(conn, "sweep", "echo a", "bash", "arp discovery", "[]")
        self.assertEqual(queries.search_scripts(conn, "ping", 10), [])
        self.assertEqual([s["name"] for s in queries.search_scripts(conn, "arp", 10)],
                         ["sweep"])

    def test_search_scripts_falls_back_to_like_without_fts5(self):
        conn = _conn()
        queries.save_script(conn, "sweep", "echo a", "bash", "ping sweep", "[]")
        with unittest.mock.patch.object(db, "has_fts5", return_value=False):
            hits = queries.search_scripts(conn, "sweep", 10)
        self.assertEqual([s["name"] for s in hits], ["sweep"])


# ── LLM accounting ──

class TestLlmInteractions(unittest.TestCase):
    def test_log_and_summarise_tokens_per_run(self):
        conn = _conn()
        rid, other = _fresh_run(conn), _fresh_run(conn)
        queries.log_llm_interaction(conn, run_id=rid, **_llm_fields())
        queries.log_llm_interaction(conn, run_id=rid, **_llm_fields(
            input_tokens=50, output_tokens=10, total_tokens=60))
        queries.log_llm_interaction(conn, run_id=other, **_llm_fields())
        self.assertEqual(queries.get_run_token_summary(conn, rid), {
            "input_tokens": 150,
            "output_tokens": 30,
            "total_tokens": 180,
            "call_count": 2,
        })

    def test_token_summary_of_run_without_calls_is_zero(self):
        conn = _conn()
        self.assertEqual(queries.get_run_token_summary(conn, _fresh_run(conn)), {
            "input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "call_count": 0})

    def test_error_row_with_message_and_no_text(self):
        conn = _conn()
        rid = _fresh_run(conn)
        queries.log_llm_interaction(conn, run_id=rid, **_llm_fields(
            status="error", error_message="rate limited",
            input_tokens=0, output_tokens=0, total_tokens=0))
        row = conn.execute(
            "SELECT status, error_message, prompt_text, created_at "
            "FROM llm_interactions").fetchone()
        self.assertEqual((row["status"], row["error_message"]), ("error", "rate limited"))
        self.assertIsNone(row["prompt_text"])
        self.assertRegex(row["created_at"], RFC3339_UTC)

    def test_total_tokens_derived_when_omitted(self):
        conn = _conn()
        rid = _fresh_run(conn)
        fields = _llm_fields()
        del fields["total_tokens"]
        queries.log_llm_interaction(conn, run_id=rid, **fields)
        self.assertEqual(queries.get_run_token_summary(conn, rid)["total_tokens"], 120)

    def test_unknown_field_rejected(self):
        conn = _conn()
        with self.assertRaises(TypeError):
            queries.log_llm_interaction(conn, run_id=None, bogus=1, **_llm_fields())

    def test_invalid_status_rejected(self):
        conn = _conn()
        with self.assertRaises(sqlite3.IntegrityError):
            queries.log_llm_interaction(conn, run_id=None, **_llm_fields(status="maybe"))

    def test_run_id_must_reference_existing_run(self):
        conn = _conn()
        with self.assertRaises(sqlite3.IntegrityError):
            queries.log_llm_interaction(conn, run_id=9999, **_llm_fields())


if __name__ == "__main__":
    unittest.main()
