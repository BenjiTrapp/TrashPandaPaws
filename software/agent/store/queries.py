"""All SQL access for the agent store, as plain functions over a connection."""

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from software.agent.store import db

DECAY_FACTOR = 0.98
PRUNE_THRESHOLD = 0.1
DECAY_AGE_SECONDS = 86400
SALIENCE_BOOST = 0.1
SALIENCE_CAP = 5.0

_RUN_TERMINAL = ("completed", "failed", "aborted")
_TASK_OPEN = ("pending", "running")

_LLM_FIELDS = (
    "run_id", "request_id", "provider", "model", "caller_context",
    "prompt_text", "response_text", "input_tokens", "output_tokens",
    "total_tokens", "latency_ms", "status", "error_message",
)


# ── Helpers ──

def _iso(moment: datetime) -> str:
    """The one place a timestamp string is produced.

    Comparisons on these columns are lexicographic, so every write must use
    the same offset spelling and the same sub-second precision.
    """
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _now() -> str:
    return _iso(datetime.now(timezone.utc))


def _dicts(rows) -> List[Dict[str, Any]]:
    return [dict(r) for r in rows]


def _one(row) -> Optional[Dict[str, Any]]:
    return dict(row) if row is not None else None


def _search_words(query: str) -> List[str]:
    return re.sub(r"[^\w\s]", " ", query).split()


def _like_clause(columns: List[str], words: List[str]):
    clauses = []
    params = []
    for word in words:
        escaped = word.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        for column in columns:
            clauses.append("%s LIKE ? ESCAPE '\\'" % column)
            params.append("%" + escaped + "%")
    return "(" + " OR ".join(clauses) + ")", params


def _fts_match(words: List[str]) -> str:
    return " OR ".join('"%s"*' % w for w in words)


# ── Runs ──

def create_run(conn, trigger_type, trigger_data, mode, config_json) -> int:
    cur = conn.execute(
        "INSERT INTO runs (trigger_type, trigger_data, mode, config_json, started_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (trigger_type, trigger_data, mode, config_json, _now()),
    )
    conn.commit()
    return cur.lastrowid


def set_run_status(conn, run_id, status) -> None:
    completed_at = _now() if status in _RUN_TERMINAL else None
    conn.execute(
        "UPDATE runs SET status = ?, completed_at = ? WHERE id = ?",
        (status, completed_at, run_id),
    )
    conn.commit()


def set_run_phase(conn, run_id, phase: int) -> None:
    conn.execute("UPDATE runs SET phase = ? WHERE id = ?", (phase, run_id))
    conn.commit()


def get_run(conn, run_id) -> Optional[Dict[str, Any]]:
    return _one(conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone())


def list_unfinished_runs(conn) -> List[Dict[str, Any]]:
    return _dicts(conn.execute(
        "SELECT * FROM runs WHERE status IN ('running', 'paused') ORDER BY id"))


# ── Tasks ──

def create_task(conn, run_id, name, description, lane, phase) -> int:
    cur = conn.execute(
        "INSERT INTO tasks (run_id, name, description, lane, phase, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (run_id, name, description, lane, phase, _now()),
    )
    conn.commit()
    return cur.lastrowid


def update_task(conn, task_id, status, result) -> None:
    completed_at = None if status in _TASK_OPEN else _now()
    conn.execute(
        "UPDATE tasks SET status = ?, result = ?, completed_at = ? WHERE id = ?",
        (status, result, completed_at, task_id),
    )
    conn.commit()


# ── Findings ──

def log_finding(conn, run_id, host, finding_type, data, source) -> int:
    cur = conn.execute(
        "INSERT INTO findings (run_id, host, finding_type, data, source, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (run_id, host, finding_type, data, source, _now()),
    )
    conn.commit()
    return cur.lastrowid


def get_findings_by_host(conn, host, run_id=None) -> List[Dict[str, Any]]:
    """Findings for one host, optionally only from one run.

    `run_id` exists because the router resolves hostnames from findings: a
    name is a legitimate target only if this run observed it tied to an
    address. Unfiltered, a finding from a different engagement could resolve
    a name for this one, which is a read across clients.
    """
    if run_id is None:
        return _dicts(conn.execute(
            "SELECT * FROM findings WHERE host = ? ORDER BY id", (host,)))
    return _dicts(conn.execute(
        "SELECT * FROM findings WHERE host = ? AND run_id = ? ORDER BY id",
        (host, run_id)))


# ── Scoring ──

def log_score(conn, run_id, action, points, risk_level, detected) -> int:
    cur = conn.execute(
        "INSERT INTO score_events (run_id, action, points, risk_level, detected, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (run_id, action, points, risk_level, 1 if detected else 0, _now()),
    )
    conn.commit()
    return cur.lastrowid


def get_score_context(conn, run_id) -> Dict[str, Any]:
    totals = conn.execute(
        "SELECT COALESCE(SUM(points), 0) AS total_score, "
        "COALESCE(SUM(detected), 0) AS detection_count "
        "FROM score_events WHERE run_id = ?", (run_id,)).fetchone()
    recent = _dicts(conn.execute(
        "SELECT * FROM score_events WHERE run_id = ? ORDER BY id DESC LIMIT 5",
        (run_id,)))
    for event in recent:
        event["detected"] = bool(event["detected"])
    return {
        "total_score": totals["total_score"],
        "detection_count": totals["detection_count"],
        "recent_events": recent,
    }


def get_run_summary(conn, run_id) -> Dict[str, Any]:
    row = conn.execute(
        "SELECT "
        "(SELECT COUNT(*) FROM tasks WHERE run_id = :r) AS task_count, "
        "(SELECT COUNT(*) FROM tasks WHERE run_id = :r AND status = 'completed') "
        "  AS completed_task_count, "
        "(SELECT COUNT(*) FROM tasks WHERE run_id = :r AND status = 'failed') "
        "  AS failed_task_count, "
        "(SELECT COUNT(*) FROM findings WHERE run_id = :r) AS finding_count, "
        "(SELECT COALESCE(SUM(points), 0) FROM score_events WHERE run_id = :r) "
        "  AS total_score, "
        "(SELECT COALESCE(SUM(detected), 0) FROM score_events WHERE run_id = :r) "
        "  AS detection_count, "
        "(SELECT phase FROM runs WHERE id = :r) AS phase",
        {"r": run_id}).fetchone()
    return dict(row)


# ── Approvals ──

def create_approval(conn, run_id, action, classification_json, ev_json) -> int:
    cur = conn.execute(
        "INSERT INTO approvals (run_id, action, classification_json, ev_json, requested_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (run_id, action, classification_json, ev_json, _now()),
    )
    conn.commit()
    return cur.lastrowid


def decide_approval(conn, approval_id, decision, decided_by) -> None:
    conn.execute(
        "UPDATE approvals SET decision = ?, decided_by = ?, decided_at = ? WHERE id = ?",
        (decision, decided_by, _now(), approval_id),
    )
    conn.commit()


def get_pending_approvals(conn, run_id) -> List[Dict[str, Any]]:
    return _dicts(conn.execute(
        "SELECT * FROM approvals WHERE run_id = ? AND decision IS NULL ORDER BY id",
        (run_id,)))


# ── Memory ──

def save_memory(conn, scope_key, topic_key, content, sector) -> int:
    now = _now()
    cur = conn.execute(
        "INSERT INTO memories (scope_key, topic_key, content, sector, created_at, accessed_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (scope_key, topic_key, content, sector, now, now),
    )
    conn.commit()
    return cur.lastrowid


def search_memory(conn, scope_key, query, limit) -> List[Dict[str, Any]]:
    words = _search_words(query)
    if not words:
        return []
    if db.has_fts5(conn):
        # The FTS index only knows `content`; scope_key is filtered on the join.
        rows = conn.execute(
            "SELECT m.id FROM memories_fts JOIN memories m ON m.id = memories_fts.rowid "
            "WHERE memories_fts MATCH ? AND m.scope_key = ? "
            "ORDER BY m.salience DESC LIMIT ?",
            (_fts_match(words), scope_key, limit)).fetchall()
    else:
        clause, params = _like_clause(["content"], words)
        rows = conn.execute(
            "SELECT id FROM memories WHERE scope_key = ? AND " + clause +
            " ORDER BY salience DESC LIMIT ?",
            [scope_key] + params + [limit]).fetchall()
    ids = [r["id"] for r in rows]
    if not ids:
        return []

    marks = ",".join("?" * len(ids))
    conn.execute(
        "UPDATE memories SET salience = MIN(salience + ?, ?), accessed_at = ? "
        "WHERE id IN (%s)" % marks,
        [SALIENCE_BOOST, SALIENCE_CAP, _now()] + ids)
    conn.commit()
    return _dicts(conn.execute(
        "SELECT * FROM memories WHERE id IN (%s) ORDER BY salience DESC, id" % marks,
        ids))


def run_decay_sweep(conn) -> int:
    cutoff = _iso(datetime.now(timezone.utc) - timedelta(seconds=DECAY_AGE_SECONDS))
    conn.execute(
        "UPDATE memories SET salience = salience * ? WHERE created_at < ?",
        (DECAY_FACTOR, cutoff))
    cur = conn.execute("DELETE FROM memories WHERE salience < ?", (PRUNE_THRESHOLD,))
    conn.commit()
    return cur.rowcount


# ── Scripts ──

def save_script(conn, name, code, language, description, tags) -> int:
    now = _now()
    conn.execute(
        "INSERT INTO scripts (name, description, language, tags, code, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(name) DO UPDATE SET "
        "description = excluded.description, language = excluded.language, "
        "tags = excluded.tags, code = excluded.code, updated_at = excluded.updated_at",
        (name, description, language, tags, code, now, now))
    conn.commit()
    return conn.execute("SELECT id FROM scripts WHERE name = ?", (name,)).fetchone()["id"]


def search_scripts(conn, query, limit) -> List[Dict[str, Any]]:
    words = _search_words(query)
    if not words:
        return []
    if db.has_fts5(conn):
        return _dicts(conn.execute(
            "SELECT s.* FROM scripts_fts JOIN scripts s ON s.id = scripts_fts.rowid "
            "WHERE scripts_fts MATCH ? ORDER BY s.use_count DESC, s.name LIMIT ?",
            (_fts_match(words), limit)))
    clause, params = _like_clause(["name", "description", "tags"], words)
    return _dicts(conn.execute(
        "SELECT * FROM scripts WHERE " + clause + " ORDER BY use_count DESC, name LIMIT ?",
        params + [limit]))


def get_script_by_name(conn, name) -> Optional[Dict[str, Any]]:
    return _one(conn.execute("SELECT * FROM scripts WHERE name = ?", (name,)).fetchone())


# ── Schedules ──

_RESULT_MAX = 200


def _next_run(expression: str, after: Optional[datetime] = None) -> str:
    # Imported here, not at the top: the scheduler imports this module, and
    # cron arithmetic belongs with the scheduler. Moving it here would put a
    # dependency on croniter into the one module every other part of the
    # agent reads the store through.
    from software.agent import scheduler
    return scheduler.next_occurrence(expression, after)


def create_schedule(conn, prompt, config_json, schedule) -> int:
    """Store a recurring task; the id is the table's integer rowid.

    `schedule` is not checked here beyond what computing the first run
    demands: an expression croniter rejects raises, and nothing is stored.
    The service validates first so the operator gets a readable reason.
    """
    next_run = _next_run(schedule)
    cur = conn.execute(
        "INSERT INTO scheduled_tasks (prompt, config_json, schedule, next_run, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (prompt, config_json, schedule, next_run, _now()))
    conn.commit()
    return cur.lastrowid


def get_schedule(conn, sid) -> Optional[Dict[str, Any]]:
    return _one(conn.execute(
        "SELECT * FROM scheduled_tasks WHERE id = ?", (sid,)).fetchone())


def list_schedules(conn) -> List[Dict[str, Any]]:
    return _dicts(conn.execute("SELECT * FROM scheduled_tasks ORDER BY id"))


def delete_schedule(conn, sid) -> bool:
    cur = conn.execute("DELETE FROM scheduled_tasks WHERE id = ?", (sid,))
    conn.commit()
    return cur.rowcount > 0


def pause_schedule(conn, sid) -> bool:
    cur = conn.execute(
        "UPDATE scheduled_tasks SET status = 'paused' "
        "WHERE id = ? AND status = 'active'", (sid,))
    conn.commit()
    return cur.rowcount > 0


def resume_schedule(conn, sid) -> bool:
    """Reactivate, with the next run counted from now.

    Not from where it was left: a schedule paused for a week would otherwise
    come back due, and run at once, at a moment nobody chose.
    """
    row = get_schedule(conn, sid)
    if row is None or row["status"] != "paused":
        return False
    conn.execute(
        "UPDATE scheduled_tasks SET status = 'active', next_run = ? WHERE id = ?",
        (_next_run(row["schedule"]), sid))
    conn.commit()
    return True


def get_due_schedules(conn) -> List[Dict[str, Any]]:
    return _dicts(conn.execute(
        "SELECT * FROM scheduled_tasks WHERE status = 'active' AND next_run <= ? "
        "ORDER BY next_run, id", (_now(),)))


def advance_schedule(conn, sid, last_result, *, ran=True) -> None:
    """Move next_run on, and record what happened.

    To the first slot after both now and the old next_run: after the old one
    so it always moves, after now so a slot that was missed is gone and not
    queued behind the one that was caught. `ran=False` is for a slot that was
    passed over; last_run then keeps naming the last time something started.
    """
    row = get_schedule(conn, sid)
    if row is None:
        return
    after = max(datetime.now(timezone.utc),
                datetime.fromisoformat(row["next_run"]))
    conn.execute(
        "UPDATE scheduled_tasks SET next_run = ?, last_result = ?, last_run = ? "
        "WHERE id = ?",
        (_next_run(row["schedule"], after), last_result[:_RESULT_MAX],
         _now() if ran else row["last_run"], sid))
    conn.commit()


def set_schedule_running(conn, sid, run_id) -> None:
    conn.execute("UPDATE scheduled_tasks SET running_run_id = ? WHERE id = ?",
                 (run_id, sid))
    conn.commit()


def finish_schedule(conn, sid, run_id, last_result) -> bool:
    """Clear the running mark and record how the run ended.

    Only if the row still names `run_id`: two callers settling the same run,
    or a row started again in between, must not both write.
    """
    cur = conn.execute(
        "UPDATE scheduled_tasks SET running_run_id = NULL, last_result = ? "
        "WHERE id = ? AND running_run_id = ?",
        (last_result[:_RESULT_MAX], sid, run_id))
    conn.commit()
    return cur.rowcount > 0


# ── CVE cache ──

def cache_cves(conn, cache_key, source, entries) -> int:
    """Replace whatever is cached under cache_key with `entries`.

    Replaced rather than appended to: a refetch after the TTL would otherwise
    leave the stale rows beside the fresh ones, and the lookup could not tell
    which to believe. One timestamp for the batch, because they were fetched
    together.
    """
    now = _now()
    try:
        conn.execute("DELETE FROM cve_cache WHERE cache_key = ?", (cache_key,))
        for entry in entries:
            conn.execute(
                "INSERT INTO cve_cache (cache_key, cve_id, description, cvss_score, "
                "cvss_vector, severity, references_json, published, source, fetched_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (cache_key, entry["cve_id"], entry.get("description") or "",
                 entry.get("cvss_score"), entry.get("cvss_vector"),
                 entry.get("severity"),
                 json.dumps(entry.get("references") or []),
                 entry.get("published"), source, now))
    except Exception:
        # Half a batch under one key would read as the complete answer.
        conn.rollback()
        raise
    conn.commit()
    return len(entries)


def get_cached_cves(conn, cache_key, max_age_days) -> List[Dict[str, Any]]:
    cutoff = _iso(datetime.now(timezone.utc) - timedelta(days=max_age_days))
    return _dicts(conn.execute(
        "SELECT * FROM cve_cache WHERE cache_key = ? AND fetched_at >= ? "
        "ORDER BY cvss_score IS NULL, cvss_score DESC, cve_id",
        (cache_key, cutoff)))


# ── LLM accounting ──

def log_llm_interaction(conn, **fields) -> int:
    unknown = set(fields) - set(_LLM_FIELDS)
    if unknown:
        raise TypeError("unknown llm_interactions fields: %s" % ", ".join(sorted(unknown)))
    if "total_tokens" not in fields:
        fields["total_tokens"] = fields.get("input_tokens", 0) + fields.get("output_tokens", 0)
    fields["created_at"] = _now()
    columns = ", ".join(fields)
    marks = ", ".join("?" * len(fields))
    cur = conn.execute(
        "INSERT INTO llm_interactions (%s) VALUES (%s)" % (columns, marks),
        list(fields.values()))
    conn.commit()
    return cur.lastrowid


def get_run_token_summary(conn, run_id) -> Dict[str, Any]:
    row = conn.execute(
        "SELECT COALESCE(SUM(input_tokens), 0) AS input_tokens, "
        "COALESCE(SUM(output_tokens), 0) AS output_tokens, "
        "COALESCE(SUM(total_tokens), 0) AS total_tokens, "
        "COUNT(*) AS call_count "
        "FROM llm_interactions WHERE run_id = ?", (run_id,)).fetchone()
    return dict(row)
