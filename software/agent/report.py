#!/usr/bin/env python3
"""The deliverable a campaign leaves behind.

A run used to end with the model's closing prose and some counters in
the drawer. There was no artefact: an operator who ran a campaign had
nothing to hand to the person who authorised it, and the findings sat in
SQLite behind a tool call.

Three decisions worth stating, because each is a way this could have
been less useful:

  * **An empty campaign still gets a report.** A report written only
    when something was found teaches the reader that its absence means
    "nothing ran". The preamble tells the model that finding nothing is a
    valid outcome; a report that cannot express that would contradict it.

  * **What was refused is in it.** A report listing only what the agent
    did invites the reader to assume it did everything it wanted. The
    gated actions and their verdicts are the evidence that it did not,
    and they are the part an authorising party actually needs.

  * **An inferred finding is labelled inferred.** The proof basis is
    carried through rather than flattened, so nobody has to guess whether
    the agent reproduced something or read it off a banner. A finding
    with no basis recorded gets none invented for it.

Markdown rather than HTML or PDF: it goes into tickets, chat and git,
and the operator GUI can render it without a dependency.
"""

import json
from typing import Any, Dict, List

from software.agent.store import queries
from software.agent.tools.recon import NO_HOST

# A report is read by a person and pasted into tickets. queries.log_finding
# already caps evidence on the way in; this is the second guard, because the
# store is also written by older code paths and by hand during triage.
EVIDENCE_LINES = 20
EVIDENCE_CHARS = 1200

# Beyond this the document stops being read. The count is always stated, so
# a truncated report says how much it is not showing.
MAX_FINDINGS = 200

_MODE_NAMES = {"auto": "Full Automated", "supervised": "Automated Attack"}


def _campaign(conn, run_id) -> Dict[str, Any]:
    row = conn.execute(
        "SELECT trigger_type, mode, status, phase, config_json, started_at, "
        "completed_at FROM runs WHERE id = ?", (run_id,)).fetchone()
    if row is None:
        return {}
    out = dict(row)
    try:
        # A malformed config must not cost the report: this is the last
        # thing a campaign does, and losing it loses the findings with it.
        out["config"] = (json.loads(out["config_json"]) or {}).get(
            "campaign", {})
    except (TypeError, ValueError):
        out["config"] = {}
    return out


def _clip_evidence(text: str) -> str:
    lines = text.splitlines()
    clipped = False
    if len(lines) > EVIDENCE_LINES:
        lines = lines[:EVIDENCE_LINES]
        clipped = True
    out = "\n".join(lines)
    if len(out) > EVIDENCE_CHARS:
        out = out[:EVIDENCE_CHARS]
        clipped = True
    return out + ("\n[...]" if clipped else "")


def _findings(conn, run_id) -> List[Dict[str, Any]]:
    return [dict(r) for r in conn.execute(
        "SELECT host, finding_type, data, evidence, proof_basis, source, "
        "timestamp FROM findings WHERE run_id = ? ORDER BY host, id",
        (run_id,))]


def _approvals(conn, run_id) -> List[Dict[str, Any]]:
    return [dict(r) for r in conn.execute(
        "SELECT action, decision, decided_by, ev_json, requested_at "
        "FROM approvals WHERE run_id = ? ORDER BY id", (run_id,))]


def _ev_of(row) -> str:
    try:
        value = (json.loads(row.get("ev_json") or "{}") or {}).get("ev")
    except (TypeError, ValueError):
        return ""
    return "" if value is None else "%+.1f" % float(value)


def render(conn, run_id) -> str:
    """The campaign's report, as Markdown."""
    run = _campaign(conn, run_id)
    cfg = run.get("config") or {}
    findings = _findings(conn, run_id)
    approvals = _approvals(conn, run_id)
    summary = queries.get_run_summary(conn, run_id)

    out = []
    w = out.append
    w("# Campaign report — run %s" % run_id)
    w("")
    mode = _MODE_NAMES.get(str(cfg.get("mode") or run.get("mode") or ""),
                           str(run.get("mode") or "unknown"))
    w("- **Mode**: %s" % mode)
    if cfg.get("unattended_behavior"):
        w("- **Unattended behaviour**: %s" % cfg["unattended_behavior"])
    w("- **Status**: %s, phase %s" % (run.get("status") or "unknown",
                                      run.get("phase")))
    w("- **Started**: %s" % (run.get("started_at") or "—"))
    if run.get("completed_at"):
        w("- **Finished**: %s" % run["completed_at"])
    allow = cfg.get("scope_allow") or []
    deny = cfg.get("scope_deny") or []
    w("- **Authorised scope**: %s" % (", ".join(allow) or "—"))
    if deny:
        w("- **Excluded**: %s" % ", ".join(deny))
    if cfg.get("phases"):
        w("- **Phases**: %s" % ", ".join(str(p) for p in cfg["phases"]))
    if cfg.get("opsec_profile"):
        w("- **OpSec profile**: %s" % cfg["opsec_profile"])
    w("")

    w("## Summary")
    w("")
    w("- Findings: **%d**" % len(findings))
    w("- Tasks: %s of %s completed, %s failed"
      % (summary.get("completed_task_count", 0),
         summary.get("task_count", 0),
         summary.get("failed_task_count", 0)))
    w("- Gated actions: %d" % len(approvals))
    w("")

    w("## Findings")
    w("")
    if not findings:
        # Stated positively. "Nothing was found" and "nothing was looked
        # for" have to be distinguishable, and the task counts above are
        # what distinguishes them.
        w("No findings were recorded. With %s task(s) completed, that is a "
          "result rather than an absence of work: nothing in the "
          "authorised scope met the bar for a finding."
          % summary.get("completed_task_count", 0))
        w("")
    else:
        shown = findings[:MAX_FINDINGS]
        if len(findings) > len(shown):
            w("Showing %d of %d; the rest are in the campaign store."
              % (len(shown), len(findings)))
            w("")
        current = None
        for item in shown:
            host = item["host"]
            heading = ("Not tied to one host" if host == NO_HOST else host)
            if heading != current:
                w("### %s" % heading)
                w("")
                current = heading
            label = "**%s**" % (item["finding_type"] or "finding")
            if item.get("proof_basis"):
                label += " · %s" % item["proof_basis"]
            w("- %s — %s" % (label, item["data"]))
            if item.get("evidence"):
                w("")
                w("  ```")
                for line in _clip_evidence(item["evidence"]).splitlines():
                    w("  " + line)
                w("  ```")
            w("")

    w("## Decisions")
    w("")
    if not approvals:
        w("No gated actions were proposed: everything this campaign did was "
          "freely permitted under its profile.")
        w("")
    else:
        w("| Action | Decision | By | EV |")
        w("|---|---|---|---|")
        for row in approvals:
            w("| `%s` | %s | %s | %s |"
              % (row["action"], row.get("decision") or "undecided",
                 row.get("decided_by") or "—", _ev_of(row) or "—"))
        w("")
        w("An action that was refused was not carried out. Tier-1 actions "
          "are refused structurally and cannot appear as approved.")
        w("")

    return "\n".join(out)
