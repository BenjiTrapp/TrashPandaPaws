#!/usr/bin/env python3
"""Orchestrator tools for judging the campaign: score, phase and summary.

Scoring runs on every campaign because it drives the gate: a detection the
model reports is a row the gate counts. The CTF-style display is the GUI's
business and plays no part here.
"""

from software.agent.llm.provider import ToolSpec
from software.agent.store import queries
from software.agent.tools import BARE, CORE, Entry

# ── The score table ──
#
# Spec §10.8, all sixteen actions. These are the values of the *scoring*
# table, which is the CTF ledger and also the source of the "unlocks" values
# in safety.RISK_TABLE. The five wifi actions are listed even on a run with
# no wifi: the reference implementation advertised them nowhere, so a model
# could only learn them from an error message.
SCORE_ACTIONS = {
    "host_discovered": 10,
    "port_found": 5,
    "service_identified": 15,
    "os_fingerprinted": 20,
    "vuln_detected": 25,
    "credential_captured": 50,
    "successful_login": 75,
    "privilege_escalation": 150,
    "rce_achieved": 200,
    "data_exfiltrated": 100,
    "detection": -100,
    "ap_discovered": 5,
    "handshake_captured": 30,
    "pmkid_captured": 30,
    "wps_pin_found": 50,
    "psk_cracked": 75,
}

RISK_LEVELS = ("low", "medium", "high")

# 1-5 are the engagement phases and 6-8 the wifi ones (spec §17.2). Which of
# them this run may use is the campaign configuration's decision, not this
# tool's: a phase the run has switched off is blocked where it matters, in
# safety.classify.
PHASE_RANGE = range(1, 9)


def _log_score(ctx):
    async def log_score(action, risk_level=None):
        if not isinstance(action, str) or action not in SCORE_ACTIONS:
            # The list travels with the error so the model can correct
            # itself instead of guessing again.
            return {"error": "unknown score action %r" % str(action)[:60],
                    "valid_actions": list(SCORE_ACTIONS)}
        if risk_level is None:
            risk_level = "high" if action == "detection" else "low"
        if risk_level not in RISK_LEVELS:
            return {"error": "unknown risk_level %r" % str(risk_level)[:30],
                    "valid_risk_levels": list(RISK_LEVELS)}
        points = SCORE_ACTIONS[action]
        # `detected` is what the gate reads. Reporting a detection through
        # this tool must tighten the leash exactly as a detection spotted in
        # command output does (spec §10.6, source 2).
        queries.log_score(ctx.conn, ctx.run_id, action, points, risk_level,
                          action == "detection")
        return {"logged": True, "action": action, "points": points}
    return log_score


def _get_score_context(ctx):
    async def get_score_context():
        return queries.get_score_context(ctx.conn, ctx.run_id)
    return get_score_context


def _get_run_summary(ctx):
    async def get_run_summary():
        return queries.get_run_summary(ctx.conn, ctx.run_id)
    return get_run_summary


def _set_phase(ctx):
    async def set_phase(phase, note=None):
        # bool is an int in Python, and True would otherwise be phase 1.
        if isinstance(phase, bool) or not isinstance(phase, int) \
                or phase not in PHASE_RANGE:
            return {"error": "phase must be an integer from %d to %d"
                             % (PHASE_RANGE[0], PHASE_RANGE[-1])}
        queries.set_run_phase(ctx.conn, ctx.run_id, phase)
        # The note has no column to live in; echoing it puts it in the tool
        # result, which the interaction log keeps.
        result = {"phase": phase}
        if isinstance(note, str) and note.strip():
            result["note"] = note.strip()[:200]
        return result
    return set_phase


def entries():
    return [
        Entry(
            ToolSpec(
                "log_score",
                "Record a scored outcome for this campaign. Report a detection "
                "here as soon as you see one: it tightens the approval gate. "
                "The point value comes from the score table, not from you.",
                {"type": "object",
                 "properties": {
                     "action": {"type": "string",
                                "enum": list(SCORE_ACTIONS),
                                "description": "the outcome achieved"},
                     "risk_level": {"type": "string",
                                    "enum": list(RISK_LEVELS),
                                    "description": "how risky the action was"}},
                 "required": ["action"]}),
            ("orchestrator",), CORE, _log_score),
        Entry(
            ToolSpec(
                "get_score_context",
                "Read the running score, the detection count and the last few "
                "scored events.",
                {"type": "object", "properties": {}}),
            ("orchestrator",), CORE, _get_score_context),
        Entry(
            ToolSpec(
                "get_run_summary",
                "Summarise the campaign so far: tasks, findings, score, "
                "detections and the current phase.",
                {"type": "object", "properties": {}}),
            ("orchestrator",), CORE, _get_run_summary),
        Entry(
            ToolSpec(
                "set_phase",
                "Report that the campaign has moved to another phase. This is "
                "what the operator's progress display shows.",
                {"type": "object",
                 "properties": {
                     "phase": {"type": "integer",
                               "description": "the phase number you are entering"},
                     "note": {"type": "string",
                              "description": "why you are moving on"}},
                 "required": ["phase"]}),
            ("orchestrator",), BARE, _set_phase),
    ]
