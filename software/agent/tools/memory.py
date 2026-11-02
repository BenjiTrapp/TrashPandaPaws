#!/usr/bin/env python3
"""Memory tools: notes that outlive a run, and findings that belong to one.

Two stores with different lifetimes. `save_memory` and `search_memory` are the
salience memory, meant to carry what one campaign learned into the next one
against the same client network. `remember_finding` and `recall_findings` are
the run's own record, which a resumed run reads back because the conversation
itself is not restored (spec §8.7).
"""

import ipaddress

from software.agent.llm.provider import ToolSpec
from software.agent.store import queries
from software.agent.tools import BARE, CORE, Entry
from software.agent.tools.recon import NO_HOST, as_text, clean

SECTORS = ("semantic", "episodic")
_DEFAULT_LIMIT = 5
_MAX_LIMIT = 20


# ── Scope key ──
#
# What memories are filed under. It comes from the campaign's authorised
# allow-list, for two reasons that pull in opposite directions. Keyed on the
# run, the memory would be useless: nothing a campaign learned would reach the
# next one against the same client. Keyed on nothing, it would leak one
# client's notes into another's. The allow-list is the one thing that
# identifies "this network" and is already fixed before the first command.
#
# Sorted and de-duplicated so the order the operator typed it in does not
# matter, and read through ipaddress so `10.0.1.5` and `10.0.1.5/32` are the
# same network. Left as readable text rather than hashed: it is a row in a
# table an operator may have to inspect. A campaign whose allow-list differs
# at all gets a different key, and so a fresh memory; that is the safe
# direction to be wrong in.

def scope_key(allow):
    parts = set()
    for entry in allow:
        text = str(entry).strip().lower()
        if not text:
            continue
        try:
            text = str(ipaddress.ip_network(text, strict=False))
        except ValueError:
            pass
        parts.add(text)
    if not parts:
        # An empty scope authorises nothing, and a key built from nothing
        # would be one every such campaign shared.
        raise ValueError("an empty scope has no memory scope")
    return "scope:" + ",".join(sorted(parts))


# ── Salience memory ──


def _save_memory(ctx):
    async def save_memory(content, sector=None, topic_key=None):
        text = clean(content)
        if text is None:
            return {"error": "content must be non-empty text"}
        sector = sector or "semantic"
        if sector not in SECTORS:
            return {"error": "unknown sector %r" % str(sector)[:30],
                    "valid_sectors": list(SECTORS)}
        queries.save_memory(ctx.conn, ctx.scope_key, clean(topic_key), text,
                            sector)
        return {"saved": True, "sector": sector}
    return save_memory


def _search_memory(ctx):
    async def search_memory(query, limit=None):
        text = clean(query)
        if text is None:
            return {"error": "query must be non-empty text"}
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            limit = _DEFAULT_LIMIT
        rows = queries.search_memory(ctx.conn, ctx.scope_key, text,
                                     min(limit, _MAX_LIMIT))
        return {"count": len(rows),
                "memories": [{"content": r["content"], "sector": r["sector"],
                              "topic_key": r["topic_key"],
                              "salience": round(r["salience"], 2)}
                             for r in rows]}
    return search_memory


# ── Findings of this run ──


def _remember_finding(ctx):
    async def remember_finding(host, finding_type, data):
        queries.log_finding(ctx.conn, ctx.run_id, clean(host) or NO_HOST,
                            as_text(finding_type), as_text(data),
                            "orchestrator")
        return {"logged": True}
    return remember_finding


def _recall_findings(ctx):
    async def recall_findings(host):
        rows = queries.get_findings_by_host(ctx.conn, clean(host) or "")
        # This run's own. The query is keyed on the host alone, and two
        # clients can both have a 10.0.1.5.
        rows = [r for r in rows if r["run_id"] == ctx.run_id]
        return {"host": host, "count": len(rows),
                "findings": [{"finding_type": r["finding_type"],
                              "data": r["data"], "source": r["source"],
                              "timestamp": r["timestamp"]} for r in rows]}
    return recall_findings


def entries():
    return [
        Entry(
            ToolSpec(
                "save_memory",
                "Keep a note for later campaigns against this same network. "
                "Save what would save time next time: how the network is laid "
                "out, what worked, what was noisy.",
                {"type": "object",
                 "properties": {
                     "content": {"type": "string",
                                 "description": "the note"},
                     "sector": {"type": "string", "enum": list(SECTORS),
                                "description": "semantic for lasting facts, "
                                               "episodic for what happened"},
                     "topic_key": {"type": "string",
                                   "description": "an optional label to group "
                                                  "related notes"}},
                 "required": ["content"]}),
            ("executor",), CORE, _save_memory),
        Entry(
            ToolSpec(
                "search_memory",
                "Search the notes kept from earlier campaigns against this "
                "network.",
                {"type": "object",
                 "properties": {
                     "query": {"type": "string",
                               "description": "words to look for"},
                     "limit": {"type": "integer",
                               "description": "how many notes at most"}},
                 "required": ["query"]}),
            ("executor",), CORE, _search_memory),
        Entry(
            ToolSpec(
                "remember_finding",
                "Record a finding in this campaign's own record. Executors "
                "record theirs; use this for what you conclude yourself.",
                {"type": "object",
                 "properties": {
                     "host": {"type": "string",
                              "description": "the address or name it is about"},
                     "finding_type": {"type": "string",
                                      "description": "the kind of finding"},
                     "data": {"type": "string",
                              "description": "the finding itself"}},
                 "required": ["host", "finding_type", "data"]}),
            ("orchestrator",), CORE, _remember_finding),
        Entry(
            ToolSpec(
                "recall_findings",
                "Read everything this campaign has recorded about one host.",
                {"type": "object",
                 "properties": {
                     "host": {"type": "string",
                              "description": "the address or name to look up"}},
                 "required": ["host"]}),
            ("orchestrator",), BARE, _recall_findings),
    ]
