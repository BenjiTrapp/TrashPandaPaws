#!/usr/bin/env python3
"""Which tools a given role is offered, at a given capability and tier.

Two filters, in this order:

    1. capability   an entry declares `requires_caps`; every one of them has
                    to be advertised by a beacon the role works through
    2. tier         an entry declares the provider.TIER_LIMITS "tool_set"
                    levels it appears at: "bare", "core", "all"

The filter reads those declarations and knows no tool by name. `get_wire_intel`
and the wifi tools belong to later sub-projects and do not exist yet; when
they do, they declare `requires_caps=("sniffer",)` and the like in their own
module, are added to `_CATALOGUE`, and are admitted by this code unchanged.
Capability comes first so that a tool is never offered at a tier and then
found to have nothing to talk to.

Usage:
    tools = registry.executor_tools(router, conn, run_id, caps=caps,
                                    tier=tier, scope_key=memory.scope_key(allow))
    tools = registry.orchestrator_tools(conn, run_id, dispatch_single=one,
                                        dispatch_parallel=many, tier=tier,
                                        scope_key=memory.scope_key(allow))

`dispatch_single(name, description)` and `dispatch_parallel(tasks)`, the
latter a list of {"name", "description"}, are the orchestrator's own and
return whatever it wants the model to read back.
"""

from typing import List

from software.agent.llm.loop import Tool
from software.agent.llm.provider import TIER_LIMITS, ToolSpec
from software.agent.tools import (Context, Entry, egress, memory, recon,
                                  scoring, scripts, vuln)

# Order is the order the model sees them in.
_CATALOGUE = (recon.entries() + scripts.entries() + vuln.entries()
              + memory.entries() + scoring.entries()
              + egress.entries())  # type: List[Entry]


def _level(tier):
    try:
        return TIER_LIMITS[tier]["tool_set"]
    except KeyError:
        raise ValueError("unknown capability tier %r; valid values: %s"
                         % (tier, ", ".join(TIER_LIMITS))) from None


def _select(role, caps, tier, online=True) -> List[Entry]:
    level = _level(tier)
    have = set(caps or ())
    return [e for e in _CATALOGUE
            if role in e.roles
            and all(c in have for c in e.requires_caps)
            and level in e.levels
            and (online or not e.requires_online)]


def specs(role, caps, tier, online=True) -> List[ToolSpec]:
    """The declarations a role would be offered, without building anything.

    For the preambles, which describe the tools and have no connection or
    router to build them with.
    """
    return [e.spec for e in _select(role, caps, tier, online)]


def executor_tools(router, conn, run_id, *, caps, tier, scope_key,
                   online=True) -> List[Tool]:
    ctx = Context(conn=conn, run_id=run_id, scope_key=scope_key, router=router)
    return [Tool(e.spec, e.build(ctx))
            for e in _select("executor", caps, tier, online)]


def orchestrator_tools(conn, run_id, *, dispatch_single, dispatch_parallel,
                       tier, scope_key, c2=None) -> List[Tool]:
    # No caps argument: the orchestrator's tools plan and record, and none of
    # them touches a beacon's hardware.
    #
    # `c2` is optional because every caller before the egress tools passed
    # none, and a tool that needs the fleet is left out rather than offered
    # and refused -- the same rule `requires_caps` follows for hardware.
    ctx = Context(conn=conn, run_id=run_id, scope_key=scope_key,
                  dispatch_single=dispatch_single,
                  dispatch_parallel=dispatch_parallel, c2=c2)
    selected = _select("orchestrator", (), tier)
    if c2 is None:
        selected = [e for e in selected if not e.requires_c2]
    return [Tool(e.spec, e.build(ctx)) for e in selected]
