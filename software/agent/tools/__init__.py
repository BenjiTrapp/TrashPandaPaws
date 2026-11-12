#!/usr/bin/env python3
"""The tools the model is given, and the shapes they are declared in.

Two roles with different surfaces: an orchestrator that plans and dispatches,
and executors that carry out one task each. The asymmetry is deliberate and
comes from the spec: an executor has no dispatch tool (that would let it
recurse) and no scoring tool (only the orchestrator judges), and the
orchestrator has no way to run a command itself.

A tool is a surface and nothing more. It does not gate, classify or enforce
scope: `run_command` hands the command to the router, which does all three,
and the router sits outside the model's reach so that it cannot be skipped by
not calling a tool. The one check that lives here is `validate_script`,
because a stored script is code the model writes now and runs later.

Each module declares its tools as `Entry` records. The registry filters them;
it knows no tool by name, so a tool from a later sub-project is admitted by
declaring it, not by editing the filter.
"""

from typing import Any, Awaitable, Callable, NamedTuple, Optional, Tuple

from software.agent.llm.provider import ToolSpec


class Context(NamedTuple):
    """What a tool's builder is given. Fields a role does not have are None."""
    conn: Any
    run_id: int
    scope_key: str
    router: Optional[Any] = None
    dispatch_single: Optional[Callable[..., Awaitable[Any]]] = None
    dispatch_parallel: Optional[Callable[..., Awaitable[Any]]] = None
    # The fleet, for the tools that read it. None on a run built without
    # one, and those tools are then not offered rather than offered and
    # refused -- the same rule `requires_caps` follows.
    c2: Optional[Any] = None


class Entry(NamedTuple):
    spec: ToolSpec
    # "executor" and/or "orchestrator".
    roles: Tuple[str, ...]
    # The provider.TIER_LIMITS "tool_set" levels this tool appears at:
    # "bare", "core" and/or "all".
    levels: Tuple[str, ...]
    # (Context) -> async function taking the model's keyword arguments.
    build: Callable[[Context], Callable[..., Awaitable[Any]]]
    # Capabilities a beacon must advertise, every one of them. A tool whose
    # capability is missing is not offered, rather than refused when called.
    requires_caps: Tuple[str, ...] = ()
    # True for a tool that reaches a third party from the operator's host.
    # The quiet OpSec profile drops it from the catalogue rather than letting
    # it be called and refused: a tool the model never sees costs no turn,
    # and the preamble describes what is offered, so it stays consistent.
    requires_online: bool = False
    # True for a tool that reads or tasks the fleet, which needs a C2
    # client in the Context. Declared rather than inferred, so a tool is
    # never offered and then found to have nothing to talk to.
    requires_c2: bool = False


# Shared by the modules that declare entries.
BARE = ("bare", "core", "all")
CORE = ("core", "all")
ALL = ("all",)
