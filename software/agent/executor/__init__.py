#!/usr/bin/env python3
"""Execution of agent commands: the router and the two executors it picks from.

An executor runs a command that has already been admitted and reports what
happened. It never decides whether the command may run (that is the router,
with safety, scope and the gate behind it) and it never raises: a dead beacon,
an unreachable C2 and a bug in the call are all results the model can read and
act on, not an exception that ends its turn.

This module holds what the router and both executors share, so that neither
executor has to import the other or the router.
"""

import math
from typing import NamedTuple, Optional

from software.agent import c2client

# ── Result ──


class ActionResult(NamedTuple):
    success: bool
    output: str = ""
    # -1 means no exit status was reported, which is not the same as a
    # failing one: the C2 reports "ok" or "error" and passes a code on only
    # when the beacon sent one.
    exit_code: int = -1
    truncated: bool = False
    # "beacon", "server", or "" when nothing ran.
    path: str = ""
    # Set when the router refused the command. The model reads this and
    # corrects itself; it is never an exception.
    blocked_reason: Optional[str] = None


def blocked(reason: str) -> ActionResult:
    return ActionResult(False, "", -1, False, "", reason)


def failed(output: str, path: str) -> ActionResult:
    return ActionResult(False, output, -1, False, path)


def from_payload(payload, path: str) -> ActionResult:
    """Read a finished task or tool run as the C2 reports it."""
    if not isinstance(payload, dict):
        return failed("[c2 unavailable: answered with something unusable]", path)
    success = payload.get("success") is True
    output = payload.get("output")
    if output is None:
        output = ""
    elif not isinstance(output, str):
        output = str(output)
    code = payload.get("exit_code")
    if isinstance(code, bool) or not isinstance(code, int):
        code = 0 if success else -1
    return ActionResult(success, output, code,
                        payload.get("truncated") is True, path)


def from_exception(exc: Exception, path: str) -> ActionResult:
    """Every way a C2 call can fail, as a result."""
    if isinstance(exc, c2client.BeaconGone):
        return failed("[beacon offline]", path)
    if isinstance(exc, c2client.C2Unavailable):
        return failed("[c2 unavailable: %s]" % exc, path)
    if isinstance(exc, c2client.C2Unauthorized):
        return failed("[c2 rejected the operator token]", path)
    # Only the class: the message of an unexpected error may quote a URL or a
    # header, and the result goes into the model's context.
    return failed("[executor error: %s]" % type(exc).__name__, path)


# ── Timeouts ──


def positive_seconds(value, default: float) -> float:
    """`value` if it is a usable duration, else `default`.

    The model supplies the timeout. A bool is an int in Python, nan compares
    false with everything, and inf would hold an executor slot forever; the
    C2 rejects the rest. Falling back is kinder than refusing: the command
    was admitted, only its stopwatch was nonsense.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    if not math.isfinite(value) or value <= 0:
        return default
    return value
