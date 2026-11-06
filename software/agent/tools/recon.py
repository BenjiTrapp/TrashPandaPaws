#!/usr/bin/env python3
"""Tools that act outward: run a command, record what it found, hand out work.

`run_command` is the only way the model touches a target, and it does nothing
but pass the command to the router. Scope, classification, the approval gate
and the scan limits all happen there, outside anything the model can call. A
check added here would be a second copy that could disagree with the first.
"""

import json

from software.agent.llm.provider import ToolSpec
from software.agent.store import queries
from software.agent.tools import BARE, CORE, Entry

# A finding with no host still needs one: the column is NOT NULL, and a
# plausible-looking name would be something the router could resolve. The
# parentheses are shell syntax, which no command can contain and still reach
# a target, so this value can never be named as one.
NO_HOST = "(none)"


def as_text(value):
    """A finding's data as stored: strings as given, structures as JSON."""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def clean(value):
    """The stripped text, or None if it is not non-blank text."""
    return value.strip() if isinstance(value, str) and value.strip() else None


def _run_command(ctx):
    async def run_command(command, beacon_id=None, server_side=False,
                          timeout=None, p_success_estimate=None):
        # p_success_estimate goes to the router as its override and is the
        # only route by which the model can move the EV calculation. The
        # router clamps it to ±0.2 of the prior; the clamp is its job.
        #
        # RouterAborted and GatePauseRequested are deliberately not caught
        # here: they end the campaign, and a tool that turned them into a
        # result would let the model read "budget spent" and carry on.
        result = await ctx.router.run_command(
            command, beacon_id=beacon_id, server_side=bool(server_side),
            timeout=timeout, p_success_override=p_success_estimate)
        out = {"success": result.success, "output": result.output,
               "exit_code": result.exit_code, "truncated": result.truncated,
               "path": result.path}
        if result.blocked_reason:
            out["blocked_reason"] = result.blocked_reason
        if result.effective_command:
            # The limiter rewrote it. Said plainly, because a model that is
            # not told believes it scanned every port and writes that down.
            out["effective_command"] = result.effective_command
        return out
    return run_command


def _log_discovery(ctx):
    async def log_discovery(finding_type, data, host=None, evidence=None,
                            proof_basis=None):
        basis = clean(proof_basis)
        if basis is not None and basis not in queries.PROOF_BASES:
            # Handed back rather than raised: the model can fix it on the
            # next turn, and a tool that crashes on a bad enum costs the
            # whole task.
            return {"error": "proof_basis must be one of %s"
                             % ", ".join(queries.PROOF_BASES)}
        queries.log_finding(ctx.conn, ctx.run_id, clean(host) or NO_HOST,
                            as_text(finding_type), as_text(data), "executor",
                            evidence=clean(evidence), proof_basis=basis)
        return {"logged": True}
    return log_discovery


def _dispatch_task(ctx):
    async def dispatch_task(task_name, task_description):
        name, description = clean(task_name), clean(task_description)
        if name is None or description is None:
            return {"error": "task_name and task_description must both be "
                             "non-empty text"}
        return await ctx.dispatch_single(name, description)
    return dispatch_task


def _dispatch_parallel_tasks(ctx):
    async def dispatch_parallel_tasks(tasks):
        if not isinstance(tasks, list) or not tasks:
            return {"error": "tasks must be a non-empty list of "
                             "{name, description} objects"}
        cleaned = []
        for index, task in enumerate(tasks):
            name = clean(task.get("name")) if isinstance(task, dict) else None
            description = (clean(task.get("description"))
                           if isinstance(task, dict) else None)
            if name is None or description is None:
                # All or nothing: dispatching the well-formed half would
                # leave the model believing the whole batch had gone.
                return {"error": "task %d needs a non-empty name and "
                                 "description; nothing was dispatched" % index}
            cleaned.append({"name": name, "description": description})
        return await ctx.dispatch_parallel(cleaned)
    return dispatch_parallel_tasks


def entries():
    return [
        Entry(
            ToolSpec(
                "run_command",
                "Run one command on a beacon, or on the C2 server with "
                "server_side. Give one plain command with no shell syntax "
                "(no ; & | ` $ ( ) < > or line breaks) and name every target "
                "explicitly. A refused command comes back with blocked_reason; "
                "read it and change the command rather than repeating it. A "
                "command that was narrowed comes back with "
                "effective_command, which is what actually ran: report that, "
                "not what you asked for.",
                {"type": "object",
                 "properties": {
                     "command": {"type": "string",
                                 "description": "the command line to run"},
                     "beacon_id": {"type": "string",
                                   "description": "the beacon to run it on; "
                                                  "omit when server_side"},
                     "server_side": {"type": "boolean",
                                     "description": "run on the C2 server "
                                                    "instead of a beacon"},
                     "timeout": {"type": "number",
                                 "description": "seconds to wait for the result"},
                     "p_success_estimate": {
                         "type": "number",
                         "description": "your own estimate, 0 to 1, that this "
                                        "action succeeds. Advisory only: it is "
                                        "limited to a narrow band around the "
                                        "built-in estimate."}},
                 "required": ["command"]}),
            ("executor",), BARE, _run_command),
        Entry(
            ToolSpec(
                "log_discovery",
                "Record something you found. For a hostname, log a finding "
                "whose data is a JSON object with its address, such as "
                "{\"ip\": \"10.0.1.5\"}: that is how a name becomes a target "
                "you may use.",
                {"type": "object",
                 "properties": {
                     "host": {"type": "string",
                              "description": "the address or name the finding "
                                             "is about"},
                     "finding_type": {"type": "string",
                                      "description": "the kind of finding: "
                                                     "host, service, os, vuln "
                                                     "or credential"},
                     "data": {"type": "string",
                              "description": "the finding itself"},
                     "evidence": {
                         "type": "string",
                         "description": "the output that proves it, quoted. "
                                        "The lines a reader needs to see, "
                                        "not the whole command output."},
                     "proof_basis": {
                         "type": "string",
                         "enum": list(queries.PROOF_BASES),
                         "description": "how this was established. "
                                        "executed-live: you ran it against "
                                        "the target and saw the result. "
                                        "executed-lab: you reproduced it "
                                        "elsewhere. inferred: you read it "
                                        "off a version, a banner or a "
                                        "configuration without triggering "
                                        "it."}},
                 "required": ["finding_type", "data"]}),
            ("executor",), BARE, _log_discovery),
        Entry(
            ToolSpec(
                "dispatch_task",
                "Hand one focused task to an executor and wait for its "
                "report. Name the targets in the description.",
                {"type": "object",
                 "properties": {
                     "task_name": {"type": "string",
                                   "description": "a short name for the task"},
                     "task_description": {"type": "string",
                                          "description": "what to do, against "
                                                         "which targets"}},
                 "required": ["task_name", "task_description"]}),
            ("orchestrator",), BARE, _dispatch_task),
        Entry(
            ToolSpec(
                "dispatch_parallel_tasks",
                "Hand several independent tasks to executors at once and wait "
                "for all of them.",
                {"type": "object",
                 "properties": {
                     "tasks": {"type": "array",
                               "items": {
                                   "type": "object",
                                   "properties": {
                                       "name": {"type": "string"},
                                       "description": {"type": "string"}},
                                   "required": ["name", "description"]},
                               "description": "the tasks to run together"}},
                 "required": ["tasks"]}),
            ("orchestrator",), CORE, _dispatch_parallel_tasks),
    ]
