#!/usr/bin/env python3
"""Stored scripts: save, search, run.

The reference implementation let a stored script bypass its safety layer
entirely, which made the whole leash removable in three lines of bash. Here a
script is checked by `safety.validate_script` when it is saved and again when
it is run, and then every line of it goes through the router like any command
the model types. Checking only at save time would let a script stored before a
rule tightened still run.

A script is a list of plain commands, one per line. That is not a limit this
module chose: the metacharacter screen forbids pipes, variables, redirects
and substitution, so a bash script that passes it has no control flow left to
lose. It is also why a line-by-line run is faithful, and why only shell-like
languages can be stored: a python program cannot be run one line at a time,
and the router has no way to put a file on a host.
"""

import json
import re

from software.agent import safety
from software.agent.llm.provider import ToolSpec
from software.agent.store import queries
from software.agent.tools import ALL, Entry
from software.agent.tools.recon import clean

LANGUAGES = ("bash", "sh")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_DEFAULT_LIMIT = 5
_MAX_LIMIT = 20


def _lines(code):
    """(file line number, command) for each line that is not blank or comment."""
    found = []
    for number, raw in enumerate(code.replace("\r\n", "\n").replace("\r", "\n")
                                 .split("\n"), start=1):
        line = raw.strip()
        if line and not line.startswith("#"):
            found.append((number, line))
    return found


def _stored(ctx, name):
    """(row, None) for a runnable, clean script; (None, error dict) otherwise."""
    name = clean(name)
    row = queries.get_script_by_name(ctx.conn, name) if name else None
    if row is None:
        return None, {"success": False, "error": "no script with that name; "
                                                 "search_scripts lists them"}
    if row["language"] not in LANGUAGES:
        return None, {"success": False,
                      "error": "scripts in %r cannot be run; only %s can"
                               % (row["language"], ", ".join(LANGUAGES))}
    # Every run, not only the first: the rules may have tightened since the
    # script was saved.
    problem = safety.validate_script(row["code"], row["language"])
    if problem:
        return None, {"success": False,
                      "error": "script refused: %s" % problem}
    return row, None


def _save_script(ctx):
    async def save_script(name, code, language, description, tags=None):
        script_name = clean(name)
        if script_name is None or not _NAME.fullmatch(script_name):
            return {"error": "name must be 1 to 64 letters, digits, '_', '.' "
                             "or '-'"}
        if not isinstance(code, str) or not code.strip():
            return {"error": "code must be non-empty text"}
        if language not in LANGUAGES:
            return {"error": "language must be one of %s" % ", ".join(LANGUAGES)}
        problem = safety.validate_script(code, language)
        if problem:
            return {"error": "script refused: %s" % problem}
        tag_list = [t for t in tags if isinstance(t, str)] \
            if isinstance(tags, list) else []
        queries.save_script(ctx.conn, script_name, code, language,
                            clean(description) or "", json.dumps(tag_list))
        return {"saved": True, "name": script_name}
    return save_script


def _search_scripts(ctx):
    async def search_scripts(query, limit=None):
        text = clean(query)
        if text is None:
            return {"error": "query must be non-empty text"}
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            limit = _DEFAULT_LIMIT
        rows = queries.search_scripts(ctx.conn, text, min(limit, _MAX_LIMIT))
        return {"count": len(rows),
                "scripts": [{"name": r["name"], "description": r["description"],
                             "language": r["language"], "tags": r["tags"]}
                            for r in rows]}
    return search_scripts


def _run_script_executor(ctx):
    async def run_script(name, timeout=None, beacon_id=None):
        row, error = _stored(ctx, name)
        if error:
            return error
        results = []
        for number, command in _lines(row["code"]):
            # Each line is a command like any other: scope, classification,
            # the gate and the scan limits all apply again here. No
            # p_success_override, since a stored script has no basis for one.
            result = await ctx.router.run_command(
                command, beacon_id=beacon_id, server_side=beacon_id is None,
                timeout=timeout, p_success_override=None)
            entry = {"line": number, "command": command,
                     "success": result.success, "output": result.output}
            if result.blocked_reason:
                entry["blocked_reason"] = result.blocked_reason
            results.append(entry)
            if not result.success:
                # Later lines may depend on this one, and a refusal means
                # the script is no longer the script the model wrote.
                return {"success": False, "script": row["name"],
                        "failed_line": number, "results": results}
        return {"success": True, "script": row["name"], "results": results}
    return run_script


def _run_script_orchestrator(ctx):
    async def run_script(name, timeout=None):
        # The orchestrator has no way to run a command, by design, so it
        # hands the script to an executor. It is checked here first so that a
        # refused script costs no dispatch, and checked again by the
        # executor, which is the one that runs it.
        row, error = _stored(ctx, name)
        if error:
            return {"error": error["error"]}
        description = ("Run the stored script '%s' with the run_script tool "
                       "and report its output." % row["name"])
        if timeout is not None:
            description += " Allow %s seconds per line." % timeout
        return await ctx.dispatch_single("run_script:" + row["name"],
                                         description)
    return run_script


_NAME_PARAM = {"type": "string", "description": "the script's name"}


def entries():
    return [
        Entry(
            ToolSpec(
                "save_script",
                "Save a script for reuse. A script is a list of plain "
                "commands, one per line, with no shell syntax; every line is "
                "checked now and again each time it runs.",
                {"type": "object",
                 "properties": {
                     "name": {"type": "string",
                              "description": "a unique name for the script"},
                     "code": {"type": "string",
                              "description": "the commands, one per line"},
                     "language": {"type": "string", "enum": list(LANGUAGES),
                                  "description": "the script's language"},
                     "description": {"type": "string",
                                     "description": "what the script does"},
                     "tags": {"type": "array", "items": {"type": "string"},
                              "description": "words to find it by"}},
                 "required": ["name", "code", "language", "description"]}),
            ("executor", "orchestrator"), ALL, _save_script),
        Entry(
            ToolSpec(
                "search_scripts",
                "Search the saved scripts by name, description or tag.",
                {"type": "object",
                 "properties": {
                     "query": {"type": "string",
                               "description": "words to look for"},
                     "limit": {"type": "integer",
                               "description": "how many scripts at most"}},
                 "required": ["query"]}),
            ("executor", "orchestrator"), ALL, _search_scripts),
        Entry(
            ToolSpec(
                "run_script",
                "Run a saved script, one command at a time through the same "
                "checks as any other command. It stops at the first line that "
                "fails or is refused. Name a beacon_id, or omit it to run on "
                "the C2 server.",
                {"type": "object",
                 "properties": {
                     "name": _NAME_PARAM,
                     "timeout": {"type": "number",
                                 "description": "seconds to wait for each line"},
                     "beacon_id": {"type": "string",
                                   "description": "the beacon to run it on"}},
                 "required": ["name"]}),
            ("executor",), ALL, _run_script_executor),
        Entry(
            ToolSpec(
                "run_script",
                "Have an executor run a saved script. You do not run commands "
                "yourself: this checks the script and dispatches it.",
                {"type": "object",
                 "properties": {
                     "name": _NAME_PARAM,
                     "timeout": {"type": "number",
                                 "description": "seconds to allow per line"}},
                 "required": ["name"]}),
            ("orchestrator",), ALL, _run_script_orchestrator),
    ]
