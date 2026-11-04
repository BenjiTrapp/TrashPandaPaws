#!/usr/bin/env python3
"""Run an admitted command as a tool on the C2 host, with no shell.

Usage:
    result = await server_tool.run_on_server(
        c2, ["nmap", "-sV", "10.0.1.5"], tool="nmap", timeout=None)
"""

import math
import os
import shlex

from software.agent.executor import (ActionResult, failed, from_exception,
                                     from_payload, positive_seconds)

_PATH = "server"

# Per tool, because a flat limit fits none of them: the rate limit forced on
# nmap makes a service scan slow, a capture is meant to be short, and a
# cracking run is meant to be long.
_TOOL_TIMEOUTS = {"nmap": 900, "tcpdump": 30, "aircrack-ng": 1800}
_DEFAULT_TIMEOUT = 60
# The C2 ends a run itself at its timeout and keeps the partial output, marked
# "[timeout after Ns, partial output]". A wait that gave up at exactly N would
# often give up first and report nothing.
_GRACE_SECONDS = 15

_PRIVILEGE = frozenset(("sudo", "doas", "pkexec"))
_PRIVILEGE_VALUE_FLAGS = frozenset(("-u", "-U", "-g", "--user", "--group"))


def tool_name(argv) -> str:
    """The program a command runs, by basename, past any privilege prefix.

    Keyed on the basename because `sudo nmap` and `/usr/bin/nmap` are nmap,
    and a lookup on argv[0] would give them the default limit.
    """
    index = 0
    while index < len(argv):
        name = os.path.basename(argv[index])
        if name not in _PRIVILEGE:
            return name
        index += 1
        while index < len(argv) and argv[index].startswith("-"):
            index += 2 if argv[index] in _PRIVILEGE_VALUE_FLAGS else 1
    return ""


async def run_on_server(c2, argv, *, tool, timeout) -> ActionResult:
    if isinstance(argv, str):
        try:
            argv = shlex.split(argv)
        except ValueError:
            return failed("[command could not be split into arguments]", _PATH)
    if not argv:
        return failed("[empty command]", _PATH)
    name = tool_name(argv)
    seconds = positive_seconds(timeout, _TOOL_TIMEOUTS.get(name, _DEFAULT_TIMEOUT))
    try:
        run_id = await c2.exec_server_tool(
            list(argv), tool=tool or name, timeout=int(math.ceil(seconds)))
        payload = await c2.await_server_tool(
            run_id, timeout=seconds + _GRACE_SECONDS)
    except Exception as exc:
        return from_exception(exc, _PATH)
    return from_payload(payload, _PATH)
