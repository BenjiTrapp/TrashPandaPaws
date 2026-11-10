#!/usr/bin/env python3
"""Run an admitted command on a beacon, through the C2's agent lane.

Usage:
    result = await beacon.run_on_beacon(c2, "raccoon-fox", "netscan 10.0.1.0/24",
                                        timeout=None)
"""

import math

from software.agent.executor import (ActionResult, failed, from_exception,
                                     from_payload, positive_seconds)

_PATH = "beacon"
_DEFAULT_TIMEOUT = 300
# The task timeout bounds the command on the beacon; the wait has to cover the
# beacon's check-in as well, once to pick the task up and again to post the
# result. A campaign checks in every 15 seconds, and the operator can slow a
# beacon well past that, so this is generous rather than exact. A dead beacon
# does not wait it out: is_alive ends the wait after three negative answers.
_GRACE_SECONDS = 60


def _liveness(c2, beacon_id):
    async def is_alive() -> bool:
        agent = await c2.get_agent(beacon_id)
        # An id the C2 does not know is not alive either.
        return agent is not None and agent.get("status") != "offline"
    return is_alive


# The verbs the beacon dispatches on, as its own first word. This is the
# agent's copy of another module's table (software/c2/beacon.py), kept here
# because the prompt has to state the language the executor is writing in:
# without it the model sends `arp -a` and gets "Unknown command: arp" back,
# with no hint that `shell arp -a` is the form that works. A test compares
# this set against that dispatch table, so a verb added there and not here
# fails rather than silently going unoffered.
BEACON_VERBS = (
    "shell", "ls", "lsjson", "cat", "pwd", "cd", "cp", "mv", "rm", "mkdir",
    "chmod", "write", "upload", "download", "loot", "exfil", "netscan",
    "arptable", "proxyinfo", "avenum", "smbloot", "persist", "unpersist",
    "tunnel", "sleep", "reconfig", "kill",
)

# Only where the name does not say it. Kept short on purpose: this goes into
# every executor prompt.
VERB_HINTS = {
    "shell": "run any other program: shell <command>",
    "lsjson": "like ls, machine-readable",
    "loot": "collect a directory as a zip",
    "exfil": "send data out over DNS",
    "netscan": "scan the local subnet",
    "arptable": "the ARP neighbour table",
    "proxyinfo": "the host's proxy configuration",
    "avenum": "enumerate AV, EDR and SIEM agents",
    "smbloot": "browse SMB shares without impacket",
    "tunnel": "start or stop the SOCKS tunnel child: tunnel start, tunnel stop",
    "sleep": "set the check-in interval and jitter",
}


async def run_on_beacon(c2, beacon_id, command, *, timeout) -> ActionResult:
    parts = command.split(None, 1) if isinstance(command, str) else []
    if not parts:
        return failed("[empty command]", _PATH)
    # The first word is the beacon's own verb (netscan, ls, shell) and the
    # rest its arguments, which is how the GUI queues them. Whether the verb
    # exists is the beacon's answer to give, not the router's.
    verb = parts[0]
    args = parts[1] if len(parts) > 1 else ""
    seconds = positive_seconds(timeout, _DEFAULT_TIMEOUT)
    try:
        task_id = await c2.queue_task(
            beacon_id, verb, args, timeout=int(math.ceil(seconds)),
            lane="agent")
        payload = await c2.await_task(
            task_id, timeout=seconds + _GRACE_SECONDS,
            is_alive=_liveness(c2, beacon_id))
    except Exception as exc:
        return from_exception(exc, _PATH)
    return from_payload(payload, _PATH)
