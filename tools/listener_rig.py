#!/usr/bin/env python3
"""Run one full cycle of a real beacon over one listener, end to end.

The beacon is the specification for every listener in this package, and it
is executable -- so the honest test of a listener is not a reading of its
code but a beacon that registers through it, collects a task, runs it, and
reports the result. That is what `run_cycle` does, and it is why it exists
even though the suite also tests each listener's pieces: the pieces can all
be right while the arrangement is wrong.

Deliberately generic. A transport is a row in `listener_lab._TRANSPORTS`
-- a listener factory and the beacon configuration that points at it --
and nothing here is shaped around any one of them. That table lives in a
third module because `demo_env.py` needs it too and this file already
imports `demo_env`.

    python3 tools/listener_rig.py quic

`tools/demo_env.py` is the model for the server half and is reused rather
than re-implemented: it already stands up the two sockets, mints one key
for both ends, and waits on conditions instead of sleeping.
"""

import argparse
import json
import pathlib
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from software.c2.beacon import Beacon
from software.c2.server import agents, results
from tools import listener_lab as lab
from tools.demo_env import DemoEnv


def available_transports():
    return lab.available_transports()


def run_cycle(transport, *, token="rig-token", timeout=40.0):
    """Register, task and collect a result over `transport` alone.

    Returns what the cycle observed, so a caller asserts on facts rather
    than on the absence of an exception.
    """
    # The module-level fleet is shared across a process, so take a before
    # picture rather than assuming it starts empty. The suite runs other
    # tests that register beacons.
    known_before = set(agents)

    env = DemoEnv(0, token, listener_token=lab.LISTENER_TOKEN)
    env.start_server()
    listener = lab.make_listener(
        transport, 0, lab.relay_url_for(transport, env.beacon_port))
    listener.start()
    try:
        # Redirected for every transport, not only the one that reads it: it
        # costs nothing where it is unused, and a branch here would sit
        # between the rig and the thing it exists to prove.
        with lab.resolver_port(listener.address[1]):
            beacon = Beacon(lab.beacon_config_for(transport, env.key,
                                                  listener.address))

            # Listen in where the beacon has already decrypted. Everything the
            # listener touches is ciphertext, so "the task left the queue" only
            # proves the listener fetched it -- the beacon could still have
            # received a mangled answer. `_process_tasking_batch` is handed
            # plaintext, so a task id appearing here is proof the client
            # decrypted what came back over the wire.
            decrypted = []
            _original_batch = beacon._process_tasking_batch

            def _recording_batch(tasking):
                decrypted.append(tasking)
                return _original_batch(tasking)

            beacon._process_tasking_batch = _recording_batch
            beacon.start()
            seen = {"transport": transport,
                    "listener_address": listener.address,
                    "registered": False,
                    "agent_id": None,
                    "task_id": None,
                    "result_status": None,
                    "result_output": None}

            if lab.is_tasking_only(transport):
                # No registration goes over this transport, so the agent has to
                # exist first. That is the channel's documented limit, not a
                # shortcoming of the rig: a beacon reached only this way can be
                # commanded and can never report.
                name = lab.register_out_of_band(env.beacon_port, env.key,
                                                beacon._implant_id,
                                                beacon.interval)
                seen["registered"] = True
                seen["agent_id"] = name
                seen["registered_out_of_band"] = True
            else:
                _wait(lambda: set(agents) - known_before,
                      "the beacon to register through the %s listener" % transport,
                      timeout)
                name = (set(agents) - known_before).pop()
                seen["registered"] = True
                seen["agent_id"] = name

            task_id = _queue(env, name, "shell", "echo raccoon_rig")
            seen["task_id"] = task_id

            if lab.is_tasking_only(transport):
                _wait(lambda: _was_dispatched(task_id),
                      "the task to be collected over %s" % transport, timeout)
                seen["tasking_collected"] = True
                _wait(lambda: any(_mentions(d, task_id) for d in decrypted),
                      "the beacon to decrypt the task it received over %s"
                      % transport, timeout)
                seen["decrypted_by_beacon"] = task_id
                seen["result_status"] = "not-applicable"
                seen["result_output"] = "this transport carries no results"
                return seen

            _wait(lambda: results.get(task_id), "the result to come back", timeout)
            record = results[task_id]
            seen["result_status"] = record.get("status")
            seen["result_output"] = record.get("output")
            return seen
    finally:
        listener.shutdown()
        for srv in getattr(env, "servers", ()):
            srv.shutdown()


def _mentions(tasking, task_id):
    """True if this decrypted tasking contains that task.

    Covers both shapes the server sends: a bare task, and `{"tasks": [..]}`
    when the agent advertises batching.
    """
    if not isinstance(tasking, dict):
        return False
    if tasking.get("id") == task_id:
        return True
    return any(isinstance(task, dict) and task.get("id") == task_id
               for task in tasking.get("tasks") or [])


def _was_dispatched(task_id):
    """True once the task has left the queue and been marked dispatched."""
    from software.c2.server import task_queues
    for queue in task_queues.values():
        for task in queue:
            if task.get("id") == task_id:
                return False
    return True


def _queue(env, agent_name, cmd, args):
    body = json.dumps({"cmd": cmd, "args": args, "data": ""}).encode()
    request = urllib.request.Request(
        "http://127.0.0.1:%d/api/agents/%s/task"
        % (env.operator_port, agent_name),
        data=body, method="POST",
        headers={"Authorization": "Bearer %s" % env.token,
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())["id"]


def _wait(predicate, what, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise RuntimeError("timed out waiting for %s" % what)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("transport", choices=available_transports())
    args = parser.parse_args(argv)

    seen = run_cycle(args.transport)
    for field, value in seen.items():
        print("  %-24s %s" % (field, value))
    ok = seen["result_status"] in ("ok", "not-applicable")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
