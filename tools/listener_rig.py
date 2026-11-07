#!/usr/bin/env python3
"""Run one full cycle of a real beacon over one listener, end to end.

The beacon is the specification for every listener in this package, and it
is executable -- so the honest test of a listener is not a reading of its
code but a beacon that registers through it, collects a task, runs it, and
reports the result. That is what `run_cycle` does, and it is why it exists
even though the suite also tests each listener's pieces: the pieces can all
be right while the arrangement is wrong.

Deliberately generic. Two later listeners reuse this, so a transport is a
row in `_TRANSPORTS` -- a listener factory and the beacon configuration
that points at it -- and nothing here is shaped around any one of them.

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
from software.c2.listeners.quic import QuicListener
from software.c2.server import agents, results
from tools.demo_env import DemoEnv, key_b64


def _quic_listener(bind_port, relay_url):
    return QuicListener("127.0.0.1", bind_port, relay_url=relay_url)


def _quic_beacon_config(key, listener_address, interval=2):
    host, port = listener_address
    return {
        "beacon_interval_seconds": interval,
        "jitter_percent": 0,
        "encryption_key": key_b64(key),
        "proxy": {"mode": "none"},
        # Only this transport. The point of the cycle is that the beacon
        # needs no other channel -- if HTTPS were left on, a green result
        # would prove nothing about the listener.
        "https": {"enabled": False},
        "dns": {"enabled": False},
        "smb": {"enabled": False},
        "quic": {"enabled": True, "server": "%s:%d" % (host, port)},
    }


# transport -> (listener factory, beacon-config builder)
_TRANSPORTS = {
    "quic": (_quic_listener, _quic_beacon_config),
}


def available_transports():
    return sorted(_TRANSPORTS)


def run_cycle(transport, *, token="rig-token", timeout=40.0):
    """Register, task and collect a result over `transport` alone.

    Returns what the cycle observed, so a caller asserts on facts rather
    than on the absence of an exception.
    """
    if transport not in _TRANSPORTS:
        raise ValueError("no listener for %r; have %s"
                         % (transport, ", ".join(available_transports())))
    make_listener, make_config = _TRANSPORTS[transport]

    # The module-level fleet is shared across a process, so take a before
    # picture rather than assuming it starts empty. The suite runs other
    # tests that register beacons.
    known_before = set(agents)

    env = DemoEnv(0, token)
    env.start_server()
    relay_url = "http://127.0.0.1:%d/api/v1/beacon" % env.beacon_port

    listener = make_listener(0, relay_url)
    listener.start()
    try:
        beacon = Beacon({"c2": make_config(env.key, listener.address)})
        beacon.start()
        seen = {"transport": transport,
                "listener_address": listener.address,
                "registered": False,
                "agent_id": None,
                "task_id": None,
                "result_status": None,
                "result_output": None}

        _wait(lambda: set(agents) - known_before,
              "the beacon to register through the %s listener" % transport,
              timeout)
        name = (set(agents) - known_before).pop()
        seen["registered"] = True
        seen["agent_id"] = name

        task_id = _queue(env, name, "shell", "echo raccoon_rig")
        seen["task_id"] = task_id

        _wait(lambda: results.get(task_id), "the result to come back", timeout)
        record = results[task_id]
        seen["result_status"] = record.get("status")
        seen["result_output"] = record.get("output")
        return seen
    finally:
        listener.shutdown()
        for srv in getattr(env, "servers", ()):
            srv.shutdown()


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
    for field in ("transport", "listener_address", "registered", "agent_id",
                  "task_id", "result_status", "result_output"):
        print("  %-18s %s" % (field, seen[field]))
    return 0 if seen["result_status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
