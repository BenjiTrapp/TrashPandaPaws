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

from unittest.mock import patch

from software.c2 import beacon as beacon_mod
from software.c2.beacon import Beacon
from software.c2.listeners.dns import DnsListener
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


_DNS_ZONE = "c2.rig"
_LISTENER_TOKEN = "rig-listener-token"


def _dns_listener(bind_port, relay_url):
    return DnsListener("127.0.0.1", bind_port, relay_url=relay_url,
                       zone=_DNS_ZONE, listener_token=_LISTENER_TOKEN)


def _dns_beacon_config(key, listener_address, interval=2):
    host, port = listener_address
    return {
        "beacon_interval_seconds": interval,
        "jitter_percent": 0,
        "encryption_key": key_b64(key),
        "proxy": {"mode": "none"},
        "https": {"enabled": False},
        "smb": {"enabled": False},
        "quic": {"enabled": False},
        # The resolver is the listener itself here. In production the
        # beacon asks a real resolver, which reaches an authoritative
        # nameserver; the rig collapses that to one hop because the hop
        # under test is the listener, not the DNS hierarchy.
        "dns": {"enabled": True, "domain": _DNS_ZONE, "resolver": host},
    }


# transport -> (listener factory, beacon-config builder)
_TRANSPORTS = {
    "quic": (_quic_listener, _quic_beacon_config),
    "dns": (_dns_listener, _dns_beacon_config),
}

# Transports with no upstream path. The beacon can receive tasking over
# these and will never report, so a cycle stops at "the task arrived".
_TASKING_ONLY = frozenset({"dns"})


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

    env = DemoEnv(0, token, listener_token=_LISTENER_TOKEN)
    env.start_server()
    # The tasking route takes the socket root and appends its own path;
    # the beacon endpoint is a full URL. Each transport's factory knows
    # which shape it needs.
    if transport in _TASKING_ONLY:
        relay_url = "http://127.0.0.1:%d" % env.beacon_port
    else:
        relay_url = "http://127.0.0.1:%d/api/v1/beacon" % env.beacon_port

    listener = make_listener(0, relay_url)
    listener.start()
    # The client's resolver port is 53 and binding that needs root, so the
    # rig points it at the listener instead. In production dockerd or
    # systemd owns 53 and forwards to an unprivileged listener, so nothing
    # binds it there either -- the named constant exists for exactly this.
    port_patch = patch.object(beacon_mod, "_DNS_PORT", listener.address[1])
    port_patch.start()
    try:
        beacon = Beacon({"c2": make_config(env.key, listener.address)})

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

        if transport in _TASKING_ONLY:
            # No registration goes over this transport, so the agent has to
            # exist first. That is the channel's documented limit, not a
            # shortcoming of the rig: a beacon reached only this way can be
            # commanded and can never report.
            name = _register_out_of_band(env, beacon._implant_id)
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

        if transport in _TASKING_ONLY:
            _wait(lambda: _was_dispatched(env, task_id),
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
        port_patch.stop()
        listener.shutdown()
        for srv in getattr(env, "servers", ()):
            srv.shutdown()


def _register_out_of_band(env, implant_id):
    """Register an agent the way a bidirectional transport would.

    The DNS channel has no registration, so a beacon that only speaks it
    needs an identity that already exists. This is what HTTPS, SMB or QUIC
    would have done on first contact.

    It has to be *this* beacon's implant id, not an invented one. The
    client puts `self._agent_id or self._implant_id` into the query name
    and never learns an agent name over DNS, so the identity registered
    here is the only thing the server can match against. Registering some
    other id stands up a cycle that cannot possibly complete -- which is
    how this was first written, and it cost an hour.
    """
    from software.c2.server import agents as fleet

    before = set(fleet)
    body = json.dumps(_wrap_for(env, {
        "action": "register", "id": implant_id, "agent_id": None,
        "hostname": "rig", "os": "Linux 6.1", "user": "nobody",
        "pid": 1, "uptime": 1, "interval": 2,
    })).encode()
    request = urllib.request.Request(
        "http://127.0.0.1:%d/api/v1/beacon" % env.beacon_port,
        data=body, method="POST",
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10):
        pass
    new = set(fleet) - before
    if not new:
        raise RuntimeError("the out-of-band registration was not accepted")
    return new.pop()


def _wrap_for(env, payload):
    from software.c2.server import ServerCrypto
    return ServerCrypto(env.key).wrap(payload)


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


def _was_dispatched(env, task_id):
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
