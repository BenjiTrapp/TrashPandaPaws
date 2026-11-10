#!/usr/bin/env python3
"""
Standalone tunnel endpoint — the reverse SOCKS endpoint with no beacon
above it, started by systemd from `services/raccoon-tunnel.service`.

**This is the client side.** It dials out to a tunnel server and carries
the operator's relays back. `python -m software.c2.tunnel` is the other
side: the process that opens the socket endpoints dial in to and holds
every build's PSK. The two names look alike and mean opposite things, so
this paragraph is here for the same reason `listeners/registry.py` carries
its own — a drop-box that started the wrong one would open a listening
socket and hold the credentials.

The sibling of `beacon_standalone.py`, and deliberately a second unit
rather than a second mode of that one. A generated build re-executes
itself into tunnel mode because it is one delivered artifact; a host
configured from `configs/raccoon.yaml` has two things it may run, and two
units is how an operator starts, stops and reads the journal of one
without the other.

Its config is `c2.tunnel` of `configs/raccoon.yaml`, read through
`tunnel_config_from_yaml`, which is where that block is validated. The
PSK is not in that file: it comes from `RACCOON_TUNNEL_PSK`, which the
unit supplies through an `EnvironmentFile`.

Nothing here is quiet about a configuration it cannot run. A block it
cannot make is a refusal with the field named, on stderr -- the journal
-- and an exit code of 1. `beacon_config_from_fallback` makes the
opposite choice for the same error and leaves the tunnel out, because
there the beacon is the access and must still start; here the endpoint
*is* the process, so there is nothing left to run. The endpoint's own
visible symptom for a half-filled block would otherwise be a connection
retried for ever, which is the hardest failure in this project to tell
from a dozen others.
"""

import logging
import signal
import sys

from software.c2.beacon import (TunnelEndpoint, beacon_config_from_fallback,
                                tunnel_config_from_yaml,
                                tunnel_mode_problem)
from software.c2.beacon_standalone import load_config


def _refuse(reason: str) -> int:
    print("Refusing to start the tunnel endpoint: " + reason,
          file=sys.stderr)
    return 1


def main() -> int:
    logging.basicConfig(
        level=logging.INFO, stream=sys.stderr,
        format="%(asctime)s [tunnel] %(levelname)s %(message)s")

    config = load_config()
    c2_cfg = (config or {}).get("c2") or {}
    if not c2_cfg.get("enabled"):
        return _refuse("c2.enabled is not set in configs/raccoon.yaml")

    # The strict read, and this process's refusal: the endpoint *is* this
    # process, so a block it cannot make leaves nothing to run. The
    # answer is discarded because the shared mapping below produces the
    # same one; what is wanted here is the exception.
    # `beacon_config_from_fallback` makes the opposite choice for this
    # same error, because there the beacon has to start regardless.
    try:
        tunnel_config_from_yaml(c2_cfg)
    except ValueError as exc:
        return _refuse(str(exc))

    # The rest of the beacon config, for `c2.proxy`: one host has one way
    # out, and the endpoint reads the same block the beacon's transports
    # do. Built by the one function that maps this file onto that shape,
    # which puts `c2.tunnel` there itself.
    beacon_cfg = beacon_config_from_fallback(c2_cfg)

    # The same predicate the generated artifact's bootstrap uses, so a
    # host with no tunnel configured and a build with none refuse in the
    # same words.
    problem = tunnel_mode_problem(beacon_cfg)
    if problem:
        return _refuse(problem)

    endpoint = TunnelEndpoint(beacon_cfg)

    def shutdown(_signal, _frame):
        endpoint.stop()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        endpoint.run()
    except RuntimeError as exc:
        # The slow-crypto refusal, which is a decision for the operator
        # and not a crash: see c2.tunnel.allow_slow_crypto.
        return _refuse(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
