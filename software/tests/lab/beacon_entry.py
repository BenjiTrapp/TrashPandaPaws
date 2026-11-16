#!/usr/bin/env python3
"""The beacon, as the lab runs it: one scenario, a bounded number of stuck cycles.

    python software/tests/lab/beacon_entry.py --scenario rescue \\
        --zone c2.lab --cycles 4

Runs the real `software.c2.beacon.Beacon` with a config that enables all
four transports, and nothing is simulated: it registers over HTTPS while
the container is still attached to `c2-net`, and every leg that later
fails does so because the driver detached it and the address stopped
routing. This script only decides where each leg points and when to stop.

`--cycles` counts *stuck* cycles: cycles in which the HTTPS leg failed. It
cannot count cycles from the start, because the beacon is healthy until
the driver severs it and a count that included those would run out before
anything was wrong. After that many, the script stops the beacon and exits
0. A beacon that is never severed runs until the container is killed; the
driver owns the timeout, and says which condition was unmet.

The key and the ports come from the environment, never the command line,
which every user on a host can read:

    RACCOON_KEY        base64 AES-256-GCM key (what the team server holds)
    LAB_BEACON_PORT    the team server's beacon socket
    LAB_SMB_PORT       the SMB listener's port
    LAB_QUIC_PORT      the QUIC target's port

Every line this script prints is prefixed `lab-beacon:` so the driver can
find them among the implant's own log lines.
"""

import argparse
import os
import socket
import sys
import traceback
from pathlib import Path

# Run by path inside the container, with the repository bind-mounted: the
# package is reached from the checkout and not from an install.
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from software.c2 import beacon as beacon_mod  # noqa: E402

# Where the SMB leg points, per scenario. Every value is a service name in
# docker-compose.yml, and test_e2e_lab fails if one stops being.
#
# The two severed scenarios point SMB at the team server's c2-net address:
# it routes while the beacon is attached and does not afterwards, which is
# the property under test. smb-up points it at a listener on beacon-net,
# which is still reachable after the severance, so the ladder has an
# upstream leg that works while the DNS listener's token does not.
SCENARIOS = {
    "rescue": "teamserver",
    "stale-token": "teamserver",
    "smb-up": "listener-smb",
}

_TEAMSERVER = "teamserver"
_RESOLVER = "resolver"


def build_config(scenario, *, zone, key, resolver, beacon_port, smb_port,
                 quic_port):
    """The beacon configuration for `scenario`."""
    if scenario not in SCENARIOS:
        raise ValueError("no scenario %r; have %s"
                         % (scenario, ", ".join(sorted(SCENARIOS))))
    return {"c2": {
        # The floor: the beacon raises anything lower to it.
        "beacon_interval_seconds": beacon_mod._MIN_INTERVAL,
        "jitter_percent": 0,
        "encryption_key": key,
        "proxy": {"mode": "none"},
        "https": {"enabled": True, "verify_ssl": False,
                  "callback_url": "http://%s:%d/api/v1/beacon"
                                  % (_TEAMSERVER, beacon_port)},
        "dns": {"enabled": True, "domain": zone, "resolver": resolver},
        "smb": {"enabled": True, "pipe_name": "msrpc_6e2f",
                "server": "%s:%d" % (SCENARIOS[scenario], smb_port)},
        "quic": {"enabled": True,
                 "server": "%s:%d" % (_TEAMSERVER, quic_port)},
    }}


def _say(text):
    print("lab-beacon: %s" % text, flush=True)


class _Done(BaseException):
    """Raised at the start of a cycle to end the loop cleanly."""


def _bound(beacon, cycles):
    """Make the beacon's loop end after `cycles` stuck cycles.

    `_start_cycle` runs once at the top of each cycle, before it clears
    anything, so what it finds in `_leg_status` is the previous cycle's
    outcome. It is the one hook that sees every cycle however it ended --
    the failure arm `continue`s past both sleeps -- and the beacon's
    behaviour is unchanged: the extra work is a count and a line.
    """
    state = {"cycle": 0, "stuck": 0}
    original = beacon._start_cycle

    def counting():
        if state["cycle"]:
            legs = dict(beacon._leg_status)
            stuck = "https" in legs
            state["stuck"] += stuck
            _say("cycle %d %s agent=%s legs=%s" % (
                state["cycle"], "stuck" if stuck else "healthy",
                beacon._agent_id or "-",
                ",".join("%s:%d/%d" % (name, legs[name][0], legs[name][1])
                         for name in sorted(legs)) or "-"))
            if state["stuck"] >= cycles:
                raise _Done()
        state["cycle"] += 1
        original()

    beacon._start_cycle = counting
    return state


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scenario", required=True, choices=sorted(SCENARIOS))
    parser.add_argument("--zone", required=True)
    parser.add_argument("--cycles", required=True, type=int,
                        help="stuck cycles to run before exiting")
    args = parser.parse_args(argv)
    if args.cycles < 1:
        parser.error("--cycles must be at least 1")

    key = os.environ.get("RACCOON_KEY", "").strip()
    if not key:
        print("lab-beacon: RACCOON_KEY is not set; the beacon has no key "
              "to encrypt with", file=sys.stderr)
        return 2
    ports = {}
    for name, var in (("beacon_port", "LAB_BEACON_PORT"),
                      ("smb_port", "LAB_SMB_PORT"),
                      ("quic_port", "LAB_QUIC_PORT")):
        try:
            ports[name] = int(os.environ[var])
        except (KeyError, ValueError):
            print("lab-beacon: %s is missing or not a port number" % var,
                  file=sys.stderr)
            return 2

    # The resolver is an address the beacon is configured with, as it would
    # be on a real host; only this script asks Docker's DNS for it.
    resolver = socket.gethostbyname(_RESOLVER)
    config = build_config(args.scenario, zone=args.zone, key=key,
                          resolver=resolver, **ports)
    _say("scenario=%s zone=%s resolver=%s smb=%s cycles=%d" % (
        args.scenario, args.zone, resolver, config["c2"]["smb"]["server"],
        args.cycles))

    beacon = beacon_mod.Beacon(config)
    state = _bound(beacon, args.cycles)
    failure = []
    loop = beacon._beacon_loop

    def guarded():
        try:
            loop()
        except _Done:
            pass
        except BaseException:
            failure.append(traceback.format_exc())

    beacon._beacon_loop = guarded
    beacon.start()
    beacon._thread.join()
    beacon.stop()
    if failure:
        print(failure[0], file=sys.stderr)
        return 1
    _say("finished after %d stuck cycles in %d" % (state["stuck"],
                                                    state["cycle"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
