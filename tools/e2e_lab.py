#!/usr/bin/env python3
"""Run the end-to-end lab: bring it up, run a scenario, assert, tear down.

    python3 tools/e2e_lab.py              # every scenario
    python3 tools/e2e_lab.py rescue       # one of them
    python3 tools/e2e_lab.py --keep       # leave it up to look at
    python3 tools/e2e_lab.py --shipped-image

`tools/listener_rig.py` proves a listener against a real beacon in this
process and `tools/listener_docker_rig.py` proves one in a container. This
proves the thing neither can: that a beacon whose transports fail *because
they do not route* reports why, through a real recursive resolver, on
Linux. The containers and networks are `software/tests/lab/`, judged
without Docker by `software/tests/test_e2e_lab.py`; what that cannot check
is whether Docker honours the topology, so this driver severs the network
and then asks the beacon container itself.

Evidence comes from the components, never from this driver's bookkeeping:

  * the resolver's own query log for what crossed the wire -- a name
    appears there only if a real resolver parsed and forwarded it;
  * the operator API for what the team server decoded;
  * the beacon container's exit code and output for what the implant did.

Needs a working `docker` and a compose command. Exits 2 and says so when
there is none, rather than failing in a way that looks like a product
fault -- `listener_docker_rig.py`'s convention, and the reason a CI job
can tell "no Docker here" from "the lab is broken".
"""

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from software.c2.dns_rescue import TRANSPORTS  # noqa: E402

COMPOSE_FILE = REPO / "software" / "tests" / "lab" / "docker-compose.yml"

# One fixed project name, so a crashed run's containers are findable and
# refusable rather than silently reused. It also scopes every compose call:
# a developer's machine carries other people's containers (fifteen of them
# while this was written) and nothing here may see, let alone remove, one.
PROJECT = "raccoon-lab"

# What the compose file defaults both listener tokens to. A scenario makes
# the DNS listener's differ from the server's to produce the stale-token
# case, so the value has to be known here.
DEFAULT_LISTENER_TOKEN = "lab-listener-token"
_STALE_TOKEN = "a-token-the-server-stopped-accepting"

# What each scenario sets up and what it claims. The claims differ on
# purpose: a scenario whose expectations were copied from its neighbour
# would pass for the wrong reason.
#
# `cycles` counts *stuck* cycles -- see beacon_entry.py, which cannot count
# from the start because the beacon is healthy until the driver severs it.
SCENARIOS = {
    # The named gap: every upstream leg unroutable, the resolver answering,
    # the listener relaying. One rescue, and a diagnosis the operator can
    # read.
    "rescue": {
        "cycles": 4,
        "rescues": 1,
        "env": {},
    },
    # The scenario the hand-kept VM died before reaching, and the only one
    # that proves the leg-recording fix on Linux. The listener holds a
    # token the server no longer accepts, so tasking over DNS returns
    # nothing while the rescue still arrives -- it goes through the beacon
    # handler, which needs no listener token. The ladder therefore runs all
    # the way down and SMB and QUIC are really attempted.
    "stale-token": {
        "cycles": 4,
        "rescues": 1,
        "legs_attempted": ("smb", "quic"),
        "env": {"LAB_DNS_LISTENER_TOKEN": _STALE_TOKEN},
    },
    # The first of the later transports, and the proof the shape extends.
    # It keeps the stale token on purpose: disabling DNS would make "no
    # rescue was sent" vacuous, because _maybe_rescue returns immediately
    # when DNS is off and the latch would never be armed. Here the resolver
    # answers, the latch IS armed and could fire, and it does not -- because
    # an upstream leg delivered.
    "smb-up": {
        "cycles": 4,
        "rescues": 0,
        "delivered_by": "smb",
        "profile": ("--profile", "smb"),
        "env": {"LAB_DNS_LISTENER_TOKEN": _STALE_TOKEN},
    },
}

_SEVER_NETWORK = "raccoon-lab_c2-net"
_BEACON = "beacon"
_RESOLVER = "resolver"
_TEAMSERVER = "teamserver"

# Where resolver.conf's `log-facility` points. Read with `docker exec cat`,
# which is what that file's own comment says to do.
_RESOLVER_LOG_PATH = "/var/log/dnsmasq/queries.log"

# How long to wait for a condition before giving up and naming it. Polled,
# never slept through: a fixed sleep is a guess that is either too short on
# a loaded machine or wasted on an idle one.
_WAIT_SECONDS = 90
_POLL_SECONDS = 1.0


class LabError(RuntimeError):
    """The lab could not be driven, or it contradicted itself."""


def _say(text):
    print(text, flush=True)


def _compose_command():
    """The compose invocation that exists here, or None.

    Measured: `docker compose` is not available on this project's
    development machine (`docker: unknown command: docker compose`) while
    the standalone `docker-compose` is, and newer `ubuntu-latest` images
    ship the plugin and have dropped the standalone. Hardcoding either
    breaks the other, so this asks.
    """
    probe = subprocess.run(["docker", "compose", "version"],
                           capture_output=True)
    if probe.returncode == 0:
        return ["docker", "compose"]
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    return None


def _compose(args, *, compose, env=None, check=True, capture=True):
    """Run one compose command, always scoped to this project.

    `env` is not optional in practice: the compose file reads
    `${RACCOON_KEY}` and `${RACCOON_TOKEN}`, which the driver generates per
    run, and a call without them brings the team server up with no key. It
    then exits 2 with its own correct complaint, which reads like a lab
    fault and is not one. Found by running it.
    """
    command = compose + ["-p", PROJECT, "-f", str(COMPOSE_FILE)] + args
    result = subprocess.run(command, capture_output=capture, text=True,
                            cwd=str(REPO), env=env)
    if check and result.returncode != 0:
        raise LabError("compose %s failed (%d)\n%s"
                       % (" ".join(args), result.returncode,
                          (result.stderr or result.stdout or "").strip()))
    return result


def _existing_containers(compose, env=None):
    """Containers already in this project, which must be none.

    A reused container reports a pass that means nothing: the beacon inside
    it has already run its cycles and the resolver's log already holds the
    rescue this run is supposed to produce. So a leftover is a refusal
    rather than something to clean up silently -- the operator may be
    looking at it, having asked for `--keep`.
    """
    done = _compose(["ps", "-a", "-q"], compose=compose, env=env,
                    check=False)
    return [line for line in (done.stdout or "").splitlines() if line.strip()]


def _container_id(compose, service, env=None):
    done = _compose(["ps", "-a", "-q", service], compose=compose, env=env)
    ids = [line for line in done.stdout.splitlines() if line.strip()]
    if not ids:
        raise LabError("no container for service %r" % (service,))
    return ids[0]


def _operator_url(compose, env=None):
    """Where the operator API landed, asked rather than assumed.

    The compose file publishes `127.0.0.1::8444` -- an ephemeral host port,
    so a developer's own 8444 is never in the way and two runs cannot
    collide. Which port that became is Docker's answer to give.
    """
    done = _compose(["port", _TEAMSERVER, "8444"], compose=compose, env=env)
    text = (done.stdout or "").strip().splitlines()
    if not text:
        raise LabError("the team server published no port for 8444")
    host, _, port = text[-1].rpartition(":")
    if not port.isdigit():
        raise LabError("could not read a port from %r" % (text[-1],))
    return "http://127.0.0.1:%s" % port


def _api(url, token, path):
    request = urllib.request.Request(
        url + path, headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(request, timeout=10) as answer:
        return json.loads(answer.read().decode())


def _wait_for(what, condition):
    """Poll until `condition` returns something truthy, or say what failed.

    Never a fixed sleep. The deadline is generous because an image's first
    start on a cold machine is slow, and the cost of being generous is
    nothing when the condition is met in a second.
    """
    deadline = time.time() + _WAIT_SECONDS
    last = None
    while time.time() < deadline:
        try:
            value = condition()
        except Exception as exc:                      # noqa: BLE001
            last = "%s: %s" % (type(exc).__name__, exc)
        else:
            if value:
                return value
            last = "condition not met yet"
        time.sleep(_POLL_SECONDS)
    raise LabError("waited %ds for %s and it never happened (%s)"
                   % (_WAIT_SECONDS, what, last))


def _in_beacon(compose, script, env=None):
    """Run a snippet of python inside the beacon container."""
    container = _container_id(compose, _BEACON)
    return subprocess.run(["docker", "exec", container, "python", "-c", script],
                          capture_output=True, text=True)


# Each probe prints `open` or `closed`. A connect, not a request: what is
# under test is whether the address routes at all.
_PROBE = (
    "import socket,sys\n"
    "try:\n"
    "    socket.create_connection((sys.argv[1], int(sys.argv[2])), 4).close()\n"
    "    print('open')\n"
    "except Exception:\n"
    "    print('closed')\n"
)


def _assert_severed(compose, env=None):
    """The negative space, asked of the beacon container itself.

    A lab whose isolation silently broke would report success for the wrong
    reason, so this is checked rather than assumed. If any of these answers
    `open`, the run aborts saying the lab is mis-wired -- which is a
    different failure from the feature being broken, and the operator needs
    to be told which.
    """
    container = _container_id(compose, _BEACON, env)
    for host, port, what in (("teamserver", 8443, "the team server's beacon socket"),
                             ("teamserver", 8445, "the QUIC address"),
                             ("teamserver", 8444, "the operator socket")):
        done = subprocess.run(
            ["docker", "exec", container, "python", "-c", _PROBE, host,
             str(port)], capture_output=True, text=True)
        answer = (done.stdout or "").strip()
        if answer == "open":
            raise LabError(
                "the lab is mis-wired: %s is still reachable from the beacon "
                "after the severance, so nothing this run reports about a "
                "stuck beacon means anything" % what)
        _say("  severed: %-38s %s" % (what, answer or "unreachable"))


# dnsmasq's query log, which is the wire evidence. `log-queries` writes one
# line per query it was asked; a name reaches it only if a real resolver
# parsed it.
_QUERY_LINE = re.compile(r"query\[(?P<type>\w+)\] (?P<name>\S+) from")
_FORWARD_LINE = re.compile(r"forwarded (?P<name>\S+) to ")

# beacon_entry.py prints one of these per cycle, prefixed `lab-beacon:`.
# `legs` lists only the legs that FAILED, which is what makes the absence
# of one evidence that it delivered.
_CYCLE_LINE = re.compile(r"cycle \d+ \w+ agent=\S+ legs=(?P<legs>\S*)")

# The order the beacon tries its transports in. A leg below the one that
# delivered is never reached, so finding one in the failures disproves the
# delivery. Taken from `dns_rescue.TRANSPORTS`, which is the same order and
# the one place it is written down.
_LADDER = TRANSPORTS


def _resolver_log(compose, env=None):
    """dnsmasq's query log, read from the file it writes.

    Not `compose logs`: `resolver.conf` sets `log-facility` to a path on
    purpose, and says why -- a stream on stderr would be mixed with
    dnsmasq's own startup lines. Reading stdout instead found nothing at
    all and looked like the beacon never querying, which it was not.
    """
    container = _container_id(compose, _RESOLVER, env)
    done = subprocess.run(
        ["docker", "exec", container, "cat", _RESOLVER_LOG_PATH],
        capture_output=True, text=True)
    if done.returncode != 0:
        raise LabError("could not read the resolver's query log at %s:\n%s"
                       % (_RESOLVER_LOG_PATH,
                          (done.stderr or "").strip()))
    return done.stdout or ""


def _queries(log):
    return [(match.group("type"), match.group("name"))
            for match in _QUERY_LINE.finditer(log)]


def _name_is_legal(name):
    """DNS limits, which the rescue's arithmetic has one character of room in.

    An off-by-one produces a third label: legal DNS, plausible to read, and
    visible only as an over-long name on a live network. So it is asserted
    here against what actually crossed the resolver.
    """
    bare = name.rstrip(".")
    labels = bare.split(".")
    return len(bare) < 253 and all(len(label) <= 63 for label in labels)


def _beacon_output(compose, env=None):
    done = _compose(["logs", "--no-color", _BEACON], compose=compose,
                    env=env)
    return (done.stdout or "") + (done.stderr or "")


def run_scenario(name, *, compose, env, keep):
    """Bring the lab up, sever the beacon, let it get stuck, then assert.

    The order matters and is not arbitrary. The beacon registers *first*,
    over a leg that works, because the implant assigns its agent id only in
    the HTTPS registration path -- a beacon that never registered
    fingerprints its implant id, the server matches that against no fleet
    key, and the rescue lands on the unattributed list instead of the
    agent's record. So the life-cycle this models is: work, then be cut
    off, which is also the only life-cycle that matters operationally.
    """
    spec = SCENARIOS[name]
    settings = dict(env)
    settings["LAB_SCENARIO"] = name
    settings["LAB_CYCLES"] = str(spec["cycles"])
    settings.update(spec.get("env", {}))

    profile = list(spec.get("profile", ()))
    _say("  bringing the lab up%s" % (" with the SMB listener" if profile
                                      else ""))
    _compose(profile + ["up", "-d"], compose=compose, env=settings,
             capture=True)

    url = _operator_url(compose, settings)
    token = settings["RACCOON_TOKEN"]
    _say("  operator API on %s" % url)

    agents = _wait_for(
        "the beacon to register over a leg that still works",
        lambda: _api(url, token, "/api/agents") or None)
    # `agent_id` and not `id`: the fleet key is the assigned name, while
    # `id` is the implant's own identifier. Taking `id` first produced a
    # 404 from /api/agents/<id> -- and it is the same distinction the
    # rescue's attribution turns on, since the server fingerprints the
    # fleet key.
    agent_id = agents[0].get("agent_id")
    if not agent_id:
        raise LabError("the operator API returned an agent with no agent_id: "
                       "%s" % (sorted(agents[0]),))
    _say("  registered as %s (%s, implant id %s)"
         % (agent_id, agents[0].get("hostname", "?"), agents[0].get("id", "?")))

    _say("  severing %s" % _SEVER_NETWORK)
    container = _container_id(compose, _BEACON, settings)
    subprocess.run(["docker", "network", "disconnect", _SEVER_NETWORK,
                    container], capture_output=True, text=True, check=True)
    _assert_severed(compose, settings)

    _say("  waiting for %d stuck cycles" % spec["cycles"])
    _wait_for("the beacon to finish its stuck cycles",
              lambda: "finished after" in _beacon_output(compose, settings))
    beacon_said = _beacon_output(compose, settings)

    log = _resolver_log(compose, settings)
    queries = _queries(log)
    marker = ".r."
    rescues = [name_ for _type, name_ in queries if marker in name_]
    tasking = [name_ for _type, name_ in queries if marker not in name_]

    _say("")
    _say("  WHAT THE REAL RESOLVER LOGGED:")
    for qtype, qname in queries:
        kind = "RESCUE " if marker in qname else "tasking"
        shown = qname if len(qname) <= 54 else qname[:51] + "..."
        _say("    [%s] %-5s %-54s %3d chars, longest label %d"
             % (kind, qtype, shown, len(qname.rstrip(".")),
                max(len(part) for part in qname.rstrip(".").split("."))))
    _say("    %d tasking queries, %d rescue" % (len(tasking), len(rescues)))

    problems = []
    wanted = spec["rescues"]
    if len(rescues) != wanted:
        if wanted == 0:
            problems.append(
                "%d rescue(s) crossed the resolver, and this scenario "
                "expects none: an upstream leg delivered while the latch "
                "was armed, so sending one means the latch fires on "
                "something other than being stuck"
                % len(rescues))
        elif not rescues:
            problems.append(
                "no rescue crossed the resolver across %d stuck cycles: the "
                "beacon never reported why it was stuck, which is the whole "
                "feature" % spec["cycles"])
        else:
            problems.append(
                "%d rescues crossed the resolver across %d stuck cycles, not "
                "%d -- the latch is the OpSec promise and a second query "
                "breaks it" % (len(rescues), spec["cycles"], wanted))
    for qname in rescues:
        if not _name_is_legal(qname):
            problems.append("the rescue name is not legal DNS: %d chars, "
                            "longest label %d"
                            % (len(qname.rstrip(".")),
                               max(len(p) for p in
                                   qname.rstrip(".").split("."))))

    record = _api(url, token, "/api/agents/" + agent_id)
    stuck = record.get("stuck")
    _say("")
    _say("  WHAT THE OPERATOR SEES:")
    if spec.get("delivered_by"):
        # NOT `last_channel`. A listener relays to the beacon handler over
        # HTTP, so an SMB delivery lands as `last_channel: http` and that
        # field cannot distinguish SMB from HTTPS at all -- the first
        # version of this check compared it to "smb", printed
        # "expected smb" when it saw "http", and passed anyway, which is a
        # central claim proved by nothing.
        #
        # The beacon's own per-cycle line does distinguish them. A leg is
        # recorded in `_leg_status` only when it FAILS, and the ladder is
        # ordered https, dns, smb, quic. So if SMB delivered, `smb` is
        # absent from every cycle's legs and `quic` was never reached; if
        # SMB had failed, both would be there -- which is exactly what the
        # stale-token scenario shows.
        delivered = spec["delivered_by"]
        legs_seen = set()
        for line in _CYCLE_LINE.finditer(beacon_said):
            for entry in line.group("legs").split(","):
                name = entry.split(":")[0].strip()
                if name and name != "-":
                    legs_seen.add(name)
        _say("    legs the beacon recorded as failed: %s"
             % (", ".join(sorted(legs_seen)) or "none"))
        if delivered in legs_seen:
            problems.append(
                "the beacon recorded %s as failed, so tasking did not "
                "arrive over it and this scenario proved nothing about "
                "that transport" % delivered)
        else:
            later = _LADDER[_LADDER.index(delivered) + 1:]
            reached = sorted(set(later) & legs_seen)
            if reached:
                problems.append(
                    "the beacon went on to try %s after %s, which it would "
                    "only do if %s had not delivered"
                    % (", ".join(reached), delivered, delivered))
            else:
                _say("    tasking arrived over %s: it is absent from the "
                     "failures and nothing below it was tried" % delivered)
    if not stuck:
        if spec["rescues"]:
            problems.append("the team server decoded no diagnosis: the agent "
                            "record carries no `stuck` summary")
        _say("    no `stuck` summary, which is what this scenario expects"
             if not spec["rescues"] else "    (nothing)")
    else:
        _say("    Stuck: %s" % stuck.get("summary", ""))
        _say("    dns_answered: %s" % stuck.get("dns_answered"))
        legs = {leg: stuck.get(leg) for leg in TRANSPORTS}
        _say("    legs: %s" % legs)
        if not spec["rescues"]:
            problems.append(
                "a diagnosis reached the operator in a scenario that "
                "expects none: %s" % stuck.get("summary"))
        if stuck.get("https") and stuck["https"][0] == "not_attempted":
            problems.append("HTTPS is reported as not attempted, but the "
                            "beacon tried it on every severed cycle")
        if not stuck.get("dns_answered"):
            problems.append("dns_answered is false, yet the rescue arrived "
                            "through the resolver -- the record contradicts "
                            "the wire")
        # The claim this lab exists to make falsifiable on Linux: an
        # unrecorded leg packs as `not_attempted`, so the operator is told
        # "not tried" about a leg that was tried and timed out.
        for leg in spec.get("legs_attempted", ()):
            reported = stuck.get(leg)
            if not reported or reported[0] == "not_attempted":
                problems.append(
                    "%s is reported as %r, but this scenario drove the "
                    "ladder all the way down and really attempted it -- on "
                    "Linux a dead endpoint raises nothing and merely times "
                    "out, which is exactly the case that used to go "
                    "unrecorded"
                    % (leg, reported[0] if reported else None))
    return problems


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    # No `choices=`: on python 3.9 argparse validates the *empty list* that
    # `nargs="*"` produces against choices and rejects it, so `--keep` with
    # no scenario named would die with "invalid choice: []". Measured.
    # Validated below instead, which also lets the error name the scenarios.
    parser.add_argument("scenarios", nargs="*", metavar="SCENARIO",
                        help="which to run (default: all of %s)"
                             % ", ".join(sorted(SCENARIOS)))
    parser.add_argument("--keep", action="store_true",
                        help="leave the lab up afterwards to look at; the "
                             "next run will refuse until it is down")
    parser.add_argument("--shipped-image", action="store_true",
                        help="build the team server from software/c2/"
                             "Dockerfile instead of the lab's thin one, to "
                             "test the packaging rather than the code")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    unknown = [name for name in args.scenarios if name not in SCENARIOS]
    if unknown:
        parser.error("no scenario named %s; have %s"
                     % (", ".join(repr(name) for name in unknown),
                        ", ".join(sorted(SCENARIOS))))

    if not shutil.which("docker"):
        print("e2e_lab: no `docker` on PATH; this rig needs one. Nothing "
              "about the product is implied by this.", file=sys.stderr)
        return 2
    if subprocess.run(["docker", "info"], capture_output=True).returncode:
        print("e2e_lab: `docker info` failed, so the daemon is not reachable. "
              "Nothing about the product is implied by this.", file=sys.stderr)
        return 2
    compose = _compose_command()
    if compose is None:
        print("e2e_lab: no compose command. Tried `docker compose` and "
              "`docker-compose`; this machine has neither.", file=sys.stderr)
        return 2

    if args.shipped_image:
        print("e2e_lab: --shipped-image is not implemented yet; the lab's "
              "thin team-server image is the only one wired up.",
              file=sys.stderr)
        return 2

    leftover = _existing_containers(compose, dict(os.environ))
    if leftover:
        print("e2e_lab: the %s project already has %d container(s). A reused "
              "container reports a pass that means nothing, so this run "
              "refuses rather than cleaning up after you -- you may be "
              "looking at it. Take it down with:\n  %s -p %s -f %s down -v"
              % (PROJECT, len(leftover), " ".join(compose), PROJECT,
                 COMPOSE_FILE), file=sys.stderr)
        return 1

    chosen = args.scenarios or sorted(SCENARIOS)
    env = {
        # Generated per run: the lab holds no secret and CI needs none.
        "RACCOON_KEY": base64.b64encode(os.urandom(32)).decode(),
        "RACCOON_TOKEN": base64.b64encode(os.urandom(18)).decode(),
    }

    _say("e2e_lab on %s, %s, compose: %s"
         % (os.uname().machine, os.uname().sysname, " ".join(compose)))
    _say("project %s, %d scenario(s): %s"
         % (PROJECT, len(chosen), ", ".join(chosen)))

    failures = {}
    for name in chosen:
        _say("")
        _say("=" * 68)
        _say("SCENARIO: %s" % name)
        settings = dict(os.environ)
        settings.update(env)
        try:
            problems = run_scenario(name, compose=compose, env=settings,
                                    keep=args.keep)
        except LabError as exc:
            problems = [str(exc)]
        except KeyboardInterrupt:
            problems = ["interrupted"]
        finally:
            if args.keep:
                _say("  --keep: leaving the lab up")
            else:
                _compose(["--profile", "smb", "down", "-v", "-t", "5"],
                         compose=compose, env=settings, check=False)
        _say("")
        if problems:
            failures[name] = problems
            _say("  VERDICT: FAILED")
            for problem in problems:
                _say("    - %s" % problem)
        else:
            _say("  VERDICT: passed")

    _say("")
    _say("%d of %d scenario(s) passed" % (len(chosen) - len(failures),
                                          len(chosen)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
