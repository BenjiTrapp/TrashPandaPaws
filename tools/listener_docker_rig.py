#!/usr/bin/env python3
"""Run one full cycle with the listener in a container, not a thread.

`tools/listener_rig.py` proves a listener against a real beacon in this
process. This proves the shape the project ships: an unprivileged
container with every capability dropped, reaching the team server through
`host-gateway`, with the port published by dockerd rather than bound by
the listener.

    python3 tools/listener_docker_rig.py smb
    python3 tools/listener_docker_rig.py --all

**UDP published ports do not work on Docker Desktop for macOS.** Measured
here: a TCP echo in a container answers through `-p 127.0.0.1:x:y`, and an
identical UDP one never receives the datagram. So the QUIC and DNS
listeners cannot be exercised in a container on a Mac, and this rig says
so and skips them rather than timing out and looking like a listener
fault. On a Linux host, where publishing is iptables rather than a
userspace proxy, both work.

What it does not do is build the team server's image. That image carries
impacket, NetExec, Responder and a graphical RDP client and takes many
minutes to build, and none of it is what this rig is testing: the team
server runs on the host here, which is also the arrangement the compose
file describes, since the listener containers reach it over
`host.docker.internal` either way.

Needs a working `docker`. Exits 2 and says so if there is none, rather
than failing in a way that looks like a listener fault.
"""

import argparse
import json
import pathlib
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from software.c2.beacon import Beacon
from software.c2.server import agents, results
from tools import listener_lab as lab
from tools.demo_env import DemoEnv, _free_port

IMAGE = "raccoon-listener:rig"
DOCKERFILE = "software/c2/listeners/Dockerfile"

# What the container publishes, and what it binds inside. The published
# port is unprivileged here on purpose: 445 and 53 are routinely taken on
# a developer machine, and the property under test is that dockerd does
# the publishing, not which number it publishes.
_INSIDE = 8445


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("transport", nargs="?",
                        choices=lab.available_transports())
    parser.add_argument("--all", action="store_true",
                        help="every transport in turn")
    parser.add_argument("--keep-image", action="store_true",
                        help="do not remove the image afterwards")
    args = parser.parse_args(argv)

    if not shutil.which("docker"):
        print("docker is not on PATH; nothing was tested", file=sys.stderr)
        return 2
    probe = subprocess.run(["docker", "info"], capture_output=True)
    if probe.returncode != 0:
        print("docker is installed but not answering; nothing was tested",
              file=sys.stderr)
        return 2

    transports = (lab.available_transports() if args.all
                  else [args.transport or "smb"])
    udp_works = _udp_publishing_works()
    if not udp_works:
        print("\nUDP published ports do not deliver on this host, so the "
              "datagram transports cannot be exercised in a container "
              "here. Measured, not assumed: an identical TCP echo answers "
              "and the UDP one never receives. This is Docker Desktop on "
              "macOS; on a Linux host both work.", flush=True)

    print("building %s from %s" % (IMAGE, DOCKERFILE), flush=True)
    build = subprocess.run(
        ["docker", "build", "-q", "-f", DOCKERFILE, "-t", IMAGE, "."],
        capture_output=True, text=True)
    if build.returncode != 0:
        print(build.stderr[-2000:], file=sys.stderr)
        return 1
    print("  %s" % build.stdout.strip(), flush=True)

    failures = []
    skipped = []
    for transport in transports:
        print("\n── %s ──" % transport, flush=True)
        if transport != "smb" and not udp_works:
            print("  skipped: this transport is UDP and this host does not "
                  "deliver published UDP ports", flush=True)
            skipped.append(transport)
            continue
        try:
            seen = run_cycle(transport)
        except Exception as exc:
            print("  FAILED: %s" % exc, flush=True)
            failures.append(transport)
            continue
        for field, value in seen.items():
            print("  %-24s %s" % (field, value), flush=True)
        if seen["result_status"] not in ("ok", "not-applicable"):
            failures.append(transport)

    if not args.keep_image:
        subprocess.run(["docker", "image", "rm", "-f", IMAGE],
                       capture_output=True)

    attempted = len(transports) - len(skipped)
    print("\n%d of %d attempted transports completed a cycle"
          % (attempted - len(failures), attempted))
    if skipped:
        print("%d skipped for want of UDP publishing: %s"
              % (len(skipped), ", ".join(skipped)))
    return 1 if failures else 0


def _udp_publishing_works(timeout=40.0):
    """Does a published UDP port actually deliver on this host?

    Two containers, one TCP and one UDP, the same publishing flag. The
    answer is measured because assuming it cost most of an afternoon: the
    UDP listeners timed out in a way indistinguishable from a broken
    listener, and the listener was fine.
    """
    started = []
    try:
        udp = subprocess.run(
            ["docker", "run", "-d", "--rm", "-p", "127.0.0.1:0:9000/udp",
             "python:3.12-slim", "python3", "-c",
             "import socket\n"
             "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
             "s.bind(('0.0.0.0', 9000))\n"
             "s.recvfrom(100)\n"
             "print('delivered', flush=True)\n"],
            capture_output=True, text=True, timeout=timeout)
        if udp.returncode != 0:
            return False
        container = udp.stdout.strip()
        started.append(container)
        time.sleep(3)
        mapped = subprocess.run(["docker", "port", container, "9000/udp"],
                                capture_output=True, text=True)
        if not mapped.stdout.strip():
            return False
        port = int(mapped.stdout.strip().rsplit(":", 1)[1])
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.sendto(b"probe", ("127.0.0.1", port))
        finally:
            probe.close()
        time.sleep(2)
        logs = subprocess.run(["docker", "logs", container],
                              capture_output=True, text=True)
        return "delivered" in logs.stdout
    except (OSError, subprocess.SubprocessError, ValueError):
        return False
    finally:
        for container in started:
            subprocess.run(["docker", "rm", "-f", container],
                           capture_output=True)


def run_cycle(transport, *, timeout=90.0):
    """Register, task and collect over `transport`, through a container."""
    known_before = set(agents)
    published = _free_port()
    # The beacon socket has to be reachable from inside a container, so it
    # is opened on every interface for the length of this run. The operator
    # socket stays on loopback, as it does everywhere: that is the property
    # the two-socket split exists for, and a rig does not get to relax it.
    env = DemoEnv(0, "docker-rig-token", beacon_port=_free_port(),
                  listener_token=lab.LISTENER_TOKEN, beacon_host="0.0.0.0")
    env.start_server()

    container = _start_container(transport, published, env)
    try:
        with lab.resolver_port(published):
            beacon = Beacon(lab.beacon_config_for(
                transport, env.key, ("127.0.0.1", published)))
            decrypted = []
            original = beacon._process_tasking_batch

            def recording(tasking):
                decrypted.append(tasking)
                return original(tasking)

            beacon._process_tasking_batch = recording
            beacon.start()

            seen = {"transport": transport,
                    "container": container[:12],
                    "published": "127.0.0.1:%d" % published,
                    "inside": _INSIDE,
                    "registered": False,
                    "agent_id": None,
                    "task_id": None,
                    "result_status": None,
                    "result_output": None}

            if lab.is_tasking_only(transport):
                name = lab.register_out_of_band(env.beacon_port, env.key,
                                                beacon._implant_id,
                                                beacon.interval)
                seen["registered"] = True
                seen["registered_out_of_band"] = True
            else:
                _wait(lambda: set(agents) - known_before,
                      "the beacon to register through the container",
                      timeout, container)
                name = (set(agents) - known_before).pop()
                seen["registered"] = True
            seen["agent_id"] = name

            task_id = _queue(env, name, "shell", "echo raccoon_docker")
            seen["task_id"] = task_id

            if lab.is_tasking_only(transport):
                _wait(lambda: any(_mentions(d, task_id) for d in decrypted),
                      "the beacon to decrypt tasking from the container",
                      timeout, container)
                seen["decrypted_by_beacon"] = task_id
                seen["result_status"] = "not-applicable"
                seen["result_output"] = "this transport carries no results"
                return seen

            _wait(lambda: results.get(task_id),
                  "the result to come back through the container",
                  timeout, container)
            record = results[task_id]
            seen["result_status"] = record.get("status")
            seen["result_output"] = record.get("output")
            return seen
    finally:
        subprocess.run(["docker", "rm", "-f", container],
                       capture_output=True)
        for srv in getattr(env, "servers", ()):
            srv.shutdown()


def _start_container(transport, published, env):
    protocol = "" if transport == "smb" else "/udp"
    relay = lab.relay_url_for(transport, env.beacon_port).replace(
        "127.0.0.1", "host.docker.internal")
    command = ["docker", "run", "-d", "--rm",
               "--name", "raccoon-rig-%s" % transport,
               # Exactly what the compose file declares, so this rig tests
               # the shipped posture and not a relaxed one.
               "--user", "65534:65534",
               "--read-only",
               "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges:true",
               "--add-host", "host.docker.internal:host-gateway",
               "-p", "127.0.0.1:%d:%d%s" % (published, _INSIDE, protocol)]
    if transport == "dns":
        command += ["-e", "RACCOON_LISTENER_TOKEN=%s" % lab.LISTENER_TOKEN]
    command += [IMAGE,
                "--transport", transport,
                "--name", "%s-%d" % (transport, _INSIDE),
                "--bind-host", "0.0.0.0", "--bind-port", str(_INSIDE),
                "--relay-url", relay]
    if transport == "dns":
        command += ["--setting", "zone=%s" % lab.DNS_ZONE]

    done = subprocess.run(command, capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError("docker run failed: %s" % done.stderr.strip())
    return done.stdout.strip()


def _queue(env, agent_name, cmd, args):
    body = json.dumps({"cmd": cmd, "args": args, "data": ""}).encode()
    request = urllib.request.Request(
        "http://127.0.0.1:%d/api/agents/%s/task"
        % (env.operator_port, agent_name),
        data=body, method="POST",
        headers={"Authorization": "Bearer %s" % env.token,
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read())["id"]


def _mentions(tasking, task_id):
    if not isinstance(tasking, dict):
        return False
    if tasking.get("id") == task_id:
        return True
    return any(isinstance(task, dict) and task.get("id") == task_id
               for task in tasking.get("tasks") or [])


def _wait(predicate, what, timeout, container):
    """Poll, and on failure say what the container had to say about it."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.2)
    logs = subprocess.run(["docker", "logs", "--tail", "20", container],
                          capture_output=True, text=True)
    raise RuntimeError("timed out waiting for %s. The container said: %s"
                       % (what, " ".join((logs.stdout + logs.stderr).split())
                          [-600:]))


if __name__ == "__main__":
    sys.exit(main())
