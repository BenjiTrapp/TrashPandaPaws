#!/usr/bin/env python3
"""Measure what a container can measure about the way out, and say what it
cannot.

There is no device. The design that this measures says so in full: nothing
in this repository has been ordered, built or measured on a bench, the
human has none, and a Docker container is what was meant by one. That
splits stage 1 into three parts, and this script reports all three rather
than quietly reporting only the first.

**Measurable, and fully.** The scout's parse cost per packet against a
replayed capture; the document handoff; the beacon's fresh-or-ignore rule;
the arithmetic, including where each rung crosses; and whether a small
model answers in a form the validator accepts.

**Measurable only as a proxy.** Latency. An arm64 container with `--cpus`
and `--memory` limits approximates the Pi 4's four cores and 4 GB, but not
a Cortex-A72's clock, and it has no PoE budget, no thermal envelope and no
bridge carrying a host's traffic at the same time. So every second here is
**optimistic by a factor nobody in this project can pin down**, and each
timing carries that sentence beside it.

**Not measurable at all.** Watts and thermals. A container cannot fix the
absence of a board, so they are named, with the reason, and carried in the
design's risk table instead of being assumed away.

Run it in the bench the design asks for:

    docker build -f tools/way_out_bench.Dockerfile -t raccoon-way-out-bench .
    docker run --rm --platform linux/arm64 --cpus 4 --memory 4g \\
        -v "$PWD:/repo" -w /repo raccoon-way-out-bench --json

and, for the model arm, with an Ollama beside it on loopback:

    docker run --rm --platform linux/arm64 --cpus 4 --memory 4g \\
        --network host -v "$PWD:/repo" -w /repo raccoon-way-out-bench \\
        --model qwen2.5:0.5b --json
"""

import argparse
import base64
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from software.c2 import beacon as beacon_mod                   # noqa: E402
from software.c2.beacon import Beacon, read_way_out_policy     # noqa: E402
from software.scout import handoff                             # noqa: E402
from software.scout.evidence import Evidence                   # noqa: E402

# The sentence every timing here carries. One string, so the report cannot
# say it two different ways.
OPTIMISTIC = (
    "an optimistic bound, not a result: this is an arm64 container with "
    "--cpus and --memory limits, which approximates the Pi 4's four cores "
    "and 4 GB but not a Cortex-A72's clock, and it is not bridging a host's "
    "traffic, drawing from a 13 W PoE budget or sharing a thermal envelope "
    "while it runs")

# What no container can answer, with the reason rather than a shrug. Carried
# in the design's risk table as well.
NOT_MEASURABLE = {
    "watts": "not measurable here: there is no device. The 802.3af budget at "
             "the board is about 13 W and has to cover bridging and "
             "capturing too, and a container draws from a wall socket. "
             "Stage 4 ships off because of this.",
    "thermals": "not measurable here: there is no device. A Pi 4 in an "
                "IP-phone-shaped enclosure under sustained load is a "
                "hardware question, and a container shares its host's "
                "cooling.",
}

_KEY = base64.b64encode(b"\x24" * 32).decode()


def _scratch():
    """A directory the way-out reader will accept, and why that is awkward.

    `read_way_out_policy` refuses a `state_dir` under `/tmp`, because both
    implant units set `PrivateTmp=true` and the handoff would silently
    never happen. The default temp directory **is** `/tmp` on Linux -- so
    the first run of this bench in a container measured a *disabled*
    feature and reported the ungated path's numbers: the borrow rung
    crossing at hour 0, the two loud rungs never crossing, and "a fresh
    document is read: False".

    That is the rule doing its job, and it is the measurement's first
    finding. The bench therefore scratches outside `/tmp` -- `/var/tmp`
    when it is writable, and `WAY_OUT_BENCH_DIR` when somebody wants to
    say where.
    """
    override = os.environ.get("WAY_OUT_BENCH_DIR")
    if override:
        os.makedirs(override, exist_ok=True)
        return tempfile.mkdtemp(prefix="way-out-bench-", dir=override)
    default = tempfile.gettempdir()
    if default == "/tmp" or default.startswith("/tmp/"):
        for candidate in ("/var/tmp", os.path.expanduser("~")):
            if os.path.isdir(candidate) and os.access(candidate, os.W_OK):
                return tempfile.mkdtemp(prefix="way-out-bench-",
                                        dir=candidate)
        raise RuntimeError(
            "every writable scratch directory here is under /tmp, which the "
            "way-out reader refuses: set WAY_OUT_BENCH_DIR to one that is "
            "not, or the bench would measure a disabled feature")
    return tempfile.mkdtemp(prefix="way-out-bench-")


# ── the packets the parse is measured against ──


def _replay(count):
    """`count` frames of exactly what the scout's filter would catch.

    Built rather than captured, because a committed pcap would be a file to
    keep in step with the filter -- and the five shapes below are the five
    rows of the design's evidence table.
    """
    from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw

    host, gateway = "10.0.0.50", "10.0.0.1"

    def tcp(src, dst, sport, dport, payload):
        return (Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
                / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport)
                / Raw(payload))

    shapes = [
        (Ether(src="aa:bb:cc:dd:ee:ff", dst="01:80:c2:00:00:03",
               type=0x888E) / Raw(b"\x01\x01\x00\x00")),
        (Ether() / IP(src=host, dst="10.0.0.2") / UDP(sport=5555, dport=53)
         / DNS(rd=1, qd=DNSQR(qname="example.com"))),
        (Ether() / IP(src="10.0.0.2", dst=host) / UDP(sport=53, dport=5555)
         / DNS(qr=1, qd=DNSQR(qname="example.com"),
               an=DNSRR(rrname="example.com", rdata="93.184.216.34"))),
        tcp(host, gateway, 44444, 3128,
            b"CONNECT a:443 HTTP/1.1\r\nHost: proxy.lan:3128\r\n"
            b"Proxy-Authorization: Basic Y29ycFxhbGljZTpzM2NyZXQ=\r\n\r\n"),
        tcp(gateway, host, 80, 44444,
            b"HTTP/1.1 302 Found\r\nLocation: http://portal.lan/login\r\n\r\n"),
        tcp(host, gateway, 44444, 80,
            b"POST /login HTTP/1.1\r\nHost: portal.lan\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
            b"user=guest&accept=1"),
        tcp(gateway, host, 80, 44444, b"HTTP/1.1 200 OK\r\n\r\n"),
    ]
    out = []
    while len(out) < count:
        out.extend(shapes)
    return out[:count]


def _beacon(state_dir, hours_dark=0.0, flags=()):
    beacon = Beacon({"c2": {
        "beacon_interval_seconds": 300, "jitter_percent": 0,
        "encryption_key": _KEY, "proxy": {"mode": "auto"},
        "https": {"enabled": False}, "dns": {"enabled": False},
        "smb": {"enabled": False}, "quic": {"enabled": False},
        "way_out": read_way_out_policy({"enabled": True,
                                        "state_dir": state_dir}),
    }})
    beacon._stuck_cycles = int(round(hours_dark * 12))
    for name in flags:
        beacon._rescue_flags |= beacon_mod._EGRESS_FLAG_BITS[name]
    return beacon


# ── the measurements ──


def measure_parse(packets=2000):
    """CPU time per packet through `Evidence.observe`.

    `process_time` and not a wall clock: what this is about is the cost the
    scout adds to a device that is already bridging, and a wall clock on a
    shared container measures the host's other tenants too.
    """
    replay = _replay(packets)
    evidence = Evidence()
    started = time.process_time()
    for packet in replay:
        evidence.observe(packet)
    spent = time.process_time() - started
    return {
        "packets": packets,
        "cpu_us_per_packet": round(spent / max(1, packets) * 1e6, 2),
        "cpu_seconds_total": round(spent, 4),
        "flags": evidence.flags(),
        "credentials": len(evidence.credentials),
        "caveat": OPTIMISTIC,
    }


def measure_handoff(rounds=500):
    """One write and one read of the document, per round."""
    root = _scratch()
    try:
        document = {
            "version": handoff.DOCUMENT_VERSION,
            "published": time.time(),
            "evidence": {"legs": {"https": "timed_out"}, "flags": []},
            "tap": {"flags": ["dot1x_seen"], "ssids": [],
                    "resolvers": {"10.0.0.2": 4}},
            "identity_pre_spent": False, "recommendation": None,
        }
        read_back = True
        started = time.time()
        for _ in range(rounds):
            handoff.write_document(root, document)
            read_back = read_back and handoff.read_document(root) is not None
        spent = time.time() - started
        return {
            "rounds": rounds,
            "us_per_round": round(spent / max(1, rounds) * 1e6, 2),
            "read_back": read_back,
            "caveat": OPTIMISTIC + ". It also includes an fsync, so it is "
                                   "a measure of this container's storage "
                                   "as much as of the code",
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


def measure_freshness():
    """The beacon's fresh-or-ignore rule, checked rather than timed.

    This is the property that makes a dead scout -- or a model too slow for
    the hardware -- harmless: the beacon degrades to its policy instead of
    acting on a stale decision. It is the half of stage 1 that a container
    answers completely, so it is a yes or no and not a number.
    """
    root = _scratch()
    try:
        beacon = _beacon(root)
        out = {}
        for name, published in (("a_fresh_document_is_read", time.time()),
                                ("a_stale_document_is_ignored",
                                 time.time() - 10000),
                                ("a_document_from_the_future_is_ignored",
                                 time.time() + 10000)):
            handoff.write_document(root, {
                "version": handoff.DOCUMENT_VERSION,
                "published": published,
                "evidence": beacon._egress_state(),
                "tap": {"flags": []}, "identity_pre_spent": False,
                "recommendation": None})
            read = beacon._way_out_document() is not None
            out[name] = read if name.endswith("is_read") else not read
        beacon._running = False
        return out
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _crosses(state_dir, verb, flags):
    """The first whole hour dark at which this rung is allowed, or None."""
    for hours in range(0, 200):
        probe = _beacon(state_dir, hours_dark=hours, flags=flags)
        allowed, _ = probe._way_out_allows(verb)
        probe._running = False
        if allowed:
            return hours
    return None


def measure_arithmetic(rounds=2000):
    """The gate's cost per decision, and where each rung crosses.

    The crossings are read out of the beacon's own numbers rather than
    typed here: a bench that repeated them would be a second place for the
    ladder to be wrong.
    """
    root = _scratch()
    try:
        beacon = _beacon(root, hours_dark=5)
        started = time.process_time()
        for _ in range(rounds):
            beacon._way_out_allows("identity")
        spent = time.process_time() - started

        crossings = {row: _crosses(root, verb, [])
                     for verb, row in (("proxy", "way_out_borrow"),
                                       ("radio", "way_out_radio"),
                                       ("identity", "way_out_identity"))}
        evidence_moves = {
            "way_out_identity with dot1x_seen":
                _crosses(root, "identity", ["dot1x_seen"]),
            "way_out_borrow with portal_answered":
                _crosses(root, "proxy", ["portal_answered"]),
        }
        beacon._running = False
        return {
            "rounds": rounds,
            "us_per_decision": round(spent / max(1, rounds) * 1e6, 3),
            # In hours dark. Read out of the beacon's own numbers, never
            # typed here: a bench that repeated them would be a second
            # place for the ladder to be wrong.
            "crossings": crossings,
            "evidence_moves_the_crossing_to": evidence_moves,
            "caveat": OPTIMISTIC,
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


def measure_model(name="", endpoint="http://127.0.0.1:11434", timeout=120):
    """Ask a real local model the real question, and report what came back.

    **A bad result is a measurement.** "It answered something the validator
    refused" and "it never answered" are findings about putting a model on
    this device, and they go in the report rather than being retried until
    they look better.
    """
    if not name:
        return {"asked": False,
                "note": "no model was named, so none was asked: pass "
                        "--model <name> with an Ollama on loopback"}
    from software.scout import model as model_mod

    state = {"version": handoff.STATE_VERSION, "stuck_cycles": 12,
             "hours_dark": 1.0,
             "evidence": {"legs": {"https": "timed_out",
                                   "dns": "answered",
                                   "smb": "not_attempted",
                                   "quic": "not_attempted",
                                   "gsocket": "carrier_failed"},
                          "flags": ["dns_answered", "portal_answered"]}}
    tap = {"flags": ["portal_answered"], "proxies": ["10.0.0.1:3128"],
           "resolvers": {"10.0.0.2": 7}, "credentials": 1,
           "tls_destinations": ["updates.example.com"],
           "pac": [], "wpad": [], "ssids": [],
           "portal": {"url": "http://portal.lan/login",
                      "content_type": "application/x-www-form-urlencoded"},
           "host_mac": "aa:bb:cc:dd:ee:ff", "host_ip": "10.0.0.50"}
    block = {"enabled": True, "endpoint": endpoint, "name": name,
             "timeout_seconds": timeout}

    started = time.time()
    note = ""
    answer = None
    try:
        answer = model_mod.ask(block, state, tap)
    except Exception as exc:
        note = "the call raised: %s" % exc
    spent = time.time() - started
    out = {
        "asked": True,
        "model": name,
        "endpoint": endpoint,
        "seconds": round(spent, 2),
        "validated": answer is not None,
        "caveat": OPTIMISTIC,
        "note": note or ("the validator accepted the answer"
                         if answer else
                         "the validator refused what came back; the scout's "
                         "log line says why, and the beacon decides on its "
                         "policy -- which is the degradation this design "
                         "relies on"),
    }
    if answer:
        out.update({"verb": answer["verb"], "argument": answer["argument"],
                    "p_success": answer["p_success"], "why": answer["why"]})
    return out


def report(packets=2000, rounds=500, model="",
           endpoint="http://127.0.0.1:11434", timeout=120):
    return {
        "bench": {
            "platform": " ".join(os.uname()[:1] + os.uname()[2:3]
                                 + os.uname()[4:5]),
            "cpus": os.cpu_count(),
            "python": sys.version.split()[0],
        },
        "parse": measure_parse(packets),
        "handoff": measure_handoff(rounds),
        "freshness": measure_freshness(),
        "arithmetic": measure_arithmetic(rounds),
        "model": measure_model(model, endpoint, timeout),
        "not_measurable": NOT_MEASURABLE,
    }


def _print(got):
    print("way out bench — %s, %s CPU(s), Python %s"
          % (got["bench"]["platform"], got["bench"]["cpus"],
             got["bench"]["python"]))
    print()
    print("measurable, and fully")
    print("  parse       %.2f us CPU per packet over %d frames; flags read: %s"
          % (got["parse"]["cpu_us_per_packet"], got["parse"]["packets"],
             ", ".join(got["parse"]["flags"]) or "none"))
    print("  handoff     %.2f us per write-and-read round (%d rounds)"
          % (got["handoff"]["us_per_round"], got["handoff"]["rounds"]))
    print("  arithmetic  %.3f us per decision; rungs cross at %s hours dark"
          % (got["arithmetic"]["us_per_decision"],
             ", ".join("%s=%s" % (row, hours) for row, hours
                       in sorted(got["arithmetic"]["crossings"].items()))))
    print("              the evidence moves them to %s"
          % got["arithmetic"]["evidence_moves_the_crossing_to"])
    print("  freshness   " + ", ".join(
        "%s: %s" % (name.replace("_", " "), held)
        for name, held in sorted(got["freshness"].items())))
    print()
    print("the model")
    if not got["model"]["asked"]:
        print("  not run — %s" % got["model"]["note"])
    else:
        print("  %s at %s: %s in %.2f s"
              % (got["model"]["model"], got["model"]["endpoint"],
                 "the validator ACCEPTED the answer"
                 if got["model"]["validated"]
                 else "the validator REFUSED what came back",
                 got["model"]["seconds"]))
        if got["model"]["validated"]:
            print("  it answered: verb=%s argument=%r p_success=%s why=%r"
                  % (got["model"]["verb"], got["model"]["argument"],
                     got["model"]["p_success"], got["model"]["why"]))
        print("  %s" % got["model"]["note"])
    print()
    print("every second above is %s" % OPTIMISTIC)
    print()
    print("not measurable here")
    for name, reason in sorted(NOT_MEASURABLE.items()):
        print("  %-9s %s" % (name, reason))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--packets", type=int, default=2000)
    parser.add_argument("--rounds", type=int, default=500)
    parser.add_argument("--model", default="",
                        help="a model an Ollama on loopback has pulled")
    parser.add_argument("--endpoint", default="http://127.0.0.1:11434")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    got = report(packets=args.packets, rounds=args.rounds, model=args.model,
                 endpoint=args.endpoint, timeout=args.timeout)
    if args.json:
        print(json.dumps(got, indent=2, sort_keys=True))
    else:
        _print(got)
    return 0


if __name__ == "__main__":
    sys.exit(main())
