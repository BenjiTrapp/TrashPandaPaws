#!/usr/bin/env python3
"""
Transparent Ethernet bridge tap.
Bridges two interfaces at L2 and captures traffic via BPF filters.
"""

import re
import subprocess
import logging
import shlex
import sys
from pathlib import Path

from scapy.all import sniff, Ether, IP, TCP, UDP
from software.sniffer.pcap_writer import PcapRotator

logger = logging.getLogger("raccoon.bridge")


def _parse_port_filter(bpf: str) -> set[tuple[str, int]]:
    """Parse a simple BPF port filter into a set of (proto, port) pairs.

    Handles filters like:
      'tcp port 21 or tcp port 23 or udp port 53'
      'tcp port 80 or tcp port 8080'
    Returns {('tcp', 21), ('tcp', 23), ('udp', 53)} etc.
    An empty filter means 'match all'.
    """
    if not bpf or not bpf.strip():
        return set()
    pairs = set()
    for m in re.finditer(r"(tcp|udp)\s+port\s+(\d+)", bpf, re.I):
        pairs.add((m.group(1).lower(), int(m.group(2))))
    return pairs


def _packet_matches(pkt, port_filter: set[tuple[str, int]]) -> bool:
    """Check if a packet matches a set of (proto, port) pairs."""
    if not port_filter:
        return True
    if not pkt.haslayer(IP):
        return False
    for proto, port in port_filter:
        if proto == "tcp" and pkt.haslayer(TCP):
            tcp = pkt[TCP]
            if tcp.sport == port or tcp.dport == port:
                return True
        elif proto == "udp" and pkt.haslayer(UDP):
            udp = pkt[UDP]
            if udp.sport == port or udp.dport == port:
                return True
    return False


class BridgeTap:
    def __init__(self, config: dict):
        self.upstream = config["network"]["upstream_iface"]
        self.downstream = config["network"]["downstream_iface"]
        self.bridge = config["network"]["bridge_name"]
        self.capture_dir = Path(config["sniffer"]["capture_dir"])
        self.profiles = config["sniffer"].get("capture_profiles", [])
        self.bpf_filter = config["sniffer"].get("bpf_filter", "")
        self.max_pcap_mb = config["sniffer"].get("max_pcap_size_mb", 50)
        self.max_total_mb = config["sniffer"].get("max_total_size_mb", 500)
        self.rotate_count = config["sniffer"].get("rotate_count", 10)
        self.encrypt_captures = config["sniffer"].get("encrypt_captures", False)
        self.gpg_recipient = config["sniffer"].get("gpg_recipient", "")
        self._running = False
        self._writers: list[tuple[str, set, PcapRotator]] = []

    def setup_bridge(self) -> bool:
        """Create the Linux bridge between upstream and downstream interfaces."""
        commands = [
            f"ip link set {self.upstream} promisc on",
            f"ip link set {self.downstream} promisc on",
            f"ip link add name {self.bridge} type bridge",
            f"ip link set {self.upstream} master {self.bridge}",
            f"ip link set {self.downstream} master {self.bridge}",
            f"ip link set {self.bridge} up",
            f"ip link set {self.upstream} up",
            f"ip link set {self.downstream} up",
            "sysctl -w net.bridge.bridge-nf-call-ip6tables=0",
            "sysctl -w net.ipv4.ip_forward=1",
        ]

        for cmd in commands:
            try:
                subprocess.run(
                    shlex.split(cmd),
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError as e:
                if "File exists" in (e.stderr or ""):
                    continue
                logger.error("Bridge setup failed: %s → %s", cmd, e.stderr)
                return False

        self._sync_bridge_nf()
        logger.info("Bridge %s active: %s <-> %s", self.bridge, self.upstream, self.downstream)
        return True

    def _sync_bridge_nf(self):
        """Set bridge-nf-call-iptables based on whether NAC bypass needs it.

        NAC bypass Phase 3 requires bridge-nf-call-iptables=1 for SNAT.
        When NAC bypass is not active, keep it at 0 for transparent bridging.
        This is called from setup_bridge and can be called by the watchdog.
        """
        nf_state_file = Path("/tmp/.raccoon_bridge_nf_state")
        if nf_state_file.exists() and nf_state_file.read_text().strip() == "1":
            logger.debug("bridge-nf-call-iptables=1 (NAC bypass active)")
        else:
            subprocess.run(
                shlex.split("sysctl -w net.bridge.bridge-nf-call-iptables=0"),
                capture_output=True, text=True,
            )

    def teardown_bridge(self):
        """Remove the bridge and restore interfaces."""
        commands = [
            f"ip link set {self.upstream} nomaster",
            f"ip link set {self.downstream} nomaster",
            f"ip link del {self.bridge}",
            f"ip link set {self.upstream} promisc off",
            f"ip link set {self.downstream} promisc off",
        ]
        for cmd in commands:
            try:
                subprocess.run(shlex.split(cmd), capture_output=True, text=True)
            except subprocess.CalledProcessError:
                pass
        logger.info("Bridge %s torn down", self.bridge)

    def _build_filter(self) -> str:
        """Build combined BPF filter from enabled profiles."""
        filters = []
        if self.bpf_filter:
            filters.append(f"({self.bpf_filter})")

        for profile in self.profiles:
            if profile.get("enabled") and profile.get("filter"):
                filters.append(f"({profile['filter']})")

        if not filters:
            return ""
        return " or ".join(filters)

    def _init_writers(self):
        """Initialize PCAP rotator per enabled capture profile."""
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self._writers = []

        for profile in self.profiles:
            if not profile.get("enabled"):
                continue
            name = profile["name"]
            port_filter = _parse_port_filter(profile.get("filter", ""))
            writer = PcapRotator(
                base_dir=self.capture_dir / name,
                prefix=name,
                max_file_mb=self.max_pcap_mb,
                max_total_mb=self.max_total_mb,
                rotate_count=self.rotate_count,
                encrypt=self.encrypt_captures,
                gpg_recipient=self.gpg_recipient,
            )
            self._writers.append((name, port_filter, writer))
            logger.info(
                "Capture profile '%s' active: %s",
                name,
                profile.get("filter", "all traffic"),
            )

    def _packet_handler(self, pkt):
        """Dispatch captured packet only to writers whose filter matches."""
        for name, port_filter, writer in self._writers:
            if _packet_matches(pkt, port_filter):
                writer.write_packet(pkt)

    def start_capture(self):
        """Start sniffing on the bridge interface."""
        self._running = True
        self._init_writers()

        combined_filter = self._build_filter()
        logger.info(
            "Starting capture on %s%s",
            self.bridge,
            f" filter='{combined_filter}'" if combined_filter else " (all traffic)",
        )

        try:
            sniff(
                iface=self.bridge,
                filter=combined_filter or None,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except PermissionError:
            logger.error("Capture requires root privileges")
            sys.exit(1)

    def stop(self):
        """Stop capture and close writers."""
        self._running = False
        for _, _, writer in self._writers:
            writer.close()
        logger.info("Capture stopped, all PCAP files closed")
