#!/usr/bin/env python3
"""
Transparent Ethernet bridge tap.
Bridges two interfaces at L2 and captures traffic via BPF filters.
"""

import subprocess
import logging
import signal
import sys
import shlex
from pathlib import Path
from typing import Optional

from scapy.all import sniff, wrpcap, Ether
from software.sniffer.pcap_writer import PcapRotator

logger = logging.getLogger("raccoon.bridge")


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
        self._running = False
        self._writers: dict[str, PcapRotator] = {}

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
            "sysctl -w net.bridge.bridge-nf-call-iptables=0",
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

        logger.info("Bridge %s active: %s <-> %s", self.bridge, self.upstream, self.downstream)
        return True

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

        for profile in self.profiles:
            if not profile.get("enabled"):
                continue
            name = profile["name"]
            self._writers[name] = PcapRotator(
                base_dir=self.capture_dir / name,
                prefix=name,
                max_file_mb=self.max_pcap_mb,
                max_total_mb=self.max_total_mb,
                rotate_count=self.rotate_count,
            )
            logger.info("Capture profile '%s' active: %s", name, profile.get("filter", "all"))

    def _packet_handler(self, pkt):
        """Dispatch captured packet to matching profile writers."""
        for name, writer in self._writers.items():
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
        for writer in self._writers.values():
            writer.close()
        logger.info("Capture stopped, all PCAP files closed")
