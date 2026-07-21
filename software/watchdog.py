#!/usr/bin/env python3
"""
Watchdog — monitors bridge health and implant components.
Restarts the bridge if it goes down and alerts via C2 on failures.
"""

import logging
import subprocess
import time
import sys
from pathlib import Path

import yaml

logger = logging.getLogger("raccoon.watchdog")

CHECK_INTERVAL = 30


def load_config() -> dict:
    for path in ["/opt/raccoon/configs/raccoon.yaml", "configs/raccoon.yaml"]:
        p = Path(path)
        if p.exists():
            with open(p) as f:
                return yaml.safe_load(f)
    return {}


def check_interface(name: str) -> bool:
    try:
        result = subprocess.run(
            ["ip", "link", "show", name],
            capture_output=True, text=True,
        )
        return "state UP" in result.stdout
    except Exception:
        return False


def check_bridge(name: str) -> bool:
    try:
        result = subprocess.run(
            ["brctl", "show", name],
            capture_output=True, text=True,
        )
        return name in result.stdout and result.returncode == 0
    except Exception:
        return False


def restart_bridge(upstream: str, downstream: str, bridge: str):
    logger.warning("Restarting bridge %s", bridge)
    cmds = [
        f"ip link del {bridge}",
        f"ip link add name {bridge} type bridge",
        f"ip link set {upstream} master {bridge}",
        f"ip link set {downstream} master {bridge}",
        f"ip link set {bridge} up",
        f"ip link set {upstream} up promisc on",
        f"ip link set {downstream} up promisc on",
    ]
    for cmd in cmds:
        subprocess.run(cmd.split(), capture_output=True)


def check_service(name: str) -> bool:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", name],
        )
        return result.returncode == 0
    except Exception:
        return False


def main():
    config = load_config()
    net = config.get("network", {})
    upstream = net.get("upstream_iface", "eth0")
    downstream = net.get("downstream_iface", "eth1")
    bridge = net.get("bridge_name", "br0")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [watchdog] %(levelname)s %(message)s",
    )

    from software.notifications import init_notifier, get_notifier
    init_notifier(config)

    logger.info("Watchdog started — monitoring %s (%s <-> %s)", bridge, upstream, downstream)

    failure_count = 0

    while True:
        issues = []

        if not check_interface(upstream):
            issues.append(f"{upstream} is DOWN")

        if not check_interface(downstream):
            issues.append(f"{downstream} is DOWN")

        if not check_bridge(bridge):
            issues.append(f"bridge {bridge} not active")
            restart_bridge(upstream, downstream, bridge)

        if not check_service("raccoon-implant"):
            issues.append("raccoon-implant service not active")

        if issues:
            failure_count += 1
            logger.warning("Health check FAIL (%d): %s", failure_count, "; ".join(issues))
            notifier = get_notifier()
            if notifier:
                notifier.notify(
                    "health_fail",
                    f"Health Check FAIL ({failure_count})",
                    issues="; ".join(issues),
                    bridge=bridge,
                )
        else:
            if failure_count > 0:
                logger.info("Health check OK (recovered after %d failures)", failure_count)
                notifier = get_notifier()
                if notifier:
                    notifier.notify(
                        "health_ok",
                        "Health Check Recovered",
                        previous_failures=str(failure_count),
                        bridge=bridge,
                    )
                failure_count = 0

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
