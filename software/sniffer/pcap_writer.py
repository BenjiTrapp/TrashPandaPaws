#!/usr/bin/env python3
"""
Rotating PCAP file writer with size-based rotation, automatic cleanup,
and optional GPG encryption of rotated files.
"""

import logging
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from scapy.all import PcapWriter

logger = logging.getLogger("raccoon.pcap")


class PcapRotator:
    def __init__(
        self,
        base_dir: Path,
        prefix: str = "capture",
        max_file_mb: int = 50,
        max_total_mb: int = 500,
        rotate_count: int = 10,
        encrypt: bool = False,
        gpg_recipient: str = "",
    ):
        self.base_dir = Path(base_dir)
        self.prefix = prefix
        self.max_file_bytes = max_file_mb * 1024 * 1024
        self.max_total_bytes = max_total_mb * 1024 * 1024
        self.rotate_count = rotate_count
        self.encrypt = encrypt and bool(gpg_recipient)
        self.gpg_recipient = gpg_recipient
        self._writer: Optional[PcapWriter] = None
        self._current_file: Optional[Path] = None
        self._current_size = 0
        self._packet_count = 0

        self.base_dir.mkdir(parents=True, exist_ok=True)

        if self.encrypt and not shutil.which("gpg"):
            logger.warning("GPG not found — captures will NOT be encrypted")
            self.encrypt = False

    def _new_filename(self) -> Path:
        ts = time.strftime("%Y%m%d_%H%M%S")
        return self.base_dir / f"{self.prefix}_{ts}.pcap"

    def _encrypt_file(self, path: Path):
        """Encrypt a PCAP file with GPG and remove the plaintext original."""
        gpg_path = path.with_suffix(".pcap.gpg")
        try:
            result = subprocess.run(
                [
                    "gpg", "--batch", "--yes", "--trust-model", "always",
                    "--recipient", self.gpg_recipient,
                    "--output", str(gpg_path),
                    "--encrypt", str(path),
                ],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 0:
                path.unlink()
                logger.debug("Encrypted %s → %s", path.name, gpg_path.name)
            else:
                logger.warning("GPG encryption failed: %s", result.stderr.strip())
        except Exception as e:
            logger.warning("GPG encryption error: %s", e)

    def _open_new(self):
        old_file = self._current_file

        if self._writer:
            self._writer.close()

        if self.encrypt and old_file and old_file.exists():
            self._encrypt_file(old_file)

        self._current_file = self._new_filename()
        self._writer = PcapWriter(str(self._current_file), append=False, sync=True)
        self._current_size = 0
        logger.debug("Opened new PCAP: %s", self._current_file)
        self._enforce_limits()

    def _enforce_limits(self):
        """Delete oldest PCAP files when total size or count exceeds limits."""
        patterns = [f"{self.prefix}_*.pcap", f"{self.prefix}_*.pcap.gpg"]
        pcaps = sorted(
            f for pat in patterns for f in self.base_dir.glob(pat)
        )

        # Exclude the currently-open file from cleanup
        if self._current_file:
            pcaps = [f for f in pcaps if f != self._current_file]

        while len(pcaps) > self.rotate_count:
            oldest = pcaps.pop(0)
            oldest.unlink()
            logger.debug("Rotated out: %s", oldest)

        total = sum(f.stat().st_size for f in pcaps if f.exists())
        while total > self.max_total_bytes and pcaps:
            oldest = pcaps.pop(0)
            total -= oldest.stat().st_size
            oldest.unlink()
            logger.debug("Size limit cleanup: %s", oldest)

    def write_packet(self, pkt):
        """Write a packet, rotating the file if needed."""
        if self._writer is None or self._current_size >= self.max_file_bytes:
            self._open_new()

        raw = bytes(pkt)
        self._writer.write(pkt)
        self._current_size += len(raw) + 16  # PCAP record header
        self._packet_count += 1

    def close(self):
        if self._writer:
            self._writer.close()
            self._writer = None
            logger.info(
                "Closed %s — %d packets written",
                self._current_file,
                self._packet_count,
            )
            if self.encrypt and self._current_file and self._current_file.exists():
                self._encrypt_file(self._current_file)

    @property
    def stats(self) -> dict:
        patterns = [f"{self.prefix}_*.pcap", f"{self.prefix}_*.pcap.gpg"]
        pcaps = [f for pat in patterns for f in self.base_dir.glob(pat)]
        return {
            "current_file": str(self._current_file) if self._current_file else None,
            "total_files": len(pcaps),
            "total_size_mb": sum(f.stat().st_size for f in pcaps) / (1024 * 1024),
            "total_packets": self._packet_count,
            "encrypted": self.encrypt,
        }
