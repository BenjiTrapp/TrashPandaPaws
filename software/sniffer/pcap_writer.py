#!/usr/bin/env python3
"""
Rotating PCAP file writer with size-based rotation and automatic cleanup.
"""

import logging
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
    ):
        self.base_dir = Path(base_dir)
        self.prefix = prefix
        self.max_file_bytes = max_file_mb * 1024 * 1024
        self.max_total_bytes = max_total_mb * 1024 * 1024
        self.rotate_count = rotate_count
        self._writer: Optional[PcapWriter] = None
        self._current_file: Optional[Path] = None
        self._current_size = 0
        self._packet_count = 0

        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _new_filename(self) -> Path:
        ts = time.strftime("%Y%m%d_%H%M%S")
        return self.base_dir / f"{self.prefix}_{ts}.pcap"

    def _open_new(self):
        if self._writer:
            self._writer.close()

        self._current_file = self._new_filename()
        self._writer = PcapWriter(str(self._current_file), append=False, sync=True)
        self._current_size = 0
        logger.debug("Opened new PCAP: %s", self._current_file)
        self._enforce_limits()

    def _enforce_limits(self):
        """Delete oldest PCAP files when total size or count exceeds limits."""
        pcaps = sorted(self.base_dir.glob(f"{self.prefix}_*.pcap"))

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

    @property
    def stats(self) -> dict:
        pcaps = list(self.base_dir.glob(f"{self.prefix}_*.pcap"))
        return {
            "current_file": str(self._current_file) if self._current_file else None,
            "total_files": len(pcaps),
            "total_size_mb": sum(f.stat().st_size for f in pcaps) / (1024 * 1024),
            "total_packets": self._packet_count,
        }
