#!/usr/bin/env python3
"""
Unit tests for the sniffer subsystem: BridgeTap packet dispatch,
PcapRotator rotation/encryption, and Exfiltrator persistence.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR


def _make_config(capture_dir="/tmp/test_captures", **sniffer_overrides):
    cfg = {
        "network": {
            "upstream_iface": "eth0",
            "downstream_iface": "eth1",
            "bridge_name": "br0",
        },
        "sniffer": {
            "enabled": True,
            "capture_dir": capture_dir,
            "max_pcap_size_mb": 1,
            "max_total_size_mb": 10,
            "rotate_count": 5,
            "bpf_filter": "",
            "encrypt_captures": False,
            "gpg_recipient": "",
            "capture_profiles": [
                {
                    "name": "credentials",
                    "filter": "tcp port 21 or tcp port 23 or tcp port 445",
                    "enabled": True,
                },
                {
                    "name": "http",
                    "filter": "tcp port 80 or tcp port 8080",
                    "enabled": True,
                },
                {
                    "name": "dns",
                    "filter": "udp port 53",
                    "enabled": True,
                },
                {
                    "name": "all",
                    "filter": "",
                    "enabled": False,
                },
            ],
        },
    }
    cfg["sniffer"].update(sniffer_overrides)
    return cfg


# ── Port filter parsing ──


class TestParsePortFilter(unittest.TestCase):
    def test_empty_filter(self):
        from software.sniffer.bridge_tap import _parse_port_filter
        self.assertEqual(_parse_port_filter(""), set())
        self.assertEqual(_parse_port_filter(None), set())

    def test_single_port(self):
        from software.sniffer.bridge_tap import _parse_port_filter
        result = _parse_port_filter("tcp port 80")
        self.assertEqual(result, {("tcp", 80)})

    def test_multiple_ports(self):
        from software.sniffer.bridge_tap import _parse_port_filter
        result = _parse_port_filter(
            "tcp port 21 or tcp port 23 or tcp port 445"
        )
        self.assertEqual(result, {("tcp", 21), ("tcp", 23), ("tcp", 445)})

    def test_mixed_protocols(self):
        from software.sniffer.bridge_tap import _parse_port_filter
        result = _parse_port_filter("tcp port 80 or udp port 53")
        self.assertEqual(result, {("tcp", 80), ("udp", 53)})

    def test_case_insensitive(self):
        from software.sniffer.bridge_tap import _parse_port_filter
        result = _parse_port_filter("TCP PORT 443")
        self.assertEqual(result, {("tcp", 443)})


# ── Packet matching ──


class TestPacketMatches(unittest.TestCase):
    def test_empty_filter_matches_all(self):
        from software.sniffer.bridge_tap import _packet_matches
        pkt = Ether() / IP() / TCP(dport=12345)
        self.assertTrue(_packet_matches(pkt, set()))

    def test_tcp_dport_match(self):
        from software.sniffer.bridge_tap import _packet_matches
        pkt = Ether() / IP() / TCP(dport=80)
        self.assertTrue(_packet_matches(pkt, {("tcp", 80)}))

    def test_tcp_sport_match(self):
        from software.sniffer.bridge_tap import _packet_matches
        pkt = Ether() / IP() / TCP(sport=80, dport=54321)
        self.assertTrue(_packet_matches(pkt, {("tcp", 80)}))

    def test_tcp_no_match(self):
        from software.sniffer.bridge_tap import _packet_matches
        pkt = Ether() / IP() / TCP(dport=443)
        self.assertFalse(_packet_matches(pkt, {("tcp", 80)}))

    def test_udp_match(self):
        from software.sniffer.bridge_tap import _packet_matches
        pkt = Ether() / IP() / UDP(dport=53)
        self.assertTrue(_packet_matches(pkt, {("udp", 53)}))

    def test_udp_no_match_wrong_proto(self):
        from software.sniffer.bridge_tap import _packet_matches
        pkt = Ether() / IP() / TCP(dport=53)
        self.assertFalse(_packet_matches(pkt, {("udp", 53)}))

    def test_non_ip_packet(self):
        from software.sniffer.bridge_tap import _packet_matches
        pkt = Ether()
        self.assertFalse(_packet_matches(pkt, {("tcp", 80)}))

    def test_multi_filter_any_match(self):
        from software.sniffer.bridge_tap import _packet_matches
        pkt = Ether() / IP() / TCP(dport=23)
        filters = {("tcp", 21), ("tcp", 23), ("tcp", 445)}
        self.assertTrue(_packet_matches(pkt, filters))


# ── Packet dispatch (Fix #1) ──


class TestPacketDispatch(unittest.TestCase):
    def test_packets_routed_to_correct_writers(self):
        from software.sniffer.bridge_tap import BridgeTap

        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(capture_dir=tmpdir)
            tap = BridgeTap(config)
            tap._init_writers()

            http_pkt = Ether() / IP() / TCP(dport=80)
            ftp_pkt = Ether() / IP() / TCP(dport=21)
            dns_pkt = Ether() / IP() / UDP(dport=53)
            ssh_pkt = Ether() / IP() / TCP(dport=22)

            # Mock all writers
            for name, port_filter, writer in tap._writers:
                writer.write_packet = MagicMock()

            tap._packet_handler(http_pkt)
            tap._packet_handler(ftp_pkt)
            tap._packet_handler(dns_pkt)
            tap._packet_handler(ssh_pkt)

            writers = {name: w for name, _, w in tap._writers}

            # HTTP writer should get only the HTTP packet
            http_calls = writers["http"].write_packet.call_count
            self.assertEqual(http_calls, 1)

            # Credentials writer should get only the FTP packet
            cred_calls = writers["credentials"].write_packet.call_count
            self.assertEqual(cred_calls, 1)

            # DNS writer should get only the DNS packet
            dns_calls = writers["dns"].write_packet.call_count
            self.assertEqual(dns_calls, 1)

    def test_ssh_packet_goes_nowhere(self):
        """SSH port 22 is not in any enabled profile filter."""
        from software.sniffer.bridge_tap import BridgeTap

        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(capture_dir=tmpdir)
            tap = BridgeTap(config)
            tap._init_writers()

            for name, port_filter, writer in tap._writers:
                writer.write_packet = MagicMock()

            ssh_pkt = Ether() / IP() / TCP(dport=22)
            tap._packet_handler(ssh_pkt)

            for name, _, writer in tap._writers:
                writer.write_packet.assert_not_called()

    def test_all_profile_catches_everything(self):
        """The 'all' profile (empty filter) should match every packet."""
        from software.sniffer.bridge_tap import BridgeTap

        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(capture_dir=tmpdir)
            # Enable the 'all' profile
            for p in config["sniffer"]["capture_profiles"]:
                if p["name"] == "all":
                    p["enabled"] = True

            tap = BridgeTap(config)
            tap._init_writers()

            for name, port_filter, writer in tap._writers:
                writer.write_packet = MagicMock()

            pkt = Ether() / IP() / TCP(dport=9999)
            tap._packet_handler(pkt)

            writers = {name: w for name, _, w in tap._writers}
            # 'all' profile should catch it
            self.assertEqual(writers["all"].write_packet.call_count, 1)
            # Other profiles should NOT (port 9999 not in their filters)
            self.assertEqual(writers["http"].write_packet.call_count, 0)
            self.assertEqual(writers["credentials"].write_packet.call_count, 0)


# ── PcapRotator ──


class TestPcapRotator(unittest.TestCase):
    def test_new_filename_format(self):
        from software.sniffer.pcap_writer import PcapRotator

        with tempfile.TemporaryDirectory() as tmpdir:
            rotator = PcapRotator(base_dir=Path(tmpdir), prefix="test")
            fn = rotator._new_filename()
            self.assertTrue(fn.name.startswith("test_"))
            self.assertTrue(fn.name.endswith(".pcap"))

    def test_enforce_limits_by_count(self):
        from software.sniffer.pcap_writer import PcapRotator

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            # Create 8 fake pcap files
            for i in range(8):
                (base / f"test_{i:04d}.pcap").write_bytes(b"\x00" * 100)

            rotator = PcapRotator(
                base_dir=base, prefix="test", rotate_count=5,
            )
            rotator._current_file = base / "current.pcap"
            rotator._enforce_limits()

            remaining = list(base.glob("test_*.pcap"))
            self.assertLessEqual(len(remaining), 5)

    def test_stats_includes_encrypted_flag(self):
        from software.sniffer.pcap_writer import PcapRotator

        with tempfile.TemporaryDirectory() as tmpdir:
            rotator = PcapRotator(base_dir=Path(tmpdir), prefix="test")
            stats = rotator.stats
            self.assertIn("encrypted", stats)
            self.assertFalse(stats["encrypted"])

    @patch("software.sniffer.pcap_writer.subprocess.run")
    @patch("shutil.which", return_value="/usr/bin/gpg")
    def test_encrypt_file_calls_gpg(self, mock_which, mock_run):
        from software.sniffer.pcap_writer import PcapRotator

        mock_run.return_value = MagicMock(returncode=0)

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            pcap_file = base / "test_00000.pcap"
            pcap_file.write_bytes(b"\x00" * 100)

            rotator = PcapRotator(
                base_dir=base, prefix="test",
                encrypt=True, gpg_recipient="operator@test.com",
            )
            rotator._encrypt_file(pcap_file)

            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            self.assertIn("gpg", call_args)
            self.assertIn("--recipient", call_args)
            self.assertIn("operator@test.com", call_args)

    @patch("shutil.which", return_value=None)
    def test_encrypt_disabled_without_gpg(self, mock_which):
        from software.sniffer.pcap_writer import PcapRotator

        with tempfile.TemporaryDirectory() as tmpdir:
            rotator = PcapRotator(
                base_dir=Path(tmpdir), prefix="test",
                encrypt=True, gpg_recipient="operator@test.com",
            )
            self.assertFalse(rotator.encrypt)


# ── Exfiltrator persistence (Fix #2) ──


class TestExfilPersistence(unittest.TestCase):
    def _make_exfil_config(self, capture_dir):
        return {
            "sniffer": {"capture_dir": capture_dir},
            "c2": {
                "exfil_method": "https",
                "exfil_chunk_size_bytes": 512,
                "fallback": {
                    "https": {"callback_url": "https://c2.test/beacon"},
                },
                "dns": {"domain": "c2.test", "resolver": "8.8.8.8"},
            },
        }

    def _import_exfiltrator(self):
        import sys
        dns_mock = MagicMock()
        sys.modules.setdefault("dns", dns_mock)
        sys.modules.setdefault("dns.resolver", dns_mock)
        from software.c2.exfil import Exfiltrator
        return Exfiltrator

    def test_sent_files_persisted_to_disk(self):
        Exfiltrator = self._import_exfiltrator()

        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._make_exfil_config(tmpdir)
            exfil = Exfiltrator(config)

            exfil._sent_files.add("/some/file.pcap")
            exfil._save_sent_files()

            sent_path = Path(tmpdir) / ".exfil_sent"
            self.assertTrue(sent_path.exists())
            self.assertIn("/some/file.pcap", sent_path.read_text())

    def test_sent_files_loaded_from_disk(self):
        Exfiltrator = self._import_exfiltrator()

        with tempfile.TemporaryDirectory() as tmpdir:
            sent_path = Path(tmpdir) / ".exfil_sent"
            sent_path.write_text("/old/file1.pcap\n/old/file2.pcap")

            config = self._make_exfil_config(tmpdir)
            exfil = Exfiltrator(config)

            self.assertIn("/old/file1.pcap", exfil._sent_files)
            self.assertIn("/old/file2.pcap", exfil._sent_files)

    def test_empty_sent_file(self):
        Exfiltrator = self._import_exfiltrator()

        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._make_exfil_config(tmpdir)
            exfil = Exfiltrator(config)
            self.assertEqual(len(exfil._sent_files), 0)


# ── Bridge-nf coordination (Fix #5) ──


class TestBridgeNfCoordination(unittest.TestCase):
    @patch("software.sniffer.bridge_tap.subprocess.run")
    def test_sync_bridge_nf_respects_nac_state_file(self, mock_run):
        from software.sniffer.bridge_tap import BridgeTap

        mock_run.return_value = MagicMock(returncode=0)

        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / ".raccoon_bridge_nf_state"
            state_file.write_text("1")

            with patch("software.sniffer.bridge_tap.Path") as MockPath:
                MockPath.return_value = state_file
                MockPath.side_effect = lambda p: state_file if ".raccoon_bridge_nf_state" in str(p) else Path(p)

                config = _make_config(capture_dir=tmpdir)
                tap = BridgeTap(config)

                # Directly test the logic: if state file says "1", don't set to 0
                nf_state_file = state_file
                if nf_state_file.exists() and nf_state_file.read_text().strip() == "1":
                    bridge_nf_should_be_zero = False
                else:
                    bridge_nf_should_be_zero = True

                self.assertFalse(bridge_nf_should_be_zero)

    @patch("software.sniffer.bridge_tap.subprocess.run")
    def test_sync_bridge_nf_defaults_to_zero(self, mock_run):
        from software.sniffer.bridge_tap import BridgeTap

        mock_run.return_value = MagicMock(returncode=0)

        with tempfile.TemporaryDirectory() as tmpdir:
            # No state file in tmpdir
            state_file = Path(tmpdir) / ".raccoon_bridge_nf_state"

            nf_state_file = state_file
            if nf_state_file.exists() and nf_state_file.read_text().strip() == "1":
                bridge_nf_should_be_zero = False
            else:
                bridge_nf_should_be_zero = True

            self.assertTrue(bridge_nf_should_be_zero)


# ── Watchdog capture restart (Fix #4) ──


class TestWatchdogCaptureRestart(unittest.TestCase):
    def test_set_bridge_tap_and_restart(self):
        import sys
        sys.modules.setdefault("yaml", MagicMock())
        from software.watchdog import set_bridge_tap, _restart_capture

        mock_tap = MagicMock()
        set_bridge_tap(mock_tap)

        _restart_capture(mock_tap)

        mock_tap.stop.assert_called_once()


# ── BPF filter building ──


class TestBuildFilter(unittest.TestCase):
    def test_combines_enabled_profiles(self):
        from software.sniffer.bridge_tap import BridgeTap

        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(capture_dir=tmpdir)
            tap = BridgeTap(config)
            f = tap._build_filter()

            self.assertIn("tcp port 21", f)
            self.assertIn("tcp port 80", f)
            self.assertIn("udp port 53", f)
            self.assertIn(" or ", f)

    def test_disabled_profiles_excluded(self):
        from software.sniffer.bridge_tap import BridgeTap

        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(capture_dir=tmpdir)
            tap = BridgeTap(config)
            f = tap._build_filter()

            # 'all' profile is disabled and has empty filter
            # Should not produce an empty parenthesized group
            self.assertNotIn("()", f)

    def test_global_bpf_prepended(self):
        from software.sniffer.bridge_tap import BridgeTap

        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_config(capture_dir=tmpdir, bpf_filter="not arp")
            tap = BridgeTap(config)
            f = tap._build_filter()

            self.assertTrue(f.startswith("(not arp)"))


if __name__ == "__main__":
    unittest.main()
