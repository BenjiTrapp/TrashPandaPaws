#!/usr/bin/env python3
"""
Unit tests for beacon capability advertisement, uplink detection and batch
task processing. Nothing here reads the real /sys, the real routing table or
the real Raccoon config: all three are redirected to temporary fixtures.
"""

import os
import shutil
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

from software.c2 import beacon as beacon_mod
from software.c2 import beacon_standalone
from software.c2.beacon import Beacon


def _make_config(**overrides):
    cfg = {
        "c2": {
            "beacon_interval_seconds": 10,
            "jitter_percent": 20,
            "encryption_key": "",
            "proxy": {"mode": "none"},
            "https": {
                "enabled": True,
                "callback_url": "https://c2.test/api/v1/beacon",
                "verify_ssl": False,
            },
            "dns": {"enabled": False},
        }
    }
    cfg["c2"].update(overrides)
    return cfg


@contextmanager
def _tmpdir():
    d = tempfile.mkdtemp(prefix="beacon_caps_")
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


@contextmanager
def _tmp_capture_dir(files):
    with _tmpdir() as d:
        for name in files:
            Path(d, name).write_bytes(b"\xd4\xc3\xb2\xa1")
        yield d


@contextmanager
def _fake_sysfs(interfaces):
    """Point the beacon at a fake /sys/class/net.

    interfaces: {name: {"wireless": bool, "driver": str}}, or None for a
    system on which the directory does not exist at all.
    """
    with _tmpdir() as root:
        net = os.path.join(root, "net")
        if interfaces is not None:
            os.makedirs(net)
            for name, spec in interfaces.items():
                iface = os.path.join(net, name)
                os.makedirs(iface)
                if spec.get("wireless"):
                    os.makedirs(os.path.join(iface, "wireless"))
                if spec.get("driver"):
                    target = os.path.join(root, "drivers", spec["driver"])
                    os.makedirs(target, exist_ok=True)
                    os.makedirs(os.path.join(iface, "device"))
                    os.symlink(target, os.path.join(iface, "device", "driver"))
        with patch.object(beacon_mod, "_SYSFS_NET", net):
            yield net


_ROUTE_HEADER = ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\t"
                 "Mask\t\tMTU\tWindow\tIRTT\n")


def _route_line(iface, dest="00000000", gw="0100A8C0", flags="0003",
                metric=0, mask="00000000"):
    return (f"{iface}\t{dest}\t{gw}\t{flags}\t0\t0\t{metric}\t{mask}"
            f"\t0\t0\t0\n")


@contextmanager
def _fake_route_table(text):
    with _tmpdir() as d:
        path = os.path.join(d, "route")
        if text is not None:
            Path(path).write_text(text)
        with patch.object(beacon_mod, "_PROC_NET_ROUTE", path):
            yield


@contextmanager
def _fake_default_route(iface):
    """A routing table whose default route runs over iface (None: no default)."""
    text = _ROUTE_HEADER
    text += _route_line("lo", dest="0000007F", gw="00000000", mask="000000FF")
    if iface is not None:
        text += _route_line(iface)
    with _fake_route_table(text):
        yield


@contextmanager
def _fake_raccoon_config(present):
    """Make the Raccoon config exist (or not) on the paths the standalone
    launcher searches, and return the file that stands in for it."""
    with _tmpdir() as d:
        path = os.path.join(d, "raccoon.yaml")
        if present:
            Path(path).write_text("sniffer:\n  capture_dir: ''\n")
        with patch.object(beacon_standalone, "CONFIG_PATHS", [path]):
            yield path


class _Hermetic(unittest.TestCase):
    """Start every test on a host with no sysfs, no route, no Raccoon config."""

    def setUp(self):
        for cm in (_fake_sysfs(None), _fake_route_table(None),
                   _fake_raccoon_config(False)):
            cm.__enter__()
            self.addCleanup(cm.__exit__, None, None, None)

    def _beacon(self, **c2_overrides):
        b = Beacon(_make_config(**c2_overrides))
        b._running = True
        return b


@contextmanager
def _capture_processed(b, raise_on=None):
    """Replace _process_tasking with a recorder that mimics kill."""
    seen = []

    def fake(tasking):
        if not tasking:
            return
        seen.append(tasking)
        if tasking.get("cmd") == "kill":
            b._running = False
        if raise_on is not None and tasking.get("cmd") == raise_on:
            raise RuntimeError("boom")

    with patch.object(b, "_process_tasking", side_effect=fake):
        yield seen


class TestCapabilityDetection(_Hermetic):
    def test_batch_is_always_advertised(self):
        self.assertIn("batch", self._beacon()._detect_caps())

    def test_platform_class_is_advertised(self):
        caps = self._beacon()._detect_caps()
        self.assertTrue(("posix" in caps) ^ ("windows" in caps))

    def test_windows_host_is_classed_as_windows(self):
        b = self._beacon()
        with patch.object(beacon_mod.platform, "system", return_value="Windows"):
            caps = b._detect_caps()
        self.assertIn("windows", caps)
        self.assertNotIn("posix", caps)

    def test_smbloot_is_advertised(self):
        self.assertIn("smbloot", self._beacon()._detect_caps())

    def test_sniffer_requires_an_existing_capture_dir_with_pcaps(self):
        b = self._beacon()
        with _tmp_capture_dir(files=[]) as d:
            b.capture_dir = d
            self.assertNotIn("sniffer", b._detect_caps())
        with _tmp_capture_dir(files=["cap_001.pcap"]) as d:
            b.capture_dir = d
            self.assertIn("sniffer", b._detect_caps())

    def test_sniffer_finds_pcaps_in_profile_subdirectories(self):
        b = self._beacon()
        with _tmpdir() as d:
            os.makedirs(os.path.join(d, "http"))
            Path(d, "http", "http_20260101.pcap").write_bytes(b"x")
            b.capture_dir = d
            self.assertIn("sniffer", b._detect_caps())

    def test_sniffer_without_a_capture_dir_attribute_does_not_raise(self):
        b = self._beacon()
        self.assertFalse(hasattr(b, "capture_dir"))
        caps = b._detect_caps()
        self.assertNotIn("sniffer", caps)
        self.assertIn("batch", caps)

    def test_sniffer_falls_back_to_the_configured_capture_dir(self):
        b = self._beacon()
        with _tmp_capture_dir(files=["cap_001.pcap"]) as captures:
            with _fake_raccoon_config(False) as cfg:
                Path(cfg).write_text(
                    "sniffer:\n  capture_dir: '%s'\n" % captures)
                self.assertIn("sniffer", b._detect_caps())

    def test_wifi_scan_requires_a_wireless_interface(self):
        b = self._beacon()
        with _fake_sysfs(interfaces={"eth0": {}}):
            self.assertNotIn("wifi:scan", b._detect_caps())
        with _fake_sysfs(interfaces={"wlan0": {"wireless": True}}):
            self.assertIn("wifi:scan", b._detect_caps())

    def test_wifi_monitor_requires_a_known_driver(self):
        b = self._beacon()
        with _fake_sysfs(interfaces={"wlan0": {"wireless": True,
                                               "driver": "brcmfmac"}}):
            caps = b._detect_caps()
            self.assertIn("wifi:scan", caps)
            self.assertNotIn("wifi:monitor", caps)
        with _fake_sysfs(interfaces={"wlan1": {"wireless": True,
                                               "driver": "88XXau"}}):
            self.assertIn("wifi:monitor", b._detect_caps())

    def test_wifi_monitor_is_found_next_to_the_onboard_chip(self):
        with _fake_sysfs(interfaces={
                "wlan0": {"wireless": True, "driver": "brcmfmac"},
                "wlan1": {"wireless": True, "driver": "rtl8812au"}}):
            caps = self._beacon()._detect_caps()
        self.assertIn("wifi:monitor", caps)

    def test_detection_never_raises_on_a_bare_system(self):
        with _fake_sysfs(interfaces=None):
            self.assertIsInstance(self._beacon()._detect_caps(), list)

    def test_detection_survives_every_probe_failing(self):
        b = self._beacon()
        with patch.object(beacon_mod.os, "listdir", side_effect=OSError), \
                patch.object(beacon_mod.Path, "exists", side_effect=OSError):
            caps = b._detect_caps()
        self.assertIsInstance(caps, list)
        self.assertIn("batch", caps)
        self.assertIn("smbloot", caps)


class TestDropboxDetection(_Hermetic):
    """"dropbox" is what the agent layer classes the host by: it must not
    depend on an optional side effect such as a capture directory."""

    def test_raccoon_config_on_disk_advertises_dropbox(self):
        with _fake_raccoon_config(True):
            self.assertIn("dropbox", self._beacon()._detect_caps())

    def test_no_raccoon_config_does_not_advertise_dropbox(self):
        with _fake_raccoon_config(False):
            self.assertNotIn("dropbox", self._beacon()._detect_caps())

    def test_launcher_hint_advertises_dropbox_without_any_config(self):
        with _fake_raccoon_config(False):
            b = self._beacon(dropbox=True)
            self.assertIn("dropbox", b._detect_caps())

    def test_hint_off_and_no_config_is_not_a_dropbox(self):
        with _fake_raccoon_config(False):
            b = self._beacon(dropbox=False)
            self.assertNotIn("dropbox", b._detect_caps())

    def test_dropbox_does_not_depend_on_captures(self):
        with _fake_raccoon_config(True):
            caps = self._beacon()._detect_caps()
        self.assertIn("dropbox", caps)
        self.assertNotIn("sniffer", caps)

    def test_dropbox_is_advertised_even_if_the_config_search_fails(self):
        """A broken config lookup must not hide the launcher's word."""
        b = self._beacon(dropbox=True)
        with patch.object(beacon_mod.Path, "exists", side_effect=OSError):
            self.assertIn("dropbox", b._detect_caps())

    def test_launchers_tell_the_beacon_it_runs_on_the_dropbox(self):
        """main.py and beacon_standalone.py build the config for the beacon;
        both must carry the hint."""
        root = Path(__file__).resolve().parents[1]
        for rel in ("main.py", "c2/beacon_standalone.py"):
            src = (root / rel).read_text()
            self.assertIn('"dropbox": True', src, rel)


class TestCapsInPayload(_Hermetic):
    def test_system_info_carries_caps(self):
        self.assertIn("caps", self._beacon()._system_info())

    def test_caps_is_a_list_of_strings(self):
        caps = self._beacon()._system_info()["caps"]
        self.assertIsInstance(caps, list)
        self.assertTrue(all(isinstance(c, str) for c in caps))

    def test_system_info_carries_the_uplink_interface(self):
        """The safety layer needs it to refuse monitor mode on the uplink."""
        self.assertIn("uplink_iface", self._beacon()._system_info())

    def test_system_info_reports_dropbox(self):
        with _fake_raccoon_config(True):
            b = self._beacon()
        self.assertIn("dropbox", b._system_info()["caps"])

    def test_uplink_is_in_the_payload(self):
        with _fake_default_route("eth0"):
            b = self._beacon()
        self.assertEqual(b._system_info()["uplink_iface"], "eth0")

    def test_detection_runs_once_not_per_check_in(self):
        with patch.object(Beacon, "_detect_caps",
                          return_value=["batch"]) as caps_mock, \
                patch.object(Beacon, "_detect_uplink_iface",
                             return_value="eth0") as uplink_mock:
            b = self._beacon()
            for _ in range(3):
                info = b._system_info()
        self.assertEqual(caps_mock.call_count, 1)
        self.assertEqual(uplink_mock.call_count, 1)
        self.assertEqual(info["caps"], ["batch"])
        self.assertEqual(info["uplink_iface"], "eth0")

    def test_payload_caps_are_a_copy(self):
        b = self._beacon()
        b._system_info()["caps"].append("junk")
        self.assertNotIn("junk", b._system_info()["caps"])

    def test_register_payload_carries_caps(self):
        b = self._beacon()
        with patch.object(b, "_https_post",
                          return_value={"success": True}) as post:
            b._register_https()
        endpoint, payload = post.call_args[0]
        self.assertEqual(endpoint, "register")
        self.assertIn("caps", payload)
        self.assertIn("uplink_iface", payload)


class TestUplinkDetection(_Hermetic):
    def test_default_route_interface_is_reported(self):
        with _fake_default_route("eth0"):
            self.assertEqual(self._beacon()._detect_uplink_iface(), "eth0")

    def test_bridge_interface_is_reported_when_it_carries_the_route(self):
        with _fake_default_route("br0"):
            self.assertEqual(self._beacon()._detect_uplink_iface(), "br0")

    def test_missing_default_route_yields_none_without_raising(self):
        with _fake_default_route(None):
            self.assertIsNone(self._beacon()._detect_uplink_iface())

    def test_missing_route_table_yields_none(self):
        with _fake_route_table(None):
            self.assertIsNone(self._beacon()._detect_uplink_iface())

    def test_garbage_route_table_yields_none(self):
        with _fake_route_table("\x00\xff nonsense\n\tfoo\n"):
            self.assertIsNone(self._beacon()._detect_uplink_iface())

    def test_lowest_metric_default_route_wins(self):
        text = (_ROUTE_HEADER + _route_line("wlan0", metric=600)
                + _route_line("eth0", metric=100))
        with _fake_route_table(text):
            self.assertEqual(self._beacon()._detect_uplink_iface(), "eth0")

    def test_tied_default_routes_over_different_interfaces_yield_none(self):
        """Guessing wrong would let the safety layer cut its own channel."""
        text = (_ROUTE_HEADER + _route_line("wlan0", metric=100)
                + _route_line("eth0", metric=100))
        with _fake_route_table(text):
            self.assertIsNone(self._beacon()._detect_uplink_iface())

    def test_route_that_is_down_is_not_a_default_route(self):
        text = _ROUTE_HEADER + _route_line("eth0", flags="0002")
        with _fake_route_table(text):
            self.assertIsNone(self._beacon()._detect_uplink_iface())

    def test_a_rejecting_route_is_not_a_default_route(self):
        text = _ROUTE_HEADER + _route_line("eth0", flags="0201")
        with _fake_route_table(text):
            self.assertIsNone(self._beacon()._detect_uplink_iface())

    def test_a_default_destination_with_a_narrower_mask_is_not_the_default(self):
        text = _ROUTE_HEADER + _route_line("eth0", mask="00FFFFFF")
        with _fake_route_table(text):
            self.assertIsNone(self._beacon()._detect_uplink_iface())

    def test_windows_reports_no_uplink(self):
        # `route print` names the interface by address, and the router
        # compares against interface *names*, so an address can never match:
        # the safety layer would believe the uplink is known and allow a
        # monitor-mode switch on it. Reporting nothing instead makes every
        # interface count as the uplink, which refuses all switches. On
        # Windows there is no monitor-mode path anyway, so the conservative
        # answer costs nothing.
        b = self._beacon()
        with patch.object(beacon_mod.platform, "system",
                          return_value="Windows"), \
                patch.object(beacon_mod.subprocess, "run") as run:
            self.assertIsNone(b._detect_uplink_iface())
        run.assert_not_called()

    def test_windows_without_a_default_route_yields_none(self):
        b = self._beacon()
        result = MagicMock(stdout="IPv4 Route Table\n", returncode=0)
        with patch.object(beacon_mod.platform, "system",
                          return_value="Windows"), \
                patch.object(beacon_mod.subprocess, "run",
                             return_value=result):
            self.assertIsNone(b._detect_uplink_iface())

    def test_windows_route_failure_yields_none(self):
        b = self._beacon()
        with patch.object(beacon_mod.platform, "system",
                          return_value="Windows"), \
                patch.object(beacon_mod.subprocess, "run",
                             side_effect=OSError):
            self.assertIsNone(b._detect_uplink_iface())


class TestBatchProcessing(_Hermetic):
    def test_single_task_dict_still_processed(self):
        """Status quo: an old server sends a single task dict."""
        b = self._beacon()
        with _capture_processed(b) as seen:
            b._process_tasking_batch(
                {"cmd": "whoami", "args": "", "task_id": "t1"})
        self.assertEqual([t["task_id"] for t in seen], ["t1"])

    def test_task_list_processed_in_order(self):
        b = self._beacon()
        batch = {"tasks": [{"cmd": "whoami", "task_id": "t1"},
                           {"cmd": "pwd", "task_id": "t2"},
                           {"cmd": "id", "task_id": "t3"}]}
        with _capture_processed(b) as seen:
            b._process_tasking_batch(batch)
        self.assertEqual([t["task_id"] for t in seen], ["t1", "t2", "t3"])

    def test_one_failing_task_does_not_stop_the_batch(self):
        b = self._beacon()
        batch = {"tasks": [{"cmd": "boom", "task_id": "t1"},
                           {"cmd": "whoami", "task_id": "t2"}]}
        with _capture_processed(b, raise_on="boom") as seen:
            b._process_tasking_batch(batch)
        self.assertIn("t2", [t["task_id"] for t in seen])

    def test_kill_in_a_batch_stops_the_remaining_tasks(self):
        b = self._beacon()
        batch = {"tasks": [{"cmd": "kill", "task_id": "t1"},
                           {"cmd": "whoami", "task_id": "t2"}]}
        with _capture_processed(b) as seen:
            b._process_tasking_batch(batch)
        self.assertEqual([t["task_id"] for t in seen], ["t1"])
        self.assertFalse(b._running)

    def test_kill_in_the_middle_runs_what_came_before_it(self):
        b = self._beacon()
        batch = {"tasks": [{"cmd": "whoami", "task_id": "t1"},
                           {"cmd": "kill", "task_id": "t2"},
                           {"cmd": "id", "task_id": "t3"}]}
        with _capture_processed(b) as seen:
            b._process_tasking_batch(batch)
        self.assertEqual([t["task_id"] for t in seen], ["t1", "t2"])

    def test_kill_through_the_real_dispatcher_stops_the_batch(self):
        b = self._beacon()
        batch = {"tasks": [{"cmd": "kill", "id": "t1"},
                           {"cmd": "sleep", "args": "99", "id": "t2"}]}
        interval = b.interval
        with patch.object(b, "_send_result_https"):
            b._process_tasking_batch(batch)
        self.assertFalse(b._running)
        self.assertEqual(b.interval, interval)

    def test_empty_dict_is_a_no_op(self):
        b = self._beacon()
        with _capture_processed(b) as seen:
            b._process_tasking_batch({})
        self.assertEqual(seen, [])

    def test_empty_task_list_is_a_no_op(self):
        b = self._beacon()
        with _capture_processed(b) as seen:
            b._process_tasking_batch({"tasks": []})
        self.assertEqual(seen, [])

    def test_malformed_task_list_does_not_raise(self):
        b = self._beacon()
        with _capture_processed(b) as seen:
            b._process_tasking_batch({"tasks": "not-a-list"})
            b._process_tasking_batch({"tasks": [None, "x",
                                                {"cmd": "pwd", "task_id": "t"}]})
        self.assertEqual([t["task_id"] for t in seen], ["t"])

    def test_beacon_loop_dispatches_through_the_batch_entry_point(self):
        b = self._beacon()
        b.https_enabled = True
        b._registered = True
        calls = []

        def once():
            b._running = False
            return {"tasks": [{"cmd": "pwd", "id": "t1"}]}

        with patch.object(b, "_beacon_https", side_effect=once), \
                patch.object(b, "_process_tasking_batch",
                             side_effect=calls.append), \
                patch.object(b, "_jittered_sleep"):
            b._beacon_loop()
        self.assertEqual(calls, [{"tasks": [{"cmd": "pwd", "id": "t1"}]}])


if __name__ == "__main__":
    unittest.main()
