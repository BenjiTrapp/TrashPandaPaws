#!/usr/bin/env python3
"""The scout: the process that watches the tapped port and publishes.

It runs on the Pi from the same venv as `software/main.py`, under
`services/raccoon-scout.service`, and it is the dependency-heavy half of
this work: scapy to capture, PyYAML to read the config, and in its model
stage one HTTP call to loopback. `beacon.py` is served to a target as
source text and may import only the standard library, so none of that can
live there -- which is the whole reason this process exists.

Two properties shape every test below.

**Quiet on a healthy implant.** It publishes nothing, captures nothing and
scans nothing until the beacon's state file says a stuck window is open.
A second promiscuous reader on a 13 W device that is already bridging and
capturing is a cost, so it is paid only while there is something to pay
it for.

**Nothing it is asked to do may raise.** It runs unattended on a device
nobody can reach; a publish that threw on a full disk would end the one
process that could have explained the rescue afterwards.

The trail is the scout's and not the beacon's: the beacon records its
attempts into the one file it writes, which is removed when a leg
delivers, and the scout copies each new attempt onto an append-only trail
that outlives the window.
"""

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from scapy.all import IP, TCP, Ether, Raw

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.scout import handoff
from software.scout.scout import Scout


def _config(**overrides):
    config = {
        "network": {"upstream_iface": "eth0", "downstream_iface": "eth1",
                    "bridge_name": "br0"},
        "nac_bypass": {"enabled": False},
        "c2": {"way_out": {"enabled": True, "state_dir": ""}},
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(config.get(key), dict):
            config[key].update(value)
        else:
            config[key] = value
    return config


class ScoutCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="raccoon-scout-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def scout(self, config=None, ssids=None, **overrides):
        config = config or _config(**overrides)
        config["c2"]["way_out"]["state_dir"] = self.root
        scout = Scout(config, self.root)
        self.addCleanup(scout.stop)
        if ssids is not None:
            patcher = mock.patch.object(scout, "_scan_ssids",
                                        lambda: list(ssids))
            patcher.start()
            self.addCleanup(patcher.stop)
        else:
            patcher = mock.patch.object(scout, "_scan_ssids", lambda: [])
            patcher.start()
            self.addCleanup(patcher.stop)
        return scout

    def stuck(self, stuck_cycles=2, attempts=(), opened=None):
        """Write the beacon's state file, as the beacon writes it.

        `opened` is carried from whatever is already there, which is what
        `Beacon._way_out_publish_state` does: one window, one stamp, so the
        scout can tell a second publish of the same window from a new one.
        """
        existing = handoff.read_state(self.root) or {}
        handoff.write_private_json(handoff.state_path(self.root), {
            "version": handoff.STATE_VERSION,
            "opened": opened or existing.get("opened") or time.time(),
            "stuck_cycles": stuck_cycles,
            "hours_dark": stuck_cycles / 12.0,
            "evidence": {"legs": {"https": "timed_out"}, "flags": []},
            "attempts": list(attempts),
        })

    def eapol(self):
        return (Ether(src="aa:bb:cc:dd:ee:ff", dst="01:80:c2:00:00:03",
                      type=0x888E) / Raw(b"\x01\x01\x00\x00"))


class TestItIsQuietUntilTheBeaconIsStuck(ScoutCase):
    def test_with_no_state_file_it_publishes_nothing(self):
        scout = self.scout()
        self.assertIsNone(scout.publish_once())
        self.assertEqual(os.listdir(self.root), [])

    def test_with_a_state_file_of_another_version_it_publishes_nothing(self):
        handoff.write_private_json(handoff.state_path(self.root),
                                   {"version": handoff.STATE_VERSION + 1})
        self.assertIsNone(self.scout().publish_once())
        self.assertIsNone(handoff.read_document(self.root))

    def test_it_captures_nothing_while_the_beacon_is_healthy(self):
        # The capture is the cost on a 13 W device that is already
        # bridging. `wanted` is what the loop asks before it sniffs.
        scout = self.scout()
        self.assertFalse(scout.wanted())
        self.stuck()
        self.assertTrue(scout.wanted())

    def test_it_scans_the_radio_only_while_the_beacon_is_stuck(self):
        scanned = []
        scout = self.scout()
        with mock.patch.object(scout, "_scan_ssids",
                               lambda: scanned.append(1) or []):
            self.assertIsNone(scout.publish_once())
            self.assertEqual(scanned, [])
            self.stuck()
            self.assertIsNotNone(scout.publish_once())
            self.assertEqual(len(scanned), 1)


class TestWhatItPublishes(ScoutCase):
    def test_the_document_carries_the_beacons_evidence_and_the_taps(self):
        scout = self.scout(ssids=[{"ssid": "GuestWifi", "open": True}])
        scout.observe(self.eapol())
        self.stuck()
        published = scout.publish_once()

        self.assertEqual(published["version"], handoff.DOCUMENT_VERSION)
        # The beacon's own evidence, copied through unchanged: the
        # recommendation is matched against it, so a scout that rewrote it
        # would make every recommendation look stale.
        self.assertEqual(published["evidence"],
                         {"legs": {"https": "timed_out"}, "flags": []})
        self.assertEqual(published["tap"]["flags"], ["dot1x_seen"])
        self.assertEqual(published["tap"]["ssids"],
                         [{"ssid": "GuestWifi", "open": True}])
        self.assertEqual(handoff.read_document(self.root), published)

    def test_the_document_is_timestamped_so_the_beacon_can_ignore_it(self):
        self.stuck()
        before = time.time()
        published = self.scout().publish_once()
        self.assertGreaterEqual(published["published"], before)
        self.assertLessEqual(published["published"], time.time())

    def test_it_says_whether_the_identity_rung_is_already_spent(self):
        self.stuck()
        self.assertFalse(self.scout().publish_once()["identity_pre_spent"])
        self.stuck()
        self.assertTrue(
            self.scout(nac_bypass={"enabled": True})
            .publish_once()["identity_pre_spent"])

    def test_an_identity_request_that_was_taken_also_counts_as_spent(self):
        self.stuck()
        handoff.write_private_json(handoff.identity_path(self.root), {
            "version": handoff.STATE_VERSION, "requested": time.time(),
            "taken": time.time(), "detail": "nac_bypass was started"})
        self.assertTrue(self.scout().publish_once()["identity_pre_spent"])

    def test_it_recommends_nothing_while_the_model_is_off(self):
        self.stuck()
        self.assertIsNone(self.scout().publish_once()["recommendation"])

    def test_a_validated_answer_becomes_the_documents_recommendation(self):
        # The one place stage 4 reaches the handoff. The beacon still
        # prices it: a recommendation is a proposal, and `_way_out_allows`
        # is what decides whether the rung may be taken.
        self.stuck()
        config = _config()
        config["c2"]["way_out"]["model"] = {
            "enabled": True, "endpoint": "http://127.0.0.1:11434",
            "name": "qwen2.5:0.5b", "timeout_seconds": 5}
        scout = self.scout(config=config, ssids=[])
        asked = {}

        def ask(model, state, tap):
            asked["model"] = model
            asked["tap"] = tap
            return {"verb": "gsocket", "chose": "model", "argument": "",
                    "p_success": 0.6, "why": "nothing answered"}

        with mock.patch("software.scout.model.ask", ask):
            published = scout.publish_once()

        self.assertEqual(published["recommendation"]["verb"], "gsocket")
        self.assertEqual(published["recommendation"]["chose"], "model")
        self.assertEqual(asked["model"]["name"], "qwen2.5:0.5b")
        # The same reading the beacon is handed, scan included, and not a
        # second one taken a moment later.
        self.assertEqual(asked["tap"], published["tap"])


class TestTheCredentialsStayOutOfTheDocument(ScoutCase):
    AUTH = ("Proxy-Authorization: Basic Y29ycFxhbGljZTpzM2NyZXQ=")

    def connect(self, auth=True):
        """A CONNECT through the host's proxy, carrying a Basic credential."""
        head = "CONNECT a:443 HTTP/1.1\r\nHost: proxy.lan:3128\r\n"
        if auth:
            head += self.AUTH + "\r\n"
        return (Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
                / IP(src="10.0.0.50", dst="10.0.0.1")
                / TCP(sport=44444, dport=3128) / Raw((head + "\r\n").encode()))

    def refused(self):
        """The 407 that makes the credential on the next CONNECT real."""
        head = ("HTTP/1.1 407 Proxy Authentication Required\r\n"
                "Proxy-Authenticate: Basic realm=\"corp\"\r\n\r\n")
        return (Ether(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff")
                / IP(src="10.0.0.1", dst="10.0.0.50")
                / TCP(sport=3128, dport=44444) / Raw(head.encode()))

    def borrowable(self, scout):
        """The whole sequence a borrowable credential needs on the wire."""
        scout.observe(self.connect(auth=False))
        scout.observe(self.refused())
        scout.observe(self.connect())

    def test_they_go_to_a_file_of_their_own_and_not_to_the_handoff(self):
        scout = self.scout()
        self.borrowable(scout)
        self.stuck()
        published = scout.publish_once()

        self.assertNotIn("s3cret", json.dumps(published))
        self.assertEqual(published["tap"]["credentials"], 1)
        borrow = handoff.read_borrow(self.root)
        self.assertEqual(borrow["credentials"][0]["secret"], "s3cret")

    def test_that_file_is_private(self):
        scout = self.scout()
        self.borrowable(scout)
        self.stuck()
        scout.publish_once()
        self.assertEqual(
            os.stat(handoff.borrow_path(self.root)).st_mode & 0o777, 0o600)


class TestTheTrail(ScoutCase):
    def attempt(self, verb, outcome="recorded"):
        return {"at": time.time(), "verb": verb, "task": verb, "rung": 2,
                "chose": "policy", "outcome": outcome,
                "gate": {"rung": 2, "row": "way_out_borrow"}}

    def trail(self):
        path = handoff.trail_path(self.root)
        if not os.path.exists(path):
            return []
        return [json.loads(line)
                for line in Path(path).read_text().splitlines()]

    def test_each_attempt_reaches_the_trail_once(self):
        scout = self.scout()
        self.stuck(attempts=[self.attempt("gsocket")])
        scout.publish_once()
        scout.publish_once()
        self.assertEqual([line["verb"] for line in self.trail()], ["gsocket"])

        self.stuck(attempts=[self.attempt("gsocket"),
                             self.attempt("proxy")])
        scout.publish_once()
        self.assertEqual([line["verb"] for line in self.trail()],
                         ["gsocket", "proxy"])

    def test_it_outlives_the_state_file(self):
        scout = self.scout()
        self.stuck(attempts=[self.attempt("gsocket")])
        scout.publish_once()
        handoff.remove(handoff.state_path(self.root))
        self.assertIsNone(scout.publish_once())
        self.assertEqual(len(self.trail()), 1)

    def test_a_new_window_starts_counting_again(self):
        scout = self.scout()
        self.stuck(attempts=[self.attempt("gsocket")], opened=1000.0)
        scout.publish_once()
        handoff.remove(handoff.state_path(self.root))
        self.stuck(attempts=[self.attempt("proxy")], opened=2000.0)
        scout.publish_once()
        self.assertEqual([line["verb"] for line in self.trail()],
                         ["gsocket", "proxy"])

    def test_each_line_says_what_drove_it(self):
        scout = self.scout()
        self.stuck(attempts=[self.attempt("gsocket")])
        scout.publish_once()
        line = self.trail()[0]
        for key in ("verb", "task", "chose", "gate", "outcome", "window",
                    "evidence"):
            self.assertIn(key, line, key)
        self.assertEqual(line["chose"], "policy")

    def test_an_attempt_that_is_not_an_object_is_skipped(self):
        scout = self.scout()
        self.stuck(attempts=[17, "proxy", self.attempt("gsocket")])
        scout.publish_once()
        self.assertEqual([line["verb"] for line in self.trail()], ["gsocket"])


class TestNothingItIsAskedToDoMayRaise(ScoutCase):
    def test_an_unwritable_state_directory_costs_one_warning(self):
        config = _config()
        config["c2"]["way_out"]["state_dir"] = "/proc/no-such-place"
        scout = Scout(config, "/proc/no-such-place")
        self.addCleanup(scout.stop)
        with mock.patch.object(scout, "_scan_ssids", lambda: []):
            self.assertIsNone(scout.publish_once())
            self.assertFalse(scout.wanted())

    def test_a_scan_that_fails_leaves_an_empty_list(self):
        scout = self.scout()
        self.stuck()
        with mock.patch.object(scout, "_run",
                               lambda *a, **k: (1, "no such device")):
            self.assertEqual(scout.publish_once()["tap"]["ssids"], [])

    def test_a_failed_scan_is_not_read_even_when_it_printed_something(self):
        # `iw` can print part of a scan and still exit non-zero -- a radio
        # that went down mid-scan. Half a scan read as a whole one would
        # offer rung 3 an SSID that may not be there, which is an attempt
        # spent on nothing.
        half = "BSS 00:11:22:33:44:55(on wlan0)\n\tSSID: GuestWifi\n" \
               "\tcapability: ESS (0x0401)\ncommand failed: Network is down\n"
        scout = self.scout(ssids=None)
        self.stuck()
        with mock.patch.object(scout, "_radio_iface", lambda: "wlan0"), \
                mock.patch.object(scout, "_run", lambda *a, **k: (240, half)), \
                mock.patch.object(scout, "_scan_ssids",
                                  Scout._scan_ssids.__get__(scout)):
            self.assertEqual(scout.publish_once()["tap"]["ssids"], [])

    def test_a_packet_that_cannot_be_read_is_ignored(self):
        scout = self.scout()
        for packet in (None, object(), b"", Ether()):
            scout.observe(packet)
        self.stuck()
        self.assertEqual(scout.publish_once()["tap"]["flags"], [])

    def test_a_config_that_is_not_what_it_should_be_costs_one_warning(self):
        # The unit is `Restart=on-failure` with a burst limit, so five
        # crashes in five minutes and systemd stops trying -- on a device
        # nobody can reach. A review found three raises reachable from a
        # single config typo: `(x or {}).get(...)` guards None and [] and
        # not a scalar.
        for config in ({"nac_bypass": "enabled"},
                       {"network": "br0"},
                       {"c2": "way_out"},
                       {"nac_bypass": 17, "network": []}):
            with self.subTest(config=config):
                broken = _config()
                broken.update(config)
                broken.setdefault("c2", {})
                if isinstance(broken["c2"], dict):
                    broken["c2"]["way_out"] = {"enabled": True,
                                               "state_dir": self.root}
                scout = Scout(broken, self.root)
                self.addCleanup(scout.stop)
                with mock.patch.object(scout, "_scan_ssids", lambda: []):
                    self.stuck()
                    scout.publish_once()       # raises nothing

    def test_a_state_file_whose_fields_are_the_wrong_shape_is_survived(self):
        scout = self.scout()
        for evidence in ("legs", 17, {"legs": []}, {"legs": "https"},
                         {"flags": "dot1x_seen"}):
            with self.subTest(evidence=evidence):
                handoff.write_private_json(handoff.state_path(self.root), {
                    "version": handoff.STATE_VERSION, "opened": time.time(),
                    "stuck_cycles": 2, "hours_dark": 0.2,
                    "evidence": evidence, "attempts": "not a list"})
                scout.publish_once()           # raises nothing

    def test_a_trail_that_cannot_be_appended_costs_nothing_else(self):
        scout = self.scout()
        self.stuck(attempts=[{"verb": "gsocket"}])
        with mock.patch.object(handoff, "append_trail",
                               side_effect=OSError("full")):
            published = scout.publish_once()
        self.assertIsNotNone(published, "the document was lost with the "
                                        "trail line")

    def test_a_half_written_trail_does_not_repeat_what_got_through(self):
        # The counter advances per line that landed, not per round: a
        # failure on the second of three used to reset nothing, so the
        # next publish re-appended the first.
        scout = self.scout()
        self.stuck(attempts=[{"verb": "gsocket"}, {"verb": "proxy"}])
        calls = {"n": 0}
        real = handoff.append_trail

        def flaky(state_dir, line):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("full")
            return real(state_dir, line)

        with mock.patch.object(handoff, "append_trail", flaky):
            scout.publish_once()
        scout.publish_once()

        lines = [json.loads(line) for line
                 in Path(handoff.trail_path(self.root)).read_text()
                 .splitlines()]
        self.assertEqual([entry["verb"] for entry in lines],
                         ["gsocket", "proxy"])

    def test_anything_that_raises_in_a_publish_costs_only_that_round(self):
        # The outer guard, which the config and state guards inside it
        # should make unreachable -- and "should" is why it is here: this
        # process is the only thing that could explain the rescue
        # afterwards, and its unit stops retrying after five failures.
        scout = self.scout()
        self.stuck()
        with mock.patch.object(handoff, "write_document",
                               side_effect=RuntimeError("something new")):
            self.assertIsNone(scout.publish_once())
        # And the next round is unaffected.
        self.assertIsNotNone(scout.publish_once())

    def test_the_implants_own_traffic_is_not_read_as_the_hosts(self):
        # The scout sniffs `br0`, which carries the beacon's own queries
        # and its own TLS. Read from sysfs at construction, so the
        # document and the model's prompt cannot describe the implant to
        # itself.
        sysfs = tempfile.mkdtemp(prefix="raccoon-sysfs-")
        self.addCleanup(shutil.rmtree, sysfs, ignore_errors=True)
        os.makedirs(os.path.join(sysfs, "br0"))
        with open(os.path.join(sysfs, "br0", "address"), "w") as handle:
            handle.write("AA:BB:CC:DD:EE:FF\n")

        from software.scout import scout as scout_mod
        with mock.patch.object(scout_mod, "_SYSFS_NET", sysfs):
            scout = self.scout()
        self.assertEqual(scout.evidence.own_mac, "aa:bb:cc:dd:ee:ff")

        head = b"CONNECT a:443 HTTP/1.1\r\nHost: proxy.lan:3128\r\n\r\n"
        scout.observe(Ether(src="aa:bb:cc:dd:ee:ff",
                            dst="11:22:33:44:55:66")
                      / IP(src="10.0.0.50", dst="10.0.0.1")
                      / TCP(sport=44444, dport=3128) / Raw(head))
        self.stuck()
        self.assertIsNone(scout.publish_once()["tap"]["host_mac"])


class TestWhatItCostsWhileTheImplantIsDark(ScoutCase):
    """It publishes on a clock, and scans far less often than it publishes.

    A review found the interval unimplemented: `run` slept only on the
    healthy branch, so a stuck implant captured continuously and ran
    `iw scan` every ~15 seconds for as long as the outage lasted. On a
    13 W device whose power budget this design spends four paragraphs
    worrying about -- and on a box shaped like an IP phone, where four
    wireless scans a minute for ever is its own signature.
    """

    def test_it_sleeps_between_publishes_while_the_beacon_is_stuck(self):
        scout = self.scout()
        self.stuck()
        slept = []
        captured = []
        with mock.patch.object(scout, "capture_slice",
                               lambda *a, **k: captured.append(1)), \
                mock.patch.object(scout, "_sleep",
                                  lambda seconds: slept.append(seconds)
                                  or scout.stop()):
            scout.run(interval=450.0)
        self.assertEqual(len(captured), 1)
        self.assertTrue(slept, "it published and went straight round again")
        self.assertGreater(slept[0], 0)
        self.assertLessEqual(slept[0], 450.0)

    def test_the_radio_is_scanned_once_per_interval_and_not_per_publish(self):
        scout = self.scout(ssids=None)
        self.stuck()
        scanned = []
        with mock.patch.object(scout, "_radio_iface", lambda: "wlan0"), \
                mock.patch.object(
                    scout, "_run",
                    lambda *a, **k: scanned.append(1) or (0, "")), \
                mock.patch.object(scout, "_scan_ssids",
                                  Scout._scan_ssids.__get__(scout)):
            for _ in range(5):
                scout.publish_once()
        self.assertEqual(len(scanned), 1,
                         "the radio was scanned once per publish: %d scans "
                         "for five publishes" % len(scanned))

    def test_a_cached_scan_is_still_published(self):
        scout = self.scout(ssids=[{"ssid": "GuestWifi", "open": True}])
        self.stuck()
        first = scout.publish_once()["tap"]["ssids"]
        second = scout.publish_once()["tap"]["ssids"]
        self.assertEqual(first, second)
        self.assertEqual(first, [{"ssid": "GuestWifi", "open": True}])


class TestTheRadioScan(ScoutCase):
    # Verbatim `iw dev wlan0 scan`, and the order is the whole point:
    # `capability:` is a fixed BSS field and comes **before** `SSID:`,
    # which is an information element. A fixture with SSID first -- which
    # is what this file shipped at first -- certifies a parser that reads
    # each network's capability off the *next* network's block and drops
    # the last SSID entirely. A review caught it; this is real output.
    OUTPUT = """BSS 00:11:22:33:44:55(on wlan0)
\tTSF: 1 usec (0d, 00:00:01)
\tfreq: 2412
\tbeacon interval: 100 TUs
\tcapability: ESS ShortSlotTime (0x0401)
\tsignal: -42.00 dBm
\tlast seen: 120 ms ago
\tSSID: GuestWifi
\tSupported rates: 1.0* 2.0* 5.5* 11.0*
BSS 66:77:88:99:aa:bb(on wlan0)
\tfreq: 2437
\tcapability: ESS Privacy ShortSlotTime (0x0411)
\tsignal: -55.00 dBm
\tSSID: CorpSecure
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
BSS cc:dd:ee:ff:00:11(on wlan0)
\tfreq: 5180
\tcapability: ESS (0x0401)
\tsignal: -71.00 dBm
\tSSID: Visitors
"""

    def test_it_reads_which_networks_are_open(self):
        scout = self.scout(ssids=None)
        with mock.patch.object(scout, "_radio_iface", lambda: "wlan0"), \
                mock.patch.object(scout, "_run",
                                  lambda *a, **k: (0, self.OUTPUT)), \
                mock.patch.object(scout, "_scan_ssids",
                                  Scout._scan_ssids.__get__(scout)):
            self.assertEqual(
                scout._scan_ssids(),
                [{"ssid": "GuestWifi", "open": True},
                 {"ssid": "CorpSecure", "open": False},
                 {"ssid": "Visitors", "open": True}])

    def test_a_hidden_network_is_not_offered_as_an_ssid(self):
        # `SSID: ` with nothing after it is a hidden network. There is
        # nothing for `iw connect` to be given, so it is not a candidate.
        hidden = ("BSS 00:11:22:33:44:55(on wlan0)\n"
                  "\tcapability: ESS (0x0401)\n\tSSID: \n")
        scout = self.scout(ssids=None)
        with mock.patch.object(scout, "_radio_iface", lambda: "wlan0"), \
                mock.patch.object(scout, "_run",
                                  lambda *a, **k: (0, hidden)), \
                mock.patch.object(scout, "_scan_ssids",
                                  Scout._scan_ssids.__get__(scout)):
            self.assertEqual(scout._scan_ssids(), [])

    def test_a_block_with_no_capability_line_is_not_guessed_at(self):
        # Truncated output -- the scan was cut short. "Probably open" is
        # not a thing this may answer: rung 3 would spend an attempt on it.
        partial = ("BSS 00:11:22:33:44:55(on wlan0)\n"
                   "\tSSID: GuestWifi\n")
        scout = self.scout(ssids=None)
        with mock.patch.object(scout, "_radio_iface", lambda: "wlan0"), \
                mock.patch.object(scout, "_run",
                                  lambda *a, **k: (0, partial)), \
                mock.patch.object(scout, "_scan_ssids",
                                  Scout._scan_ssids.__get__(scout)):
            self.assertEqual(scout._scan_ssids(), [])

    def test_the_same_network_on_two_bands_is_offered_once(self):
        twice = ("BSS 00:11:22:33:44:55(on wlan0)\n"
                 "\tcapability: ESS (0x0401)\n\tSSID: GuestWifi\n"
                 "BSS 00:11:22:33:44:66(on wlan0)\n"
                 "\tcapability: ESS (0x0401)\n\tSSID: GuestWifi\n")
        scout = self.scout(ssids=None)
        with mock.patch.object(scout, "_radio_iface", lambda: "wlan0"), \
                mock.patch.object(scout, "_run",
                                  lambda *a, **k: (0, twice)), \
                mock.patch.object(scout, "_scan_ssids",
                                  Scout._scan_ssids.__get__(scout)):
            self.assertEqual(scout._scan_ssids(),
                             [{"ssid": "GuestWifi", "open": True}])

    def test_with_no_radio_it_scans_nothing(self):
        scout = self.scout(ssids=None)
        ran = []
        with mock.patch.object(scout, "_radio_iface", lambda: None), \
                mock.patch.object(scout, "_run",
                                  lambda *a, **k: ran.append(a) or (0, "")), \
                mock.patch.object(scout, "_scan_ssids",
                                  Scout._scan_ssids.__get__(scout)):
            self.assertEqual(scout._scan_ssids(), [])
            self.assertEqual(ran, [])


class TestItBringsNothingNewToInstall(unittest.TestCase):
    def test_its_requirements_name_only_what_the_implant_already_has(self):
        scout = (REPO_ROOT / "software" / "scout" / "requirements.txt")
        implant = (REPO_ROOT / "software" / "requirements.txt").read_text()
        for line in scout.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            self.assertIn(line, implant,
                          "%r is not already in software/requirements.txt, so "
                          "the scout would need an install the drop box has "
                          "not had" % line)

    def test_the_implants_own_requirements_have_not_grown(self):
        # The project's hard promise. The scout's file exists so that this
        # one does not have to change.
        implant = (REPO_ROOT / "software" / "requirements.txt").read_text()
        names = [line.split("#", 1)[0].strip().split(">")[0].split("=")[0]
                 for line in implant.splitlines()
                 if line.split("#", 1)[0].strip()]
        self.assertEqual(sorted(names),
                         ["colorama", "cryptography", "dnspython", "netifaces",
                          "numpy", "pyaudio", "pyyaml", "requests", "scapy"])


if __name__ == "__main__":
    unittest.main()
