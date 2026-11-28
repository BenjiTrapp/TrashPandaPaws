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

The trail is not the scout's: the beacon records each attempt into the
one file it writes *and* appends the trail line in the same call, because
it is the only process that knows an attempt happened. This file used to
hold the scout's copy of it; the comment where those tests were says why
they moved, and `test_way_out_trail.py` holds them now.
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
from software.tests import way_out_scratch as _scratch


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
        self.root = _scratch.scratch(self, "raccoon-scout-")

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

    def stuck(self, stuck_cycles=2, opened=None):
        """Write the beacon's state file, as the beacon writes it.

        **As the beacon writes it now**, which is the point of this
        helper: it carried an `attempts` list the beacon dropped and no
        `touched`, `spent` or `budget`, so every test built on it was
        exercising `wanted()`'s upgrade-compatibility branch instead of
        the production one. `touched` is what tells this process the
        beacon is still writing.

        `opened` is carried from whatever is already there, which is what
        `Beacon._way_out_publish_state` does: one window, one stamp, so the
        scout can tell a second publish of the same window from a new one.
        """
        existing = handoff.read_state(self.root) or {}
        handoff.write_private_json(handoff.state_path(self.root), {
            "version": handoff.STATE_VERSION,
            "opened": opened or existing.get("opened") or time.time(),
            "touched": time.time(),
            "stuck_cycles": stuck_cycles,
            "hours_dark": stuck_cycles / 12.0,
            "evidence": {"legs": {"https": "timed_out"}, "flags": []},
            "spent": 0,
            "budget": 3,
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

    def test_it_is_removed_when_the_window_closes(self):
        # The one file in this handoff that carries a **secret** -- a third
        # party's proxy password, captured off the wire -- and it used to
        # outlive the outage it was captured for: the beacon removes its
        # own window when a leg delivers, the scout stops publishing
        # because there is no window, and so the last borrow file stayed
        # on the disk of a device built to look like an IP phone until
        # somebody reimaged it. The page's "the trail holds no password"
        # is true precisely because this file does, so this file does not
        # get to be the one that is left behind.
        scout = self.scout()
        self.borrowable(scout)
        self.stuck()
        scout.publish_once()
        self.assertTrue(os.path.exists(handoff.borrow_path(self.root)))

        handoff.remove(handoff.state_path(self.root))     # a leg delivered
        with mock.patch.object(scout, "_sleep",
                               lambda seconds: scout.stop()):
            scout.run(interval=300.0)

        self.assertFalse(os.path.exists(handoff.borrow_path(self.root)),
                         "a captured password is still on the disk after the "
                         "outage it was captured for ended")

    def test_the_document_goes_with_it_when_the_window_closes(self):
        # The one handoff file nothing ever removed. It names the host's
        # MAC and IP, the host's proxies and resolvers, its TLS
        # destinations and the SSIDs in range -- so it stayed on the disk
        # of a device built to look like an IP phone after the outage it
        # described had ended. The beacon removes its own window file; the
        # scout owns this one and the borrow file.
        scout = self.scout()
        self.borrowable(scout)
        self.stuck()
        scout.publish_once()
        self.assertTrue(os.path.exists(handoff.document_path(self.root)))

        handoff.remove(handoff.state_path(self.root))     # a leg delivered
        with mock.patch.object(scout, "_sleep",
                               lambda seconds: scout.stop()):
            scout.run(interval=300.0)

        self.assertFalse(os.path.exists(handoff.document_path(self.root)),
                         "the tap's whole reading of the host is still on "
                         "the disk after the outage ended")
        self.assertFalse(os.path.exists(handoff.borrow_path(self.root)))

    def test_the_next_window_starts_from_no_captured_secret(self):
        # The same property from the beacon's side: a borrow verb on the
        # next outage must not find the last outage's credential, because
        # the evidence behind it is spent -- the scout drops its
        # `Evidence` at the same moment and for the same reason.
        scout = self.scout()
        self.borrowable(scout)
        self.stuck()
        scout.publish_once()

        handoff.remove(handoff.state_path(self.root))
        with mock.patch.object(scout, "_sleep",
                               lambda seconds: scout.stop()):
            scout.run(interval=300.0)
        self.assertIsNone(handoff.read_borrow(self.root))

        scout._running = True
        self.stuck(opened=time.time())
        scout.publish_once()
        self.assertEqual(handoff.read_borrow(self.root)["credentials"], [])

    def test_a_window_that_turned_over_between_polls_starts_again(self):
        # The hole the test above left, and it is the common case rather
        # than the exotic one: this process publishes every
        # `document_max_age_seconds / 2` and the beacon's outages turn
        # over on its own cycle, so a leg delivering and the next one
        # failing inside one of those sleeps is a window the scout never
        # saw *end*. It then republished the previous outage's captured
        # credential into the new window with a fresh `written` stamp,
        # which is newer than the new window's `opened` -- so the beacon's
        # own guard against exactly this passed it.
        scout = self.scout()
        self.borrowable(scout)
        self.stuck(opened=time.time() - 1200)
        scout.publish_once()
        self.assertEqual(len(handoff.read_borrow(self.root)["credentials"]),
                         1)
        self.assertEqual(handoff.read_document(self.root)["tap"]["proxies"],
                         ["10.0.0.1:3128"])

        # No poll in between: the window is simply a different one now.
        self.stuck(opened=time.time())
        document = scout.publish_once()

        self.assertEqual(handoff.read_borrow(self.root)["credentials"], [],
                         "the previous outage's captured password was "
                         "republished into this window")
        self.assertIsNone(handoff.read_borrow(self.root)["portal"])
        self.assertEqual(document["tap"]["proxies"], [])
        self.assertEqual(document["tap"]["credentials"], 0)
        self.assertIsNone(document["tap"]["host_mac"])

    def test_the_same_window_published_twice_keeps_its_evidence(self):
        # The other half, and the reason this is keyed on `opened` rather
        # than on "the state file changed": the beacon rewrites that file
        # every cycle of an outage the design's worst case puts at a week,
        # and evidence that reset on every publish would leave every rung
        # with nothing to act on.
        scout = self.scout()
        self.borrowable(scout)
        self.stuck(opened=time.time() - 1200)
        scout.publish_once()

        self.stuck(stuck_cycles=6)
        document = scout.publish_once()

        self.assertEqual(document["tap"]["credentials"], 1)
        self.assertEqual(len(handoff.read_borrow(self.root)["credentials"]),
                         1)

    def test_a_window_with_no_opened_stamp_is_not_read_as_a_new_one(self):
        # A beacon older than the field. Reading an upgrade as a new
        # window on every poll would throw the evidence away on every
        # poll, which is the one thing worse than keeping it too long.
        scout = self.scout()
        self.borrowable(scout)
        handoff.write_private_json(handoff.state_path(self.root), {
            "version": handoff.STATE_VERSION, "touched": time.time(),
            "stuck_cycles": 2, "evidence": {}})
        scout.publish_once()
        document = scout.publish_once()
        self.assertEqual(document["tap"]["credentials"], 1)

    def test_a_stamp_that_disappears_mid_window_is_not_a_new_window(self):
        # The sharper half: the beacon was replaced by one that does not
        # write `opened` while a window was open -- a downgrade, or a
        # half-finished install. "No stamp" is not a *different* stamp,
        # and treating it as one would spend this window's evidence on
        # somebody else's packaging mistake.
        scout = self.scout()
        self.stuck(opened=time.time() - 600)
        scout.publish_once()
        self.borrowable(scout)

        handoff.write_private_json(handoff.state_path(self.root), {
            "version": handoff.STATE_VERSION, "touched": time.time(),
            "stuck_cycles": 4, "evidence": {}})
        document = scout.publish_once()

        self.assertEqual(document["tap"]["credentials"], 1)
        self.assertEqual(len(handoff.read_borrow(self.root)["credentials"]),
                         1)


# The trail used to be here, and it is not the scout's any more. It copied
# new attempts out of the beacon's window file on this process's own
# publishing clock, which lost every attempt made in the last interval of a
# window -- a leg delivering removes that file, and on a recovered implant
# the lost line is the attempt that worked -- and duplicated what it had
# already copied whenever this unit restarted. `test_way_out_trail.py` holds
# it where it lives now: `Beacon._way_out_record_attempt`.


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


class TestWhichSideOfTheBridgeTheHostIsOn(ScoutCase):
    """The anchor for every piece of evidence a rung acts on.

    Three reviews running it was something an adversary could write.
    The bridge learns which port a MAC is on, and a peer on the segment
    cannot forge the port their frames arrive on -- so the scout asks the
    bridge.
    """

    FDB = """33:33:00:00:00:01 dev eth0 self permanent
aa:bb:cc:dd:ee:ff dev eth1 master br0
01:00:5e:00:00:01 dev eth1 self permanent
de:ad:be:ef:00:02 dev eth1 master br0
11:22:33:44:55:66 dev eth0 master br0
ff:ff:ff:ff:ff:ff dev eth1 self permanent
"""

    def test_it_reads_the_downstream_ports_own_addresses(self):
        scout = self.scout()
        with mock.patch.object(scout, "_run",
                               lambda *a, **k: (0, self.FDB)):
            self.assertEqual(scout._host_macs(),
                             ["aa:bb:cc:dd:ee:ff", "de:ad:be:ef:00:02"])

    def test_it_asks_about_the_configured_downstream_interface(self):
        # Both the shipped names and an operator's, because asking about
        # the *configured* port is the whole claim: a hard-coded `eth1`
        # satisfied a test that only ever used the default, and on a build
        # whose host is on another port it would anchor the evidence to a
        # port the host is not on -- which reads as "the bridge knows
        # nobody", so every frame on the segment becomes the host's again.
        for bridge, downstream in (("br0", "eth1"), ("raccoon0", "enp2s0")):
            with self.subTest(downstream=downstream):
                scout = self.scout(network={"bridge_name": bridge,
                                            "downstream_iface": downstream})
                asked = []
                with mock.patch.object(
                        scout, "_run",
                        lambda argv, **k: asked.append(argv) or (0, self.FDB)):
                    scout._host_macs()
                self.assertEqual(asked, [["bridge", "fdb", "show", "br",
                                          bridge, "dev", downstream]])

    def test_a_reading_that_fails_is_no_reading_rather_than_an_empty_one(self):
        # None and not `[]`: an empty list would mean "the host is nobody"
        # and the scout would collect nothing at all, which is worse than
        # a scout that can be lied to on a host whose bridge it cannot
        # read. `Evidence` says which.
        scout = self.scout()
        for answer in ((1, "Cannot find device"), (0, ""), (0, "rubbish\n")):
            with self.subTest(answer=answer):
                with mock.patch.object(scout, "_run",
                                       lambda *a, **k: answer):
                    self.assertIsNone(scout._host_macs())

    def test_the_evidence_is_given_the_reading(self):
        scout = self.scout()
        with mock.patch.object(scout, "_run",
                               lambda *a, **k: (0, self.FDB)):
            scout.refresh_identity()
        self.assertEqual(scout.evidence.host_macs,
                         frozenset(["aa:bb:cc:dd:ee:ff",
                                    "de:ad:be:ef:00:02"]))

    def test_the_reading_is_refreshed_per_publish(self):
        # The bridge learns and ages entries while the implant is dark, so
        # a reading taken once at construction would go stale over a
        # window the design says can last a week.
        scout = self.scout()
        self.stuck()
        seen = []
        with mock.patch.object(
                scout, "_run",
                lambda *a, **k: seen.append(1) or (0, self.FDB)):
            scout.publish_once()
            scout.publish_once()
        self.assertEqual(len(seen), 2)


class TestADeadBeaconDoesNotLeaveItRunning(ScoutCase):
    """The freshness rule, in the direction nobody had checked.

    The beacon ignores a stale document, so a dead scout is harmless. The
    scout had nothing of the kind: the window file is removed only when a
    leg delivers, never on a `kill`, a crash, an OOM kill or a
    `systemctl stop` -- so a dead beacon left the scout capturing and
    scanning the radio for ever, which is the detection signature the page
    spends a paragraph on.
    """

    def test_a_window_nobody_has_touched_for_hours_is_not_wanted(self):
        scout = self.scout()
        self.stuck()
        self.assertTrue(scout.wanted())

        # Self-consistent, as the beacon writes it: 30 days of 300 s
        # cycles. `hours_dark` over `stuck_cycles` is what tells this
        # process how long a cycle takes, so a fixture that disagrees
        # with itself would be testing arithmetic nothing produces.
        handoff.write_private_json(handoff.state_path(self.root), {
            "version": handoff.STATE_VERSION,
            "opened": time.time() - 30 * 86400,
            "touched": time.time() - 30 * 86400,
            "stuck_cycles": 30 * 24 * 12, "hours_dark": 720.0,
            "evidence": {}})
        self.assertFalse(scout.wanted(),
                         "the scout is still capturing 30 days after the "
                         "beacon stopped writing")
        self.assertIsNone(scout.publish_once())

    def test_a_window_the_beacon_is_still_writing_is_wanted(self):
        scout = self.scout()
        handoff.write_private_json(handoff.state_path(self.root), {
            "version": handoff.STATE_VERSION,
            "opened": time.time() - 30 * 86400,
            "touched": time.time() - 60,
            "stuck_cycles": 8640, "hours_dark": 720.0,
            "evidence": {}})
        self.assertTrue(scout.wanted(),
                        "a week-long outage is the case this exists for")

    def test_a_window_with_no_stamp_at_all_is_wanted(self):
        # A beacon older than this field. Reading it as dead would turn an
        # upgrade into a scout that never starts.
        scout = self.scout()
        handoff.write_private_json(handoff.state_path(self.root), {
            "version": handoff.STATE_VERSION, "opened": time.time() - 1000,
            "stuck_cycles": 2, "evidence": {}})
        self.assertTrue(scout.wanted())

    def test_the_ceiling_follows_the_beacons_live_interval(self):
        # `beacon_interval_seconds` is the operator's, has no upper bound,
        # and is re-set at runtime by the `sleep` task verb -- so the yaml
        # is only what the beacon *started* with. A fixed hour made every
        # live window on a long-interval build read as dead for most of
        # every cycle, and this process answers that by dropping its
        # evidence and deleting its captured credential. The window
        # carries the live number: `hours_dark` over `stuck_cycles` is
        # what a cycle currently costs.
        scout = self.scout()
        window = {"version": handoff.STATE_VERSION,
                  "opened": time.time() - 90000,
                  "touched": time.time() - 7300,
                  "stuck_cycles": 12, "hours_dark": 24.0, "evidence": {}}
        handoff.write_private_json(handoff.state_path(self.root), window)

        self.assertEqual(scout._window_ceiling(window), 12 * 7200)
        self.assertTrue(scout.wanted(),
                        "one missed cycle read as a dead beacon")

        # And the hour is a floor, not a multiplier to be shrunk: a short
        # interval does not buy a short ceiling, because the window file
        # is the only thing that says an outage is still on.
        brisk = dict(window, stuck_cycles=720, hours_dark=1.0)
        self.assertEqual(scout._window_ceiling(brisk), 3600)

    def test_a_window_that_does_not_say_falls_back_to_the_config(self):
        scout = self.scout(config=_config(c2={
            "beacon_interval_seconds": 7200,
            "way_out": {"enabled": True, "state_dir": self.root}}))
        self.assertEqual(
            scout._window_ceiling({"version": handoff.STATE_VERSION}),
            12 * 7200)

    def test_a_missing_or_rubbish_interval_is_the_floor(self):
        for value in (None, "soon", 0, True, -300):
            with self.subTest(interval=value):
                scout = self.scout(config=_config(c2={
                    "beacon_interval_seconds": value,
                    "way_out": {"enabled": True, "state_dir": self.root}}))
                self.assertEqual(scout._window_ceiling({}), 3600)

    def test_a_cycle_the_window_claims_is_longer_than_a_day_is_capped(self):
        # The window file is trusted, but not without bound: a file whose
        # numbers imply a cycle of weeks would keep this process
        # capturing and scanning the radio for ever, which is the
        # detection signature `wanted` exists to bound.
        scout = self.scout()
        absurd = {"version": handoff.STATE_VERSION, "stuck_cycles": 2,
                  "hours_dark": 720.0}
        self.assertEqual(scout._window_ceiling(absurd), 12 * 86400)

    def test_a_window_whose_own_numbers_are_rubbish_falls_back(self):
        scout = self.scout(config=_config(c2={
            "beacon_interval_seconds": 600,
            "way_out": {"enabled": True, "state_dir": self.root}}))
        for window in ({"stuck_cycles": 0, "hours_dark": 4.0},
                       {"stuck_cycles": 12, "hours_dark": 0},
                       {"stuck_cycles": True, "hours_dark": 4.0},
                       {"stuck_cycles": 12, "hours_dark": "four"},
                       {"stuck_cycles": -12, "hours_dark": 4.0}):
            with self.subTest(window=window):
                self.assertEqual(scout._window_ceiling(window), 12 * 600)


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
        # The *duration*, not merely that it sleeps: `self._sleep(1.0)`
        # passes an "is it positive" assertion and is a 15-in-16 capture
        # duty cycle on the 13 W device this cost control exists for.
        self.assertAlmostEqual(slept[0], 450.0 - 15, delta=1.0)

    def test_the_scan_interval_is_the_publishing_interval_at_least(self):
        # `max` and not `min`: a short publishing interval must not buy a
        # short scan interval, because the scan is the part that is
        # visible on somebody's wireless controller.
        scout = self.scout()
        scout.run.__func__  # it is a method, not a stand-in
        for interval, expected in ((450.0, 450.0), (10.0, 300.0),
                                   (1200.0, 1200.0)):
            with self.subTest(interval=interval):
                scout._running = False
                scout.run(interval=interval)
                self.assertEqual(scout._scan_interval, expected)

    def test_the_radio_is_scanned_once_per_interval_and_not_per_publish(self):
        scout = self.scout(ssids=None)
        self.stuck()
        scanned = []

        def run(argv, **_kwargs):
            # Only `iw` is the radio scan; the bridge's forwarding table
            # is read every publish on purpose and is not a scan.
            if argv and argv[0] == "iw":
                scanned.append(argv)
            return 0, ""

        with mock.patch.object(scout, "_radio_iface", lambda: "wlan0"), \
                mock.patch.object(scout, "_run", run), \
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
\tBSS Load:
\t\t * station count: 3
\t\t * channel utilisation: 12/255
\tsignal: -71.00 dBm
\tSSID: Visitors
BSS 22:33:44:55:66:77(on wlan0)
\tfreq: 5200
\tsignal: -88.00 dBm
\tSSID: CutShort
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
