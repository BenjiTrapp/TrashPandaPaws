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

import base64
import errno
import io
import socket
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib import error as urllib_error

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.c2 import beacon as beacon_mod
from software.c2.beacon import read_way_out_policy
from software.scout import handoff
from software.tests import test_egress_decider as _decider
from software.tests import way_out_scratch as _scratch

A_CREDENTIAL = {"kind": "proxy-basic", "user": "corp\\alice",
                "secret": "s3cret", "where": "10.0.0.1:3128"}
A_PORTAL = {"url": "http://portal.lan/login", "body": "user=guest&accept=1",
            "content_type": "application/x-www-form-urlencoded"}


class RungCase(_decider.DeciderCase):
    """A beacon with a state directory, a scout document and a borrow file."""

    def setUp(self):
        super().setUp()
        self.state = _scratch.scratch(self, "raccoon-rung-")

    def beacon(self, hours_dark=24.0, tap=None, borrow=None, **extra):
        block = {"enabled": True, "state_dir": self.state}
        beacon = _scratch.assert_live(
            self, self.a_beacon(way_out=read_way_out_policy(block), **extra))
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

    def beacon_with_raw_borrow(self, text, **extra):
        """A beacon whose borrow file is whatever `text` says."""
        beacon = self.beacon(**extra)
        Path(handoff.borrow_path(self.state)).write_text(text)
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
        self.assertEqual(proxies["https"], "http://10.0.0.1:3128")
        self.assertEqual(proxies["http"], proxies["https"])

    def test_the_secret_does_not_leave_the_borrow_file(self):
        # Not only the verb's answer. A review found the password in the
        # check-in payload's `proxy_active` and in `proxyinfo`'s output,
        # because it had been written into the proxy URL -- so a third
        # party's credential, captured from their traffic, was persisted
        # in the team server's database and rendered in its panel from the
        # next check-in onward. That is a finding against the operator on
        # any engagement with scoped credential handling.
        beacon = self.beacon(borrow={"credentials": [A_CREDENTIAL]})
        answer = beacon._exec_egress("credential")

        self.assertIn("corp\\alice", answer)
        self.assertIn("10.0.0.1:3128", answer)
        for where, text in (("the verb's answer", answer),
                            ("the check-in payload",
                             json.dumps(beacon._system_info())),
                            ("proxyinfo", beacon._exec_proxyinfo()),
                            ("the session's proxies",
                             json.dumps(beacon._proxy_session.proxies))):
            with self.subTest(where=where):
                self.assertNotIn("s3cret", text, where)
                self.assertNotIn("czNjcmV0", text, where)

    def test_the_credential_still_authenticates_the_proxy(self):
        # Keeping it out of the URL must not mean dropping it: the header
        # is what answers the 407.
        beacon = self.beacon(borrow={"credentials": [A_CREDENTIAL]})
        beacon._exec_egress("credential")
        header = beacon._proxy_session.headers.get("Proxy-Authorization", "")
        self.assertTrue(header.startswith("Basic "))
        self.assertEqual(
            base64.b64decode(header.split(None, 1)[1]).decode(),
            "corp\\alice:s3cret")

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
        for text in ("", "{not json", "[]",
                     '{"version": 1, "credentials": "alice"}',
                     '{"version": 1, "credentials": [17]}',
                     '{"version": 1, "credentials": [{"kind": "x"}]}',
                     # A version this implant does not know: the two halves
                     # are upgraded by two different installs, and this is
                     # the file that selects a credential.
                     '{"version": 99, "credentials": [{"kind": "proxy-basic",'
                     ' "user": "a", "secret": "b", "where": "c:1"}]}'):
            with self.subTest(text=text):
                beacon = self.beacon_with_raw_borrow(text)
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
        # `replace` and not `add`, both of them: a second attempt is the
        # ordinary case -- no verb tests its own result -- and `add`
        # answers "File exists", which used to roll the working
        # association back on top of itself.
        self.assertIn("ip addr replace 192.168.9.42/24 dev wlan0", joined)
        self.assertIn("ip route replace default via 192.168.9.1 dev wlan0 "
                      "table 100", joined)
        self.assertIn("ip rule add from 192.168.9.42 table 100", joined)
        # And the rule is removed before it is added, because `ip rule
        # add` has no `replace` and stacks silently.
        self.assertLess(joined.index("ip rule del from 192.168.9.42 "
                                     "table 100"),
                        joined.index("ip rule add from 192.168.9.42 "
                                     "table 100"))
        # Nothing flushes the interface: an operator's management address
        # on the onboard radio is not this rung's to delete.
        self.assertNotIn("ip addr flush dev wlan0", joined)
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

        # And the dhclient invocation itself, which is the part the argv
        # list above cannot show: the route in question would be installed
        # by `dhclient-script`, not by this process. `-sf /bin/true` is
        # the nine characters that stop it, and nothing asserted them --
        # delete them and the implant strands itself the first time this
        # rung fires, with nothing red.
        dhclient = [argv for argv in ran if argv and argv[0] == "dhclient"]
        self.assertEqual(len(dhclient), 1, ran)
        self.assertIn("-sf", dhclient[0])
        self.assertEqual(dhclient[0][dhclient[0].index("-sf") + 1],
                         "/bin/true",
                         "dhclient's own script installs a default route, "
                         "which is the one thing this rung may never do")
        self.assertIn("-1", dhclient[0],
                      "one attempt and then give up: this runs on the "
                      "beacon's thread")

    def test_every_radio_command_has_a_deadline(self):
        # A deadline per command, which is what this rung actually has:
        # it runs on the beacon's own thread, so a `dhclient` that never
        # returned would cost the implant its loop. It is **not** a time
        # box on the association, which nothing here ends -- see
        # `docs/WAY_OUT.md`, which says so rather than implying otherwise.
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

    def test_the_scoped_route_is_one_this_implant_can_actually_use(self):
        # The sharp end of the rung, and it did not work: `ip rule from
        # <addr>` matches only packets whose *source* is that address, and
        # for a locally-generated connection the kernel looks the route up
        # with an unspecified source -- so table 100 was unreachable and
        # the implant's traffic kept leaving exactly where it did before,
        # while the verb reported success. Something has to bind it.
        beacon = self.beacon(tap=self.open_ssid())
        self.onboard(beacon)
        self.radio(beacon)
        answer = beacon._exec_egress("radio")

        self.assertNotIn("[error]", answer)
        self.assertEqual(beacon._way_out_source, "192.168.9.42")
        # And the sockets that carry this implant's traffic use it.
        session = beacon._proxy_session or beacon_mod._HttpSession()
        self.assertEqual(session.source_address, ("192.168.9.42", 0))
        self.assertIn("192.168.9.42", answer)

    def test_a_dns_query_leaves_from_the_same_address(self):
        beacon = self.beacon(tap=self.open_ssid())
        self.onboard(beacon)
        self.radio(beacon)
        beacon._exec_egress("radio")

        bound = []

        class FakeSocket(object):
            def __init__(self, *_a, **_k):
                pass

            def settimeout(self, _seconds):
                pass

            def bind(self, address):
                bound.append(address)

            def sendto(self, *_a):
                pass

            def recvfrom(self, _size):
                # Twelve bytes of nothing: enough for `_dns_query` to
                # return an empty answer rather than raise, which keeps
                # this test about the bind and nothing else.
                return b"\x00" * 12, ("10.0.0.2", 53)

            def close(self):
                pass

        with mock.patch.object(beacon_mod.socket, "socket", FakeSocket):
            beacon_mod._dns_query("x.lan", "TXT", "10.0.0.2", timeout=1,
                                  source=beacon._way_out_source)
        self.assertEqual(bound, [("192.168.9.42", 0)])

    def test_the_source_survives_the_leg_that_the_radio_delivered(self):
        # This test used to assert the opposite, and it was asserting the
        # defect. A leg delivering is the moment the rung is *working* --
        # the delivery came through table 100 -- so unbinding there sent
        # the next cycle back out of the dead tapped port, with
        # `_stuck_cycles` reset to zero, so the implant had to re-climb
        # five hours to re-run the rung. One delivering cycle per five
        # hours, for ever: a rung that only looks like a way out, which is
        # the design's own anti-goal.
        beacon = self.beacon(tap=self.open_ssid())
        self.onboard(beacon)
        self.radio(beacon)
        beacon._exec_egress("radio")
        self.assertEqual(beacon._way_out_source, "192.168.9.42")

        beacon._leg_recovered()
        self.assertEqual(beacon._way_out_source, "192.168.9.42")
        self.assertEqual(beacon._proxy_session.source_address,
                         ("192.168.9.42", 0))

    def test_a_rung_two_verb_does_not_quietly_unbind_the_radio(self):
        # Rung 2 crosses at one hour dark and rung 3 at five, so after
        # `radio` succeeds the candidate walk will reach `proxy` or
        # `credential` on a later cycle. Each of them builds a fresh
        # session, and each used to drop the bind while `_way_out_source`
        # went on claiming it -- so HTTP left by the dead tapped port with
        # the log line still saying "this implant's own traffic only".
        beacon = self.beacon(tap=self.open_ssid(),
                             borrow={"credentials": [A_CREDENTIAL]})
        self.onboard(beacon)
        self.radio(beacon)
        beacon._exec_egress("radio")

        beacon._proxy.proxies.append({"url": "http://10.0.0.9:3128"})
        for task in ("credential", "proxy http://10.0.0.9:3128",
                     "rediscover"):
            with self.subTest(task=task):
                beacon._exec_egress(task)
                self.assertEqual(beacon._proxy_session.source_address,
                                 ("192.168.9.42", 0), task)

    def test_a_rollback_drops_the_source_too(self):
        beacon = self.beacon(tap=self.open_ssid())
        self.onboard(beacon)
        self.radio(beacon, fail_at="ip rule add")
        self.assertIn("[error]", beacon._exec_egress("radio"))
        self.assertEqual(beacon._way_out_source, "")

    def test_a_failed_retry_unbinds_what_the_first_attempt_bound(self):
        # The only path on which the rollback's unbind is reachable, and
        # it is the ordinary one: the first attempt succeeded and bound
        # the lease, the second failed, and the association is gone -- so
        # sockets pinned to an address on a network the implant is no
        # longer associated with would be sockets that cannot reach
        # anything at all.
        beacon = self.beacon(tap=self.open_ssid())
        self.onboard(beacon)
        self.radio(beacon)
        self.assertNotIn("[error]", beacon._exec_egress("radio"))
        self.assertEqual(beacon._way_out_source, "192.168.9.42")

        self.radio(beacon, fail_at="iw dev wlan0 connect")
        self.assertIn("[error]", beacon._exec_egress("radio"))
        self.assertEqual(beacon._way_out_source, "")
        self.assertIsNone(beacon._proxy_session.source_address)

    def test_a_second_attempt_does_not_tear_down_a_working_one(self):
        # No verb tests its own result, so the policy keeps choosing
        # `radio` on the next stuck cycle: a second attempt is the
        # ordinary case. It used to fail on `ip addr add` ("File exists"),
        # roll back with no address to go on -- so neither the table nor
        # the rule was removed -- and then disconnect and down the
        # interface, killing the association that was working.
        beacon = self.beacon(tap=self.open_ssid())
        self.onboard(beacon)
        ran = self.radio(beacon)
        self.assertNotIn("[error]", beacon._exec_egress("radio"))

        del ran[:]
        answer = beacon._exec_egress("radio")
        joined = [" ".join(argv) for argv in ran]
        self.assertNotIn("[error]", answer, joined)
        self.assertNotIn("iw dev wlan0 disconnect", joined,
                         "a second attempt tore down the first one's "
                         "association: %r" % joined)

    def test_a_rollback_clears_a_rule_this_attempt_did_not_install(self):
        # A rollback that only undid its own steps left the *previous*
        # attempt's source rule and table-100 route behind -- a change the
        # operator cannot see and cannot undo from the far side. The lease
        # is how a later rollback knows which address to remove.
        beacon = self.beacon(tap=self.open_ssid())
        self.onboard(beacon)
        ran = self.radio(beacon)
        self.assertNotIn("[error]", beacon._exec_egress("radio"))

        del ran[:]
        beacon._exec_egress("radio foo-not-open")      # declines, nothing ran
        ran2 = self.radio(beacon, fail_at="iw dev wlan0 connect")
        beacon._exec_egress("radio")
        joined = [" ".join(argv) for argv in ran2]
        self.assertIn("ip route flush table 100", joined, joined)
        self.assertIn("ip rule del from 192.168.9.42 table 100", joined,
                      joined)

    def test_the_lease_stays_in_the_private_directory(self):
        # Not litter: it is the only record of which address the source
        # rule was installed for that survives a restart of this process,
        # and it lives in the 0700 handoff directory with everything else.
        beacon = self.beacon(tap=self.open_ssid())
        self.onboard(beacon)
        self.radio(beacon)
        self.assertNotIn("[error]", beacon._exec_egress("radio"))
        self.assertIn("way_out_radio.lease", os.listdir(self.state))

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

    def test_a_sessions_own_headers_are_carried_on_a_json_post(self):
        # Where the borrowed credential actually goes out. `post` is what
        # every leg of this beacon uses, and a version that dropped
        # `self.headers` would leave the rung silently doing nothing: the
        # proxy would answer 407 again and the operator would read
        # "credential borrowed" in the trail.
        session, seen = self.captured()
        session.headers["Proxy-Authorization"] = "Basic Y29ycDpwdw=="
        session.post("http://127.0.0.1/api", {"a": 1}, {})
        self.assertEqual(seen["request"].get_header("Proxy-authorization"),
                         "Basic Y29ycDpwdw==")

    def test_a_per_request_header_wins_over_the_sessions(self):
        session, seen = self.captured()
        session.headers["X-Thing"] = "session"
        session.post("http://127.0.0.1/api", {"a": 1}, {"X-Thing": "request"})
        self.assertEqual(seen["request"].get_header("X-thing"), "request")

    def test_a_sessions_own_headers_are_carried_on_a_raw_post(self):
        session, seen = self.captured()
        session.headers["Proxy-Authorization"] = "Basic Y29ycDpwdw=="
        session.post_raw("http://portal.lan/login", b"a=1", {})
        self.assertEqual(seen["request"].get_header("Proxy-authorization"),
                         "Basic Y29ycDpwdw==")

    def test_a_refusal_is_an_answer_and_not_an_exception(self):
        session, _ = self.captured(status=403)
        self.assertEqual(session.post_raw("http://portal.lan/login", b"a=1",
                                          {}).status_code, 403)


class TestTheBindIsASocketFactAndNotAField(unittest.TestCase):
    """What the kernel did, read off the far end of a real connection.

    The two handlers under `_HttpSession` are the whole of the radio
    rung's bind: `ip rule from <address>` matches only packets whose
    source *is* that address, so a handler that forwards no
    `source_address` leaves the rung installing a route nothing can
    select -- which is exactly how rung 3 shipped once, and the design's
    recorded lesson from it is that a verb whose effect is on the kernel
    cannot be proved by asserting its argument. Every other test of the
    bind asserts `session.source_address`, a field; these two connect to
    a listener on this host and read the source that listener *observed*.

    Loopback has one address everywhere this suite runs, so the **port**
    carries the discrimination. `source_address` is a pair, the rung
    passes port 0 and lets the kernel choose, and pinning the port here
    is the same mechanism seen from the far end: with the handlers
    dropping it, the connection arrives from an ephemeral port that is
    not this one.
    """

    def a_free_port(self) -> int:
        """A port nothing is listening on, for the client to bind.

        Asked of the kernel rather than picked: a hard-coded port would
        be a test that fails on whichever machine happens to be using it.
        There is a window between this closing the probe and the client
        binding, which `bound_to` handles by asking for another one.
        """
        probe = socket.socket()
        try:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]
        finally:
            probe.close()

    def bound_to(self, attempt):
        """Run `attempt(port)` from a pinned local port; return the port.

        Retried on `EADDRINUSE` alone, and three times: something else on
        this machine taking the port between `a_free_port` and the
        connect is the one failure here that is not about the code under
        test, and swallowing any wider class of error would be a test
        that passes when the bind does not work at all.
        """
        last = None
        for _ in range(3):
            port = self.a_free_port()
            try:
                attempt(port)
            except OSError as exc:
                if getattr(exc, "errno", None) != errno.EADDRINUSE:
                    raise
                last = exc
                continue
            except urllib_error.URLError as exc:
                reason = getattr(exc, "reason", None)
                if getattr(reason, "errno", None) != errno.EADDRINUSE:
                    return port
                last = exc
                continue
            return port
        raise AssertionError("no free local port stayed free: %r" % (last,))

    def session(self, port):
        session = beacon_mod._HttpSession()
        # No proxy from this machine's environment: `http_proxy` set by
        # whoever is running the suite would send the request somewhere
        # else entirely, and the test would be about their proxy.
        session.trust_env = False
        session.source_address = ("127.0.0.1", port)
        return session

    def test_an_http_request_arrives_from_the_address_it_was_bound_to(self):
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                seen.append(self.client_address)
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.05},
                                  daemon=True)
        thread.start()

        def stop():
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.addCleanup(stop)
        url = "http://127.0.0.1:%d/x" % server.server_address[1]
        answered = []

        def attempt(port):
            del seen[:]
            response = self.session(port).post_raw(url, b"a=1", {}, timeout=10)
            answered.append(response.status_code)

        port = self.bound_to(attempt)
        self.assertEqual(answered, [200])
        self.assertEqual(seen, [("127.0.0.1", port)])

    def test_an_https_request_arrives_from_the_address_it_was_bound_to(self):
        # A plain TCP listener and not a TLS one: the handshake is not the
        # subject and cannot be set up from the standard library, which
        # cannot mint a certificate. The source address is carried by the
        # connection, and the listener has read it off the accepted socket
        # before it declines to speak TLS -- so the request failing is
        # part of the arrangement, and what it failed *with* is checked.
        seen = []
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        # With a timeout, so the thread below can be asked to stop: closing
        # a listening socket is not guaranteed to wake another thread out
        # of `accept`, and the first draft of this test spent five seconds
        # per run proving it.
        listener.settimeout(0.2)
        done = threading.Event()

        def accept():
            while not done.is_set():
                try:
                    connection, peer = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                seen.append(peer)
                connection.close()

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()

        def stop():
            done.set()
            thread.join(timeout=5)
            listener.close()

        self.addCleanup(stop)
        url = "https://127.0.0.1:%d/x" % listener.getsockname()[1]
        refused = []

        def attempt(port):
            del seen[:]
            try:
                self.session(port).post_raw(url, b"a=1", {}, timeout=10)
            except urllib_error.URLError as exc:
                reason = getattr(exc, "reason", None)
                if getattr(reason, "errno", None) == errno.EADDRINUSE:
                    raise
                refused.append(exc)
            else:
                raise AssertionError("the listener spoke TLS after all")

        port = self.bound_to(attempt)
        self.assertEqual(len(refused), 1, refused)
        self.assertEqual(seen, [("127.0.0.1", port)])


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
