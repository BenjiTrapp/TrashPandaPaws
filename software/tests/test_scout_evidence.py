#!/usr/bin/env python3
"""What the implant is uniquely placed to see, and what it makes of it.

The implant is an inline tap between a switch port and a host, so it can
watch what gets out of that host *working* -- which is evidence nobody in
this repository collects today. These tests are about the reading, not
about the capture: every one of them hands `Evidence.observe` a packet and
asks what the evidence now says.

**Nothing `observe` is given may raise.** It runs on a capture thread on a
13 W device, and a parse error on a malformed frame that cost the scout its
thread would cost the implant the evidence it exists to collect. So the
malformed cases below are not politeness: they are the contract.
"""

import sys
import unittest
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from software.scout import evidence as evidence_mod  # noqa: E402


def _tcp(src, dst, sport, dport, payload=b""):
    packet = (Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
              / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport))
    return packet / Raw(payload) if payload else packet


class EvidenceCase(unittest.TestCase):
    """One fresh `Evidence` per test, plus the packets they are made of."""

    HOST = "10.0.0.50"
    GATEWAY = "10.0.0.1"

    def setUp(self):
        self.evidence = evidence_mod.Evidence()

    # ── the packets ──

    def eapol(self):
        # 0x888E is the ether type nac_bypass.py forwards so the downstream
        # device stays authenticated; one frame of it is the whole evidence.
        return (Ether(src="aa:bb:cc:dd:ee:ff", dst="01:80:c2:00:00:03",
                      type=0x888E) / Raw(b"\x01\x01\x00\x00"))

    def http_request(self, method, host, target, body=b"", headers=(),
                     dport=80):
        lines = ["%s %s HTTP/1.1" % (method, target), "Host: %s" % host]
        lines.extend(headers)
        head = ("\r\n".join(lines) + "\r\n\r\n").encode()
        return _tcp(self.HOST, self.GATEWAY, 44444, dport, head + body)

    def http_response(self, status, headers=(), sport=80, body=b""):
        lines = ["HTTP/1.1 %d %s" % (status, "OK" if status == 200 else "Found")]
        lines.extend(headers)
        head = ("\r\n".join(lines) + "\r\n\r\n").encode()
        return _tcp(self.GATEWAY, self.HOST, sport, 44444, head + body)

    def dns_query(self, name, resolver):
        return (Ether() / IP(src=self.HOST, dst=resolver)
                / UDP(sport=55555, dport=53)
                / DNS(rd=1, qd=DNSQR(qname=name)))

    def dns_answer(self, name, resolver, address="93.184.216.34"):
        return (Ether() / IP(src=resolver, dst=self.HOST)
                / UDP(sport=53, dport=55555)
                / DNS(qr=1, qd=DNSQR(qname=name),
                      an=DNSRR(rrname=name, rdata=address)))

    def client_hello(self, sni):
        return _tcp(self.HOST, self.GATEWAY, 44445, 443,
                    _client_hello_bytes(sni))

    def server_hello(self):
        # A record of type 22 (handshake) from the server is all this needs:
        # the question is whether the handshake got an answer, not what the
        # answer said.
        return _tcp(self.GATEWAY, self.HOST, 443, 44445,
                    b"\x16\x03\x03\x00\x04\x02\x00\x00\x00")


def _client_hello_bytes(sni):
    """A TLS ClientHello record carrying exactly one server_name extension.

    Built by hand rather than with scapy's TLS layer: the scout parses the
    payload bytes itself (so that a truncated record is a packet ignored
    rather than an exception on the capture thread), and a test that built
    the record with a different library would be testing that library's
    agreement with this parser instead of the parser.
    """
    name = sni.encode()
    server_name = b"\x00" + len(name).to_bytes(2, "big") + name
    name_list = len(server_name).to_bytes(2, "big") + server_name
    extension = b"\x00\x00" + len(name_list).to_bytes(2, "big") + name_list
    extensions = len(extension).to_bytes(2, "big") + extension
    body = (b"\x03\x03" + b"\x00" * 32      # version, random
            + b"\x00"                        # no session id
            + b"\x00\x02\x13\x01"            # one cipher suite
            + b"\x01\x00"                    # one compression method
            + extensions)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


class TestTheTwoDeadFlags(EvidenceCase):
    """`dot1x_seen` and `portal_answered`, which nothing has ever set."""

    def test_an_eapol_frame_sets_dot1x_seen(self):
        self.assertFalse(self.evidence.dot1x_seen)
        self.evidence.observe(self.eapol())
        self.assertTrue(self.evidence.dot1x_seen)
        self.assertEqual(self.evidence.flags(), ["dot1x_seen"])

    def test_ordinary_traffic_does_not_set_dot1x_seen(self):
        self.evidence.observe(self.dns_query("example.com", "10.0.0.2"))
        self.assertFalse(self.evidence.dot1x_seen)
        self.assertEqual(self.evidence.flags(), [])

    def test_a_redirect_alone_does_not_set_portal_answered(self):
        # A redirect is a portal noticed, not a portal answered. The flag
        # says the host got *past* one, which is what makes it worth
        # borrowing; a rung that replayed an unanswered redirect would
        # spend an attempt on a login page.
        self.evidence.observe(self.http_response(
            302, ["Location: http://portal.lan/login"]))
        self.assertIsNone(self.evidence.portal)
        self.assertFalse(self.evidence.portal_answered)

    def test_a_redirect_then_an_answered_post_sets_portal_answered(self):
        self.evidence.observe(self.http_response(
            302, ["Location: http://portal.lan/login"]))
        self.evidence.observe(self.http_request(
            "POST", "portal.lan", "/login", body=b"user=guest&accept=1",
            headers=["Content-Type: application/x-www-form-urlencoded"]))
        self.evidence.observe(self.http_response(200))
        self.assertTrue(self.evidence.portal_answered)
        self.assertEqual(self.evidence.portal["url"],
                         "http://portal.lan/login")
        self.assertEqual(self.evidence.portal["body"], "user=guest&accept=1")
        self.assertEqual(self.evidence.portal["content_type"],
                         "application/x-www-form-urlencoded")
        self.assertEqual(self.evidence.flags(), ["portal_answered"])

    def test_a_post_to_somewhere_else_is_not_a_portal_answer(self):
        self.evidence.observe(self.http_response(
            302, ["Location: http://portal.lan/login"]))
        self.evidence.observe(self.http_request(
            "POST", "intranet.lan", "/search", body=b"q=1"))
        self.evidence.observe(self.http_response(200))
        self.assertFalse(self.evidence.portal_answered)
        self.assertIsNone(self.evidence.portal)

    def test_both_flags_are_reported_in_the_records_bit_order(self):
        # The order the operator reads them in dns_rescue.py, not
        # alphabetically: `_egress_check_flag`'s messages already make that
        # promise about the live flags.
        self.evidence.observe(self.http_response(
            302, ["Location: http://portal.lan/login"]))
        self.evidence.observe(self.http_request(
            "POST", "portal.lan", "/login", body=b"ok=1"))
        self.evidence.observe(self.http_response(200))
        self.evidence.observe(self.eapol())
        self.assertEqual(self.evidence.flags(),
                         ["dot1x_seen", "portal_answered"])


class TestTheHostsProxy(EvidenceCase):
    """What the host proves about getting out through a proxy."""

    def test_a_connect_request_records_the_proxy(self):
        self.evidence.observe(self.http_request(
            "CONNECT", "proxy.lan:3128", "intranet.lan:443", dport=3128))
        self.assertEqual(self.evidence.proxies, ["10.0.0.1:3128"])

    def test_the_same_proxy_twice_is_recorded_once(self):
        for _ in range(3):
            self.evidence.observe(self.http_request(
                "CONNECT", "proxy.lan:3128", "intranet.lan:443", dport=3128))
        self.assertEqual(self.evidence.proxies, ["10.0.0.1:3128"])

    def test_a_wpad_lookup_records_the_name_it_asked_for(self):
        self.evidence.observe(self.dns_query("wpad.corp.lan", "10.0.0.2"))
        self.evidence.observe(self.dns_answer("wpad.corp.lan", "10.0.0.2"))
        self.assertIn("wpad.corp.lan", self.evidence.wpad)

    def test_a_pac_fetch_records_its_url(self):
        self.evidence.observe(self.http_request(
            "GET", "wpad.corp.lan", "/wpad.dat"))
        self.assertIn("http://wpad.corp.lan/wpad.dat", self.evidence.pac)


class TestTheHostsResolver(EvidenceCase):
    """Which resolver the host uses, and whether it answers."""

    def test_an_answered_query_counts_its_resolver(self):
        self.evidence.observe(self.dns_query("example.com", "10.0.0.2"))
        self.evidence.observe(self.dns_answer("example.com", "10.0.0.2"))
        self.assertEqual(self.evidence.resolvers, {"10.0.0.2": 1})

    def test_an_unanswered_query_counts_nothing(self):
        # The question the rung needs answered is "does this resolver
        # answer", so a query with no reply is not evidence for it.
        self.evidence.observe(self.dns_query("example.com", "10.0.0.2"))
        self.assertEqual(self.evidence.resolvers, {})

    def test_a_response_with_no_answer_section_counts_nothing(self):
        empty = (Ether() / IP(src="10.0.0.2", dst=self.HOST)
                 / UDP(sport=53, dport=55555)
                 / DNS(qr=1, rcode=3, qd=DNSQR(qname="nope.lan")))
        self.evidence.observe(self.dns_query("nope.lan", "10.0.0.2"))
        self.evidence.observe(empty)
        self.assertEqual(self.evidence.resolvers, {})

    def test_two_resolvers_are_counted_apart(self):
        for resolver in ("10.0.0.2", "10.0.0.3", "10.0.0.2"):
            self.evidence.observe(self.dns_query("example.com", resolver))
            self.evidence.observe(self.dns_answer("example.com", resolver))
        self.assertEqual(self.evidence.resolvers,
                         {"10.0.0.2": 2, "10.0.0.3": 1})


class TestTheHostsWorkingTlsDestinations(EvidenceCase):
    """The target a louder rung aims at: somewhere the host proves works."""

    def test_a_handshake_that_completed_records_its_sni(self):
        self.evidence.observe(self.client_hello("updates.example.com"))
        self.assertEqual(self.evidence.tls_destinations, [])
        self.evidence.observe(self.server_hello())
        self.assertEqual(self.evidence.tls_destinations,
                         ["updates.example.com"])

    def test_a_client_hello_with_no_answer_records_nothing(self):
        # "The host proves this works" is the whole value of this line. A
        # ClientHello nobody answered proves the opposite.
        self.evidence.observe(self.client_hello("blocked.example.com"))
        self.assertEqual(self.evidence.tls_destinations, [])

    def test_a_truncated_client_hello_records_nothing_and_raises_nothing(self):
        raw = _client_hello_bytes("updates.example.com")
        for cut in (3, 6, 10, 44, len(raw) - 2):
            with self.subTest(cut=cut):
                fresh = evidence_mod.Evidence()
                fresh.observe(_tcp(self.HOST, self.GATEWAY, 1, 443, raw[:cut]))
                fresh.observe(self.server_hello())
                self.assertEqual(fresh.tls_destinations, [])


class TestTheCredentialsTheHostHandsOver(EvidenceCase):
    """Plaintext credentials on the wire, for the borrow rung."""

    def test_a_basic_proxy_authorization_header_is_recorded_decoded(self):
        self.evidence.observe(self.http_request(
            "CONNECT", "proxy.lan:3128", "intranet.lan:443", dport=3128,
            headers=["Proxy-Authorization: Basic Y29ycFxhbGljZTpzM2NyZXQ="]))
        self.assertEqual(len(self.evidence.credentials), 1)
        found = self.evidence.credentials[0]
        self.assertEqual(found["kind"], "proxy-basic")
        self.assertEqual(found["user"], "corp\\alice")
        self.assertEqual(found["secret"], "s3cret")
        self.assertEqual(found["where"], "10.0.0.1:3128")

    def test_an_ntlm_proxy_authorization_header_records_no_secret(self):
        # NTLM is a challenge-response, so the header carries no password
        # to borrow. Recorded as what it is, so the rung can decline with a
        # reason rather than select a credential with an empty secret.
        self.evidence.observe(self.http_request(
            "CONNECT", "proxy.lan:3128", "intranet.lan:443", dport=3128,
            headers=["Proxy-Authorization: NTLM TlRMTVNTUAAB"]))
        self.assertEqual([c["kind"] for c in self.evidence.credentials],
                         ["proxy-ntlm"])
        self.assertEqual(self.evidence.credentials[0]["secret"], "")

    def test_the_same_credential_twice_is_recorded_once(self):
        for _ in range(2):
            self.evidence.observe(self.http_request(
                "CONNECT", "proxy.lan:3128", "intranet.lan:443", dport=3128,
                headers=["Proxy-Authorization: Basic Y29ycFxhbGljZTpzM2NyZXQ="]))
        self.assertEqual(len(self.evidence.credentials), 1)

    def test_an_unreadable_basic_header_records_nothing(self):
        for value in ("Basic", "Basic !!!!", "Basic " + "A" * 5,
                      "Basic bm9jb2xvbg=="):
            with self.subTest(value=value):
                fresh = evidence_mod.Evidence()
                fresh.observe(self.http_request(
                    "CONNECT", "proxy.lan:3128", "a:443", dport=3128,
                    headers=["Proxy-Authorization: " + value]))
                self.assertEqual(fresh.credentials, [])


class TestTheHostsIdentity(EvidenceCase):
    """The MAC and IP rung 4 would take."""

    def test_the_first_host_side_sender_is_the_identity(self):
        self.evidence.observe(self.http_request("GET", "intranet.lan", "/"))
        self.assertEqual(self.evidence.host_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(self.evidence.host_ip, self.HOST)


class TestNothingObserveIsGivenMayRaise(EvidenceCase):
    """The contract, because this runs on a capture thread with no guard."""

    def test_every_shape_of_rubbish_leaves_the_evidence_untouched(self):
        before = self.evidence.as_document_fields()
        for packet in (None, object(), b"", b"\x00" * 7, Ether(),
                       Ether() / IP(src=self.HOST, dst=self.GATEWAY),
                       _tcp(self.HOST, self.GATEWAY, 1, 80, b"\xff\xfe\xfd"),
                       _tcp(self.HOST, self.GATEWAY, 1, 80, b"GET"),
                       (Ether() / IP(src=self.HOST, dst="10.0.0.2")
                        / UDP(sport=1, dport=53) / Raw(b"\x01")),
                       self.http_response(302)):
            with self.subTest(packet=repr(packet)[:40]):
                self.evidence.observe(packet)
        self.assertEqual(self.evidence.as_document_fields(), before)

    def test_a_packet_whose_layers_raise_is_ignored(self):
        class Hostile(object):
            def haslayer(self, _layer):
                raise RuntimeError("a layer that bites")

            def __getitem__(self, _layer):
                raise RuntimeError("a layer that bites")

        self.evidence.observe(Hostile())
        self.assertEqual(self.evidence.flags(), [])


class TestTheDocumentFields(EvidenceCase):
    """What Task 3 publishes: JSON-safe, and no secret in it."""

    def test_the_fields_are_json_safe_and_carry_no_secret(self):
        import json
        self.evidence.observe(self.eapol())
        self.evidence.observe(self.http_request(
            "CONNECT", "proxy.lan:3128", "a:443", dport=3128,
            headers=["Proxy-Authorization: Basic Y29ycFxhbGljZTpzM2NyZXQ="]))
        fields = self.evidence.as_document_fields()
        text = json.dumps(fields)
        # The credentials live in their own file, 0600, and never in the
        # document the beacon reads -- the document is the handoff, and a
        # handoff carrying passwords is a second place they can be found.
        self.assertNotIn("s3cret", text)
        self.assertEqual(fields["flags"], ["dot1x_seen"])
        self.assertEqual(fields["proxies"], ["10.0.0.1:3128"])
        self.assertEqual(fields["credentials"], 1)


class TestTheFilterIsTheTableAndNoMore(unittest.TestCase):
    """One BPF expression, narrow on purpose: a second reader on 13 W."""

    def test_the_filter_names_every_protocol_the_evidence_reads(self):
        for needle in ("0x888e", "port 53", "port 80", "port 443"):
            self.assertIn(needle, evidence_mod.BPF_FILTER)

    def test_the_filter_is_not_a_full_capture(self):
        self.assertNotEqual(evidence_mod.BPF_FILTER.strip(), "")


if __name__ == "__main__":
    unittest.main()
