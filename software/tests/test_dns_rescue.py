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


if __name__ == "__main__":
    unittest.main()
