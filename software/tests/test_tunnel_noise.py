#!/usr/bin/env python3
"""
Unit tests for the tunnel's Noise primitives in `software/c2/beacon.py`:
X25519 key agreement and the Noise-flavoured HKDF.

Both primitives have two backends, as AES-256-GCM in the same module
already does -- OpenSSL through ctypes where libcrypto loads, and a pure
Python fallback where it does not (macOS Library Validation). A
cryptographic fallback that quietly disagrees with the fast path is worse
than no fallback, so every vector here is run against the pure code
explicitly and, where libcrypto is present, against both.

The arbiter for X25519 is the RFC 7748 §5.2 test vector. The arbiter for
HKDF is RFC 5869 test case 1, adapted to Noise's calling convention: the
chaining key is the salt and there is no `info`, so the expected outputs
are chained from the PRK the RFC publishes for that case.
"""

import unittest
from contextlib import contextmanager

from software.c2 import beacon as beacon_mod

# RFC 7748 §5.2, the first X25519 test vector.
RFC7748_SCALAR = bytes.fromhex(
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
RFC7748_U = bytes.fromhex(
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
RFC7748_OUT = bytes.fromhex(
    "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")

# RFC 5869 test case 1 inputs, and the PRK the RFC publishes for them.
RFC5869_IKM = bytes.fromhex("0b" * 22)
RFC5869_SALT = bytes.fromhex("000102030405060708090a0b0c")
RFC5869_PRK = bytes.fromhex(
    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")

# HMAC-SHA256(PRK, 0x01), then (output_1 || 0x02) and (output_2 || 0x03):
# RFC 5869's expansion chain with an empty `info`, which is what Noise
# §4.3 specifies. Chained from the published PRK above, so these literals
# depend on the RFC and not on the module under test.
NOISE_OUT_1 = bytes.fromhex(
    "b2a3d45126d31fb6828ef00d76c6d54e9c2bd4785e49c6ad86e327d89d0de940")
NOISE_OUT_2 = bytes.fromhex(
    "8eeda1cbef2b03f30e053d5be784c2ab37f5a4de412baa10f01f456e9772aae7")
NOISE_OUT_3 = bytes.fromhex(
    "5734f7dda6560fdac61bc17a37fe5a0394aa9d554fa28df55a05db4da8f42c08")


@contextmanager
def _pure_backend():
    """Force the pure-Python X25519 path, whatever this machine loaded."""
    original = beacon_mod._USE_PURE_PYTHON_X25519
    beacon_mod._USE_PURE_PYTHON_X25519 = True
    try:
        yield
    finally:
        beacon_mod._USE_PURE_PYTHON_X25519 = original


@contextmanager
def _ctypes_backend():
    """Force the OpenSSL X25519 path. Skips when libcrypto did not load."""
    if beacon_mod._crypto is None:
        raise unittest.SkipTest("libcrypto unavailable on this machine")
    original = beacon_mod._USE_PURE_PYTHON_X25519
    beacon_mod._USE_PURE_PYTHON_X25519 = False
    try:
        yield
    finally:
        beacon_mod._USE_PURE_PYTHON_X25519 = original


class TestX25519(unittest.TestCase):
    """X25519 key agreement, both backends."""

    def test_x25519_rfc7748_vector(self):
        # A Montgomery ladder that is subtly wrong still returns 32
        # plausible bytes, so the published vector is the only check that
        # means anything -- and it has to hold for whichever backend the
        # target machine ends up using.
        with _pure_backend():
            self.assertEqual(beacon_mod._x25519(RFC7748_SCALAR, RFC7748_U),
                             RFC7748_OUT)
        if beacon_mod._crypto is not None:
            with _ctypes_backend():
                self.assertEqual(
                    beacon_mod._x25519(RFC7748_SCALAR, RFC7748_U),
                    RFC7748_OUT)

    def test_x25519_pure_matches_ctypes(self):
        # The two backends have to agree on traffic neither of them has
        # seen before, not just on the one vector: a handshake where the
        # two ends picked different backends must still converge.
        with _ctypes_backend():
            private, public = beacon_mod._x25519_keypair()
            peer_private, peer_public = beacon_mod._x25519_keypair()
            via_ctypes = beacon_mod._x25519(private, peer_public)
            peer_via_ctypes = beacon_mod._x25519(peer_private, public)
        with _pure_backend():
            via_pure = beacon_mod._x25519(private, peer_public)
            peer_via_pure = beacon_mod._x25519(peer_private, public)
        self.assertEqual(via_pure, via_ctypes)
        self.assertEqual(peer_via_pure, peer_via_ctypes)
        self.assertEqual(via_pure, peer_via_pure)

    def test_x25519_round_trip_shared_secret(self):
        # Diffie-Hellman's whole point: a*B == b*A over keys nobody chose
        # in advance. Run on the pure backend so it holds everywhere.
        with _pure_backend():
            a_private, a_public = beacon_mod._x25519_keypair()
            b_private, b_public = beacon_mod._x25519_keypair()
            self.assertEqual(len(a_private), 32)
            self.assertEqual(len(a_public), 32)
            self.assertNotEqual(a_private, b_private)
            shared_a = beacon_mod._x25519(a_private, b_public)
            shared_b = beacon_mod._x25519(b_private, a_public)
        self.assertEqual(shared_a, shared_b)
        self.assertEqual(len(shared_a), 32)
        self.assertNotEqual(shared_a, b"\x00" * 32)

    def test_x25519_rejects_wrong_length(self):
        # A 31- or 33-byte key is a framing bug upstream. The pure ladder
        # would silently reinterpret it and return a shared secret the
        # other end cannot reach, so both backends refuse it instead.
        backends = [_pure_backend()]
        if beacon_mod._crypto is not None:
            backends.append(_ctypes_backend())
        for backend in backends:
            with backend:
                for length in (31, 33):
                    with self.assertRaises(ValueError):
                        beacon_mod._x25519(b"\x01" * length, RFC7748_U)
                    with self.assertRaises(ValueError):
                        beacon_mod._x25519(RFC7748_SCALAR, b"\x01" * length)


class TestHkdf(unittest.TestCase):
    """The Noise §4.3 HKDF, which the handshake calls with 2 and with 3."""

    def test_hkdf_rfc5869_case_1(self):
        two = beacon_mod._hkdf(RFC5869_SALT, RFC5869_IKM, 2)
        self.assertEqual(len(two), 2)
        self.assertEqual(two, (NOISE_OUT_1, NOISE_OUT_2))

        three = beacon_mod._hkdf(RFC5869_SALT, RFC5869_IKM, 3)
        self.assertEqual(len(three), 3)
        self.assertEqual(three, (NOISE_OUT_1, NOISE_OUT_2, NOISE_OUT_3))

        # The third output is an extension of the same chain, so asking
        # for three must not change the first two.
        self.assertEqual(three[:2], two)
        # Noise derives the PRK by keying HMAC with the chaining key,
        # which is RFC 5869's salt -- this is the vector that pins which
        # argument is the key.
        self.assertNotEqual(beacon_mod._hkdf(RFC5869_IKM, RFC5869_SALT, 2),
                            two)
        for output in three:
            self.assertEqual(len(output), 32)


if __name__ == "__main__":
    unittest.main()
