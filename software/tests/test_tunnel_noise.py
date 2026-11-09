#!/usr/bin/env python3
"""
Unit tests for the tunnel's Noise primitives in `software/c2/beacon.py`:
X25519 key agreement and the Noise-flavoured HKDF.

Both primitives have two backends, as AES-256-GCM in the same module
already does -- OpenSSL through ctypes where libcrypto offers the EVP
raw-key API, and a pure Python fallback where it does not (macOS Library
Validation denying libcrypto entirely, or an OpenSSL older than 1.1.1). A
cryptographic fallback that quietly disagrees with the fast path is worse
than no fallback, so every vector here is run against the pure code
explicitly and, where the OpenSSL path is usable, against both.

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

# Low-order points on Curve25519: u = 0, and u = 1 which has order 4. Both
# yield an all-zero shared secret for every scalar, so a peer that sends
# one knows the secret before we derive it.
LOW_ORDER_U = (b"\x00" * 32, b"\x01" + b"\x00" * 31)

# Whether the module chose the pure backend when it was imported, which is
# the only honest way to ask whether the OpenSSL path is usable here. Not
# `_crypto is None`: libcrypto 1.0.2 loads and serves AES-256-GCM while
# exporting no EVP_PKEY_new_raw_private_key, so the module falls back to
# pure with a perfectly non-None handle. Gating on the handle would force
# the ctypes path on such a host and error on the missing symbol instead
# of skipping. Snapshotted because the context managers below assign to
# the live flag.
_IMPORT_PURE = beacon_mod._USE_PURE_PYTHON_X25519


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
    """Force the OpenSSL X25519 path. Skips where that path is unusable."""
    if _IMPORT_PURE:
        raise unittest.SkipTest(
            "no OpenSSL X25519 on this machine: libcrypto is absent or "
            "predates the EVP_PKEY raw-key API")
    original = beacon_mod._USE_PURE_PYTHON_X25519
    beacon_mod._USE_PURE_PYTHON_X25519 = False
    try:
        yield
    finally:
        beacon_mod._USE_PURE_PYTHON_X25519 = original


def _available_backends():
    """Every backend this machine can actually run, as context managers.

    The pure path is always one of them; the OpenSSL path joins it only
    where the module would have used it. A vector that has to hold on both
    is run through all of these.
    """
    backends = [_pure_backend()]
    if not _IMPORT_PURE:
        backends.append(_ctypes_backend())
    return backends


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
        if not _IMPORT_PURE:
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
        for backend in _available_backends():
            with backend:
                for length in (31, 33):
                    with self.assertRaises(ValueError):
                        beacon_mod._x25519(b"\x01" * length, RFC7748_U)
                    with self.assertRaises(ValueError):
                        beacon_mod._x25519(RFC7748_SCALAR, b"\x01" * length)

    def test_x25519_rejects_low_order_peer_key(self):
        # A peer public key of low order drives the shared secret to all
        # zeroes for any scalar, so whoever sent it knows the secret we
        # are about to key the tunnel with. OpenSSL refuses to derive one;
        # the pure ladder would happily return the zeroes, so it refuses
        # too. Both backends are held to that here, because the value of
        # the check is precisely that they agree -- a fallback that
        # accepts what the fast path rejects is the gap being closed.
        for backend in _available_backends():
            with backend:
                for peer_public in LOW_ORDER_U:
                    with self.assertRaises(ValueError):
                        beacon_mod._x25519(RFC7748_SCALAR, peer_public)
                # The scalar is fine and an honest peer key still works,
                # so the rejection is about the peer key and not a blanket
                # failure of the backend under test.
                self.assertEqual(
                    beacon_mod._x25519(RFC7748_SCALAR, RFC7748_U),
                    RFC7748_OUT)


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

    def test_hkdf_rejects_other_output_counts(self):
        # Noise defines two and three outputs and nothing else, and this
        # implementation narrows the contract to exactly those. That
        # narrowing is a decision, so it is recorded here rather than left
        # as an untested branch in a function the handshake depends on: a
        # caller that one day needs one output fails a test here instead
        # of raising inside a delivered beacon.
        for num_outputs in (1, 4):
            with self.assertRaises(ValueError):
                beacon_mod._hkdf(RFC5869_SALT, RFC5869_IKM, num_outputs)


if __name__ == "__main__":
    unittest.main()
