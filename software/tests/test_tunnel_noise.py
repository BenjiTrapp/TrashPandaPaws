#!/usr/bin/env python3
"""
Unit tests for the tunnel's Noise layer in `software/c2/beacon.py`: X25519
key agreement, the Noise-flavoured HKDF, and the
`Noise_NKpsk0_25519_AESGCM_SHA256` handshake and transport state machine.

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

The arbiter for the state machine is the Cacophony vector for this exact
suite, copied in below. It has to be an outside arbiter: a Noise
implementation driven against itself agrees with itself even when it has
misread the pattern, so every self-interop test here would pass on a
transcript no other implementation could speak. The vector pins the bytes
instead.
"""

import unittest
from unittest import mock
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


# The same question for AES-256-GCM, which the Noise cipher state drives.
# A separate flag and a separate measurement: libcrypto 1.0.2 serves
# AES-256-GCM while exporting no raw-key API, so one backend can be the
# fast path while the other is not.
_IMPORT_PURE_AES = beacon_mod._USE_PURE_PYTHON_AES


@contextmanager
def _pure_aes_backend():
    """Force the pure-Python AES-256-GCM path."""
    original = beacon_mod._USE_PURE_PYTHON_AES
    beacon_mod._USE_PURE_PYTHON_AES = True
    try:
        yield
    finally:
        beacon_mod._USE_PURE_PYTHON_AES = original


@contextmanager
def _ctypes_aes_backend():
    """Force the OpenSSL AES-256-GCM path. Skips where it is unusable."""
    if _IMPORT_PURE_AES:
        raise unittest.SkipTest("no OpenSSL AES-256-GCM on this machine")
    original = beacon_mod._USE_PURE_PYTHON_AES
    beacon_mod._USE_PURE_PYTHON_AES = False
    try:
        yield
    finally:
        beacon_mod._USE_PURE_PYTHON_AES = original


def _available_aes_backends():
    """(name, context manager) for every AES backend this machine runs."""
    backends = [("pure", _pure_aes_backend())]
    if not _IMPORT_PURE_AES:
        backends.append(("openssl", _ctypes_aes_backend()))
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


# ── The Cacophony vector for Noise_NKpsk0_25519_AESGCM_SHA256 ──
#
# Copied from `vectors/cacophony.txt` in haskell-cryptography/cacophony,
# the entry whose `protocol_name` is exactly this suite. Cacophony is an
# independent Haskell implementation of the Noise Protocol Framework, and
# its corpus is the one the Noise wiki points implementers at. The vector
# fixes both ephemerals and a non-empty prologue, because the transcript
# is only reproducible if every input is pinned.
#
# This is the only Noise test here that can disagree with the
# specification. Every other Noise test below drives our initiator against
# our own responder, which proves the two halves agree with each other and
# nothing at all about whether they agree with the standard.

VECTOR_PROLOGUE = b"John Galt"
VECTOR_PSK = bytes.fromhex(
    "54686973206973206d7920417573747269616e20706572737065637469766521")
VECTOR_INIT_EPHEMERAL = bytes.fromhex(
    "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")
VECTOR_RESP_EPHEMERAL = bytes.fromhex(
    "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b")
VECTOR_RESP_STATIC = bytes.fromhex(
    "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893")
# The vector calls this `init_remote_static`: the public half of
# `resp_static`, which the NK pre-message says the initiator already has.
VECTOR_RESP_STATIC_PUBLIC = bytes.fromhex(
    "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62")
VECTOR_HANDSHAKE_HASH = bytes.fromhex(
    "c9855b6c52aeba6b7d07097d260e058ea90e85fa810c0c3e2ec3869f3f4319c9")

# The vector's first two messages are the handshake: message 1 from the
# initiator, message 2 from the responder, each carrying a payload.
VECTOR_ONE_PAYLOAD = b"Ludwig von Mises"
VECTOR_ONE_MESSAGE = bytes.fromhex(
    "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944"
    "052cffc8d5cdfaed3f9ca0a86c406cf58d24cfc3cec1af5060fd25c4e8a5ac04")
VECTOR_TWO_PAYLOAD = b"Murray Rothbard"
VECTOR_TWO_MESSAGE = bytes.fromhex(
    "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843"
    "afd57077a1747b71254c19bd798c87ac61a2d4808a30a1372f81b2cb4d85f6")

# The rest are transport messages, alternating with the initiator first.
VECTOR_TRANSPORT = (
    ("initiator", b"F. A. Hayek",
     bytes.fromhex("0ed5fabce6ef0ded315c4f213c51ea1e89be89f86c5dc98e50d15d")),
    ("responder", b"Carl Menger",
     bytes.fromhex("ba3cbc8800e6eb1b585269dca0f00fdc21f830eb1a497589215f7f")),
    ("initiator", b"Jean-Baptiste Say",
     bytes.fromhex("f1205cc05144bce5aad775bc12a7d569bfdd474337cdb03b09ae54"
                   "78c0cd166eb4")),
    ("responder", b"Eugen B\xf6hm von Bawerk",
     bytes.fromhex("32b8e77e5be275d093618c2a1fef8b6c4c263b23a39d25cce75101"
                   "5d44a7b4003aa4f66512")),
)


def _vector_sessions():
    """The vector's two sessions, with its ephemerals and prologue pinned."""
    initiator = beacon_mod.NoiseSession.initiator(
        VECTOR_RESP_STATIC_PUBLIC, VECTOR_PSK, prologue=VECTOR_PROLOGUE)
    initiator._fix_ephemeral(VECTOR_INIT_EPHEMERAL)
    responder = beacon_mod.NoiseSession.responder(
        VECTOR_RESP_STATIC, lambda: [VECTOR_PSK], prologue=VECTOR_PROLOGUE)
    responder._fix_ephemeral(VECTOR_RESP_EPHEMERAL)
    return initiator, responder


def _handshake_pair(psk=None, psk_lookup=None, payload=b"hello"):
    """A completed handshake over fresh keys.

    Returns (initiator, responder, the first message's payload): the shape
    every caller below needs, with the two PSK arguments left open so a
    test can give the two ends different material.
    """
    static_private, static_public = beacon_mod._x25519_keypair()
    if psk is None:
        psk = b"\x11" * 32
    if psk_lookup is None:
        psk_lookup = (lambda: [psk])
    initiator = beacon_mod.NoiseSession.initiator(static_public, psk)
    responder = beacon_mod.NoiseSession.responder(static_private, psk_lookup)
    first = responder.respond(initiator.initiate(payload))
    initiator.complete(responder.reply())
    return initiator, responder, first


class TestNoiseAgainstThePublishedVector(unittest.TestCase):
    """`Noise_NKpsk0_25519_AESGCM_SHA256` against the Cacophony corpus.

    Run under every AES backend this machine has, because the handshake
    is where the authenticated data matters: Noise uses the running
    handshake hash as the AAD of each handshake payload, so a backend that
    mishandles AAD would produce a transcript that still round-trips
    against itself.
    """

    def test_the_protocol_name_is_exactly_the_hash_length(self):
        # Noise's InitializeSymmetric pads a short protocol name with
        # zeroes and hashes a long one. This suite's name is 32 bytes --
        # exactly SHA256's output -- so `h` starts as the name verbatim and
        # neither branch is reachable. That is why the implementation
        # carries neither; a rename that broke the coincidence would make
        # it wrong, so the coincidence is pinned here.
        self.assertEqual(len(beacon_mod.NoiseSession.PROTOCOL_NAME), 32)
        self.assertEqual(beacon_mod.NoiseSession.PROTOCOL_NAME,
                         b"Noise_NKpsk0_25519_AESGCM_SHA256")

    def test_handshake_messages_match_the_published_vector(self):
        for name, backend in _available_aes_backends():
            with self.subTest(aes=name), backend:
                initiator, responder = _vector_sessions()
                message_one = initiator.initiate(VECTOR_ONE_PAYLOAD)
                self.assertEqual(message_one, VECTOR_ONE_MESSAGE)
                self.assertEqual(responder.respond(message_one),
                                 VECTOR_ONE_PAYLOAD)
                message_two = responder.reply(VECTOR_TWO_PAYLOAD)
                self.assertEqual(message_two, VECTOR_TWO_MESSAGE)
                initiator.complete(message_two)

    def test_handshake_hash_matches_the_published_vector(self):
        # The handshake hash covers the protocol name, the prologue, the
        # pre-message, both ephemerals and both handshake ciphertexts, so
        # agreeing on it means agreeing on the order every one of those
        # was mixed in.
        for name, backend in _available_aes_backends():
            with self.subTest(aes=name), backend:
                initiator, responder = _vector_sessions()
                responder.respond(initiator.initiate(VECTOR_ONE_PAYLOAD))
                initiator.complete(responder.reply(VECTOR_TWO_PAYLOAD))
                self.assertEqual(initiator.handshake_hash,
                                 VECTOR_HANDSHAKE_HASH)
                self.assertEqual(responder.handshake_hash,
                                 VECTOR_HANDSHAKE_HASH)

    def test_transport_messages_match_the_published_vector(self):
        # Four transport messages, alternating, which pins the split --
        # which of the two keys each end sends under -- and the nonce
        # encoding, since the third message from each end uses counter 1.
        for name, backend in _available_aes_backends():
            with self.subTest(aes=name), backend:
                initiator, responder = _vector_sessions()
                responder.respond(initiator.initiate(VECTOR_ONE_PAYLOAD))
                initiator.complete(responder.reply(VECTOR_TWO_PAYLOAD))
                for sender, payload, expected in VECTOR_TRANSPORT:
                    if sender == "initiator":
                        writer, reader = initiator, responder
                    else:
                        writer, reader = responder, initiator
                    message = writer.encrypt(payload)
                    self.assertEqual(message, expected,
                                     "%s transport message" % sender)
                    self.assertEqual(reader.decrypt(message), payload)


class TestNoiseSession(unittest.TestCase):
    """The state machine as the tunnel will drive it, over fresh keys."""

    def test_nkpsk0_handshake_completes_and_keys_match(self):
        initiator, responder, _ = _handshake_pair()
        self.assertEqual(initiator.handshake_hash, responder.handshake_hash)
        self.assertEqual(len(initiator.handshake_hash), 32)
        # Matching hashes are not matching keys: carry traffic each way.
        self.assertEqual(responder.decrypt(initiator.encrypt(b"up")), b"up")
        self.assertEqual(initiator.decrypt(responder.encrypt(b"down")),
                         b"down")
        # The two directions are separate keys with separate counters, so
        # the first message each way is distinct even for one plaintext.
        self.assertNotEqual(initiator.encrypt(b"same"),
                            responder.encrypt(b"same"))

    def test_first_message_carries_a_payload_the_responder_reads(self):
        # The discriminator the tunnel server dispatches on: whether this
        # connection is a command channel or a relay is inside the first
        # authenticated payload, so `respond` has to hand it back.
        _, _, first = _handshake_pair(payload=b'{"kind":1,"id":"abc"}')
        self.assertEqual(first, b'{"kind":1,"id":"abc"}')

    def test_wrong_psk_fails_the_handshake(self):
        static_private, static_public = beacon_mod._x25519_keypair()
        initiator = beacon_mod.NoiseSession.initiator(
            static_public, b"\x01" * 32)
        responder = beacon_mod.NoiseSession.responder(
            static_private, lambda: [b"\x02" * 32])
        secret = b"PAYLOAD-THAT-MUST-NOT-APPEAR"
        message = initiator.initiate(secret)
        with self.assertRaises(ValueError) as caught:
            responder.respond(message)
        # The refusal must not become a disclosure: no part of the
        # plaintext in the message, and no plaintext anywhere in the
        # message bytes, which would mean it was never encrypted at all.
        self.assertNotIn("PAYLOAD", str(caught.exception))
        self.assertNotIn(secret, message)
        # And the session is dead rather than half-open.
        with self.assertRaises(RuntimeError):
            responder.reply()
        with self.assertRaises(RuntimeError):
            responder.encrypt(b"anything")

    def test_responder_tries_several_psks_and_takes_the_matching_one(self):
        # A deployment holds one PSK per build, so the responder cannot
        # know which one a connection belongs to until it authenticates.
        psk = b"\x33" * 32
        calls = []

        def lookup():
            calls.append(1)
            return [b"\x44" * 32, psk, b"\x55" * 32]

        initiator, responder, first = _handshake_pair(
            psk=psk, psk_lookup=lookup, payload=b"third-in-the-list")
        self.assertEqual(first, b"third-in-the-list")
        # Which one matched is what the caller maps to a build identity.
        self.assertEqual(responder.psk, psk)
        self.assertEqual(initiator.psk, psk)
        # Asked once, and the candidate list is the whole bound on the work.
        self.assertEqual(len(calls), 1)
        self.assertEqual(responder.decrypt(initiator.encrypt(b"x")), b"x")

    def test_an_empty_psk_list_fails_the_handshake(self):
        # A responder with no PSKs registered has nothing to try. It must
        # say so rather than fall through to an unauthenticated session.
        static_private, static_public = beacon_mod._x25519_keypair()
        initiator = beacon_mod.NoiseSession.initiator(
            static_public, b"\x11" * 32)
        responder = beacon_mod.NoiseSession.responder(
            static_private, lambda: [])
        with self.assertRaises(ValueError):
            responder.respond(initiator.initiate(b"hello"))

    def test_first_message_is_indistinguishable_without_the_psk(self):
        # Everything about message 1 that an enumerator could fingerprint:
        # a constant byte at any offset is the `00 00` mistake the
        # original's infrastructure was mapped by. Same server key, same
        # PSK, same payload, so only the ephemeral differs -- and that
        # must be enough to vary every byte, which it is only if the
        # ephemeral is mixed into the key before the payload is sealed.
        static_private, static_public = beacon_mod._x25519_keypair()
        psk = b"\x66" * 32
        payload = b"HELLO"
        messages = [
            beacon_mod.NoiseSession.initiator(
                static_public, psk).initiate(payload)
            for _ in range(12)]
        lengths = set(len(m) for m in messages)
        # Length is the one thing the pattern does leak: 32 bytes of
        # ephemeral, the payload, and a 16-byte tag.
        self.assertEqual(lengths, {32 + len(payload) + 16})
        for offset in range(32 + len(payload) + 16):
            seen = set(m[offset] for m in messages)
            self.assertGreater(len(seen), 1,
                               "byte %d is the same in all 12 first "
                               "messages" % offset)
        self.assertEqual(len(set(messages)), len(messages))
        for message in messages:
            self.assertNotIn(payload, message)
        # Each of those is a real message, not noise: the responder that
        # holds the matching static key reads the last one.
        responder = beacon_mod.NoiseSession.responder(
            static_private, lambda: [psk])
        self.assertEqual(responder.respond(messages[-1]), payload)

    def test_transport_messages_are_sequenced(self):
        # Noise gives each direction a counter and no window, which is
        # what a stream wants: a frame that arrives early and a frame that
        # arrives twice are both the wrong counter, and both are refused.
        initiator, responder, _ = _handshake_pair()
        first = initiator.encrypt(b"one")
        second = initiator.encrypt(b"two")
        self.assertNotEqual(first, second)
        with self.assertRaises(ValueError):
            responder.decrypt(second)
        self.assertEqual(responder.decrypt(first), b"one")
        with self.assertRaises(ValueError):
            responder.decrypt(first)
        # None of those failures consumed the counter, so the stream can
        # still be read in order.
        self.assertEqual(responder.decrypt(second), b"two")

    def test_the_nonce_counter_refuses_to_wrap(self):
        # Noise forbids the 2**64-1 nonce outright: reusing a counter
        # under one key would destroy the cipher, so the session must stop
        # instead. Unreachable in practice at 64 bits, so it is driven
        # here rather than left as an unexercised branch.
        initiator, responder, _ = _handshake_pair()
        initiator._send._nonce = 2 ** 64 - 1
        with self.assertRaises(ValueError) as caught:
            initiator.encrypt(b"one too many")
        self.assertIn("nonce", str(caught.exception))
        responder._recv._nonce = 2 ** 64 - 1
        with self.assertRaises(ValueError) as caught:
            responder.decrypt(b"\x00" * 32)
        self.assertIn("nonce", str(caught.exception))

    def test_message_over_65535_is_refused_by_the_api(self):
        # A Noise transport message is at most 65535 bytes including the
        # 16-byte tag, so the plaintext ceiling is 65519. The refusal has
        # to happen here: the framing above this adds a `>H` prefix, and a
        # message that does not fit in it would be silently truncated.
        initiator, responder, _ = _handshake_pair()
        largest = b"A" * 65519
        sealed = initiator.encrypt(largest)
        self.assertEqual(len(sealed), 65535)
        self.assertEqual(responder.decrypt(sealed), largest)
        with self.assertRaises(ValueError) as caught:
            initiator.encrypt(b"A" * 65520)
        self.assertIn("65519", str(caught.exception))
        with self.assertRaises(ValueError):
            responder.decrypt(b"A" * 65536)

    def test_a_handshake_payload_that_cannot_fit_is_refused(self):
        # Message 1 spends 32 bytes on the ephemeral and 16 on the tag, so
        # its payload ceiling is lower than the transport one. Checked
        # separately because the overhead differs, not because the rule
        # does.
        _, static_public = beacon_mod._x25519_keypair()
        initiator = beacon_mod.NoiseSession.initiator(
            static_public, b"\x77" * 32)
        with self.assertRaises(ValueError):
            initiator.initiate(b"A" * (65535 - 32 - 16 + 1))

    def test_decrypt_of_a_tampered_frame_raises(self):
        initiator, responder, _ = _handshake_pair()
        sealed = initiator.encrypt(b"carry me")
        for offset in (0, len(sealed) // 2, len(sealed) - 1):
            tampered = bytearray(sealed)
            tampered[offset] ^= 0x01
            with self.assertRaises(ValueError):
                responder.decrypt(bytes(tampered))
        # A truncated frame is refused too, and none of those failures
        # moved the counter: the honest frame still reads.
        with self.assertRaises(ValueError):
            responder.decrypt(sealed[:-1])
        self.assertEqual(responder.decrypt(sealed), b"carry me")

    def test_a_tampered_handshake_message_raises(self):
        static_private, static_public = beacon_mod._x25519_keypair()
        psk = b"\x88" * 32
        message = bytearray(beacon_mod.NoiseSession.initiator(
            static_public, psk).initiate(b"hello"))
        # Offset 0 is inside the ephemeral public key, which the pattern
        # sends in clear. Changing it changes both the hash and the shared
        # secret, so the clear part of the message is authenticated too:
        # there is no part of message 1 an attacker can edit in flight.
        message[0] ^= 0x01
        responder = beacon_mod.NoiseSession.responder(
            static_private, lambda: [psk])
        with self.assertRaises(ValueError):
            responder.respond(bytes(message))

    def test_a_truncated_handshake_message_raises(self):
        static_private, _ = beacon_mod._x25519_keypair()
        responder = beacon_mod.NoiseSession.responder(
            static_private, lambda: [b"\x99" * 32])
        for length in (0, 31, 32, 47):
            with self.assertRaises(ValueError):
                responder.respond(b"\x00" * length)

    def test_calls_out_of_order_are_refused(self):
        # Worth a guard rather than left to fail obscurely: Noise's cipher
        # state returns the plaintext unchanged when it holds no key, so a
        # transport call before the split is the one sequencing mistake
        # that would quietly put cleartext on the wire. One keypair
        # throughout, so the only thing being refused here is the order.
        static_private, static_public = beacon_mod._x25519_keypair()
        initiator = beacon_mod.NoiseSession.initiator(
            static_public, b"\xaa" * 32)
        responder = beacon_mod.NoiseSession.responder(
            static_private, lambda: [b"\xaa" * 32])
        for session in (initiator, responder):
            with self.assertRaises(RuntimeError):
                session.encrypt(b"too early")
            with self.assertRaises(RuntimeError):
                session.decrypt(b"too early")
        # Each role refuses the other's messages, and refuses to repeat
        # its own.
        with self.assertRaises(RuntimeError):
            initiator.respond(b"\x00" * 48)
        with self.assertRaises(RuntimeError):
            responder.initiate(b"")
        with self.assertRaises(RuntimeError):
            responder.reply()
        with self.assertRaises(RuntimeError):
            initiator.complete(b"\x00" * 48)
        message = initiator.initiate(b"hello")
        with self.assertRaises(RuntimeError):
            initiator.initiate(b"again")
        responder.respond(message)
        with self.assertRaises(RuntimeError):
            responder.respond(message)
        initiator.complete(responder.reply())
        with self.assertRaises(RuntimeError):
            responder.reply()

    def test_a_psk_that_is_not_32_bytes_is_refused(self):
        # Noise defines the PSK as 32 bytes. HKDF would accept any length
        # and the handshake would complete, so a short key would look like
        # it worked -- which is the worst possible outcome for a secret.
        _, static_public = beacon_mod._x25519_keypair()
        for psk in (b"", b"\x01" * 31, b"\x01" * 33):
            with self.assertRaises(ValueError):
                beacon_mod.NoiseSession.initiator(static_public, psk)
        static_private, static_public = beacon_mod._x25519_keypair()
        initiator = beacon_mod.NoiseSession.initiator(
            static_public, b"\x01" * 32)
        responder = beacon_mod.NoiseSession.responder(
            static_private, lambda: [b"\x01" * 31])
        with self.assertRaises(ValueError):
            responder.respond(initiator.initiate(b"hello"))

    def test_a_static_key_that_is_not_32_bytes_is_refused(self):
        with self.assertRaises(ValueError):
            beacon_mod.NoiseSession.initiator(b"\x01" * 31, b"\x02" * 32)
        with self.assertRaises(ValueError):
            beacon_mod.NoiseSession.responder(b"\x01" * 33,
                                              lambda: [b"\x02" * 32])


class TestFindingLibcryptoOnPosix(unittest.TestCase):
    """`_load_libcrypto` has to resolve the library a POSIX host actually has.

    `ctypes.util.find_library` adds the `lib` prefix itself: the name of
    libcrypto on Linux is `crypto`, and `find_library("libcrypto")` looks
    for `liblibcrypto.so`. A candidate list of Windows file stems
    therefore cannot resolve anything on the platform this project
    deploys to -- measured on Debian 13 with the system interpreter,
    `libcrypto.so.3` sat in `/usr/lib/<triplet>/` while
    `_load_libcrypto()` returned None, so the tunnel refused to start on
    its own target.

    The resolver is faked rather than probed, so the test says the same
    thing on every host: the loader is handed a resolver that knows only
    the POSIX stem, and has to come back with a library.
    """

    def test_the_loader_resolves_the_bare_posix_stem(self):
        handle = object()
        asked = []

        def only_the_posix_stem(name):
            asked.append(name)
            return "/usr/lib/libcrypto.so.3" if name == "crypto" else None

        with mock.patch.object(beacon_mod.platform, "system",
                               return_value="Linux"), \
                mock.patch("ctypes.util.find_library",
                           side_effect=only_the_posix_stem), \
                mock.patch("ctypes.CDLL", return_value=handle), \
                mock.patch("os.listdir", return_value=[]):
            loaded = beacon_mod._load_libcrypto()

        self.assertIs(loaded, handle,
                      "the loader asked for %s and gave up; a POSIX host "
                      "names this library 'crypto'" % (asked,))
        self.assertIn("crypto", asked)


if __name__ == "__main__":
    unittest.main()
