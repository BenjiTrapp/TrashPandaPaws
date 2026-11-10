#!/usr/bin/env python3
"""
Unit tests for the tunnel's wire format: the `>H` length-prefixed framing,
the typed command-message codec, and the SOCKS5 request/reply codec.

Everything here is imported through `software.c2.tunnel.protocol`, which is
the name the server side uses, even though the implementation lives in
`software/c2/beacon.py` because that is the only file the generator
delivers to a target. Importing through the re-export means these tests
prove the re-export as well as the code behind it.

Two things these tests are careful about.

**The arbiter for the SOCKS bytes is RFC 1928, not this code.** The
protocol we derive from spoke a SOCKS5 dialect with the version bytes
stripped, the ports little-endian and the status codes inverted, and the
whole point of this layer is that ours does none of that. So the byte
offsets and the literal values below are written out from the RFC rather
than read back from the encoder: a test that only checks that the decoder
undoes the encoder would pass just as happily on the dialect we are
deliberately not speaking.

**The short-read tests drive a real socket pair.** A `recv` loop that
happens to return early is indistinguishable from one that correctly
detects a short read, right up until it blocks in production, so the peer
here is a real socket that a real thread closes mid-frame. Every socket
these tests read from carries a timeout, which turns "blocks forever" into
a failure with a legible message instead of a hung suite.
"""

import json
import socket
import struct
import threading
import time
import unittest
from contextlib import contextmanager

from software.c2 import beacon as beacon_mod
from software.c2.beacon import NoiseSession
from software.c2.tunnel import protocol

# Long enough that a stall is unambiguous, short enough that a hung test
# does not hold the suite up for minutes.
_TIMEOUT = 5.0

# 8080 big-endian. Little-endian it would be b"\x90\x1f", which decodes to
# 0x901f = 36895 -- the inherited trait, and a number nothing listens on.
_PORT = 0x1F90
_PORT_BE = b"\x1f\x90"


@contextmanager
def _socket_pair():
    """A connected pair, both ends on a timeout so a stall is a failure."""
    left, right = socket.socketpair()
    left.settimeout(_TIMEOUT)
    right.settimeout(_TIMEOUT)
    try:
        yield left, right
    finally:
        left.close()
        right.close()


@contextmanager
def _writing(sock, payload):
    """`write_frame` on a thread, so a payload larger than the socket
    buffer does not deadlock against a reader in this one.
    """
    failure = []

    def run():
        try:
            protocol.write_frame(sock, payload)
        except BaseException as exc:          # reported, never swallowed
            failure.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    try:
        yield
    finally:
        thread.join(_TIMEOUT)
        if thread.is_alive():
            raise AssertionError("write_frame did not return")
        if failure:
            raise failure[0]


def _recv_exactly(sock, count):
    """Read `count` bytes without using the reader under test."""
    got = b""
    while len(got) < count:
        chunk = sock.recv(count - len(got))
        if not chunk:
            raise AssertionError("the peer closed after %d of %d bytes"
                                 % (len(got), count))
        got += chunk
    return got


def _handshaken_pair():
    """An initiator and a responder past the handshake, keyed alike."""
    psk = bytes(range(32))
    static_private, static_public = beacon_mod._x25519_keypair()
    initiator = NoiseSession.initiator(static_public, psk)
    responder = NoiseSession.responder(static_private, lambda: [psk])
    responder.respond(initiator.initiate(b"hello"))
    initiator.complete(responder.reply())
    return initiator, responder


class TestFraming(unittest.TestCase):

    def test_frame_round_trip_over_a_socket_pair(self):
        for size in (1, 2, 47, 1500, protocol.MAX_FRAME_LEN):
            with self.subTest(size=size):
                payload = bytes(range(256)) * (size // 256) + bytes(
                    range(size % 256))
                self.assertEqual(len(payload), size)
                with _socket_pair() as (left, right):
                    with _writing(left, payload):
                        self.assertEqual(protocol.read_frame(right), payload)

    def test_the_length_prefix_is_two_bytes_big_endian(self):
        # 258 bytes is b"\x01\x02" big-endian and b"\x02\x01" little, so
        # this one length tells the two apart without ambiguity. Read off
        # the wire directly rather than through `read_frame`, which would
        # be the decoder vouching for the encoder.
        with _socket_pair() as (left, right):
            with _writing(left, b"x" * 258):
                frame = _recv_exactly(right, 2 + 258)
        self.assertEqual(frame[:2], b"\x01\x02")
        self.assertEqual(struct.unpack(">H", frame[:2])[0], 258)
        self.assertEqual(frame[2:], b"x" * 258)

    def test_a_frame_split_across_several_reads_is_reassembled(self):
        """The recv loop must keep reading until the frame is whole."""
        payload = b"a" * 300
        with _socket_pair() as (left, right):
            def dribble():
                # The pauses are what make the split real: without them
                # the kernel coalesces the writes and the reader gets the
                # whole frame in one recv, which proves nothing.
                for piece in (struct.pack(">H", len(payload)), payload[:7],
                              payload[7:120], payload[120:]):
                    left.sendall(piece)
                    time.sleep(0.02)

            thread = threading.Thread(target=dribble)
            thread.start()
            try:
                self.assertEqual(protocol.read_frame(right), payload)
            finally:
                thread.join(_TIMEOUT)

    def test_frame_longer_than_max_payload_is_refused_before_the_socket(self):
        """A frame's payload is one Noise message, so its ceiling is
        `MAX_FRAME_LEN` (65535) and not `MAX_PAYLOAD_LEN` (65519) -- the
        latter is the plaintext that goes *inside* one, and the 16-byte
        difference between them is the GCM tag.
        """
        over = b"\x00" * (protocol.MAX_FRAME_LEN + 1)
        with _socket_pair() as (left, right):
            with self.assertRaises(ValueError) as caught:
                protocol.write_frame(left, over)
            self.assertIn("65536", str(caught.exception))
            # Nothing at all reached the wire: a non-blocking peer with an
            # empty receive buffer raises rather than returning bytes.
            right.setblocking(False)
            with self.assertRaises(BlockingIOError):
                right.recv(1)

    def test_an_empty_frame_is_refused_at_both_ends(self):
        """A zero-length frame is the two bytes `00 00` on the wire, which
        is the inherited keep-alive that got the original's infrastructure
        enumerated. Neither end will produce or accept one.
        """
        with _socket_pair() as (left, right):
            with self.assertRaises(ValueError):
                protocol.write_frame(left, b"")
            left.sendall(b"\x00\x00")
            with self.assertRaises(ValueError):
                protocol.read_frame(right)

    def test_truncated_frame_raises_rather_than_blocking_forever(self):
        # A prefix promising 100 bytes, 10 bytes of body, then FIN.
        with _socket_pair() as (left, right):
            left.sendall(struct.pack(">H", 100) + b"z" * 10)
            left.shutdown(socket.SHUT_WR)
            with self.assertRaises(ValueError) as caught:
                protocol.read_frame(right)
            self.assertIn("10 of 100", str(caught.exception))

    def test_a_truncated_length_prefix_raises(self):
        with _socket_pair() as (left, right):
            left.sendall(b"\x01")
            left.shutdown(socket.SHUT_WR)
            with self.assertRaises(ValueError) as caught:
                protocol.read_frame(right)
            self.assertIn("1 of 2", str(caught.exception))

    def test_a_peer_that_closes_before_sending_anything_raises(self):
        with _socket_pair() as (left, right):
            left.shutdown(socket.SHUT_WR)
            with self.assertRaises(ValueError):
                protocol.read_frame(right)

    def test_the_frame_ceiling_is_the_noise_message_ceiling(self):
        """One number, not two: the `>H` prefix can express exactly the
        largest message Noise will emit, so a frame that fits the prefix
        always fits the cipher and there is no third limit to keep aligned.
        """
        self.assertEqual(protocol.MAX_FRAME_LEN,
                         NoiseSession.MAX_MESSAGE_LEN)
        self.assertEqual(protocol.MAX_FRAME_LEN, 0xFFFF)
        self.assertEqual(protocol.MAX_PAYLOAD_LEN,
                         NoiseSession.MAX_PAYLOAD_LEN)
        self.assertEqual(protocol.MAX_PAYLOAD_LEN, 65519)

    def test_frames_carry_noise_messages_end_to_end(self):
        """The layers fit: what `encrypt` emits is what a frame takes."""
        initiator, responder = _handshaken_pair()
        with _socket_pair() as (left, right):
            sent = protocol.encode_message(protocol.MSG_PING, {"seq": 1})
            with _writing(left, initiator.encrypt(sent)):
                got = responder.decrypt(protocol.read_frame(right))
            self.assertEqual(protocol.decode_message(got),
                             (protocol.MSG_PING, {"seq": 1}))


class TestMessageCodec(unittest.TestCase):

    BODIES = {
        protocol.MSG_HELLO: {"identity": "abc123", "host": "WS-01",
                             "os": "Windows"},
        protocol.MSG_RELAY: {"token": "00" * 32},
        protocol.MSG_OPEN_RELAY: {"token": "11" * 32},
        protocol.MSG_PING: {"seq": 7},
        protocol.MSG_PONG: {"seq": 7},
        protocol.MSG_CLOSE: {"reason": "operator stopped the tunnel"},
    }

    def test_message_round_trip_for_every_kind(self):
        self.assertEqual(sorted(self.BODIES), sorted(protocol.MESSAGE_KINDS))
        for kind, body in self.BODIES.items():
            with self.subTest(kind=protocol.MESSAGE_KIND_NAMES[kind]):
                raw = protocol.encode_message(kind, body)
                self.assertEqual(raw[0], kind)
                self.assertEqual(protocol.decode_message(raw), (kind, body))

    def test_the_six_kinds_have_the_numbers_the_protocol_fixes(self):
        self.assertEqual(
            (protocol.MSG_HELLO, protocol.MSG_RELAY, protocol.MSG_OPEN_RELAY,
             protocol.MSG_PING, protocol.MSG_PONG, protocol.MSG_CLOSE),
            (1, 2, 3, 4, 5, 6))

    def test_unknown_message_kind_raises(self):
        for kind in (0, 7, 255):
            with self.subTest(kind=kind):
                with self.assertRaises(ValueError):
                    protocol.encode_message(kind, {})
                with self.assertRaises(ValueError):
                    protocol.decode_message(bytes([kind]) + b"{}")

    def test_a_kind_that_does_not_fit_in_a_byte_raises(self):
        for kind in (-1, 256):
            with self.subTest(kind=kind):
                with self.assertRaises(ValueError):
                    protocol.encode_message(kind, {})

    def test_bodies_are_compact_json(self):
        raw = protocol.encode_message(protocol.MSG_HELLO,
                                      {"b": 2, "a": [1, {"c": 3}]})
        text = raw[1:].decode("utf-8")
        self.assertNotIn(" ", text)
        self.assertEqual(json.loads(text), {"a": [1, {"c": 3}], "b": 2})
        # Sorted keys, so the same body always encodes to the same bytes
        # and a capture of our own rig diffs cleanly.
        self.assertTrue(text.startswith('{"a"'))

    def test_an_empty_body_is_valid(self):
        raw = protocol.encode_message(protocol.MSG_PONG, {})
        self.assertEqual(raw, bytes([protocol.MSG_PONG]) + b"{}")
        self.assertEqual(protocol.decode_message(raw),
                         (protocol.MSG_PONG, {}))

    def test_a_body_that_is_not_a_mapping_raises(self):
        for body in ([], "hello", 7, None):
            with self.subTest(body=body):
                with self.assertRaises(ValueError):
                    protocol.encode_message(protocol.MSG_PING, body)

    def test_a_body_that_is_not_json_raises(self):
        for tail in (b"", b"not json", b"[1,2]", b'{"a":1', b"\xff\xfe"):
            with self.subTest(tail=tail):
                with self.assertRaises(ValueError):
                    protocol.decode_message(
                        bytes([protocol.MSG_PING]) + tail)

    def test_an_empty_message_raises(self):
        with self.assertRaises(ValueError):
            protocol.decode_message(b"")

    def test_a_body_too_large_for_one_noise_message_is_refused(self):
        """Caught by the encoder, where the error can name the field, and
        not by `encrypt`, where it is a length and nothing more.
        """
        with self.assertRaises(ValueError) as caught:
            protocol.encode_message(protocol.MSG_HELLO,
                                    {"host": "x" * protocol.MAX_PAYLOAD_LEN})
        self.assertIn(str(protocol.MAX_PAYLOAD_LEN), str(caught.exception))

    def test_a_body_that_json_cannot_represent_raises(self):
        with self.assertRaises(ValueError):
            protocol.encode_message(protocol.MSG_HELLO, {"when": object()})


class TestSocksRequestCodec(unittest.TestCase):

    def test_socks_request_round_trip_ipv4_ipv6_and_domain(self):
        cases = (
            (protocol.ATYP_IPV4, "192.0.2.10", b"\xc0\x00\x02\x0a"),
            (protocol.ATYP_IPV6, "2001:db8::1",
             bytes.fromhex("20010db8000000000000000000000001")),
            (protocol.ATYP_DOMAIN, "intranet.example.test",
             b"\x15intranet.example.test"),
        )
        for atyp, address, on_the_wire in cases:
            with self.subTest(atyp=atyp):
                raw = protocol.encode_socks_request(
                    protocol.CMD_CONNECT, atyp, address, _PORT)
                # RFC 1928: VER CMD RSV ATYP, then the address, then the
                # port. Spelled out rather than taken from the decoder.
                self.assertEqual(
                    raw,
                    bytes([5, protocol.CMD_CONNECT, 0, atyp])
                    + on_the_wire + _PORT_BE)
                self.assertEqual(protocol.decode_socks_request(raw),
                                 (protocol.CMD_CONNECT, atyp, address, _PORT))

    def test_ipv6_is_supported_rather_than_refused(self):
        """The original refuses ATYP=4. We write both ends, so that
        refusal is a bug we do not reproduce.
        """
        raw = protocol.encode_socks_request(
            protocol.CMD_CONNECT, protocol.ATYP_IPV6, "::1", 443)
        self.assertEqual(len(raw), 4 + 16 + 2)
        self.assertEqual(protocol.decode_socks_request(raw)[2], "::1")

    def test_socks_ports_are_big_endian(self):
        raw = protocol.encode_socks_request(
            protocol.CMD_CONNECT, protocol.ATYP_IPV4, "127.0.0.1", _PORT)
        self.assertEqual(raw[-2:], _PORT_BE)
        self.assertEqual(protocol.decode_socks_request(raw)[3], _PORT)
        # And the inherited little-endian reading is not what we produce:
        # the same two bytes the other way round are a different port.
        self.assertEqual(struct.unpack("<H", raw[-2:])[0], 0x901F)
        self.assertNotEqual(struct.unpack("<H", raw[-2:])[0], _PORT)

    def test_the_version_byte_is_present_and_checked(self):
        raw = protocol.encode_socks_request(
            protocol.CMD_CONNECT, protocol.ATYP_IPV4, "127.0.0.1", _PORT)
        self.assertEqual(raw[0], 5)
        # The original's dialect: the same request with the version byte
        # stripped. It must not parse here.
        with self.assertRaises(ValueError):
            protocol.decode_socks_request(raw[1:])
        for version in (0, 4, 6):
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    protocol.decode_socks_request(
                        bytes([version]) + raw[1:])

    def test_the_reserved_byte_is_present_and_checked(self):
        raw = protocol.encode_socks_request(
            protocol.CMD_CONNECT, protocol.ATYP_IPV4, "127.0.0.1", _PORT)
        self.assertEqual(raw[2], 0)
        with self.assertRaises(ValueError):
            protocol.decode_socks_request(raw[:2] + b"\x01" + raw[3:])

    def test_bind_and_udp_commands_decode_but_are_flagged_unsupported(self):
        """A peer asking for one gets an RFC 1928 refusal, which means the
        request has to parse first. Only CONNECT is answered.
        """
        for cmd in (protocol.CMD_BIND, protocol.CMD_UDP_ASSOCIATE):
            with self.subTest(cmd=cmd):
                raw = protocol.encode_socks_request(
                    cmd, protocol.ATYP_IPV4, "192.0.2.10", _PORT)
                self.assertEqual(
                    protocol.decode_socks_request(raw),
                    (cmd, protocol.ATYP_IPV4, "192.0.2.10", _PORT))
                self.assertFalse(protocol.socks_command_supported(cmd))
        self.assertTrue(
            protocol.socks_command_supported(protocol.CMD_CONNECT))
        self.assertEqual(protocol.SUPPORTED_COMMANDS,
                         (protocol.CMD_CONNECT,))
        # And the code to answer an unsupported one with is the RFC's.
        self.assertEqual(protocol.REPLY_COMMAND_NOT_SUPPORTED, 7)

    def test_an_unknown_command_is_refused_rather_than_decoded(self):
        raw = protocol.encode_socks_request(
            protocol.CMD_CONNECT, protocol.ATYP_IPV4, "192.0.2.10", _PORT)
        for cmd in (0, 4, 255):
            with self.subTest(cmd=cmd):
                with self.assertRaises(ValueError):
                    protocol.decode_socks_request(
                        raw[:1] + bytes([cmd]) + raw[2:])
                with self.assertRaises(ValueError):
                    protocol.encode_socks_request(
                        cmd, protocol.ATYP_IPV4, "192.0.2.10", _PORT)

    def test_an_unknown_address_type_is_refused(self):
        raw = protocol.encode_socks_request(
            protocol.CMD_CONNECT, protocol.ATYP_IPV4, "192.0.2.10", _PORT)
        for atyp in (0, 2, 5):
            with self.subTest(atyp=atyp):
                with self.assertRaises(ValueError):
                    protocol.decode_socks_request(
                        raw[:3] + bytes([atyp]) + raw[4:])
                with self.assertRaises(ValueError):
                    protocol.encode_socks_request(
                        protocol.CMD_CONNECT, atyp, "192.0.2.10", _PORT)

    def test_an_address_that_is_not_of_its_stated_type_is_refused(self):
        cases = ((protocol.ATYP_IPV4, "2001:db8::1"),
                 (protocol.ATYP_IPV4, "example.test"),
                 (protocol.ATYP_IPV6, "192.0.2.10"),
                 (protocol.ATYP_IPV4, "192.0.2.999"))
        for atyp, address in cases:
            with self.subTest(atyp=atyp, address=address):
                with self.assertRaises(ValueError):
                    protocol.encode_socks_request(
                        protocol.CMD_CONNECT, atyp, address, _PORT)

    def test_a_domain_that_does_not_fit_its_length_byte_is_refused(self):
        with self.assertRaises(ValueError):
            protocol.encode_socks_request(
                protocol.CMD_CONNECT, protocol.ATYP_DOMAIN, "a" * 256, _PORT)
        with self.assertRaises(ValueError):
            protocol.encode_socks_request(
                protocol.CMD_CONNECT, protocol.ATYP_DOMAIN, "", _PORT)
        longest = protocol.encode_socks_request(
            protocol.CMD_CONNECT, protocol.ATYP_DOMAIN, "a" * 255, _PORT)
        self.assertEqual(protocol.decode_socks_request(longest)[2], "a" * 255)

    def test_a_port_outside_a_uint16_is_refused(self):
        for port in (-1, 65536):
            with self.subTest(port=port):
                with self.assertRaises(ValueError):
                    protocol.encode_socks_request(
                        protocol.CMD_CONNECT, protocol.ATYP_IPV4,
                        "192.0.2.10", port)

    def test_a_short_or_over_long_request_is_refused(self):
        raw = protocol.encode_socks_request(
            protocol.CMD_CONNECT, protocol.ATYP_IPV4, "192.0.2.10", _PORT)
        for truncated in range(len(raw)):
            with self.subTest(length=truncated):
                with self.assertRaises(ValueError):
                    protocol.decode_socks_request(raw[:truncated])
        # Trailing bytes are a malformed request, not the start of the
        # relayed stream: a request arrives as one whole frame.
        with self.assertRaises(ValueError):
            protocol.decode_socks_request(raw + b"\x00")


class TestSocksReplyCodec(unittest.TestCase):

    def test_socks_reply_zero_is_success(self):
        """RFC 1928 §6, not the original's inversion where 1 meant ok."""
        self.assertEqual(protocol.REPLY_SUCCEEDED, 0)
        raw = protocol.encode_socks_reply(
            protocol.REPLY_SUCCEEDED, protocol.ATYP_IPV4, "192.0.2.10",
            _PORT)
        self.assertEqual(raw[1], 0)
        self.assertEqual(
            protocol.decode_socks_reply(raw),
            (protocol.REPLY_SUCCEEDED, protocol.ATYP_IPV4, "192.0.2.10",
             _PORT))
        # 1 is a failure here and success in the original, which is the
        # one byte most likely to be mistaken for a bug.
        self.assertEqual(protocol.REPLY_GENERAL_FAILURE, 1)
        self.assertNotEqual(protocol.REPLY_GENERAL_FAILURE,
                            protocol.REPLY_SUCCEEDED)

    def test_the_reply_codes_are_the_rfcs(self):
        self.assertEqual(
            (protocol.REPLY_SUCCEEDED, protocol.REPLY_GENERAL_FAILURE,
             protocol.REPLY_NOT_ALLOWED, protocol.REPLY_NETWORK_UNREACHABLE,
             protocol.REPLY_HOST_UNREACHABLE,
             protocol.REPLY_CONNECTION_REFUSED, protocol.REPLY_TTL_EXPIRED,
             protocol.REPLY_COMMAND_NOT_SUPPORTED,
             protocol.REPLY_ADDRESS_TYPE_NOT_SUPPORTED),
            (0, 1, 2, 3, 4, 5, 6, 7, 8))

    def test_socks_reply_round_trip_ipv4_ipv6_and_domain(self):
        cases = ((protocol.ATYP_IPV4, "198.51.100.7"),
                 (protocol.ATYP_IPV6, "2001:db8::dead:beef"),
                 (protocol.ATYP_DOMAIN, "gateway.example.test"))
        for atyp, address in cases:
            with self.subTest(atyp=atyp):
                raw = protocol.encode_socks_reply(
                    protocol.REPLY_SUCCEEDED, atyp, address, _PORT)
                self.assertEqual(raw[:4],
                                 bytes([5, protocol.REPLY_SUCCEEDED, 0,
                                        atyp]))
                self.assertEqual(raw[-2:], _PORT_BE)
                self.assertEqual(
                    protocol.decode_socks_reply(raw),
                    (protocol.REPLY_SUCCEEDED, atyp, address, _PORT))

    def test_a_failure_reply_needs_no_bound_address(self):
        """RFC 1928 leaves BND.ADDR and BND.PORT meaningless when REP is
        not 0, so the refusal path does not have to invent one.
        """
        raw = protocol.encode_socks_reply(
            protocol.REPLY_CONNECTION_REFUSED)
        self.assertEqual(
            raw, bytes([5, 5, 0, protocol.ATYP_IPV4]) + b"\x00" * 4
            + b"\x00\x00")
        self.assertEqual(
            protocol.decode_socks_reply(raw),
            (protocol.REPLY_CONNECTION_REFUSED, protocol.ATYP_IPV4,
             "0.0.0.0", 0))

    def test_the_reply_version_byte_is_present_and_checked(self):
        raw = protocol.encode_socks_reply(protocol.REPLY_SUCCEEDED)
        self.assertEqual(raw[0], 5)
        with self.assertRaises(ValueError):
            protocol.decode_socks_reply(raw[1:])
        with self.assertRaises(ValueError):
            protocol.decode_socks_reply(b"\x04" + raw[1:])

    def test_an_unknown_reply_code_is_refused(self):
        for code in (9, 255):
            with self.subTest(code=code):
                with self.assertRaises(ValueError):
                    protocol.encode_socks_reply(code)
                raw = protocol.encode_socks_reply(protocol.REPLY_SUCCEEDED)
                with self.assertRaises(ValueError):
                    protocol.decode_socks_reply(
                        raw[:1] + bytes([code]) + raw[2:])

    def test_a_short_or_over_long_reply_is_refused(self):
        raw = protocol.encode_socks_reply(
            protocol.REPLY_SUCCEEDED, protocol.ATYP_IPV6, "::1", _PORT)
        for truncated in range(len(raw)):
            with self.subTest(length=truncated):
                with self.assertRaises(ValueError):
                    protocol.decode_socks_reply(raw[:truncated])
        with self.assertRaises(ValueError):
            protocol.decode_socks_reply(raw + b"\x00")


class TestTheReExport(unittest.TestCase):
    """`protocol.py` must not hold a second copy of any of this.

    The implementation lives in `beacon.py` because the generator delivers
    that file and nothing else; `protocol.py` is the name the server side
    imports. If the two ever drift apart, the endpoint and the server stop
    speaking the same protocol while every test on either side passes.
    """

    def test_every_codec_is_the_beacons_own_object(self):
        from software.c2 import beacon as beacon_mod
        for name in ("read_frame", "write_frame", "encode_message",
                     "decode_message", "encode_socks_request",
                     "decode_socks_request", "encode_socks_reply",
                     "decode_socks_reply", "socks_command_supported"):
            with self.subTest(name=name):
                self.assertIs(getattr(protocol, name),
                              getattr(beacon_mod, name))


if __name__ == "__main__":
    unittest.main()
