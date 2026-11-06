#!/usr/bin/env python3
"""
Regression tests for the security-audit remediation of the C2 beacon and
team server.
"""

import base64
import json
import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

from software.c2 import beacon as beacon_mod
from software.c2.beacon import Beacon


PLAINTEXT_TASKING = {"tasks": [{"cmd": "shell", "args": "id"}]}


def _plaintext_b64() -> bytes:
    """The tasking a keyless party would send: b64(json), never encrypted."""
    return base64.b64encode(json.dumps(PLAINTEXT_TASKING).encode())


def _config(**transport):
    c2 = {
        "beacon_interval_seconds": 10,
        "jitter_percent": 20,
        "encryption_key": "",
        "proxy": {"mode": "none"},
        "https": {"enabled": False},
        "dns": {"enabled": False},
    }
    c2.update(transport)
    return {"c2": c2}


def _dns_beacon():
    return Beacon(_config(dns={"enabled": True, "domain": "c2.test",
                               "resolver": "8.8.8.8"}))


def _smb_beacon():
    return Beacon(_config(smb={"enabled": True, "server": "smb.test"}))


def _quic_beacon():
    return Beacon(_config(quic={"enabled": True, "server": "quic.test"}))


def _one_checkin(b):
    """Run exactly one pass of the real _beacon_loop and return every task
    that reached _process_tasking, i.e. everything that would have executed."""
    executed = []

    def stop(*_args, **_kwargs):
        b._running = False

    b._running = True
    with patch.object(b, "_process_tasking", side_effect=executed.append), \
            patch.object(b, "_jittered_sleep", side_effect=stop), \
            patch.object(b, "_backoff_sleep", side_effect=stop):
        b._beacon_loop()
    return executed


class _FakeUdp:
    """Stands in for the QUIC transport's UDP socket: swallows the request
    and answers with one datagram carrying the given payload."""

    def __init__(self, response_payload: bytes):
        frame = struct.pack(">I", len(response_payload)) + response_payload
        self._datagram = struct.pack(">IHH", 1, 0, 1) + frame
        self._sent = False

    def settimeout(self, _t):
        pass

    def sendto(self, _data, _addr):
        pass

    def recvfrom(self, _n):
        if self._sent:
            raise socket.timeout()
        self._sent = True
        return self._datagram, ("quic.test", 4433)

    def close(self):
        pass


class TestAeadIsNotOptional(unittest.TestCase):
    """Decryption failing is a failed exchange, never instructions."""

    # _encrypt takes a dict but the SMB and QUIC request legs hand it bytes,
    # so it raises before any response is read. Stubbing it lets these tests
    # reach the response leg, which is the one under test.
    def _smb_returning(self, b, response: bytes):
        return (patch.object(b, "_encrypt", return_value="req"),
                patch.object(b, "_smb_connect", return_value=MagicMock()),
                patch.object(b, "_smb_write_pipe", return_value=True),
                patch.object(b, "_smb_read_pipe", return_value=response))

    def _quic_returning(self, b, response: bytes):
        return (patch.object(b, "_encrypt", return_value="req"),
                patch.object(beacon_mod.socket, "socket",
                             side_effect=lambda *a, **k: _FakeUdp(response)))

    def _enter(self, patches):
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_dns_plaintext_tasking_is_refused(self):
        b = _dns_beacon()
        with patch.object(beacon_mod, "_dns_query",
                          return_value=[_plaintext_b64().decode()]):
            self.assertIsNone(b._beacon_dns())
            executed = _one_checkin(b)
        self.assertEqual(executed, [])

    # The SMB and QUIC fallbacks parsed the raw response bytes, the DNS one
    # parsed b64(json); a keyless party can use either shape.
    def _plaintext_shapes(self):
        return (("b64", _plaintext_b64()),
                ("raw", json.dumps(PLAINTEXT_TASKING).encode()))

    def test_smb_plaintext_tasking_is_refused(self):
        for shape, response in self._plaintext_shapes():
            with self.subTest(shape=shape):
                b = _smb_beacon()
                self._enter(self._smb_returning(b, response))
                self.assertIsNone(b._beacon_smb())
                self.assertEqual(_one_checkin(b), [])

    def test_quic_plaintext_tasking_is_refused(self):
        for shape, response in self._plaintext_shapes():
            with self.subTest(shape=shape):
                b = _quic_beacon()
                self._enter(self._quic_returning(b, response))
                self.assertIsNone(b._beacon_quic())
                self.assertEqual(_one_checkin(b), [])

    def test_undecryptable_response_is_a_failed_checkin_not_an_empty_one(self):
        # An empty-but-successful check-in resets the failure counter, so the
        # fifth consecutive failure would never trigger re-registration.
        b = _dns_beacon()
        b._registered = True
        b._consecutive_failures = 4
        with patch.object(beacon_mod, "_dns_query",
                          return_value=[_plaintext_b64().decode()]), \
                patch.object(b, "_register_https") as register:
            executed = _one_checkin(b)
        self.assertEqual(executed, [])
        self.assertEqual(b._consecutive_failures, 5)
        register.assert_called_once()
        self.assertFalse(b._registered)

    def test_dns_one_bad_record_does_not_abort_the_remaining_records(self):
        b = _dns_beacon()
        genuine = {"tasks": [{"cmd": "pwd", "id": "t1"}]}
        records = [_plaintext_b64().decode(), "not-base64-at-all!!",
                   b._encrypt(genuine)]
        with patch.object(beacon_mod, "_dns_query", return_value=records):
            self.assertEqual(b._beacon_dns(), genuine)
            executed = _one_checkin(b)
        self.assertEqual(executed, genuine["tasks"])

    def test_encrypted_responses_still_work_on_every_channel(self):
        genuine = {"tasks": [{"cmd": "pwd", "id": "t1"}]}

        dns = _dns_beacon()
        with patch.object(beacon_mod, "_dns_query",
                          return_value=[dns._encrypt(genuine)]):
            self.assertEqual(dns._beacon_dns(), genuine)

        smb = _smb_beacon()
        self._enter(self._smb_returning(smb, smb._encrypt(genuine).encode()))
        self.assertEqual(smb._beacon_smb(), genuine)

        quic = _quic_beacon()
        self._enter(self._quic_returning(quic, quic._encrypt(genuine).encode()))
        self.assertEqual(quic._beacon_quic(), genuine)


# New test classes belong above this guard; never append below it.
if __name__ == "__main__":
    unittest.main()
