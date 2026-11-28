#!/usr/bin/env python3
"""The QUIC client's answer has to come from the endpoint it asked.

`_quic_send` read its answer with `recvfrom` and threw the source address
away, and it ignored the `stream_id` it got back as well. So anything that
could reach the beacon's ephemeral source port could put a fragment into a
reassembly in progress and make the exchange fail. It could not inject
*tasking* -- that needs the key, and `TestAeadIsNotOptional` holds the line
-- so this denied a channel rather than opening a command path. The
listener keys its own reassembly on the sender's address; a listener cannot
compensate for a client that does not.

Measured through real sockets, not through a fake: both tests bind a second
UDP socket of their own and send from it, which is exactly what the
defect's reach is -- a different source address on the same host. A fake
socket could be made to answer anything, and would prove nothing about
whether the client looks at where an answer came from.
"""

import base64
import os
import socket
import struct
import sys
import threading
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.c2 import dns_rescue
from software.c2.beacon import Beacon

_HEADER = struct.Struct(">IHH")


def _a_beacon(server):
    return Beacon({"c2": {
        "beacon_interval_seconds": 300,
        "jitter_percent": 0,
        "encryption_key": base64.b64encode(os.urandom(32)).decode(),
        "proxy": {"mode": "none"},
        "https": {"enabled": False},
        "dns": {"enabled": False, "domain": "", "resolver": "1.1.1.1"},
        "quic": {"enabled": True, "server": server},
    }})


class _Endpoint:
    """A real UDP socket that answers one request, as the listener does.

    It echoes the request's `stream_id`, which is what `listeners/quic.py`
    does and what the client is now entitled to expect. `answer` is a
    callable so a test can decide what comes back after seeing the request.
    """

    def __init__(self, answer):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(10)
        self.address = self.sock.getsockname()
        self.requests = []
        self._answer = answer
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        try:
            self.sock.close()
        except OSError:
            pass
        self._thread.join(timeout=5)

    def _serve(self):
        try:
            data, sender = self.sock.recvfrom(4096)
        except (OSError, socket.timeout):
            return
        self.requests.append(data)
        stream_id = _HEADER.unpack(data[:8])[0]
        self._answer(self, sender, stream_id)

    def frame(self, payload: bytes, stream_id: int) -> bytes:
        body = struct.pack(">I", len(payload)) + payload
        return _HEADER.pack(stream_id, 0, 1) + body


class QuicCase(unittest.TestCase):
    def endpoint(self, answer):
        end = _Endpoint(answer).start()
        self.addCleanup(end.stop)
        return end

    def beacon_for(self, end):
        return _a_beacon("%s:%d" % end.address)

    def client_port(self, request_bytes, end):
        """Where the client's request came from, as the endpoint saw it."""
        del request_bytes
        return end


class TestAnAnswerFromAnotherSenderIsIgnored(QuicCase):
    def test_a_fragment_from_a_third_party_does_not_end_the_exchange(self):
        # The endpoint answers correctly; an interloper on this host sends a
        # well-formed fragment from its own address first. Before the fix
        # the interloper's bytes went into the reassembly and the exchange
        # failed on a payload that did not decrypt.
        sent = {}

        def answer(end, sender, stream_id):
            sent["sender"] = sender
            spoof = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                spoof.sendto(end.frame(b"not the real answer", stream_id),
                             sender)
            finally:
                spoof.close()

        end = self.endpoint(answer)
        beacon = self.beacon_for(end)
        reply = beacon._quic_send({"action": "beacon", "id": "probe"})
        # Nothing legitimate ever came back, so the exchange still fails --
        # but it has to fail as a *timeout*, meaning the interloper's
        # fragment was dropped rather than reassembled and decrypted.
        self.assertIsNone(reply)
        self.assertTrue(sent, "the endpoint never saw a request")
        self.assertEqual(beacon._leg_status.get("quic", (None,))[0],
                         dns_rescue.CLASSES["timed_out"],
                         "the third party's fragment was accepted: the leg "
                         "reports a bad payload instead of a timeout")

    def test_the_real_endpoints_answer_is_still_accepted(self):
        # The property the check must not cost. The endpoint answers with a
        # real envelope from its own address, and the client reads it.
        def answer(end, sender, stream_id):
            payload = beacon._encrypt({"tasks": []}).encode()
            end.sock.sendto(end.frame(payload, stream_id), sender)

        end = self.endpoint(answer)
        beacon = self.beacon_for(end)
        self.assertEqual(beacon._quic_send({"action": "beacon"}), {"tasks": []})


class TestAnAnswerUnderAnotherStreamIdIsIgnored(QuicCase):
    def test_a_fragment_with_the_wrong_stream_id_is_dropped(self):
        # The second half of the same defect: the client read `stream_id`
        # out of the header and never compared it. The listener echoes the
        # request's id and says so in its own module docstring, so a
        # mismatch is not a legitimate answer from anybody.
        def answer(end, sender, stream_id):
            payload = beacon._encrypt({"tasks": [{"cmd": "shell"}]}).encode()
            end.sock.sendto(end.frame(payload, stream_id ^ 0xFFFF), sender)

        end = self.endpoint(answer)
        beacon = self.beacon_for(end)
        self.assertIsNone(beacon._quic_send({"action": "beacon"}),
                          "a fragment under another stream id was read as "
                          "the answer to this exchange")
        self.assertEqual(beacon._leg_status.get("quic", (None,))[0],
                         dns_rescue.CLASSES["timed_out"])


class TestTheListenerDocumentationMatches(unittest.TestCase):
    def test_the_listener_no_longer_says_the_client_ignores_the_stream_id(self):
        text = (REPO_ROOT / "software" / "c2" / "listeners"
                / "quic.py").read_text()
        self.assertNotIn(
            "It ignores the\nstream_id it gets back", text,
            "listeners/quic.py still says the client ignores the stream_id "
            "it gets back, which is no longer true")
        self.assertIn("stream_id", text)


if __name__ == "__main__":
    unittest.main()
