"""A UDP listener for the beacon's fragmented framing.

The beacon calls this transport "QUIC-style". It is not QUIC: there is no
handshake, no congestion control and no encryption at this layer -- the
payload arrives already encrypted and this module never looks inside it.
What it is, read from `beacon.py:_quic_send`, is a length-prefixed frame
cut into datagrams:

    frame    = struct ">I" (length) + payload
    datagram = struct ">IHH" (stream_id, frag_index, total_frags) + chunk

Eight bytes of header, not sixteen. The chunk size the beacon sends is
1200, and its receive buffer is 1500, so an answer datagram must stay
under that including its own header.

Two details of the client's receive loop shape this module. It ignores the
stream_id it gets back, and it takes `expected` from whichever datagram it
last parsed -- so every answer datagram must carry the same total_frags,
and echoing the request's stream_id costs nothing while making concurrent
exchanges legible in a capture.

What this module does *not* do is as important as what it does. It does
not hold the encryption key, so it cannot read or forge beacon traffic. It
does not invent an answer: when the relay fails it sends nothing, and the
beacon's own timeout treats that as a failed exchange and retries on its
own schedule. And it does not trust a sender: a datagram arriving here is
one packet from anybody, so every buffer it can grow is capped.
"""

import logging
import socket
import struct
import threading
import time
from typing import Dict, Optional, Tuple

from .relay import relay

logger = logging.getLogger("raccoon.listeners.quic")

_HEADER = struct.Struct(">IHH")
_HEADER_LEN = _HEADER.size          # 8

# The beacon reads answers with recvfrom(1500). Staying at the chunk size
# it sends keeps both directions symmetric and well inside that.
_DEFAULT_FRAG = 1200

# A datagram cannot exceed this, so reading more would only mask a bug.
_RECV_BUF = 65535

# Shorter than base64 of a 12-byte nonce plus a 16-byte tag: not a payload.
_MIN_PAYLOAD_LEN = 32


class _Partial:
    """Fragments of one frame, from one sender, under one stream id."""

    __slots__ = ("chunks", "total", "bytes", "touched")

    def __init__(self, total: int):
        self.chunks: Dict[int, bytes] = {}
        self.total = total
        self.bytes = 0
        self.touched = time.monotonic()

    def add(self, index: int, chunk: bytes) -> None:
        if index not in self.chunks:
            self.bytes += len(chunk)
        self.chunks[index] = chunk
        self.touched = time.monotonic()

    @property
    def complete(self) -> bool:
        return len(self.chunks) == self.total

    def joined(self) -> bytes:
        return b"".join(self.chunks[i] for i in sorted(self.chunks))


class QuicListener:
    """Terminate the beacon's UDP framing and relay what it carries."""

    # A partial that stops arriving is the normal case under packet loss,
    # and the abnormal case is a scanner sending fragment 0 of 9 forever.
    # Both are handled by the same two caps and one timeout rather than by
    # trusting the sender.
    max_partials = 256
    max_buffered_bytes = 16 * 1024 * 1024
    partial_ttl = 30.0

    # A frame longer than this is refused before anything is buffered.
    max_frame_bytes = 64 * 1024 * 1024

    def __init__(self, bind_host: str, bind_port: int, *, relay_url: str,
                 frag_size: int = _DEFAULT_FRAG, sock=None):
        self.relay_url = relay_url
        self.frag_size = frag_size
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
        self._partials: Dict[Tuple[Tuple[str, int], int], _Partial] = {}
        self._seen = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ── lifecycle ──

    def start(self) -> None:
        """Serve in a background thread."""
        if self._thread is not None:
            raise RuntimeError("this listener is already serving")
        self._thread = threading.Thread(target=self.serve_forever,
                                        daemon=True)
        self._thread.start()

    def serve_forever(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(_RECV_BUF)
            except socket.timeout:
                self.expire_partials()
                continue
            except OSError:
                break                       # the socket was closed under us
            with self._lock:
                self._seen += 1
            try:
                self._on_datagram(data, addr)
            except Exception as exc:
                # One malformed sender must not take the service down for
                # every other beacon.
                logger.debug("listener: dropped a datagram from %s: %s",
                             addr, exc)

    def shutdown(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    # ── observable state, for tests and for the status panel ──

    def counters(self) -> dict:
        """What this listener has seen, in the shape every listener uses.

        One shape across the three transports, because the panel shows
        them side by side and a per-transport dictionary would have the
        panel knowing which keys each one happens to have.
        """
        return {"datagrams_seen": self.datagrams_seen(),
                "partials_open": self.partial_count()}


    def datagrams_seen(self) -> int:
        """Datagrams read off the socket, counted before any is judged.

        Exists so a test can wait for the listener to have *looked* at what
        it was sent. Waiting on a predicate that is already true is not a
        wait, and a test that asserts before the service has read its input
        passes for the wrong reason -- a mutation check is what exposed
        that here.
        """
        with self._lock:
            return self._seen

    def partial_count(self) -> int:
        with self._lock:
            return len(self._partials)

    def buffered_bytes(self) -> int:
        with self._lock:
            return sum(p.bytes for p in self._partials.values())

    def expire_partials(self, older_than: Optional[float] = None) -> int:
        """Drop partials untouched for longer than `older_than` seconds."""
        ttl = self.partial_ttl if older_than is None else older_than
        cutoff = time.monotonic() - ttl
        with self._lock:
            stale = [k for k, p in self._partials.items()
                     if p.touched <= cutoff]
            for key in stale:
                del self._partials[key]
        return len(stale)

    # ── the exchange ──

    def _on_datagram(self, data: bytes, addr) -> None:
        if len(data) < _HEADER_LEN:
            return
        stream_id, index, total = _HEADER.unpack(data[:_HEADER_LEN])
        chunk = data[_HEADER_LEN:]

        # A sender states its own fragment count, so every part of it is
        # checked before a byte is kept. The first clause is implied by the
        # second -- index is never negative, so total == 0 always trips
        # index >= total -- and is kept because a reader asking "is a zero
        # fragment count handled?" should find the answer here rather than
        # having to reason about it. A mutation check proved the redundancy
        # rather than a missing test.
        if total == 0 or index >= total:
            return
        if total * self.frag_size > self.max_frame_bytes:
            return

        # Keyed on the sender's address as well as the stream id: the id is
        # four random bytes the sender picks, so two beacons can collide,
        # and splicing their frames together would hand each the other's
        # answer.
        key = (addr, stream_id)

        with self._lock:
            partial = self._partials.get(key)
            if partial is None:
                if (len(self._partials) >= self.max_partials
                        or self._buffered_locked() >= self.max_buffered_bytes):
                    # Full. Reclaim what has gone stale and try once more;
                    # if it is still full, this datagram is dropped rather
                    # than letting the caps be exceeded.
                    self._expire_locked(self.partial_ttl)
                    if (len(self._partials) >= self.max_partials
                            or self._buffered_locked()
                            >= self.max_buffered_bytes):
                        logger.debug("listener: at capacity, dropping from %s",
                                     addr)
                        return
                partial = _Partial(total)
                self._partials[key] = partial
            partial.add(index, chunk)
            if not partial.complete:
                return
            del self._partials[key]

        frame = partial.joined()
        payload = _unframe(frame)
        if payload is None:
            return

        answer = relay(payload, url=self.relay_url)
        if answer is None:
            # Nothing invented: the beacon's timeout treats silence as a
            # failed exchange, which is what actually happened.
            return
        self._send_frame(answer.encode(), addr, stream_id)

    def _send_frame(self, payload: bytes, addr, stream_id: int) -> None:
        frame = struct.pack(">I", len(payload)) + payload
        total = max(1, (len(frame) + self.frag_size - 1) // self.frag_size)
        for index in range(total):
            chunk = frame[index * self.frag_size:(index + 1) * self.frag_size]
            try:
                self._sock.sendto(_HEADER.pack(stream_id, index, total) + chunk,
                                  addr)
            except OSError as exc:
                logger.debug("listener: send to %s failed: %s", addr, exc)
                return

    # ── locked helpers ──

    def _buffered_locked(self) -> int:
        return sum(p.bytes for p in self._partials.values())

    def _expire_locked(self, ttl: float) -> None:
        cutoff = time.monotonic() - ttl
        for key in [k for k, p in self._partials.items()
                    if p.touched <= cutoff]:
            del self._partials[key]


def _unframe(frame: bytes) -> Optional[str]:
    """Take the payload out of a [4-byte length][payload] frame."""
    if len(frame) < 4:
        return None
    length = struct.unpack(">I", frame[:4])[0]
    body = frame[4:4 + length]
    if len(body) != length:
        return None
    # A real payload is base64 of at least a 12-byte nonce and a 16-byte
    # tag, so it cannot be short. Without this, a frame declaring length 0
    # passed the check above -- len(b"") == 0 -- and the listener relayed an
    # empty payload, generating pointless traffic to the team server on a
    # stray sender's behalf. A test found it; the arithmetic check alone
    # did not.
    if length < _MIN_PAYLOAD_LEN:
        return None
    try:
        return body.decode("ascii")
    except UnicodeDecodeError:
        # The payload is base64; anything else did not come from a beacon.
        return None
