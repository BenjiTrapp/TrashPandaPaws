"""The operator's SOCKS5 port: one per identity, on loopback, authenticated.

An operator points `proxychains`, `nmap` or a browser at a port on this
host and reaches the network an endpoint sits in. This module is that
port. It speaks RFC 1928 with RFC 1929 authentication to whatever
connects, and for each connection it asks `TunnelServer` for a relay to
one identity, hands the request down it and then pumps bytes.

**One fixed port per identity, assigned by the tunnel server's port
table.** This class does not choose the port; it binds the one it is
given, so a client's configuration does not move under it when a server
restarts or an endpoint reconnects. Nothing here knows about any identity
but its own: a second identity is a second `SocksFront` on its own port,
which is what keeps a port from ever pointing at a different network than
the operator believes.

**The port authenticates, and that is deliberate.** Loopback keeps other
hosts out and does nothing at all about other local users on this host:
an unauthenticated port here is a pivot into the target network for
anybody with a shell on the team server. The credentials are generated
per identity by the caller and only checked here, with
`hmac.compare_digest` and without short-circuiting between the two
fields. The protocol this derives from shipped two hardcoded credential
strings that are now literals in a public detection rule, which is the
second reason there is no default pair anywhere in this module.

**The greeting and the RFC 1929 sub-negotiation live here, not in
`protocol.py`.** That module carries only the request and the reply,
because those are the two messages both ends of the tunnel speak. An
endpoint never performs a greeting and never authenticates a SOCKS
client -- the relay channel it serves is already authenticated by Noise
and bound to a 32-byte token -- so this is the only side that has a
greeting at all, and the codec for it belongs to the one side that uses
it.

**A bind address that is not loopback is refused rather than trusted.**
The caller passes one in, and the check is here because this is the
object that would do the binding. Only an IP literal is accepted: a name
resolves through a resolver this process does not own, so `localhost` is
not proof of anything at bind time, and it is refused with a message
saying so.

**`max_sessions` defaults to 256.** One session costs a relay TCP
connection, a Noise session on the endpoint and two threads here, so the
cap is what stops an operator's own tooling from exhausting the team
server. 256 is chosen to sit above what a scan actually holds open --
`nmap` through a proxy is a connect scan, which keeps tens to low
hundreds of sockets in flight -- and below what the host would struggle
with, since at two threads per session a full port is about 512 threads.
Crossing it answers RFC 1928 reply `0x01` and counts the refusal -- never
a silent drop, because a drop is indistinguishable from a dead tunnel at
the far end, and a scan across a /24 is what finds this limit before
anything else does.

**Every refusal after the request is a reply.** `BIND` and `UDP
ASSOCIATE` decode -- Task 3's codec made sure of it -- so a client asking
for one gets `0x07`, command not supported, rather than a parse error it
cannot tell from a hung proxy. An unassigned `ATYP` gets `0x08`, because
its address has no length this end can know, so there is nothing to
delimit and nothing to forward. A greeting that is not SOCKS5 at all gets
nothing: the only message this layer can send is itself a SOCKS5 message.

Two sharp edges in the layers below, handled here:

* **`RelayStream`'s exception contract is coarser than it looks.** On the
  stream, `recv` returning `b""` means the far end is finished and says
  nothing about why: `RelayStream.recv_message` turns an orderly FIN, a
  truncated frame and a dead socket into the same empty answer, and its
  `MSG_PEEK` separates them only for its own logging, not for a caller.
  They are indistinguishable here and they do not need to be told apart,
  because the one action available is the same for all three: end the
  session. A `ValueError` is the exception -- a frame that did not
  authenticate, over which the stream has already closed itself, which is
  Noise §5.1 -- and it is logged as the hostile thing it may be.
  `socket.timeout` is an `OSError` and is reachable only while a timeout
  is set, which here is exactly the request/reply exchange: a bounded wait
  on the endpoint's answer, where a stall means a dead endpoint and the
  client is told `0x01` rather than left hanging. The pump itself runs
  with no timeout, because an idle SOCKS session is a normal thing -- a
  target that speaks first and a client that waits -- and `stop` unparks
  both directions by shutting their descriptors down.

* **A single `sendall` does not make concurrent writes safe**; it loops
  over partial sends and releases the GIL. The relay stream has a write
  lock of its own, so that side is covered. On the client socket there is
  no lock and instead an invariant: exactly one thread may write to it at
  a time. The connection's own thread writes the greeting, the
  sub-negotiation status and the reply, then becomes the
  client-to-endpoint pump, which never writes to the client socket again;
  the endpoint-to-client pump is the only writer from then on, and it is
  joined before anything else touches that socket. No SOCKS reply is ever
  sent after pumping starts, which is what makes that hold.

**Nothing an unauthenticated peer does is open-ended.** The threat model
for this port is the other local users of this host, and this process
hosts the rest of the C2's listeners, so a peer that can hold threads and
descriptors here can take those down with it. Two bounds, because a
socket timeout alone is not one:

* **An absolute deadline on the handshake**, not a timeout per `recv`.
  `handshake_timeout` is measured from the accept with `time.monotonic`
  and every read of the greeting, the sub-negotiation and the request is
  given what is left of it. A per-`recv` timeout bounds nothing: a peer
  that sends one byte just inside it, over and over, resets it every time
  and holds its thread for as long as it likes. The same deadline shape
  is in `_finish`, whose drain would otherwise never end against a client
  that keeps sending.

* **A cap on handshakes in flight**, separate from `max_sessions` and
  released the moment a connection authenticates. It defaults to
  `max_sessions`, because a handshake that could never become a session
  is one this port has no use for, and it can be set far lower. Past it a
  connection is closed without a byte -- there is no SOCKS message to
  refuse with before a greeting -- and counted under its own key. Its
  point is that a flood of silent peers cannot crowd out the operator's
  authenticated sessions, which `max_sessions` alone would let it do.

Stdlib only, and nothing from `software.c2.server`. There is no import of
this package's own `server` module either: a duck-typed
`tunnel_server.open_session` is all that is needed, and the test that
keeps the flask-bearing team server out of this package matches on the
module name `.server`.
"""

import hmac
import ipaddress
import logging
import socket
import threading
import time
from typing import Dict, List, Optional, Set, Tuple

from .protocol import (
    ATYP_DOMAIN,
    ATYP_IPV4,
    ATYP_IPV6,
    MAX_PAYLOAD_LEN,
    REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
    REPLY_COMMAND_NOT_SUPPORTED,
    REPLY_GENERAL_FAILURE,
    REPLY_SUCCEEDED,
    SOCKS_COMMAND_NAMES,
    SOCKS_REPLY_NAMES,
    SOCKS_VERSION,
    decode_socks_reply,
    decode_socks_request,
    encode_socks_reply,
    encode_socks_request,
    socks_command_supported,
)

logger = logging.getLogger("raccoon.tunnel.socks")

__all__ = ["SocksFront", "DEFAULT_MAX_SESSIONS"]

# See the module docstring: above what a connect scan holds open, and
# about 512 threads at full stretch.
DEFAULT_MAX_SESSIONS = 256

# How long a reply is given to leave for a client that is not reading it.
# Bounded for the same reason the handshake is, and separate from the
# handshake's deadline: a client that drips its request right up to that
# deadline must still be answered rather than silently dropped, which is
# what sending the reply on the remainder of an exhausted budget would do.
_REPLY_TIMEOUT = 10.0

# RFC 1928 §3, the method-selection messages. Only username/password is
# accepted; 0xFF is "none of the methods you offered".
_METHOD_USERPASS = 0x02
_METHOD_NONE_ACCEPTABLE = 0xFF

# RFC 1929 §2. The sub-negotiation has a version byte of its own, and it
# is 1 -- not the 5 of the greeting that precedes it.
_AUTH_VERSION = 0x01
_AUTH_SUCCESS = 0x00
_AUTH_FAILURE = 0x01

# RFC 1929 caps each field at what one length byte can express.
_MAX_CREDENTIAL_LEN = 0xFF

# ver | cmd | rsv | atyp, before the address.
_REQUEST_HEADER_LEN = 4

# One read fills at most one frame: the relay stream's plaintext ceiling.
_CHUNK = MAX_PAYLOAD_LEN

# How long `accept` blocks before the loop looks at the stop flag again.
_ACCEPT_POLL = 0.25

# How long a thread is waited for at teardown. Both pumps are unparked by
# a shutdown rather than left to notice on their own, so this is a bound
# on a pathology and not on the normal path.
_JOIN_TIMEOUT = 5.0

# How long a polite close spends reading what the client sent and we never
# wanted. Without it, closing a socket with unread bytes in its receive
# buffer sends an RST, and an RST can discard the refusal we just wrote --
# which would turn "the client gets a reply" into "sometimes it does". It
# is an absolute deadline on the drain, not a timeout per read: a client
# that keeps sending would otherwise be drained for as long as it liked.
_LINGER = 0.25


class SocksFront(object):
    """The operator-facing SOCKS5 listener for one endpoint identity.

    `tunnel_server` is anything with `open_session(identity)` returning a
    session that has `wait_paired(timeout)`, `sock` and `close()` -- in
    production that is `TunnelServer`.

    `bind_port` is the port this identity owns in the tunnel server's port
    table. 0 binds an ephemeral port, which is what the tests use; `port`
    reports what was actually bound.

    `max_pending` caps the handshakes in flight and defaults to
    `max_sessions`; `handshake_timeout` is an absolute deadline on one,
    measured from the accept. Both exist because the peers on this port
    are unauthenticated until they are not, and this process hosts more
    than this port.
    """

    def __init__(self, tunnel_server, identity: str, bind_port: int,
                 username: str, password: str,
                 max_sessions: int = DEFAULT_MAX_SESSIONS,
                 max_pending: Optional[int] = None,
                 bind_host: str = "127.0.0.1",
                 handshake_timeout: float = 15.0,
                 connect_timeout: float = 30.0,
                 backlog: int = 128):
        self._tunnel = tunnel_server
        self.identity = str(identity)
        if not self.identity:
            raise ValueError("a SOCKS front serves one named identity")
        self.bind_host, self._family = _loopback(bind_host)
        self.bind_port = int(bind_port)
        if not 0 <= self.bind_port <= 0xFFFF:
            raise ValueError("bind_port %r is not a port" % (bind_port,))
        self._username = _credential(username, "username")
        self._password = _credential(password, "password")
        self.max_sessions = int(max_sessions)
        if self.max_sessions < 1:
            raise ValueError("max_sessions must be at least 1, got %r"
                             % (max_sessions,))
        # A handshake that could never become a session is one this port
        # has no use for, so the default is the session cap itself. It is
        # its own knob because a deployment that wants the pre-auth
        # exposure much smaller than the session count should be able to
        # say so without shrinking what the operator can open.
        self.max_pending = (self.max_sessions if max_pending is None
                            else int(max_pending))
        if self.max_pending < 1:
            raise ValueError("max_pending must be at least 1, got %r"
                             % (max_pending,))
        self.handshake_timeout = _positive(handshake_timeout,
                                           "handshake_timeout")
        self.connect_timeout = _positive(connect_timeout, "connect_timeout")
        self.backlog = int(backlog)

        self.port = None            # type: Optional[int]
        self._lock = threading.Lock()
        self._listener = None       # type: Optional[socket.socket]
        self._accept_thread = None  # type: Optional[threading.Thread]
        self._stopping = threading.Event()
        self._stopping.set()
        self._workers = []          # type: List[threading.Thread]
        # Every client socket and every relay session in flight, so `stop`
        # can unpark a pump instead of waiting for one to notice.
        self._clients = set()       # type: Set[socket.socket]
        self._sessions = set()
        # The subset of `_clients` that has not authenticated yet, which is
        # what `max_pending` bounds. A set rather than a counter so that
        # releasing a slot is idempotent: the connection's own thread
        # releases it on a successful authentication and its teardown
        # releases it again for every other outcome.
        self._pending = set()       # type: Set[socket.socket]
        self._live = 0
        self._accepted = 0
        self._carried = 0
        self._bytes_in = 0
        self._bytes_out = 0
        self._refusals = {"auth": 0, "capacity": 0, "command": 0,
                          "address": 0, "tunnel": 0, "protocol": 0,
                          "timeout": 0, "pending": 0,
                          "threads": 0}   # type: Dict[str, int]

    # ── lifecycle ──

    def start(self) -> None:
        """Bind, listen, and start the accept loop. Sets `port`."""
        if self._listener is not None:
            raise RuntimeError("this SOCKS front is already serving")
        sock = socket.socket(self._family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.bind_host, self.bind_port))
            sock.listen(self.backlog)
        except OSError:
            sock.close()
            raise
        # A poll rather than a blocking accept, so `stop` does not depend
        # on the platform's behaviour when a listening socket is closed
        # under a thread sitting in `accept`.
        sock.settimeout(_ACCEPT_POLL)
        self._listener = sock
        self.port = sock.getsockname()[1]
        self._stopping.clear()
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="socks-accept", daemon=True)
        self._accept_thread.start()
        logger.info("socks: %r is served on %s:%d, at most %d sessions",
                    self.identity, self.bind_host, self.port,
                    self.max_sessions)

    def stop(self) -> None:
        """Stop serving and drop every session. Safe before `start`, twice."""
        self._stopping.set()
        listener, self._listener = self._listener, None
        if listener is not None:
            listener.close()
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=_JOIN_TIMEOUT)
        self._accept_thread = None
        with self._lock:
            clients = list(self._clients)
            sessions = list(self._sessions)
            workers = list(self._workers)
            self._workers = []
        # The relay first, then the client socket: a pump parked on either
        # side is unparked by the shutdown of the descriptor it is on, and
        # a session whose stream is gone has nothing left to carry.
        for session in sessions:
            session.close()
        for client in clients:
            _shut(client)
        for worker in workers:
            worker.join(timeout=_JOIN_TIMEOUT)

    def is_serving(self) -> bool:
        return self._listener is not None

    # ── what the panel reads ──

    def stats(self) -> dict:
        """One row's worth of what this port has done.

        `accepted` counts connections, and the `refused_*` counters count
        the ones this port turned away; a client that vanished mid-greeting
        is neither, so the three do not have to add up. `bytes_out` is
        toward the target network and `bytes_in` is back from it, both
        plaintext and both for the life of this object.

        The refusal keys are deliberately not interchangeable, because the
        three resource limits fail for different reasons and an operator
        reading this row has to be able to tell them apart:

        * `refused_capacity` -- `max_sessions`, which is the operator's own
          tooling asking for more than the port carries.
        * `refused_pending` -- `max_pending`, which is more handshakes in
          flight than this port will hold open at once.
        * `refused_threads` -- no thread could be started for a connection,
          which is the process as a whole out of room.
        * `refused_timeout` -- a handshake that ran past its deadline,
          counted because it was cut off deliberately and not lost.

        `refused_auth` covers a client that would not authenticate as well
        as one that got the credentials wrong: both mean nobody proved
        they were the operator.
        """
        with self._lock:
            refusals = dict(self._refusals)
            row = {
                "identity": self.identity,
                "port": self.port,
                "serving": self._listener is not None,
                "sessions": self._live,
                "max_sessions": self.max_sessions,
                "pending": len(self._pending),
                "max_pending": self.max_pending,
                "accepted": self._accepted,
                "carried": self._carried,
                "bytes_in": self._bytes_in,
                "bytes_out": self._bytes_out,
                "refused": sum(refusals.values()),
            }
        for why, count in refusals.items():
            row["refused_" + why] = count
        return row

    # ── the accept loop ──

    def _accept_loop(self) -> None:
        while not self._stopping.is_set():
            listener = self._listener
            if listener is None:
                return
            try:
                conn, address = listener.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if self._stopping.is_set():
                    return
                logger.debug("socks: accept failed: %s", exc)
                self._stopping.wait(0.05)
                continue
            except Exception:
                # The accept loop is the one thread that must not die: an
                # operator whose port stopped answering has no tunnel.
                # Backed off on the stop flag like the `OSError` arm
                # above, so a fault that persists cannot spin a core.
                logger.exception("socks: unexpected error in the accept loop")
                self._stopping.wait(0.05)
                continue
            peer = "%s:%d" % address[:2]
            worker = threading.Thread(target=self._serve, args=(conn, peer),
                                      name="socks-conn", daemon=True)
            with self._lock:
                self._accepted += 1
                crowded = len(self._pending) >= self.max_pending
                if not crowded:
                    self._workers = [t for t in self._workers if t.is_alive()]
                    self._workers.append(worker)
                    self._clients.add(conn)
                    self._pending.add(conn)
                else:
                    self._refusals["pending"] += 1
            if crowded:
                # Nothing has been read, so there is no SOCKS message to
                # refuse this inside: a greeting has to come first. Closed
                # on the accept loop rather than in a thread, because the
                # whole point of the cap is not to start one.
                logger.warning(
                    "socks: %r already has %d handshakes in flight, which is "
                    "its limit; closed %s", self.identity, self.max_pending,
                    peer)
                _shut(conn)
                continue
            try:
                self._start(worker)
            except RuntimeError as exc:
                # The process has no more threads to give. Nothing has
                # been read here either, so this is also a close rather
                # than a refusal on the wire -- and it is counted apart
                # from both session and handshake limits, because it is
                # the host that ran out and not this port.
                with self._lock:
                    self._clients.discard(conn)
                    self._pending.discard(conn)
                    # And out of the join list, or `stop` would raise on a
                    # thread that was never started.
                    if worker in self._workers:
                        self._workers.remove(worker)
                    self._refusals["threads"] += 1
                logger.warning("socks: no thread could be started for %s: "
                               "%s", peer, exc)
                _shut(conn)

    def _start(self, thread: threading.Thread) -> None:
        """Start a thread that is already registered for teardown.

        A method rather than a bare `thread.start()` at two call sites, so
        that both report a process with no threads left the same way --
        and so that a test can reach that branch without having to
        exhaust the host to do it.

        `start` does not use this: a front whose accept loop cannot be
        started has failed to start, and that belongs to the caller rather
        than to one connection.
        """
        thread.start()

    def _serve(self, conn: socket.socket, peer: str) -> None:
        """One client connection, from its greeting to its last byte."""
        # Absolute, and from here rather than from the first read: what is
        # being bounded is how long an unauthenticated peer may hold this
        # thread, which starts when the connection was accepted.
        deadline = time.monotonic() + self.handshake_timeout
        try:
            self._handle(conn, peer, deadline)
        except socket.timeout:
            # Only reachable from the handshake reads, which are the only
            # place a timeout is set on this socket, and `_exactly` gives
            # each of them no more than the deadline has left. So this is
            # the deadline and not a per-read stall.
            logger.warning("socks: %s did not finish its handshake within "
                           "%.1fs; closed", peer, self.handshake_timeout)
            self._refused("timeout")
        except (OSError, ValueError) as exc:
            # A client that left mid-handshake, or a reset: all of it is
            # this one connection's business. Not counted as a refusal,
            # because this end did not refuse anything.
            logger.debug("socks: dropped %s: %s", peer, exc)
        except Exception:
            logger.exception("socks: unexpected error serving %s", peer)
        finally:
            with self._lock:
                self._clients.discard(conn)
                self._pending.discard(conn)
            _finish(conn)

    def _handle(self, conn: socket.socket, peer: str,
                deadline: float) -> None:
        if not self._greet(conn, peer, deadline):
            return
        if not self._authenticate(conn, peer, deadline):
            return
        request = self._read_request(conn, peer, deadline)
        if request is None:
            return
        cmd, atyp, address, port = request
        if not socks_command_supported(cmd):
            # Decoded, so it can be refused properly rather than looking
            # like a parse error or a dead tunnel.
            logger.info("socks: %s asked %r for %s, which this port does "
                        "not serve", peer, self.identity,
                        SOCKS_COMMAND_NAMES.get(cmd, cmd))
            self._refuse(conn, REPLY_COMMAND_NOT_SUPPORTED, "command")
            return
        with self._lock:
            # The check and the increment are one critical section, or two
            # clients arriving together both see the last free slot. The
            # refusal itself is sent after the lock is released: this lock
            # is not reentrant and `_refuse` takes it to count.
            admitted = self._live < self.max_sessions
            if admitted:
                self._live += 1
        if not admitted:
            logger.warning(
                "socks: %r is already carrying %d sessions, which is its "
                "limit; refused %s for %s:%d", self.identity,
                self.max_sessions, peer, address, port)
            self._refuse(conn, REPLY_GENERAL_FAILURE, "capacity")
            return
        try:
            self._carry(conn, peer, cmd, atyp, address, port)
        finally:
            with self._lock:
                self._live -= 1

    # ── the greeting and RFC 1929 ──

    def _greet(self, conn: socket.socket, peer: str,
               deadline: float) -> bool:
        """RFC 1928 §3. True once username/password has been selected."""
        head = _exactly(conn, 2, deadline)
        if head[0] != SOCKS_VERSION:
            # Nothing to answer with: every message this layer can send is
            # itself a SOCKS5 message, and this peer is not speaking one.
            logger.info("socks: %s opened with version %d, not %d; closed",
                        peer, head[0], SOCKS_VERSION)
            self._refused("protocol")
            return False
        methods = _exactly(conn, head[1], deadline)
        if _METHOD_USERPASS not in methods:
            _say(conn, bytes([SOCKS_VERSION, _METHOD_NONE_ACCEPTABLE]))
            logger.info("socks: %s offered no authentication method this "
                        "port accepts; refused", peer)
            self._refused("auth")
            return False
        _say(conn, bytes([SOCKS_VERSION, _METHOD_USERPASS]))
        return True

    def _authenticate(self, conn: socket.socket, peer: str,
                      deadline: float) -> bool:
        """RFC 1929 §2. True once the credentials match."""
        head = _exactly(conn, 2, deadline)
        if head[0] != _AUTH_VERSION:
            logger.info("socks: %s sent sub-negotiation version %d, not %d; "
                        "closed", peer, head[0], _AUTH_VERSION)
            self._refused("protocol")
            return False
        username = _exactly(conn, head[1], deadline)
        password = _exactly(conn, _exactly(conn, 1, deadline)[0], deadline)
        # Both comparisons run before the branch: `and` would skip the
        # second one whenever the first failed, which tells a caller
        # whether it got the username right.
        user_ok = hmac.compare_digest(username, self._username)
        password_ok = hmac.compare_digest(password, self._password)
        if not (user_ok and password_ok):
            _say(conn, bytes([_AUTH_VERSION, _AUTH_FAILURE]))
            logger.warning("socks: %s failed to authenticate to %r's port",
                           peer, self.identity)
            self._refused("auth")
            return False
        _say(conn, bytes([_AUTH_VERSION, _AUTH_SUCCESS]))
        # It is the operator from here, so it stops counting against the
        # cap on unauthenticated connections. What it can do next is
        # bounded by `max_sessions` instead.
        with self._lock:
            self._pending.discard(conn)
        return True

    def _read_request(self, conn: socket.socket, peer: str,
                      deadline: float) -> Optional[Tuple[int, int, str, int]]:
        """One request off the stream, or None having answered the client.

        A request arrives as its own frame on the relay channel, so
        `decode_socks_request` wants exactly one and nothing else. Out of
        a TCP stream it has to be delimited first, and `ATYP` is what says
        how long it is. The version and reserved bytes are not checked
        here: the codec is the authority on those, and the read is bounded
        either way at four bytes plus a 255-byte name plus a port.
        """
        header = _exactly(conn, _REQUEST_HEADER_LEN, deadline)
        atyp = header[3]
        if atyp == ATYP_IPV4:
            body = _exactly(conn, 4, deadline)
        elif atyp == ATYP_IPV6:
            body = _exactly(conn, 16, deadline)
        elif atyp == ATYP_DOMAIN:
            length = _exactly(conn, 1, deadline)
            body = length + _exactly(conn, length[0], deadline)
        else:
            logger.info("socks: %s sent address type %d, which has no length "
                        "this end can know; refused", peer, atyp)
            self._refuse(conn, REPLY_ADDRESS_TYPE_NOT_SUPPORTED, "address")
            return None
        raw = header + body + _exactly(conn, 2, deadline)
        try:
            return decode_socks_request(raw)
        except ValueError as exc:
            logger.info("socks: %s sent a malformed request: %s", peer, exc)
            self._refused("protocol")
            return None

    # ── the relay ──

    def _carry(self, conn: socket.socket, peer: str, cmd: int, atyp: int,
               address: str, port: int) -> None:
        """Open a relay, hand it the request, and pump what comes back."""
        target = "%s:%d" % (address, port)
        try:
            session = self._tunnel.open_session(self.identity)
        except (ValueError, OSError) as exc:
            # No endpoint connected, or its command channel has just gone.
            logger.warning("socks: %s asked %r for %s and there is no tunnel "
                           "to carry it: %s", peer, self.identity, target, exc)
            self._refuse(conn, REPLY_GENERAL_FAILURE, "tunnel")
            return
        with self._lock:
            self._sessions.add(session)
        try:
            if not session.wait_paired(self.connect_timeout):
                logger.warning("socks: %r did not open a relay for %s within "
                               "%.1fs; refused", self.identity, target,
                               self.connect_timeout)
                self._refuse(conn, REPLY_GENERAL_FAILURE, "tunnel")
                return
            stream = session.sock
            if not self._exchange(conn, peer, stream, cmd, atyp, address,
                                  port):
                return
            with self._lock:
                self._carried += 1
            logger.info("socks: %s is carrying %s through %r", peer, target,
                        self.identity)
            self._pump(conn, stream)
        finally:
            with self._lock:
                self._sessions.discard(session)
            session.close()

    def _exchange(self, conn: socket.socket, peer: str, stream, cmd: int,
                  atyp: int, address: str, port: int) -> bool:
        """Send the request, pass the endpoint's reply on. True to pump.

        The request is re-encoded from what was decoded rather than
        forwarded as the bytes that arrived, so exactly one well-formed
        request goes down the relay. The reply travels the other way
        untouched once it has decoded, because the endpoint is the only
        thing that knows why a target did not answer and flattening its
        code into a general failure would cost the operator that.

        A timeout is set for this exchange and only for it. A stall here is
        an endpoint that is not going to answer, and the client is told so;
        the pump that follows has no timeout, because an idle session is
        an ordinary thing.
        """
        target = "%s:%d" % (address, port)
        try:
            stream.settimeout(self.connect_timeout)
            stream.sendall(encode_socks_request(cmd, atyp, address, port))
            raw = stream.recv_message()
        except socket.timeout:
            logger.warning("socks: %r did not answer a request for %s within "
                           "%.1fs; refused", self.identity, target,
                           self.connect_timeout)
            self._refuse(conn, REPLY_GENERAL_FAILURE, "tunnel")
            return False
        except (OSError, ValueError) as exc:
            # An empty read is handled below. Here the relay either broke
            # under the write or delivered a frame that did not
            # authenticate, which has already closed the stream.
            logger.warning("socks: the relay carrying %s for %r failed: %s",
                           target, self.identity, exc)
            self._refuse(conn, REPLY_GENERAL_FAILURE, "tunnel")
            return False
        if not raw:
            logger.warning("socks: %r closed the relay for %s without "
                           "answering", self.identity, target)
            self._refuse(conn, REPLY_GENERAL_FAILURE, "tunnel")
            return False
        try:
            reply = decode_socks_reply(raw)[0]
        except ValueError as exc:
            # One frame is one message on this protocol, so a frame that is
            # not exactly a reply is a broken endpoint and not a reply with
            # the stream's first bytes stuck to it.
            logger.warning("socks: %r answered a request for %s with "
                           "something that is not a reply: %s",
                           self.identity, target, exc)
            self._refuse(conn, REPLY_GENERAL_FAILURE, "tunnel")
            return False
        _say(conn, raw)
        if reply != REPLY_SUCCEEDED:
            logger.info("socks: %r could not reach %s: %s", self.identity,
                        target, SOCKS_REPLY_NAMES.get(reply, reply))
            return False
        return True

    def _pump(self, conn: socket.socket, stream) -> None:
        """Carry bytes until either side is finished.

        Both descriptors lose their timeout here. The handshake had one
        because a client that connects and says nothing must not hold a
        thread, but an idle *session* is an ordinary thing -- a target that
        speaks first, an operator's shell waiting on a prompt -- and a
        timeout on this loop would drop it. `stop` unparks both directions
        by shutting their descriptors down instead.

        This thread owns the client-to-endpoint direction and a second one
        owns the other, so each socket has exactly one writer: see the
        module docstring. Whichever direction ends first ends the session,
        because a SOCKS proxy that kept half of one open would leave the
        operator's tool waiting on a target that has gone.
        """
        conn.settimeout(None)
        stream.settimeout(None)
        back = threading.Thread(target=self._downstream, args=(conn, stream),
                                name="socks-relay", daemon=True)
        try:
            self._start(back)
        except RuntimeError as exc:
            # No thread for the return direction. A one-way proxy is worse
            # than none, so the session ends here: the caller's `finally`
            # closes the relay and the client sees the connection go.
            logger.warning("socks: %r could not start the return direction "
                           "of a session; closing it: %s", self.identity, exc)
            return
        try:
            self._upstream(conn, stream)
        finally:
            # Shut both descriptors before the join: the other thread may
            # be parked in a read or in a send that TCP backpressure has
            # stopped, and neither wakes on its own.
            stream.close()
            _shutdown(conn)
            back.join(timeout=_JOIN_TIMEOUT)

    def _upstream(self, conn: socket.socket, stream) -> None:
        """The client's bytes, toward the target network."""
        while True:
            try:
                data = conn.recv(_CHUNK)
            except OSError:
                return
            if not data:
                return
            try:
                stream.sendall(data)
            except (OSError, ValueError):
                return
            with self._lock:
                self._bytes_out += len(data)

    def _downstream(self, conn: socket.socket, stream) -> None:
        """The target network's bytes, back to the client."""
        try:
            self._downstream_loop(conn, stream)
        finally:
            # This direction ending means the target has gone, so the
            # session goes with it: the client is sent the FIN it is
            # waiting for and the other direction's blocked `recv` is
            # unparked. A half-open session kept here would leave an
            # operator's tool waiting on a relay that no longer exists.
            stream.close()
            _shutdown(conn)

    def _downstream_loop(self, conn: socket.socket, stream) -> None:
        while True:
            try:
                data = stream.recv(_CHUNK)
            except ValueError:
                # A frame that did not authenticate. `RelayStream` has
                # already closed itself over it, per Noise §5.1.
                logger.warning("socks: a relay frame for %r did not "
                               "authenticate; the session is over",
                               self.identity)
                return
            except OSError:
                return
            # `b""` is the far end finished, and which of the three ways it
            # finished -- an orderly teardown, a truncated frame, a dead
            # socket -- is not knowable here: `RelayStream.recv_message`
            # answers all three with an empty read. They need no telling
            # apart, because the one thing to do about any of them is to
            # end the session.
            if not data:
                return
            try:
                conn.sendall(data)
            except OSError:
                return
            with self._lock:
                self._bytes_in += len(data)

    # ── refusals ──

    def _refuse(self, conn: socket.socket, reply: int, why: str) -> None:
        """Answer with an RFC 1928 reply code and count it.

        Always a reply, never a silent close: at the far end a drop is
        indistinguishable from a tunnel that has died, and a client that
        cannot tell the two apart retries instead of reporting.
        """
        self._refused(why)
        try:
            _say(conn, encode_socks_reply(reply))
        except OSError as exc:
            logger.debug("socks: could not answer %s: %s", why, exc)

    def _refused(self, why: str) -> None:
        with self._lock:
            self._refusals[why] += 1


def _exactly(sock: socket.socket, count: int, deadline: float) -> bytes:
    """Exactly `count` bytes, before `deadline`.

    `deadline` is an absolute `time.monotonic()`, and each `recv` is given
    only what is left of it. A plain `settimeout` would be no bound at
    all: it restarts on every byte that arrives, so a peer sending one
    byte just inside it holds this thread for as long as it cares to.
    Reaching the deadline raises `socket.timeout`, which is also what the
    last `recv` raises when it runs the budget out, so the caller has one
    case and not two.

    `ValueError` is a peer that closed with the read half-done, which is a
    client that left rather than one that stalled.
    """
    if count <= 0:
        return b""
    chunks = []
    have = 0
    while have < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout(
                "the handshake deadline passed with %d of %d bytes read"
                % (have, count))
        sock.settimeout(remaining)
        chunk = sock.recv(count - have)
        if not chunk:
            raise ValueError("the client closed with %d of %d bytes sent"
                             % (have, count))
        chunks.append(chunk)
        have += len(chunk)
    return b"".join(chunks)


def _say(sock: socket.socket, data: bytes) -> None:
    """Write a handshake message or a reply, on a bounded timeout.

    Its own timeout rather than whatever the last read left behind. The
    reads run on the remainder of the handshake deadline, so a client that
    dripped its request until that budget was nearly gone would otherwise
    have its refusal written with microseconds to spare and dropped -- and
    a refusal that is not delivered is the silent drop this port exists
    not to do.
    """
    sock.settimeout(_REPLY_TIMEOUT)
    sock.sendall(data)


def _loopback(value) -> Tuple[str, int]:
    """`(host, family)` for a loopback literal; `ValueError` for anything else.

    A name is refused rather than resolved. The resolver belongs to the
    host, not to this process: `localhost` is whatever `/etc/hosts` says
    today, and a SOCKS port that is reachable from off-box is a pivot into
    the target network for whoever finds it.
    """
    host = str(value)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError(
            "a SOCKS bind address must be a loopback IP literal such as "
            "127.0.0.1 or ::1, and %r is a name, whose resolution is not "
            "this process's to trust" % (host,))
    if not address.is_loopback:
        raise ValueError("%r is not a loopback address, and this port must "
                         "not be reachable from another host" % (host,))
    return host, (socket.AF_INET6 if address.version == 6 else socket.AF_INET)


def _credential(value, what: str) -> bytes:
    """One RFC 1929 field as the bytes it is compared as."""
    if not isinstance(value, str) or not value:
        raise ValueError("the SOCKS %s is a non-empty string; this port "
                         "authenticates and has no anonymous mode" % what)
    raw = value.encode("utf-8")
    if len(raw) > _MAX_CREDENTIAL_LEN:
        raise ValueError("RFC 1929 gives the %s one length byte, so it is at "
                         "most %d bytes; this one is %d"
                         % (what, _MAX_CREDENTIAL_LEN, len(raw)))
    return raw


def _positive(value, what: str) -> float:
    seconds = float(value)
    if seconds <= 0:
        raise ValueError("%s must be a positive number of seconds, got %r"
                         % (what, value))
    return seconds


def _shutdown(sock: socket.socket) -> None:
    """Shut a socket down both ways without closing it.

    Without closing, because another thread may still be inside a `recv`
    or a `sendall` on this descriptor: the shutdown is what unparks it,
    and closing the descriptor is left to the one place that knows every
    thread using it has finished.
    """
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def _finish(sock: socket.socket) -> None:
    """Close a client socket without losing the last thing written to it.

    `close` on a socket with unread bytes in its receive buffer sends an
    RST, and an RST can discard bytes already queued the other way -- so a
    client that pipelined data behind its request could lose the very
    refusal this port sent it. The FIN goes first, then what the client
    sent is read and dropped, and only then is the descriptor closed.

    The drain runs to an absolute deadline rather than on a timeout per
    read, for the same reason the handshake does: a client that keeps
    sending would reset a per-read timeout forever and pin this thread
    inside a function whose whole purpose is to end quickly.
    """
    try:
        sock.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    deadline = time.monotonic() + _LINGER
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            if not sock.recv(4096):
                break
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _shut(sock: socket.socket) -> None:
    """Drop a socket now, waiting for nothing.

    `stop` promises to be immediate, so this is the teardown it uses: the
    shutdown is what unparks another thread's blocked `recv` or `sendall`
    on the descriptor, which a bare `close` does not reliably do.
    """
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass
