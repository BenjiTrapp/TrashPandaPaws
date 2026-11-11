"""The operator's shell port: one per identity, on loopback, authenticated.

An operator attaches their own terminal to a port on this host and lands
in a shell on the implant host. This module is that port. It is the
sibling of `socks.py`: the same listener, the same caps, the same
counters and the same teardown discipline, with the SOCKS greeting and
request replaced by one prompt and one line of text, and with
`open_shell_session` in place of `open_session`.

**Read `socks.py` first.** Everything that module's docstring argues
about this shape holds here and is not repeated: one fixed port per
identity so a client's configuration does not move under it; a bind
address that is refused rather than trusted unless it is a loopback IP
literal; credentials compared with `hmac.compare_digest` and no default
pair anywhere; an absolute deadline on the handshake rather than a
timeout per `recv`; a cap on handshakes in flight separate from the cap
on live sessions; exactly one thread writing to the client socket at a
time; and a polite close that drains briefly so a refusal the client has
not read yet is not discarded by an RST. The three argument helpers --
`loopback_bind`, `credential`, `positive` -- and the three socket
teardowns are imported from there rather than copied, because two
implementations of a security property are one implementation and one
latent hole.

Four things are different here, and each one is a decision rather than an
accident.

**One password and no username.** RFC 1929 wanted a pair; this stream has
no protocol at all. The username would be the identity of the build,
which is already the key of the port table and is not a secret, so it
would buy nothing while giving an attach client one more thing to get
wrong. The password is a second secret, minted per identity beside the
SOCKS pair and never equal to it: whoever was handed a SOCKS credential
for a pivot should not thereby hold a root shell on the host.

**The geometry rides on the end of the password line, and that is the
sharp edge.** The line is `<password>` or `<password> <cols>x<rows>`, and
an operator's password may contain a space -- so a naive split reads part
of it as a terminal size and locks them out of their own port.
`parse_auth_line` therefore splits once from the right and takes the tail
as geometry only when it is entirely a geometry; anything else is part of
the password. The bounds come from `protocol`, which is where the
endpoint reads them too: both ends clamp against the same three numbers,
and a second copy of them here would show up as a terminal of the wrong
size and nothing more.

**Every refusal is a line of plain text, including the ones SOCKS has to
answer silently.** What is at the far end is a terminal, so a sentence is
the only refusal an operator can read -- and a drop is indistinguishable
from a dead tunnel, which is how an operator ends up debugging the
network instead of reading the reason. `raccoon: ` and a CRLF, matching
the endpoint's own refusals, because the terminal is in raw mode. Two of
them are written from the accept loop, before any thread exists for the
connection, and those use a short timeout of their own: the loop that
answers the operator's next connection must not park behind a peer that
declines to read sixty bytes.

**Four sessions by default, not 256.** A shell session costs a process
and a pseudo-terminal on the implant and the endpoint holds four at once,
so a fifth admitted here could only be refused at the far end, after the
operator had already been told they were through. The cap matches the
endpoint's deliberately.

One sharp edge of this wire, handled in `_read_line`: the bytes after the
newline are already input for the shell. An attach client is free to put
the password line and the first keystrokes in one segment, so what
follows the newline is kept and sent down the session rather than
dropped -- unlike a SOCKS request, there is no reply in between that
would stop a client from pipelining.

Stdlib only, and nothing from `software.c2.server`. There is no import of
this package's own `server` module either: a duck-typed
`tunnel_server.open_shell_session` is all that is needed.
"""

import hmac
import logging
import re
import socket
import threading
import time
from typing import Dict, List, Optional, Set, Tuple

from .protocol import (
    MAX_PAYLOAD_LEN,
    SHELL_DEFAULT_COLS,
    SHELL_DEFAULT_ROWS,
    SHELL_GEOMETRY_MAX,
)
from .socks import (
    credential,
    loopback_bind,
    positive,
    # The socket teardown this port shares with the SOCKS one, under the
    # names it has there. A copy here would be a copy of the reasoning
    # about an RST discarding a refusal and about what unparks a blocked
    # pump, which is exactly the kind of duplication the two ports are
    # meant not to have.
    _finish,
    _shut,
    _shutdown,
)

logger = logging.getLogger("raccoon.tunnel.shell")

__all__ = ["ShellFront", "DEFAULT_MAX_SESSIONS", "PROMPT", "parse_auth_line"]

# Four, because the endpoint holds four shell sessions at once: see the
# module docstring.
DEFAULT_MAX_SESSIONS = 4

# What a client reads before it sends anything. Written first so that a
# terminal shows the operator what is wanted instead of looking hung.
PROMPT = b"password: "

# How long a prompt or a refusal is given to leave for a client that is
# not reading it. Its own timeout rather than whatever the last read left
# behind: the reads run on the remainder of the auth deadline, so a client
# that dripped its line until that budget was nearly gone would otherwise
# have its refusal written with microseconds to spare and dropped.
_SAY_TIMEOUT = 10.0

# The same, for the two refusals the accept loop sends before a thread
# exists. Short, because that loop is how the operator's next connection
# is answered.
_ACCEPT_SAY_TIMEOUT = 0.5

# The longest auth line this port will read. A password is at most 255
# bytes -- `credential`'s bound, which both operator ports share -- plus a
# space and a geometry of at most eleven, so this is twice what any
# legitimate line needs and a bound on what an unauthenticated peer can
# make this process buffer.
_MAX_LINE = 512

# How long the endpoint is given to dial its side of the session back.
# A constant rather than a knob: the endpoint answers `OPEN_SHELL` by
# opening a pty and dialling out at once, so a wait this long is already
# a dead endpoint, and the one thing an operator could do with a shorter
# number is give up on a tunnel that was about to work.
_PAIR_TIMEOUT = 30.0

# One read fills at most one frame: the relay stream's plaintext ceiling.
_CHUNK = MAX_PAYLOAD_LEN

# How long `accept` blocks before the loop looks at the stop flag again.
_ACCEPT_POLL = 0.25

# How long a thread is waited for at teardown. Both pumps are unparked by
# a shutdown rather than left to notice on their own, so this is a bound
# on a pathology and not on the normal path.
_JOIN_TIMEOUT = 5.0

# A geometry and nothing else. Anchored on both ends on purpose: a tail
# that is merely geometry-shaped at the front -- `200x` , `80x24junk` --
# is part of the password, because a password is whatever the operator
# chose and this port does not get to trim it.
_GEOMETRY = re.compile(r"\A(\d{1,5})x(\d{1,5})\Z")

# Everything outside printable ASCII, which is what a refusal is reduced
# to before it is written: see `_line`.
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")


class _TooLong(Exception):
    """The auth line ran past its bound before a newline arrived."""


def parse_auth_line(line: str) -> Tuple[str, int, int]:
    """`(password, cols, rows)` from one attach line.

    The line is `<password>` or `<password> <cols>x<rows>`, and the
    geometry is optional. One split from the right, and the tail counts as
    geometry only when it matches a geometry entirely: a password with a
    space in it is ordinary -- a passphrase, or two words from a password
    manager -- and reading `words` as a terminal size would lock an
    operator out of their own port with no way to tell why.

    The sizes are clamped into `1..SHELL_GEOMETRY_MAX` rather than
    refused. `0x0` and `9999x9999` are what a terminal in an odd state
    reports, and refusing the session over it would cost the operator the
    shell for a cosmetic reason; the endpoint clamps against the same
    bound before its `ioctl`.
    """
    parts = line.rsplit(" ", 1)
    if len(parts) == 2:
        match = _GEOMETRY.match(parts[1])
        if match is not None:
            return (parts[0], _clamp(int(match.group(1))),
                    _clamp(int(match.group(2))))
    return line, SHELL_DEFAULT_COLS, SHELL_DEFAULT_ROWS


def _clamp(value: int) -> int:
    return max(1, min(SHELL_GEOMETRY_MAX, value))


class ShellFront(object):
    """The operator-facing shell listener for one endpoint identity.

    `tunnel_server` is anything with `open_shell_session(identity, cols,
    rows)` returning a session that has `wait_paired(timeout)`, `sock` and
    `close()` -- in production that is `TunnelServer`.

    `bind_port` is the port this identity owns in the tunnel server's
    shell port table. 0 binds an ephemeral port, which is what the tests
    use; `port` reports what was actually bound.

    `transcripts` is where a later task records a session. It is stored
    and nothing is asked of it here.
    """

    def __init__(self, tunnel_server, identity: str, bind_port: int,
                 password: str, *,
                 max_sessions: int = DEFAULT_MAX_SESSIONS,
                 max_pending: Optional[int] = None,
                 bind_host: str = "127.0.0.1",
                 handshake_timeout: float = 15.0,
                 backlog: int = 16,
                 transcripts=None):
        self._tunnel = tunnel_server
        self.identity = str(identity)
        if not self.identity:
            raise ValueError("a shell front serves one named identity")
        self.bind_host, self._family = loopback_bind(bind_host)
        self.bind_port = int(bind_port)
        if not 0 <= self.bind_port <= 0xFFFF:
            raise ValueError("bind_port %r is not a port" % (bind_port,))
        self._password = credential(password, "shell password")
        self.max_sessions = int(max_sessions)
        if self.max_sessions < 1:
            raise ValueError("max_sessions must be at least 1, got %r"
                             % (max_sessions,))
        # A handshake that could never become a session is one this port
        # has no use for, so the default is the session cap itself.
        self.max_pending = (self.max_sessions if max_pending is None
                            else int(max_pending))
        if self.max_pending < 1:
            raise ValueError("max_pending must be at least 1, got %r"
                             % (max_pending,))
        self.handshake_timeout = positive(handshake_timeout,
                                          "handshake_timeout")
        self.backlog = int(backlog)
        self._transcripts = transcripts

        self.port = None            # type: Optional[int]
        self._lock = threading.Lock()
        self._listener = None       # type: Optional[socket.socket]
        self._accept_thread = None  # type: Optional[threading.Thread]
        self._stopping = threading.Event()
        self._stopping.set()
        self._workers = []          # type: List[threading.Thread]
        # Every client socket and every session in flight, so `stop` can
        # unpark a pump instead of waiting for one to notice.
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
        self._refusals = {"auth": 0, "capacity": 0, "pending": 0,
                          "tunnel": 0, "timeout": 0, "threads": 0,
                          "unsupported": 0}    # type: Dict[str, int]

    # ── lifecycle ──

    def start(self) -> None:
        """Bind, listen, and start the accept loop. Sets `port`."""
        if self._listener is not None:
            raise RuntimeError("this shell front is already serving")
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
            target=self._accept_loop, name="shell-accept", daemon=True)
        self._accept_thread.start()
        logger.info("shell: %r is served on %s:%d, at most %d sessions",
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
        # The session first, then the client socket: a pump parked on
        # either side is unparked by the shutdown of the descriptor it is
        # on, and a session whose stream is gone has nothing left to carry.
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

        `accepted` counts connections and `refused` counts the ones this
        port turned away, per kind; a client that vanished at the prompt is
        neither, so they do not have to add up. `bytes_out` is toward the
        implant's terminal and `bytes_in` is back from it, both plaintext
        and both for the life of this object.

        The refusal keys are deliberately not interchangeable, because an
        operator who cannot attach has to be able to tell which of these
        it was:

        * `auth` -- nobody proved they were the operator: a wrong
          password, an empty answer, or a line past its bound.
        * `capacity` -- `max_sessions`, which is this port already
          carrying all the terminals it will hold.
        * `pending` -- `max_pending`, more handshakes in flight than this
          port will hold open at once.
        * `threads` -- no thread could be started, which is the process as
          a whole out of room rather than either cap.
        * `timeout` -- a line that did not arrive inside the deadline,
          counted because it was cut off deliberately and not lost.
        * `tunnel` -- there is no endpoint to carry it, or it never dialled
          back.
        * `unsupported` -- the endpoint is connected but advertised no
          `shell` feature, which is a build older than this feature and a
          different thing to do about it than a tunnel that is down.
        """
        with self._lock:
            return {
                "identity": self.identity,
                "port": self.port,
                "serving": self._listener is not None,
                "live": self._live,
                "max_sessions": self.max_sessions,
                "pending": len(self._pending),
                "max_pending": self.max_pending,
                "accepted": self._accepted,
                "carried": self._carried,
                "bytes_in": self._bytes_in,
                "bytes_out": self._bytes_out,
                "refused": dict(self._refusals),
            }

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
                logger.debug("shell: accept failed: %s", exc)
                self._stopping.wait(0.05)
                continue
            except Exception:
                # The accept loop is the one thread that must not die: an
                # operator whose port stopped answering has no shell.
                # Backed off on the stop flag like the `OSError` arm
                # above, so a fault that persists cannot spin a core.
                logger.exception("shell: unexpected error in the accept loop")
                self._stopping.wait(0.05)
                continue
            peer = "%s:%d" % address[:2]
            worker = threading.Thread(target=self._serve, args=(conn, peer),
                                      name="shell-conn", daemon=True)
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
                # Answered here rather than in a thread, because the whole
                # point of the cap is not to start one -- and answered in
                # text, because there is no protocol on this stream that
                # a line of English could be mistaken for.
                logger.warning(
                    "shell: %r already has %d handshakes in flight, which is "
                    "its limit; refused %s", self.identity, self.max_pending,
                    peer)
                _refuse_now(conn,
                            "this shell port already has %d attach attempts "
                            "in flight, which is all it will hold at once. "
                            "Try again in a moment." % self.max_pending)
                continue
            try:
                self._start(worker)
            except RuntimeError as exc:
                # The process has no more threads to give. Counted apart
                # from both caps, because it is the host that ran out and
                # not this port's policy.
                with self._lock:
                    self._clients.discard(conn)
                    self._pending.discard(conn)
                    # And out of the join list, or `stop` would raise on a
                    # thread that was never started.
                    if worker in self._workers:
                        self._workers.remove(worker)
                    self._refusals["threads"] += 1
                logger.warning("shell: no thread could be started for %s: "
                               "%s", peer, exc)
                _refuse_now(conn,
                            "this team server has no thread left to serve a "
                            "shell session. Something else on it is holding "
                            "far more than it should.")

    def _start(self, thread: threading.Thread) -> None:
        """Start a thread that is already registered for teardown.

        A method rather than a bare `thread.start()`, as in `socks.py`, so
        that a test can reach the no-threads-left branch without having to
        exhaust the host to do it.
        """
        thread.start()

    def _serve(self, conn: socket.socket, peer: str) -> None:
        """One client connection, from its prompt to its last byte."""
        # Absolute, and from here rather than from the first read: what is
        # being bounded is how long an unauthenticated peer may hold this
        # thread, which starts when the connection was accepted.
        deadline = time.monotonic() + self.handshake_timeout
        try:
            self._handle(conn, peer, deadline)
        except socket.timeout:
            # Only reachable from the auth line's reads, which are the
            # only place a timeout is set on this socket for a read, and
            # `_read_line` gives each of them no more than the deadline has
            # left. So this is the deadline and not a per-read stall.
            logger.warning("shell: %s did not send a password line within "
                           "%.1fs; closed", peer, self.handshake_timeout)
            self._refuse(conn, "no password line arrived within %.1f seconds, "
                               "so this connection was closed."
                         % self.handshake_timeout, "timeout")
        except (OSError, ValueError) as exc:
            # A client that left at the prompt, or a reset: all of it is
            # this one connection's business. Not counted as a refusal,
            # because this end did not refuse anything.
            logger.debug("shell: dropped %s: %s", peer, exc)
        except Exception:
            logger.exception("shell: unexpected error serving %s", peer)
        finally:
            with self._lock:
                self._clients.discard(conn)
                self._pending.discard(conn)
            _finish(conn)

    def _handle(self, conn: socket.socket, peer: str,
                deadline: float) -> None:
        _say(conn, PROMPT)
        try:
            line, pipelined = _read_line(conn, deadline, _MAX_LINE)
        except _TooLong as exc:
            logger.warning("shell: %s sent %s; refused", peer, exc)
            self._refuse(conn, "that password line is longer than this port "
                               "will read. Send the password, optionally "
                               "followed by a space and <cols>x<rows>.",
                         "auth")
            return
        # Replacement characters rather than an error: a line that is not
        # UTF-8 cannot be the password, which is a UTF-8 string, so it
        # fails the comparison below like any other wrong answer instead of
        # taking a path of its own.
        password, cols, rows = parse_auth_line(
            line.decode("utf-8", "replace"))
        # Compared even when it is empty. A `if not password` ahead of this
        # would answer an absent password faster than a wrong one, and tell
        # a caller which of the two it had given.
        if not hmac.compare_digest(password.encode("utf-8"), self._password):
            logger.warning("shell: %s failed to authenticate to %r's shell "
                           "port", peer, self.identity)
            self._refuse(conn, "that is not the password for this shell "
                               "port.", "auth")
            return
        # It is the operator from here, so it stops counting against the cap
        # on unauthenticated connections. What it can do next is bounded by
        # `max_sessions` instead.
        with self._lock:
            self._pending.discard(conn)
        with self._lock:
            # The check and the increment are one critical section, or two
            # clients arriving together both see the last free slot. The
            # refusal itself is sent after the lock is released: this lock
            # is not reentrant and `_refuse` takes it to count.
            admitted = self._live < self.max_sessions
            if admitted:
                self._live += 1
        if not admitted:
            logger.warning("shell: %r is already carrying %d sessions, which "
                           "is its limit; refused %s", self.identity,
                           self.max_sessions, peer)
            self._refuse(conn, "this shell port is already carrying %d "
                               "sessions, which is all it will hold at once. "
                               "Close one and attach again."
                         % self.max_sessions, "capacity")
            return
        try:
            self._carry(conn, peer, cols, rows, pipelined)
        finally:
            with self._lock:
                self._live -= 1

    # ── the session ──

    def _carry(self, conn: socket.socket, peer: str, cols: int, rows: int,
               pipelined: bytes) -> None:
        """Ask for a terminal, wait for it, and pump what comes back."""
        try:
            session = self._tunnel.open_shell_session(self.identity, cols,
                                                      rows)
        except (ValueError, OSError) as exc:
            # No endpoint connected, one that predates this feature, or a
            # command channel that has just gone. The tunnel server's text
            # is passed on rather than summarised: it is the only thing
            # that knows which of the three happened, and an operator who
            # is told "no shell" learns nothing about whether to rebuild
            # the implant or wait for it to call home.
            reason = str(exc)
            # `unsupported` when the refusal is about the feature the
            # endpoint did not advertise, because that is a build to
            # replace and not a tunnel to wait for. Matched on the text
            # because `open_shell_session` raises one exception type for
            # every reason it has.
            why = "unsupported" if "feature" in reason else "tunnel"
            logger.warning("shell: %s asked %r for a terminal and there is "
                           "none to give: %s", peer, self.identity, reason)
            self._refuse(conn, reason, why)
            return
        with self._lock:
            self._sessions.add(session)
        try:
            if not session.wait_paired(_PAIR_TIMEOUT):
                logger.warning("shell: %r did not open a terminal within "
                               "%.1fs; refused %s", self.identity,
                               _PAIR_TIMEOUT, peer)
                self._refuse(conn, "the endpoint for %r did not open a "
                                   "terminal within %.1f seconds."
                             % (self.identity, _PAIR_TIMEOUT), "tunnel")
                return
            stream = session.sock
            with self._lock:
                self._carried += 1
            logger.info("shell: %s is attached to %r, %dx%d", peer,
                        self.identity, cols, rows)
            if pipelined:
                # Already input for the shell: see the module docstring.
                try:
                    stream.sendall(pipelined)
                except (OSError, ValueError) as exc:
                    logger.warning("shell: the terminal for %r went before "
                                   "its first bytes: %s", self.identity, exc)
                    return
                with self._lock:
                    self._bytes_out += len(pipelined)
            self._pump(conn, stream)
        finally:
            with self._lock:
                self._sessions.discard(session)
            session.close()

    def _pump(self, conn: socket.socket, stream) -> None:
        """Carry bytes until either side is finished.

        Both descriptors lose their timeout here. The auth line had a
        deadline because a client that connects and says nothing must not
        hold a thread, but an idle *session* is the normal state of a
        shell -- a prompt waiting to be typed at, a capture running for an
        hour -- and a timeout on this loop would drop it. `stop` unparks
        both directions by shutting their descriptors down instead.

        This thread owns the operator-to-terminal direction and a second
        one owns the other, so each socket has exactly one writer: no
        refusal is ever written after this point, which is what makes that
        hold. Whichever direction ends first ends the session, because the
        operator's terminal must not be left attached to a shell that has
        exited.
        """
        conn.settimeout(None)
        stream.settimeout(None)
        back = threading.Thread(target=self._downstream, args=(conn, stream),
                                name="shell-relay", daemon=True)
        try:
            self._start(back)
        except RuntimeError as exc:
            # No thread for the output direction. A terminal that cannot
            # show what the shell says is worse than none, so the session
            # ends here: the caller's `finally` closes it and the client
            # sees the connection go.
            logger.warning("shell: %r could not start the output direction "
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
        """What the operator types, toward the implant's terminal."""
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
        """What the terminal prints, back to the operator."""
        try:
            self._downstream_loop(conn, stream)
        finally:
            # This direction ending means the shell has gone, so the
            # session goes with it: the operator's client is sent the FIN
            # it is waiting for and the other direction's blocked `recv` is
            # unparked.
            stream.close()
            _shutdown(conn)

    def _downstream_loop(self, conn: socket.socket, stream) -> None:
        while True:
            try:
                data = stream.recv(_CHUNK)
            except ValueError:
                # A frame that did not authenticate. `RelayStream` has
                # already closed itself over it, per Noise §5.1.
                logger.warning("shell: a frame for %r did not authenticate; "
                               "the session is over", self.identity)
                return
            except OSError:
                return
            # `b""` is the far end finished, and which of the three ways it
            # finished -- an orderly teardown, a truncated frame, a dead
            # socket -- is not knowable here, nor worth knowing: the one
            # thing to do about any of them is to end the session.
            if not data:
                return
            try:
                conn.sendall(data)
            except OSError:
                return
            with self._lock:
                self._bytes_in += len(data)

    # ── refusals ──

    def _refuse(self, conn: socket.socket, reason: str, why: str) -> None:
        """One line of readable text, and count it.

        Text and not a code: what is at the other end of this stream is
        the operator's terminal, so a sentence is the only refusal they can
        read -- and a terminal in raw mode needs the carriage return, which
        is why this matches the endpoint's own refusals exactly. Never a
        silent close: a drop is indistinguishable from a dead tunnel, and
        an operator who cannot tell those apart debugs the network.
        """
        self._refused(why)
        try:
            _say(conn, _line(reason))
        except OSError as exc:
            logger.debug("shell: could not tell %s why it was refused: %s",
                         why, exc)

    def _refused(self, why: str) -> None:
        with self._lock:
            self._refusals[why] += 1


def _line(reason: str) -> bytes:
    """One refusal, as the endpoint writes its own: named, and CRLF.

    Flattened and reduced to printable ASCII on the way out, because not
    every reason is written here: the ones out of `open_shell_session`
    carry that module's wording, and one of them quotes the feature list
    the *endpoint* advertised, which came from the implant host. That is
    not a party this end trusts, and what this writes to goes straight
    into a terminal in raw mode -- so a newline cannot turn one line into
    several and an escape sequence cannot repaint the operator's screen.
    """
    flat = " ".join(str(reason).split())
    return ("raccoon: %s\r\n" % _UNPRINTABLE.sub("?", flat)).encode("utf-8")


def _say(sock: socket.socket, data: bytes) -> None:
    """Write the prompt or a refusal, on a bounded timeout of its own."""
    sock.settimeout(_SAY_TIMEOUT)
    sock.sendall(data)


def _refuse_now(sock: socket.socket, reason: str) -> None:
    """Refuse from the accept loop and drop the socket, waiting for nothing.

    A short timeout rather than `_say`'s: this runs on the thread that
    accepts the operator's next connection, so a peer that declines to
    read its refusal must cost that loop milliseconds and not seconds.
    """
    try:
        sock.settimeout(_ACCEPT_SAY_TIMEOUT)
        sock.sendall(_line(reason))
    except OSError:
        pass
    _shut(sock)


def _read_line(sock: socket.socket, deadline: float,
               limit: int) -> Tuple[bytes, bytes]:
    """`(line, pipelined)`: one line, and whatever followed the newline.

    `deadline` is an absolute `time.monotonic()`, and each `recv` is given
    only what is left of it. A plain `settimeout` would be no bound at
    all: it restarts on every byte that arrives, so a peer sending one
    byte just inside it holds this thread for as long as it cares to.
    Reaching the deadline raises `socket.timeout`, which is also what the
    last `recv` raises when it runs the budget out, so the caller has one
    case and not two.

    `ValueError` is a peer that closed without finishing its line, which
    is a client that left rather than one that stalled. `_TooLong` is a
    peer that is sending without ever meaning to finish, which is a
    refusal the client can be told about.

    The bytes after the newline are returned rather than dropped: on this
    wire they are already input for the shell.
    """
    have = b""
    while b"\n" not in have:
        if len(have) > limit:
            raise _TooLong("%d bytes with no end of line, past the %d-byte "
                           "bound" % (len(have), limit))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout(
                "the deadline passed with %d bytes of a password line read"
                % len(have))
        sock.settimeout(remaining)
        chunk = sock.recv(limit + 1 - len(have))
        if not chunk:
            raise ValueError("the client closed after %d bytes of a password "
                             "line" % len(have))
        have += chunk
    line, _, pipelined = have.partition(b"\n")
    if line.endswith(b"\r"):
        # A client whose terminal sends CRLF. The password is what was
        # typed, not what the line discipline added to it.
        line = line[:-1]
    return line, pipelined
