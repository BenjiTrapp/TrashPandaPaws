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
not read yet is not discarded by an RST. The six helpers it shares with
that module -- the three argument checks `loopback_bind`, `credential`
and `positive`, and the three socket teardowns `shut`, `shutdown_both`
and `finish` -- are imported from there rather than copied, because two
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

**One thing this port has that `socks.py` does not: it can record.** What
a transcript holds is the output direction, byte for byte -- what the
terminal showed, which is a typescript in `script(1)`'s sense. That
already contains everything the operator typed, because the terminal
echoes it, so there is no second keystroke file to write and no second
one to protect. Recording is off unless a directory is configured, and
`Transcripts.open` is called at the pairing: by then the password line
has been read and compared, so the attach password cannot reach a
transcript. What can reach one is a credential the operator types
*inside* a session, unavoidably -- which is why these are 0600 files in a
0700 directory and why the documentation says so in those words. And
because a transcript is still only a log file, nothing about it may cost
a session: a directory that cannot be created, one that turns out to be
a symlink, a write that fails, a session past the ceiling -- each is
logged once with its reason, sets the recorder aside, and leaves the
shell running. A directory this module did not create is checked rather
than trusted, and a transcript with no sidecar beside it is a session
that was interrupted: `Transcripts` has both in full.

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
import json
import logging
import os
import re
import socket
import stat
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
    finish,
    loopback_bind,
    positive,
    shut,
    shutdown_both,
)

logger = logging.getLogger("raccoon.tunnel.shell")

__all__ = ["ShellFront", "DEFAULT_MAX_SESSIONS", "PROMPT", "Recorder",
           "TRANSCRIPT_MAX_BYTES", "Transcripts", "parse_auth_line"]

# Four, because the endpoint holds four shell sessions at once: see the
# module docstring.
DEFAULT_MAX_SESSIONS = 4

# The floor under `max_pending` when it is left unset: see `__init__`. The
# session cap alone would let a handful of silent peers crowd the operator
# out of a port whose whole purpose is that they can reach it.
_MIN_PENDING = 8

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

# The most one session will record, after which recording stops and the
# session carries on. A ceiling rather than a disk quota, because what
# this bounds is one `tcpdump` or one `yes` inside a shell: 16 MiB is far
# more terminal output than an engagement reads back, and far less than a
# team server's disk.
TRANSCRIPT_MAX_BYTES = 16 * 1024 * 1024

# A transcript is evidence and a secret at the same time, so the same two
# modes the key store uses.
_DIR_MODE = 0o700
_FILE_MODE = 0o600

# Everything a build identity may not contribute to a path component:
# see `_folder_name`.
_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")

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


class Recorder(object):
    """One session's typescript, and the sidecar written when it closes.

    Owned by the one thread that pumps the output direction: that thread
    opens it, writes every byte it sends to the operator, and closes it
    in its own teardown. So there is no lock here, and no lifetime
    question for anything else to get wrong.

    **Nothing this object does raises.** A transcript is a log file and
    the thing it is logging is an operator's shell: a failed write, a
    descriptor that has gone, a full disk -- each is logged once with its
    reason, sets this recorder aside, and leaves the session running.
    `truncated` is then true, because that is exactly what it means: the
    transcript is short of the session, whether it stopped at the ceiling
    or because the disk said no.
    """

    def __init__(self, path: str, handle, facts: dict, max_bytes: int):
        self.path = path
        self.truncated = False
        self.bytes = 0
        self._handle = handle
        self._sidecar = path + ".json"
        self._facts = facts
        self._max = max_bytes
        self._closed = False
        # Why this recording stopped short, once it has. The sidecar's
        # `stopped`, kept rather than only logged: see `close`.
        self._stopped = None    # type: Optional[str]

    def write(self, data: bytes) -> None:
        """Record what the operator's terminal was shown.

        Guarded as a whole, and not only around the two calls that were
        expected to fail. This runs on the thread carrying the session,
        so "a transcript cannot cost a session" should not rest on having
        correctly predicted which line would raise -- the same reason
        `ShellFront._downstream` closes a recorder inside a `finally` of
        its own rather than trusting this class to behave.
        """
        try:
            self._write(data)
        except Exception as exc:
            self._stop("could not be recorded: %s" % exc)

    def _write(self, data: bytes) -> None:
        handle = self._handle
        if handle is None or not data:
            return
        room = self._max - self.bytes
        if room <= 0:
            # Exactly at the ceiling with more to show. Nothing had been
            # dropped until this call, so this is where it stops rather
            # than where it stopped.
            self._stop("reached its %d-byte ceiling" % self._max)
            return
        chunk = data if len(data) <= room else data[:room]
        try:
            handle.write(chunk)
            # Flushed per chunk rather than left in a buffer. This is
            # evidence, and the bytes of a session whose team server was
            # killed are worth more on the disk than in a buffer that
            # died with it. One write per chunk, and a chunk already cost
            # a read and a send.
            handle.flush()
        except Exception as exc:
            self._stop("could not be written: %s" % exc)
            return
        self.bytes += len(chunk)
        if len(chunk) < len(data):
            self._stop("reached its %d-byte ceiling" % self._max)

    def close(self, reason: str) -> None:
        """Close the transcript and write the sidecar beside it.

        `reason` is why the **session** ended, in the words of whichever
        teardown called this. The sidecar's `stopped` is the other
        question -- why the **recording** stopped short of the session --
        and is None unless this recorder was set aside. They are
        different facts, and conflating them would leave the one artifact
        that travels with the evidence unable to say why it is short: a
        transcript cut off at the ceiling would carry nothing but "the
        terminal closed", and only the team server's log, which is not
        what gets copied out, would know better.

        Safe twice: this is called from a teardown.
        """
        if self._closed:
            return
        self._closed = True
        handle, self._handle = self._handle, None
        if handle is not None:
            try:
                handle.close()
            except Exception as exc:
                logger.warning("shell: the transcript %s could not be "
                               "closed: %s", self.path, exc)
        facts = dict(self._facts)
        facts.update({
            "ended": _stamp(time.time()),
            "bytes": self.bytes,
            "truncated": self.truncated,
            "reason": " ".join(str(reason).split()),
            "stopped": self._stopped,
        })
        try:
            _write_private_json(self._sidecar, facts)
        except Exception as exc:
            # The transcript itself is already on the disk and closed, so
            # this costs a reader the facts about it and nothing else --
            # which is why they are restated here, in the one place left
            # that still has them.
            logger.warning("shell: the sidecar %s could not be written: %s. "
                           "The transcript it describes is %s, %d bytes%s.",
                           self._sidecar, exc, self.path, self.bytes,
                           (", truncated: " + self._stopped)
                           if self.truncated else "")
            return
        logger.info("shell: the transcript %s is closed after %d bytes%s: %s",
                    self.path, self.bytes,
                    (" (truncated: %s)" % self._stopped) if self.truncated
                    else "", facts["reason"])

    def _stop(self, what: str) -> None:
        """Set this recorder aside, saying why, and say it once.

        Once is enforced here rather than left to the fact that `_write`
        returns early on a handle that has gone: `write` guards itself as
        a whole, so an unexpected failure that recurs would otherwise be
        reported per chunk for the rest of the session -- a degradation
        is one line naming its reason, not a stream of them.

        `what` is kept as well as logged, because it is the sidecar's
        `stopped`: this log line stays on the team server, and the
        sidecar is what travels with the transcript.
        """
        if self._stopped is not None:
            return
        handle, self._handle = self._handle, None
        self.truncated = True
        self._stopped = " ".join(str(what).split())
        logger.warning("shell: the transcript %s %s, so the rest of this "
                       "session is not recorded. The session itself is "
                       "untouched.", self.path, self._stopped)
        if handle is not None:
            try:
                handle.close()
            except Exception:
                # Already reported above, and a descriptor this end can do
                # nothing more with is not worth a second line.
                pass


class Transcripts(object):
    """Where sessions are recorded, when a directory is configured.

    `directory` absent -- `None`, or the empty string a configuration key
    that is present and blank produces -- is recording switched off:
    `enabled` is False, `open` answers None, no directory is created and
    no byte is written. That is the default, and it is one answer for the
    whole deployment rather than one per identity, because "is this
    engagement recorded" is how the question is actually asked.

    When it is on, one session is one `<identity>/<when>-<n>.typescript`
    under this directory, created 0600 in directories created 0700, with a
    `.json` sibling written at the close carrying `identity`, `session`,
    `peer`, `started`, `ended`, `bytes`, `truncated`, `reason` and
    `stopped`. `bytes` is what the transcript holds -- the file's own
    size -- `truncated` says whether the session had more to show than
    that, `reason` is why the session ended and `stopped` is why the
    recording stopped short of it, or None when it did not.

    **A transcript with no `.json` beside it is an interrupted session.**
    The sidecar is written when the recording closes, so a team server
    that was killed mid-session leaves the bytes that had been flushed
    and nothing to describe them. That is the intended trade -- the
    alternative is rewriting the sidecar on every chunk -- but whoever
    reads one of these directories should know that the absence means
    "cut off", not "empty".

    One directory this module did not create is one it does not own:
    an operator who ran `mkdir -p` before setting the key, or a path
    shared with something else. Such a directory is verified rather than
    assumed. A symlink is refused outright and costs the recording; a
    real directory wider than 0700 is kept, used and logged once naming
    it and the mode found, because silently `chmod`-ing an operator's
    directory is a surprise in the wrong direction. The transcripts
    inside are 0600 either way; what a wide directory leaks is which
    builds were attached to and when.

    `max_bytes` is the per-session ceiling. A parameter so that a test can
    reach it without pushing 16 MiB through a session; nothing in
    production passes it.
    """

    def __init__(self, directory=None, *,
                 max_bytes: int = TRANSCRIPT_MAX_BYTES):
        self.directory = (os.path.abspath(os.fspath(directory))
                          if directory else None)  # type: Optional[str]
        self.enabled = self.directory is not None
        self.max_bytes = int(max_bytes)
        if self.max_bytes < 1:
            raise ValueError("max_bytes must be at least 1, got %r"
                             % (max_bytes,))

    def open(self, identity: str, session: int,
             peer: str) -> Optional[Recorder]:
        """A recorder for one session, or None if nothing will be recorded.

        Never raises, and that covers building the path as well as using
        it: a directory that cannot be created, one that turns out to be
        a symlink, a name already taken, a file that cannot be opened.
        Each costs this recording, is logged once with its reason, and
        leaves the caller a None it can carry a session with. The
        operator's shell must not die because a log file could not be
        opened.
        """
        if self.directory is None:
            return None
        started = time.time()
        # Named in the warning below if the path cannot even be built, so
        # that the reason is never a `NameError` about a missing local.
        folder = path = self.directory
        try:
            folder = os.path.join(self.directory, _folder_name(identity))
            # Basic ISO-8601 rather than extended: a colon is hostile in a
            # filename on one of the filesystems an engagement's evidence
            # gets copied to, and awkward in every shell. The sidecar's
            # own `started` is the extended spelling, for reading.
            path = os.path.join(folder, "%s-%d.typescript" % (
                time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(started)),
                session))
            # The configured root first and the identity folder second,
            # rather than one call for the leaf: the root is the component
            # most likely to exist already, and therefore the one whose
            # mode has to be checked rather than assumed. Verification
            # starts there and not above it -- `/var/log` is 0755 on every
            # host and saying so would be noise, not a finding.
            _private_dir(self.directory)
            _private_dir(folder)
            # `O_EXCL`, so a name already taken is a refusal and never an
            # overwrite: the one file this must not damage is a transcript
            # somebody already has. `O_NOFOLLOW` beside it for the same
            # reason `_write_operator_token` in `c2/server.py` carries
            # one -- a link planted in place of the name is refused rather
            # than written through, and `O_EXCL` alone only covers the
            # final component. 0600 from the instant it exists rather than
            # tightened afterwards.
            descriptor = os.open(path,
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | getattr(os, "O_NOFOLLOW", 0),
                                 _FILE_MODE)
            handle = os.fdopen(descriptor, "wb")
        except Exception as exc:
            logger.warning("shell: %r's session %d for %s is not being "
                           "recorded: %s could not be opened: %s",
                           identity, session, peer, path, exc)
            return None
        logger.info("shell: recording %r's session %d for %s to %s",
                    identity, session, peer, path)
        return Recorder(path, handle, {
            "identity": str(identity),
            "session": int(session),
            "peer": str(peer),
            "started": _stamp(started),
        }, self.max_bytes)


def _folder_name(identity: str) -> str:
    """One path component for a build identity, whatever it is made of.

    An identity is an operator-chosen string, and this is the only place
    one becomes a path: `../..` and a leading dot are flattened rather
    than trusted. Two identities can therefore share a folder, which is
    the lesser of the two evils and costs nothing a reader needs -- every
    sidecar in it carries the identity verbatim.
    """
    flat = _UNSAFE_NAME.sub("_", str(identity)).lstrip(".")
    return flat or "unnamed"


def _private_dir(path: str) -> None:
    """Make `path` exist as a 0700 directory, or say why it is not one.

    Not `os.makedirs(mode=_DIR_MODE)`: that applies the mode to the leaf
    alone and leaves any parent it had to create at the process umask,
    which for this tree would be 0600 transcripts under a directory
    anybody can list.

    A component that already exists is one this module did not make, so
    it is verified rather than assumed -- see `_verify_private_dir` for
    which of the two outcomes each kind gets. The old behaviour here was
    to swallow `FileExistsError` and carry on, which made "directories
    0700" quietly untrue for the most ordinary case there is: an operator
    who ran `mkdir -p` before setting the key.
    """
    parent = os.path.dirname(path)
    if parent and parent != path and not os.path.isdir(parent):
        _private_dir(parent)
    try:
        os.mkdir(path, _DIR_MODE)
        return
    except FileExistsError:
        pass
    _verify_private_dir(path)


def _verify_private_dir(path: str) -> None:
    """Check a directory this module found rather than created.

    `os.lstat`, not `os.stat`: the question is what this name *is*, and
    following it would answer about the target instead.

    A symlink is refused, and that is deliberately not a warning. A
    planted directory symlink is not a mode an operator chose, and
    writing a 0600 transcript through one would put an engagement's
    evidence wherever the link points; `O_NOFOLLOW` on the transcript
    itself only covers the final component, so the components above it
    are checked here. Anything that exists and is not a directory is
    refused for the same reason.

    A real directory wider than 0700 is kept, used, and logged once
    naming it and the mode found. Not tightened: it may be a directory an
    operator created, or one shared with something else, and a recorder
    that silently `chmod`s somebody's directory is a worse surprise than
    a wide one it told them about. The transcripts in it are 0600
    regardless; what leaks is the identity folders and the session
    filenames -- which builds were attached to, and when.
    """
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        raise OSError("%s is a symbolic link, and a transcript is not "
                      "written through one" % path)
    if not stat.S_ISDIR(info.st_mode):
        raise OSError("%s already exists and is not a directory" % path)
    mode = stat.S_IMODE(info.st_mode)
    if mode & ~_DIR_MODE:
        logger.warning(
            "shell: %s already existed as mode 0%o, which is wider than "
            "the 0%o this module creates, so the identity folders and "
            "transcript names under it can be listed by others. The "
            "transcripts themselves are still 0%o. This is not a directory "
            "this module made, so its mode is yours to change: "
            "chmod 0%o %s", path, mode, _DIR_MODE, _FILE_MODE, _DIR_MODE,
            path)


def _write_private_json(path: str, document: dict) -> None:
    """Write one small JSON file 0600: all of it, or none of it.

    A scratch file in the same directory, created 0600, fsynced and moved
    over the target -- the shape `keys.py` writes the key store with, for
    the same two reasons. Whoever reads a sidecar never sees half of one,
    and the file is private from the instant it exists. `O_NOFOLLOW` as
    well, because the directory this lands in is not always one this
    module created: see `_verify_private_dir`.
    """
    data = (json.dumps(document, indent=2, sort_keys=True)
            + "\n").encode("utf-8")
    directory, name = os.path.split(path)
    scratch = os.path.join(directory,
                           ".%s.%s.tmp" % (name, os.urandom(6).hex()))
    descriptor = os.open(scratch, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), _FILE_MODE)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(scratch, path)
    finally:
        try:
            os.unlink(scratch)
        except FileNotFoundError:
            pass


def _stamp(when: float) -> str:
    """One instant, UTC, as the key store spells its own timestamps."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(when))


class ShellFront(object):
    """The operator-facing shell listener for one endpoint identity.

    `tunnel_server` is anything with `open_shell_session(identity, cols,
    rows)` returning a session that has `wait_paired(timeout)`, `sock` and
    `close()` -- in production that is `TunnelServer`.

    `bind_port` is the port this identity owns in the tunnel server's
    shell port table. 0 binds an ephemeral port, which is what the tests
    use; `port` reports what was actually bound.

    `transcripts` is a `Transcripts`, or None for a deployment that
    records nothing. Only the output direction of a session is recorded,
    and only from its pairing onward: see the module docstring.
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
        # has no use for, so the floor is the session cap -- but four,
        # which is what the endpoint will carry, is far too few to bound
        # the pre-auth exposure with: four silent loopback sockets would
        # then be able to turn the operator's own attach away for a whole
        # handshake timeout. `SocksFront` inherits no such problem,
        # because its cap is 256. Eight is a cheap floor: a handshake
        # costs a thread and a socket until it is refused.
        self.max_pending = (max(self.max_sessions, _MIN_PENDING)
                            if max_pending is None else int(max_pending))
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
        # The number in a transcript's name: the nth session this port has
        # started recording. Not in `stats`, which is the SOCKS row's
        # shape and read generically by the panel; this is here so that two
        # sessions paired in the same second are still two files.
        self._recorded = 0
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
            shut(client)
        for worker in workers:
            worker.join(timeout=_JOIN_TIMEOUT)

    def is_serving(self) -> bool:
        return self._listener is not None

    # ── what the panel reads ──

    def stats(self) -> dict:
        """One row's worth of what this port has done.

        The same keys as `SocksFront.stats`, and deliberately so: the
        operator panel's row reads the two generically -- `refused` is the
        total and every `refused_<why>` is one kind of it, discovered by
        prefix rather than named -- so a shell row that spelled any of
        this differently would be a second rendering to write and a second
        one to keep right.

        `accepted` counts connections and the `refused_*` counters count
        the ones this port turned away; a client that vanished at the
        prompt is neither, so the three do not have to add up. `bytes_out`
        is toward the implant's terminal and `bytes_in` is back from it,
        both plaintext and both for the life of this object.

        The refusal keys are deliberately not interchangeable, because an
        operator who cannot attach has to be able to tell which of these
        it was:

        * `refused_auth` -- nobody proved they were the operator: a wrong
          password, an empty answer, or a line past its bound.
        * `refused_capacity` -- `max_sessions`, which is this port already
          carrying all the terminals it will hold.
        * `refused_pending` -- `max_pending`, more handshakes in flight
          than this port will hold open at once.
        * `refused_threads` -- no thread could be started, which is the
          process as a whole out of room rather than either cap.
        * `refused_timeout` -- a handshake cut off at its deadline: a
          password line that never arrived, or a prompt this client would
          not read. Counted because it was ended deliberately, not lost.
        * `refused_tunnel` -- there is no endpoint to carry it, or it never
          dialled back.
        * `refused_unsupported` -- the endpoint is connected but advertised
          no `shell` feature, which is a build older than this feature and
          a different thing to do about it than a tunnel that is down.
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
            # The auth line's reads and nothing else: the prompt's write
            # has its own arm in `_handle`, and `_read_line` gives each of
            # its reads no more than the deadline has left. So this is the
            # deadline and not a per-read stall.
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
            finish(conn)

    def _handle(self, conn: socket.socket, peer: str,
                deadline: float) -> None:
        try:
            _say(conn, PROMPT)
        except socket.timeout:
            # Its own arm, because `socket.timeout` is an `OSError` and
            # this one is not the line's deadline: this client is not
            # reading ten bytes, so telling it that no password line
            # arrived would be the wrong reason, and writing a refusal to
            # a socket that has just proved it is not read would only buy
            # another stall. Counted, because it was ended here.
            logger.warning("shell: %s would not read the prompt within "
                           "%.1fs; closed", peer, _SAY_TIMEOUT)
            self._refused("timeout")
            return
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
            # The discriminator is an attribute the tunnel server sets on
            # the one refusal that means "this build cannot do it", not a
            # phrase in the text: an identity is an operator-chosen string
            # that any word could appear in, and reading the reason out of
            # the wording would misclassify a *different* refusal whose
            # text happens to quote such an identity. An attribute rather
            # than an exception type imported from there, because this
            # port holds its tunnel server as a duck-typed collaborator.
            why = ("unsupported" if getattr(exc, "shell_unsupported", False)
                   else "tunnel")
            logger.warning("shell: %s asked %r for a terminal and there is "
                           "none to give: %s", peer, self.identity, reason)
            self._refuse(conn, reason, why)
            return
        with self._lock:
            self._sessions.add(session)
        try:
            if self._stopping.is_set():
                # `stop` takes its list of sessions to close under the
                # lock, so one added after that snapshot has nobody to
                # close it: without this check a connection caught between
                # `open_shell_session` returning and the add above would
                # sit out the whole pair timeout after `stop` had returned.
                logger.debug("shell: %r stopped while a session for %s was "
                             "being opened; dropped it", self.identity, peer)
                return
            if not session.wait_paired(_PAIR_TIMEOUT):
                logger.warning("shell: %r did not open a terminal within "
                               "%.1fs; refused %s", self.identity,
                               _PAIR_TIMEOUT, peer)
                self._refuse(conn, "the endpoint for %r did not open a "
                                   "terminal within %.1f seconds."
                             % (self.identity, _PAIR_TIMEOUT), "tunnel")
                return
            logger.info("shell: %s is attached to %r, %dx%d", peer,
                        self.identity, cols, rows)
            self._pump(conn, session.sock, pipelined, peer)
        finally:
            with self._lock:
                self._sessions.discard(session)
            session.close()

    def _pump(self, conn: socket.socket, stream, pipelined: bytes,
              peer: str) -> None:
        """Carry bytes until either side is finished.

        Both descriptors lose their timeout here. The auth line had a
        deadline because a client that connects and says nothing must not
        hold a thread, but an idle *session* is the normal state of a
        shell -- a prompt waiting to be typed at, a capture running for an
        hour -- and a timeout on this loop would drop it. `stop` unparks
        both directions by shutting their descriptors down instead.

        This thread owns the operator-to-terminal direction and a second
        one owns the other, so each socket has exactly one writer: no
        refusal is ever written once that second thread is running, which
        is what makes that hold. Whichever direction ends first ends the
        session, because the operator's terminal must not be left attached
        to a shell that has exited.

        `carried` is counted here and not at the pairing, so that it means
        a session that actually ran in both directions.
        """
        conn.settimeout(None)
        stream.settimeout(None)
        back = threading.Thread(target=self._downstream,
                                args=(conn, stream, peer),
                                name="shell-relay", daemon=True)
        try:
            self._start(back)
        except RuntimeError as exc:
            # No thread for the output direction. A terminal that cannot
            # show what the shell says is worse than none, so the session
            # ends -- but it is refused in text and counted like the
            # accept loop's twin branch, rather than closed silently: the
            # one thing this port must never do is leave the operator
            # unable to tell a refusal from a dead tunnel. `back` never
            # started, so this thread is still the only writer on `conn`.
            logger.warning("shell: %r could not start the output direction "
                           "of a session; closing it: %s", self.identity, exc)
            self._refuse(conn, "this team server has no thread left for the "
                               "output half of a shell session, so the "
                               "session was closed rather than run one way. "
                               "Something else on it is holding far more "
                               "than it should.", "threads")
            return
        with self._lock:
            self._carried += 1
        try:
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
            self._upstream(conn, stream)
        finally:
            # Shut both descriptors before the join: the other thread may
            # be parked in a read or in a send that TCP backpressure has
            # stopped, and neither wakes on its own.
            stream.close()
            shutdown_both(conn)
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

    def _downstream(self, conn: socket.socket, stream, peer: str) -> None:
        """What the terminal prints, back to the operator -- and recorded.

        The transcript is opened here and closed here, on the one thread
        that writes to it. This direction is all a transcript holds, and a
        recorder that is created and destroyed by the thread that owns it
        has no lifetime for anything else to get wrong. It is opened after
        the pairing, which is after the password line was read and
        compared, so the attach password cannot reach a transcript.
        """
        recorder = self._record(peer)
        # A default, so that this is still answerable if the loop below
        # leaves by a way it has no name for.
        reason = "the output direction of the session ended"
        try:
            reason = self._downstream_loop(conn, stream, recorder)
        finally:
            try:
                if recorder is not None:
                    recorder.close(reason)
            finally:
                # This direction ending means the shell has gone, so the
                # session goes with it: the operator's client is sent the
                # FIN it is waiting for and the other direction's blocked
                # `recv` is unparked.
                #
                # In a `finally` of its own so that the ordering and the
                # guarantee can both hold at once. The transcript is
                # closed first, because its sidecar is what a reader comes
                # back for and it should be on the disk before the session
                # is let go of; and the session is torn down regardless of
                # what closing the transcript did. `Recorder.close` is
                # written not to raise, and this is what makes that a
                # property of the session rather than a promise one class
                # makes about itself.
                stream.close()
                shutdown_both(conn)

    def _record(self, peer: str) -> Optional[Recorder]:
        """A recorder for one session's output, or None for no recording.

        None is the ordinary answer: recording is off unless a directory
        was configured, and `Transcripts.open` answers None for every
        failure it meets as well.
        """
        transcripts = self._transcripts
        if transcripts is None:
            return None
        with self._lock:
            self._recorded += 1
            number = self._recorded
        try:
            return transcripts.open(self.identity, number, peer)
        except Exception:
            # Belt and braces: `Transcripts.open` reports its own
            # failures, so reaching here is the object this port was
            # handed rather than a disk that filled. Even that costs the
            # recording and never the operator's shell.
            logger.exception("shell: %r's session %d could not be recorded",
                             self.identity, number)
            return None

    def _downstream_loop(self, conn: socket.socket, stream,
                         recorder: Optional[Recorder]) -> str:
        """Carry this direction until it ends, and say why it ended."""
        while True:
            try:
                data = stream.recv(_CHUNK)
            except ValueError:
                # A frame that did not authenticate. `RelayStream` has
                # already closed itself over it, per Noise §5.1.
                logger.warning("shell: a frame for %r did not authenticate; "
                               "the session is over", self.identity)
                return "a frame of this session did not authenticate"
            except OSError:
                return "the terminal's stream ended"
            # `b""` is the far end finished, and which of the three ways it
            # finished -- an orderly teardown, a truncated frame, a dead
            # socket -- is not knowable here, nor worth knowing: the one
            # thing to do about any of them is to end the session.
            if not data:
                return "the terminal closed"
            try:
                conn.sendall(data)
            except OSError:
                return "the operator's connection ended"
            with self._lock:
                self._bytes_in += len(data)
            if recorder is not None:
                # After the send, so a transcript is what the operator's
                # terminal was shown, and outside the lock, because a disk
                # write under it would serialise every session on this
                # port behind this one.
                #
                # Unguarded here because `Recorder.write` guards itself as
                # a whole: anything that goes wrong inside it sets the
                # recorder aside and returns. A `try` around this call
                # could not do better -- it could not drop the recorder
                # without also losing the reference this session's
                # teardown needs to close it and write its sidecar.
                recorder.write(data)

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
    shut(sock)


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
