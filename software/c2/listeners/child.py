"""The process discipline two supervisors share, and nothing else.

`listeners/supervisor.py` owns the listener processes and
`tunnel/supervisor.py` owns the tunnel-server process. They are separate
state machines on purpose -- one keeps a table of named children and the
other keeps exactly one, they read different configuration, and only one
of them has a `ListenerSpec` -- but the mechanics of *being* a supervised
child are identical, and were briefly copied: spawn it with its stderr on
a file, read the one `control-port <n>` line it prints, SIGTERM then
SIGKILL then reap, and ask it for its status over its loopback control
socket.

Two copies of that had already drifted within a single commit, and in
both cases the better version was the one fewer people read. So it lives
here once.

**This module imports no listener and no transport.** It is in this
package beside `errors.py`, which is here for the same reason: a module
that `tunnel/supervisor.py` may import must not have to reach
`supervisor` to be reached, because `supervisor` pulls in `registry` and
`registry` imports all three listener classes -- so the DNS parser, the
QUIC reassembler and the hand-written SMB2 parser would come with it. A
module anything may import must therefore import nothing from this
package, and this one imports nothing at all beyond the standard library
and `errors`. `test_child_can_be_imported_without_loading_a_listener`
holds that.

**What that property is, exactly, because the obvious reading is too
strong.** It is not a claim that a tunnel-only deployment loads no
protocol parser. `_build_supervisor` in `server.py` imports
`listeners.registry` whenever `--config` is given, and a `--config` is
what configures a tunnel server, so the three parsers are loaded in
every deployment that can have one. The property is about this module's
own import graph: anything in the tree can import it without acquiring a
transport, which is what makes it safe to share between two supervisors
that know nothing about each other.

Three properties the callers depend on, each learned from a failure:

  * **Every refusal carries a reason, and the child's own words.** A
    child that fails to start is reported with what it put on stderr, not
    with the fact that it is not running: "address already in use" is the
    one thing that tells an operator what to do about it.
  * **A child that exited and a child that is alive and silent are
    different faults.** Both produce no line to read, and saying "did not
    come up within 20s" about a process that exited in half a second
    sends the reader looking for a slow machine.
  * **No child is left behind.** `terminate` reaps, because an unreaped
    child is a zombie whose pid still answers `kill -0`, and a status
    would keep reporting it as running.
"""

import json
import os
import socket
import subprocess
import tempfile
import threading
from typing import Optional

from .errors import SupervisorError

__all__ = ["SupervisedChild", "launch", "read_control_port",
           "read_line_with_timeout", "tail", "discard", "kill",
           "TERM_GRACE", "CONTROL_TIMEOUT"]

# SIGTERM, then this long, then SIGKILL. A child's own shutdown closes its
# sockets and joins its threads, which is quick; one that needs longer is
# wedged, and leaving it running would hold its port against the next
# start. Both supervisors keep their own copy of this value so that a test
# can patch it in the module it is testing -- see `SupervisedChild.
# term_grace`.
TERM_GRACE = 5.0

CONTROL_TIMEOUT = 5.0

# How much of one control reply is read before giving up on it. The
# default suits a listener's handful of counters; a supervisor whose child
# answers with a row per endpoint raises it on its own subclass.
MAX_REPLY = 1 << 16

# One recv at a time. Deliberately not the reply cap: a cap is a bound on
# a pathology, and this is the ordinary read size.
_CHUNK = 4096


class SupervisedChild(object):
    """One supervised process, and what is known about how it ended.

    Subclasses add exactly two things: how to build the command line, and
    which timeouts to read. Everything below is the same whatever the
    child is.
    """

    # How much of one reply is read before the read gives up on finding a
    # newline. A class attribute so a child that answers with more than a
    # listener's handful of counters can raise it.
    max_reply = MAX_REPLY

    def __init__(self, process, control_port, stderr_path, owned=False):
        self.process = process
        self.control_port = control_port
        self.stderr_path = stderr_path
        self.pid = process.pid
        # Whether this object created the stderr file and may therefore
        # delete it. False by default, and false for a child built around
        # a path the caller chose -- a test hands `os.devnull`, and a
        # teardown that unlinked it would be a memorable afternoon.
        self._owned = owned

    # ── the timeouts, as methods ──

    def term_grace(self):
        """How long SIGTERM is given before SIGKILL.

        A method rather than a constant read at import, so a subclass can
        resolve it from its own module when it is asked. That is what
        makes `patch.object(supervisor, "_TERM_GRACE", 1.0)` reach the
        escalation it is testing; a module-level read here would quietly
        ignore it and the test would pass having held nothing.
        """
        return TERM_GRACE

    def control_timeout(self):
        return CONTROL_TIMEOUT

    # ── state ──

    def alive(self) -> bool:
        return self.process.poll() is None

    def reap(self) -> None:
        """Collect a child that has already exited, and drop its log."""
        try:
            self.process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass
        self.discard()

    def death_detail(self) -> str:
        code = self.process.returncode
        if code is None:
            return "exit status unknown"
        reason = describe_exit(code)
        text = tail(self.stderr_path)
        return "%s; its output was: %s" % (reason, text) if text else reason

    def terminate(self) -> None:
        """SIGTERM, then SIGKILL, then reap. No child is left behind.

        Reaped rather than merely signalled: an unreaped child is a
        zombie, its pid still answers `kill -0`, and a status would keep
        reporting it as running.
        """
        grace = self.term_grace()
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                self.process.kill()
                try:
                    self.process.wait(timeout=grace)
                except subprocess.TimeoutExpired:
                    pass
        _close(self.process)
        self.discard()

    def discard(self) -> None:
        """Remove the stderr file, if this object made it.

        Called from every path that is finished with a child. Without it
        each start leaves a `*.log` in the system temporary directory for
        ever -- a few per test run, one per restart in production.
        """
        if not self._owned or not self.stderr_path:
            return
        discard(self.stderr_path)
        self._owned = False

    def ask_status(self, token: str) -> Optional[dict]:
        """One question over the control socket, or None if unanswered."""
        if self.control_port is None:
            return None
        timeout = self.control_timeout()
        try:
            with socket.create_connection(("127.0.0.1", self.control_port),
                                          timeout=timeout) as sock:
                sock.sendall(json.dumps({"token": token,
                                         "verb": "status"}).encode() + b"\n")
                sock.settimeout(timeout)
                raw = b""
                while b"\n" not in raw and len(raw) < self.max_reply:
                    chunk = sock.recv(_CHUNK)
                    if not chunk:
                        break
                    raw += chunk
        except (OSError, socket.timeout):
            return None
        try:
            answer = json.loads(raw.split(b"\n", 1)[0] or b"{}")
        except ValueError:
            return None
        return answer if isinstance(answer, dict) and "error" not in answer \
            else None


def launch(command, cwd, env, prefix):
    """Start `command` and return `(process, stderr_path)`.

    stderr goes to a file rather than a pipe. A pipe nobody drains fills
    its buffer and then blocks the child mid-log, which looks exactly
    like a child that hung.
    """
    handle = tempfile.NamedTemporaryFile(prefix=prefix, suffix=".log",
                                         delete=False)
    process = subprocess.Popen(
        command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=handle,
        stdin=subprocess.DEVNULL, text=True)
    handle.close()
    return process, handle.name


def read_control_port(process, stderr_path, what, timeout):
    """Read the one line the child prints, or raise with its stderr.

    `what` names the child in the refusal, because the message is what a
    panel shows: "listener 'dns-53'" or "the tunnel server".
    """
    line, parked = _read_line(process.stdout, timeout)
    if line is None:
        # A child that exited and one that is alive and silent are the
        # same `None` here and are not the same fault, so they are not
        # reported in the same words: a start refused in half a second
        # that says "did not come up within 20s" sends the reader looking
        # for a slow machine.
        code = process.poll()
        # `parked` is why this is not simply `kill(process)`. A reader
        # thread still blocked on `readline` holds the buffered stream's
        # lock, and `close()` waits for that lock -- so closing here
        # would block until whatever still holds the write end lets go.
        # A `/bin/sh` wrapper killed while a `sleep` grandchild keeps the
        # pipe open is exactly that, and it blocked a listener test for
        # the full sixty seconds of the sleep. When the read *did* finish
        # the thread is gone and the pipe is closed properly, which is
        # what keeps a give-up path from leaking it.
        kill(process, close_stdout=not parked)
        if code is not None:
            raise SupervisorError(
                "%s exited before it could serve (%s). Its output was: %s"
                % (what, describe_exit(code), tail(stderr_path)))
        raise SupervisorError(
            "%s did not come up within %gs. Its output was: %s"
            % (what, timeout, tail(stderr_path)))
    if not line.startswith("control-port "):
        kill(process)
        raise SupervisorError(
            "%s printed %r instead of its control port. Its output was: %s"
            % (what, line[:120], tail(stderr_path)))
    value = line.split(" ", 1)[1].strip()
    if value == "none":
        return None
    try:
        return int(value)
    except ValueError:
        kill(process)
        raise SupervisorError(
            "%s printed an unreadable control port %r" % (what, value))


def read_line_with_timeout(stream, timeout):
    """Read one line, giving up after `timeout`.

    A blocking readline on a child that never prints would hang the team
    server, so the read happens on a thread the caller can abandon. The
    thread is a daemon: if the child is killed its stdout closes and the
    read returns, and if it is not, the thread costs nothing.
    """
    return _read_line(stream, timeout)[0]


def _read_line(stream, timeout):
    """`(line_or_None, parked)` -- the line, and whether the reader is stuck.

    `parked` is True when the wait ran out with the thread still inside
    `readline`, which is the one state in which the stream must not be
    closed. See `read_control_port`.
    """
    if stream is None:
        return None, False
    out = {}

    def _read():
        try:
            out["line"] = stream.readline()
        except (OSError, ValueError):
            out["line"] = ""

    worker = threading.Thread(target=_read, daemon=True)
    worker.start()
    worker.join(timeout)
    parked = worker.is_alive()
    line = out.get("line")
    if not line:
        return None, parked
    return line.strip(), parked


def describe_exit(code) -> str:
    """How a finished child is named in a panel's detail line.

    The wording is `listeners/supervisor.py`'s, kept to the letter: it is
    what `death_detail` has always produced and what an operator reading
    a dead row sees.
    """
    if code is None:
        return "exit status unknown"
    if code < 0:
        return "exited on signal %d" % -code
    return "exit code %d" % code


def tail(path, limit=400):
    try:
        with open(path) as handle:
            text = handle.read()
    except OSError:
        return ""
    text = " ".join(text.split())
    return text[-limit:]


def discard(path):
    """Remove a child's stderr log. Used where no object owns it yet.

    A spawn that is refused has already put the file's contents into the
    exception, and nothing will read it again -- without this each
    refused start leaves one behind in the system temporary directory for
    ever.
    """
    try:
        os.unlink(path)
    except OSError:
        pass


def kill(process, close_stdout=True):
    """Give up on a child: SIGKILL, reap, and close its pipe.

    `close_stdout=False` for the one caller that must not -- a reader
    thread parked inside `readline` holds the stream's lock, and `close`
    waits for it. See `read_control_port`.
    """
    try:
        process.kill()
        process.wait(timeout=5.0)
    except Exception:
        pass
    if close_stdout:
        _close(process)


def _close(process):
    """Close the child's stdout pipe.

    Every path that gives up on a child goes through `kill` or
    `terminate`, and a pipe left open is a `ResourceWarning` in whatever
    test happens to run next.
    """
    if getattr(process, "stdout", None) is None:
        return
    try:
        process.stdout.close()
    except (OSError, ValueError):
        pass
