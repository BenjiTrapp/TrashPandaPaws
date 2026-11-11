#!/usr/bin/env python3
"""
Unit tests for `tools/raccoon_shell.py`, the client an operator attaches
their terminal to a shell port with.

Four things these tests are careful about.

**The wire is written as literals, and checked against the port's own
parser.** The fake port here writes `b"password: "` and reads one line,
because that is what `software/c2/tunnel/shell.py` does -- and the line
the client sends is then handed to that module's real `parse_auth_line`.
So these tests fail if the client stops speaking the wire *or* if the two
ends stop agreeing about it, which is the failure a mock of either side
could not see. The full port, with a real endpoint behind it, is
`test_tunnel_shell.py`'s subject and is not repeated here.

**`sys.stdin` and `sys.stdout` are pipes, not a terminal.** That is what
makes a client that owns a terminal testable at all: the keystrokes are
written into a pipe and what the terminal was shown is read back out of
another. It is also a real limit, so it is stated rather than implied --
with a pipe for stdin, `isatty()` is False, so **in every end-to-end test
below the raw-mode path is skipped, no `SIGWINCH` handler is installed,
and neither is exercised.** What that leaves unverified is covered as far
as it can be: `RawTerminalTests` puts a real pty through `raw_terminal`
and reads the terminal's modes back with `termios`, including after an
exception inside the session, because a client that exits leaving the
operator's terminal in raw mode is the one bug nobody forgives. What
stays unverified here is the resize note -- it needs a `SIGWINCH` at a
terminal -- and the `getpass` prompt, which by design reads from
`/dev/tty` and not from this process's stdin.

**A refusal is read where an operator reads it.** The port answers a
wrong password, a full port or a dead tunnel with one line of plain text
and then a close, so each refusal test asserts the text reached stderr,
asserts it was *not* written into the terminal as though it were shell
output, and asserts the exit code is not zero.

**The password is never on a command line.** One test asserts the
environment is what is read, and that a third positional argument is a
usage error -- there is nowhere for a password to go on this client's
command line, which is the point.
"""

import io
import os
import select
import socket
import sys
import termios
import threading
import time
import traceback
import unittest

from software.c2.tunnel import shell as shell_mod
from tools import raccoon_shell

_LOOPBACK = "127.0.0.1"

# The port's own prompt, as a literal. Asserted against `shell.PROMPT` in
# `test_it_sends_the_password_and_the_local_geometry`, so that a change to
# one end is noticed here rather than in an engagement.
_PROMPT = b"password: "

# Two of the port's refusals, verbatim: one it sends after reading a
# password line, and one its accept loop sends before it has prompted at
# all. The second is the shape a client gets wrong by assuming the first
# thing it reads is a prompt.
_WRONG_PASSWORD = b"raccoon: that is not the password for this shell port.\r\n"
_TOO_BUSY = (b"raccoon: this shell port already has 8 attach attempts in "
             b"flight, which is all it will hold at once. Try again in a "
             b"moment.\r\n")

# What the fake port says when it has paired a terminal. Not a prompt the
# client knows anything about -- it is the first bytes of a shell.
_SHELL_PROMPT = b"root@implant:~# "


def _paired_then_closed(conn, port):
    """A terminal that says one thing, and then its stream ends."""
    conn.sendall(_SHELL_PROMPT)


def _paired_then_echoes(conn, port):
    """A terminal that echoes in upper case until the client is done.

    Upper case so that what comes back out of the client's stdout is
    distinguishable from what the test wrote into its stdin: a loop that
    showed the operator their own keystrokes would otherwise pass.
    """
    conn.sendall(_SHELL_PROMPT)
    for data in _typed(conn, port.pipelined):
        port.received += data
        conn.sendall(data.upper())


def _typed(conn, pipelined):
    """What the client sent, starting with whatever was pipelined.

    Bytes that arrived in the same segment as the auth line are already
    input for the terminal -- a client is free to send its first
    keystrokes behind the newline, and the real port keeps them for that
    reason rather than dropping them. Which segment they arrive in is a
    race, so both are the same thing here.
    """
    if pipelined:
        yield pipelined
    while True:
        data = conn.recv(4096)
        if not data:
            return
        yield data


def _refuses(conn, port):
    """One line of plain text, and then the close that follows it."""
    conn.sendall(_WRONG_PASSWORD)


class _FakePort(object):
    """The shell port's wire on an ephemeral loopback port, scripted.

    One connection: the greeting, one line read and kept, then `session`
    -- a callable handed the socket and this object. The socket is closed
    when that returns, which is the close every one of the port's own
    endings has.

    `expect_line` is False for the refusals the port's accept loop sends
    before it prompts: there is no line to read, and whether the client
    sent its password to a port that had already refused it is then
    answerable by `line` being None.

    Anything this fake raises is kept and re-raised by `stop`, so a fake
    that died does not show up as a mysterious client failure.
    """

    def __init__(self, session, greeting=_PROMPT, expect_line=True):
        self.line = None            # the auth line, without its newline
        self.pipelined = None       # whatever arrived in the same segment
        self.received = b""         # terminal bytes the client sent
        self.failure = None
        self._session = session
        self._greeting = greeting
        self._expect_line = expect_line
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((_LOOPBACK, 0))
        self._listener.listen(1)
        self._listener.settimeout(10.0)
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve,
                                        name="fake-shell-port", daemon=True)
        self._thread.start()

    def stop(self):
        """Join the fake, and fail the test with whatever it raised."""
        self._thread.join(timeout=10.0)
        self.close()
        if self._thread.is_alive():
            raise AssertionError("the fake shell port is still serving")
        if self.failure is not None:
            raise AssertionError("the fake shell port raised:\n%s"
                                 % self.failure)

    def close(self):
        """Stop listening. Safe twice, and safe before anything connected."""
        self._listener.close()

    def _serve(self):
        try:
            conn, _ = self._listener.accept()
            try:
                # A bound on every read, so a client that never says
                # anything costs this fake ten seconds and not a hung
                # suite.
                conn.settimeout(10.0)
                conn.sendall(self._greeting)
                if self._expect_line:
                    have = b""
                    while b"\n" not in have:
                        chunk = conn.recv(4096)
                        if not chunk:
                            return
                        have += chunk
                    self.line, _, self.pipelined = have.partition(b"\n")
                    self._session(conn, self)
            finally:
                conn.close()
        except Exception:
            self.failure = traceback.format_exc()


class ShellClientTests(unittest.TestCase):
    """One attach each, against a fake port and through two pipes."""

    def setUp(self):
        self.errors = io.StringIO()
        self._patch(sys, "stderr", self.errors)
        # Nothing here may fall back to the real terminal's size, and
        # nothing may read a password from one either: both are set per
        # test, and cleared here so that a missing one is a failure rather
        # than a pass that depended on this machine.
        for name in ("RACCOON_SHELL_PASSWORD", "COLUMNS", "LINES"):
            self._unset(name)
        self._shown_fd = None

    # ── the fixtures ──

    def _patch(self, obj, name, value):
        saved = getattr(obj, name)
        self.addCleanup(setattr, obj, name, saved)
        setattr(obj, name, value)

    def _env(self, name, value):
        self._remember(name)
        os.environ[name] = value

    def _unset(self, name):
        self._remember(name)
        os.environ.pop(name, None)

    def _remember(self, name):
        saved = os.environ.get(name)
        if saved is None:
            self.addCleanup(os.environ.pop, name, None)
        else:
            self.addCleanup(os.environ.__setitem__, name, saved)

    def _port(self, session, **kwargs):
        port = _FakePort(session, **kwargs)
        self.addCleanup(port.close)
        return port

    def _terminal(self, typed=b""):
        """A stdin and a stdout that are pipes rather than a terminal.

        `typed` is what the operator typed, and the write end is closed
        behind it: stdin then ends, which is what makes each of these
        tests finish on its own rather than on a timeout. A real terminal
        does not end, so this is the one place the fixture is unlike the
        thing it stands in for.
        """
        keys_r, keys_w = os.pipe()
        shown_r, shown_w = os.pipe()
        if typed:
            os.write(keys_w, typed)
        os.close(keys_w)
        stdin = os.fdopen(keys_r, "rb", 0)
        stdout = os.fdopen(shown_w, "wb", 0)
        self.addCleanup(stdin.close)
        self.addCleanup(stdout.close)
        self.addCleanup(os.close, shown_r)
        self._patch(sys, "stdin", stdin)
        self._patch(sys, "stdout", stdout)
        self._shown_fd = shown_r

    def _shown(self, timeout=2.0):
        """Everything the client wrote to its terminal.

        Read once `main` has returned, so what is in the pipe is all of
        it: the timeout bounds a client that wrote nothing, it is not a
        wait for one that is still writing.
        """
        chunks = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not select.select([self._shown_fd], [], [], 0.05)[0]:
                break
            chunk = os.read(self._shown_fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    def _attach(self, port, *extra):
        return raccoon_shell.main([_LOOPBACK, str(port.port)] + list(extra))

    # ── the tests ──

    def test_it_sends_the_password_and_the_local_geometry(self):
        self.assertEqual(shell_mod.PROMPT, _PROMPT)
        port = self._port(_paired_then_closed)
        self._terminal()
        # A space in the password, because that is the sharp edge of this
        # one-line wire: the port takes the tail as a geometry only when
        # it is entirely a geometry, so a password of two words has to
        # come back out of its parser whole.
        self._env("RACCOON_SHELL_PASSWORD", "two words")
        self._env("COLUMNS", "200")
        self._env("LINES", "50")

        self.assertEqual(self._attach(port), 0)
        port.stop()

        self.assertEqual(port.line, b"two words 200x50")
        # Nothing is pipelined behind the newline: the port keeps those
        # bytes as the session's first input, and a client that leaked
        # part of its line into them would be feeding them to a shell.
        self.assertEqual(port.pipelined, b"")
        self.assertEqual(shell_mod.parse_auth_line(port.line.decode("utf-8")),
                         ("two words", 200, 50))

        # A terminal that reports an absurd width still has to produce a
        # line the port can parse: a geometry of six digits matches no
        # geometry at all, so the port would read it as part of the
        # password and refuse the operator their own port.
        self._env("COLUMNS", "999999")
        self.assertEqual(raccoon_shell.geometry(), (99999, 50))
        line = raccoon_shell.auth_line("two words", 99999, 50)
        self.assertEqual(shell_mod.parse_auth_line(line.decode("utf-8")
                                                   .rstrip("\n"))[0],
                         "two words")

    def test_a_password_with_a_line_ending_cannot_be_sent(self):
        """The handshake is one line, so that is said rather than truncated."""
        self._terminal()

        with self.assertRaises(ValueError):
            raccoon_shell.auth_line("two\nwords", 200, 50)
        # Port 1, which nothing here listens on: a client that tried to
        # connect before building its line would say so, and this
        # asserts the other message.
        self.assertEqual(raccoon_shell.attach(_LOOPBACK, 1, "two\nwords",
                                              (80, 24)), 1)
        said = self.errors.getvalue()
        self.assertIn("one line", said)
        # And the password is not quoted back into the message: this one
        # goes to a terminal, and the others go to a log.
        self.assertNotIn("words", said)

    def test_the_password_comes_from_the_environment_when_it_is_set(self):
        port = self._port(_paired_then_closed)
        self._terminal()
        self._env("RACCOON_SHELL_PASSWORD", "out of the environment")
        self._env("COLUMNS", "120")
        self._env("LINES", "40")

        self.assertEqual(self._attach(port), 0)
        port.stop()
        self.assertEqual(port.line, b"out of the environment 120x40")
        # Read from the environment and nowhere else: were it not, this
        # would have gone to a `getpass` prompt, which reads a terminal
        # this test does not have.
        self.assertEqual(raccoon_shell.read_password(),
                         "out of the environment")

        # And there is nowhere on the command line to put one, which is
        # the whole reason for the environment variable: a command line is
        # readable by every user on the host.
        with self.assertRaises(SystemExit):
            self._attach(port, "out of the command line")

    def test_it_carries_bytes_both_ways(self):
        port = self._port(_paired_then_echoes)
        self._terminal(typed=b"whoami\n")
        self._env("RACCOON_SHELL_PASSWORD", "attach")
        self._env("COLUMNS", "80")
        self._env("LINES", "24")

        self.assertEqual(self._attach(port), 0)
        port.stop()

        # Whichever segment they arrived in: see `_typed`.
        self.assertEqual(port.received, b"whoami\n")
        self.assertEqual(self._shown(), _SHELL_PROMPT + b"WHOAMI\n")

    def test_it_restores_the_terminal_when_the_stream_ends(self):
        port = self._port(_paired_then_closed)
        self._terminal()
        self._env("RACCOON_SHELL_PASSWORD", "attach")
        self._env("COLUMNS", "80")
        self._env("LINES", "24")

        self.assertEqual(self._attach(port), 0)
        port.stop()
        self.assertEqual(self._shown(), _SHELL_PROMPT)
        self.assertEqual(self.errors.getvalue(), "")

        # stdin here is a pipe, so there was no terminal to put into raw
        # mode and none to put back, and `raw_terminal` says so rather
        # than reaching for `termios` on a descriptor that has no modes.
        # The restoring itself is `RawTerminalTests`.
        with raccoon_shell.raw_terminal(sys.stdin) as raw:
            self.assertFalse(raw)

    def test_a_refusal_line_is_shown_and_the_exit_code_is_nonzero(self):
        port = self._port(_refuses)
        self._terminal()
        self._env("RACCOON_SHELL_PASSWORD", "not the password")
        self._env("COLUMNS", "80")
        self._env("LINES", "24")

        self.assertEqual(self._attach(port), 1)
        port.stop()

        # The whole line and nothing else: the port's refusals end in a
        # CRLF, because the operator's terminal may be in raw mode when
        # it writes one, and a client that passed that carriage return
        # through to its own stderr would print a stray character after
        # every refusal.
        self.assertEqual(self.errors.getvalue(),
                         "raccoon: that is not the password for this shell "
                         "port.\n")
        # Shown to the operator, not fed to their terminal as though a
        # shell had printed it.
        self.assertEqual(self._shown(), b"")

    def test_a_refusal_before_the_prompt_is_shown_too(self):
        """The accept loop refuses without prompting, and says so first."""
        port = self._port(None, greeting=_TOO_BUSY, expect_line=False)
        self._terminal()
        self._env("RACCOON_SHELL_PASSWORD", "attach")
        self._env("COLUMNS", "80")
        self._env("LINES", "24")

        self.assertEqual(self._attach(port), 1)
        port.stop()

        self.assertEqual(self.errors.getvalue(),
                         _TOO_BUSY.decode("ascii").replace("\r\n", "\n"))
        # And the password was not sent into a socket that had already
        # been refused.
        self.assertIsNone(port.line)
        self.assertEqual(self._shown(), b"")


def _modes(fd):
    """A terminal's modes, less the two bits the kernel owns itself.

    `PENDIN` and `FLUSHO` are status rather than settings -- input
    waiting to be retyped, output held -- and the kernel sets them around
    a mode change of its own accord: restoring a pty on macOS reads back
    with `PENDIN` raised. Masking them is what lets the rest be compared
    exactly, which is the assertion that matters: every setting this
    client changed is back where it found it.
    """
    modes = termios.tcgetattr(fd)
    modes[3] &= ~(getattr(termios, "PENDIN", 0)
                  | getattr(termios, "FLUSHO", 0))
    return modes


class RawTerminalTests(unittest.TestCase):
    """What the end-to-end tests above cannot reach: a real terminal.

    A pty, so `isatty()` is true and `termios` has modes to read back.
    This is the only place the raw-mode path runs at all.
    """

    # What raw mode is for: a keystroke reaches the far end instead of
    # being echoed, buffered into a line, or turned into a signal here.
    _COOKED = termios.ECHO | termios.ICANON | termios.ISIG

    def setUp(self):
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        self.terminal = os.fdopen(slave, "rb", 0)
        self.addCleanup(self.terminal.close)
        self.fd = slave
        self.cooked = _modes(slave)
        self.assertTrue(self.cooked[3] & self._COOKED)

    def test_the_terminal_is_raw_for_the_session_and_cooked_after_it(self):
        with raccoon_shell.raw_terminal(self.terminal) as raw:
            self.assertTrue(raw)
            self.assertEqual(_modes(self.fd)[3] & self._COOKED, 0)
        self.assertEqual(_modes(self.fd), self.cooked)

    def test_the_terminal_is_restored_when_the_session_raises(self):
        with self.assertRaises(RuntimeError):
            with raccoon_shell.raw_terminal(self.terminal):
                raise RuntimeError("the stream died mid-session")
        self.assertEqual(_modes(self.fd), self.cooked)


if __name__ == "__main__":
    unittest.main()
