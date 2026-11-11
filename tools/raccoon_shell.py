#!/usr/bin/env python3
"""Attach this terminal to one build's shell session.

    python3 tools/raccoon_shell.py 127.0.0.1 <port>

The port is the one the panel shows for a build, on the team server's
loopback; from anywhere else it is reached over an `ssh -L` forward
first. `socat -,raw,echo=0,escape=0x1d TCP:127.0.0.1:<port>` attaches to
the same port and is the documented fallback, so this client exists for
the two things `socat` cannot do.

**It sends the terminal's size.** The port's wire is a prompt, one line
of text, and then raw bytes in both directions; the line is
`<password>` or `<password> <cols>x<rows>`, and the geometry is how the
far end sizes the pseudo-terminal it opens. `socat` sends none, so a
session attached with it comes up at the port's default 120x40 whatever
the operator's window is. This reads the local size and puts it on the
line. The geometry rides on the *end* of the password line and the port
takes it off only when the tail is entirely a geometry, so a password
with a space in it is ordinary and needs no quoting -- but a size that
is not digits-x-digits would be read as part of the password and refuse
the operator their own port, which is why `geometry` clamps what it
reports into something the port can parse.

**It puts the terminal in raw mode, and always puts it back.** That is
what makes this a terminal rather than a line editor: every keystroke
reaches the far end, including the ones the local line discipline would
otherwise act on, and the echo comes from the shell's own pty. Raw mode
is entered only when stdin is a terminal and restored in a `finally`
that covers every way out -- the stream ending, a refusal, an interrupt,
an unexpected exception -- because a client that exits leaving an
operator's terminal in raw mode has taken their shell away along with
the session.

**The size is sent once and cannot be renegotiated.** There is no resize
message on this wire; the far end sizes its pty at the `ioctl` that
opens it. So a `SIGWINCH` mid-session is answered with a note to the
operator rather than a message to the port: the `stty rows ... cols ...`
line to paste into the session, which is the documented remedy.

**The password is never on the command line.** `RACCOON_SHELL_PASSWORD`
or a `getpass` prompt, and there is no option for it: a command line is
readable by every user on the host, which is the same rule this
repository states about tokens and keys.

There is no escape character. The way out of a session is to end the
shell at the far end -- `exit`, or the Ctrl-D the far end's terminal
reads -- after which this client's exit code is 0. A refusal is one line
of plain text from the port, which is printed and answered with 1.

Stdlib only, and nothing from `software/`: this is a file an operator
copies to a workstation that has nothing else of this repository on it.
"""

import argparse
import contextlib
import getpass
import os
import select
import shutil
import signal
import socket
import sys
import termios
import tty
from typing import List, Optional, Tuple

__all__ = ["attach", "auth_line", "geometry", "main", "raw_terminal",
           "read_password", "resize_notice"]

# Where the password is read from, when it is not asked for.
ENV_PASSWORD = "RACCOON_SHELL_PASSWORD"

# What the port writes before it reads the line. Read and discarded: it
# is there so that a terminal shows an operator what is wanted, and this
# client already knows.
PROMPT = b"password: "

# How every refusal from the far end begins -- the port's own and the
# endpoint's. It is the one thing that tells a line of plain text apart
# from the first bytes of a shell: see `_relay`.
REFUSAL = b"raccoon: "

# The size asked for when there is no terminal to measure, which is the
# port's own default spelled out: a client with no window attached asks
# for what it would have got by saying nothing.
_DEFAULT_SIZE = (120, 40)

# One to five digits, which is the only bound that matters on this side:
# the port reads a geometry off the end of the line only when it matches
# `\d{1,5}x\d{1,5}` entirely. The port's own, far narrower, ceiling is
# its business -- a second copy of that number here could only show up as
# a terminal of the wrong size.
_GEOMETRY_MAX = 99999

# How long the connection and the handshake are given. The session that
# follows has no timeout at all: an idle shell is the normal state of
# one, and the port itself bounds the wait for a terminal and refuses in
# text when it runs out, so there is nothing for a timer here to save.
_CONNECT_TIMEOUT = 15.0
_HANDSHAKE_TIMEOUT = 30.0

# How long the rest of a refusal is waited for, once its first bytes have
# arrived. Short: what is outstanding is the end of one short line from a
# peer that has already decided to close.
_DRAIN_TIMEOUT = 2.0

# The most a refusal will be read before it is printed. A bound on what a
# peer that answered with a prefix and then a flood can make this buffer.
_REFUSAL_MAX = 4096

_CHUNK = 65536


class _Refusal(Exception):
    """The far end answered with a line of text instead of a terminal.

    Carried out of the session rather than printed where it was found, so
    that it is printed after the terminal has been put back out of raw
    mode: a refusal written into a raw terminal staircases down the
    screen.
    """

    def __init__(self, text: bytes):
        Exception.__init__(self, text)
        self._text = text

    @property
    def line(self) -> str:
        """The first line of it, reduced to printable ASCII.

        The port already writes its refusals this way, and one of them
        passes on wording that came from the implant host. This is going
        to a terminal, so a newline cannot turn one line into several and
        an escape sequence cannot repaint the operator's screen -- the
        same reasoning the port's own `_line` is written from, applied
        again at the end that does the printing.

        Stripped before that reduction and not after: the port ends its
        refusals with a CRLF, because the terminal they are written to
        may be in raw mode, and a carriage return reduced to a `?` would
        print a stray character after every refusal.
        """
        flat = self._text.split(b"\n", 1)[0].decode("utf-8", "replace")
        return "".join(c if " " <= c <= "~" else "?" for c in flat.strip())


def geometry() -> Tuple[int, int]:
    """This terminal's `(cols, rows)`, as a size the port can parse.

    `shutil.get_terminal_size` honours `COLUMNS` and `LINES`, falls back
    to the ioctl on stdout, and falls back again to what it is given --
    here the port's own default, so a client with no terminal at all asks
    for what it would have got by saying nothing.

    Clamped into one to five digits so that the line stays parseable: see
    `_GEOMETRY_MAX`. A terminal reporting 0 or six digits is a terminal
    in an odd state, and the cost of passing that on verbatim is not a
    badly sized session but a refused one.
    """
    size = shutil.get_terminal_size(_DEFAULT_SIZE)
    return _digits(size.columns), _digits(size.lines)


def _digits(value: int) -> int:
    return max(1, min(_GEOMETRY_MAX, int(value)))


def read_password() -> str:
    """The attach password, from the environment or from a prompt.

    Never from the command line, and there is no option for one: a
    command line is readable by every user on the host -- `ps` on the
    team server, a shell history on the workstation -- so the two ways in
    are an environment variable, for a wrapper script, and a prompt
    `getpass` reads from the terminal without echoing it.
    """
    password = os.environ.get(ENV_PASSWORD)
    if password:
        return password
    return getpass.getpass("raccoon shell password: ")


def auth_line(password: str, cols: int, rows: int) -> bytes:
    """The one line this wire is: `<password> <cols>x<rows>`, and a newline.

    Nothing is quoted or escaped, because nothing can be: the port splits
    once from the right and takes the tail as a geometry only when it is
    entirely a geometry, so a password with spaces in it arrives whole. A
    password with a line ending in it is the one thing that cannot be
    sent at all -- the newline is the end of the line -- and that is said
    rather than silently truncated into a wrong password.
    """
    if "\n" in password or "\r" in password:
        raise ValueError("that password has a line ending in it, and this "
                         "handshake is one line, so it cannot be sent")
    return ("%s %dx%d\n" % (password, cols, rows)).encode("utf-8")


@contextlib.contextmanager
def raw_terminal(stream):
    """Hold a terminal in raw mode for a session, and always put it back.

    Yields True when there was a terminal to change. A stream that is a
    pipe or a file is left alone and yields False: this client is
    perfectly usable with its input redirected, and `termios` on a
    descriptor with no modes would only raise.

    The restore is in a `finally`, so it covers every way out of the
    block -- an orderly end, a refusal, `KeyboardInterrupt`, an
    unexpected exception -- and it runs even when putting the terminal
    into raw mode is what failed.
    """
    fd = -1
    saved = None
    try:
        if stream is not None and stream.isatty():
            fd = stream.fileno()
            saved = termios.tcgetattr(fd)
    except (AttributeError, OSError, ValueError, termios.error):
        # A stdin that has been closed, replaced with something that is
        # not a file, or is a terminal this platform will not describe.
        # None of it is worth refusing a session over.
        saved = None
    try:
        if saved is not None:
            tty.setraw(fd)
        yield saved is not None
    finally:
        if saved is not None:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, saved)
            except (OSError, termios.error) as exc:
                # The one failure this client cannot paper over, so it
                # says what will: an operator reading a staircased
                # terminal needs the command, not the diagnosis.
                _note("this terminal could not be put back: %s. `stty sane` "
                      "will do it." % exc)


@contextlib.contextmanager
def resize_notice(out_fd: int, enabled: bool):
    """Answer a resize with the one line that fixes it.

    The size goes out once, on the auth line, and this wire has nowhere
    to put a second one: the far end sizes its pty at the `ioctl` that
    opens it. So a `SIGWINCH` is not a message to the port, it is a note
    to the operator -- the `stty` line to paste into the session.

    Written from the handler itself rather than noticed by the relay
    loop: a `select` waiting for a keystroke resumes after the handler
    runs, so a flag would hold the note until the next byte arrived,
    which on an idle shell is whenever the operator next types.

    `enabled` is whether there is a terminal at all; without one there is
    no resize to hear. A handler that cannot be installed -- no
    `SIGWINCH` on this platform, or not the main thread -- costs the note
    and nothing else.
    """
    if not enabled or not hasattr(signal, "SIGWINCH"):
        yield
        return

    def note(signum, frame):
        cols, rows = geometry()
        _write(out_fd, ("raccoon-shell: this terminal is now %dx%d, and a "
                        "session's size is set once, at attach. Paste this "
                        "into the session: stty rows %d cols %d\r\n"
                        % (cols, rows, rows, cols)).encode("utf-8"))

    try:
        previous = signal.signal(signal.SIGWINCH, note)
    except (OSError, ValueError):
        yield
        return
    try:
        yield
    finally:
        try:
            signal.signal(signal.SIGWINCH, previous)
        except (OSError, ValueError, TypeError):
            pass


def attach(host: str, port: int, password: str,
           size: Tuple[int, int]) -> int:
    """One attach, from the connection to the last byte: an exit code.

    0 is a session that ran and ended; 1 is anything that stopped one,
    each said in a line of its own on stderr. The line is built before
    the connection, so a password that cannot be sent costs no socket.
    """
    try:
        line = auth_line(password, size[0], size[1])
    except ValueError as exc:
        # Said where it is raised, and without quoting the password back.
        _note(str(exc))
        return 1
    try:
        sock = socket.create_connection((host, port), _CONNECT_TIMEOUT)
    except OSError as exc:
        _note("could not reach %s:%d: %s. That port is on the team server's "
              "loopback, so from anywhere else it is reached over `ssh -L "
              "%d:127.0.0.1:%d <user>@<team-server>` first."
              % (host, port, exc, port, port))
        return 1
    try:
        sock.settimeout(_HANDSHAKE_TIMEOUT)
        # The prompt is read before the password is sent, so that a port
        # whose accept loop refused this connection before prompting is
        # answered by reading its line rather than by sending a secret
        # into a socket that is already closing.
        greeting = _recv_upto(sock, len(PROMPT))
        if not greeting:
            _note("%s:%d closed without asking for a password." % (host, port))
            return 1
        if greeting.startswith(REFUSAL):
            raise _refusal(sock, greeting)
        sock.sendall(line)
        # No timeout from here on: the port is opening a terminal on the
        # implant and waiting for it to dial back, which it bounds itself
        # and refuses in text when it runs out, and after that an idle
        # shell is the normal state of a session.
        sock.settimeout(None)
        return _carry(sock)
    except _Refusal as refusal:
        # Printed here, which is outside `_carry` and therefore after the
        # terminal has been put back: see `_Refusal`.
        sys.stderr.write(refusal.line + "\n")
        sys.stderr.flush()
        return 1
    except OSError as exc:
        _note("the connection to %s:%d ended: %s" % (host, port, exc))
        return 1
    finally:
        sock.close()


def _carry(sock: socket.socket) -> int:
    """Raw mode, a resize note, and bytes both ways until one side ends."""
    try:
        keys, shown = sys.stdin.fileno(), sys.stdout.fileno()
    except (AttributeError, OSError, ValueError):
        _note("this client needs a real stdin and stdout to carry a "
              "terminal, and has not got them.")
        return 1
    with raw_terminal(sys.stdin) as raw, resize_notice(shown, raw):
        return _relay(sock, keys, shown)


def _relay(sock: socket.socket, keys: int, shown: int) -> int:
    """Everything after the handshake: one `select` over two descriptors.

    The first bytes back from the far end are held until they can be told
    apart from a refusal, which is the only ambiguity on this wire: both
    a refusal and a shell's first prompt arrive as bytes after the auth
    line. Everything the port refuses, it refuses before a session byte
    exists, so judging the first bytes alone is enough -- and holding
    them rather than reading ahead for a whole line is what keeps a
    terminal that says nothing until it is typed at from looking hung.
    """
    watched = [sock, keys]
    held = b""
    judged = False
    while True:
        try:
            ready = select.select(watched, [], [])[0]
        except OSError:
            # A descriptor went out from under the select: the session is
            # over either way.
            return 0
        if sock in ready:
            try:
                data = sock.recv(_CHUNK)
            except OSError:
                data = b""
            if not data:
                if held:
                    # Short of a refusal and now finished, so it was the
                    # far end's own output after all.
                    _write(shown, held)
                return 0
            if not judged:
                held += data
                if held.startswith(REFUSAL):
                    raise _refusal(sock, held)
                if len(held) < len(REFUSAL) and REFUSAL.startswith(held):
                    continue
                data, held, judged = held, b"", True
            _write(shown, data)
        if keys in ready:
            try:
                data = os.read(keys, _CHUNK)
            except OSError:
                data = b""
            if not data:
                # Stdin is finished -- redirected input that ran out, or
                # a terminal that has gone. The far end is told so, and
                # a descriptor that is now readable forever is dropped
                # from the select rather than spun on.
                watched.remove(keys)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                continue
            try:
                sock.sendall(data)
            except OSError:
                return 0


def _refusal(sock: socket.socket, first: bytes) -> _Refusal:
    """Read the rest of a refusal that has begun, and carry it out."""
    return _Refusal(first + _drain(sock))


def _drain(sock: socket.socket) -> bytes:
    """The rest of one short line, from a peer that is about to close."""
    sock.settimeout(_DRAIN_TIMEOUT)
    have = b""
    while b"\n" not in have and len(have) < _REFUSAL_MAX:
        try:
            chunk = sock.recv(_REFUSAL_MAX)
        except OSError:
            break
        if not chunk:
            break
        have += chunk
    return have


def _recv_upto(sock: socket.socket, count: int) -> bytes:
    """Up to `count` bytes, or fewer if the peer stopped sending."""
    have = b""
    while len(have) < count:
        chunk = sock.recv(count - len(have))
        if not chunk:
            break
        have += chunk
    return have


def _write(fd: int, data: bytes) -> None:
    """All of it, however many writes that takes."""
    while data:
        try:
            data = data[os.write(fd, data):]
        except InterruptedError:
            continue


def _note(message: str) -> None:
    """One line from this client, named so it is not read as the port's."""
    sys.stderr.write("raccoon-shell: %s\n" % message)
    sys.stderr.flush()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="raccoon_shell.py",
        description=__doc__.splitlines()[0],
        epilog="The password is read from %s, or asked for at a prompt. "
               "There is no option for it: a command line is readable by "
               "every user on the host." % ENV_PASSWORD)
    parser.add_argument("host", help="where the shell port is, which for an "
                                     "ssh -L forward is 127.0.0.1")
    parser.add_argument("port", type=int,
                        help="the port the panel shows for this build")
    args = parser.parse_args(argv)
    try:
        return attach(args.host, args.port, read_password(), geometry())
    except KeyboardInterrupt:
        # Only reachable where Ctrl-C is still a signal: at the password
        # prompt, or with stdin redirected. Inside a session it is a byte
        # the far end's terminal reads, which is the point of raw mode.
        _note("interrupted")
        return 130
    except EOFError:
        _note("no password was given, so nothing was attached")
        return 1


if __name__ == "__main__":
    sys.exit(main())
