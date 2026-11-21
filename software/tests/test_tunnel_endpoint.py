#!/usr/bin/env python3
"""
Unit tests for the tunnel endpoint in `software/c2/beacon.py`: the far end
of the tunnel, which connects out, holds one command channel, and dials a
second connection per relay the operator asks for.

Six things these tests are careful about.

**Both halves are real.** The server end is a real `TunnelServer` with a
real `KeyStore`, and the near end is the real `TunnelEndpoint` running
`run()` on a thread. There is no mock of a Noise session, no mock of a
socket and no stub of either half: the whole point of this task is that
the two ends match, and a mock of one agrees with whatever the other does.
The operator's side is driven through `TunnelServer.open_session`, which
is the API `SocksFront` calls.

**The target speaks first, on purpose.** `_Target` sends a banner the
instant it accepts. So `test_endpoint_dials_a_relay_when_asked_and_carries_
a_connect` fails if the endpoint ever coalesces the target's first bytes
into its SOCKS reply: the reply would arrive as one frame with the banner
glued on and `decode_socks_reply` refuses that, exactly as the operator's
port does.

**The restart test restarts.** It stops the server and constructs a new
one over the same `state_path` and the same port, because the property
under test is that an endpoint whose server vanished retries rather than
exits -- and that it comes back to the same identity and the same assigned
SOCKS port. Nothing calls an internal reconnect method.

**Two of the four unreachable-target cases come from a seam, and it is
named.** Connection refused and an unresolvable name are produced for
real: a closed loopback port refuses, and a `.invalid` name cannot resolve
(RFC 2606). "No route" and "a connect that hangs" cannot be produced
portably -- on this machine an unrouted IPv6 address answers
`EHOSTUNREACH` rather than `ENETUNREACH`, and whether a TEST-NET-1 address
hangs or is refused outright depends on the host's default route. So
`_UnreachableEndpoint` overrides `_dial_target`, which is the one call that
touches the target network, and raises what the OS raises in those
conditions. Everything else in those two tests is real: the server, the
Noise sessions, the SOCKS codec, the reply framing and the session
teardown.

**No port is hardcoded.** Every listener in this file binds port 0 and is
read back. `_PORT_RANGE` is the range the server assigns loopback SOCKS
ports from; nothing in this task binds one, so it is a pair of numbers in
a JSON file.

**No thread may die quietly.** `setUp` installs a `threading.excepthook`
and a handler on both loggers, and the last cleanup to run asserts that no
thread raised and that nothing was logged at ERROR or above. An endpoint
that survives a dead relay by crashing a pump thread would otherwise pass
every assertion here.

**The shell tests run against a fake server end, and only that end is
fake.** `TunnelServer` learns about shell sessions two tasks after this
one, so `_FakeTunnelServer` stands in for its session table: the Noise
responder, the framing, the message codec and the `KeyStore` behind it are
all the real ones, and the endpoint dials it, handshakes with it and
claims against it with exactly the bytes the real server will read. What
those tests then assert on is a real `bash` on a real PTY -- its output,
its working directory, its `$$`, and whether that pid is still in the
process table afterwards.
"""

import ast
import base64
import contextlib
import errno
import inspect
import logging
import os
import re
import select
import shutil
import socket
import sys
import tempfile
import textwrap
import threading
import time
import traceback
import pwd
import unittest
from unittest import mock

from software.c2 import beacon as beacon_mod
from software.c2.beacon import (
    ATYP_DOMAIN,
    ATYP_IPV4,
    ATYP_IPV6,
    CMD_CONNECT,
    REPLY_CONNECTION_REFUSED,
    REPLY_HOST_UNREACHABLE,
    REPLY_NETWORK_UNREACHABLE,
    REPLY_SUCCEEDED,
    REPLY_TTL_EXPIRED,
    MSG_HELLO,
    MSG_OPEN_SHELL,
    MSG_SHELL,
    SHELL_DEFAULT_COLS,
    SHELL_DEFAULT_ROWS,
    SHELL_GEOMETRY_MAX,
    NoiseSession,
    TunnelEndpoint,
    decode_message,
    decode_socks_reply,
    encode_message,
    encode_socks_request,
    read_frame,
    tunnel_config_problem,
    write_frame,
)
from software.c2.tunnel.keys import KeyStore
from software.c2.tunnel.server import TunnelServer

_LOOPBACK = "127.0.0.1"
_LOOPBACK6 = "::1"

# The range the tunnel server assigns SOCKS ports from. Nothing binds one
# in this task, so this is a pair of numbers in a JSON file and not a port
# in a test; every listener here binds 0 and is read back.
_PORT_RANGE = (40300, 40399)

# A name that cannot resolve, per RFC 2606 §2: `.invalid` is reserved and
# guaranteed not to be delegated.
_UNRESOLVABLE = "no-endpoint-here.invalid"

# A PTY session is POSIX-only, and so are the tests of one. Read once at
# import, the way `_ipv6_loopback_works()` is.
_HAS_PTY = hasattr(os, "openpty")
_NO_PTY = "this host has no pty support, so it cannot carry a shell session"

# The start of a line as it arrives from a pty, which is not always the
# character the line begins with. Bash 5 enables bracketed paste and
# writes the disable sequence immediately before the line it is about to
# print, so a pattern anchored with `^` against raw pty bytes sees
# `\x1b[?2004l\r40 120` and misses the value that is plainly there.
# Measured on Debian 13 with bash 5.2.37; macOS's bash 3.2 does not do
# it, which is why this surfaced only on the platform this project
# deploys to. The sequences are allowed rather than stripped, so one
# pattern can both drive `read_until_match` and be asserted on.
_LINE_START = rb"(?m)^(?:\x1b\[[0-9?;]*[a-zA-Z]|\r)*"

# Two tests are about bash specifically -- the generated rcfile is a bash
# construction -- and the rest run on whatever shell the host has.
_HAS_BASH = os.access("/bin/bash", os.X_OK)
_NO_BASH = "this host has no /bin/bash, so there is no rcfile path to test"

# Flag completion comes from bash-completion, which is a package and not
# part of bash. A host without it can still run the session, so the two
# tests that measure the loader skip rather than fail. These are the three
# places a distribution puts it; Debian 13 ships the first, and its
# `/etc/bash.bashrc` has the direct source commented out.
_COMPLETION_LOADERS = ("/etc/profile.d/bash_completion.sh",
                       "/usr/share/bash-completion/bash_completion",
                       "/etc/bash_completion")
_HAS_BASH_COMPLETION = any(os.access(path, os.R_OK)
                           for path in _COMPLETION_LOADERS)
_NO_BASH_COMPLETION = ("this host has no bash-completion installed, so "
                       "there is no loader for a session to pick up")

# A session only has a *controlling* terminal where `setsid(1)` is there
# to acquire one, which is the endpoint's preferred path; without it the
# session runs the documented fallback, which has no controlling terminal
# and therefore no signal from `^C`. Probed independently of the
# endpoint's own resolver -- `shutil.which`, the way `test_tunnel_yara`
# finds `yara` -- so that a resolver which stopped finding `setsid`
# produces a failing test rather than a skipped one.
_HAS_SETSID = shutil.which("setsid") is not None
_NO_SETSID = ("no setsid(1) on this host, as on macOS, so the session "
              "takes the documented fallback path -- on which Darwin "
              "hands a session leader its controlling terminal anyway, "
              "so this would pass here without proving anything. The "
              "deployment target is Linux, where setsid is present and "
              "where the fallback really has no ^C")

# A stand-in for `setsid -c`, for the host that has no `setsid(1)` at all.
#
# What `setsid -c` does is `setsid()`, `TIOCSCTTY` on its stdin, and
# `exec`. It is a separate *program* for one reason only: no interpreter
# may run between the fork and the exec of a process holding as many
# threads and locks as this one. A shim is already past that point -- it
# is its own exec'd program with one thread -- so it can make the two
# calls in Python and then exec the shell, which is what makes the
# endpoint's preferred path assertable on a host with no `setsid` to
# probe for.
#
# It records the argv it was given, and refuses an invocation without
# `-c`, so both halves of what the endpoint has to get right are read
# back from the program that was actually run.
_SETSID_STAND_IN = '''#!%s
import fcntl
import os
import sys
import termios

args = sys.argv[1:]
with open(sys.argv[0] + ".ran", "w") as handle:
    handle.write("\\n".join(sys.argv))
if args[:1] != ["-c"]:
    raise SystemExit("asked for no controlling terminal: %%r" %% (args,))
args = args[1:]
os.setsid()
fcntl.ioctl(0, termios.TIOCSCTTY, 0)
os.execv(args[0], args)
'''


def _alive(pid):
    """True while `pid` is still in the process table.

    Signal 0 and not a flag of anybody's: it is the kernel's answer. A
    zombie answers yes, which is deliberate -- a process that has been
    signalled but not reaped is still a row in `ps`.
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _free_port():
    """A loopback port with nothing on it: bound, read back, released.

    What connects to it afterwards is refused, which is the one
    unreachable-target condition a test can produce for real and quickly.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((_LOOPBACK, 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def _ipv6_loopback_works():
    """True if `::1` can be bound here, so the IPv6 test means something."""
    if not socket.has_ipv6:
        return False
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        sock.bind((_LOOPBACK6, 0))
        return True
    except OSError:
        return False
    finally:
        sock.close()


class _Target(object):
    """A TCP service in the endpoint's own network: a banner, then an echo.

    The banner goes out the moment the connection is accepted, so a reply
    that carried the target's first bytes with it would be visible as a
    frame that is not a SOCKS reply. The echo is tagged with the port that
    was asked for, so a crossed stream is visible too.
    """

    def __init__(self, host=_LOOPBACK, banner=b"", echo=True):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self._listener = socket.socket(family, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((host, 0))
        self._listener.listen(8)
        self._listener.settimeout(0.2)
        self.host = host
        self.port = self._listener.getsockname()[1]
        self.banner = banner
        self._echo = echo
        self._lock = threading.Lock()
        self._conns = []
        self._stop = threading.Event()
        self.errors = []
        self._thread = threading.Thread(target=self._accept, daemon=True,
                                        name="target-accept")
        self._thread.start()

    def _accept(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self._conns.append(conn)
            threading.Thread(target=self._serve, args=(conn,), daemon=True,
                             name="target-conn").start()

    def _serve(self, conn):
        try:
            if self.banner:
                conn.sendall(self.banner)
            while self._echo:
                data = conn.recv(4096)
                if not data:
                    return
                conn.sendall(b"echo:" + data)
        except OSError:
            return
        except Exception:
            self.errors.append(traceback.format_exc())

    def close(self):
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        with self._lock:
            conns, self._conns = self._conns, []
        for conn in conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
        self._thread.join(timeout=3.0)


class _ConnectProxy(object):
    """A stub HTTP `CONNECT` proxy on loopback that records what it is asked.

    Deliberately not an HTTP server: the request line, the headers and
    `200 Connection Established` are the whole of what a corporate proxy
    gives the endpoint and the whole of what the endpoint has to get
    right. `request_lines` is what the test asserts on, because a
    `CONNECT` with the wrong target is how a tunnel silently goes direct.
    """

    def __init__(self):
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((_LOOPBACK, 0))
        self._listener.listen(8)
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        self._lock = threading.Lock()
        self._request_lines = []
        self._socks = []
        self._stop = threading.Event()
        self.errors = []
        self._thread = threading.Thread(target=self._accept, daemon=True,
                                        name="proxy-accept")
        self._thread.start()

    @property
    def request_lines(self):
        with self._lock:
            return list(self._request_lines)

    def _accept(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self._socks.append(conn)
            threading.Thread(target=self._serve, args=(conn,), daemon=True,
                             name="proxy-conn").start()

    def _serve(self, client):
        upstream = None
        try:
            line = self._read_line(client)
            while True:
                header = self._read_line(client)
                if not header:
                    break
            with self._lock:
                self._request_lines.append(line)
            parts = line.split(" ")
            if len(parts) < 2 or parts[0] != "CONNECT":
                client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                return
            host, _, port = parts[1].rpartition(":")
            upstream = socket.create_connection((host, int(port)),
                                                timeout=10.0)
            with self._lock:
                self._socks.append(upstream)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._bridge(client, upstream)
        except OSError:
            return
        except Exception:
            self.errors.append(traceback.format_exc())

    @staticmethod
    def _read_line(sock):
        chunks = []
        while len(chunks) < 8192:
            byte = sock.recv(1)
            if not byte:
                break
            if byte == b"\n":
                break
            if byte != b"\r":
                chunks.append(byte)
        return b"".join(chunks).decode("latin-1")

    def _bridge(self, one, two):
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(65535)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        back = threading.Thread(target=forward, args=(two, one), daemon=True,
                                name="proxy-down")
        back.start()
        forward(one, two)
        back.join(timeout=3.0)

    def close(self):
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        with self._lock:
            socks, self._socks = self._socks, []
        for sock in socks:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        self._thread.join(timeout=3.0)


class _Redirector(object):
    """A plain TCP forwarder on loopback, the way a redirector sits in front.

    Everything it accepts is bridged to one fixed address, so the port the
    endpoint is configured with and the port the tunnel server bound are
    two different numbers -- which is the deployment the one-port design
    exists for and the one case in which the two values can disagree.
    `connections` is what the test asserts on: a relay that went straight
    to the server's own port never passed through here.
    """

    def __init__(self, target_host, target_port):
        self._target = (target_host, target_port)
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((_LOOPBACK, 0))
        self._listener.listen(8)
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        self._lock = threading.Lock()
        self._connections = 0
        self._socks = []
        self._stop = threading.Event()
        self.errors = []
        self._thread = threading.Thread(target=self._accept, daemon=True,
                                        name="redirector-accept")
        self._thread.start()

    @property
    def connections(self):
        with self._lock:
            return self._connections

    def _accept(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self._connections += 1
                self._socks.append(conn)
            threading.Thread(target=self._serve, args=(conn,), daemon=True,
                             name="redirector-conn").start()

    def _serve(self, client):
        try:
            upstream = socket.create_connection(self._target, timeout=10.0)
        except OSError:
            try:
                client.close()
            except OSError:
                pass
            return
        with self._lock:
            self._socks.append(upstream)
        try:
            self._bridge(client, upstream)
        except OSError:
            return
        except Exception:
            self.errors.append(traceback.format_exc())

    @staticmethod
    def _bridge(one, two):
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(65535)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        back = threading.Thread(target=forward, args=(two, one), daemon=True,
                                name="redirector-down")
        back.start()
        forward(one, two)
        back.join(timeout=3.0)

    def close(self):
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        with self._lock:
            socks, self._socks = self._socks, []
        for sock in socks:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        self._thread.join(timeout=3.0)


class _NoiseStream(object):
    """One Noise stream as the server end holds it: send bytes, read bytes.

    The framing and the cipher are the real ones, so what this reads is
    what an operator's port would read and what it writes is what an
    endpoint's pump has to accept. One thread uses one of these at a
    time, which is what makes the two nonce counters safe without a lock.
    """

    def __init__(self, conn, noise):
        self.conn = conn
        self.noise = noise
        self.buffer = b""

    def send(self, data):
        write_frame(self.conn, self.noise.encrypt(data))

    def send_message(self, kind, body):
        self.send(encode_message(kind, body))

    def read_until(self, needle, timeout=20.0):
        """Everything read so far once `needle` is in it, else None."""
        return self._read_while(lambda buf: needle in buf, timeout)

    def read_until_match(self, pattern, timeout=20.0):
        """Everything read so far once `pattern` matches it, else None."""
        return self._read_while(lambda buf: pattern.search(buf), timeout)

    def wait_closed(self, timeout=10.0):
        """True once the endpoint has closed this stream, False on silence.

        The two have to be told apart: a refusal that was never followed
        by a close would otherwise read as a close that simply took a
        while, which is the whole of what that assertion is for.
        """
        deadline = time.time() + timeout
        while True:
            left = deadline - time.time()
            if left <= 0:
                return False
            self.conn.settimeout(left)
            try:
                frame = read_frame(self.conn)
            except socket.timeout:
                return False
            except (OSError, ValueError):
                return True
            self.buffer += self.noise.decrypt(frame)

    def _read_while(self, done, timeout):
        deadline = time.time() + timeout
        while not done(self.buffer):
            left = deadline - time.time()
            if left <= 0:
                return None
            self.conn.settimeout(left)
            try:
                frame = read_frame(self.conn)
            except socket.timeout:
                continue
            except (OSError, ValueError):
                # A FIN, mid-frame or between frames: the endpoint is
                # finished with this session.
                return None
            self.buffer += self.noise.decrypt(frame)
        return self.buffer

    def close(self):
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.conn.close()
        except OSError:
            pass


class _FakeTunnelServer(object):
    """The server end of a tunnel, far enough to ask for a shell session.

    The real `TunnelServer` learns about shell sessions two tasks after
    this one, so what stands in for it here is its session table and
    nothing else: the Noise responder, the framing, the message codec and
    the `KeyStore` behind them are the real ones, and the endpoint dials
    this, handshakes with it and claims against it with exactly the bytes
    the real server will read.

    `opened` is every connection in arrival order, as `(kind, body,
    stream)`. That is what makes "the second connection's first message
    is a SHELL claim carrying the token" an assertion rather than an
    inference.
    """

    def __init__(self, store):
        self._store = store
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((_LOOPBACK, 0))
        self._listener.listen(8)
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        self._lock = threading.Lock()
        self._opened = []
        self._stop = threading.Event()
        self.errors = []
        self._thread = threading.Thread(target=self._accept, daemon=True,
                                        name="fake-tunnel-accept")
        self._thread.start()

    @property
    def opened(self):
        with self._lock:
            return list(self._opened)

    @property
    def channel(self):
        """The command channel's stream, or None until the HELLO arrives."""
        for kind, _, stream in self.opened:
            if kind == MSG_HELLO:
                return stream
        return None

    @property
    def shells(self):
        """`(body, stream)` for every connection that claimed a shell."""
        return [(body, stream) for kind, body, stream in self.opened
                if kind == MSG_SHELL]

    def _accept(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._greet, args=(conn,), daemon=True,
                             name="fake-tunnel-conn").start()

    def _greet(self, conn):
        """The responder's half of the handshake, then remember the claim."""
        try:
            conn.settimeout(10.0)
            noise = NoiseSession.responder(self._store.static_private(),
                                           self._store.psks)
            payload = noise.respond(read_frame(conn))
            write_frame(conn, noise.reply())
            kind, body = decode_message(payload)
            with self._lock:
                self._opened.append((kind, body, _NoiseStream(conn, noise)))
        except (OSError, ValueError):
            # An endpoint that was stopped mid-dial. Costs this
            # connection, as it does on the real server.
            try:
                conn.close()
            except OSError:
                pass
        except Exception:
            self.errors.append(traceback.format_exc())

    def close(self):
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        for _, _, stream in self.opened:
            stream.close()
        self._thread.join(timeout=3.0)


class _UnreachableEndpoint(TunnelEndpoint):
    """An endpoint whose target network always answers with one error.

    The seam the module docstring explains: `_dial_target` is the single
    call that touches the target network, and the two conditions no test
    can produce portably -- no route, and a connect that hangs past the
    timeout -- are injected there as the exception the OS raises for them.
    """

    failure = None

    def _dial_target(self, address, port, timeout):
        raise self.failure


class TunnelEndpointTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name
        self.state_path = os.path.join(self.root, "state", "tunnel_ports.json")
        self.keys_path = os.path.join(self.root, "keys", "tunnel_keys.json")
        self.store = KeyStore(self.keys_path)
        self.psks = {}
        for identity in ("build-alpha", "build-beta"):
            psk = os.urandom(32)
            self.store.register_build(identity, psk)
            self.psks[identity] = psk
        self.public = self.store.static_public()

        # Registered first so it runs last: the server has to be stopped
        # and every endpoint shut down before the verdict is read.
        self.thread_errors = []
        self.log_records = []
        self.addCleanup(self._assert_nothing_broke_quietly)

        previous_hook = threading.excepthook
        threading.excepthook = self.thread_errors.append
        self.addCleanup(setattr, threading, "excepthook", previous_hook)

        handler = logging.Handler(level=logging.ERROR)
        handler.emit = self.log_records.append
        for name in ("raccoon.c2", "raccoon.tunnel.server"):
            log = logging.getLogger(name)
            log.addHandler(handler)
            self.addCleanup(log.removeHandler, handler)

    def _assert_nothing_broke_quietly(self):
        self.assertEqual(
            [getattr(args, "exc_value", args) for args in self.thread_errors],
            [], "a thread raised; the endpoint let an exception escape one "
                "of its loops")
        self.assertEqual(
            [record.getMessage() for record in self.log_records], [],
            "something was logged at ERROR or above; an expected failure is "
            "logged below that")

    # ── harness ──

    def start_server(self, **kwargs):
        port_range = kwargs.pop("port_range", _PORT_RANGE)
        bind_port = kwargs.pop("bind_port", 0)
        options = {
            # Long enough that no test sees an unasked-for PING; the
            # keep-alive test sets its own.
            "keepalive_interval": 30.0,
            "idle_timeout": 30.0,
            "handshake_timeout": 10.0,
            "session_timeout": 20.0,
        }
        options.update(kwargs)
        server = TunnelServer(self.store, _LOOPBACK, bind_port, port_range,
                              self.state_path, **options)
        server.start()
        self.addCleanup(server.stop)
        return server

    def config_for(self, server_port, identity="build-alpha", **overrides):
        """A beacon config whose `c2.tunnel` block points at `server_port`."""
        proxy = overrides.pop("proxy", {"mode": "none"})
        tunnel = {
            "enabled": True,
            "server": _LOOPBACK,
            "port": server_port,
            "public_key": base64.b64encode(self.public).decode("ascii"),
            "psk": base64.b64encode(self.psks[identity]).decode("ascii"),
            "identity": identity,
        }
        tunnel.update(overrides)
        return {"c2": {"tunnel": tunnel, "proxy": proxy}}

    def start_endpoint(self, config, factory=TunnelEndpoint):
        """An endpoint running `run()` on a thread, stopped and joined."""
        endpoint = factory(config)
        thread = threading.Thread(target=endpoint.run, name="endpoint",
                                  daemon=True)
        # LIFO: `stop` runs first, then the join it unblocks, and last the
        # assertion that the join was not a timeout. Without that
        # assertion a `run` that outlived its `stop` would leave the suite
        # green, which is a tunnel that ignores shutdown.
        self.addCleanup(self.assert_ended, thread)
        self.addCleanup(thread.join, 5.0)
        self.addCleanup(endpoint.stop)
        thread.start()
        return endpoint

    def assert_ended(self, thread):
        self.assertFalse(thread.is_alive(),
                         "the endpoint's run() thread outlived its stop()")

    def fast_retries(self):
        """Shrink the reconnect backoff so a restart test is not a wait.

        The shape is the beacon's own -- a base delay, 1.5 per failure, a
        ceiling -- and only the base is moved, so what is exercised is the
        real loop and not a different one.
        """
        original = beacon_mod._TUNNEL_RETRY_BASE
        beacon_mod._TUNNEL_RETRY_BASE = 0.05
        self.addCleanup(setattr, beacon_mod, "_TUNNEL_RETRY_BASE", original)

    def pure_python_aes(self, enabled):
        """Force the AES backend flag, as `test_tunnel_noise.py` does."""
        original = beacon_mod._USE_PURE_PYTHON_AES
        beacon_mod._USE_PURE_PYTHON_AES = enabled
        self.addCleanup(setattr, beacon_mod, "_USE_PURE_PYTHON_AES", original)

    def target(self, host=_LOOPBACK, banner=b"", echo=True):
        service = _Target(host=host, banner=banner, echo=echo)
        self.addCleanup(service.close)
        return service

    def row(self, server, identity):
        for row in server.endpoints():
            if row["identity"] == identity:
                return row
        return {"identity": identity, "state": "absent"}

    def wait_for(self, predicate, timeout=15.0, what="condition"):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return True
            time.sleep(0.01)
        self.fail("%s was still false after %.1fs" % (what, timeout))

    def wait_connected(self, server, identity="build-alpha", timeout=15.0):
        self.wait_for(
            lambda: self.row(server, identity)["state"] == "connected",
            timeout=timeout, what="the endpoint registering as %r" % identity)
        return self.row(server, identity)

    def relay(self, server, identity="build-alpha", timeout=15.0):
        """A paired relay stream, asked for the way the SOCKS port asks."""
        session = server.open_session(identity)
        self.addCleanup(session.close)
        self.assertTrue(
            session.wait_paired(timeout),
            "the endpoint did not dial a relay within %.1fs" % timeout)
        stream = session.sock
        stream.settimeout(timeout)
        return stream

    def request(self, stream, cmd, atyp, address, port):
        """One SOCKS request down a relay, and the decoded reply to it.

        The reply is read with `recv_message`, so a frame carrying anything
        but exactly one reply fails here -- which is what makes this the
        check that the endpoint never coalesces the target's first bytes
        into its answer.
        """
        stream.sendall(encode_socks_request(cmd, atyp, address, port))
        raw = stream.recv_message()
        self.assertTrue(raw, "the endpoint closed the relay without a reply")
        return decode_socks_reply(raw)


class TestRegistration(TunnelEndpointTestCase):
    def test_endpoint_connects_registers_and_appears_on_the_server(self):
        server = self.start_server()
        endpoint = self.start_endpoint(self.config_for(server.port))

        row = self.wait_connected(server)
        self.assertEqual(row["identity"], "build-alpha")
        self.assertEqual(row["state"], "connected")
        self.assertTrue(_PORT_RANGE[0] <= row["port"] <= _PORT_RANGE[1])
        # The HELLO carries what the panel shows, and the endpoint knows
        # its own host rather than being told it.
        self.assertTrue(row["hostname"])
        self.assertTrue(row["os"])
        # No beacon above this endpoint, so no implant to correlate with.
        # The server reports that as unlinked, which is a supported
        # deployment and not a missing field.
        self.assertIsNone(row["implant_id"])

        status = endpoint.status()
        self.assertEqual(status["identity"], "build-alpha")
        self.assertEqual(status["port"], server.port)
        self.assertTrue(status["connected"])
        self.assertEqual(status["egress"], "direct")
        self.assertEqual(status["sessions"], 0)

    def test_the_row_names_the_user_the_endpoint_runs_as(self):
        """The panel warns about a shell's rights, so it has to know them.

        A shell session has exactly the privileges of the endpoint process
        that spawned it: root when the endpoint came up from the service
        unit, and some unprivileged account when a generated build was
        started by hand. The panel used to state "root shell" for both,
        which is a claim nothing on the team server could check -- the
        HELLO carried hostname, OS, crypto and features, and no user.

        So the endpoint reports it, the way it already reports its own
        hostname rather than being told: from the effective uid, which is
        what the shell will actually have.
        """
        server = self.start_server()
        self.start_endpoint(self.config_for(server.port))

        row = self.wait_connected(server)

        expected = pwd.getpwuid(os.geteuid()).pw_name
        self.assertEqual(row["user"], expected,
                         "the row does not name the user whose rights the "
                         "shell session would have")

    def test_endpoint_sends_the_implant_id_when_the_config_carries_one(self):
        server = self.start_server()
        self.start_endpoint(self.config_for(server.port,
                                            implant_id="implant-abcd"))

        row = self.wait_connected(server)
        self.assertEqual(row["implant_id"], "implant-abcd")

    def with_environment_implant_id(self, value):
        """The variable a beacon sets on the child it spawns."""
        patch = mock.patch.dict(
            os.environ, {beacon_mod._TUNNEL_IMPLANT_ENV: value})
        patch.start()
        self.addCleanup(patch.stop)

    def test_endpoint_sends_the_implant_id_from_the_environment(self):
        """A beacon's child has no `implant_id` in its config, ever.

        The id is minted when the beacon starts, and the block the child
        reads was written by the generator before that, so no generated
        block emits the key at all. The beacon hands the id down in
        the environment instead, and the endpoint announces it: without
        that, the server sees an endpoint no fleet agent owns.
        """
        self.with_environment_implant_id("implant-from-the-beacon")
        server = self.start_server()
        self.start_endpoint(self.config_for(server.port))

        row = self.wait_connected(server)
        self.assertEqual(row["implant_id"], "implant-from-the-beacon")

    def test_the_config_wins_over_the_environment(self):
        # No generated config carries the key today, so this is the rule
        # for a config built by hand or by a future source: a value
        # written into the config is a statement about this endpoint's
        # identity, and the variable is only what a parent filled in.
        self.with_environment_implant_id("implant-from-the-beacon")
        server = self.start_server()
        self.start_endpoint(self.config_for(
            server.port, implant_id="implant-from-the-config"))

        row = self.wait_connected(server)
        self.assertEqual(row["implant_id"], "implant-from-the-config")

    def test_a_blank_config_id_does_not_shadow_the_environment(self):
        # Whitespace is absent on both sides: a config that carries
        # `"implant_id": "  "` must not stop the fallback.
        self.with_environment_implant_id("implant-from-the-beacon")
        server = self.start_server()
        self.start_endpoint(self.config_for(server.port, implant_id="  "))

        row = self.wait_connected(server)
        self.assertEqual(row["implant_id"], "implant-from-the-beacon")

    def test_a_blank_environment_id_is_no_id(self):
        self.with_environment_implant_id("   ")
        server = self.start_server()
        self.start_endpoint(self.config_for(server.port))

        row = self.wait_connected(server)
        self.assertIsNone(row["implant_id"])

    def test_hello_advertises_the_shell_feature(self):
        # Port 1234 is never dialled: nothing here runs the endpoint.
        endpoint = TunnelEndpoint(self.config_for(1234))
        self.addCleanup(endpoint.stop)

        self.assertEqual(endpoint._hello()["features"], ["shell"])

    def test_a_hello_without_features_still_decodes(self):
        # What an endpoint built before this field existed sends.
        kind, body = decode_message(encode_message(MSG_HELLO,
                                                   {"identity": "x"}))
        self.assertEqual(kind, MSG_HELLO)
        self.assertNotIn("features", body)

    def test_endpoint_answers_ping_with_pong(self):
        # The server drops an endpoint that is silent for a whole idle
        # timeout, so an endpoint still connected well past three
        # keep-alives is one whose PONGs are arriving.
        server = self.start_server(keepalive_interval=0.2, idle_timeout=0.8)
        self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)

        time.sleep(2.0)
        row = self.row(server, "build-alpha")
        self.assertEqual(row["state"], "connected")
        self.assertLess(row["last_seen_age"], 0.8)

    def test_endpoint_reconnects_after_the_server_disappears(self):
        self.fast_retries()
        server = self.start_server()
        port = server.port
        self.start_endpoint(self.config_for(port))
        first = self.wait_connected(server)

        server.stop()
        # `stop` clears the endpoint table synchronously, so the row is
        # already disconnected -- and it is still a row, because the
        # identity keeps the SOCKS port it was assigned.
        self.assertEqual(self.row(server, "build-alpha")["state"],
                         "disconnected")

        # A new server over the same port table and the same port: a
        # restart as an operator performs it, not a reconnect method.
        restarted = self.start_server(bind_port=port)
        self.assertEqual(restarted.port, port)
        row = self.wait_connected(restarted)
        self.assertEqual(row["port"], first["port"],
                         "the identity came back on a different SOCKS port")


class TestCarryingAConnect(TunnelEndpointTestCase):
    def test_endpoint_dials_a_relay_when_asked_and_carries_a_connect(self):
        server = self.start_server()
        endpoint = self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)
        service = self.target(banner=b"SSH-2.0-stub\r\n")

        stream = self.relay(server)
        reply, atyp, address, port = self.request(
            stream, CMD_CONNECT, ATYP_IPV4, _LOOPBACK, service.port)
        self.assertEqual(reply, REPLY_SUCCEEDED)
        # RFC 1928 §6: BND.ADDR and BND.PORT are the endpoint's own
        # outgoing socket, not a canned zero.
        self.assertEqual(atyp, ATYP_IPV4)
        self.assertEqual(address, _LOOPBACK)
        self.assertNotEqual(port, 0)

        # The banner was already on its way when the reply was written, so
        # this is the assertion that the reply was a frame of its own.
        self.assertEqual(stream.recv(len(service.banner)), service.banner)
        stream.sendall(b"hello")
        self.assertEqual(stream.recv(64), b"echo:hello")

        self.wait_for(lambda: endpoint.status()["sessions"] == 1,
                      what="the endpoint counting its relay")

    def test_endpoint_carries_a_connect_to_a_domain_name(self):
        server = self.start_server()
        self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)
        service = self.target()

        stream = self.relay(server)
        reply = self.request(stream, CMD_CONNECT, ATYP_DOMAIN, "localhost",
                             service.port)[0]
        self.assertEqual(reply, REPLY_SUCCEEDED)
        stream.sendall(b"named")
        self.assertEqual(stream.recv(64), b"echo:named")

    @unittest.skipUnless(_ipv6_loopback_works(), "no IPv6 loopback here")
    def test_endpoint_carries_a_connect_to_an_ipv6_target(self):
        server = self.start_server()
        self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)
        service = self.target(host=_LOOPBACK6)

        stream = self.relay(server)
        reply, atyp, address, port = self.request(
            stream, CMD_CONNECT, ATYP_IPV6, _LOOPBACK6, service.port)
        self.assertEqual(reply, REPLY_SUCCEEDED)
        # The bound address is the family the endpoint actually left on,
        # which for an IPv6 target is an IPv6 socket.
        self.assertEqual(atyp, ATYP_IPV6)
        self.assertEqual(socket.inet_pton(socket.AF_INET6, address),
                         socket.inet_pton(socket.AF_INET6, _LOOPBACK6))
        self.assertNotEqual(port, 0)

        stream.sendall(b"six")
        self.assertEqual(stream.recv(64), b"echo:six")

    def test_two_relays_at_once_do_not_cross_their_streams(self):
        server = self.start_server()
        self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)
        one = self.target()
        two = self.target()

        first = self.relay(server)
        second = self.relay(server)
        self.assertEqual(self.request(first, CMD_CONNECT, ATYP_IPV4,
                                      _LOOPBACK, one.port)[0], REPLY_SUCCEEDED)
        self.assertEqual(self.request(second, CMD_CONNECT, ATYP_IPV4,
                                      _LOOPBACK, two.port)[0], REPLY_SUCCEEDED)
        first.sendall(b"one")
        second.sendall(b"two")
        self.assertEqual(first.recv(64), b"echo:one")
        self.assertEqual(second.recv(64), b"echo:two")

    def test_a_target_that_closes_ends_the_session(self):
        server = self.start_server()
        self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)
        service = self.target(banner=b"bye", echo=False)

        stream = self.relay(server)
        self.assertEqual(self.request(stream, CMD_CONNECT, ATYP_IPV4,
                                      _LOOPBACK, service.port)[0],
                         REPLY_SUCCEEDED)
        self.assertEqual(stream.recv(3), b"bye")
        service.close()
        # The far end finishing is reported as an empty read and not as a
        # session that hangs on for ever.
        self.assertEqual(stream.recv(64), b"")


class TestEgress(TunnelEndpointTestCase):
    def test_a_relay_dials_the_port_the_endpoint_was_configured_with(self):
        # The one case in which the server's bound port and the
        # endpoint's configured port differ -- a redirector in front of
        # the tunnel server, which is the deployment the one-port design
        # exists for. Every other test in this file runs both halves on
        # one real port, so the two values are never allowed to disagree
        # and a relay that dialled the server-advertised number would
        # pass them all.
        server = self.start_server()
        redirector = _Redirector(_LOOPBACK, server.port)
        self.addCleanup(redirector.close)
        self.assertNotEqual(redirector.port, server.port)

        self.start_endpoint(self.config_for(redirector.port))
        self.wait_connected(server)
        self.relay(server)

        # The command channel and the relay, both through the front: a
        # relay that went to `server.port` direct would leave this at one
        # while every other assertion in the suite still passed.
        self.assertEqual(redirector.connections, 2,
                         "the relay did not go through the port the "
                         "endpoint was configured with")
        self.assertEqual(redirector.errors, [])

    def test_endpoint_connects_through_a_local_connect_proxy(self):
        server = self.start_server()
        proxy = _ConnectProxy()
        self.addCleanup(proxy.close)
        config = self.config_for(
            server.port,
            proxy={"mode": "manual", "url": "http://%s:%d" % (_LOOPBACK,
                                                              proxy.port)})
        endpoint = self.start_endpoint(config)

        self.wait_connected(server)
        self.assertEqual(
            proxy.request_lines[0],
            "CONNECT %s:%d HTTP/1.1" % (_LOOPBACK, server.port),
            "the endpoint asked the proxy for the wrong target")
        self.assertEqual(endpoint.status()["egress"],
                         "proxy %s:%d" % (_LOOPBACK, proxy.port))
        self.assertEqual(proxy.errors, [])

    def test_a_relay_takes_the_same_way_out_as_the_command_channel(self):
        server = self.start_server()
        proxy = _ConnectProxy()
        self.addCleanup(proxy.close)
        config = self.config_for(
            server.port,
            proxy={"mode": "manual", "url": "http://%s:%d" % (_LOOPBACK,
                                                              proxy.port)})
        self.start_endpoint(config)
        self.wait_connected(server)
        service = self.target()

        stream = self.relay(server)
        self.assertEqual(self.request(stream, CMD_CONNECT, ATYP_IPV4,
                                      _LOOPBACK, service.port)[0],
                         REPLY_SUCCEEDED)
        # One CONNECT for the command channel and one for the relay: the
        # single server port is what makes both acceptable to a proxy that
        # permits 443 and nothing else.
        self.assertEqual(len(proxy.request_lines), 2)
        self.assertEqual(set(proxy.request_lines),
                         {"CONNECT %s:%d HTTP/1.1" % (_LOOPBACK,
                                                      server.port)})

    def test_a_proxy_that_refuses_the_connect_falls_back_to_direct(self):
        # A proxy answering 403 is the corporate case this endpoint has to
        # survive: the way out has to be tried in order and the last of
        # them is always direct.
        server = self.start_server()
        refuser = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(refuser.close)
        refuser.bind((_LOOPBACK, 0))
        refuser.listen(4)
        refused_port = refuser.getsockname()[1]
        stop = threading.Event()

        def refuse():
            refuser.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = refuser.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                try:
                    conn.recv(4096)
                    conn.sendall(b"HTTP/1.1 403 Forbidden\r\n"
                                 b"Content-Length: 0\r\n\r\n")
                except OSError:
                    pass
                finally:
                    conn.close()

        thread = threading.Thread(target=refuse, daemon=True, name="refuser")
        # LIFO, so the flag is set before the join that waits on it.
        self.addCleanup(thread.join, 3.0)
        self.addCleanup(stop.set)
        thread.start()

        config = self.config_for(
            server.port,
            proxy={"mode": "manual",
                   "url": "http://%s:%d" % (_LOOPBACK, refused_port)})
        endpoint = self.start_endpoint(config)

        self.wait_connected(server)
        self.assertEqual(endpoint.status()["egress"], "direct")


class TestAnUnreachableTarget(TunnelEndpointTestCase):
    def unreachable(self, server, failure, atyp=ATYP_IPV4,
                    address=_LOOPBACK, port=1):
        """Ask for a target that cannot be reached, and read the answer."""
        factory = TunnelEndpoint
        if failure is not None:
            def factory(config):
                endpoint = _UnreachableEndpoint(config)
                endpoint.failure = failure
                return endpoint
        self.start_endpoint(self.config_for(server.port), factory=factory)
        self.wait_connected(server)
        stream = self.relay(server)
        reply = self.request(stream, CMD_CONNECT, atyp, address, port)[0]
        return reply, stream

    def test_connection_refused_becomes_socks_reply_05(self):
        server = self.start_server()
        reply, stream = self.unreachable(server, None, port=_free_port())
        self.assertEqual(reply, REPLY_CONNECTION_REFUSED)
        # And the session is over rather than left half-open: an operator's
        # tool waiting on a refused connection is the failure this answers.
        self.assertEqual(stream.recv(16), b"")

    def test_no_route_becomes_socks_reply_03(self):
        server = self.start_server()
        reply, stream = self.unreachable(
            server, OSError(errno.ENETUNREACH, "Network is unreachable"))
        self.assertEqual(reply, REPLY_NETWORK_UNREACHABLE)
        self.assertEqual(stream.recv(16), b"")

    def test_unresolvable_name_becomes_socks_reply_04(self):
        server = self.start_server()
        reply, stream = self.unreachable(server, None, atyp=ATYP_DOMAIN,
                                         address=_UNRESOLVABLE, port=80)
        self.assertEqual(reply, REPLY_HOST_UNREACHABLE)
        self.assertEqual(stream.recv(16), b"")

    def test_a_connect_that_hangs_past_the_timeout_closes_the_session(self):
        server = self.start_server()
        reply, stream = self.unreachable(
            server, socket.timeout("timed out"))
        self.assertEqual(reply, REPLY_TTL_EXPIRED)
        self.assertEqual(stream.recv(16), b"")

    def test_an_unmapped_errno_becomes_the_general_failure_reply(self):
        server = self.start_server()
        reply = self.unreachable(
            server, OSError(errno.EPIPE, "Broken pipe"))[0]
        self.assertEqual(reply, beacon_mod.REPLY_GENERAL_FAILURE)

    def test_bind_and_udp_associate_are_refused_with_the_right_code(self):
        server = self.start_server()
        self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)
        for cmd in (beacon_mod.CMD_BIND, beacon_mod.CMD_UDP_ASSOCIATE):
            with self.subTest(cmd=cmd):
                stream = self.relay(server)
                reply = self.request(stream, cmd, ATYP_IPV4, _LOOPBACK,
                                     9)[0]
                self.assertEqual(reply,
                                 beacon_mod.REPLY_COMMAND_NOT_SUPPORTED)


class TestTheThroughputGate(TunnelEndpointTestCase):
    def test_pure_python_aes_refuses_to_start_and_says_why(self):
        self.pure_python_aes(True)
        server = self.start_server()
        endpoint = TunnelEndpoint(self.config_for(server.port))
        self.addCleanup(endpoint.stop)

        with self.assertRaises(RuntimeError) as caught:
            endpoint.run()
        message = str(caught.exception)
        self.assertIn("allow_slow_crypto", message)
        self.assertIn("KB/s", message)
        # It refused before connecting, so nothing registered.
        self.assertEqual(server.endpoints(), [])

    def test_the_override_lets_it_start_and_the_status_reports_the_slow_path(
            self):
        self.pure_python_aes(True)
        server = self.start_server()
        endpoint = self.start_endpoint(
            self.config_for(server.port, allow_slow_crypto=True))

        row = self.wait_connected(server)
        # The endpoint's own path, carried in its HELLO. `server_crypto`
        # is this process and is a different fact: on a target with no
        # libcrypto the two disagree, and a row that reported only the
        # server's would say `openssl` in exactly the case the display
        # exists for.
        self.assertEqual(row["endpoint_crypto"], "pure-python")
        self.assertIn(row["server_crypto"], ("openssl", "pure-python"))
        status = endpoint.status()
        self.assertEqual(status["crypto"], "pure-python")
        self.assertTrue(status["slow_crypto_allowed"])

    def test_a_row_with_no_endpoint_on_it_reports_no_endpoint_crypto(self):
        # It arrives with the HELLO and leaves with the channel: the
        # server cannot know a disconnected endpoint's cipher, and a row
        # that kept the last value would be asserting something about a
        # host it has not heard from.
        self.fast_retries()
        server = self.start_server()
        endpoint = self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)
        endpoint.stop()

        self.wait_for(
            lambda: self.row(server, "build-alpha")["state"] == "disconnected",
            what="the server noticing the endpoint went")
        row = self.row(server, "build-alpha")
        self.assertIsNone(row["endpoint_crypto"])
        self.assertIn(row["server_crypto"], ("openssl", "pure-python"))

    def test_the_fast_path_needs_no_override(self):
        if beacon_mod._USE_PURE_PYTHON_AES:
            self.skipTest("this host has no libcrypto, so there is no fast "
                          "path to assert on")
        server = self.start_server()
        endpoint = self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)
        self.assertEqual(endpoint.status()["crypto"], "openssl")


class TestLifecycle(TunnelEndpointTestCase):
    """`stop` is final, and final before `run` as well as during it.

    Task 8 is the consumer that owns this: it starts the endpoint on a
    thread and stops it on a command, so a `stop` arriving in the
    milliseconds between `thread.start()` and `run`'s first line is an
    ordinary event and not a contrived one. These tests do not race for
    it -- they set the flag first and then require `run` to honour it,
    which is the same property without the timing.
    """

    def test_stop_before_run_keeps_the_endpoint_from_dialling(self):
        server = self.start_server()
        endpoint = TunnelEndpoint(self.config_for(server.port))
        endpoint.stop()

        ended = threading.Event()

        def once():
            endpoint.run()
            ended.set()

        thread = threading.Thread(target=once, name="endpoint", daemon=True)
        self.addCleanup(self.assert_ended, thread)
        self.addCleanup(thread.join, 5.0)
        thread.start()

        self.assertTrue(
            ended.wait(5.0),
            "run() did not return after a stop() that preceded it; a run "
            "that clears the flag reconnects for ever instead")
        self.assertEqual(server.endpoints(), [],
                         "the endpoint dialled out after it had been stopped")
        self.assertFalse(endpoint.status()["connected"])

    def test_stop_is_safe_twice_and_after_a_session(self):
        server = self.start_server()
        endpoint = self.start_endpoint(self.config_for(server.port))
        self.wait_connected(server)

        endpoint.stop()
        endpoint.stop()
        self.assertFalse(endpoint.status()["connected"])


@unittest.skipUnless(_HAS_PTY, _NO_PTY)
class TestWritingToATerminal(unittest.TestCase):
    """`_write_all`: the loop that must not outlast the session it serves.

    Against a pipe rather than a PTY master, deliberately. A full pipe
    applies back-pressure on every platform; a full tty input queue does
    so only on Linux, because BSD discards the overflow instead -- so on
    the machine this was written on a master write cannot be made to
    block at all, and the end-to-end version of this test (in
    `TestAShellSession`) can only bite on the deployment target. What is
    under test here is the loop, which is the same loop either way.
    """

    def test_a_write_nobody_drains_ends_when_the_session_does(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        os.set_blocking(write_fd, False)
        # Filled the way a foreground command that never reads its stdin
        # fills the slave's input queue.
        while True:
            try:
                os.write(write_fd, b"x" * 65536)
            except BlockingIOError:
                break
        over = threading.Event()
        returned = []

        def write():
            returned.append(beacon_mod._write_all(
                write_fd, b"y" * 4096, lambda: not over.is_set(), select))

        thread = threading.Thread(target=write, name="write-all", daemon=True)
        # Joined before the descriptors are closed under it: LIFO, so
        # this cleanup runs first.
        self.addCleanup(thread.join, 5.0)
        thread.start()

        thread.join(0.6)
        self.assertTrue(thread.is_alive(),
                        "the write returned although nothing had drained "
                        "the pipe: a byte went somewhere it could not")
        self.assertEqual(returned, [])

        over.set()

        thread.join(5.0)
        self.assertFalse(thread.is_alive(),
                         "the write did not end with its session; on a PTY "
                         "master this is the thread that runs the teardown")
        self.assertEqual(returned, [False],
                         "a write cut short by the end of its session "
                         "reported success")


class _ShellChoice(object):
    """The stand-ins for the host that the shell choice is tested against.

    Each one answers for the paths it is told about and leaves every other
    path to the real function. A patch of `os.path` is process-wide, so
    one that answered for everything would also lie to whatever else asks
    while it is in force.
    """

    @contextlib.contextmanager
    def _passwd(self, shell):
        """The effective user's passwd entry names `shell` as login shell."""
        entry = mock.Mock(pw_shell=shell)
        with mock.patch.object(pwd, "getpwuid", return_value=entry):
            yield

    @contextlib.contextmanager
    def _executable(self, paths):
        """Only the paths given are executable files, whatever this host has.

        The probe and `os.path.isfile` both, because the chooser asks
        both and a path like `/usr/local/bin/bash` is not on every host.
        `isfile` is the host's own for a path that is not one of these:
        the chooser needs both answers to be yes, and the probe is no for
        every such path.
        """
        real_isfile = os.path.isfile

        def isfile(path):
            return True if path in paths else real_isfile(path)

        with mock.patch.object(beacon_mod, "_shell_executable",
                               lambda path: path in paths), \
                mock.patch.object(os.path, "isfile", isfile):
            yield

    @contextlib.contextmanager
    def _dev_fd(self, present):
        """The host has, or has not, a `/dev/fd` directory."""
        real_isdir = os.path.isdir

        def isdir(path):
            return present if path == beacon_mod._DEV_FD else real_isdir(path)

        with mock.patch.object(os.path, "isdir", isdir):
            yield


class TestTheLoginShell(_ShellChoice, unittest.TestCase):
    """Which shell a session runs, chosen without spawning one.

    Apart from `TestAShellSession`, which turns the login shell off so
    that the choice is bash where the host has one and `/bin/sh` where it
    does not, and its assertions do not depend on whose account runs the
    suite: here the choice itself is under test, with the passwd entry
    and the executable probe both stood in for.
    """

    @contextlib.contextmanager
    def _passwd_of(self, lookup):
        """`pwd.getpwuid` is `lookup`, and the two uids are told apart."""
        with mock.patch.object(pwd, "getpwuid", side_effect=lookup), \
                mock.patch.object(os, "geteuid", return_value=4242), \
                mock.patch.object(os, "getuid", return_value=1):
            yield

    def _names_used_by(self, function):
        """Every name `function` reads or imports, as the parser sees it.

        Identifiers and not text: a docstring, a comment and a variable
        that merely contains the letters are not the function doing
        anything. What is collected is each `ast.Name`, each attribute
        accessed (`os.environ` gives `environ`) and each name imported, so
        a test can ask whether the environment is *named* and an unrelated
        local called `environment` is not.
        """
        names = set()
        for node in ast.walk(ast.parse(
                textwrap.dedent(inspect.getsource(function)))):
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
            elif isinstance(node, ast.alias):
                names.add(node.name.split(".")[-1])
        return names

    def test_the_login_shell_of_the_effective_user_is_what_runs(self):
        """`$SHELL` under the shipped service unit is the service
        manager's environment, not a user's choice, so the passwd entry
        is what is asked."""
        with self._passwd("/bin/zsh"), self._executable({"/bin/zsh"}):
            self.assertEqual(beacon_mod._shell_program(), "/bin/zsh")

    def test_a_login_shell_that_is_not_there_does_not_cost_the_session(self):
        for shell in ("/usr/bin/fish", "", "/nonexistent/zsh"):
            with self._passwd(shell), self._executable({"/bin/bash"}):
                self.assertEqual(beacon_mod._shell_program(), "/bin/bash",
                                 shell)

    def test_a_shell_nobody_has_driven_with_flags_is_not_driven(self):
        """fish and tcsh take neither `--rcfile` nor bash's `-i`
        semantics, so the preference runs rather than an untested flag."""
        with self._passwd("/usr/bin/fish"), \
                self._executable({"/usr/bin/fish", "/bin/bash"}):
            self.assertEqual(beacon_mod._shell_program(), "/bin/bash")

    def test_a_bash_or_zsh_wherever_the_host_keeps_it_is_the_login_shell(self):
        for shell in ("/usr/local/bin/bash", "/usr/bin/bash", "/bin/bash",
                      "/usr/bin/zsh", "/opt/homebrew/bin/zsh"):
            with self._passwd(shell), self._executable({shell, "/bin/sh"}):
                self.assertEqual(beacon_mod._shell_program(), shell, shell)

    def test_only_bash_and_zsh_are_ever_the_login_shell(self):
        for shell in ("/sbin/nologin", "/usr/bin/false", "/bin/sh",
                      "/bin/ksh", "/bin/dash", "/bin/tcsh", "/usr/bin/fish"):
            with self._passwd(shell), \
                    self._executable({shell, "/bin/bash", "/bin/sh"}):
                self.assertEqual(beacon_mod._shell_program(), "/bin/bash",
                                 shell)
                self.assertEqual(beacon_mod._login_shell(), "", shell)

    def test_the_environments_shell_is_not_a_fallback_either(self):
        """An empty passwd answer does not hand the choice to `$SHELL`."""
        with self._passwd(""), \
                self._executable({"/bin/zsh", "/bin/bash"}), \
                mock.patch.dict(os.environ, {"SHELL": "/bin/zsh"}):
            self.assertEqual(beacon_mod._shell_program(), "/bin/bash")

    def test_a_directory_is_not_a_shell(self):
        """`os.access(X_OK)` is true of a directory, so the probe alone
        would accept it and the session would die at exec."""
        for name in ("bash", "zsh"):
            directory = os.path.join(tempfile.mkdtemp(), name)
            os.mkdir(directory)
            self.addCleanup(shutil.rmtree, os.path.dirname(directory),
                            True)
            self.assertTrue(os.access(directory, os.X_OK))
            with self._passwd(directory):
                self.assertEqual(beacon_mod._login_shell(), "", directory)

    def test_a_relative_name_is_not_a_shell(self):
        """`os.access` resolves it against the working directory and
        `Popen` against `PATH`: the probe could be about another file."""
        for shell in ("bash", "zsh", "./bash", "bin/zsh"):
            with self._passwd(shell), self._executable({shell, "/bin/sh"}):
                self.assertEqual(beacon_mod._login_shell(), "", shell)

    def test_a_malformed_passwd_entry_falls_back_rather_than_throwing(self):
        def unreadable(uid):
            raise OSError("passwd unreadable")

        def without_a_shell(uid):
            return mock.Mock(spec=[])

        for lookup in (unreadable, without_a_shell):
            with self._passwd_of(lookup), self._executable({"/bin/bash"}):
                self.assertEqual(beacon_mod._shell_program(), "/bin/bash",
                                 lookup.__name__)

    def test_it_is_the_effective_uid_whose_entry_is_asked(self):
        entry = mock.Mock(pw_shell="/bin/zsh")

        def lookup(uid):
            if uid != 4242:
                raise KeyError(uid)
            return entry

        with self._passwd_of(lookup), \
                self._executable({"/bin/zsh", "/bin/bash"}):
            self.assertEqual(beacon_mod._shell_program(), "/bin/zsh")

    @unittest.skipUnless(os.path.isdir("/dev/fd"), "no /dev/fd to hand bash")
    def test_a_bash_that_is_not_in_bin_still_gets_the_generated_rcfile(self):
        """Comparing the path with `/bin/bash` said "not bash" of
        `/usr/local/bin/bash`, and the session lost the rcfile: no
        completion, and history on."""
        shell = "/usr/local/bin/bash"
        with self._passwd(shell), self._executable({shell}):
            argv, env, held = beacon_mod._shell_invocation(80, 24)
        for fd in held:
            os.close(fd)
        self.assertEqual(argv[:2], [shell, "--rcfile"])
        self.assertEqual(argv[3:], ["-i"])
        self.assertEqual(len(held), 1)
        self.assertNotEqual(env.get("HISTFILE"), os.devnull)

    def test_a_shell_that_is_not_bash_takes_the_weaker_path(self):
        with self._passwd("/bin/zsh"), self._executable({"/bin/zsh"}):
            argv, env, held = beacon_mod._shell_invocation(80, 24)
        self.assertEqual(argv, ["/bin/zsh", "-i"])
        self.assertEqual((env["HISTFILE"], held), (os.devnull, ()))

    def test_a_pipe_that_cannot_be_opened_refuses_rather_than_records(self):
        """The downgrade this replaces was the worst trade available: a
        session that quietly wrote the operator's commands to their own
        history file while the view said history was off."""
        with self._passwd("/bin/bash"), self._executable({"/bin/bash"}), \
                self._dev_fd(True), \
                mock.patch.object(beacon_mod, "_shell_rcfile_fd",
                                  side_effect=OSError("too many files")):
            with self.assertRaises(OSError):
                beacon_mod._shell_invocation(80, 24)

    def test_the_guard_a_host_reports_is_the_guard_a_session_gets(self):
        """What `HELLO` carries has to be what the spawn does, or the
        view states a fact about the wrong thing."""
        cases = (("/bin/bash", True, "off"),
                 ("/usr/local/bin/bash", True, "off"),
                 ("/bin/zsh", True, "weak"),
                 ("/bin/bash", False, "weak"))
        for shell, has_dev_fd, expected in cases:
            with self._passwd(shell), self._executable({shell}), \
                    self._dev_fd(has_dev_fd):
                guard, detail = beacon_mod._history_guard()
                argv, env, held = beacon_mod._shell_invocation(80, 24)
            for fd in held:
                os.close(fd)
            case = (shell, has_dev_fd)
            self.assertEqual(guard, expected, case)
            self.assertEqual("--rcfile" in argv, guard == "off",
                             "the spawn disagreed with the report")
            self.assertEqual(env.get("HISTFILE") == os.devnull,
                             guard == "weak", case)
            self.assertEqual(bool(detail), guard == "weak", case)

    def test_the_invocation_acts_on_the_shell_it_chose_not_on_a_second_look(self):
        """`_guard_of` exists so that the program and the guard come from
        one passwd lookup. Every other test holds the entry constant, where
        one lookup and two cannot differ; a login shell changed between
        the two (`chsh` on a service that has run for months) is the case
        that can."""
        for first, second, rcfile in (("/bin/bash", "/bin/zsh", True),
                                      ("/bin/zsh", "/bin/bash", False)):
            lookups = [mock.Mock(pw_shell=first)] + (
                [mock.Mock(pw_shell=second)] * 5)
            with self._executable({"/bin/bash", "/bin/zsh"}), \
                    self._dev_fd(True), \
                    mock.patch.object(pwd, "getpwuid",
                                      side_effect=lookups) as lookup:
                argv, env, held = beacon_mod._shell_invocation(80, 24)
            for fd in held:
                os.close(fd)
            case = (first, second)
            self.assertEqual(argv[0], first, case)
            self.assertEqual("--rcfile" in argv, rcfile, case)
            self.assertEqual(env.get("HISTFILE") == os.devnull, not rcfile,
                             case)
            self.assertEqual(lookup.call_count, 1, case)

    def test_a_guard_that_no_longer_matches_the_reported_one_is_refused(self):
        """The half of the guard that can go stale, caught at the session.

        `/dev/fd` is the host's and does not move. The login shell is the
        user's: `chsh`, or a bash removed, takes effect on the next
        session of an endpoint that has been connected for months, and
        the panel would still be showing what the HELLO said. So the
        invocation is told what was reported and builds nothing when the
        session it would build disagrees -- in either direction, because
        "reported weak and this one is off" is a view that is just as
        untrue of the session in front of the operator, and one
        comparison that refuses both ways cannot be got subtly wrong.

        The pair is compared and not the word. The last two refusals are
        weak both times and differ in the reason, which is printed beside
        the word: a panel that blames `/bin/zsh` over a session
        that is bash without a `/dev/fd` is wrong about the part an
        operator acts on.

        `None` is a caller that has reported nothing: there is nothing to
        contradict, and every other test here passes two arguments.
        """
        cases = (  # (shell then, /dev/fd then, shell now, /dev/fd now)
            ("/bin/bash", True, "/bin/bash", True, False),
            ("/bin/zsh", True, "/bin/zsh", True, False),
            ("/bin/bash", False, "/bin/bash", False, False),
            ("/bin/bash", True, "/bin/zsh", True, True),
            ("/bin/zsh", True, "/bin/bash", True, True),
            ("/bin/bash", False, "/bin/zsh", True, True),
            ("/bin/zsh", True, "/bin/zsh", False, False),
            ("/bin/bash", True, "/bin/bash", False, True),
            ("/bin/zsh", True, "/usr/local/bin/zsh", True, True),
        )
        for then, fd_then, now, fd_now, refuses in cases:
            with self._passwd(then), self._executable({then}), \
                    self._dev_fd(fd_then):
                reported = beacon_mod._history_guard()
            held = ()
            with self._passwd(now), self._executable({now}), \
                    self._dev_fd(fd_now):
                try:
                    _, _, held = beacon_mod._shell_invocation(80, 24,
                                                              reported)
                    refused = False
                except beacon_mod._HistoryGuardChanged:
                    refused = True
            for fd in held:
                os.close(fd)
            self.assertEqual(refused, refuses,
                             (then, fd_then, now, fd_now, reported))

        with self._passwd("/bin/zsh"), self._executable({"/bin/zsh"}), \
                self._dev_fd(True):
            _, _, held = beacon_mod._shell_invocation(80, 24, None)
        self.assertEqual(held, ())

    def test_a_zsh_session_blames_the_shell_and_not_the_host(self):
        """The operator can tell a login zsh apart from an ancient host
        only if the reason says which it was."""
        with self._passwd("/bin/zsh"), self._executable({"/bin/zsh"}), \
                self._dev_fd(True):
            _, detail = beacon_mod._history_guard()
        self.assertIn("zsh", detail)
        self.assertNotIn(beacon_mod._DEV_FD, detail)
        # Read by an operator on the page's first line, so it says what
        # cannot be done and not which flag is missing.
        self.assertEqual(detail, "/bin/zsh cannot be given a startup file "
                                 "of ours")

    def test_a_host_without_dev_fd_blames_the_host_and_not_the_shell(self):
        with self._passwd("/bin/bash"), self._executable({"/bin/bash"}), \
                self._dev_fd(False):
            _, detail = beacon_mod._history_guard()
        self.assertIn(beacon_mod._DEV_FD, detail)
        self.assertNotIn("is not bash", detail)
        self.assertNotIn("startup file of ours", detail)

    # A guard that reads source is only worth what it reads. Mutating
    # `beacon.py` and re-running can silently run the *old* code: a `.pyc`
    # is trusted when the source's size and mtime-second match, and a
    # mutation that changes one character straight after another that did
    # the same matches. That happened here: a mutation looked caught by
    # the wrong test because it had not run at all. Between mutations,
    # delete `software/c2/__pycache__/beacon*` and run with `-B`.
    def test_the_environments_shell_variable_is_never_consulted(self):
        """By behaviour through the invocation, and by scan of every
        function that chooses a shell. `_shell_invocation` is not scanned:
        it reads `os.environ` for the child's environment, which is the
        right reading of it."""
        with self._passwd("/bin/zsh"), self._executable({"/bin/zsh"}), \
                mock.patch.dict(os.environ, {"SHELL": "/bin/ksh"}):
            self.assertEqual(beacon_mod._shell_program(), "/bin/zsh")
            self.assertEqual(beacon_mod._shell_invocation(80, 24)[0][0],
                             "/bin/zsh")
        for chooser in (beacon_mod._login_shell, beacon_mod._shell_program,
                        beacon_mod._history_guard, beacon_mod._guard_of):
            used = self._names_used_by(chooser)
            for reading in ("environ", "getenv"):
                self.assertNotIn(reading, used, chooser.__name__)

    def test_a_scan_for_the_environment_is_not_fooled_by_a_name(self):
        """The scan above has been tripped three times by text that was
        not a reading. It must see through a local called `environment`,
        catch both ways of reading the variable, and catch a reading whose
        name never appears as an attribute: a bare name and an import
        under another name are how one hides from a scan that walks only
        attributes, and both branches that see them were dead here --
        every test passed with either deleted."""
        from os import environ

        def innocent():
            """Says os.environ and getenv in prose."""
            environment = 1  # os.environ
            return environment

        def contains_the_letters():
            """Every kind of identifier the scan collects, each one
            *containing* a name it is looking for and none of them equal
            to one: a bare name, an attribute, and an import."""
            from somewhere import getenv_all
            return getenv_all(thing.environ_of(environment))

        def reads_environ():
            return os.environ.get("SHELL")

        def reads_getenv():
            return os.getenv("SHELL")

        def reads_a_bare_environ():
            """What `from os import environ` at the top of a module and a
            read down here looks like: no attribute is touched."""
            return dict(environ)

        def reads_getenv_under_another_name():
            """The name is in the import and nowhere else."""
            from os import getenv as ask
            return ask("SHELL")

        self.assertFalse({"environ", "getenv"}
                         & self._names_used_by(innocent))
        # By equality and not by substring. A set cannot be asked "does
        # any member contain this", so the question is put the other way:
        # the identifiers come back whole and the two readings are not in
        # them. Each of the three node kinds has to pass through that
        # test, so a scan that cut an identifier down to a name it knows
        # fails in whichever branch does it.
        found = self._names_used_by(contains_the_letters)
        self.assertLessEqual({"getenv_all", "environ_of", "environment"},
                             found)
        self.assertFalse({"environ", "getenv"} & found, found)
        self.assertIn("environ", self._names_used_by(reads_environ))
        self.assertIn("getenv", self._names_used_by(reads_getenv))
        self.assertIn("environ", self._names_used_by(reads_a_bare_environ))
        self.assertIn("getenv",
                      self._names_used_by(reads_getenv_under_another_name))

    def test_a_passwd_lookup_that_raises_falls_back_rather_than_throwing(self):
        with mock.patch.object(pwd, "getpwuid",
                               side_effect=KeyError("no such uid")), \
                self._executable({"/bin/bash"}):
            self.assertEqual(beacon_mod._shell_program(), "/bin/bash")


class TestTheHelloCarriesTheHistoryGuard(_ShellChoice,
                                        TunnelEndpointTestCase):
    """What a HELLO says about command history on this host.

    Modelled on `TestRegistration.test_hello_advertises_the_shell_feature`:
    port 1234 is never dialled, because the body is what is under test and
    not the connection.

    Said once, at connect, because what reads it is a panel looking at an
    endpoint row rather than at a session. The half of the answer that can
    go stale between the HELLO and a session -- the login shell -- is
    caught where the session is built; see `TestARefusedShellSession`.
    """

    def _body(self):
        endpoint = TunnelEndpoint(self.config_for(1234))
        self.addCleanup(endpoint.stop)
        return endpoint._hello()

    def test_hello_reports_the_history_guard_a_session_here_would_get(self):
        with self._passwd("/bin/bash"), self._executable({"/bin/bash"}), \
                self._dev_fd(True):
            body = self._body()
        self.assertEqual(body["history"], "off")
        self.assertEqual(body["history_detail"], "")

    def test_hello_reports_the_weaker_guard_and_what_caused_it(self):
        """Both branches, because the "off" case on its own is passed by a
        body that says "off" whatever the host is."""
        with self._passwd("/bin/zsh"), self._executable({"/bin/zsh"}), \
                self._dev_fd(True):
            body = self._body()
        self.assertEqual(body["history"], "weak")
        self.assertIn("zsh", body["history_detail"])

    def test_a_host_without_dev_fd_reports_the_weaker_guard_too(self):
        with self._passwd("/bin/bash"), self._executable({"/bin/bash"}), \
                self._dev_fd(False):
            body = self._body()
        self.assertEqual(body["history"], "weak")
        self.assertIn(beacon_mod._DEV_FD, body["history_detail"])


@unittest.skipUnless(_HAS_PTY, _NO_PTY)
class TestARefusedShellSession(_ShellChoice, TunnelEndpointTestCase):
    """What `_serve_shell` does when the history guard cannot be built.

    The socket and the noise session are `None`: the refusal is the only
    thing that would touch them and it is stood in for, so a session that
    reached for either anywhere else would fail here.
    """

    def _serve_with_a_pipe_that_fails(self, error):
        """Run `_serve_shell` with bash chosen and its rcfile pipe failing.

        Returns the reasons given for refusing, and the master descriptors
        `openpty` handed out so the caller can see they were closed.
        """
        refusals = []
        masters = []
        pty_mod = beacon_mod._shell_modules()[0]
        real_openpty = pty_mod.openpty

        def openpty():
            master, slave = real_openpty()
            masters.extend((master, slave))
            return master, slave

        endpoint = TunnelEndpoint(self.config_for(1234))
        self.addCleanup(endpoint.stop)
        with self._passwd("/bin/bash"), self._executable({"/bin/bash"}), \
                self._dev_fd(True), \
                mock.patch.object(pty_mod, "openpty", openpty), \
                mock.patch.object(beacon_mod, "_shell_rcfile_fd",
                                  side_effect=error), \
                mock.patch.object(TunnelEndpoint, "_refuse_shell",
                                  lambda self, sock, noise, reason:
                                  refusals.append(reason)):
            endpoint._serve_shell(None, None, 80, 24)
        return endpoint, refusals, masters

    def _serve_after_the_login_shell_changed(self, at_hello, at_session):
        """A HELLO on one login shell, and then a session on another.

        The HELLO goes through `_hello`, not by writing whatever it
        remembers: what has to be checked against is what was *reported*,
        and a test that set the memory by hand would hold no claim about
        that. Returns the guard the HELLO carried as well, so each test
        can say which direction it drove.
        """
        refusals = []
        masters = []
        pty_mod = beacon_mod._shell_modules()[0]
        real_openpty = pty_mod.openpty

        def openpty():
            master, slave = real_openpty()
            masters.extend((master, slave))
            return master, slave

        endpoint = TunnelEndpoint(self.config_for(1234))
        self.addCleanup(endpoint.stop)
        with self._passwd(at_hello), self._executable({at_hello}), \
                self._dev_fd(True):
            reported = endpoint._hello()["history"]
        with self._passwd(at_session), self._executable({at_session}), \
                self._dev_fd(True), \
                mock.patch.object(pty_mod, "openpty", openpty), \
                mock.patch.object(TunnelEndpoint, "_refuse_shell",
                                  lambda self, sock, noise, reason:
                                  refusals.append(reason)):
            endpoint._serve_shell(None, None, 80, 24)
        return endpoint, reported, refusals, masters

    def test_the_operator_is_told_the_login_shell_changed_under_them(self):
        """`chsh` between the HELLO and the session, which is the whole
        reason the reported guard is checked again here. The sentence has
        to say that it changed since the tunnel connected, show both
        answers, and say that reconnecting reports the new one -- the
        operator is looking at a panel that is now out of date and nothing
        else will tell them."""
        _, reported, refusals, _ = self._serve_after_the_login_shell_changed(
            "/bin/bash", "/bin/zsh")
        self.assertEqual(reported, "off")
        self.assertEqual(len(refusals), 1)
        self.assertRegex(refusals[0], r"(?i)histor")
        self.assertRegex(refusals[0], r"(?i)reconnect")
        self.assertRegex(refusals[0], r"(?i)since the tunnel connected")
        self.assertIn("told history is off", refusals[0])
        self.assertIn("history not guaranteed off (/bin/zsh cannot be given "
                      "a startup file of ours)", refusals[0])
        self.assertNotRegex(refusals[0], r"Traceback|OSError\(")
        self._assert_speaks_as_the_page(refusals[0])

    def _assert_speaks_as_the_page(self, refusal):
        """The page's words, not the code's: no `%r` quoting, no `weak`,
        which the page never shows a person, and the one way to reconnect
        that reports the answer again. The guard is remembered in `_hello`,
        which runs only when the command channel reconnects; a shell is a
        message on the channel already up, so closing the view and opening
        another changes nothing and the person would be declined in a
        loop. Only stopping and starting the endpoint, each a task taken at
        a check-in, builds a fresh endpoint and a fresh HELLO."""
        self.assertNotIn("'", refusal.replace("host's", "")
                         .replace("doesn't", ""))
        self.assertNotRegex(refusal, r"\bweak\b")
        self.assertIn("tunnel panel", refusal)
        self.assertRegex(refusal, r"Stop this endpoint[^.]*Start it")
        self.assertRegex(refusal, r"(?i)check-in")
        self.assertRegex(refusal, r"(?i)only when the tunnel itself "
                                  r"reconnects")
        # Named only to say it does not work, never as the advice.
        self.assertNotIn("\u2715", refusal)
        self.assertNotIn("Open a shell", refusal)
        self.assertRegex(refusal, r"(?i)opening another shell does not do it")

    def test_a_guard_that_changed_the_other_way_is_refused_as_well(self):
        """Reported `weak`, and this session would hold history off. The
        view is no more true of the session than in the other direction,
        and one comparison that refuses both ways is the rule that cannot
        be got subtly wrong."""
        _, reported, refusals, _ = self._serve_after_the_login_shell_changed(
            "/bin/zsh", "/bin/bash")
        self.assertEqual(reported, "weak")
        self.assertEqual(len(refusals), 1)
        self.assertIn("told history is not guaranteed off (/bin/zsh cannot "
                      "be given a startup file of ours)", refusals[0])
        self.assertIn("would have history off", refusals[0])
        self._assert_speaks_as_the_page(refusals[0])

    def test_a_login_shell_that_changed_between_two_weak_ones_is_refused(self):
        """The word is `weak` before and after, and the reason is what
        changed: the interface would go on naming a shell that is no
        longer the one a session gets. The sentence has to show both
        reasons, because that is the difference the operator is owed."""
        _, reported, refusals, _ = self._serve_after_the_login_shell_changed(
            "/bin/zsh", "/usr/local/bin/zsh")
        self.assertEqual(reported, "weak")
        self.assertEqual(len(refusals), 1)
        self.assertIn("(/bin/zsh cannot be given", refusals[0])
        self.assertIn("(/usr/local/bin/zsh cannot be given", refusals[0])
        self._assert_speaks_as_the_page(refusals[0])

    def test_the_refusal_claims_no_cause_it_has_not_established(self):
        """Only `/dev/fd` went, and the shell is the same bash. The pair
        differs, so the session is refused, but a sentence that said the
        login shell changed would be untrue of this host. What it may say
        is what it knows: the two answers, which carry the cause."""
        refusals = []
        endpoint = TunnelEndpoint(self.config_for(1234))
        self.addCleanup(endpoint.stop)
        with self._passwd("/bin/bash"), self._executable({"/bin/bash"}), \
                self._dev_fd(True):
            endpoint._hello()
        with self._passwd("/bin/bash"), self._executable({"/bin/bash"}), \
                self._dev_fd(False), \
                mock.patch.object(TunnelEndpoint, "_refuse_shell",
                                  lambda self, sock, noise, reason:
                                  refusals.append(reason)):
            endpoint._serve_shell(None, None, 80, 24)
        self.assertEqual(len(refusals), 1)
        self.assertNotRegex(refusals[0], r"(?i)login shell")
        self.assertNotRegex(refusals[0], r"is not bash|startup file of ours")
        self.assertIn(beacon_mod._DEV_FD, refusals[0])
        self.assertRegex(refusals[0], r"(?i)reconnect")
        self._assert_speaks_as_the_page(refusals[0])

    def test_reconnecting_after_a_refusal_reports_the_new_shell(self):
        """The refusal promises it: reconnect, and the tunnel reports what
        the host does now. Held here as a sequence -- HELLO on one shell,
        a refused session on another, the HELLO again on the new one, and
        then a session that starts -- because an endpoint that remembered
        only its first answer would make the refusal permanent, and every
        other test here passes one HELLO."""
        refusals = []
        bridged = []
        endpoint = TunnelEndpoint(self.config_for(1234))
        self.addCleanup(endpoint.stop)

        def session():
            with self._passwd("/bin/bash"), \
                    self._executable({"/bin/bash"}), self._dev_fd(True), \
                    mock.patch.object(TunnelEndpoint, "_refuse_shell",
                                      lambda self, sock, noise, reason:
                                      refusals.append(reason)), \
                    mock.patch.object(TunnelEndpoint, "_shell_bridge",
                                      lambda self, sock, noise, master,
                                      select_mod: bridged.append(master)):
                endpoint._serve_shell(None, None, 80, 24)

        with self._passwd("/bin/zsh"), self._executable({"/bin/zsh"}), \
                self._dev_fd(True):
            self.assertEqual(endpoint._hello()["history"], "weak")
        session()
        self.assertEqual((len(refusals), len(bridged)), (1, 0))

        with self._passwd("/bin/bash"), self._executable({"/bin/bash"}), \
                self._dev_fd(True):
            self.assertEqual(endpoint._hello()["history"], "off")
        session()
        self.assertEqual((len(refusals), len(bridged)), (1, 1),
                         "a session after the reconnect was refused: %r"
                         % refusals)
        self.assertEqual(endpoint._shells, 0)

    def test_a_session_refused_for_a_changed_shell_leaves_nothing_taken(self):
        """As for the pipe: no slot held and no descriptor open. A
        refusal is the cheap path and must not be the one that leaks.

        That a guard which still *matches* gets its session is held by
        `TestAShellSession`, which runs a real HELLO and a real shell
        through the same endpoint.
        """
        endpoint, _, refusals, masters = \
            self._serve_after_the_login_shell_changed("/bin/bash", "/bin/zsh")
        self.assertEqual(len(refusals), 1)
        self.assertEqual(endpoint._shells, 0)
        self.assertEqual(len(masters), 2)
        for fd in masters:
            with self.assertRaises(OSError, msg="descriptor %d" % fd):
                os.fstat(fd)

    def test_the_operator_is_told_why_the_session_was_refused(self):
        """A stream that simply goes quiet is the one failure worse than
        a wrong answer: `_refuse_shell`'s own docstring says a terminal
        can only read a sentence."""
        _, refusals, _ = self._serve_with_a_pipe_that_fails(
            OSError("too many files"))
        self.assertEqual(len(refusals), 1)
        self.assertRegex(refusals[0], r"(?i)histor")
        self.assertNotRegex(refusals[0], r"Traceback|OSError\(")

    def test_the_refusal_claims_only_the_cause_the_error_gives(self):
        """Out of descriptors is said of `EMFILE` and `ENFILE` and of
        nothing else."""
        cases = ((OSError(errno.EMFILE, "Too many open files"), True),
                 (OSError(errno.ENFILE, "Too many open files in system"),
                  True),
                 (OSError(errno.ENOMEM, "Cannot allocate memory"), False),
                 (OSError("no errno at all"), False))
        for error, says_so in cases:
            _, refusals, _ = self._serve_with_a_pipe_that_fails(error)
            self.assertEqual(len(refusals), 1)
            self.assertEqual(bool(re.search(r"file descriptors",
                                            refusals[0])), says_so,
                             (error, refusals[0]))
            self.assertRegex(refusals[0], r"(?i)histor")

    def test_an_oserror_that_is_not_the_pipe_is_not_called_the_pipe(self):
        """The refusal that names history is for the pipe only; anything
        else the invocation raises takes the generic one."""
        refusals = []
        endpoint = TunnelEndpoint(self.config_for(1234))
        self.addCleanup(endpoint.stop)
        with mock.patch.object(beacon_mod, "_shell_invocation",
                               side_effect=OSError("something else")), \
                mock.patch.object(TunnelEndpoint, "_refuse_shell",
                                  lambda self, sock, noise, reason:
                                  refusals.append(reason)):
            endpoint._serve_shell(None, None, 80, 24)
        self.assertEqual(len(refusals), 1)
        self.assertNotRegex(refusals[0], r"(?i)histor")
        self.assertEqual(endpoint._shells, 0)

    def test_a_refused_session_leaves_nothing_taken(self):
        """No slot held and no descriptor open: a host that is out of
        descriptors is the one that cannot afford to lose more."""
        endpoint, refusals, masters = self._serve_with_a_pipe_that_fails(
            OSError("too many files"))
        self.assertEqual(len(refusals), 1)
        self.assertEqual(endpoint._shells, 0)
        self.assertEqual(len(masters), 2)
        for fd in masters:
            with self.assertRaises(OSError, msg="descriptor %d" % fd):
                os.fstat(fd)


class TestAShellSession(TunnelEndpointTestCase):
    """`MSG_OPEN_SHELL`: a real PTY on the endpoint, dialled out like a relay.

    Against `_FakeTunnelServer`, for the reason the module docstring
    gives. Everything on the endpoint's side is the real thing, including
    the `bash` these tests talk to: a command is typed into the stream and
    its *output* -- never the terminal's echo of what was typed -- is what
    is asserted on. Where a marker could appear in both, it is written so
    that it cannot: `echo "hello""_pty"` is typed and `hello_pty` comes
    back, so a session that only echoed its input would fail.
    """

    def setUp(self):
        super(TestAShellSession, self).setUp()
        # These tests talk to bash, or to `/bin/sh` where they remove it,
        # and were written when that was the only choice. The login shell
        # is the host's -- zsh on the machine this is developed on -- so
        # leaving it to the host would make every assertion below depend
        # on whose account runs the suite. The login-shell tests patch
        # the passwd entry themselves.
        self.patched("_login_shell", lambda: "")
        self.server = _FakeTunnelServer(self.store)
        self.addCleanup(self.assert_server_was_quiet)
        self.addCleanup(self.server.close)
        self.endpoint = self.start_endpoint(self.config_for(self.server.port))
        self.wait_for(lambda: self.server.channel is not None,
                      what="the endpoint's command channel")
        self.channel = self.server.channel

    def assert_server_was_quiet(self):
        self.assertEqual(self.server.errors, [])

    # ── harness ──

    def patched(self, name, value):
        """Replace one module-level name in `beacon` for this test."""
        original = getattr(beacon_mod, name)
        setattr(beacon_mod, name, value)
        self.addCleanup(setattr, beacon_mod, name, original)

    def ask_for_a_shell(self, cols=None, rows=None, server=None,
                        channel=None):
        """One OPEN_SHELL, and the stream the endpoint claims it with.

        `server` and `channel` name a second endpoint's pair where a test
        has connected one; `setUp`'s is the default.
        """
        server = server if server is not None else self.server
        channel = channel if channel is not None else self.channel
        token = os.urandom(16).hex()
        wanted = len(server.shells) + 1
        body = {"port": server.port, "token": token}
        if cols is not None:
            body["cols"] = cols
        if rows is not None:
            body["rows"] = rows
        channel.send_message(MSG_OPEN_SHELL, body)
        self.wait_for(lambda: len(server.shells) >= wanted,
                      what="the endpoint dialling back for a shell session")
        claim, stream = server.shells[wanted - 1]
        self.assertEqual(claim, {"token": token},
                         "the endpoint claimed the session with the wrong "
                         "body")
        return stream

    def an_endpoint_that_connected_under_this_tests_patches(self):
        """A second server and endpoint, dialled with the patches in force.

        `setUp` connects one before a test can change the host, and the
        HELLO carries the history guard of the host as it was then. A
        session whose guard has changed since is refused on purpose -- see
        `_HistoryGuardChanged` -- so a test that strips bash after `setUp`
        would be describing a host that lost bash mid-tunnel. Where what
        it means is a host that never had one, it connects here instead.

        Returns `(server, channel)` for `ask_for_a_shell`.
        """
        server = _FakeTunnelServer(self.store)
        self.addCleanup(lambda: self.assertEqual(server.errors, []))
        self.addCleanup(server.close)
        self.start_endpoint(self.config_for(server.port,
                                            identity="build-beta"))
        self.wait_for(lambda: server.channel is not None,
                      what="the second endpoint's command channel")
        return server, server.channel

    def expect(self, stream, needle, timeout=20.0):
        """Read `stream` until `needle` arrives, or fail saying what did."""
        data = stream.read_until(needle, timeout=timeout)
        if data is None:
            self.fail("%r never arrived on the shell stream; what did: %r"
                      % (needle, stream.buffer[-500:]))
        return data

    def run_in_the_shell(self, stream, command, marker):
        """Type one command, and return everything read once `marker` lands."""
        stream.send(command)
        return self.expect(stream, marker)

    def a_setsid_stand_in(self):
        """Point the endpoint's wrapper probe at `_SETSID_STAND_IN`."""
        path = os.path.join(self.root, "setsid-stand-in")
        with open(path, "w") as handle:
            handle.write(_SETSID_STAND_IN % sys.executable)
        os.chmod(path, 0o700)
        self.patched("_setsid_program", lambda: path)
        return path

    def a_home_directory(self, bashrc=None):
        """An empty HOME this process's children inherit, with a `.bashrc`.

        The endpoint builds a session's environment from its own, which is
        this process's, so pointing `HOME` at a directory of the test's own
        is how the host's rc files are put under the test's control. It is
        restored afterwards.
        """
        home = tempfile.mkdtemp(dir=self.root)
        if bashrc is not None:
            with open(os.path.join(home, ".bashrc"), "w") as handle:
                handle.write(bashrc)
        previous = os.environ.get("HOME")
        os.environ["HOME"] = home
        if previous is None:
            self.addCleanup(os.environ.pop, "HOME", None)
        else:
            self.addCleanup(os.environ.__setitem__, "HOME", previous)
        return home

    def a_changed_environment(self, **values):
        """Set (or, given None, remove) variables this process's children inherit.

        The endpoint builds a session's environment from its own, so this
        is how a variable the host "already has" is put under the test's
        control. Restored afterwards.
        """
        for name, value in values.items():
            previous = os.environ.get(name)
            if previous is None:
                self.addCleanup(os.environ.pop, name, None)
            else:
                self.addCleanup(os.environ.__setitem__, name, previous)
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    @staticmethod
    def the_pages_red():
        """`--red` as the page defines it, as the `r;g;b` an SGR code wants.

        Read out of the page's own stylesheet rather than written down
        here, so a palette change that the prompt did not follow fails.
        """
        path = os.path.join(os.path.dirname(beacon_mod.__file__),
                            "server.py")
        with open(path, encoding="utf-8") as handle:
            found = re.search(r"--red:\s*#([0-9a-fA-F]{6})\s*;", handle.read())
        assert found, "the page no longer defines --red"
        value = found.group(1)
        return ";".join(str(int(value[i:i + 2], 16)) for i in (0, 2, 4))

    def assert_a_red_prompt(self, ps1):
        """`ps1` is the interface's red around the host and directory.

        Each property is one way a prompt goes wrong: no `\\h` or `\\w`
        and it names neither; an escape outside `\\[ \\]` and bash
        miscounts the width, so line editing wraps wrongly; no reset and
        everything the operator types is red.
        """
        start = r"\[\e[38;2;%sm\]" % self.the_pages_red()
        reset = r"\[\e[0m\]"
        found = re.fullmatch(re.escape(start) + r"(.*)" + re.escape(reset)
                             + r"\s*", ps1, re.DOTALL)
        self.assertIsNotNone(
            found, "the prompt is not the page's --red, wrapped in \\[ \\], "
            "and reset at the end: %r" % (ps1,))
        body = found.group(1)
        self.assertIn("\\h", body, "the prompt does not name the host")
        self.assertIn("\\w", body,
                      "the prompt does not name the working directory")
        self.assertNotIn("\\e", body,
                         "something else is coloured inside the prompt")

    def value_in_the_shell(self, stream, expansion):
        """What `expansion` (e.g. `$PS1`) comes to inside the session, as text.

        Printed between a `V<n>=[` and a `] END<n>` that cannot be in the
        echo of the command, because each is split by a pair of quotes.
        The stream's buffer is cumulative, so each call has a number of
        its own and cannot be satisfied by an earlier call's output.
        """
        self._asked = getattr(self, "_asked", 0) + 1
        n = b"%d" % self._asked
        command = (b'echo "V""' + n + b'=[' + expansion + b']" "E""ND' + n
                   + b'"\n')
        data = self.run_in_the_shell(stream, command, b" END" + n)
        found = re.findall(rb"V" + n + rb"=\[(.*?)\] END" + n, data,
                           re.DOTALL)
        self.assertEqual(len(found), 1, data)
        return found[0].decode("utf-8", "replace")

    # ── the claim ──

    def test_an_open_shell_dials_back_and_claims_with_its_token(self):
        token = os.urandom(16).hex()
        self.channel.send_message(MSG_OPEN_SHELL,
                                  {"port": self.server.port, "token": token,
                                   "cols": 100, "rows": 30})

        self.wait_for(lambda: len(self.server.opened) >= 2,
                      what="the endpoint dialling back for a shell session")
        opened = self.server.opened
        # A second connection, and its first message is the claim: the
        # endpoint dials out for a session exactly as it does for a relay,
        # and nothing new listens on the implant.
        self.assertEqual([kind for kind, _, _ in opened],
                         [MSG_HELLO, MSG_SHELL])
        self.assertEqual(opened[1][1], {"token": token})

    def test_an_open_shell_without_a_token_is_ignored(self):
        self.channel.send_message(MSG_OPEN_SHELL, {"port": self.server.port})

        # Nothing is dialled -- and the command channel is still there,
        # which is the half of this that matters: an arm that fell through
        # to `_control_loop`'s `else` would drop the channel and take
        # every live SOCKS session with it.
        time.sleep(1.0)
        self.assertEqual([kind for kind, _, _ in self.server.opened],
                         [MSG_HELLO])
        self.ask_for_a_shell()

    # ── the session ──

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    def test_a_command_echoes_back_through_the_pty(self):
        stream = self.ask_for_a_shell()

        self.run_in_the_shell(stream, b'echo "hello""_pty"\n', b"hello_pty")

        # Counted as a session, as a relay is: a panel that showed a host
        # with four shells open as idle would be lying about it.
        self.wait_for(lambda: self.endpoint.status()["sessions"] == 1,
                      what="the endpoint counting its shell session")

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    def test_the_prompt_starts_in_the_root_directory(self):
        # What is pinned is that `_SHELL_CWD` is handed to `Popen`, and it
        # holds for bash. A login shell's own startup file may `cd`
        # elsewhere, which is the user's configuration winning and not a
        # fault here -- see the pin in `setUp`.
        stream = self.ask_for_a_shell()

        data = self.run_in_the_shell(stream, b"pwd\n", b"/\r\n")

        # A line that is exactly `/`, not a prompt that happens to carry a
        # slash: the install directory in a prompt is a free finding.
        self.assertRegex(data, re.compile(_LINE_START + rb"/\r?$"))

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    def test_the_shell_is_reaped_when_the_stream_dies(self):
        # Review Focus.
        self.assert_the_shell_is_reaped()

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    def test_a_wrapped_shell_is_reaped_when_the_stream_dies(self):
        """The same, with the session spawned through `setsid -c`.

        The teardown signals a process *group*, and on the preferred path
        the claim that `Popen`'s pid is still that group's id rests on
        `setsid(1)` exec'ing in place instead of forking. If that were
        wrong, `_end_shell` would reap the wrapper and leave a live
        `bash -i` on the target -- the exact defect this task exists to
        prevent -- so the claim is executed here rather than left in a
        docstring. The stand-in has the same no-fork shape; real
        `setsid(1)`'s own behaviour is the first Linux run's to confirm.
        """
        self.a_setsid_stand_in()
        self.assert_the_shell_is_reaped()

    def assert_the_shell_is_reaped(self):
        """A session's stream dies; its child leaves the process table.

        The pid comes from the session itself -- `$$` in the shell -- and
        the verdict is read out of the process table, not out of a flag
        this code sets. An unreaped child is a zombie, and signal 0
        succeeds on a zombie, so this fails on a teardown that signals
        without waiting as well as on one that never signals.
        """
        stream = self.ask_for_a_shell()
        data = self.run_in_the_shell(stream, b'echo "P""ID=$$"\n', b"PID=")
        found = re.search(rb"PID=(\d+)", data)
        self.assertIsNotNone(found, "the shell did not report its own pid")
        pid = int(found.group(1))
        os.kill(pid, 0)

        stream.close()

        # A deadline sized to the endpoint's *own* worst case, not to one
        # grace window. `_end_shell` can spend up to `_SHELL_TERM_GRACE`
        # waiting out SIGHUP and then, if the shell did not go, another
        # `_SHELL_TERM_GRACE` waiting out SIGKILL -- and the stream close
        # has to propagate to that teardown first. The old budget of one
        # grace plus a second was below that sum, so under load, where the
        # SIGHUP wait actually times out, the reap outran the deadline and
        # the test flaked. This covers both grace windows with slack for
        # the dispatch and the scheduler; its teeth are unchanged, because
        # a child that is never reaped stays in the table past any
        # deadline and the `else` still fires.
        grace = 2 * beacon_mod._SHELL_TERM_GRACE + 5.0
        deadline = time.time() + grace
        while time.time() < deadline:
            if not _alive(pid):
                break
            time.sleep(0.02)
        else:
            self.fail("the shell's child %d was still in the process table "
                      "%.1fs after its stream died; a session whose stream "
                      "goes must leave no shell running on the target"
                      % (pid, grace))
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    def test_input_the_shell_is_not_reading_does_not_hold_the_teardown(self):
        """A paste during a capture must not wedge the session's teardown.

        The slave's input queue is a few kilobytes that only the
        foreground command drains, so a command which does not read its
        stdin -- this `sleep`, or the `tcpdump` an operator would really
        be running -- leaves a write to the master unable to complete.
        That write is on the thread that runs the teardown, so a blocking
        one would mean a dead stream whose child, master and threads were
        all still alive, with nothing left to notice: the output
        direction is silent, because the shell is producing nothing.

        So: a sleeping foreground command, more input than the queue
        holds, then the stream closes. The session has to survive the
        paste and the child has to go with the stream.

        Only Linux can make the write itself block, for the reason
        `TestWritingToATerminal` gives, so on a BSD this is the weaker
        half of the claim: that a paste a non-blocking master cannot
        take is waited out rather than treated as a dead terminal.
        """
        stream = self.ask_for_a_shell()
        data = self.run_in_the_shell(stream, b'echo "P""ID=$$"\n', b"PID=")
        pid = int(re.search(rb"PID=(\d+)", data).group(1))
        self.run_in_the_shell(
            stream, b'echo "S""LEEPING"; sleep 300\n', b"SLEEPING")

        # A comment, so that a session which somehow did read it runs
        # nothing; 32 KB, so that no tty's input queue can hold it.
        stream.send(b"#" + b"x" * 32000 + b"\n")

        time.sleep(0.5)
        self.assertTrue(_alive(pid),
                        "the paste ended the session: input the terminal "
                        "cannot take yet is not a terminal that has gone")

        stream.close()

        grace = beacon_mod._SHELL_TERM_GRACE + 2.0
        self.wait_for(lambda: not _alive(pid), timeout=grace,
                      what="the shell %d going after a paste it never read "
                           "and a stream that then closed" % pid)

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    def test_a_closed_session_gives_its_slot_back(self):
        # Without this, deleting `_drop_shell_slot` passes every other
        # test in the file and produces an endpoint on which shell
        # sessions stop working after the fourth, for as long as it runs.
        held = []
        for number in range(beacon_mod._SHELL_MAX_SESSIONS):
            stream = self.ask_for_a_shell()
            self.run_in_the_shell(stream, b'echo "H""ELD_%d"\n' % number,
                                  b"HELD_%d" % number)
            held.append(stream)
        for stream in held:
            stream.close()

        # The slot is released in an outer `finally`, after `_end_shell`'s
        # signal-and-grace, while the panel counter (`status()["sessions"]`)
        # is released in an inner one -- so a wait on the counter can
        # return with the four slots still held and the fifth attach
        # refused, which is the flake this test used to carry under load.
        # The thing this test is really about is that a fifth session
        # eventually runs, so it retries the fifth attach until one does,
        # rather than timing the slot release. Its teeth are intact: if the
        # slot were never given back, no attempt would ever carry `FIFTH`
        # and the deadline below would fail.
        deadline = time.time() + 30.0
        last = b""
        while time.time() < deadline:
            fifth = self.ask_for_a_shell()
            # A refused attach still dials back, but with a line of text
            # rather than a shell: `raccoon: ...`. A real shell carries
            # the command's output instead, so one read for either tells
            # them apart. The marker is split so the terminal's echo of
            # what was typed cannot satisfy it -- only the shell's own
            # output can, exactly as `run_in_the_shell` does it.
            fifth.send(b'echo "F""IFTH"\n')
            data = fifth.read_until_match(
                re.compile(rb"FIFTH|raccoon:"), timeout=5.0)
            if data is not None and b"FIFTH" in data:
                return
            last = fifth.buffer[-200:]
            fifth.close()
            time.sleep(0.05)
        self.fail("a fifth shell session never ran after the first four were "
                  "closed; the slot is not being given back. Last attempt "
                  "read: %r" % (last,))

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    @unittest.skipUnless(_HAS_BASH, _NO_BASH)
    def test_history_is_off_after_an_rc_file_that_sets_it(self):
        # The point of the generated rcfile: the host's own rc files run,
        # because that is where completion comes from, and history is
        # turned off *after* them. A `HISTFILE` in the environment would
        # be undone by this `.bashrc`.
        home = self.a_home_directory(
            bashrc='HISTFILE="$HOME/.bash_history"\nexport RC_RAN=yes\n')
        stream = self.ask_for_a_shell()

        data = self.run_in_the_shell(
            stream, b'echo "H""=[$HISTFILE]" "R""=[$RC_RAN]"\n', b"H=[")

        self.assertIn(b"H=[]", data, "HISTFILE survived the generated rcfile")
        self.assertIn(b"R=[yes]", data,
                      "the host's own ~/.bashrc was not sourced, so "
                      "bash-completion would not be either")
        stream.close()
        self.wait_for(lambda: ".bash_history" not in os.listdir(home),
                      timeout=10.0,
                      what="the session leaving no history file behind")

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    @unittest.skipUnless(_HAS_BASH, _NO_BASH)
    @unittest.skipUnless(_HAS_BASH_COMPLETION, _NO_BASH_COMPLETION)
    def test_flag_completion_is_loaded_the_way_a_login_shell_loads_it(self):
        """`nmap --sc<TAB>` has to offer `--script`, as it would over ssh.

        Measured on Debian 13 with bash-completion 2.16: a real
        interactive ssh session has the loader and this session did not.
        The reason is that the package installs itself through
        `/etc/profile.d/bash_completion.sh`, which only a **login** shell
        reads -- `/etc/bash.bashrc` has the direct source commented out --
        and a session here is `bash -i` with an rcfile, so neither
        `/etc/profile` nor anything in `profile.d` is read.

        Flag completion is the property that ruled out a line-mode REPL in
        the design, so a session without it is the rejected approach
        wearing a pty.

        The probe prints `$?` rather than a word, because a pty echoes the
        command line back and a word would be found in the echo before
        anything had run.
        """
        stream = self.ask_for_a_shell()

        data = self.run_in_the_shell(
            stream,
            b'declare -F _completion_loader >/dev/null 2>&1;'
            b' echo "BC""=[$?]"\n',
            b"BC=[")

        self.assertIn(b"BC=[0]", data,
                      "bash-completion's loader is not in the session, so "
                      "an operator gets no flag completion -- the one thing "
                      "a pty session was supposed to buy over a REPL")

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    @unittest.skipUnless(_HAS_BASH, _NO_BASH)
    @unittest.skipUnless(_HAS_BASH_COMPLETION, _NO_BASH_COMPLETION)
    def test_loading_completion_does_not_bring_history_back(self):
        # The rcfile's whole purpose is that history ends up off. Sourcing
        # a few thousand lines of someone else's shell code before that
        # happens is a new way for it to come back on, so the two
        # properties are measured together rather than assumed to compose.
        stream = self.ask_for_a_shell()

        data = self.run_in_the_shell(
            stream, b'echo "HIST""=[$(set -o | grep -c \'^history.*on$\')]"\n',
            b"HIST=[")

        self.assertIn(b"HIST=[0]", data,
                      "history is on in a session that loaded completion")

    def test_the_rcfile_sources_nothing_it_has_not_checked_for(self):
        """Every path in the rcfile is read only after a test for it.

        A bare `. /etc/profile.d/bash_completion.sh` on a host without the
        package is an error message in the first thing an operator sees,
        on every session, forever. The file is a few lines of generated
        shell that cannot be tested by running it on a host that lacks
        exactly the file in question, so the guard is checked as text.
        """
        for line in beacon_mod._SHELL_RCFILE.splitlines():
            if not line.strip().startswith("."):
                continue
            self.fail("the rcfile sources %r on its own line, so a host "
                      "without that file gets an error on every session; "
                      "guard it with a readability test like the lines "
                      "above it" % (line.strip(),))

    def test_the_colour_defaults_are_set_before_the_host_is_sourced(self):
        """Review Focus 5. Order is the whole requirement, in two parts.

        The two environment variables are above everything. The prompt is
        between the distribution's file and the operator's: above the
        first, Debian's unconditional `PS1` overwrites it and it never
        shows; below the second, it overwrites the operator's own.
        """
        rc = beacon_mod._SHELL_RCFILE
        system_file = rc.rindex("/etc/bash.bashrc")
        operators_file = rc.index('"$HOME/.bashrc"')
        self.assertLess(rc.rindex("CLICOLOR"), system_file,
                        "a CLICOLOR is set at or below the system file")
        self.assertLess(rc.rindex("LSCOLORS"), system_file,
                        "a LSCOLORS is set at or below the system file")
        self.assertGreater(rc.index("PS1"), system_file,
                           "the prompt is above /etc/bash.bashrc, which "
                           "sets its own PS1 on Debian and ParrotOS and "
                           "would overwrite it")
        self.assertLess(rc.index("PS1"), operators_file,
                        "the prompt is below ~/.bashrc, so it overwrites "
                        "the operator's own")
        self.assertEqual(rc.count("PS1"), 1)

    def test_the_defaults_do_not_touch_what_the_host_already_has(self):
        rc = beacon_mod._SHELL_RCFILE.lower()
        self.assertNotIn("ls_colors", rc)
        self.assertNotIn("dircolors", rc,
                         "dircolors is the host's business, and a host with "
                         "an LS_COLORS of its own would be overwritten")

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    @unittest.skipUnless(_HAS_BASH, _NO_BASH)
    def test_a_stand_in_dircolors_is_never_run_and_ls_colors_is_kept(self):
        """Measured rather than read: a `dircolors` on the PATH that would
        set `LS_COLORS` is put there, and the session must not run it."""
        stubs = os.path.join(self.root, "stub-bin")
        os.makedirs(stubs)
        for name in ("dircolors", "gdircolors"):
            path = os.path.join(stubs, name)
            with open(path, "w") as handle:
                handle.write("#!/bin/sh\n"
                             "echo \"LS_COLORS='di=1;31'; export LS_COLORS\"\n")
            os.chmod(path, 0o755)
        self.a_home_directory()
        self.a_changed_environment(
            PATH=stubs + os.pathsep + os.environ.get("PATH", ""),
            LS_COLORS="di=1;34")
        stream = self.ask_for_a_shell()
        self.assertEqual(self.value_in_the_shell(stream, b"$LS_COLORS"),
                         "di=1;34",
                         "the host's LS_COLORS was replaced")
        stream.close()

        self.a_changed_environment(LS_COLORS=None)
        stream = self.ask_for_a_shell()
        self.assertEqual(
            self.value_in_the_shell(stream, b"${LS_COLORS-unset}"), "unset",
            "a host with no LS_COLORS was given one")

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    @unittest.skipUnless(_HAS_BASH, _NO_BASH)
    def test_the_operators_own_settings_win_over_the_colour_defaults(self):
        # The order test above reads text; this one asks a real bash. A
        # `.bashrc` that sets its own prompt and its own colour variables
        # has to be what the session ends up with.
        self.a_home_directory(
            bashrc='PS1="MINE> "\nCLICOLOR=0\nLSCOLORS=gxgxgxgxgxgxgxgxgxgxgx\n')
        stream = self.ask_for_a_shell()

        self.assertEqual(self.value_in_the_shell(stream, b"$PS1"), "MINE> ",
                         "the default prompt overwrote the operator's own")
        self.assertEqual(self.value_in_the_shell(stream, b"$CLICOLOR"), "0",
                         "the default CLICOLOR overwrote the operator's own")
        self.assertEqual(self.value_in_the_shell(stream, b"$LSCOLORS"),
                         "gxgxgxgxgxgxgxgxgxgxgx",
                         "the default LSCOLORS overwrote the operator's own")

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    @unittest.skipUnless(_HAS_BASH, _NO_BASH)
    def test_a_host_with_no_configuration_gets_colour_and_a_red_prompt(self):
        self.a_changed_environment(CLICOLOR=None, LSCOLORS=None)
        self.a_home_directory()
        stream = self.ask_for_a_shell()

        self.assertEqual(self.value_in_the_shell(stream, b"$CLICOLOR"), "1")
        self.assertRegex(self.value_in_the_shell(stream, b"$LSCOLORS"),
                         r"^(?:[a-hA-Hx]{2}){11}$",
                         "LSCOLORS is not eleven pairs of BSD colour letters")
        self.assert_a_red_prompt(self.value_in_the_shell(stream, b"$PS1"))

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    @unittest.skipUnless(_HAS_BASH, _NO_BASH)
    def test_colour_variables_already_in_the_environment_are_kept(self):
        """The defaults fill a gap; they never replace what the host has."""
        self.a_changed_environment(CLICOLOR="0",
                                   LSCOLORS="gxfxcxdxbxegedabagacad")
        self.a_home_directory()
        stream = self.ask_for_a_shell()

        self.assertEqual(self.value_in_the_shell(stream, b"$CLICOLOR"), "0",
                         "an existing CLICOLOR was overwritten")
        self.assertEqual(self.value_in_the_shell(stream, b"$LSCOLORS"),
                         "gxfxcxdxbxegedabagacad",
                         "an existing LSCOLORS was overwritten")

    @unittest.skipUnless(_HAS_BASH, _NO_BASH)
    def test_the_prompt_survives_the_system_file_and_the_operators_wins(self):
        """What a real bash does with the generated file, around a system file.

        The endpoint cannot be given a stand-in `/etc/bash.bashrc`: the
        path is fixed in the generated file and the test may not write to
        `/etc`. So this runs a real bash on the generated text with that
        one path swapped for a file of the test's own that sets a `PS1`,
        as Debian's does. What it proves is the ordering behaviour of bash
        on the file this code generates. That the real `/etc/bash.bashrc`
        of a Debian host looks like the stand-in is reasoned, not measured
        here.
        """
        import subprocess
        rc = beacon_mod._SHELL_RCFILE
        self.assertIn("/etc/bash.bashrc", rc)
        system = os.path.join(self.root, "stand-in-system-bashrc")
        with open(system, "w") as handle:
            handle.write('PS1="DISTRO> "\n')
        rcfile = os.path.join(self.root, "generated-rcfile")
        with open(rcfile, "w") as handle:
            handle.write(rc.replace("/etc/bash.bashrc", system))

        def prompt_with(bashrc):
            home = self.a_home_directory(bashrc=bashrc)
            done = subprocess.run(
                ["/bin/bash", "--rcfile", rcfile, "-i"],
                input=b'echo "P""=[$PS1]"\nexit\n', cwd=home,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env=dict(os.environ, HOME=home), timeout=30)
            found = re.findall(r"(?m)^P=\[(.*)\]$",
                               done.stdout.decode("utf-8", "replace"))
            self.assertEqual(len(found), 1, done.stdout)
            return found[0]

        ours = prompt_with(None)
        self.assertNotEqual(ours, "DISTRO> ",
                            "the distribution's prompt survived ours")
        self.assert_a_red_prompt(ours)
        self.assertEqual(prompt_with('PS1="MINE> "\n'), "MINE> ",
                         "our prompt overwrote the operator's own")

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    @unittest.skipUnless(_HAS_BASH, _NO_BASH)
    def test_a_bash_login_shell_outside_bin_is_handed_the_rcfile_too(self):
        """The path nothing had walked: a login shell that is a bash.

        `_login_shell` accepts bash by basename, `_guard_of` calls any
        bash "off", and `_shell_invocation` therefore hands it the
        generated rcfile: a user whose login shell is
        `/opt/homebrew/bin/bash` gets this file, not only the fallback.
        `setUp` pins `_login_shell` to `""`, which is why no test went
        down here. A symlink named `bash` in a directory of the test's own
        stands in for a bash that is not `/bin/bash`.
        """
        directory = os.path.join(self.root, "opt", "bin")
        os.makedirs(directory)
        login = os.path.join(directory, "bash")
        os.symlink("/bin/bash", login)
        self.patched("_login_shell", lambda: login)
        self.assertEqual(beacon_mod._history_guard(), ("off", ""),
                         "a bash login shell is not given the rcfile")

        # The history lines run last: a `.bashrc` that turns history on
        # and names a file must find both undone.
        self.a_home_directory(bashrc='HISTFILE="$HOME/.bash_history"\n'
                                     'set -o history\n')
        stream = self.ask_for_a_shell()
        self.assertEqual(self.value_in_the_shell(stream, b"$BASH"), login,
                         "the session did not run the login shell")
        self.assertEqual(self.value_in_the_shell(stream, b"$HISTFILE"), "",
                         "the history lines did not run last")
        self.assertEqual(
            self.value_in_the_shell(
                stream, b"$(set -o | grep -c '^history.*on$')"), "0",
            "history is on in a bash login shell")
        # The prompt is ours, since the `.bashrc` above sets none.
        self.assert_a_red_prompt(self.value_in_the_shell(stream, b"$PS1"))
        stream.close()

        # And the operator's own prompt still wins over it.
        self.a_home_directory(bashrc='PS1="MINE> "\n')
        stream = self.ask_for_a_shell()
        self.assertEqual(self.value_in_the_shell(stream, b"$PS1"), "MINE> ",
                         "our prompt overwrote a bash login shell's own")

    def test_the_rcfile_still_ends_by_turning_history_off(self):
        """The colour lines went in above the sourcing; the history lines
        must stay below it, or the host's rc runs after them."""
        rc = beacon_mod._SHELL_RCFILE
        self.assertGreater(rc.index("unset HISTFILE"),
                           rc.index('"$HOME/.bashrc"'))
        self.assertTrue(rc.rstrip().endswith("set +o history"))

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    @unittest.skipUnless(_HAS_BASH, _NO_BASH)
    def test_the_generated_rcfile_leaves_nothing_on_disk(self):
        # The rcfile is the contents of a pipe, handed to bash as
        # `/dev/fd/<n>`, so there is nothing to clean up and nothing for a
        # host-based scan to find. Both directories a file could land in
        # are the test's own and start empty, which is what makes "no new
        # file" checkable without racing whatever else uses /tmp.
        home = self.a_home_directory()
        spool = tempfile.mkdtemp(dir=self.root)
        previous = os.environ.get("TMPDIR")
        os.environ["TMPDIR"] = spool
        if previous is None:
            self.addCleanup(os.environ.pop, "TMPDIR", None)
        else:
            self.addCleanup(os.environ.__setitem__, "TMPDIR", previous)
        stream = self.ask_for_a_shell()

        self.run_in_the_shell(stream, b'echo "live""_session"\n',
                              b"live_session")
        stream.close()

        self.wait_for(lambda: not os.listdir(home), timeout=10.0,
                      what="HOME staying empty")
        self.assertEqual(os.listdir(spool), [],
                         "the rcfile was written to a file on disk")

    # `stty size` reports the terminal's own size, read out of the ioctl
    # the endpoint applied, so it is the size the session really has and
    # not the numbers that were asked for.
    _SIZE = re.compile(_LINE_START + rb"(\d+) (\d+)\s*$")

    def the_terminal_size(self, stream):
        """The `(rows, cols)` the session's terminal actually has."""
        stream.send(b"stty size\n")
        data = stream.read_until_match(self._SIZE)
        if data is None:
            self.fail("`stty size` reported nothing that looks like a "
                      "terminal size; what came back: %r"
                      % (stream.buffer[-500:],))
        return tuple(int(value) for value in self._SIZE.search(data).groups())

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    def test_absurd_geometry_is_clamped_before_the_ioctl(self):
        # Review Focus.
        stream = self.ask_for_a_shell(cols=0, rows=99999)

        rows, cols = self.the_terminal_size(stream)

        for name, value in (("rows", rows), ("cols", cols)):
            self.assertGreaterEqual(value, 1, "%s reached the ioctl as %d"
                                    % (name, value))
            self.assertLessEqual(value, SHELL_GEOMETRY_MAX,
                                 "%s reached the ioctl as %d" % (name, value))
        self.assertEqual((rows, cols), (SHELL_GEOMETRY_MAX, 1))

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    def test_the_default_geometry_is_used_when_none_is_asked_for(self):
        stream = self.ask_for_a_shell()

        self.assertEqual(self.the_terminal_size(stream),
                         (SHELL_DEFAULT_ROWS, SHELL_DEFAULT_COLS))

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    def test_bin_sh_is_used_when_bash_is_absent(self):
        # The probe is the seam: a host without bash is not something a
        # test can arrange, and what is under test is the choice made
        # from the probe's answer, not `os.access` itself.
        #
        # It is the *shared* probe, so this host has no `setsid` either
        # for the length of this test, and the session therefore takes
        # the fallback spawn as well as the fallback shell. Both are
        # wanted here -- a host stripped to `/bin/sh` is a host unlikely
        # to carry util-linux -- and whoever maintains the setsid path
        # should know that this test does not exercise it.
        #
        # The endpoint is connected *after* the patch, because its HELLO
        # reports which history guard a session here gets and a session
        # whose guard has changed since is refused. A host that never had
        # bash is what this test means; a host that lost it mid-tunnel is
        # `TestARefusedShellSession`'s business.
        self.patched("_shell_executable", lambda path: False)
        server, channel = \
            self.an_endpoint_that_connected_under_this_tests_patches()
        stream = self.ask_for_a_shell(server=server, channel=channel)

        data = self.run_in_the_shell(
            stream, b'echo "S""=[$0]" "H""=[$HISTFILE]"\n', b"S=[")

        self.assertIn(b"S=[/bin/sh]", data,
                      "the session did not fall back to /bin/sh")
        # And on `/bin/sh` there is no `--rcfile`, so history is held off
        # by the weaker documented path instead.
        self.assertIn(b"H=[%s]" % os.devnull.encode("ascii"), data)

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    @unittest.skipUnless(_HAS_SETSID, _NO_SETSID)
    def test_control_c_interrupts_a_running_command(self):
        """`^C` reaches the running command, through the host's setsid(1)."""
        self.assert_control_c_reaches_the_command()

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    def test_the_shell_is_spawned_through_setsid_asking_for_a_ctty(self):
        """The preferred path's own half, on a host with no `setsid(1)`.

        The behaviour above is the claim, and it is a claim this machine
        cannot carry. What it *can* carry is everything the endpoint is
        responsible for: that the shell is spawned as `<setsid> -c
        <shell> …` and not directly, and that `Popen` is not *also* asked
        for a new session. The wrapper is stood in for -- see
        `_SETSID_STAND_IN` -- and reports the argv it was handed.
        """
        wrapper = self.a_setsid_stand_in()
        stream = self.ask_for_a_shell()

        # That the session works at all is the second half, and it is not
        # readable off an argv: the stand-in's `setsid()` succeeded, so
        # the child was not already a session leader -- had `Popen` been
        # asked for a new session as well, that call would have failed
        # with EPERM and no shell would ever have run.
        self.run_in_the_shell(stream, b'echo "W""RAPPED"\n', b"WRAPPED")

        with open(wrapper + ".ran") as handle:
            argv = handle.read().splitlines()
        self.assertEqual(argv[:2], [wrapper, "-c"],
                         "the shell was not spawned through the wrapper "
                         "asking for a controlling terminal: %r" % (argv,))
        # Bash or `/bin/sh` only because `setUp` pins the login shell off;
        # with the host's own choice this would be whatever that is.
        self.assertIn(argv[2], ("/bin/bash", "/bin/sh"))
        self.assertIn("-i", argv[3:])

    def assert_control_c_reaches_the_command(self):
        """`0x03` on the stream kills the foreground command. Needs a ctty.

        The point of an interactive session over a task channel is partly
        this: a capture can be started and then stopped. The byte only
        becomes a SIGINT if the slave is some session's *controlling*
        terminal, because the line discipline signals that terminal's
        foreground process group -- and with no such group it has nobody
        to signal and discards the byte. So this fails on a session whose
        child merely has a session of its own, which is all
        `start_new_session=True` gives.

        A grandchild reports its own pid and then sleeps in the
        foreground. Both halves are asserted, because either alone is
        passable by accident: the pid leaves the process table, and the
        shell takes a command again afterwards -- which it could not if
        the sleep were still holding the terminal.
        """
        stream = self.ask_for_a_shell()
        data = self.run_in_the_shell(
            stream, b"/bin/sh -c 'echo \"K\"\"ID=$$\"; sleep 300'\n", b"KID=")
        found = re.search(rb"KID=(\d+)", data)
        self.assertIsNotNone(found, "the foreground command reported no pid")
        pid = int(found.group(1))
        os.kill(pid, 0)

        stream.send(b"\x03")

        self.wait_for(lambda: not _alive(pid), timeout=10.0,
                      what="^C interrupting the foreground command %d" % pid)
        self.run_in_the_shell(stream, b'echo "B""ACK"\n', b"BACK")

    # ── refusals, in text, because a terminal is what is reading them ──

    @unittest.skipUnless(_HAS_PTY, _NO_PTY)
    def test_the_fifth_concurrent_session_is_refused_in_text(self):
        live = []
        for number in range(beacon_mod._SHELL_MAX_SESSIONS):
            stream = self.ask_for_a_shell()
            # Read a command's output back before asking for the next, so
            # all four are demonstrably live and holding their slots.
            self.run_in_the_shell(stream, b'echo "READY""_%d"\n' % number,
                                  b"READY_%d" % number)
            live.append(stream)

        stream = self.ask_for_a_shell()

        data = self.expect(stream, b"\n", timeout=10.0)
        text = data.decode("utf-8", "replace")
        self.assertIn(str(beacon_mod._SHELL_MAX_SESSIONS), text,
                      "the refusal does not say what the limit is: %r" % text)
        self.assertNotIn("Traceback", text)
        self.assertTrue(stream.wait_closed(),
                        "the refused session was not closed")
        # The four that were already there are untouched by the refusal.
        for number, held in enumerate(live):
            self.run_in_the_shell(held, b'echo "STILL""_%d"\n' % number,
                                  b"STILL_%d" % number)

    def test_a_host_without_a_pty_refuses_in_text(self):
        def no_pty():
            raise ImportError("No module named 'pty'")

        self.patched("_shell_modules", no_pty)
        stream = self.ask_for_a_shell()

        data = self.expect(stream, b"\n", timeout=10.0)
        text = data.decode("utf-8", "replace")
        self.assertIn("pty", text)
        # A sentence, not a stack trace: the operator is looking at a
        # terminal and this is the only thing they will see.
        self.assertNotIn("Traceback", text)
        self.assertNotIn("File \"", text)
        self.assertTrue(stream.wait_closed(),
                        "the refused session was not closed")


class TestTheNtlmRoute(TunnelEndpointTestCase):
    """`_ntlm_route`, with no NTLM upstream in sight.

    `_NtlmProxyRelay.start()` binds its loopback port before it returns
    and touches the upstream only when a CONNECT arrives, so the route it
    offers can be asserted without a proxy that speaks NTLM at all. What
    is under test is this class's half of the wiring: that the config keys
    are read, that the local relay is put ahead of `proxy.url`, that a
    config with no credentials yields no route rather than a relay that
    could never authenticate, and that `stop` takes the relay's port with
    it. Everything from `_dial_route` onward is the same code the stub
    CONNECT proxy tests above already carry traffic through.
    """

    def endpoint(self, ntlm, url=""):
        proxy = {"mode": "manual", "url": url, "ntlm": ntlm}
        # Port 1234 is never dialled here: nothing in this class connects.
        endpoint = TunnelEndpoint(self.config_for(1234, proxy=proxy))
        self.addCleanup(endpoint.stop)
        return endpoint

    @staticmethod
    def _refuses(port):
        """True once nothing is listening on `port`."""
        try:
            sock = socket.create_connection((_LOOPBACK, port), timeout=1.0)
        except OSError:
            return True
        sock.close()
        return False

    def test_an_ntlm_upstream_becomes_the_first_way_out(self):
        endpoint = self.endpoint(
            {"enabled": True, "host": "proxy.corp.invalid", "port": 8080,
             "username": "CORP\\operator", "password": "not-a-real-secret"},
            url="http://%s:3128" % _LOOPBACK)

        # `_configured_routes` rather than `_routes`, so that asserting on
        # the order does not also run proxy discovery, which shells out
        # and resolves names on whatever host this is.
        routes = endpoint._configured_routes()
        self.assertEqual(len(routes), 2)
        host, port = routes[0]
        self.assertEqual(host, _LOOPBACK)
        self.assertNotEqual(port, 0)
        # The local relay and not the configured proxy: a build told to
        # authenticate with NTLM has to reach the upstream through the
        # thing that can do it, and `proxy.url` is the fallback behind it.
        self.assertNotEqual(port, 3128)
        self.assertEqual(routes[1], (_LOOPBACK, 3128))
        # Asked twice, the same relay: one local port per endpoint.
        self.assertEqual(endpoint._configured_routes(), routes)

        endpoint.stop()
        self.wait_for(lambda: self._refuses(port), timeout=5.0,
                      what="the NTLM relay's port closing with its endpoint")

    def test_ntlm_without_credentials_offers_no_route(self):
        endpoint = self.endpoint({"enabled": True,
                                  "host": "proxy.corp.invalid"},
                                 url="http://%s:3128" % _LOOPBACK)
        self.assertEqual(endpoint._configured_routes(), [(_LOOPBACK, 3128)])

    def test_ntlm_disabled_offers_no_route(self):
        endpoint = self.endpoint({"enabled": False, "host": "proxy.corp",
                                  "username": "u", "password": "p"},
                                 url="http://%s:3128" % _LOOPBACK)
        self.assertEqual(endpoint._configured_routes(), [(_LOOPBACK, 3128)])


class TestConfigProblems(TunnelEndpointTestCase):
    def good(self):
        return self.config_for(1234)

    def test_a_complete_config_has_no_problem(self):
        self.assertIsNone(tunnel_config_problem(self.good()))

    def test_config_problem_names_the_missing_field(self):
        for field in ("server", "port", "public_key", "psk", "identity"):
            with self.subTest(field=field):
                config = self.good()
                del config["c2"]["tunnel"][field]
                problem = tunnel_config_problem(config)
                self.assertIsNotNone(problem,
                                     "a config missing %r was accepted"
                                     % field)
                self.assertIn("c2.tunnel." + field, problem)

    def test_a_disabled_or_absent_tunnel_is_not_a_problem(self):
        config = self.good()
        config["c2"]["tunnel"]["enabled"] = False
        del config["c2"]["tunnel"]["server"]
        self.assertIsNone(tunnel_config_problem(config))
        self.assertIsNone(tunnel_config_problem({"c2": {}}))
        self.assertIsNone(tunnel_config_problem({}))
        self.assertIsNone(tunnel_config_problem(None))

    def test_a_key_that_is_not_32_bytes_is_named_and_not_echoed(self):
        for field in ("public_key", "psk"):
            for value in (base64.b64encode(os.urandom(31)).decode("ascii"),
                          "not base64 at all!!"):
                with self.subTest(field=field, value=value):
                    config = self.good()
                    config["c2"]["tunnel"][field] = value
                    problem = tunnel_config_problem(config)
                    self.assertIsNotNone(problem)
                    self.assertIn("c2.tunnel." + field, problem)
                    self.assertNotIn(value, problem)

    def test_a_port_that_is_not_a_port_is_named(self):
        for value in (0, 70000, "https", True, None):
            with self.subTest(value=value):
                config = self.good()
                config["c2"]["tunnel"]["port"] = value
                problem = tunnel_config_problem(config)
                self.assertIsNotNone(problem,
                                     "port %r was accepted" % (value,))
                self.assertIn("c2.tunnel.port", problem)

    def test_the_endpoint_refuses_a_config_it_cannot_run(self):
        config = self.good()
        del config["c2"]["tunnel"]["psk"]
        with self.assertRaises(ValueError) as caught:
            TunnelEndpoint(config)
        self.assertIn("c2.tunnel.psk", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
