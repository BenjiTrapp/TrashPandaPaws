"""Starting, stopping and reporting on the tunnel server, which is a process.

The team server runs this. It spawns `python3 -m software.c2.tunnel` as a
child, kills it on request, and reads its state over the child's loopback
control socket. Task 10's panel calls `start`, `stop` and `status` and
nothing else.

**One child, not a table of them.** There is one tunnel server per
deployment -- one implant-facing port, one port table, one key store --
so this is deliberately not `listeners/supervisor.py` with a different
spec type. The two share their discipline and not their code, for the
reason `listeners/errors.py` exists: importing `listeners.supervisor`
pulls in `listeners.registry`, which imports all three listener classes,
and the DNS parser, the QUIC reassembler and the hand-written SMB2 parser
must not be loaded into a process that only wants to spawn a tunnel. The
exception is shared, because that module was written to be importable by
anything.

Three properties this is built around, each one borrowed from the
listeners' supervisor because each was learned from a failure:

  * **Every refusal carries a reason.** A tunnel server that silently
    fails to start, or a `stop` that returns while the process keeps
    running, shows up later as an endpoint that never appears -- and so
    do a wrong PSK, a blocked egress and a proxy that refuses CONNECT. So
    `start` and `stop` raise `SupervisorError` with the pid or the reason
    in the message, and never return quietly having done nothing.

  * **`managed=False` is a first-class state, not an error.** A team
    server without the privilege to start a sibling process still reports
    what is configured and says why it cannot act, and the panel disables
    its button with that reason showing.

  * **No secret on a command line.** The control token goes to the child
    through its environment. The PSKs are not passed at all: the child
    reads them out of the key store the generator writes, and the path to
    that file is the only thing on the command line.

**Stopping this process drops every endpoint at once**, because every
command channel and every relay is a socket it holds. That is a property
of the arrangement and not a defect, and the route and the panel both say
so before and after acting -- an endpoint's own stop is a task for its
agent and takes a check-in, which is the other half of the same point.
"""

import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Optional

from ..listeners.errors import SupervisorError

__all__ = ["TunnelSupervisor", "SupervisorError", "tunnel_server_config"]

# How long to wait for the child to print its control port before giving
# up and reporting what it put on stderr instead. The child mints a
# keypair on a cold start, which on the pure-Python backend is the slowest
# thing it does.
_START_TIMEOUT = 30.0

# SIGTERM, then this long, then SIGKILL. The child's own shutdown closes
# its sockets and joins its threads, which is quick; one that needs longer
# is wedged, and leaving it running would hold the implant-facing port
# against the next start.
_TERM_GRACE = 5.0

_CONTROL_TIMEOUT = 5.0

# A control reply carries one row per endpoint with its counters, so it is
# larger than a listener's. Bounded all the same: the child is trusted,
# the socket is not a reason to read without a limit.
_MAX_REPLY = 4 << 20

_DEFAULTS = {
    "bind_host": "0.0.0.0",
    "bind_port": 8446,
    "socks_port_first": 19050,
    "socks_port_last": 19099,
    "keepalive_seconds": 30.0,
}


def tunnel_server_config(config: dict) -> Optional[dict]:
    """The `c2.tunnel_server` block, validated, or None when it is off.

    Refused by field name when it cannot be run, the way
    `listeners/registry.py` refuses a listener and `keys.py` refuses a
    damaged store: a tunnel server that was silently not configured shows
    up as an endpoint that never appears, which is the hardest class of
    failure in this project to attribute.
    """
    c2 = (config or {}).get("c2") or {}
    block = c2.get("tunnel_server")
    if block is None:
        return None
    if not isinstance(block, dict):
        raise ValueError("c2.tunnel_server must be a block of settings, "
                         "not %s" % type(block).__name__)
    if not block.get("enabled"):
        return None

    out = dict(_DEFAULTS)
    host = block.get("bind_host", out["bind_host"])
    if not isinstance(host, str) or not host.strip():
        raise ValueError("c2.tunnel_server.bind_host must be an address to "
                         "bind, got %r" % (host,))
    out["bind_host"] = host.strip()
    for field in ("bind_port", "socks_port_first", "socks_port_last"):
        value = block.get(field, out[field])
        if not isinstance(value, int) or isinstance(value, bool) \
                or not 1 <= value <= 65535:
            raise ValueError("c2.tunnel_server.%s must be a port between 1 "
                             "and 65535, got %r" % (field, value))
        out[field] = value
    if out["socks_port_first"] > out["socks_port_last"]:
        raise ValueError(
            "c2.tunnel_server.socks_port_first %d is above socks_port_last "
            "%d, so no endpoint could be given a port"
            % (out["socks_port_first"], out["socks_port_last"]))
    keepalive = block.get("keepalive_seconds", out["keepalive_seconds"])
    try:
        keepalive = float(keepalive)
    except (TypeError, ValueError):
        raise ValueError("c2.tunnel_server.keepalive_seconds must be a "
                         "number of seconds, got %r" % (keepalive,))
    if keepalive <= 0:
        raise ValueError("c2.tunnel_server.keepalive_seconds must be "
                         "positive, got %r" % (keepalive,))
    out["keepalive_seconds"] = keepalive
    return out


class TunnelSupervisor:
    """Own the one tunnel-server process this deployment is responsible for."""

    def __init__(self, config: dict, data_dir, *, managed: bool = True,
                 python: Optional[str] = None, cwd: Optional[str] = None):
        self.config = dict(config)
        self.data_dir = Path(data_dir)
        self.managed = managed
        self.python = python or sys.executable
        # The repository root, so `-m software.c2.tunnel` resolves for a
        # child started from anywhere.
        self.cwd = cwd or str(Path(__file__).resolve().parents[3])
        self.control_token = secrets.token_urlsafe(32)
        self._child = None          # type: Optional[_Child]
        self._lock = threading.Lock()

    # ── the three the panel calls ──

    def start(self) -> dict:
        self._require_managed("start")
        with self._lock:
            if self._child is not None and self._child.alive():
                raise SupervisorError(
                    "the tunnel server is already running as pid %d; stop it "
                    "first" % self._child.pid)
            if self._child is not None:
                # It died and nobody reaped it yet. Do that now, or the
                # next status would report the corpse.
                self._child.reap()
            self._child = _Child.spawn(self)
        return self.status()

    def stop(self) -> dict:
        self._require_managed("stop")
        with self._lock:
            child = self._child
            if child is None or not child.alive():
                raise SupervisorError(
                    "the tunnel server is not running, so there is nothing "
                    "to stop")
            child.terminate()
            self._child = None
        return self.status()

    def status(self) -> dict:
        """The server block, with the child's endpoint rows inside it."""
        entry = {
            "state": "stopped",
            "can_control": self.managed,
            "pid": None,
            "detail": "configured, not started",
            "bind_host": self.config.get("bind_host"),
            "bind_port": self.config.get("bind_port"),
            "socks_port_first": self.config.get("socks_port_first"),
            "socks_port_last": self.config.get("socks_port_last"),
            "address": None,
            "crypto": None,
            "uptime_seconds": None,
            "endpoints": [],
            "sessions": [],
        }
        if not self.managed:
            entry["state"] = "unmanaged"
            entry["detail"] = (
                "this deployment does not manage the tunnel server process; "
                "start and stop it the way the team server is started")
            return entry
        with self._lock:
            child = self._child
        if child is None:
            return entry
        if not child.alive():
            entry["state"] = "died"
            entry["detail"] = child.death_detail()
            return entry

        entry["state"] = "running"
        entry["pid"] = child.pid
        reported = child.ask_status(self.control_token)
        if reported is None:
            # Alive, but its control socket did not answer. Worth saying
            # out loud rather than showing no endpoints as though none had
            # connected -- which is the one reading an operator must not
            # be given by accident.
            entry["detail"] = ("running, but its control socket did not "
                               "answer, so the endpoints below may be "
                               "incomplete")
            return entry
        entry["detail"] = "up for %ss" % reported.get("uptime_seconds", "?")
        entry["address"] = reported.get("address")
        entry["crypto"] = reported.get("crypto")
        entry["uptime_seconds"] = reported.get("uptime_seconds")
        rows = reported.get("endpoints")
        entry["endpoints"] = rows if isinstance(rows, list) else []
        sessions = reported.get("sessions")
        entry["sessions"] = sessions if isinstance(sessions, list) else []
        return entry

    def stop_all(self) -> None:
        """Tear the child down. Used on shutdown and by every test."""
        with self._lock:
            child, self._child = self._child, None
        if child is not None:
            try:
                child.terminate()
            except Exception:
                pass

    # ── internals ──

    def _require_managed(self, action: str) -> None:
        if not self.managed:
            raise SupervisorError(
                "this deployment does not manage the tunnel server process, "
                "so it cannot %s it. The team server is running without the "
                "privilege to start a sibling process -- in Docker that is "
                "deliberate, because mounting the Docker socket would give "
                "the container control of its host. Start and stop the "
                "tunnel server the same way the team server itself is "
                "started." % action)

    def key_store_path(self) -> Path:
        """The PSK registry, which the generator writes and the child reads."""
        return self.data_dir / "tunnel" / "keys.json"

    def state_path(self) -> Path:
        """The port table, so an identity keeps its SOCKS port."""
        return self.data_dir / "tunnel" / "ports.json"


class _Child:
    """The tunnel-server process, and what is known about how it ended."""

    def __init__(self, process, control_port, stderr_path):
        self.process = process
        self.control_port = control_port
        self.stderr_path = stderr_path
        self.pid = process.pid

    @classmethod
    def spawn(cls, supervisor: "TunnelSupervisor") -> "_Child":
        config = supervisor.config
        command = [supervisor.python, "-m", "software.c2.tunnel",
                   "--bind-host", str(config["bind_host"]),
                   "--bind-port", str(config["bind_port"]),
                   "--socks-port-first", str(config["socks_port_first"]),
                   "--socks-port-last", str(config["socks_port_last"]),
                   "--keepalive-seconds", str(config["keepalive_seconds"]),
                   "--key-store", str(supervisor.key_store_path()),
                   "--state-path", str(supervisor.state_path()),
                   "--control-port", "0"]

        environment = dict(os.environ)
        # Secrets by environment, never argv: a command line is readable
        # by every user on the host. The beacon's symmetric key is not
        # here in any form -- the tunnel authenticates with its own Noise
        # credentials and has no field that could hold one.
        environment["RACCOON_CONTROL_TOKEN"] = supervisor.control_token
        environment["PYTHONPATH"] = supervisor.cwd
        environment["PYTHONUNBUFFERED"] = "1"

        # stderr to a file rather than a pipe. A pipe nobody drains fills
        # its buffer and then blocks the child mid-log, which would look
        # exactly like a tunnel server that hung.
        handle = tempfile.NamedTemporaryFile(prefix="raccoon-tunnel-",
                                             suffix=".log", delete=False)
        process = subprocess.Popen(
            command, cwd=supervisor.cwd, env=environment,
            stdout=subprocess.PIPE, stderr=handle, stdin=subprocess.DEVNULL,
            text=True)
        handle.close()

        port = cls._read_control_port(process, handle.name)
        return cls(process, port, handle.name)

    @staticmethod
    def _read_control_port(process, stderr_path):
        """Read the one line the child prints, or raise with its stderr."""
        line = _read_line_with_timeout(process.stdout, _START_TIMEOUT)
        if line is None:
            # A child that exited and one that is alive and silent are
            # the same `None` here and are not the same fault, so they
            # are not reported in the same words: the listeners'
            # supervisor calls both a timeout, and a start refused in
            # half a second that says "did not come up within 30s" sends
            # the reader looking for a slow machine.
            code = process.poll()
            _kill(process)
            if code is not None:
                raise SupervisorError(
                    "the tunnel server %s before it could serve. Its "
                    "output was: %s"
                    % ("exited on signal %d" % -code if code < 0
                       else "exited with code %d" % code,
                       _tail(stderr_path)))
            raise SupervisorError(
                "the tunnel server did not come up within %gs. Its output "
                "was: %s" % (_START_TIMEOUT, _tail(stderr_path)))
        if not line.startswith("control-port "):
            _kill(process)
            raise SupervisorError(
                "the tunnel server printed %r instead of its control port. "
                "Its output was: %s" % (line[:120], _tail(stderr_path)))
        value = line.split(" ", 1)[1].strip()
        if value == "none":
            return None
        try:
            return int(value)
        except ValueError:
            _kill(process)
            raise SupervisorError(
                "the tunnel server printed an unreadable control port %r"
                % value)

    def alive(self) -> bool:
        return self.process.poll() is None

    def reap(self) -> None:
        try:
            self.process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass

    def death_detail(self) -> str:
        code = self.process.returncode
        if code is None:
            return "exit status unknown"
        if code < 0:
            reason = "exited on signal %d" % -code
        else:
            reason = "exit code %d" % code
        tail = _tail(self.stderr_path)
        return "%s; its output was: %s" % (reason, tail) if tail else reason

    def terminate(self) -> None:
        """SIGTERM, then SIGKILL, then reap. No child is left behind.

        Reaped rather than merely signalled: an unreaped child is a
        zombie, its pid still answers `kill -0`, and `status` would keep
        reporting it as running.
        """
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=_TERM_GRACE)
            except subprocess.TimeoutExpired:
                self.process.kill()
                try:
                    self.process.wait(timeout=_TERM_GRACE)
                except subprocess.TimeoutExpired:
                    pass
        if self.process.stdout is not None:
            try:
                self.process.stdout.close()
            except OSError:
                pass

    def ask_status(self, token: str) -> Optional[dict]:
        """One question over the control socket, or None if it did not answer."""
        if self.control_port is None:
            return None
        try:
            with socket.create_connection(("127.0.0.1", self.control_port),
                                          timeout=_CONTROL_TIMEOUT) as sock:
                sock.sendall(json.dumps({"token": token,
                                         "verb": "status"}).encode() + b"\n")
                sock.settimeout(_CONTROL_TIMEOUT)
                raw = b""
                while b"\n" not in raw and len(raw) < _MAX_REPLY:
                    chunk = sock.recv(65536)
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


def _read_line_with_timeout(stream, timeout):
    """Read one line, giving up after `timeout`.

    A blocking readline on a child that never prints would hang the team
    server, so the read happens on a thread the caller can abandon. The
    thread is a daemon: if the child is killed its stdout closes and the
    read returns, and if it is not, the thread costs nothing.
    """
    if stream is None:
        return None
    out = {}

    def _read():
        try:
            out["line"] = stream.readline()
        except (OSError, ValueError):
            out["line"] = ""

    worker = threading.Thread(target=_read, daemon=True)
    worker.start()
    worker.join(timeout)
    line = out.get("line")
    if not line:
        return None
    return line.strip()


def _tail(path, limit=400):
    try:
        with open(path) as handle:
            text = handle.read()
    except OSError:
        return ""
    text = " ".join(text.split())
    return text[-limit:]


def _kill(process):
    try:
        process.kill()
        process.wait(timeout=5.0)
    except Exception:
        pass
    # Closed here as well as in `terminate`: every path that gives up on a
    # child goes through one of the two, and a pipe left open is a
    # ResourceWarning in whatever test happens to run next.
    if process.stdout is not None:
        try:
            process.stdout.close()
        except (OSError, ValueError):
            pass
