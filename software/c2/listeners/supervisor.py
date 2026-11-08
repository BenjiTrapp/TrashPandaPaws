"""Starting, stopping and reporting on listeners that are separate processes.

The team server runs this. It spawns a listener as a child process, kills
it on request, and reads its state over the child's loopback control
socket. Task 9's panel calls `start`, `stop` and `status` and nothing
else.

Three properties this is built around, each learned from a failure
somewhere in this project:

  * **Every refusal carries a reason.** A listener that silently fails to
    start, or a `stop` that returns while the process keeps running, shows
    up later as a beacon that does not check in -- and four unrelated
    faults produce exactly that symptom, so an operator chasing it has no
    way to tell them apart. So `start` and `stop` raise `SupervisorError`
    with the pid or the name in the message, and never return quietly
    having done nothing.

  * **`managed=False` is a first-class state, not an error.** The compose
    file deliberately does not mount the Docker socket, so a team server
    in a container cannot start a sibling. In that mode `status` still
    reports every configured listener and says why it cannot act, and the
    panel disables its buttons with that reason showing. A control that
    silently does nothing is the anti-goal.

  * **No secret on a command line.** The listener token and the control
    token go to the child through its environment. The encryption key goes
    nowhere near it in any form.

The control token is generated here, per supervisor, and exists only in
memory and in the children's environment. It is deliberately *not* the
operator token: a listener is the most exposed process in the
arrangement, and one that held the operator token could task the whole
fleet the moment it could reach the operator socket.
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
from typing import Dict, List, Optional

from .registry import ListenerSpec

# How long to wait for a child to print its control port before giving up
# and reporting what it put on stderr instead.
_START_TIMEOUT = 20.0

# SIGTERM, then this long, then SIGKILL. The child's own shutdown closes
# its socket and joins its serving thread, which is quick; a child that
# needs longer than this is wedged, and leaving it running would hold the
# port against the next start.
_TERM_GRACE = 5.0

_CONTROL_TIMEOUT = 5.0


class SupervisorError(Exception):
    """A refusal with a reason in it, for the panel to show verbatim."""


class Supervisor:
    """Own the listener processes this deployment is responsible for."""

    def __init__(self, specs: List[ListenerSpec], *, managed: bool = True,
                 listener_token: Optional[str] = None,
                 python: Optional[str] = None,
                 cwd: Optional[str] = None):
        self.specs = {spec.name: spec for spec in specs}
        self.managed = managed
        self.listener_token = listener_token
        self.python = python or sys.executable
        # The repository root, so `-m software.c2.listeners` resolves for a
        # child started from anywhere.
        self.cwd = cwd or str(Path(__file__).resolve().parents[3])
        self.control_token = secrets.token_urlsafe(32)
        self._children = {}        # type: Dict[str, _Child]
        self._lock = threading.Lock()

    # ── the three the panel calls ──

    def start(self, name: str) -> dict:
        spec = self._spec(name)
        self._require_managed("start")
        with self._lock:
            child = self._children.get(name)
            if child is not None and child.alive():
                raise SupervisorError(
                    "listener %r is already running as pid %d; stop it first"
                    % (name, child.pid))
            if child is not None:
                # It died and nobody reaped it yet. Do that now, or the
                # next status would report the corpse.
                child.reap()
            started = _Child.spawn(spec, self)
            self._children[name] = started
        return self._entry(spec, started)

    def stop(self, name: str) -> dict:
        spec = self._spec(name)
        self._require_managed("stop")
        with self._lock:
            child = self._children.get(name)
            if child is None or not child.alive():
                raise SupervisorError(
                    "listener %r is not running, so there is nothing to stop"
                    % name)
            child.terminate()
            self._children.pop(name, None)
        return self._entry(spec, None)

    def status(self) -> List[dict]:
        out = []
        with self._lock:
            for name in sorted(self.specs):
                out.append(self._entry(self.specs[name],
                                       self._children.get(name)))
        return out

    def stop_all(self) -> None:
        """Tear everything down. Used on shutdown and by every test."""
        with self._lock:
            for name in list(self._children):
                child = self._children.pop(name)
                try:
                    child.terminate()
                except Exception:
                    pass

    # ── internals ──

    def _spec(self, name: str) -> ListenerSpec:
        spec = self.specs.get(name)
        if spec is None:
            raise SupervisorError(
                "no listener called %r is configured; have %s"
                % (name, ", ".join(sorted(self.specs)) or "none"))
        return spec

    def _require_managed(self, action: str) -> None:
        if not self.managed:
            raise SupervisorError(
                "this deployment does not manage listener processes, so it "
                "cannot %s one. The team server is running without the "
                "privilege to start a sibling process -- in Docker that is "
                "deliberate, because mounting the Docker socket would give "
                "the container control of its host. Start and stop the "
                "listeners the same way the team server itself is started."
                % action)

    def _entry(self, spec: ListenerSpec, child) -> dict:
        entry = {
            "name": spec.name,
            "transport": spec.transport,
            "enabled": spec.enabled,
            "bind_host": spec.bind_host,
            "bind_port": spec.bind_port,
            "can_control": self.managed,
            "pid": None,
            "state": "stopped",
            "detail": "",
            "counters": {},
        }
        if not self.managed:
            entry["state"] = "unmanaged"
            entry["detail"] = (
                "this deployment does not manage listener processes; start "
                "and stop them the way the team server is started")
            return entry
        if child is None:
            entry["detail"] = "configured, not started"
            return entry
        if not child.alive():
            entry["state"] = "died"
            entry["detail"] = child.death_detail()
            return entry

        entry["state"] = "running"
        entry["pid"] = child.pid
        reported = child.ask_status(self.control_token)
        if reported is None:
            # The process is alive but its control socket did not answer.
            # Worth saying out loud rather than showing empty counters as
            # though the listener were idle.
            entry["detail"] = ("running, but its control socket did not "
                               "answer")
        else:
            entry["counters"] = reported.get("counters", {})
            entry["detail"] = "up for %ss" % reported.get("uptime_seconds", "?")
            entry["address"] = reported.get("address")
        return entry


class _Child:
    """One listener process, and what is known about how it ended."""

    def __init__(self, process, control_port, stderr_path):
        self.process = process
        self.control_port = control_port
        self.stderr_path = stderr_path
        self.pid = process.pid

    @classmethod
    def spawn(cls, spec: ListenerSpec, supervisor: "Supervisor") -> "_Child":
        command = [supervisor.python, "-m", "software.c2.listeners",
                   "--transport", spec.transport,
                   "--name", spec.name,
                   "--bind-host", spec.bind_host,
                   "--bind-port", str(spec.bind_port),
                   "--relay-url", spec.relay_url,
                   "--control-port", "0"]
        for key, value in sorted(spec.settings.items()):
            command += ["--setting", "%s=%s" % (key, value)]

        environment = dict(os.environ)
        # Secrets by environment, never argv: a command line is readable
        # by every user on the host.
        environment["RACCOON_CONTROL_TOKEN"] = supervisor.control_token
        if supervisor.listener_token:
            environment["RACCOON_LISTENER_TOKEN"] = supervisor.listener_token
        else:
            environment.pop("RACCOON_LISTENER_TOKEN", None)
        environment["PYTHONPATH"] = supervisor.cwd
        environment["PYTHONUNBUFFERED"] = "1"

        # stderr to a file rather than a pipe. A pipe nobody drains fills
        # its buffer and then blocks the child mid-log, which would look
        # exactly like a listener that hung.
        handle = tempfile.NamedTemporaryFile(
            prefix="raccoon-listener-%s-" % spec.name, suffix=".log",
            delete=False)
        process = subprocess.Popen(
            command, cwd=supervisor.cwd, env=environment,
            stdout=subprocess.PIPE, stderr=handle, stdin=subprocess.DEVNULL,
            text=True)
        handle.close()

        port = cls._read_control_port(process, handle.name, spec)
        return cls(process, port, handle.name)

    @staticmethod
    def _read_control_port(process, stderr_path, spec):
        """Read the one line the child prints, or raise with its stderr."""
        line = _read_line_with_timeout(process.stdout, _START_TIMEOUT)
        if line is None:
            _kill(process)
            raise SupervisorError(
                "listener %r did not come up within %gs. Its output was: %s"
                % (spec.name, _START_TIMEOUT, _tail(stderr_path)))
        if not line.startswith("control-port "):
            _kill(process)
            raise SupervisorError(
                "listener %r printed %r instead of its control port. Its "
                "output was: %s" % (spec.name, line[:120],
                                    _tail(stderr_path)))
        value = line.split(" ", 1)[1].strip()
        if value == "none":
            return None
        try:
            return int(value)
        except ValueError:
            _kill(process)
            raise SupervisorError(
                "listener %r printed an unreadable control port %r"
                % (spec.name, value))

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

        Reaped rather than merely signalled: an unreaped child is a zombie,
        its pid still answers `kill -0`, and `status` would keep reporting
        it as running.
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
                while b"\n" not in raw and len(raw) < 65536:
                    chunk = sock.recv(4096)
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
