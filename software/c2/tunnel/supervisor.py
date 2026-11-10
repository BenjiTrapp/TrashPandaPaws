"""Starting, stopping and reporting on the tunnel server, which is a process.

The team server runs this. It spawns `python3 -m software.c2.tunnel` as a
child, kills it on request, and reads its state over the child's loopback
control socket. Task 10's panel calls `start`, `stop` and `status` and
nothing else.

**One child, not a table of them.** There is one tunnel server per
deployment -- one implant-facing port, one port table, one key store --
so this is deliberately not `listeners/supervisor.py` with a different
spec type. The two state machines have almost nothing in common: this one
holds a single child rather than a dict keyed by name, it reads
`c2.tunnel_server` rather than `c2.listeners`, it has no `ListenerSpec`
and no transport, and its refusals are about state rather than about a
name that might have been typed wrong. What they *do* share is the
mechanics of being a supervised child, and that is shared code rather
than a second copy: `listeners/child.py`. Two copies of it had already
drifted within one commit, each time in the direction of the version
fewer people read.

That module is in the listeners' package and imports no listener, for the
same reason `listeners/errors.py` is there: anything may import it. This
module reaches for both and for nothing else in that package, so it loads
no transport. It is also 150 lines of `subprocess` discipline that has no
business in a 9,000-line Flask module, which is where it would otherwise
have gone.

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

import os
import secrets
import sys
import threading
from pathlib import Path
from typing import Optional

from ..listeners.child import (SupervisedChild, discard, launch,
                               read_control_port)
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
#
# Kept here rather than read from `child.py` so that a test can patch the
# escalation in the module it is testing; `_Child.term_grace` resolves it
# when it is asked.
_TERM_GRACE = 5.0

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
        """The PSK registry, which the generator writes and the child reads.

        Asked of `tunnel/keys.py` rather than spelled here: this and the
        generator's `_tunnel_keystore_path` each used to build the path
        and each claimed to be the one both sides share, which is how two
        copies of a path drift into a generator registering PSKs in a
        file the server never reads. Imported inside the method so this
        module keeps holding no key material and no crypto import of its
        own; it spawns a child and that is all.
        """
        from .keys import keystore_path

        return keystore_path(self.data_dir)

    def state_path(self) -> Path:
        """The port table, so an identity keeps its SOCKS port."""
        return self.data_dir / "tunnel" / "ports.json"


class _Child(SupervisedChild):
    """The tunnel-server process. Its command line, and nothing else.

    Spawning, the control-port read, the SIGTERM/SIGKILL escalation and
    the status question live in `listeners/child.py`, shared with the
    listeners' supervisor -- see this module's docstring for why that is
    the one thing the two have in common.
    """

    # One row per endpoint with its counters, which is larger than a
    # listener's handful. Bounded all the same: the child is trusted, a
    # socket is not a reason to read without a limit.
    max_reply = 4 << 20

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

        process, stderr_path = launch(command, supervisor.cwd, environment,
                                      "raccoon-tunnel-")
        try:
            port = read_control_port(process, stderr_path,
                                     "the tunnel server", _START_TIMEOUT)
        except SupervisorError:
            discard(stderr_path)
            raise
        return cls(process, port, stderr_path, owned=True)

    def term_grace(self):
        # Resolved here, from this module, for the reason the listeners'
        # one is: a test patches the constant in the module it is testing.
        return _TERM_GRACE
