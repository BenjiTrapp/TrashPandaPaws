"""Run the tunnel server as a process.

    python3 -m software.c2.tunnel --bind-host 0.0.0.0 --bind-port 8446 \\
        --socks-port-first 19050 --socks-port-last 19099 \\
        --key-store ~/.raccoon-c2/tunnel/keys.json \\
        --state-path ~/.raccoon-c2/tunnel/ports.json

Started this way by `tunnel/supervisor.py`, and startable the same way by
hand or by a systemd unit. It is a separate process from the team server
for one reason: **the team server keeps exactly two listening sockets and
gains no protocol parser.** This process holds the Noise responder, the
static private key and every build's PSK, opens the implant-facing port,
and opens one loopback SOCKS port per connected endpoint -- all of which
the operator interface must be able to lose without losing the fleet.

It is deliberately not a listener and not in `c2.listeners`: a listener
never holds the encryption key, which is what makes one safe on a host
you do not mind losing. See `configs/raccoon.yaml` and docs/LISTENERS.md.

**No secret is ever an argument.** The control token comes from the
environment, because anything on a command line is readable by every user
on the host through `ps` -- a finding this project has already paid for
once. `--key-store` is the *path* to the PSK registry, not key material;
the file is read by this process and by the generator, and it never
appears on a command line in any other form. The per-identity SOCKS
credential is minted here, in memory, and reported over the control
socket.

Unlike `listeners/__main__.py` this process accepts no socket from
`$LISTEN_FDS`. That mechanism exists so a listener can serve port 53 or
445 without the privilege to bind them; the tunnel port is unprivileged
by design -- `configs/raccoon.yaml` ships 8446 and says why -- and
`TunnelServer` binds its own socket, so there would be nothing for an
inherited descriptor to do but add a way to get it wrong.

On startup it prints one line to stdout and then never writes there
again:

    control-port <n>      a control socket is listening on 127.0.0.1:<n>
    control-port none     no control token was given, so there is none

The supervisor reads that line to find the control socket. Everything
else, including every log line, goes to stderr.
"""

import argparse
import hmac
import json
import logging
import os
import secrets
import signal
import socket
import socketserver
import sys
import threading
import time

from .keys import KeyStore
from .server import TunnelServer, crypto_path
from .socks import SocksFront

logger = logging.getLogger("raccoon.tunnel.main")

# Where a control socket may bind, and the only place. This surface can
# start nothing and stop nothing; it answers one question. Even so it is
# loopback-only, like the listeners' -- and so is every SOCKS port this
# process opens, which `SocksFront` enforces for itself.
_CONTROL_HOST = "127.0.0.1"

_CONTROL_TOKEN_VAR = "RACCOON_CONTROL_TOKEN"

# Where every SOCKS port binds. The same address as the control socket and
# a separate constant on purpose: these are two different claims, and
# `SocksFront` refuses a non-loopback address of its own accord -- an
# unauthenticated pivot into the target network reachable from another
# host is not something a typo should be able to produce.
_SOCKS_HOST = "127.0.0.1"

# One request, one line, and a cap so a client cannot make this process
# buffer. A status request is about eighty bytes.
_MAX_REQUEST = 4096

# How long the reconciliation loop sleeps between passes. An endpoint
# connects and then waits for its SOCKS port, so this is the delay an
# operator sees between "connected" appearing on the row and the port
# being open; half a second is below noticing and costs nothing.
_RECONCILE_INTERVAL = 0.5

# Bytes of randomness in a SOCKS password. Per identity, generated here,
# and never written to disk: it protects a loopback port against the
# other local users of the team server, and a port that outlives this
# process has lost its sessions anyway.
_PASSWORD_BYTES = 16


def main(argv=None):
    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, stream=sys.stderr,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s")

    try:
        keystore = KeyStore(args.key_store)
        # Read once at startup so a damaged store is a refusal here, with
        # the file named, rather than a handshake that fails later for a
        # reason nobody can see. `KeyStore` re-reads on every call, so a
        # build registered after this point is still accepted.
        builds = keystore.builds()
    except (OSError, ValueError) as exc:
        print("could not use the key store at %s: %s" % (args.key_store, exc),
              file=sys.stderr)
        return 1

    try:
        server = TunnelServer(
            keystore, args.bind_host, args.bind_port,
            (args.socks_port_first, args.socks_port_last), args.state_path,
            keepalive_interval=args.keepalive_seconds)
    except (OSError, ValueError) as exc:
        print("could not build the tunnel server: %s" % exc, file=sys.stderr)
        return 1

    fronts = _Fronts(server)
    try:
        server.start()
    except OSError as exc:
        print("could not listen on %s:%d: %s"
              % (args.bind_host, args.bind_port, exc), file=sys.stderr)
        return 1
    logger.info("tunnel: %d build%s registered, crypto path %s",
                len(builds), "" if len(builds) == 1 else "s", crypto_path())

    control = _start_control(server, fronts, args)
    stopping = threading.Event()

    def _handle(signum, _frame):
        print("stopping on signal %d" % signum, file=sys.stderr)
        stopping.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _handle)

    try:
        while not stopping.is_set():
            # Opening a port is the one thing this loop does, and it is
            # done here rather than from the accept path so that a port
            # that cannot be bound delays nothing and crashes nothing.
            fronts.reconcile(server.endpoints())
            stopping.wait(_RECONCILE_INTERVAL)
    finally:
        if control is not None:
            control.shutdown()
            control.server_close()
        fronts.stop_all()
        server.stop()
    return 0


def _parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bind-host", default="0.0.0.0",
                        help="where endpoints dial in")
    parser.add_argument("--bind-port", type=int, required=True,
                        help="one port carries every command channel and "
                             "every relay; 0 picks a free one")
    parser.add_argument("--socks-port-first", type=int, required=True,
                        help="first loopback SOCKS port, one per endpoint")
    parser.add_argument("--socks-port-last", type=int, required=True,
                        help="last loopback SOCKS port, inclusive")
    parser.add_argument("--key-store", required=True,
                        help="the PSK and identity registry the generator "
                             "writes; a path, never key material")
    parser.add_argument("--state-path", required=True,
                        help="the port table, so an identity keeps its "
                             "SOCKS port across restarts")
    parser.add_argument("--keepalive-seconds", type=float, default=30.0,
                        help="PING/PONG interval; an endpoint is declared "
                             "gone after three missed ones")
    parser.add_argument("--control-port", type=int, default=0,
                        help="0 picks a free port; the chosen one is printed")
    return parser


class _Fronts(object):
    """The loopback SOCKS ports this process has opened, one per identity.

    One per endpoint identity, on the port the tunnel server's port table
    assigned it, because an operator's `proxychains.conf` names that port
    and this design's own anti-goal is a port that moves under them.

    A port is opened when its identity first connects and then **kept**,
    disconnected or not. Closing it on a disconnect would make a tunnel
    that dropped for thirty seconds look to the operator's tooling like
    one that was never issued a port, and reopening it is the moment at
    which another process could have taken the number. While the endpoint
    is away the port still answers, authenticates, and then refuses the
    session with the tunnel's own reply code, which is a refusal the
    operator can read.

    `factory` is `SocksFront` in production and is a parameter so the
    reconciliation can be tested without binding anything.

    `reconcile` is the only writer and is called from one thread -- the
    main loop -- so it reads the tables without the lock and takes it to
    change them. The lock is there for `decorate`, which runs on a
    control-socket thread.
    """

    def __init__(self, tunnel_server, factory=None):
        self._tunnel = tunnel_server
        self._factory = factory or SocksFront
        self._lock = threading.Lock()
        self._fronts = {}          # type: dict
        self._credentials = {}     # type: dict
        self._failures = {}        # type: dict

    def reconcile(self, rows):
        """Open a SOCKS port for every connected identity that has none."""
        for row in rows:
            identity = row.get("identity")
            port = row.get("port")
            if (not identity or row.get("state") != "connected"
                    or identity in self._fronts or not port):
                continue
            # The username is the identity, which is not a secret and
            # makes a proxychains entry say which endpoint it reaches.
            # Only the password is random.
            credential = (str(identity), secrets.token_urlsafe(_PASSWORD_BYTES))
            try:
                # Every argument past `password` by keyword: `max_pending`
                # sits between `max_sessions` and `bind_host`, so a
                # positional call here would silently cap the handshakes
                # in flight with a hostname.
                front = self._factory(self._tunnel, identity, int(port),
                                      credential[0], credential[1],
                                      bind_host=_SOCKS_HOST)
                front.start()
            except (OSError, ValueError) as exc:
                # The likeliest cause by far is another process holding
                # the number, and the operator can only act on it if they
                # are told. Recorded against the row rather than raised:
                # one unusable port must not cost the other endpoints
                # theirs.
                reason = ("the SOCKS port %s for %r could not be opened: %s"
                          % (port, identity, exc))
                if self._failures.get(identity) != reason:
                    logger.warning("tunnel: %s", reason)
                with self._lock:
                    self._failures[identity] = reason
                continue
            with self._lock:
                self._fronts[identity] = front
                self._credentials[identity] = credential
                self._failures.pop(identity, None)
            logger.info("tunnel: %r is served on %s:%s",
                        identity, _SOCKS_HOST, port)

    def decorate(self, row):
        """One `endpoints()` row plus what its SOCKS port has done.

        This row carries the port's `username` and `password`, which is a
        deliberate exception to the rule `TunnelServer.status()` keeps --
        no field a screenshot must not carry. That rule is about the relay
        session token, which is the credential that would let somebody
        else take an operator's relay, and about what gets written to
        disk. This one is the operator's own credential for the operator's
        own loopback port: the port authenticates per RFC 1929 precisely
        so that another local user of the team server cannot pivot
        through it, and an operator who cannot read it cannot write their
        `proxychains.conf`. The team server already shows the operator
        token in its settings panel for the same reason. It is minted per
        identity, never written to disk, and travels only over the
        token-authenticated loopback control socket.
        """
        identity = row.get("identity")
        with self._lock:
            front = self._fronts.get(identity)
            credential = self._credentials.get(identity)
            failure = self._failures.get(identity, "")
        out = dict(row)
        out["socks"] = front.stats() if front is not None else None
        out["username"] = credential[0] if credential else None
        out["password"] = credential[1] if credential else None
        out["socks_detail"] = failure or ("" if front is not None else (
            "no SOCKS port is open yet: one opens on this identity's "
            "assigned port when the endpoint connects"))
        return out

    def stop_all(self):
        with self._lock:
            fronts = list(self._fronts.values())
            self._fronts = {}
            self._credentials = {}
        for front in fronts:
            try:
                front.stop()
            except Exception as exc:          # pragma: no cover - teardown
                logger.warning("tunnel: a SOCKS port did not stop: %s", exc)


def _start_control(server, fronts, args):
    """Open the control socket, or say there is none, and print which.

    No token means no socket, exactly as in `listeners/__main__.py`: a
    tunnel server started by hand or by a systemd unit, with no supervisor
    to talk to, opens no surface at all.
    """
    token = os.environ.get(_CONTROL_TOKEN_VAR)
    if not token:
        print("control-port none", flush=True)
        print("no %s in the environment, so no control socket"
              % _CONTROL_TOKEN_VAR, file=sys.stderr)
        return None

    control = _ControlServer((_CONTROL_HOST, args.control_port),
                             _ControlHandler)
    control.token = token
    control.tunnel = server
    control.fronts = fronts
    control.started_at = time.time()
    threading.Thread(target=control.serve_forever,
                     kwargs={"poll_interval": 0.1}, daemon=True).start()
    print("control-port %d" % control.server_address[1], flush=True)
    return control


class _ControlServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    token = None
    tunnel = None
    fronts = None
    started_at = 0.0


class _ControlHandler(socketserver.BaseRequestHandler):
    """One JSON line in, one JSON line out, and `status` is the only verb.

    Not start, and not stop. This process cannot start itself, and a verb
    that let it stop itself would be a remote kill switch on the process
    that holds every build's PSK -- reachable by anything that learned one
    token on one host. Starting and stopping are things the supervisor
    does from outside, with a signal, which is also why an endpoint's own
    start and stop are not here: they are tasks for an agent, queued by
    the team server.
    """

    def handle(self):
        self.request.settimeout(5.0)
        try:
            raw = self._read_line()
        except (OSError, socket.timeout):
            return
        if raw is None:
            return

        try:
            request = json.loads(raw)
            if not isinstance(request, dict):
                raise ValueError("not an object")
        except ValueError:
            self._reply({"error": "the request is not a JSON object"})
            return

        presented = request.get("token")
        expected = self.server.token
        if not isinstance(presented, str) or not _same(presented, expected):
            self._reply({"error": "unauthorized"})
            return

        verb = request.get("verb")
        if verb != "status":
            self._reply({"error": "the only verb is status",
                         "refused": str(verb)[:64]})
            return
        self._reply(self._status())

    def _read_line(self):
        buffer = b""
        while b"\n" not in buffer:
            if len(buffer) > _MAX_REQUEST:
                return None
            chunk = self.request.recv(1024)
            if not chunk:
                return buffer.decode("utf-8", "replace") or None
            buffer += chunk
        return buffer.split(b"\n", 1)[0].decode("utf-8", "replace")

    def _status(self):
        tunnel = self.server.tunnel
        fronts = self.server.fronts
        return {
            "pid": os.getpid(),
            "address": [tunnel.bind_host, tunnel.port],
            # Reported so a test can hold the claim that this surface is
            # loopback-only. Asserting it by failing to connect from
            # elsewhere needs a second address this host may not have,
            # and a test that skips does not hold anything.
            "control_address": list(self.server.server_address),
            "uptime_seconds": round(time.time() - self.server.started_at, 1),
            # The process-level fact, repeated on every row by
            # `endpoints()` as well: a tunnel on the pure-Python cipher
            # runs at roughly 50-200 KB/s, and an operator who cannot see
            # that spends an afternoon on a network fault that is not
            # there.
            "crypto": crypto_path(),
            "socks_port_range": [tunnel.first_port, tunnel.last_port],
            "endpoints": [fronts.decorate(row) for row in tunnel.endpoints()],
            "sessions": tunnel.status(),
        }

    def _reply(self, payload):
        try:
            self.request.sendall(json.dumps(payload).encode() + b"\n")
        except OSError:
            pass


def _same(presented: str, expected: str) -> bool:
    return hmac.compare_digest(presented.encode(), expected.encode())


if __name__ == "__main__":
    sys.exit(main())
