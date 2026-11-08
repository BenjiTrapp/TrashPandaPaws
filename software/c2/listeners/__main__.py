"""Run one listener as a process.

    python3 -m software.c2.listeners --transport quic --bind-host 0.0.0.0 \\
        --bind-port 8443 --relay-url http://127.0.0.1:8443/api/v1/beacon

Started this way by `supervisor.Supervisor`, and startable the same way by
hand or by a systemd unit. One process serves exactly one listener: a
crash costs that transport and nothing else, which is the property the
whole arrangement was chosen for.

**No secret is ever an argument.** The listener token and the control
token come from the environment, because anything on a command line is
readable by every user on the host through `ps` -- a finding this project
has already paid for once. The encryption key is not here in any form:
a listener moves opaque ciphertext and must not be able to read it.

Two things this process can be handed instead of creating them itself:

  * A **pre-bound service socket**, when `$LISTEN_FDS` is set the way
    systemd sets it. The privileged port belongs to systemd or to
    dockerd's port mapping, so nothing here needs the privilege to bind
    53 or 445 -- no `cap_add`, no `setcap`, no sudo.
  * Nothing else. There is no configuration file read here and no network
    call made to fetch one.

On startup it prints one line to stdout and then never writes there
again:

    control-port <n>      a control socket is listening on 127.0.0.1:<n>
    control-port none     no control token was given, so there is none

The supervisor reads that line to find the control socket. Everything
else, including every log line, goes to stderr.
"""

import argparse
import json
import os
import signal
import socket
import socketserver
import sys
import threading
import time

from .registry import ListenerSpec, transport_names

# Where a control socket may bind, and the only place. This surface can
# start nothing and stop nothing; it answers one question. Even so it is
# loopback-only, because the host a listener runs on is the most exposed
# one in the arrangement.
_CONTROL_HOST = "127.0.0.1"

# systemd hands inherited descriptors starting at 3.
_LISTEN_FDS_START = 3

_CONTROL_TOKEN_VAR = "RACCOON_CONTROL_TOKEN"
_LISTENER_TOKEN_VAR = "RACCOON_LISTENER_TOKEN"

# One request, one line, and a cap so a client cannot make this process
# buffer. A status request is about eighty bytes.
_MAX_REQUEST = 4096


def main(argv=None):
    args = _parser().parse_args(argv)

    settings = {}
    for item in args.setting or []:
        if "=" not in item:
            print("--setting takes key=value, got %r" % item, file=sys.stderr)
            return 2
        key, value = item.split("=", 1)
        settings[key] = value

    spec = ListenerSpec(name=args.name or args.transport,
                        transport=args.transport, enabled=True,
                        bind_host=args.bind_host, bind_port=args.bind_port,
                        relay_url=args.relay_url, settings=settings)

    try:
        inherited = _inherited_socket(args.transport)
    except _ActivationError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    try:
        listener = spec.build(
            listener_token=os.environ.get(_LISTENER_TOKEN_VAR),
            sock=inherited)
    except (ValueError, OSError) as exc:
        print("could not start the %s listener: %s" % (args.transport, exc),
              file=sys.stderr)
        return 1

    control = _start_control(listener, args, spec)
    listener.start()

    stopping = threading.Event()

    def _handle(signum, _frame):
        print("stopping on signal %d" % signum, file=sys.stderr)
        stopping.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _handle)

    try:
        while not stopping.is_set():
            stopping.wait(0.2)
    finally:
        if control is not None:
            control.shutdown()
            control.server_close()
        listener.shutdown()
    return 0


def _parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--transport", required=True,
                        choices=transport_names())
    parser.add_argument("--name", help="what the panel calls this listener")
    parser.add_argument("--bind-host", default="0.0.0.0")
    parser.add_argument("--bind-port", type=int, required=True)
    parser.add_argument("--relay-url", required=True,
                        help="the team server's agent socket")
    parser.add_argument("--setting", action="append", metavar="KEY=VALUE",
                        help="a transport's own setting, repeatable")
    parser.add_argument("--control-port", type=int, default=0,
                        help="0 picks a free port; the chosen one is printed")
    return parser


def _inherited_socket(transport):
    """The service socket systemd handed over, or None.

    `$LISTEN_PID` is checked as the protocol requires: the variable is
    inherited by grandchildren that were never meant to have the
    descriptor, and using it there would steal the socket from the process
    systemd is waiting on.
    """
    try:
        count = int(os.environ.get("LISTEN_FDS", "0"))
    except ValueError:
        return None
    if count < 1:
        return None
    owner = os.environ.get("LISTEN_PID")
    if owner and owner != str(os.getpid()):
        print("ignoring LISTEN_FDS: it names pid %s, not %d"
              % (owner, os.getpid()), file=sys.stderr)
        return None

    kind = socket.SOCK_STREAM if transport == "smb" else socket.SOCK_DGRAM
    try:
        sock = socket.socket(fileno=_LISTEN_FDS_START)
    except OSError as exc:
        # `$LISTEN_FDS` promised a socket on fd 3 and there is none. Said
        # plainly rather than as a traceback, and fatal rather than
        # falling back to binding: the fallback would try to bind the
        # privileged port this mechanism exists to avoid, and fail with a
        # permission error that sends the reader somewhere else entirely.
        raise _ActivationError(
            "LISTEN_FDS says a socket was handed over on descriptor %d, but "
            "it is not usable: %s. Nothing was bound. Check that the unit "
            "has a matching .socket file, or unset LISTEN_FDS to let this "
            "process bind for itself." % (_LISTEN_FDS_START, exc))
    if sock.type != kind:
        sock.detach()
        raise _ActivationError(
            "the descriptor handed over on %d is a %s socket, and a %s "
            "listener needs %s" % (_LISTEN_FDS_START, _kind_name(sock.type),
                                   transport, _kind_name(kind)))
    print("using the inherited descriptor on %r" % (sock.getsockname(),),
          file=sys.stderr)
    return sock


class _ActivationError(Exception):
    """Socket activation was asked for and cannot be honoured."""


def _kind_name(kind):
    return {socket.SOCK_STREAM: "stream", socket.SOCK_DGRAM: "datagram"} \
        .get(kind, str(kind))


def _start_control(listener, args, spec):
    """Open the control socket, or say there is none, and print which.

    No token means no socket. That is the same shape the rest of this
    branch uses for an unconfigured feature -- the socket policy is inert
    without `operator_port`, the tasking route refuses everyone without a
    listener token -- and it means a listener started by hand or by a
    systemd unit, with no supervisor to talk to, opens no surface at all.
    """
    token = os.environ.get(_CONTROL_TOKEN_VAR)
    if not token:
        print("control-port none", flush=True)
        print("no %s in the environment, so no control socket"
              % _CONTROL_TOKEN_VAR, file=sys.stderr)
        return None

    server = _ControlServer((_CONTROL_HOST, args.control_port),
                            _ControlHandler)
    server.token = token
    server.listener = listener
    server.spec = spec
    server.started_at = time.time()
    threading.Thread(target=server.serve_forever,
                     kwargs={"poll_interval": 0.1}, daemon=True).start()
    print("control-port %d" % server.server_address[1], flush=True)
    return server


class _ControlServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    token = None
    listener = None
    spec = None
    started_at = 0.0


class _ControlHandler(socketserver.BaseRequestHandler):
    """One JSON line in, one JSON line out, and `status` is the only verb.

    Not start, and not stop. A listener cannot start itself, and a verb
    that let it stop itself would be a remote kill switch on the most
    exposed process in the arrangement -- reachable by anything that
    learned one token on one host. Starting and stopping are things the
    supervisor does to a process from outside, with a signal.
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
        listener = self.server.listener
        spec = self.server.spec
        return {
            "name": spec.name,
            "transport": spec.transport,
            "pid": os.getpid(),
            "address": list(listener.address),
            # Reported so a test can hold the claim that this surface is
            # loopback-only. Asserting it by failing to connect from
            # elsewhere needs a second address this host may not have, and
            # a test that skips does not hold anything.
            "control_address": list(self.server.server_address),
            "uptime_seconds": round(time.time() - self.server.started_at, 1),
            "counters": listener.counters(),
        }

    def _reply(self, payload):
        try:
            self.request.sendall(json.dumps(payload).encode() + b"\n")
        except OSError:
            pass


def _same(presented: str, expected: str) -> bool:
    import hmac

    return hmac.compare_digest(presented.encode(), expected.encode())


if __name__ == "__main__":
    sys.exit(main())
