#!/usr/bin/env python3
"""Stand up the shell session feature for real, so the panel can be photographed.

Not a mock-up: a real tunnel-server child process, a real Noise handshake
from a real `TunnelEndpoint`, a real shell front on a loopback port, and
the shipped Flask app reading the real supervisor. The tunnel panel being
captured is the panel, fed by an endpoint that actually connected -- the
only way to settle a rendering question this repository has no JavaScript
runner to answer.

    software/.venv/bin/python tools/tunnel_demo_env.py \
        --operator-port 18544 --token demo-operator-token

The one thing done by hand is registering the build's PSK in the key
store, which the generator would otherwise write -- there is no artifact
here to carry one. Nothing else is specific to the machine: the repository
root is found from this file, the tunnel server binds a free loopback
port, and the shell range is a fixed window clear of the SOCKS pool. The
flags mean what `demo_env.py`'s do: `--operator-port` is the GUI and API,
which is what a capture opens, and `--token` is the operator token it
authenticates with.

The default token is a well-known constant, `demo-operator-token`, the
same `demo_env.py` ships. That is acceptable precisely because the
operator socket is loopback-only: `make_server` below binds the GUI to
127.0.0.1 and a token readable in this file guards nothing an
attacker on the host could not already reach. A deployment that is not a
local capture rig passes its own `--token`.

`--endpoints` runs more than one build, so the panel can be seen with a
stack of cards, and `--identity` fixes the build name, so a long one can
be used to see whether it wraps rather than widening the panel. Both have
defaults that reproduce the single-endpoint capture the plan asks for.

Stays in the foreground until interrupted, printing the operator URL, each
identity, its assigned shell port and the transcript directory. It stops
the endpoints and the supervisor, and removes its temporary directory, on
the way out -- for an interrupt (Ctrl-C) and for a `kill`: a tool whose
whole job is to be started and stopped by hand installs a SIGTERM handler
so the default terminate-without-unwinding does not leave a tunnel server
behind holding the implant-facing port.
"""

import argparse
import base64
import os
import pathlib
import shutil
import signal
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from werkzeug.serving import make_server

from software.c2.beacon import TunnelEndpoint
from software.c2.server import ServerCrypto, create_app
from software.c2.tunnel.keys import PSK_LEN, KeyStore
from software.c2.tunnel.supervisor import TunnelSupervisor, tunnel_server_config

# The repository root, discovered from this file rather than written down,
# so the supervisor can spawn `-m software.c2.tunnel` from anywhere and the
# script moves with the checkout.
REPO = str(pathlib.Path(__file__).resolve().parents[1])

# The shell window sits a hundred ports above the SOCKS pool and does not
# touch it: `tunnel_server_config` and `TunnelServer.__init__` both refuse
# an overlap, and these defaults are chosen to clear that refusal. Fixed
# rather than probed, because `demo_config` is the seam a test reads and a
# probe would make it answer differently on each call.
_SOCKS_FIRST, _SOCKS_LAST = 19050, 19059
_SHELL_FIRST, _SHELL_LAST = 19150, 19159


def _free_port() -> int:
    """A loopback port that was free a moment ago.

    The implant-facing port has no reason to be fixed here -- only the
    endpoints this script starts itself dial it, and they are handed the
    number after it is bound -- so a concrete free one is picked rather
    than hardcoding a port that may already be in use.
    """
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def demo_config(bind_port, socks_first, socks_last, shell_first, shell_last,
                transcript_dir):
    """The `{"c2": {"tunnel_server": ...}}` block this environment runs.

    The part a test can check without starting a process: passed through
    `tunnel_server_config` it must validate and come back with the same
    ports, a shell range and a transcript directory, and its shell range
    must not overlap the SOCKS range `TunnelServer` refuses an overlap
    with. Built here in one place so the test judges exactly what `main`
    ships.
    """
    return {"c2": {"tunnel_server": {
        "enabled": True,
        "bind_host": "127.0.0.1",
        "bind_port": bind_port,
        "socks_port_first": socks_first,
        "socks_port_last": socks_last,
        "shell_port_first": shell_first,
        "shell_port_last": shell_last,
        "shell_transcript_dir": transcript_dir,
    }}}


def default_demo_config(bind_port, transcript_dir):
    """`demo_config` with the ranges this script actually ships.

    The seam a test validates: `demo_config` alone is parametric, so a test
    that passed it literals would leave `_SOCKS_FIRST/_LAST` and
    `_SHELL_FIRST/_LAST` unread and would stay green if someone edited the
    shipped constants to overlap. This reads them, so the test is checking
    what `main` runs and the overlap refusal is exercised against the real
    defaults. `main` calls this too, so there is one spelling of the ports.
    """
    return demo_config(bind_port, _SOCKS_FIRST, _SOCKS_LAST,
                       _SHELL_FIRST, _SHELL_LAST, transcript_dir)


def _register_endpoint(supervisor, bind_port, identity):
    """Mint a build's PSK, register it by hand, and dial a real endpoint.

    Returns the `TunnelEndpoint`, already running on its own thread. The
    PSK is registered in the store the generator would otherwise write to:
    there is no artifact here to carry one, so the one credential the Noise
    handshake needs is made and filed in the one place the child reads it.
    """
    store = KeyStore(supervisor.key_store_path())
    psk = os.urandom(PSK_LEN)
    store.register_build(identity, psk)
    public = base64.b64encode(store.static_public()).decode("ascii")

    endpoint = TunnelEndpoint({"c2": {
        "tunnel": {
            "enabled": True,
            "server": "127.0.0.1",
            "port": bind_port,
            "public_key": public,
            "psk": base64.b64encode(psk).decode("ascii"),
            "identity": identity,
            "keepalive_seconds": 30,
        },
        "proxy": {"mode": "none"},
    }})
    threading.Thread(target=endpoint.run,
                     name="endpoint-%s" % identity, daemon=True).start()
    return endpoint


def _wait_connected(supervisor, count):
    """Wait for `count` endpoints to connect; say so on stderr if they don't.

    Returns the number connected. A silent return after the timeout would
    leave the script printing `shell None` and carrying on as though the
    demo were what it claims, so a shortfall is named on stderr rather than
    left for the operator to notice in the panel.
    """
    for _ in range(80):
        rows = supervisor.status().get("endpoints") or []
        connected = [r for r in rows if r.get("state") == "connected"]
        if len(connected) >= count:
            return len(connected)
        time.sleep(0.25)
    rows = supervisor.status().get("endpoints") or []
    connected = [r for r in rows if r.get("state") == "connected"]
    if len(connected) < count:
        print("warning: only %d of %d endpoints connected within 20s; the "
              "panel will show the rest as not connected"
              % (len(connected), count), file=sys.stderr)
    return len(connected)


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--operator-port", type=int, default=18544,
                        help="operator socket: the GUI and the API")
    parser.add_argument("--token", default="demo-operator-token")
    parser.add_argument("--endpoints", type=int, default=1,
                        help="how many builds to connect, so the panel can "
                             "be seen with a stack of cards")
    parser.add_argument("--identity",
                        help="fix the first build's identity, so a long one "
                             "can be used to see whether it wraps")
    return parser


def _raise_keyboard_interrupt(signum, frame):
    # SIGTERM's default handler terminates the process without unwinding,
    # so `finally` never runs and the tunnel child is orphaned holding the
    # implant-facing port. Turning it into the same exception Ctrl-C raises
    # routes a `kill` through the one cleanup path below.
    raise KeyboardInterrupt


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)

    work = pathlib.Path(tempfile.mkdtemp(prefix="tunnel-demo-"))
    data = work / "data"
    data.mkdir(parents=True)
    transcripts = work / "transcripts"

    bind_port = _free_port()
    config = default_demo_config(bind_port, str(transcripts))
    block = tunnel_server_config(config)

    supervisor = TunnelSupervisor(block, data, cwd=REPO)
    endpoints = []
    # The child exists from here on, so cleanup has to cover everything
    # after it: an exception in `_register_endpoint`, the up-to-20s wait,
    # `create_app` or `make_server` (a busy --operator-port raises OSError
    # here) must not leave the tunnel server behind. The `try` opens
    # immediately after `start`, not after `serve_forever`.
    supervisor.start()
    try:
        identities = []
        for index in range(max(1, args.endpoints)):
            if index == 0 and args.identity:
                identity = args.identity
            else:
                identity = "tun-" + os.urandom(6).hex()
            identities.append(identity)
            endpoints.append(_register_endpoint(supervisor, bind_port,
                                                 identity))

        _wait_connected(supervisor, len(endpoints))

        app = create_app(ServerCrypto(b"k" * 32), args.token, data,
                         server_config=config,
                         operator_port=args.operator_port,
                         tunnel_supervisor=supervisor)
        server = make_server("127.0.0.1", args.operator_port, app,
                             threaded=True)

        print("operator http://127.0.0.1:%d/  token %s"
              % (args.operator_port, args.token))
        rows = {r.get("identity"): r
                for r in (supervisor.status().get("endpoints") or [])}
        for identity in identities:
            row = rows.get(identity) or {}
            print("endpoint %s  shell %s" % (identity, row.get("shell_port")))
        print("transcripts %s" % transcripts)
        sys.stdout.flush()

        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for endpoint in endpoints:
            endpoint.stop()
        # `stop_all` is the documented shutdown path and never raises: it
        # tears the child down whether it is running, already dead, or was
        # never started. `stop()` would raise SupervisorError on a child
        # that has already died, which an `except: pass` would then have to
        # swallow -- and swallowing is how a real failure to stop would go
        # unseen.
        supervisor.stop_all()
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
