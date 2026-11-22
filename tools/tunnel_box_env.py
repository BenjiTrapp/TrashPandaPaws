#!/usr/bin/env python3
"""The team server side, for a shell session into a *container*.

Why this exists and `tools/tunnel_demo_env.py` was not used: that script
runs its `TunnelEndpoint` in its own process on this machine, so the pty a
shell session opens is a shell on the Mac, with the Mac's tools. The thing
being tried here is the opposite -- an endpoint whose filesystem is not
this one, so that a tool only it has proves which host the operator is
working on.

So this starts the server side only, binds the control socket where a
container can reach it, and prints the one credential an endpoint needs.
The endpoint is started separately, in a container, by the shipped
`software.c2.tunnel_standalone` entry point reading an ordinary
`configs/raccoon.yaml`.

Shell ports still bind 127.0.0.1 -- `ShellFront` refuses anything else,
and that is on the tunnel server's host, which is this one. So
`tools/raccoon_shell.py 127.0.0.1 <port>` attaches from here.
"""

import base64
import os
import pathlib
import signal
import shutil
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from werkzeug.serving import make_server

from software.c2.server import ServerCrypto, create_app
from software.c2.tunnel.keys import PSK_LEN, KeyStore
from software.c2.tunnel.supervisor import TunnelSupervisor, tunnel_server_config

IDENTITY = "parrot-box"
CONTROL_PORT = 19600
SOCKS_FIRST, SOCKS_LAST = 19610, 19620
SHELL_FIRST, SHELL_LAST = 19630, 19640
OPERATOR_PORT = 18555
TOKEN = "werkzeug-im-beacon"


def _raise_keyboard_interrupt(signum, frame):
    raise KeyboardInterrupt


def main() -> int:
    signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)

    work = pathlib.Path(tempfile.mkdtemp(prefix="tunnel-box-"))
    data = work / "data"
    data.mkdir(parents=True)
    transcripts = work / "transcripts"

    config = {"c2": {"tunnel_server": {
        "enabled": True,
        # Not 127.0.0.1, and this is the one difference from the shipped
        # demo that matters: a container reaches this machine over
        # host.docker.internal, which is a real interface and not the
        # loopback. The control socket is Noise_NKpsk0 and unauthenticated
        # dials get nowhere, but it is still a socket on the LAN side of a
        # laptop and that is a deliberate choice for a test, not a default.
        "bind_host": "0.0.0.0",
        "bind_port": CONTROL_PORT,
        "socks_port_first": SOCKS_FIRST,
        "socks_port_last": SOCKS_LAST,
        "shell_port_first": SHELL_FIRST,
        "shell_port_last": SHELL_LAST,
        "shell_transcript_dir": str(transcripts),
    }}}
    block = tunnel_server_config(config)

    supervisor = TunnelSupervisor(block, data, cwd=REPO)
    supervisor.start()
    try:
        store = KeyStore(supervisor.key_store_path())
        psk = os.urandom(PSK_LEN)
        store.register_build(IDENTITY, psk)

        print("IDENTITY=%s" % IDENTITY)
        print("CONTROL_PORT=%d" % CONTROL_PORT)
        print("PSK=%s" % base64.b64encode(psk).decode("ascii"))
        print("PUBLIC_KEY=%s" % base64.b64encode(
            store.static_public()).decode("ascii"))
        print("TRANSCRIPTS=%s" % transcripts)
        sys.stdout.flush()

        app = create_app(ServerCrypto(b"k" * 32), TOKEN, data,
                         server_config=config,
                         operator_port=OPERATOR_PORT,
                         tunnel_supervisor=supervisor)
        server = make_server("127.0.0.1", OPERATOR_PORT, app, threaded=True)
        print("OPERATOR=http://127.0.0.1:%d/  TOKEN=%s"
              % (OPERATOR_PORT, TOKEN))
        sys.stdout.flush()
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        supervisor.stop_all()
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
