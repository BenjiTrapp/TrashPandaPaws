#!/usr/bin/env python3
"""Stand up a C2 with a real beacon checked in, for capturing figures.

Why in-process rather than the shipped launcher: the figures have to show
a fleet, a process list, a netstat and loot, and all of that comes from a
beacon that is actually running. The test suite already starts a real C2
and a real `Beacon` this way, so the GUI being photographed is the GUI,
talking to a beacon that answers for real -- not a mock-up and not a
seeded database.

    python3 tools/demo_env.py --operator-port 18500 --token demo-token

The flags mean what server.py's do: --port is the beacon socket and
--operator-port the GUI and API, which is what a capture opens.

Stays in the foreground until interrupted, printing the beacon id it got
so the capture step can address it. Nothing here is specific to the
machine: the beacon reports this host, which is the point.
"""

import argparse
import base64
import os
import pathlib
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from werkzeug.serving import make_server

from software.c2.beacon import Beacon
from software.c2.server import ServerCrypto, agents, create_app


def random_key() -> bytes:
    """A fresh AES-256-GCM key, minted once and handed to both ends.

    A key mismatch is not reported: the registration is simply never
    accepted and the fleet stays empty. That cost this project an afternoon
    once, so the key is made in one place and the same bytes go to the
    server and, through key_b64, to the beacon. It is bytes, not hex --
    AESGCM takes a buffer.
    """
    return os.urandom(32)


def key_b64(key: bytes) -> str:
    """The form the beacon's `encryption_key` and the server's --key take."""
    return base64.b64encode(key).decode()


def beacon_config(port, key, interval=2):
    return {
        "c2": {
            "beacon_interval_seconds": interval,
            "jitter_percent": 0,
            "encryption_key": key_b64(key),
            "proxy": {"mode": "none"},
            "https": {
                "enabled": True,
                "callback_url": "http://127.0.0.1:%d/api/v1/beacon" % port,
                "verify_ssl": False,
            },
            "dns": {"enabled": False, "domain": "", "resolver": "8.8.8.8"},
        },
    }


class DemoEnv:
    """The C2 on two sockets, as `server.py` runs it.

    `operator_port` is the GUI and the API, what the capture tools open.
    `beacon_port` is the agent socket, the only one the beacon is pointed
    at. 0 for either picks a free port, read back once bound. With
    the two apart the socket policy is live, so the figures show the GUI as
    it is actually reached, not a single-socket arrangement nobody runs.
    """

    def __init__(self, operator_port, token, data_dir=None, beacon_port=0,
                 listener_token=None):
        self.operator_port = operator_port
        self.beacon_port = beacon_port
        self.token = token
        self.listener_token = listener_token
        self.data_dir = pathlib.Path(data_dir or tempfile.mkdtemp())
        self.key = random_key()
        self.beacon = None
        self.beacon_id = None

    def start_server(self):
        operator = make_server("127.0.0.1", self.operator_port, None,
                               threaded=True)
        agent = make_server("127.0.0.1", self.beacon_port, None, threaded=True)
        self.operator_port = operator.server_port
        self.beacon_port = agent.server_port
        self.app = create_app(
            ServerCrypto(self.key), self.token, self.data_dir,
            server_config={"host": "127.0.0.1", "port": self.beacon_port,
                           "operator_host": "127.0.0.1",
                           "operator_port": self.operator_port},
            operator_port=self.operator_port,
            listener_token=self.listener_token)
        self.servers = (operator, agent)
        for srv in self.servers:
            srv.app = self.app
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        self._wait(self._answers, "the C2 to accept connections")

    def _answers(self):
        import urllib.error
        import urllib.request
        try:
            urllib.request.urlopen(
                "http://127.0.0.1:%d/api/agents" % self.operator_port,
                timeout=2)
        except urllib.error.HTTPError:
            return True          # 401 is an answer
        except Exception:
            return False
        return True

    def start_beacon(self):
        self.beacon = Beacon(beacon_config(self.beacon_port, self.key))
        self.beacon.start()
        self._wait(lambda: bool(agents), "the beacon to register")
        record = list(agents.values())[0]
        # The addressable name, not the raw hash in the record: tasking
        # takes the former, and confusing the two is a mistake this
        # project has already made against a live beacon.
        self.beacon_id = record.get("agent_id") or record.get("id")

    @staticmethod
    def _wait(predicate, what, timeout=20.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return
            time.sleep(0.2)
        raise RuntimeError("timed out waiting for %s" % what)


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--operator-port", type=int, default=18500,
                        help="operator socket: the GUI and the API")
    parser.add_argument("--port", type=int, default=0,
                        help="beacon socket (default: any free port)")
    parser.add_argument("--token", default="demo-operator-token")
    parser.add_argument("--data-dir")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    env = DemoEnv(args.operator_port, args.token, args.data_dir, args.port)
    env.start_server()
    print("c2 http://127.0.0.1:%d  token %s" % (env.operator_port, env.token))
    print("beacons http://127.0.0.1:%d" % env.beacon_port)
    env.start_beacon()
    print("beacon %s" % env.beacon_id)
    print("data %s" % env.data_dir)
    sys.stdout.flush()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
