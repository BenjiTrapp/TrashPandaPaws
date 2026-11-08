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
from software.c2.listeners.registry import ListenerSpec
from software.c2.listeners.supervisor import Supervisor
from tools import listener_lab as lab


def _free_port() -> int:
    """A port that was free a moment ago.

    A listener in a config file needs a fixed port because the beacon is
    configured with one, so `bind_port: 0` is refused there -- a local
    environment picks a concrete free one instead.
    """
    import socket as _socket

    probe = _socket.socket()
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


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
        self.listeners = {}
        self.listener_ports = {}
        self.beacons = {}
        self.supervisor = None
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
            listener_token=self.listener_token,
            supervisor=self)
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

    # ── listeners in front of the agent socket ──

    def start_listeners(self, transports):
        """Stand up one listener per transport, as separate processes.

        Through the supervisor, which is how a deployment does it: a
        listener is its own process so that a fault in one protocol parser
        costs one transport instead of the fleet and the operator
        interface together. Running them as threads here would be simpler
        and would test something this project does not ship.

        A side effect worth having: the 📡 panel lists exactly these and
        can stop and start them, so the panel can be used rather than only
        looked at.
        """
        if self.listener_token is None:
            raise RuntimeError(
                "the server was built without a listener token, so its "
                "tasking route refuses every listener")
        specs = []
        for transport in transports:
            settings = {"zone": lab.DNS_ZONE} if transport == "dns" else {}
            port = _free_port()
            specs.append(ListenerSpec(
                name="%s-%d" % (transport, port), transport=transport,
                enabled=True, bind_host="127.0.0.1", bind_port=port,
                relay_url=lab.relay_url_for(transport, self.beacon_port),
                settings=settings))
            self.listener_ports[transport] = port
            if transport == "dns":
                # Process-wide and it has to outlive this call: the beacons
                # started below ask their resolver on this port for as long
                # as the environment runs.
                lab.set_resolver_port(port)
        self.supervisor = Supervisor(specs, listener_token=self.listener_token)
        for spec in specs:
            self.listeners[spec.transport] = self.supervisor.start(spec.name)
        return self.listeners

    def start_beacon_over(self, transport):
        """Start a beacon that speaks only `transport`, and name its agent.

        Returns the agent name the panel shows, so a caller can print
        something you can act on rather than "started".
        """
        address = ("127.0.0.1", self.listener_ports[transport])
        beacon = Beacon(lab.beacon_config_for(transport, self.key, address))
        # Every beacon on one host computes the same implant id --
        # `sha256("<hostname>:<machine>")[:16]`, plus the eth0 MAC where
        # that file exists -- so without this the three beacons here would
        # register as one agent and share one task queue. That is a real
        # property of the client and not an artefact of running them in
        # one process; it is recorded in docs/AGENT.md. The suffix is
        # stable, so restarting this environment reuses the same agents
        # rather than filling the panel with ghosts.
        beacon._implant_id = "%s-%s" % (beacon._implant_id, transport)
        before = set(agents)
        if lab.is_tasking_only(transport):
            # Nothing registers over this transport, so the identity has to
            # exist before the beacon speaks. A beacon reached only this
            # way can be commanded and will never report -- the panel has
            # to say that, and so does this environment.
            name = lab.register_out_of_band(self.beacon_port, self.key,
                                            beacon._implant_id)
            beacon.start()
        else:
            beacon.start()
            self._wait(lambda: set(agents) - before,
                       "the beacon to register over %s" % transport)
            name = (set(agents) - before).pop()
        self.beacons[transport] = beacon
        return name

    # ── the panel's view of this environment ──
    #
    # `create_app` is built before the listeners exist, so DemoEnv stands
    # in for the supervisor and forwards once there is one. Without this
    # the panel would have been given None at startup and would report
    # "none configured" for the whole run.

    @property
    def managed(self):
        return self.supervisor.managed if self.supervisor else False

    def status(self):
        return self.supervisor.status() if self.supervisor else []

    def start(self, name):
        return self._delegate("start", name)

    def stop(self, name):
        return self._delegate("stop", name)

    def _delegate(self, action, name):
        from software.c2.listeners.errors import SupervisorError

        if self.supervisor is None:
            raise SupervisorError("no listeners are configured in this "
                                  "environment; start it with "
                                  "--with-listeners")
        return getattr(self.supervisor, action)(name)

    def stop_all(self):
        if self.supervisor is not None:
            self.supervisor.stop_all()

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
    parser.add_argument("--with-listeners", action="store_true",
                        help="also run a listener per transport, each with "
                             "a beacon that speaks only that one")
    parser.add_argument("--listener-token", default=lab.LISTENER_TOKEN,
                        help="shared secret between the server and its "
                             "listeners")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    env = DemoEnv(args.operator_port, args.token, args.data_dir, args.port,
                  listener_token=args.listener_token
                  if args.with_listeners else None)
    env.start_server()
    print("c2 http://127.0.0.1:%d  token %s" % (env.operator_port, env.token))
    print("beacons http://127.0.0.1:%d" % env.beacon_port)
    env.start_beacon()
    print("beacon %s  https" % env.beacon_id)

    if args.with_listeners:
        env.start_listeners(lab.available_transports())
        for transport in lab.available_transports():
            name = env.start_beacon_over(transport)
            note = ""
            if lab.is_tasking_only(transport):
                note = ("  tasking only: it will never report a result, "
                        "and each task is delivered once")
            print("beacon %s  %s via 127.0.0.1:%d  listener pid %s%s"
                  % (name, transport, env.listener_ports[transport],
                     env.listeners[transport].get("pid"), note))
        print("listener token %s" % args.listener_token)
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
