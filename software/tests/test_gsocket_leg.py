#!/usr/bin/env python3
"""The beacon's fifth leg: a `gs-netcat` forward out to the team server.

The four legs an implant already has share one precondition: the team
server has to be reachable at an address the implant can name. When that
infrastructure is blocked, all four fail together. This leg's precondition
is different -- a child process dials *out* to the Global Socket Relay
Network and the team server's carrier does the same -- so these tests are
about the child, the latch that decides when it runs, and the record the
leg leaves when it cannot.

What these tests are careful about.

**Nothing here touches the Global Socket Relay Network.** Every process
spawned below is a stand-in, and every byte moved is moved over loopback.
A suite that needed the GSRN would send traffic to a third-party relay
from whatever machine runs it, which is the one side effect this feature's
constraints call out. Three stand-ins appear, and the split is deliberate:

  * `software/tests/data/fake_gs_netcat.sh`, the fixture Task 4 ships, is
    used wherever what matters is the *process*: the argv it was spawned
    with, the environment it was handed, its pid, its death, its restart.
    In the implant's client shape (`-w -p <port>`) it binds the forward's
    port and goes quiet, which is exactly enough for a cycle to find the
    leg ready.
  * `_never_binds`, written into each test's own directory, stays up and
    binds nothing. It is the one shape the shipped fixture cannot take,
    and it is what a `gs-netcat` looks like between joining the relay
    network and having a forward: the case `ready_timeout_seconds` exists
    for.
  * `_forwarder`, likewise test-local, binds the forward and actually
    pipes it to a port given in its environment. The shipped fixture
    deliberately does not forward -- it models what a carrier can
    *observe* about its child -- and a full cycle needs bytes to move.

**The bind address is settled elsewhere, and these stand-ins deliberately
differ from it.** A real `gs-netcat -p` forward binds **every interface** —
measured in upstream source at v1.4.43 and cited above `GsocketCarrier.argv`
in `software/c2/gsocket/carrier.py`. The stand-ins here bind loopback anyway,
because a test suite must not open a port to the network of whatever machine
runs it; what is under test is the leg's behaviour against a forward it can
reach on `127.0.0.1`, which is the address the beacon itself uses. So nothing
in this file is evidence about the real binary's bind address, in either
direction.

**The latch is the operator's decision, so it is tested as behaviour.**
The carrier does not run at beacon start. It starts the first time a cycle
ends with no upstream leg having delivered, and then stays up for the life
of the process. So a healthy implant holds no GSRN connection at all,
which is the lazy half, and a second outage costs no readiness wait, which
is the warm half. Both halves have a test, and the first asserts that no
child was spawned at all rather than that one was spawned and unused.

**The first cycle of an outage records `carrier_failed`, deliberately.**
The leg is tried where it sits in the chain, which is before the point
where `_beacon_loop` concludes that nothing delivered -- so on the cycle
that *discovers* the outage there is no carrier yet, and the leg says so.
Recording `not_attempted` instead would tell an operator "GSOCKET: not
tried" about the one leg that is being brought up for them, which is the
mistake the SMB and QUIC legs each shipped once already.

**The copies are pinned against their originals.** `beacon.py` is served
to a target as source text and may import nothing from this repository, so
it carries its own binary check and its own argv. Two tests compare them
against `software/c2/gsocket/carrier.py` word for word, the way
`test_dns_rescue.py` holds the rescue format's copy. One reason string
reads oddly from the implant's side; it is a known, parked review finding
and it is copied unchanged, because a divergence improvised here would
break the comparison and hide the parked item.

**No orphans.** Every beacon built here is torn down through
`Beacon.stop`, which takes the carrier's child with it, and the tests that
kill a child wait for the pid to be gone.
"""

import base64
import hashlib
import logging
import os
import pathlib
import shutil
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from software.c2 import beacon as beacon_mod
from software.c2 import server as server_mod
from software.c2.beacon import Beacon, beacon_config_from_fallback
from software.c2.gsocket import carrier as carrier_mod
from software.c2.gsocket.config import LEG_DEFAULTS

FAKE_GS_NETCAT = (pathlib.Path(__file__).resolve().parent / "data"
                  / "fake_gs_netcat.sh")

# A `gs-netcat` that is up but whose forward is not. The shape the shipped
# fixture cannot take, because that one binds `-p` in the client shape on
# purpose.
_NEVER_BINDS = """#!/usr/bin/env python3
import time

# No socket of any kind: a gs-netcat between joining the relay network
# and having a forward is a process that exists and listens on nothing.
while True:
    time.sleep(3600)
"""

# A forward that forwards. `-p` is bound on loopback and piped to
# LEG_TEST_TARGET_PORT, which is where the team server's beacon socket is
# in these tests. The pipe is per-connection and both directions are
# pumped, because an HTTP exchange needs both.
_FORWARDER = """#!/usr/bin/env python3
import os, socket, sys, threading

port = None
args = sys.argv[1:]
for index, value in enumerate(args):
    if value == "-p" and index + 1 < len(args):
        port = int(args[index + 1])
if port is None:
    sys.exit(64)
target = int(os.environ["LEG_TEST_TARGET_PORT"])


def pump(src, dst):
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass


def serve(near):
    far = socket.socket()
    try:
        far.connect(("127.0.0.1", target))
    except OSError:
        near.close()
        far.close()
        return
    threading.Thread(target=pump, args=(near, far), daemon=True).start()
    threading.Thread(target=pump, args=(far, near), daemon=True).start()


listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", port))
listener.listen(16)
while True:
    conn, _ = listener.accept()
    serve(conn)
"""


def _free_port() -> int:
    """A port that was free a moment ago.

    Racy by nature, which is why a configuration file is given a fixed
    `local_port` and a test takes whatever nobody is using right now.
    """
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def _alive(pid: int) -> bool:
    """Whether `pid` still exists, without reaping or signalling it."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _accepts(port: int, timeout: float = 5.0) -> bool:
    """Whether something accepts on loopback `port` within `timeout`."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        sock = socket.socket()
        sock.settimeout(0.5)
        try:
            sock.connect(("127.0.0.1", port))
            return True
        except OSError:
            time.sleep(0.05)
        finally:
            sock.close()
    return False


class _TeamServer:
    """The real team server app, on a real loopback port.

    `create_app` and `ServerCrypto` as shipped: the point of the full-cycle
    test is that the beacon's envelope and the server's are the same
    envelope, so neither side may be stood in for.
    """

    def __init__(self):
        self.key = os.urandom(32)
        self.crypto = server_mod.ServerCrypto(self.key)

    def start(self):
        from werkzeug.serving import make_server

        # Werkzeug logs a line per request to stderr, and this fixture
        # serves a few hundred across the file. The suite's output is
        # worth more than the access log of a server that is torn down
        # thirty lines later.
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        self._saved = (dict(server_mod.agents), dict(server_mod.task_queues),
                       dict(server_mod.results), dict(server_mod.history))
        self.data_dir = pathlib.Path(tempfile.mkdtemp(prefix="raccoon-leg-srv-"))
        self._server = make_server("127.0.0.1", 0, None, threaded=True)
        self.port = self._server.server_port
        self._server.app = server_mod.create_app(
            self.crypto, "operator-token", self.data_dir)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._thread.join(timeout=5)
        agents, queues, results, history = self._saved
        for live, saved in ((server_mod.agents, agents),
                            (server_mod.task_queues, queues),
                            (server_mod.results, results),
                            (server_mod.history, history)):
            live.clear()
            live.update(saved)
        shutil.rmtree(self.data_dir, ignore_errors=True)

    @property
    def callback_url(self) -> str:
        return "http://127.0.0.1:%d/api/v1/beacon" % self.port

    def agent_of(self, implant_id: str):
        for name, info in server_mod.agents.items():
            if info.get("id") == implant_id:
                return name
        return None


class LegFixture(unittest.TestCase):
    """A beacon with a gsocket leg over a stand-in, and no orphans after."""

    # How long a reading waits for the stand-in's child to record. An
    # attribute rather than a literal so the test that pins the waiting
    # rule can shorten it instead of sleeping for the real deadline.
    _RECORD_WAIT_SECONDS = 30.0

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="raccoon-gsocket-leg-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.addCleanup(self._stop_beacons)
        self._beacons = []

        # The secret is a file and never a value on a command line, so the
        # leg needs a path that exists and nothing more.
        self.secret_file = os.path.join(self.root, "gsocket-secret")
        with open(self.secret_file, "w") as handle:
            handle.write("Th1s-Is-N0t-A-Real-Secret\n")
        os.chmod(self.secret_file, 0o600)

        # Copied rather than referenced: one test rewrites the binary, and
        # a test that edited the file in the repository would be a test
        # that broke the next one.
        self.binary = os.path.join(self.root, "gs-netcat")
        shutil.copy(FAKE_GS_NETCAT, self.binary)
        os.chmod(self.binary, 0o755)

        self.argv_file = os.path.join(self.root, "argv.txt")
        self.env_file = os.path.join(self.root, "env.txt")
        self.pid_file = os.path.join(self.root, "pid.txt")
        recording = mock.patch.dict(os.environ, {
            "FAKE_GS_NETCAT_ARGV_FILE": self.argv_file,
            "FAKE_GS_NETCAT_ENV_FILE": self.env_file,
            "FAKE_GS_NETCAT_PID_FILE": self.pid_file,
        })
        recording.start()
        self.addCleanup(recording.stop)

    # ── the beacons ──

    def a_beacon(self, gsocket=None, key=b"\x11" * 32, **transports) -> Beacon:
        """A beacon with every leg off but what a test turns on."""
        block = {
            "enabled": True,
            "secret_file": self.secret_file,
            "binary_path": self.binary,
            "local_port": _free_port(),
        }
        if gsocket is not None:
            block.update(gsocket)
        config = {"c2": {
            "beacon_interval_seconds": 300,
            "jitter_percent": 0,
            "encryption_key": base64.b64encode(key).decode(),
            "proxy": {"mode": "none"},
            "https": {"enabled": False},
            "dns": {"enabled": False},
            "smb": {"enabled": False},
            "quic": {"enabled": False},
            "gsocket": block,
        }}
        config["c2"].update(transports)
        beacon = Beacon(config)
        self._beacons.append(beacon)
        return beacon

    def a_raw_beacon(self, block) -> Beacon:
        """A beacon whose gsocket block is exactly `block`.

        Used where what is under test is the reading of the block itself,
        so the fixture must not fill anything in.
        """
        config = {"c2": {
            "encryption_key": base64.b64encode(b"\x11" * 32).decode(),
            "https": {"enabled": False},
            "gsocket": block,
        }}
        beacon = Beacon(config)
        self._beacons.append(beacon)
        return beacon

    def run_cycles(self, beacon: Beacon, count: int = 1) -> float:
        """Run `count` real passes of `_beacon_loop`; return the seconds taken.

        The loop itself is not stood in for: only the two sleeps at the
        bottom of it are, which is how `test_c2_hardening` drives one
        check-in. A failing HTTPS *registration* also sleeps through
        `_backoff_sleep`, so a test that wants N cycles either leaves
        HTTPS off or points it at a server that answers.
        """
        seen = {"n": 0}

        def sleep(*_args, **_kwargs):
            seen["n"] += 1
            if seen["n"] >= count:
                beacon._running = False

        beacon._running = True
        started = time.monotonic()
        with mock.patch.object(beacon, "_jittered_sleep", side_effect=sleep), \
                mock.patch.object(beacon, "_backoff_sleep", side_effect=sleep):
            beacon._beacon_loop()
        return time.monotonic() - started

    def _stop_beacons(self):
        for beacon in self._beacons:
            beacon._running = False
            beacon._gsocket_stop()

    # ── the stand-ins ──

    def _script(self, name: str, body: str) -> str:
        path = os.path.join(self.root, name)
        with open(path, "w") as handle:
            handle.write(body)
        os.chmod(path, 0o755)
        return path

    def never_binds(self) -> str:
        return self._script("never-binds", _NEVER_BINDS)

    def forwarder(self, target_port: int) -> str:
        env = mock.patch.dict(os.environ,
                              {"LEG_TEST_TARGET_PORT": str(target_port)})
        env.start()
        self.addCleanup(env.stop)
        return self._script("forwarder", _FORWARDER)

    def team_server(self) -> _TeamServer:
        server = _TeamServer()
        server.start()
        self.addCleanup(server.stop)
        return server

    # ── readings ──

    def recorded_argv(self):
        """The argv the stand-in recorded, once it has recorded one.

        Waited for, because `_gsocket_start` returns as soon as the child
        is spawned: the exec that writes this file happens on the child's
        own time.
        """
        with open(self._recorded(self.argv_file)) as handle:
            return [line.rstrip("\n") for line in handle]

    def recorded_environment(self) -> str:
        with open(self._recorded(self.env_file)) as handle:
            return handle.read()

    def _recorded(self, path: str) -> str:
        # Existence is not the finish line, and that is the whole point of
        # this helper. The stand-in writes with `env > "$FILE"`, and the
        # shell's redirection *creates and truncates* the file before `env`
        # has produced a byte -- so a reader that stopped at
        # `os.path.exists` could read an empty file and assert happily
        # against "". Waiting for a size is what makes the reading honest.
        #
        # The deadline is generous rather than tight: the previous five
        # seconds were measured failing on a loaded machine (a full suite
        # beside four other processes), and the only cost of a long
        # deadline is how long a genuine breakage takes to be reported,
        # while the cost of a short one is a test that fails for a reason
        # that has nothing to do with what it asserts.
        deadline = time.monotonic() + self._RECORD_WAIT_SECONDS
        while time.monotonic() < deadline:
            try:
                if os.path.getsize(path) > 0:
                    return path
            except OSError:
                pass
            time.sleep(0.05)
        raise AssertionError(
            "the stand-in recorded nothing at %s within %.1fs (exists: %s)"
            % (path, self._RECORD_WAIT_SECONDS, os.path.exists(path)))

    def child_pid(self, beacon: Beacon) -> int:
        proc = beacon._gsocket_proc
        self.assertIsNotNone(proc, "no carrier child was spawned")
        return proc.pid

    def assertGsocketLeg(self, beacon: Beacon, klass: str):
        self.assertEqual(beacon._leg_status.get("gsocket"),
                         (beacon_mod._RESCUE_CLASSES[klass], 0),
                         "the gsocket leg did not record %s" % klass)


class TestTheChain(LegFixture):
    """Where the leg sits, and what it is allowed to mean."""

    def test_gsocket_is_last_in_the_chain(self):
        self.assertEqual(beacon_mod._FALLBACK_TRANSPORTS,
                         ("https", "dns", "smb", "quic", "gsocket"))

    def test_gsocket_is_an_upstream_leg(self):
        # bidirectional, so it may re-arm the rescue latch
        self.assertIn("gsocket", beacon_mod._RESCUE_UPSTREAM)

    def test_the_config_block_reaches_the_beacon(self):
        # `beacon_config_from_fallback` loops over `_FALLBACK_TRANSPORTS`,
        # so the plumbing follows the chain -- but it followed nothing for
        # SMB and QUIC for a year, which is why this is asserted and not
        # assumed.
        block = {"enabled": True, "secret_file": "/tmp/s",
                 "binary_path": "/usr/bin/gs-netcat"}
        built = beacon_config_from_fallback(
            {"encryption_key": "k", "fallback": {"enabled": True,
                                                 "gsocket": block}})
        self.assertEqual(built["c2"]["gsocket"], block)

    def test_the_defaults_are_the_ones_the_config_module_publishes(self):
        # beacon.py may not import `config.LEG_DEFAULTS`, so it carries
        # the five numbers as a copy. Drift is a forward that lands on the
        # wrong port, or a leg that is never ready and nothing saying why.
        beacon = self.a_raw_beacon({"enabled": True,
                                    "secret_file": self.secret_file,
                                    "binary_path": self.binary})
        for key, value in LEG_DEFAULTS.items():
            with self.subTest(setting=key):
                self.assertEqual(getattr(beacon, "gsocket_" + key), value)

    def test_the_two_argv_shapes_agree(self):
        # `implant_argv` exists in `carrier.py` so that this copy has
        # something to be compared against; nothing imports it here.
        beacon = self.a_beacon()
        self.assertEqual(
            beacon._gsocket_argv(),
            carrier_mod.implant_argv(self.binary, self.secret_file,
                                     beacon.gsocket_local_port))

    def test_an_unusable_block_disables_the_leg_and_says_why(self):
        # No third validator: `config.validate_leg` lives in a module
        # beacon.py cannot import, and the other four transports all read
        # an unusable block as "off". What is not allowed is reading it as
        # "off" in silence.
        cases = {
            "no secret_file": {"enabled": True, "secret_file": "",
                               "binary_path": self.binary},
            "a local_port that is not a port": {
                "enabled": True, "secret_file": self.secret_file,
                "binary_path": self.binary, "local_port": "sixteen"},
            "a local_port out of range": {
                "enabled": True, "secret_file": self.secret_file,
                "binary_path": self.binary, "local_port": 70000},
            "a scheme that is not http": {
                "enabled": True, "secret_file": self.secret_file,
                "binary_path": self.binary, "scheme": "gopher"},
        }
        for label, block in cases.items():
            with self.subTest(block=label):
                with self.assertLogs("raccoon.c2", level="WARNING") as caught:
                    beacon = self.a_raw_beacon(block)
                self.assertFalse(beacon.gsocket_enabled)
                self.assertEqual(len(caught.records), 1, caught.output)
                self.assertIn("gsocket", caught.output[0].lower())

    def test_an_enabled_that_is_not_a_bool_leaves_the_leg_off(self):
        # `bool("false")` is True, and YAML does not unquote a quoted
        # scalar, so this read `enabled: "false"` as *enabled*: a file
        # that says false dialling a third-party relay network, in the
        # one leg where that is what being enabled means. The team
        # server's `config.validate_leg` refuses such a value by name;
        # here a raised exception would cost the whole beacon, so the leg
        # is off and says why once -- which is how the other unusable
        # blocks are treated two tests up.
        for bad in ("false", "true", "no", "off", 1, 0, None, []):
            with self.subTest(enabled=bad):
                with self.assertLogs("raccoon.c2", level="WARNING") as caught:
                    beacon = self.a_raw_beacon(
                        {"enabled": bad, "secret_file": self.secret_file,
                         "binary_path": self.binary})
                self.assertIs(beacon.gsocket_enabled, False)
                self.assertEqual(len(caught.records), 1, caught.output)
                self.assertIn("enabled", caught.output[0])
                self.assertIn(repr(bad), caught.output[0])

    def test_an_absent_block_is_simply_off(self):
        config = {"c2": {"encryption_key": base64.b64encode(b"\x11" * 32)
                         .decode(), "https": {"enabled": False}}}
        beacon = Beacon(config)
        self._beacons.append(beacon)
        self.assertFalse(beacon.gsocket_enabled)


class TestTheLatch(LegFixture):
    """Lazy, then warm: when the child runs and when it does not."""

    def test_the_carrier_does_not_run_while_https_delivers(self):
        # The lazy half of the latch: no child process at all. A healthy
        # implant holds no GSRN connection, which is the whole reason the
        # carrier is not started at beacon start.
        server = self.team_server()
        beacon = self.a_beacon(key=server.key,
                               https={"enabled": True,
                                      "callback_url": server.callback_url})
        self.run_cycles(beacon, 2)

        self.assertIsNone(beacon._gsocket_proc)
        self.assertFalse(os.path.exists(self.argv_file),
                         "a gs-netcat was spawned while HTTPS was working")
        self.assertNotIn("gsocket", beacon._leg_status)
        self.assertIsNotNone(server.agent_of(beacon._implant_id),
                             "HTTPS never delivered, so this proves nothing")

    def test_the_carrier_starts_when_no_upstream_leg_delivered(self):
        beacon = self.a_beacon()
        self.run_cycles(beacon, 1)

        pid = self.child_pid(beacon)
        self.assertTrue(_alive(pid))
        self.assertTrue(_accepts(beacon.gsocket_local_port),
                        "the forward never came up")
        # The first cycle of an outage is the cycle that discovers it, and
        # the leg sits ahead of the point where that is concluded. So the
        # carrier it brings up was not there when the leg was tried, and
        # the record says so rather than claiming the leg was not tried.
        self.assertGsocketLeg(beacon, "carrier_failed")

    def test_the_carrier_stays_up_once_started(self):
        # The warm half: the second outage costs no readiness wait, which
        # is only true if the child from the first one is still there.
        server = self.team_server()
        beacon = self.a_beacon(gsocket={"binary_path":
                                        self.forwarder(server.port)},
                               key=server.key)
        self.run_cycles(beacon, 2)
        pid = self.child_pid(beacon)
        self.assertTrue(beacon._registered,
                        "the leg never registered, so nothing was delivered")
        self.assertTrue(beacon._gsocket_ready_seen)

        # The outage ends: HTTPS works again and delivers. Nothing stops
        # the carrier, because an operator who has lost four legs once does
        # not want to pay for the fifth coming up twice.
        beacon.https_enabled = True
        beacon.callback_url = server.callback_url
        elapsed = self.run_cycles(beacon, 1)

        self.assertEqual(self.child_pid(beacon), pid)
        self.assertTrue(_alive(pid))
        self.assertLess(elapsed, 5.0,
                        "a warm carrier cost the cycle a readiness wait")

    def test_a_cycle_before_the_carrier_is_ready_records_carrier_failed(self):
        beacon = self.a_beacon(gsocket={"binary_path": self.never_binds(),
                                        "ready_timeout_seconds": 1})
        self.run_cycles(beacon, 1)
        pid = self.child_pid(beacon)
        elapsed = self.run_cycles(beacon, 1)

        self.assertTrue(_alive(pid), "the child died rather than being slow")
        self.assertGsocketLeg(beacon, "carrier_failed")
        # Bounded by `ready_timeout_seconds` and by nothing else: a cycle
        # that waited for ever on a forward that never came up would take
        # the beacon with it. The window is measured from the start, which
        # was a few milliseconds before this cycle began, so the floor is
        # asserted loosely and the ceiling is what matters.
        self.assertGreaterEqual(elapsed, 0.5)
        self.assertLess(elapsed, 10.0)

    def test_a_bound_local_port_records_carrier_failed_and_the_cycle_moves_on(self):
        # bind local_port first, then run one cycle
        beacon = self.a_beacon(gsocket={"ready_timeout_seconds": 20})
        held = socket.socket()
        # Bound and not listening, which is what a port already taken on
        # the implant looks like: `gs-netcat` cannot have it, and a connect
        # to it is refused rather than accepted by something else.
        held.bind(("127.0.0.1", beacon.gsocket_local_port))
        self.addCleanup(held.close)

        self.run_cycles(beacon, 1)
        pid = self.child_pid(beacon)
        for _ in range(100):
            if not _alive(pid):
                break
            time.sleep(0.05)
        elapsed = self.run_cycles(beacon, 1)

        self.assertGsocketLeg(beacon, "carrier_failed")
        self.assertFalse(_alive(pid), "the child kept running without a port")
        self.assertLess(elapsed, 10.0,
                        "the cycle waited on a child that had already gone")

    def test_a_killed_child_is_restarted_after_the_delay(self):
        # The restart lives in the latch and nowhere else: the cycle after
        # the child died finds no upstream leg delivering, which is the
        # same condition that started it in the first place.
        patient = self.a_beacon(gsocket={"restart_delay_seconds": 30})
        self.run_cycles(patient, 1)
        first = self.child_pid(patient)
        os.kill(first, 9)
        for _ in range(100):
            if not _alive(first):
                break
            time.sleep(0.05)

        self.assertFalse(patient._gsocket_start())
        self.assertIsNone(patient._gsocket_proc)
        self.assertGsocketLeg(patient, "carrier_failed")

        quick = self.a_beacon(gsocket={"restart_delay_seconds": 1})
        self.run_cycles(quick, 1)
        old = self.child_pid(quick)
        os.kill(old, 9)
        time.sleep(1.1)

        self.assertTrue(quick._gsocket_start())
        new = self.child_pid(quick)
        self.assertNotEqual(new, old)
        self.assertTrue(_alive(new))

    def test_the_restart_ceiling_is_honoured_and_logged_once(self):
        # `max_restarts: 0` is unlimited, as it is for c2.sliver, so a
        # ceiling has to be a number an operator set on purpose -- and a
        # value nothing read would be worse than no value at all.
        beacon = self.a_beacon(gsocket={"restart_delay_seconds": 1,
                                        "max_restarts": 1})
        self.run_cycles(beacon, 1)

        first = self.child_pid(beacon)
        os.kill(first, 9)
        time.sleep(1.1)
        self.assertTrue(beacon._gsocket_start(), "the one restart was refused")
        second = self.child_pid(beacon)
        self.assertNotEqual(second, first)

        os.kill(second, 9)
        time.sleep(1.1)
        with self.assertLogs("raccoon.c2", level="WARNING") as caught:
            self.assertFalse(beacon._gsocket_start(),
                             "the ceiling let a second restart through")
        self.assertIsNone(beacon._gsocket_proc)
        self.assertGsocketLeg(beacon, "carrier_failed")
        self.assertEqual(len(caught.records), 1, caught.output)
        self.assertIn("max_restarts", caught.output[0])

    def test_stopping_the_beacon_takes_the_carrier_with_it(self):
        beacon = self.a_beacon()
        self.run_cycles(beacon, 1)
        pid = self.child_pid(beacon)
        beacon.stop()
        for _ in range(100):
            if not _alive(pid):
                break
            time.sleep(0.05)
        self.assertFalse(_alive(pid),
                         "a gs-netcat outlived the beacon that spawned it")
        self.assertIsNone(beacon._gsocket_proc)

    def test_the_secret_never_reaches_the_command_line(self):
        beacon = self.a_beacon()
        self.run_cycles(beacon, 1)
        argv = self.recorded_argv()

        self.assertIn("-k", argv)
        self.assertIn(self.secret_file, argv)
        self.assertNotIn("-s", argv)
        with open(self.secret_file) as handle:
            value = handle.read().strip()
        for entry in argv:
            self.assertNotIn(value, entry)

    def test_the_child_gets_no_raccoon_variable_and_no_gsocket_args(self):
        # The beacon holds the AES key this leg's traffic is sealed with,
        # and `GSOCKET_ARGS` is appended to the argv by gsocket's own
        # tools -- including, if somebody set it, the `-s <secret>` this
        # leg exists never to produce.
        with mock.patch.dict(os.environ, {"RACCOON_KEY": "not-a-real-key",
                                          "GSOCKET_ARGS": "-s leaked"}):
            beacon = self.a_beacon()
            self.run_cycles(beacon, 1)
            child_env = self.recorded_environment()
        self.assertNotIn("RACCOON_", child_env)
        self.assertNotIn("GSOCKET_ARGS", child_env)
        self.assertNotIn("leaked", child_env)


class TestTheBinaryCheck(LegFixture):
    """The leg verifies what it is about to exec, with its own copy."""

    def test_a_missing_binary_disables_the_leg_and_logs_once(self):
        # two cycles, one log line, class binary_missing
        absent = os.path.join(self.root, "not-installed")
        beacon = self.a_beacon(gsocket={"binary_path": absent})
        with self.assertLogs("raccoon.c2", level="WARNING") as caught:
            self.run_cycles(beacon, 2)

        self.assertIsNone(beacon._gsocket_proc)
        self.assertGsocketLeg(beacon, "binary_missing")
        self.assertEqual(len(caught.records), 1, caught.output)
        self.assertIn(absent, caught.output[0])
        self.assertIn("no such file", caught.output[0])

    def test_the_two_binary_checks_give_the_same_reasons(self):
        # beacon.py's copy against carrier.verify_binary: the copy is
        # deliberate, so a test holds it, as the rescue format's is held.
        with open(self.binary, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        directory = os.path.join(self.root, "a-directory")
        os.mkdir(directory)
        unexecutable = os.path.join(self.root, "not-executable")
        shutil.copy(self.binary, unexecutable)
        os.chmod(unexecutable, 0o644)

        cases = [
            ("an empty binary_path", "", ""),
            ("a path with nothing at it",
             os.path.join(self.root, "absent"), ""),
            ("a directory", directory, ""),
            ("a file this user may not exec", unexecutable, ""),
            ("the digest it was measured with", self.binary, digest),
            ("an upper-case digest", self.binary, digest.upper()),
            ("a digest that does not match", self.binary, "0" * 64),
            ("no digest at all", self.binary, ""),
        ]
        if os.geteuid() != 0:
            # Executable and unreadable, so the exec-bit check passes and
            # the hash cannot be taken. Root may read it regardless, and a
            # suite run as root would be asserting the wrong branch.
            unreadable = os.path.join(self.root, "unreadable")
            shutil.copy(self.binary, unreadable)
            os.chmod(unreadable, 0o111)
            cases.append(("a binary that cannot be read", unreadable,
                          "1" * 64))

        for label, path, sha in cases:
            with self.subTest(case=label):
                beacon = self.a_raw_beacon({
                    "enabled": True, "secret_file": self.secret_file,
                    "binary_path": path, "sha256": sha})
                self.assertEqual(beacon._gsocket_binary_problem(),
                                 carrier_mod.binary_problem(path, sha))

    def test_the_mismatch_reason_is_copied_clause_for_clause(self):
        # The clause about "the secret that fronts the beacon socket"
        # reads oddly from an implant's side and is a known, parked review
        # finding. It is copied unchanged on purpose: a divergence
        # improvised here would break the comparison above and hide the
        # parked item.
        beacon = self.a_beacon(gsocket={"sha256": "0" * 64})
        reason = beacon._gsocket_binary_problem()
        self.assertIn("which would be handed the secret that fronts the "
                      "beacon socket", reason)
        self.assertIn(self.binary, reason)


class TestTheHttpPathIsReused(LegFixture):
    """One client, two bases, and a failure filed against the right leg."""

    def test_the_base_still_defaults_to_the_callback_urls_parent(self):
        # Every existing caller has to behave identically, which is why
        # the parameter has a default rather than a caller.
        beacon = self.a_beacon(https={"enabled": True,
                                      "callback_url": "https://c2.test/api/v1/beacon"})
        self.assertTrue(beacon._evasive_url("beacon")
                        .startswith("https://c2.test/api/v1/"))

    def test_the_leg_aims_at_its_own_forward(self):
        beacon = self.a_beacon()
        base = "http://127.0.0.1:%d/api/v1" % beacon.gsocket_local_port
        self.assertTrue(beacon._evasive_url("beacon", base).startswith(base))
        self.assertEqual(beacon._gsocket_base(), base)

    def test_a_gsocket_failure_is_filed_against_gsocket_not_https(self):
        # _https_post hardcodes "https" in three _record_leg calls today,
        # so without the transport argument the carrier's failures would
        # be read as the HTTPS leg's -- and an operator would chase a
        # callback URL that is working.
        for status in (503, 407):
            with self.subTest(status=status):
                beacon = self.a_beacon()

                class _Resp:
                    status_code = status

                    def json(self):
                        return {}

                class _Session:
                    trust_env = True
                    proxies = {}

                    def post(self, *_a, **_kw):
                        return _Resp()

                # Patched where the leg builds its session rather than
                # assigned to `_proxy_session`: a loopback base is never
                # dialled through a proxy, so the proxy session is
                # deliberately not the one used (see the test below).
                with mock.patch.object(beacon_mod, "_HttpSession", _Session), \
                        mock.patch.object(beacon_mod.logger, "warning"):
                    beacon._https_post("beacon", {"action": "beacon"},
                                       base=beacon._gsocket_base(),
                                       transport="gsocket")
                self.assertIn("gsocket", beacon._leg_status)
                self.assertNotIn("https", beacon._leg_status)
                self.assertEqual(beacon._leg_status["gsocket"][1], status)

    def test_a_forward_that_leads_nowhere_is_filed_against_gsocket(self):
        # The same property without a stand-in for the HTTP client: the
        # forward is up and binds, and what it forwards to is shut. That
        # is a real `gs-netcat` whose peer is not there.
        beacon = self.a_beacon(gsocket={"binary_path":
                                        self.forwarder(_free_port())})
        self.run_cycles(beacon, 2)

        self.assertIn("gsocket", beacon._leg_status)
        self.assertNotIn("https", beacon._leg_status)

    def test_a_loopback_forward_is_not_dialled_through_a_proxy(self):
        # The leg exists for the network where every other leg failed, and
        # a corporate proxy is the commonest reason for that. A POST to
        # the implant's own forward must not be handed to one: the far end
        # of that forward is the beacon socket, not the internet.
        beacon = self.a_beacon()
        beacon._proxy_session = beacon_mod._HttpSession()
        beacon._proxy_session.proxies = {"http": "http://127.0.0.1:1",
                                         "https": "http://127.0.0.1:1"}
        urls = []

        class _Session(beacon_mod._HttpSession):
            def post(self, url, json_data, headers, timeout=30):
                urls.append((url, dict(self.proxies), self.trust_env))
                raise OSError("nothing is listening")

        with mock.patch.object(beacon_mod, "_HttpSession", _Session):
            beacon._https_post("beacon", {"action": "beacon"},
                               base=beacon._gsocket_base(),
                               transport="gsocket")
        self.assertTrue(urls, "the leg never posted")
        for url, proxies, trust_env in urls:
            self.assertIn("127.0.0.1", url)
            self.assertEqual(proxies, {})
            self.assertFalse(trust_env)


class TestAFullCycle(LegFixture):
    """Register, task, result -- the real beacon, the real server crypto."""

    def test_a_full_cycle_over_gsocket_against_the_real_server_crypto(self):
        server = self.team_server()
        beacon = self.a_beacon(gsocket={"binary_path":
                                        self.forwarder(server.port)},
                               key=server.key)

        # Cycle one brings the carrier up; cycle two registers through it.
        self.run_cycles(beacon, 2)
        agent = server.agent_of(beacon._implant_id)
        self.assertIsNotNone(agent, "the leg never registered")
        self.assertTrue(beacon._registered)

        server_mod.task_queues[agent].append(
            {"id": "task-gsocket-1", "cmd": "pwd", "args": "",
             "status": "queued"})
        self.run_cycles(beacon, 1)

        result = server_mod.results.get("task-gsocket-1")
        self.assertIsNotNone(result, "no result came back over the forward")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["output"].strip(), os.getcwd())
        self.assertEqual(server_mod.agents[agent]["last_channel"], "http")


class TestRegisteringOverTheFirstUpstreamLeg(LegFixture):
    """Registration is a property of the chain, not of HTTPS.

    The registration preamble used to be gated on `https_enabled`, which
    was true enough while HTTPS was the only leg that carried an
    `action=register` of its own. The configuration this feature exists
    for is the one where it is *off*: four legs blocked, gsocket the only
    way out. An implant like that never registered, never appeared in the
    fleet, and looked healthy from every other angle.

    Four properties are held here, and the third is the one that is easy
    to get wrong.

    **Every upstream leg can register**, in chain order, and `dns` is not
    one of them: it is receive-only, so a registration sent over it could
    never be followed by a result.

    **A registration adopts the id the server assigned.** `_agent_id` was
    set in `_register_https` and nowhere else, while the SMB, QUIC and
    gsocket rungs promoted `_registered` on their own -- so an implant
    that registered over any leg but HTTPS filed its results under its
    *implant* id. The server's `history` is keyed by the agent name, so
    that work never appeared against the agent at all.

    **Registration does not start the carrier.** The latch is the
    operator's decision: a healthy implant holds no GSRN connection, so
    nothing may bring `gs-netcat` up before the chain has been tried. For
    a gsocket-only implant that means its carrier is not a candidate at
    beacon start -- the preamble finds nothing to try, skips, and the leg
    registers from inside the loop on the cycle after the latch started
    the child.

    **A leg that is not configured is never blamed.** The re-registration
    every fifth failed cycle is on the same generalisation, because an
    `https` failure in the rescue record of an implant with no HTTPS leg
    describes a callback URL the operator never set.
    """

    def test_a_gsocket_only_beacon_registers(self):
        # https, dns, smb and quic all disabled: the case the whole
        # feature exists for. The agent must appear in the fleet, under
        # the name the server assigned -- and the beacon must then file
        # its work under that name, because registering without adopting
        # the id is half a registration.
        server = self.team_server()
        beacon = self.a_beacon(gsocket={"binary_path":
                                        self.forwarder(server.port)},
                               key=server.key)

        # Cycle one brings the carrier up; cycle two registers through it.
        self.run_cycles(beacon, 2)

        agent = server.agent_of(beacon._implant_id)
        self.assertIsNotNone(agent, "the beacon never reached the fleet")
        self.assertTrue(beacon._registered)
        self.assertEqual(beacon._agent_id, agent,
                         "registered without adopting the assigned id")

        # And the consequence of that id, which is the part an operator
        # sees: a result filed under the implant id misses `history`,
        # which `_handle_result` keys by the agent name. Queued the way
        # `api_create_task` does it, including the history entry it
        # writes beside the task.
        server_mod.task_queues.setdefault(agent, []).append(
            {"id": "task-upstream-1", "cmd": "pwd", "args": "",
             "status": "queued"})
        server_mod.history.setdefault(agent, []).append(
            {"task_id": "task-upstream-1", "cmd": "pwd", "status": "queued"})
        self.run_cycles(beacon, 1)

        result = server_mod.results.get("task-upstream-1")
        self.assertIsNotNone(result, "no result came back over the forward")
        self.assertEqual(result["agent_id"], agent,
                         "the result was filed under the implant id")
        entry = [record for record in server_mod.history[agent]
                 if record.get("task_id") == "task-upstream-1"]
        self.assertEqual([record["status"] for record in entry], ["ok"],
                         "the agent's history never learned the task ran")

    def test_the_preamble_is_skipped_when_no_upstream_leg_is_enabled(self):
        # Nothing here carries a registration: the four upstream legs are
        # off and `dns` is receive-only. The preamble must not run at all
        # -- a generalisation that walked an empty chain would spend its
        # ten attempts and ten backoff sleeps before the first cycle, and
        # then warn about a registration nothing could have attempted.
        beacon = self.a_beacon(gsocket={"enabled": False})

        self.assertEqual(beacon._registration_legs(), [])
        with mock.patch.object(beacon_mod.logger, "warning") as warned:
            self.run_cycles(beacon, 1)

        self.assertFalse(beacon._registered)
        self.assertEqual(warned.call_args_list, [],
                         "a skipped preamble warned about registration")
        # One cycle ran and counted its one failure, which is only
        # possible if the preamble spent none of the mocked sleeps.
        self.assertEqual(beacon._consecutive_failures, 1)

    def test_registration_does_not_start_the_carrier(self):
        # The lazy half of the latch, from registration's side. An
        # implant whose only leg is gsocket has nothing to register over
        # at beacon start, and that is the correct answer rather than a
        # gap: starting the carrier here would hold a GSRN connection for
        # the life of every healthy implant, which is the thing the
        # operator decided against.
        beacon = self.a_beacon()

        self.assertEqual(beacon._registration_legs(), [])
        self.assertFalse(beacon._register_upstream())

        self.assertIsNone(beacon._gsocket_proc)
        self.assertFalse(os.path.exists(self.argv_file),
                         "registration spawned a gs-netcat of its own")

    def test_the_upstream_legs_are_walked_in_chain_order(self):
        # Four properties in one story, because they are one state.
        #
        # Before the latch has run there is nothing to register over,
        # which is the test above. After it the carrier is warm and its
        # leg is a candidate -- that is what makes a re-registration over
        # gsocket possible on a later cycle. When the other three legs
        # come back the order is the chain's and comes from one place.
        # And `dns` is in none of them, for the reason
        # `_RESCUE_UPSTREAM` excludes it: it carries nothing out, so a
        # registration over it could never be followed by a result.
        beacon = self.a_beacon()
        self.assertEqual(beacon._registration_legs(), [])

        self.run_cycles(beacon, 1)

        self.assertIsNotNone(beacon._gsocket_proc)
        self.assertTrue(_accepts(beacon.gsocket_local_port),
                        "the forward never came up")
        self.assertEqual(beacon._registration_legs(), ["gsocket"])

        # The outage ends, as in `test_the_carrier_stays_up_once_started`:
        # flipped rather than reconfigured, because what is under test is
        # the order of a list and not the reading of a config block.
        beacon.https_enabled = True
        beacon.smb_enabled = True
        beacon.quic_enabled = True
        beacon.dns_enabled = True

        self.assertEqual(beacon._registration_legs(),
                         list(beacon_mod._RESCUE_UPSTREAM))
        self.assertNotIn("dns", beacon._registration_legs())

    def test_the_ten_attempt_ceiling_is_still_the_ceiling(self):
        # Ten attempts, one walk of the chain each, and then the loop
        # proceeds unregistered rather than holding an implant on a
        # server that is not there for ever. The HTTPS leg here is
        # configured and dead, so the attempts are real ones.
        beacon = self.a_beacon(
            gsocket={"enabled": False},
            https={"enabled": True,
                   "callback_url": "http://127.0.0.1:%d/api/v1/beacon"
                                   % _free_port()})

        with self.assertLogs("raccoon.c2", level="WARNING") as caught:
            self.run_cycles(beacon, 11)

        self.assertFalse(beacon._registered)
        # Eleven sleeps were on offer and the preamble took ten: the
        # eleventh belongs to the first cycle, which counted its own one
        # failure. Without the ceiling the preamble would have spent that
        # sleep too, no cycle would have run, and the reset below it
        # would have left this at zero.
        self.assertEqual(beacon._consecutive_failures, 1)
        self.assertTrue(any("proceeding unregistered" in line
                            for line in caught.output), caught.output)

    def test_a_beacon_with_no_https_leg_files_no_https_failure(self):
        # Every fifth failed cycle re-registers. That used to call
        # `_register_https` whatever the configuration, so a beacon whose
        # only leg is gsocket posted to an empty callback URL and filed an
        # `https` failure into its own rescue record -- a diagnostic about
        # a leg the operator never configured, sitting beside the real
        # reason. The forward here is up and leads nowhere, which is a
        # real `gs-netcat` whose peer is not there.
        beacon = self.a_beacon(gsocket={"binary_path":
                                        self.forwarder(_free_port())})

        self.run_cycles(beacon, 5)

        self.assertEqual(beacon._consecutive_failures, 5,
                         "the fifth failed cycle was never reached")
        self.assertIn("gsocket", beacon._leg_status)
        self.assertNotIn("https", beacon._leg_status)


class TestTheReadingsWaitForContent(LegFixture):
    """The helper the other classes read through, tested on its own.

    This file lost a full-suite run to the rule below: a reading that
    stopped at `os.path.exists` accepted a file the shell's redirection
    had created and `env` had not yet filled. Both failure shapes are
    pinned here, because neither is reproducible on an idle machine and a
    flake nobody can reproduce is a flake nobody fixes.
    """

    _RECORD_WAIT_SECONDS = 0.4

    def test_a_file_that_exists_but_is_empty_is_not_a_recording(self):
        # The exact state `env > "$FILE"` passes through on its way to
        # writing: present, and empty. Accepting it is how a test asserts
        # against "" and passes while proving nothing.
        path = os.path.join(self.root, "empty.txt")
        open(path, "w").close()

        with self.assertRaises(AssertionError) as caught:
            self._recorded(path)

        message = str(caught.exception)
        self.assertIn(path, message)
        self.assertIn("exists: True", message,
                      "the failure does not distinguish an empty "
                      "recording from an absent one, which is the whole "
                      "difference between a slow child and a broken one")

    def test_content_arriving_late_is_waited_for(self):
        # The child writes on its own time, which is the reason the
        # helper waits at all. Deliberately after a delay longer than one
        # poll interval, so a helper that only looked once would fail.
        path = os.path.join(self.root, "late.txt")
        open(path, "w").close()

        def fill():
            time.sleep(0.1)
            with open(path, "w") as handle:
                handle.write("SHELL=/bin/sh\n")

        writer = threading.Thread(target=fill)
        writer.start()
        self.addCleanup(writer.join)

        with open(self._recorded(path)) as handle:
            self.assertEqual(handle.read(), "SHELL=/bin/sh\n")


class TestTheServersWords(unittest.TestCase):
    """The two classes only this leg can emit have words on the server."""

    def test_the_two_carrier_classes_have_words(self):
        for klass in ("binary_missing", "carrier_failed"):
            with self.subTest(klass=klass):
                self.assertIn(klass, server_mod._RESCUE_LEG_WORDS)

    def test_a_carrier_record_does_not_summarise_as_unknown(self):
        from software.c2 import dns_rescue

        record = dns_rescue.unpack(dns_rescue.pack(
            {"https": (dns_rescue.CLASSES["timed_out"], 0),
             "gsocket": (dns_rescue.CLASSES["binary_missing"], 0)}, 0))
        summary = server_mod._rescue_summary(record)
        self.assertNotIn("unknown", summary)
        self.assertIn("GSOCKET", summary)

        record["gsocket"] = (dns_rescue.CLASSES["carrier_failed"], 0)
        self.assertNotIn("unknown", server_mod._rescue_summary(record))


if __name__ == "__main__":
    unittest.main()
