#!/usr/bin/env python3
"""Tests for the carrier supervisor and the panel rows it produces.

What these tests are careful about.

**Nothing here touches the Global Socket Relay Network.** Every process
these tests spawn is `software/tests/data/fake_gs_netcat.sh`, the
stand-in Task 4 ships: in the server shape (`-l -d <host> -p <port>`) it
stays up until it is killed and binds nothing, which is what lets several
carriers in one test all forward into `127.0.0.1:8443` the way the real
deployment does. The suite is run on machines where dialling a
third-party relay would be the one side effect this feature's constraints
call out, so the stand-in is not a convenience.

Each test copies the stand-in into its own temporary directory rather than
pointing at the file in the repository, because one of them rewrites the
binary under a running carrier to prove that the status path does not
re-hash it.

**The refusals are asserted on their content, not on their type.** The
whole reason this supervisor exists in the shape it does is that the four
unrelated faults behind a quiet carrier -- no binary, a replaced binary,
an implant with no secret registered, a child that joined the relay and
never found its peer -- all surface later as a beacon that does not check
in. So a test that only asserted "it raised" would pass against a
supervisor whose every answer was "could not start", which is the version
of this module that would be useless at three in the morning. Two cases
are pinned as *different* from each other on purpose: an unregistered
implant and a world-readable key file. The first is retryable once a
build has been generated; the second means a credential has to be
re-keyed and an implant reflashed, and collapsing the two would lose
that.

**A dead carrier's row does not claim to know why it died.** The carrier
sends its child's stderr to `DEVNULL`, as `sliver.py` does, so the
characteristic gsocket failure arrives here as an exit code and nothing
else. One test holds the row to saying exactly that much.

**No orphans.** Every supervisor built here is torn down through
`stop_all`, and the one test that kills a child does it by the pid the
row reported, then waits for the row to agree that it is gone.
"""

import base64
import hashlib
import json
import logging
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from software.c2.gsocket.carrier import CarrierError
from software.c2.gsocket.config import CarrierSpec
from software.c2.gsocket.secrets import SecretStore, secretstore_path
from software.c2.gsocket.supervisor import CarrierSupervisor
from software.c2.listeners.registry import ListenerSpec
from software.c2.listeners.supervisor import Supervisor
from software.c2.server import ServerCrypto, create_app

FAKE_GS_NETCAT = Path(__file__).resolve().parent / "data" / "fake_gs_netcat.sh"

# What the agent socket answers for everything that is not the beacon
# endpoint or the DNS tasking route. A refusal would tell a prober what is
# listening, so the cover answer is the same one the beacon catch-all
# gives.
COVER = {"status": "ok", "version": "2.1.0"}


def _free_port() -> int:
    """A port that was free a moment ago."""
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


def _quiet_werkzeug(case: unittest.TestCase) -> None:
    """Keep the request log out of the suite's output."""
    quiet = logging.getLogger("werkzeug")
    previous = quiet.level
    quiet.setLevel(logging.ERROR)
    case.addCleanup(quiet.setLevel, previous)


class _PanelServer:
    """A real team server on two sockets, with the panel's two supervisors.

    Two sockets because the property a new route erodes first is the one
    that keeps the operator interface off the network-facing socket, and
    it cannot be tested through a single-socket app: `create_app` leaves
    the policy inert when `operator_port` is None, which is how every
    pre-split deployment still works.
    """

    operator_token = "operator-token-for-gsocket-tests"

    def __init__(self, data_dir, supervisor=None, carrier_supervisor=None):
        self.data_dir = Path(data_dir)
        self.supervisor = supervisor
        self.carrier_supervisor = carrier_supervisor
        self.crypto = ServerCrypto(os.urandom(32))
        self.servers = ()

    def start(self):
        from werkzeug.serving import make_server

        operator = make_server("127.0.0.1", 0, None, threaded=True)
        agent = make_server("127.0.0.1", 0, None, threaded=True)
        self.operator_port = operator.server_port
        self.agent_port = agent.server_port
        app = create_app(
            self.crypto, self.operator_token, self.data_dir,
            server_config={"host": "127.0.0.1", "port": self.agent_port,
                           "operator_host": "127.0.0.1",
                           "operator_port": self.operator_port},
            operator_port=self.operator_port,
            supervisor=self.supervisor,
            carrier_supervisor=self.carrier_supervisor)
        self.servers = (operator, agent)
        for srv in self.servers:
            srv.app = app
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        return self

    def stop(self):
        for srv in self.servers:
            srv.shutdown()

    # ── requests ──

    def get(self, path, *, port=None, token=operator_token):
        return self._call(path, port=port, token=token)

    def post(self, path, *, port=None, token=operator_token):
        return self._call(path, port=port, token=token, method="POST")

    def page(self) -> str:
        """The operator page as the server serves it."""
        request = urllib.request.Request(
            "http://127.0.0.1:%d/" % self.operator_port)
        request.add_header("Authorization", "Bearer %s" % self.operator_token)
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.read().decode("utf-8", "replace")

    def _call(self, path, *, port=None, token=None, method="GET"):
        url = "http://127.0.0.1:%d%s" % (port or self.operator_port, path)
        request = urllib.request.Request(url, method=method)
        if token is not None:
            request.add_header("Authorization", "Bearer %s" % token)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            body = exc.read()
            try:
                return exc.code, json.loads(body or b"{}")
            except ValueError:
                return exc.code, None


class CarrierFixture(unittest.TestCase):
    """A secret store, a copy of the stand-in binary, and no orphans."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="raccoon-gsocket-supervisor-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        # A copy rather than the file in the repository: one test appends
        # to this binary while a carrier is running.
        self.binary = os.path.join(self.root, "gs-netcat")
        shutil.copy(str(FAKE_GS_NETCAT), self.binary)
        os.chmod(self.binary, 0o755)

        self.store = SecretStore(str(secretstore_path(self.root)))
        self.secrets = {}
        for identity in ("raccoon-01", "raccoon-02"):
            secret = SecretStore.generate()
            self.store.register_implant(identity, secret)
            self.secrets[identity] = secret

        self.argv_file = os.path.join(self.root, "argv.txt")
        record = mock.patch.dict(os.environ, {
            "FAKE_GS_NETCAT_ARGV_FILE": self.argv_file,
        })
        record.start()
        self.addCleanup(record.stop)

    # ── building ──

    def spec(self, name="raccoon-01-carrier", identity="raccoon-01",
             **overrides) -> CarrierSpec:
        fields = {
            "name": name,
            "identity": identity,
            "enabled": True,
            "beacon_host": "127.0.0.1",
            # The team server's own beacon socket. Every carrier names the
            # same one, which is the normal deployment and not a clash: a
            # carrier forwards into that socket rather than binding it.
            "beacon_port": 8443,
            "binary_path": self.binary,
            "sha256": "",
        }
        fields.update(overrides)
        return CarrierSpec(**fields)

    def supervisor(self, specs=None, **kwargs) -> CarrierSupervisor:
        built = CarrierSupervisor(
            [self.spec()] if specs is None else specs, self.store, **kwargs)
        self.addCleanup(built.stop_all)
        return built

    def listener_supervisor(self, name="panel-quic") -> Supervisor:
        """A real listener supervisor that is never asked to start anything.

        `status()` on a listener nobody started spawns no process, so this
        gives the merged route a genuine listener row to put beside a
        carrier's without a child process in the test.
        """
        built = Supervisor([ListenerSpec(
            name=name, transport="quic", enabled=True,
            bind_host="127.0.0.1", bind_port=_free_port(),
            relay_url="http://127.0.0.1:1/api/v1/beacon")])
        self.addCleanup(built.stop_all)
        return built

    def panel(self, **kwargs) -> _PanelServer:
        _quiet_werkzeug(self)
        server = _PanelServer(os.path.join(self.root, "data"), **kwargs)
        self.addCleanup(server.stop)
        return server.start()

    # ── reading ──

    def row(self, supervisor, name="raccoon-01-carrier") -> dict:
        for entry in supervisor.status():
            if entry["name"] == name:
                return entry
        raise AssertionError("no row for carrier %r in %r"
                             % (name, supervisor.status()))

    def wait_until_down(self, supervisor, name="raccoon-01-carrier",
                        timeout=10.0) -> dict:
        """The row, once the supervisor agrees the carrier is not running."""
        deadline = time.time() + timeout
        while True:
            entry = self.row(supervisor, name)
            if not entry["running"]:
                return entry
            if time.time() > deadline:
                raise AssertionError(
                    "carrier %r still reads as running: %r" % (name, entry))
            time.sleep(0.05)

    def recorded_argv(self, timeout=5.0):
        """The argv the spawned stand-in saw, waited for."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with open(self.argv_file) as handle:
                    text = handle.read()
            except FileNotFoundError:
                text = ""
            if text:
                return text.splitlines()
            time.sleep(0.05)
        raise AssertionError("the stand-in never recorded its argv")


class TestTheCarrierSupervisor(CarrierFixture):
    """What the supervisor reports, what it refuses, and in what words."""

    # ── the status row ──

    def test_a_configured_carrier_is_reported_before_it_is_started(self):
        rows = self.supervisor().status()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "raccoon-01-carrier")
        self.assertEqual(rows[0]["transport"], "gsocket")
        self.assertEqual(rows[0]["identity"], "raccoon-01")
        # The field that says this row is not a listener's: a carrier
        # listens on the relay network under one implant's secret and
        # binds nothing, so there is no socket to report.
        self.assertIsNone(rows[0]["socket"])
        self.assertFalse(rows[0]["running"])
        self.assertIsNone(rows[0]["pid"])
        self.assertIsNone(rows[0]["uptime"])
        self.assertIn("not started", rows[0]["detail"])

    def test_one_row_per_configured_carrier_in_name_order(self):
        supervisor = self.supervisor([
            self.spec(name="zeta", identity="raccoon-02"),
            self.spec(name="alpha", identity="raccoon-01"),
        ])
        self.assertEqual([row["name"] for row in supervisor.status()],
                         ["alpha", "zeta"])

    def test_a_started_carrier_reports_its_pid_and_its_uptime(self):
        supervisor = self.supervisor()
        answer = supervisor.start("raccoon-01-carrier")
        self.assertTrue(answer["running"])
        self.assertTrue(_alive(answer["pid"]),
                        "start returned a pid that is not alive")
        self.assertIsNotNone(answer["uptime"])
        self.assertGreaterEqual(answer["uptime"], 0)
        self.assertIn(str(answer["pid"]), answer["detail"])

        row = self.row(supervisor)
        self.assertEqual(row["pid"], answer["pid"])
        self.assertTrue(row["running"])

    def test_a_stopped_carrier_says_it_was_stopped_from_the_panel(self):
        supervisor = self.supervisor()
        pid = supervisor.start("raccoon-01-carrier")["pid"]
        answer = supervisor.stop("raccoon-01-carrier")
        self.assertFalse(answer["running"])
        self.assertIsNone(answer["pid"])
        self.assertIsNone(answer["uptime"])
        self.assertFalse(_alive(pid),
                         "stop returned but pid %d is still alive" % pid)
        # Not "exited on signal 15", which is true and reads as a fault.
        # This server signalled it, so the row says so.
        self.assertIn("stopped", answer["detail"])
        self.assertEqual(self.row(supervisor)["detail"], answer["detail"])

    def test_a_dead_carrier_does_not_claim_to_know_why_it_died(self):
        # The characteristic gsocket failure -- the carrier joined the
        # relay network and never found its peer -- reaches this
        # supervisor as an exit code and nothing else, because the child's
        # stderr goes to DEVNULL exactly as sliver.py's does. So the row
        # may report the status and must not invent a cause for it.
        supervisor = self.supervisor()
        pid = supervisor.start("raccoon-01-carrier")["pid"]
        os.kill(pid, signal.SIGKILL)
        row = self.wait_until_down(supervisor)
        self.assertIsNone(row["pid"])
        self.assertIsNone(row["uptime"])
        self.assertIn("signal %d" % signal.SIGKILL, row["detail"])
        self.assertIn("all this server knows", row["detail"],
                      "the row does not admit that the exit status is all "
                      "it has")
        # The failure that matters is named in the subjunctive, as the
        # thing that would leave no message, rather than asserted as what
        # happened. Nothing here can tell those apart.
        self.assertIn("would leave no message behind", row["detail"])
        for invented in ("the relay refused", "wrong secret",
                         "could not find its peer"):
            self.assertNotIn(invented, row["detail"],
                             "the row invents a cause it cannot know")

    def test_a_status_row_does_not_rehash_the_binary(self):
        # `probe()` verifies the binary first, and a configured sha256
        # re-reads a multi-megabyte file. A panel page load must not pay
        # that, and -- worse than the cost -- a row that re-verified would
        # report a replaced binary for a carrier that is running
        # perfectly well, which is the one finding here nobody should get
        # wrong.
        with open(self.binary, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        supervisor = self.supervisor([self.spec(sha256=digest)])
        supervisor.start("raccoon-01-carrier")
        with open(self.binary, "ab") as handle:
            handle.write(b"\n# the binary changed under the running child\n")

        row = self.row(supervisor)
        self.assertTrue(row["running"], "the status path re-verified the "
                                        "binary of a running carrier")
        self.assertNotIn("sha256", row["detail"])
        # And the check is not lost, only moved: the next start is where
        # it belongs, before anything is exec'd.
        supervisor.stop("raccoon-01-carrier")
        with self.assertRaises(CarrierError) as caught:
            supervisor.start("raccoon-01-carrier")
        self.assertIn("sha256", str(caught.exception))

    # ── the refusals ──

    def test_an_unknown_name_names_itself_and_what_does_exist(self):
        supervisor = self.supervisor()
        for action in ("start", "stop"):
            with self.subTest(action=action):
                with self.assertRaises(CarrierError) as caught:
                    getattr(supervisor, action)("not-a-carrier")
                reason = str(caught.exception)
                self.assertIn("not-a-carrier", reason)
                self.assertIn("raccoon-01-carrier", reason,
                              "the refusal does not say what is configured")

    def test_starting_a_running_carrier_is_refused_with_its_pid(self):
        supervisor = self.supervisor()
        pid = supervisor.start("raccoon-01-carrier")["pid"]
        with self.assertRaises(CarrierError) as caught:
            supervisor.start("raccoon-01-carrier")
        reason = str(caught.exception)
        self.assertIn("raccoon-01-carrier", reason)
        self.assertIn(str(pid), reason)
        self.assertTrue(_alive(pid), "the refused start killed the carrier")

    def test_stopping_a_carrier_that_is_not_running_is_refused_by_name(self):
        supervisor = self.supervisor()
        with self.assertRaises(CarrierError) as caught:
            supervisor.stop("raccoon-01-carrier")
        self.assertIn("raccoon-01-carrier", str(caught.exception))
        self.assertIn("nothing to stop", str(caught.exception))

    def test_an_implant_with_no_registered_secret_is_refused_by_name(self):
        # `SecretStore.secret_file_for` raises KeyError here, and it is a
        # deliberate refusal: nothing can listen under an implant's secret
        # before that implant has one. It is also retryable, which is why
        # it must not share a wording with the next test.
        supervisor = self.supervisor([self.spec(identity="raccoon-99")])
        with self.assertRaises(CarrierError) as caught:
            supervisor.start("raccoon-01-carrier")
        reason = str(caught.exception)
        self.assertIn("raccoon-01-carrier", reason)
        self.assertIn("raccoon-99", reason)
        self.assertIn("no gsocket secret is registered", reason)
        self.assertNotIn("reflash", reason,
                         "an unregistered implant is read as a disclosure")
        self.assertIn("start refused", self.row(supervisor)["detail"])

    def test_a_world_readable_key_file_is_refused_as_a_disclosure(self):
        # `secret_file_for` raises ValueError for an existing key file
        # other users can read, and that is a different answer from the
        # one above: the secret must be assumed read, so what it calls for
        # is a re-key and a reflash rather than another attempt.
        path = self.store.secret_file_for("raccoon-01")
        os.chmod(str(path), 0o644)
        supervisor = self.supervisor()
        with self.assertRaises(CarrierError) as caught:
            supervisor.start("raccoon-01-carrier")
        reason = str(caught.exception)
        self.assertIn("raccoon-01-carrier", reason)
        self.assertIn("reflash", reason)
        self.assertIn("not to be retried", reason,
                      "the refusal reads as something to try again")
        # And the secret itself stays out of it: this message reaches an
        # operator's screen and from there a bug report.
        self.assertNotIn(self.secrets["raccoon-01"], reason)

    def test_a_refused_start_does_not_report_the_previous_death(self):
        # The stale-row failure. A carrier that died keeps its exit code,
        # so a row assembled from the process alone would answer a failed
        # start with `running: False, exit_code: -9` -- the previous
        # event, read as this one. The CarrierError carries the truth.
        supervisor = self.supervisor()
        pid = supervisor.start("raccoon-01-carrier")["pid"]
        os.kill(pid, signal.SIGKILL)
        died = self.wait_until_down(supervisor)["detail"]
        self.assertIn("signal %d" % signal.SIGKILL, died)

        os.chmod(self.binary, 0o644)
        with self.assertRaises(CarrierError) as caught:
            supervisor.start("raccoon-01-carrier")
        reason = str(caught.exception)

        row = self.row(supervisor)
        self.assertIn("start refused", row["detail"])
        self.assertIn("may not execute it", row["detail"])
        self.assertNotIn("signal %d" % signal.SIGKILL, row["detail"],
                         "the row reports the previous death as though it "
                         "were the failed start")
        self.assertIn(self.binary, reason)

    def test_a_successful_start_clears_an_earlier_refusal(self):
        supervisor = self.supervisor()
        os.chmod(self.binary, 0o644)
        with self.assertRaises(CarrierError):
            supervisor.start("raccoon-01-carrier")
        self.assertIn("start refused", self.row(supervisor)["detail"])

        os.chmod(self.binary, 0o755)
        supervisor.start("raccoon-01-carrier")
        self.assertNotIn("refused", self.row(supervisor)["detail"])

    # ── managed=False, which is a state and not an error ──

    def test_an_unmanaged_deployment_still_reports_every_carrier(self):
        supervisor = self.supervisor([
            self.spec(name="alpha", identity="raccoon-01"),
            self.spec(name="zeta", identity="raccoon-02"),
        ], managed=False)
        rows = supervisor.status()
        self.assertEqual([row["name"] for row in rows], ["alpha", "zeta"])
        for row in rows:
            self.assertFalse(row["can_control"])
            self.assertFalse(row["running"])
            self.assertIsNone(row["socket"])
            self.assertTrue(row["detail"],
                            "an unmanaged carrier is reported with no reason")
            self.assertIn("does not manage", row["detail"])

    def test_an_unmanaged_deployment_refuses_with_the_carrier_named(self):
        supervisor = self.supervisor(managed=False)
        for action in ("start", "stop"):
            with self.subTest(action=action):
                with self.assertRaises(CarrierError) as caught:
                    getattr(supervisor, action)("raccoon-01-carrier")
                reason = str(caught.exception)
                self.assertIn("raccoon-01-carrier", reason)
                self.assertIn(action, reason)
                self.assertIn("does not manage", reason)
        # Nothing was spawned, which is the point: a control that silently
        # does nothing is the anti-goal, and so is one that silently does
        # something.
        self.assertFalse(os.path.exists(self.argv_file))

    def test_an_unmanaged_deployment_refuses_an_unknown_name_as_unknown(self):
        # Order matters: a name nobody configured is a 404 whether or not
        # this deployment could act on it, and an operator who mistyped
        # should not be told about Docker sockets.
        supervisor = self.supervisor(managed=False)
        with self.assertRaises(CarrierError) as caught:
            supervisor.start("not-a-carrier")
        self.assertIn("no carrier called", str(caught.exception))

    # ── the secret ──

    def test_the_secret_reaches_the_carrier_as_a_path_and_never_as_an_argument(self):
        # The property the whole arrangement rests on, asserted against a
        # real spawn rather than against the argv builder: the supervisor
        # is the thing that obtains the credential, so it is the thing
        # that could put it on a command line.
        supervisor = self.supervisor()
        supervisor.start("raccoon-01-carrier")
        argv = self.recorded_argv()
        self.assertIn("-k", argv)
        self.assertNotIn("-s", argv)
        secret = self.secrets["raccoon-01"]
        for entry in argv:
            self.assertNotIn(secret, entry,
                             "the secret reached the command line")
        # And what -k points at is the store's 0600 key file.
        keyfile = argv[argv.index("-k") + 1]
        self.assertEqual(stat.S_IMODE(os.stat(keyfile).st_mode), 0o600)
        with open(keyfile) as handle:
            self.assertEqual(handle.read(), secret)

    def test_no_status_row_carries_the_secret_or_the_path_to_it(self):
        supervisor = self.supervisor()
        supervisor.start("raccoon-01-carrier")
        blob = json.dumps(supervisor.status())
        self.assertNotIn(self.secrets["raccoon-01"], blob)
        # The path too: the row becomes an API response and from there a
        # screenshot, and the file holding a credential is not something
        # an operator needs to read off a panel.
        self.assertNotIn("keyfiles", blob)

    # ── shutdown ──

    def test_stop_all_leaves_no_carrier_running(self):
        supervisor = self.supervisor([
            self.spec(name="alpha", identity="raccoon-01"),
            self.spec(name="zeta", identity="raccoon-02"),
        ])
        pids = [supervisor.start(name)["pid"] for name in ("alpha", "zeta")]
        supervisor.stop_all()
        for pid in pids:
            self.assertFalse(_alive(pid),
                             "stop_all left pid %d holding its relay "
                             "address" % pid)
        for row in supervisor.status():
            self.assertFalse(row["running"])

    def test_stop_all_is_safe_when_nothing_was_ever_started(self):
        # The shutdown path calls this without working out which carriers
        # it managed to start, so the first one that was never started
        # must not hide the rest.
        self.supervisor().stop_all()


class TestTheListenerPanelWithCarriers(CarrierFixture):
    """The 📡 route once it answers for two blocks instead of one.

    The sentence this route used to answer with -- "no listeners are
    configured" -- is the thing to watch: a deployment may configure
    carriers and no listeners at all, and that sentence would hide them.
    """

    def test_a_carrier_row_reports_no_socket(self):
        panel = self.panel(supervisor=self.listener_supervisor(),
                           carrier_supervisor=self.supervisor())
        status, body = panel.get("/api/server/listeners")
        self.assertEqual(status, 200)
        rows = {row["name"]: row for row in body["listeners"]}
        self.assertEqual(sorted(rows), ["panel-quic", "raccoon-01-carrier"])

        # Where a listener reports the socket it binds...
        listener = rows["panel-quic"]
        self.assertEqual(listener["bind_host"], "127.0.0.1")
        self.assertIsInstance(listener["bind_port"], int)

        # ...a carrier reports none, because it binds none. It listens on
        # the Global Socket Relay Network under one implant's secret, and
        # its identity is the only address it has.
        carrier = rows["raccoon-01-carrier"]
        self.assertIsNone(carrier["socket"])
        self.assertEqual(carrier["transport"], "gsocket")
        self.assertEqual(carrier["identity"], "raccoon-01")
        self.assertNotIn("bind_port", carrier)

    def test_carriers_show_even_when_no_listeners_are_configured(self):
        # Today this route answers "no listeners are configured" and stops
        # there. That sentence must not hide a configured carrier.
        panel = self.panel(supervisor=None,
                           carrier_supervisor=self.supervisor())
        status, body = panel.get("/api/server/listeners")
        self.assertEqual(status, 200)
        self.assertEqual([row["name"] for row in body["listeners"]],
                         ["raccoon-01-carrier"])
        self.assertTrue(body["managed"])
        self.assertNotIn("no listeners are configured", body.get("detail", ""))

    def test_the_unconfigured_answer_names_both_blocks(self):
        panel = self.panel()
        status, body = panel.get("/api/server/listeners")
        self.assertEqual(status, 200)
        self.assertEqual(body["listeners"], [])
        for block in ("c2.listeners", "c2.gsocket_carrier"):
            self.assertIn(block, body["detail"],
                          "the empty panel does not say where to configure "
                          "%s" % block)

    def test_one_row_per_configured_implant(self):
        panel = self.panel(carrier_supervisor=self.supervisor([
            self.spec(name="raccoon-01-carrier", identity="raccoon-01"),
            self.spec(name="raccoon-02-carrier", identity="raccoon-02"),
        ]))
        _status, body = panel.get("/api/server/listeners")
        self.assertEqual(
            [(row["name"], row["identity"]) for row in body["listeners"]],
            [("raccoon-01-carrier", "raccoon-01"),
             ("raccoon-02-carrier", "raccoon-02")])

    def test_start_and_stop_reach_the_carrier_by_name(self):
        carriers = self.supervisor()
        panel = self.panel(supervisor=self.listener_supervisor(),
                           carrier_supervisor=carriers)

        status, body = panel.post(
            "/api/server/listeners/raccoon-01-carrier/start")
        self.assertEqual(status, 200)
        self.assertTrue(body["running"])
        pid = body["pid"]
        self.assertTrue(_alive(pid))

        status, body = panel.post(
            "/api/server/listeners/raccoon-01-carrier/stop")
        self.assertEqual(status, 200)
        self.assertFalse(body["running"])
        self.assertFalse(_alive(pid),
                         "the route returned but pid %d is still alive" % pid)

    def test_an_unknown_name_is_404_and_a_wrong_state_is_409(self):
        # The distinction api_listener_action already makes: 404 when the
        # name is owned by neither block, 409 when the name is fine and
        # the state is not.
        panel = self.panel(carrier_supervisor=self.supervisor())

        status, body = panel.post("/api/server/listeners/nope/start")
        self.assertEqual(status, 404)
        self.assertIn("nope", body["error"])

        panel.post("/api/server/listeners/raccoon-01-carrier/start")
        status, body = panel.post(
            "/api/server/listeners/raccoon-01-carrier/start")
        self.assertEqual(status, 409)
        self.assertIn("already running", body["error"])

        status, body = panel.post(
            "/api/server/listeners/raccoon-01-carrier/stop")
        self.assertEqual(status, 200)
        status, body = panel.post(
            "/api/server/listeners/raccoon-01-carrier/stop")
        self.assertEqual(status, 409)
        self.assertIn("nothing to stop", body["error"])

    def test_a_name_in_both_blocks_is_refused_rather_than_guessed(self):
        # Merging two namespaces into one route creates a case neither
        # block had: a name both configure. There is no "whichever
        # supervisor owns it" then, and a route that picked one would give
        # an operator a button that starts something other than the row it
        # sits on.
        panel = self.panel(supervisor=self.listener_supervisor(name="twin"),
                           carrier_supervisor=self.supervisor(
                               [self.spec(name="twin")]))
        status, body = panel.post("/api/server/listeners/twin/start")
        self.assertEqual(status, 409)
        self.assertIn("twin", body["error"])
        self.assertIn("c2.gsocket_carrier", body["error"])
        self.assertFalse(os.path.exists(self.argv_file),
                         "the ambiguous name started a carrier anyway")

    def test_an_unmanaged_deployment_says_so_through_the_route(self):
        panel = self.panel(carrier_supervisor=self.supervisor(managed=False))
        status, body = panel.get("/api/server/listeners")
        self.assertEqual(status, 200)
        self.assertFalse(body["managed"])
        self.assertTrue(body["detail"])
        self.assertEqual(len(body["listeners"]), 1,
                         "an unmanaged deployment hides its carriers")
        status, body = panel.post(
            "/api/server/listeners/raccoon-01-carrier/start")
        self.assertEqual(status, 409)
        self.assertIn("raccoon-01-carrier", body["error"])

    def test_the_agent_socket_cannot_reach_this_route(self):
        # The property a new route erodes first. The agent socket serves
        # the beacon endpoint and the DNS tasking route and nothing else;
        # everything else gets the cover answer. It matters more for these
        # two than for most, because they start and stop processes.
        carriers = self.supervisor()
        panel = self.panel(carrier_supervisor=carriers)

        status, body = panel.get("/api/server/listeners",
                                 port=panel.agent_port)
        self.assertEqual(status, 200)
        self.assertEqual(body, COVER)

        status, body = panel.post(
            "/api/server/listeners/raccoon-01-carrier/start",
            port=panel.agent_port)
        self.assertEqual(body, COVER)
        self.assertFalse(self.row(carriers)["running"],
                         "a carrier was started from the beacon socket")

    def test_the_route_requires_the_operator_token(self):
        panel = self.panel(carrier_supervisor=self.supervisor())
        for token in (None, "", "wrong"):
            with self.subTest(token=token):
                status, _ = panel.get("/api/server/listeners", token=token)
                self.assertEqual(status, 401)
                status, _ = panel.post(
                    "/api/server/listeners/raccoon-01-carrier/start",
                    token=token)
                self.assertEqual(status, 401)

    def test_no_answer_carries_a_secret(self):
        carriers = self.supervisor()
        panel = self.panel(carrier_supervisor=carriers)
        _status, started = panel.post(
            "/api/server/listeners/raccoon-01-carrier/start")
        _status, listed = panel.get("/api/server/listeners")
        for body in (started, listed):
            blob = json.dumps(body)
            self.assertNotIn(self.secrets["raccoon-01"], blob)
            self.assertNotIn("keyfiles", blob)


class TestTheCarrierPanelRow(CarrierFixture):
    """What the served page does with a row that has no socket.

    Read out of the page the server serves rather than out of the source,
    so a change that breaks the template fails here instead of in a
    browser.
    """

    def setUp(self):
        super().setUp()
        self.page = self.panel().page()
        start = self.page.index("function showListeners()")
        self.body = self.page[start:self.page.index("</script>", start)]

    def test_the_row_renders_no_socket_and_the_identity_instead(self):
        self.assertIn("socket === null", self.body,
                      "the panel does not tell a carrier row from a "
                      "listener's")
        self.assertIn("esc(String(entry.identity))", self.body,
                      "a carrier's identity reaches the page unescaped, or "
                      "not at all")
        self.assertIn("no socket", self.body,
                      "the row does not say that a carrier binds nothing")

    def test_the_row_says_what_a_carrier_is(self):
        for phrase in ("relay network", "no encryption key"):
            self.assertIn(phrase, self.body.lower(),
                          "the panel does not say %r" % phrase)

    def test_the_listener_row_is_left_as_it_was(self):
        # The sibling shape still renders its socket, and every value a
        # row influences still goes through esc().
        self.assertIn("esc(entry.bind_host)", self.body)
        for field in ("name", "transport", "state", "detail"):
            self.assertIn("esc(entry.%s)" % field, self.body,
                          "entry.%s reaches the page unescaped" % field)
        self.assertNotIn('onclick="listener', self.body,
                         "a handler body is built as a string")


class TestTheCarrierStartupPath(unittest.TestCase):
    """What `--config` does with `c2.gsocket_carrier`, and what it refuses.

    This is the path that turns Task 3's unknown-key strictness from a
    library feature into a production guarantee: until something at
    start-up calls `load_carriers`, a `c2.gsocket_carrier` block can hold
    a key nobody reads and look applied. And it is fatal rather than a
    warning, for the reason the listeners' and the tunnel's are: a
    carrier that was silently not configured shows up as a beacon that
    never checks in, which is the hardest failure in this project to
    attribute.
    """

    def _config(self, text) -> Path:
        path = Path(tempfile.mkdtemp()) / "raccoon.yaml"
        path.write_text(text)
        self.addCleanup(shutil.rmtree, str(path.parent), ignore_errors=True)
        return path

    def _spawn(self, config_path, data_dir):
        root = str(Path(__file__).resolve().parents[2])
        environment = dict(os.environ)
        environment["PYTHONPATH"] = root
        environment.pop("RACCOON_LISTENER_TOKEN", None)
        process = subprocess.Popen(
            [sys.executable, "-m", "software.c2.server",
             "--key", base64.b64encode(os.urandom(32)).decode(),
             "--config", str(config_path),
             "--port", str(_free_port()),
             "--operator-port", str(_free_port()),
             "--data-dir", str(data_dir)],
            cwd=root, env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        self.addCleanup(self._reap, process)
        return process

    @staticmethod
    def _reap(process):
        if process.poll() is None:
            process.kill()
        process.wait(timeout=30)
        # Closed explicitly: a killed child's pipes are otherwise left for
        # the garbage collector, which reports them as a ResourceWarning
        # and puts it in the middle of the suite's output.
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()

    def test_a_carrier_key_that_belongs_to_the_leg_is_fatal_at_startup(self):
        # `local_port` is a real setting on the *implant's* side and has
        # no reader on this one. Refused rather than ignored, and told
        # which block it belongs to, because the two blocks read almost
        # identically and mean opposite things.
        process = self._spawn(self._config(
            "c2:\n"
            "  gsocket_carrier:\n"
            "    - name: raccoon-01\n"
            "      identity: raccoon-01\n"
            "      beacon_host: 127.0.0.1\n"
            "      beacon_port: 8443\n"
            "      binary_path: /usr/bin/gs-netcat\n"
            "      local_port: 16443\n"), tempfile.mkdtemp())
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.fail("the server started with a carrier block it cannot "
                      "read; nothing at start-up called load_carriers")
        self.assertNotEqual(process.returncode, 0)
        stderr = process.stderr.read()
        self.assertIn("local_port", stderr)
        self.assertIn("c2.fallback.gsocket", stderr,
                      "the refusal does not say which block the key "
                      "belongs to")

    def test_a_valid_carrier_block_starts_the_server_and_its_secret_store(self):
        data_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, data_dir, ignore_errors=True)
        process = self._spawn(self._config(
            "c2:\n"
            "  gsocket_carrier:\n"
            "    - name: raccoon-01-carrier\n"
            "      identity: raccoon-01\n"
            "      enabled: false\n"
            "      beacon_host: 127.0.0.1\n"
            "      beacon_port: 8443\n"
            "      binary_path: %s\n" % FAKE_GS_NETCAT), data_dir)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            pass                        # still running: it started
        else:
            self.fail("the server exited with %d; its error output was: %s"
                      % (process.returncode, process.stderr.read()[:600]))

        store = Path(data_dir) / "gsocket" / "secrets.json"
        self.assertTrue(store.exists(),
                        "the carrier supervisor was built without a secret "
                        "store, so nothing could ever be started")
        self.assertEqual(stat.S_IMODE(store.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
