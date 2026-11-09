"""The tunnel server as a process, its two routes, and the panel.

Three things are under test here and they are deliberately kept apart,
because the whole point of this task is that the operator surface has
**two objects and not one**:

  * `python3 -m software.c2.tunnel` -- the supervised process. One
    `control-port <n>` line on stdout and never stdout again, every log
    line on stderr, and no secret anywhere on its command line, because
    `ps` is readable by every user on the host.
  * `GET /api/server/tunnel` and the two action routes. The tunnel
    **server** starts and stops immediately and drops every endpoint with
    it; an **endpoint** is an agent's tunnel, so stopping one queues a
    `tunnel stop` task that takes effect at the next check-in and shows as
    pending with the expected time until the agent confirms.
  * the panel markup, read out of the page the server actually serves.

The page is a Python string and this project has no JavaScript runner, so
the panel checks locate the construct they are about and assert on it --
the shape `test_listeners.py` established for the Listeners panel.

No test here binds a fixed port. The team server's sockets are bound on 0
and read back, and the one SOCKS port range handed to a child comes from
a probe: `test_tunnel_config.py` left a note that the task which starts
binding those ports has to apply that rule again, and this is that task.
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from software.c2 import server as server_mod
from software.c2.server import ServerCrypto, create_app

_REPO = Path(__file__).resolve().parents[2]

# What a supervised child authenticates its control socket with. Not the
# operator token: see listeners/supervisor.py.
_CONTROL_TOKEN = "control-token-for-tests"


def _free_port() -> int:
    """A port that was free a moment ago.

    Inherently racy, and that is exactly why a configuration file names a
    fixed port while a test never does: an operator needs the port the
    beacon was built with, a test needs one no other test is using now.
    """
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def _pid_alive(pid: int) -> bool:
    """Whether that pid still answers. Used to hold a stop to its word."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class _FakeTunnelSupervisor:
    """A `TunnelSupervisor` that spawns nothing and records what it was asked.

    The real one is exercised through the child-process tests above; these
    routes are about what an operator is told, so the state is canned and
    every call is recorded -- `test_an_unknown_action_is_404_and_never_
    reaches_the_supervisor` is an assertion about this list.
    """

    def __init__(self, endpoints=(), state="running", managed=True):
        self.calls = []
        self.endpoints = [dict(row) for row in endpoints]
        self.state = state
        self.managed = managed

    def status(self):
        self.calls.append("status")
        return {
            "state": self.state,
            "can_control": self.managed,
            "pid": 4242 if self.state == "running" else None,
            "detail": "up for 12.0s" if self.state == "running" else "",
            "bind_host": "0.0.0.0",
            "bind_port": 8446,
            "socks_port_first": 19050,
            "socks_port_last": 19099,
            "crypto": "openssl" if self.state == "running" else None,
            "endpoints": [dict(row) for row in self.endpoints]
            if self.state == "running" else [],
        }

    def start(self):
        self.calls.append("start")
        self.state = "running"
        return self.status()

    def stop(self):
        self.calls.append("stop")
        self.state = "stopped"
        return self.status()


def _endpoint(identity="a1b2c3d4e5f6", **over):
    """One `TunnelServer.endpoints()` row as the child reports it.

    `agent` and `linked` are None and False here on purpose: the child has
    no fleet table, so the route is what links a row to an agent, and
    these two fields are what it overwrites.
    """
    row = {
        "identity": identity,
        "port": 19050,
        "state": "connected",
        "implant_id": "implant-" + identity,
        "agent": None,
        "linked": False,
        "hostname": "WS-1",
        "os": "Windows 10",
        "peer": "198.51.100.7:51515",
        "sessions": 2,
        "bytes_in": 4096,
        "bytes_out": 2048,
        "last_seen_age": 3.0,
        "connected_for": 120.0,
        "crypto": "openssl",
        "socks": {"identity": identity, "port": 19050, "serving": True,
                  "sessions": 2, "max_sessions": 64, "pending": 0,
                  "max_pending": 64, "accepted": 9, "carried": 7,
                  "bytes_in": 4096, "bytes_out": 2048, "refused": 1,
                  "refused_auth": 1, "refused_capacity": 0,
                  "refused_command": 0, "refused_address": 0,
                  "refused_tunnel": 0, "refused_protocol": 0,
                  "refused_timeout": 0, "refused_pending": 0,
                  "refused_threads": 0},
        "socks_detail": "",
        "username": identity,
        "password": "socks-password-for-tests",
    }
    row.update(over)
    return row


class _RouteCase(unittest.TestCase):
    """A test client, the fleet cleared around every test."""

    TOKEN = "operator-token-for-tests"

    def setUp(self):
        for store in (server_mod.agents, server_mod.task_queues,
                      server_mod.history, server_mod.results):
            self.addCleanup(store.clear)
            store.clear()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.data_dir = Path(self._tmp.name)

    def client(self, supervisor):
        app = create_app(ServerCrypto(b"k" * 32), self.TOKEN, self.data_dir,
                         tunnel_supervisor=supervisor)
        return app.test_client()

    def auth(self):
        return {"Authorization": "Bearer %s" % self.TOKEN}

    def agent(self, implant_id, interval=300, last_seen_ago=0.0):
        """Put one agent in the fleet the way a registration does."""
        name = "probe-%d" % (len(server_mod.agents) + 1)
        server_mod.agents[name] = {
            "id": implant_id,
            "agent_id": name,
            "hostname": "WS-1",
            "os": "Windows 10",
            "interval": interval,
            "last_seen": "now",
            "_last_seen_ts": time.time() - last_seen_ago,
        }
        server_mod.task_queues[name] = []
        server_mod.history[name] = []
        return name


class TestTheTunnelProcess(unittest.TestCase):
    """`python3 -m software.c2.tunnel`: the supervised process itself."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def spawn(self, control_token=_CONTROL_TOKEN):
        # The SOCKS range is one probed port, not a literal: this process
        # binds a port out of that range the moment an endpoint connects.
        # No endpoint connects in these tests, so nothing is bound -- and
        # the range still comes from a probe, because the note in
        # test_tunnel_config.py asked this task to re-apply that rule
        # rather than inherit the assumption that the range is inert.
        socks = _free_port()
        command = [sys.executable, "-m", "software.c2.tunnel",
                   "--bind-host", "127.0.0.1", "--bind-port", "0",
                   "--socks-port-first", str(socks),
                   "--socks-port-last", str(socks),
                   "--key-store", str(self.root / "keys.json"),
                   "--state-path", str(self.root / "ports.json"),
                   "--control-port", "0"]
        env = dict(os.environ, PYTHONPATH=str(_REPO), PYTHONUNBUFFERED="1")
        env.pop("RACCOON_CONTROL_TOKEN", None)
        if control_token is not None:
            env["RACCOON_CONTROL_TOKEN"] = control_token
        child = subprocess.Popen(command, cwd=str(_REPO), env=env,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        self.addCleanup(self._reap, child)
        return child

    def _reap(self, child):
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=20)
        for stream in (child.stdout, child.stderr):
            if stream is not None:
                stream.close()

    @staticmethod
    def _ask(port, token, verb="status"):
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            sock.sendall(json.dumps({"token": token,
                                     "verb": verb}).encode() + b"\n")
            sock.settimeout(10)
            raw = b""
            while b"\n" not in raw and len(raw) < 1 << 20:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
        return json.loads(raw.split(b"\n", 1)[0])

    def test_tunnel_main_prints_a_control_port_line_and_nothing_else_to_stdout(self):
        child = self.spawn()
        first = child.stdout.readline().strip()
        self.assertRegex(first, r"^control-port \d+$")
        port = int(first.split(" ", 1)[1])

        # The line is true, not decoration: the port answers the one verb
        # this surface has, over loopback, with the token from the
        # environment.
        answer = self._ask(port, _CONTROL_TOKEN)
        self.assertEqual(answer.get("pid"), child.pid, answer)
        self.assertIn("endpoints", answer)
        self.assertEqual(answer["control_address"][0], "127.0.0.1")

        # And then stdout is finished with. Asked for after the process has
        # done its talking: a listener that logged to stdout would corrupt
        # the one line a supervisor parses.
        child.terminate()
        self.assertEqual(child.wait(timeout=30), 0)
        rest = child.stdout.read()
        self.assertEqual(rest, "", "the process wrote to stdout again")
        self.assertIn("127.0.0.1", child.stderr.read(),
                      "nothing was logged to stderr at all")

    def test_no_secret_is_accepted_as_a_command_line_argument(self):
        from software.c2.tunnel import __main__ as tunnel_main

        options = set()
        for action in tunnel_main._parser()._actions:
            options.update(action.option_strings)
        # Named one by one rather than matched by substring: `--key-store`
        # is a path to a file and must stay allowed, and a looser check
        # that forbade "key" would forbid it.
        for banned in ("--psk", "--token", "--control-token", "--password",
                       "--socks-password", "--secret", "--key", "--enc-key",
                       "--operator-token", "--listener-token"):
            self.assertNotIn(banned, options,
                             "%s puts a secret in ps" % banned)

        # The positive half: the one secret this process needs comes from
        # the environment, and without it there is no control socket at
        # all -- the same shape listeners/__main__.py has.
        child = self.spawn(control_token=None)
        self.assertEqual(child.stdout.readline().strip(), "control-port none")
        child.terminate()
        child.wait(timeout=30)
        self.assertIn("RACCOON_CONTROL_TOKEN", child.stderr.read(),
                      "the refusal does not name the variable to set")

    def test_a_connected_endpoint_gets_a_socks_port_on_its_assigned_number(self):
        """The reconciliation, with the binding faked.

        What this holds is that a SOCKS front is opened once per connected
        identity, on the port the port table assigned it and not an
        ephemeral one, and that a second pass does not open a second.
        """
        from software.c2.tunnel import __main__ as tunnel_main

        made = []

        class _Front:
            def __init__(self, tunnel, identity, bind_port, username,
                         password, **kw):
                self.identity = identity
                self.port = bind_port
                self.username = username
                self.password = password
                self.started = 0
                self.stopped = 0
                made.append(self)

            def start(self):
                self.started += 1

            def stop(self):
                self.stopped += 1

            def stats(self):
                return {"identity": self.identity, "port": self.port,
                        "serving": True}

        fronts = tunnel_main._Fronts(object(), factory=_Front)
        self.addCleanup(fronts.stop_all)
        rows = [{"identity": "one", "port": 19051, "state": "connected"},
                {"identity": "two", "port": 19052, "state": "disconnected"}]
        fronts.reconcile(rows)
        fronts.reconcile(rows)

        self.assertEqual([(f.identity, f.port) for f in made],
                         [("one", 19051)],
                         "a front per connected identity, opened once")
        self.assertEqual(made[0].started, 1)
        self.assertTrue(made[0].password, "no SOCKS credential was generated")

        decorated = fronts.decorate(rows[0])
        self.assertEqual(decorated["socks"]["port"], 19051)
        self.assertEqual(decorated["username"], made[0].username)
        self.assertEqual(decorated["password"], made[0].password)
        # A disconnected identity has no port open and says so rather than
        # reporting an empty row of counters.
        quiet = fronts.decorate(rows[1])
        self.assertIsNone(quiet["socks"])
        self.assertTrue(quiet["socks_detail"])


class TestTheRowFixtureMatchesTheRealThing(unittest.TestCase):
    """`_endpoint()` is hand-written, so something must hold it honest.

    No route or panel test ever sees a row from a real `TunnelServer`,
    and the supervisor tests that start a real child have no endpoint
    connected, so they see an empty list. Rename a key in the tunnel
    server and every test in this file would stay green while the panel
    rendered blanks.
    """

    def test_the_fixture_only_uses_keys_a_real_row_has(self):
        from software.c2.tunnel import __main__ as tunnel_main
        from software.c2.tunnel.keys import KeyStore
        from software.c2.tunnel.server import TunnelServer

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        # A port table with one identity already in it, which is what a
        # restart reads: `endpoints()` then reports that identity as
        # disconnected without anything having to connect. The port is
        # recorded, never bound.
        port = _free_port()
        (root / "ports.json").write_text(
            json.dumps({"version": 1, "ports": {"a1b2c3d4e5f6": port}}),
            encoding="utf-8")
        server = TunnelServer(KeyStore(root / "keys.json"), "127.0.0.1", 0,
                              (port, port), str(root / "ports.json"))
        rows = server.endpoints()
        self.assertEqual([row["identity"] for row in rows], ["a1b2c3d4e5f6"])

        # Plus what the process adds on the way out through its control
        # socket, which is the other half of what the route receives.
        real = set(tunnel_main._Fronts(server).decorate(rows[0]))
        self.assertLessEqual(
            set(_endpoint()), real,
            "the fixture carries keys a real endpoint row does not: %s"
            % sorted(set(_endpoint()) - real))


class TestTheSupervisor(unittest.TestCase):
    """`TunnelSupervisor`: the real child, started and stopped for real.

    The routes above use a fake, because they are about what an operator
    is told. This is about whether the process arrives and leaves.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.data_dir = Path(self._tmp.name)

    def supervisor(self, managed=True, **over):
        from software.c2.tunnel.supervisor import TunnelSupervisor

        # bind_port 0 so the child picks its own and reports it back; the
        # SOCKS range is one probed port, and no endpoint connects here,
        # so nothing out of it is bound.
        block = {"bind_host": "127.0.0.1", "bind_port": 0,
                 "socks_port_first": _free_port(),
                 "socks_port_last": _free_port(),
                 "keepalive_seconds": 30.0}
        block["socks_port_last"] = max(block["socks_port_first"],
                                       block["socks_port_last"])
        block.update(over)
        made = TunnelSupervisor(block, self.data_dir, managed=managed)
        self.addCleanup(made.stop_all)
        return made

    def test_start_brings_a_child_up_and_status_reports_what_it_says(self):
        supervisor = self.supervisor()
        state = supervisor.start()
        self.assertEqual(state["state"], "running")
        self.assertTrue(state["pid"])
        # Read over the child's control socket, which is the only way the
        # team server learns any of this: a port it actually bound, the
        # crypto path of that process, and an endpoint list that is empty
        # rather than missing.
        self.assertEqual(state["address"][0], "127.0.0.1")
        self.assertTrue(state["address"][1])
        self.assertIn(state["crypto"], ("openssl", "pure-python"))
        self.assertEqual(state["endpoints"], [])
        self.assertIn("up for", state["detail"])
        # The key store was created by the child, under the data
        # directory the generator writes to.
        self.assertTrue(supervisor.key_store_path().exists())

    def test_a_second_start_is_refused_with_the_pid(self):
        from software.c2.tunnel.supervisor import SupervisorError

        supervisor = self.supervisor()
        pid = supervisor.start()["pid"]
        with self.assertRaises(SupervisorError) as caught:
            supervisor.start()
        self.assertIn(str(pid), str(caught.exception))

    def test_a_child_that_cannot_bind_refuses_with_its_own_reason(self):
        from software.c2.tunnel.supervisor import SupervisorError

        # Held open for the duration, so this is not the free-port-then-
        # bind race: the port is in use because this test is using it.
        taken = socket.socket()
        self.addCleanup(taken.close)
        taken.bind(("127.0.0.1", 0))
        taken.listen(1)

        supervisor = self.supervisor(bind_port=taken.getsockname()[1])
        with self.assertRaises(SupervisorError) as caught:
            supervisor.start()
        reason = str(caught.exception)
        # The child's own sentence, carried up from its stderr. Without
        # it the panel would say only that the process is not running,
        # and "address already in use" is the one thing that would have
        # told the operator what to do about it.
        self.assertIn("could not listen on", reason)
        self.assertIn(str(taken.getsockname()[1]), reason)
        # And nothing is left behind claiming to be running.
        self.assertEqual(supervisor.status()["state"], "stopped")

    def test_stop_reaps_the_child_and_stopping_twice_is_refused(self):
        from software.c2.tunnel.supervisor import SupervisorError

        supervisor = self.supervisor()
        pid = supervisor.start()["pid"]
        state = supervisor.stop()
        self.assertEqual(state["state"], "stopped")
        self.assertIsNone(state["pid"])
        # Reaped, not merely signalled: an unreaped child is a zombie
        # whose pid still answers, and status would keep calling it alive.
        self.assertFalse(_pid_alive(pid))
        with self.assertRaises(SupervisorError) as caught:
            supervisor.stop()
        self.assertIn("nothing to stop", str(caught.exception))

    def test_an_unmanaged_deployment_says_why_it_cannot_act(self):
        from software.c2.tunnel.supervisor import SupervisorError

        supervisor = self.supervisor(managed=False)
        state = supervisor.status()
        self.assertEqual(state["state"], "unmanaged")
        self.assertFalse(state["can_control"])
        self.assertTrue(state["detail"])
        for action in ("start", "stop"):
            with self.subTest(action=action):
                with self.assertRaises(SupervisorError) as caught:
                    getattr(supervisor, action)()
                self.assertIn("does not manage", str(caught.exception))

    def test_a_block_that_cannot_be_run_is_refused_by_field_name(self):
        from software.c2.tunnel.supervisor import tunnel_server_config

        self.assertIsNone(tunnel_server_config({}))
        self.assertIsNone(tunnel_server_config(
            {"c2": {"tunnel_server": {"enabled": False, "bind_port": 1}}}))
        good = tunnel_server_config({"c2": {"tunnel_server": {
            "enabled": True, "bind_host": "0.0.0.0", "bind_port": 8446,
            "socks_port_first": 19050, "socks_port_last": 19099,
            "keepalive_seconds": 30}}})
        self.assertEqual(good["bind_port"], 8446)
        self.assertEqual(good["keepalive_seconds"], 30.0)

        for field, block in (
                ("bind_port", {"bind_port": 0}),
                ("bind_port", {"bind_port": "8446"}),
                ("socks_port_first", {"socks_port_first": 70000}),
                ("bind_host", {"bind_host": ""}),
                ("keepalive_seconds", {"keepalive_seconds": 0}),
                ("socks_port_first", {"socks_port_first": 19099,
                                      "socks_port_last": 19050})):
            with self.subTest(block=block):
                asked = dict({"enabled": True}, **block)
                with self.assertRaises(ValueError) as caught:
                    tunnel_server_config({"c2": {"tunnel_server": asked}})
                self.assertIn(field, str(caught.exception))


class TestTheTunnelRoutes(_RouteCase):
    """What `/api/server/tunnel` tells an operator, and what it refuses."""

    def test_get_tunnel_lists_endpoints_with_port_sessions_and_crypto_path(self):
        supervisor = _FakeTunnelSupervisor(endpoints=[_endpoint()])
        name = self.agent("implant-a1b2c3d4e5f6")
        reply = self.client(supervisor).get("/api/server/tunnel",
                                            headers=self.auth())
        self.assertEqual(reply.status_code, 200)
        body = reply.get_json()

        # The server block and the endpoint rows are separate objects in
        # the answer, because they are separate objects on the screen.
        self.assertEqual(body["server"]["state"], "running")
        self.assertEqual(len(body["endpoints"]), 1)
        row = body["endpoints"][0]
        self.assertEqual(row["identity"], "a1b2c3d4e5f6")
        self.assertEqual(row["port"], 19050)
        self.assertEqual(row["sessions"], 2)
        self.assertEqual(row["socks"]["max_sessions"], 64)
        # The crypto path, on the row. A tunnel on the pure-Python cipher
        # runs at 50-200 KB/s, and without this the operator debugs a
        # network fault for an afternoon.
        self.assertEqual(row["crypto"], "openssl")
        # And the fleet link the child could not make for itself.
        self.assertEqual(row["agent"], name)
        self.assertTrue(row["linked"])
        self.assertEqual(row["interval"], 300)

    def test_server_stop_is_immediate_and_the_response_says_it_drops_every_endpoint(self):
        supervisor = _FakeTunnelSupervisor(
            endpoints=[_endpoint("aaa"), _endpoint("bbb", port=19051)])
        client = self.client(supervisor)
        reply = client.post("/api/server/tunnel/stop", headers=self.auth())
        self.assertEqual(reply.status_code, 200)
        body = reply.get_json()

        self.assertEqual(supervisor.calls.count("stop"), 1)
        self.assertEqual(body["server"]["state"], "stopped")
        # Immediate: nothing about this is pending, which is the one way
        # the answer differs in kind from an endpoint stop.
        self.assertFalse(body["pending"])
        self.assertEqual(body["endpoints"], [])
        self.assertEqual(body["dropped"], 2)
        self.assertIn("every endpoint", body["detail"])
        self.assertIn("2", body["detail"])

    def test_endpoint_stop_queues_a_task_and_reports_pending_with_an_expected_time(self):
        supervisor = _FakeTunnelSupervisor(endpoints=[_endpoint()])
        name = self.agent("implant-a1b2c3d4e5f6", interval=120,
                          last_seen_ago=20.0)
        client = self.client(supervisor)
        reply = client.post("/api/server/tunnel/endpoint/a1b2c3d4e5f6/stop",
                            headers=self.auth())
        self.assertEqual(reply.status_code, 200)
        body = reply.get_json()

        # It queued a task for that agent, and nothing reached the
        # supervisor: an endpoint is not the server.
        self.assertNotIn("stop", supervisor.calls)
        queue = server_mod.task_queues[name]
        self.assertEqual([(t["cmd"], t["args"]) for t in queue],
                         [("tunnel", "stop")])
        self.assertEqual(body["task_id"], queue[0]["id"])

        # And the operator is told it has not happened yet, with when to
        # expect it. 120 s interval, last seen 20 s ago, so about 100 s.
        self.assertTrue(body["pending"])
        self.assertEqual(body["interval"], 120)
        self.assertAlmostEqual(body["expected_seconds"], 100, delta=5)
        self.assertRegex(body["expected"], r"^\d{2}:\d{2}$")
        self.assertIn("next check-in", body["detail"])

        # The row says the same thing, so a panel that polls instead of
        # reading the action's answer tells the same story.
        row = client.get("/api/server/tunnel",
                         headers=self.auth()).get_json()["endpoints"][0]
        self.assertTrue(row["pending"])
        self.assertEqual(row["pending_action"], "stop")
        self.assertEqual(row["expected"], body["expected"])

    def test_endpoint_stop_for_an_unknown_identity_is_404(self):
        supervisor = _FakeTunnelSupervisor(endpoints=[_endpoint()])
        client = self.client(supervisor)
        reply = client.post("/api/server/tunnel/endpoint/nope/stop",
                            headers=self.auth())
        # 404 for a name that does not exist, 409 for a name that does and
        # a state that will not have it: the split api_listener_action
        # makes, so a panel can tell "you typed it wrong" from "it is
        # already running".
        self.assertEqual(reply.status_code, 404)
        self.assertIn("nope", reply.get_json()["error"])
        self.assertEqual(supervisor.calls, ["status"])

        # The same identity, known but with no fleet agent above it, is a
        # 409: there is nothing to task.
        unlinked = _FakeTunnelSupervisor(endpoints=[_endpoint("lonely")])
        refused = self.client(unlinked).post(
            "/api/server/tunnel/endpoint/lonely/stop", headers=self.auth())
        self.assertEqual(refused.status_code, 409)
        self.assertIn("lonely", refused.get_json()["error"])

    def test_an_unknown_action_is_404_and_never_reaches_the_supervisor(self):
        supervisor = _FakeTunnelSupervisor(endpoints=[_endpoint()])
        self.agent("implant-a1b2c3d4e5f6")
        client = self.client(supervisor)
        for path in ("/api/server/tunnel/restart",
                     "/api/server/tunnel/status",
                     "/api/server/tunnel/endpoint/a1b2c3d4e5f6/restart"):
            with self.subTest(path=path):
                reply = client.post(path, headers=self.auth())
                self.assertEqual(reply.status_code, 404)
                self.assertIn("start and stop", reply.get_json()["error"])
        self.assertEqual(supervisor.calls, [],
                         "an unknown action reached the supervisor")
        self.assertEqual(server_mod.task_queues["probe-1"], [],
                         "an unknown action queued a task")

    def test_an_unconfigured_deployment_says_so_rather_than_failing(self):
        client = self.client(None)
        body = client.get("/api/server/tunnel", headers=self.auth()).get_json()
        self.assertEqual(body["endpoints"], [])
        self.assertFalse(body["managed"])
        self.assertIn("c2.tunnel_server", body["detail"])
        # And a button pressed against it refuses with a reason rather
        # than calling a method on None and answering 500.
        for path in ("/api/server/tunnel/start",
                     "/api/server/tunnel/endpoint/anything/stop"):
            with self.subTest(path=path):
                reply = client.post(path, headers=self.auth())
                self.assertEqual(reply.status_code, 409)
                self.assertIn("no tunnel server", reply.get_json()["error"])

    def test_an_unlinked_endpoint_is_shown_as_unlinked_not_hidden(self):
        # A Pi started from systemd has no fleet member above it, and that
        # is a supported deployment: the row appears, marked unlinked.
        supervisor = _FakeTunnelSupervisor(
            endpoints=[_endpoint("pi-dropbox", implant_id=None),
                       _endpoint("desk", implant_id="implant-desk",
                                 port=19051)])
        name = self.agent("implant-desk")
        body = self.client(supervisor).get(
            "/api/server/tunnel", headers=self.auth()).get_json()

        rows = {row["identity"]: row for row in body["endpoints"]}
        self.assertEqual(sorted(rows), ["desk", "pi-dropbox"])
        self.assertFalse(rows["pi-dropbox"]["linked"])
        self.assertIsNone(rows["pi-dropbox"]["agent"])
        self.assertIsNone(rows["pi-dropbox"]["interval"])
        self.assertEqual(rows["desk"]["agent"], name)
        self.assertTrue(rows["desk"]["linked"])

    def test_a_refusal_from_the_endpoint_child_reaches_the_row(self):
        # The child's stderr is DEVNULL, so the throughput gate's careful
        # sentence and the config pre-flight's reach nobody: the operator
        # sees exit_code 1 at the next check-in. The `tunnel` verb returns
        # that sentence as its task output, so the row carries it.
        supervisor = _FakeTunnelSupervisor(endpoints=[_endpoint()])
        name = self.agent("implant-a1b2c3d4e5f6")
        refusal = ("[error] Not starting a tunnel child: this host has no "
                   "libcrypto, so the tunnel would run on pure-Python "
                   "AES-GCM")
        server_mod.history[name] = [
            {"task_id": "t1", "cmd": "tunnel", "args": "start",
             "status": "ok", "output": refusal},
        ]
        row = self.client(supervisor).get(
            "/api/server/tunnel",
            headers=self.auth()).get_json()["endpoints"][0]
        self.assertEqual(row["refusal"], refusal)

    def test_the_route_carries_no_psk_and_no_control_token(self):
        supervisor = _FakeTunnelSupervisor(endpoints=[_endpoint()])
        supervisor.control_token = "control-token-not-for-the-panel"
        self.agent("implant-a1b2c3d4e5f6")
        blob = json.dumps(self.client(supervisor).get(
            "/api/server/tunnel", headers=self.auth()).get_json())
        self.assertNotIn(supervisor.control_token, blob)
        self.assertNotIn("psk", blob.lower())

    def test_the_routes_need_the_operator_token(self):
        client = self.client(_FakeTunnelSupervisor())
        self.assertEqual(client.get("/api/server/tunnel").status_code, 401)
        self.assertEqual(
            client.post("/api/server/tunnel/stop").status_code, 401)
        self.assertEqual(client.post(
            "/api/server/tunnel/endpoint/x/stop").status_code, 401)


class TestTheSocketPolicy(unittest.TestCase):
    """A real team server on two sockets, which is the only way to test this.

    `app.test_client()` goes through no socket at all, so `SERVER_PORT` is
    not meaningful there and the policy is inert: the split has to be
    exercised over TCP.
    """

    TOKEN = "operator-token-for-tests"

    def setUp(self):
        import logging

        from werkzeug.serving import make_server

        for store in (server_mod.agents, server_mod.task_queues,
                      server_mod.history, server_mod.results):
            self.addCleanup(store.clear)
            store.clear()
        quiet = logging.getLogger("werkzeug")
        previous = quiet.level
        quiet.setLevel(logging.ERROR)
        self.addCleanup(quiet.setLevel, previous)

        self.supervisor = _FakeTunnelSupervisor(endpoints=[_endpoint()])
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        operator = make_server("127.0.0.1", 0, None, threaded=True)
        self.addCleanup(operator.server_close)
        agent = make_server("127.0.0.1", 0, None, threaded=True)
        self.addCleanup(agent.server_close)
        self.operator_port = operator.server_port
        self.agent_port = agent.server_port
        app = create_app(
            ServerCrypto(b"k" * 32), self.TOKEN, Path(tmp.name),
            server_config={"host": "127.0.0.1", "port": self.agent_port,
                           "operator_host": "127.0.0.1",
                           "operator_port": self.operator_port},
            operator_port=self.operator_port,
            tunnel_supervisor=self.supervisor)
        self.servers = (operator, agent)
        for srv in self.servers:
            srv.app = app
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(lambda: [s.shutdown() for s in self.servers])

    def _request(self, port, path, method="GET"):
        request = urllib.request.Request(
            "http://127.0.0.1:%d%s" % (port, path), method=method)
        request.add_header("Authorization", "Bearer %s" % self.TOKEN)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def test_the_routes_are_operator_socket_only(self):
        # The cover the catch-all gives anything it does not recognise. A
        # 403 or a 404 here would tell a prober what is listening, and
        # these routes can start and stop processes.
        cover = self._request(self.agent_port, "/no/such/page")
        self.assertEqual(cover[0], 200)

        for method, path in (("GET", "/api/server/tunnel"),
                             ("POST", "/api/server/tunnel/start"),
                             ("POST", "/api/server/tunnel/stop"),
                             ("POST", "/api/server/tunnel/endpoint/x/stop")):
            with self.subTest(method=method, path=path):
                self.assertEqual(
                    self._request(self.agent_port, path, method), cover)
        self.assertEqual(self.supervisor.calls, [],
                         "a request on the agent socket reached the "
                         "supervisor")

        # And the same requests on the operator socket are served.
        status, _body = self._request(self.operator_port, "/api/server/tunnel")
        self.assertEqual(status, 200)


class TestTheTunnelPanel(unittest.TestCase):
    """What the served page says about the two objects.

    Read out of the page the server serves, not out of the source, so a
    change that breaks the template fails here rather than in a browser.
    """

    @classmethod
    def setUpClass(cls):
        import logging

        from werkzeug.serving import make_server

        quiet = logging.getLogger("werkzeug")
        previous = quiet.level
        quiet.setLevel(logging.ERROR)
        tmp = tempfile.TemporaryDirectory()
        server = make_server("127.0.0.1", 0, None, threaded=True)
        server.app = create_app(ServerCrypto(b"k" * 32), "t", Path(tmp.name))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d/" % server.server_port,
                    timeout=15) as response:
                cls.page = response.read().decode("utf-8", "replace")
        finally:
            server.shutdown()
            server.server_close()
            tmp.cleanup()
            quiet.setLevel(previous)
        start = cls.page.index("function showTunnel()")
        cls.body = cls.page[start:cls.page.index("</script>", start)]

    def test_the_header_has_a_tunnel_button_after_the_listener_one(self):
        listeners = self.page.index("showListeners()")
        tunnel = self.page.index("showTunnel()")
        loot = self.page.index("showLootViewer()")
        self.assertLess(listeners, tunnel)
        self.assertLess(tunnel, loot)

    def test_the_panel_warns_that_stopping_the_server_drops_every_endpoint(self):
        """The warning is in a `confirm()` the stop button goes through.

        **What this does not hold:** the assertion below is on source
        order, so it proves the question is written before the request is
        built and nothing stronger. A bare `confirm(...)` whose answer was
        discarded, or an `||` where the code has `&&`, would still pass.
        There is no JavaScript runner in this repository and the panel
        needs a DOM rather than a function, so this is the stopping point
        rather than a step towards one -- read it as "the question is
        asked first", not as "the gate works".
        """
        self.assertIn("every endpoint", self.body)
        confirm = [line for line in self.body.splitlines()
                   if "confirm(" in line]
        self.assertTrue(confirm, "the server stop asks nothing before acting")
        window = self.body[self.body.index("confirm("):]
        self.assertLess(self.body.index("confirm("),
                        self.body.index('"/api/server/tunnel/" + action'),
                        "the request is built before the question is asked")
        self.assertIn("endpoint", window[:600].lower())

    def test_a_pending_endpoint_stop_shows_the_expected_time(self):
        # The latency is displayed rather than hidden: a stop that
        # silently takes five minutes is the anti-goal.
        self.assertIn("pending until ~", self.body)
        window = self.body[self.body.index("pending until ~") - 300:
                           self.body.index("pending until ~") + 300]
        self.assertIn("esc(row.expected)", window)
        self.assertIn("disabled", window,
                      "a pending row still offers the button that did it")

    def test_the_two_objects_are_separate_blocks_in_the_panel(self):
        # One start/stop for the server, its own per-row control for an
        # endpoint, and the identity of each button is in the attribute
        # the handler reads -- not in one shared button.
        self.assertIn("data-tunnel-server", self.body)
        self.assertIn("data-tunnel-endpoint", self.body)
        self.assertLess(self.body.index("data-tunnel-server"),
                        self.body.index("data-tunnel-endpoint"),
                        "the endpoints are drawn above the server block")

    def test_the_row_shows_the_crypto_path_and_any_refusal(self):
        self.assertIn("esc(row.crypto)", self.body)
        self.assertIn("esc(row.refusal)", self.body)
        slow = self.body[self.body.index("esc(row.crypto)") - 400:
                         self.body.index("esc(row.crypto)") + 400]
        self.assertIn("pure-python", slow,
                      "the panel never says which path is the slow one")

    def test_every_value_an_endpoint_influences_is_escaped(self):
        # A row's hostname, OS and peer come from a HELLO written by
        # whatever is at the far end of the tunnel, and its refusal from a
        # child process. Each goes through esc(), and the handlers are
        # attached in JavaScript rather than built into an attribute.
        for field in ("identity", "state", "hostname", "os", "peer",
                      "refusal", "crypto"):
            self.assertIn("esc(row.%s)" % field, self.body,
                          "row.%s reaches the page unescaped" % field)
        self.assertNotIn('onclick="tunnel', self.body,
                         "a handler body is built as a string")
        self.assertIn("addEventListener", self.body)

    def test_the_panel_names_the_socks_credential_for_proxychains(self):
        # The port authenticates per RFC 1929, so the operator needs the
        # credential where they are looking at the port.
        self.assertIn("esc(row.username)", self.body)
        self.assertIn("esc(row.password)", self.body)


# New test classes belong above this guard; never append below it.
if __name__ == "__main__":
    unittest.main()
