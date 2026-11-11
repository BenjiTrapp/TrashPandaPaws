"""The tunnel server as a process, its two routes, and the operator page.

Four things are under test here and they are deliberately kept apart,
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
  * the Beacon Gen form's tunnel section, read out of that same page: the
    request each delivery path posts, and the one client-side check,
    which mirrors the generator route's refusals and invents none.

The page is a Python string and this project has no JavaScript runner, so
the panel and form checks locate the construct they are about and assert
on it -- the shape `test_listeners.py` established for the Listeners
panel.

No test here binds a fixed port. The team server's sockets are bound on 0
and read back, and the one SOCKS port range handed to a child comes from
a probe: `test_tunnel_config.py` left a note that the task which starts
binding those ports has to apply that rule again, and this is that task.
"""

import json
import os
import re
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


def _child_command_line(pid: int) -> str:
    """The child's argv as the OS shows it: `/proc` on Linux, `ps` elsewhere.

    The same threat `test_no_secret_is_accepted_as_a_command_line_argument`
    reads with, used here to read the opposite -- that an argument which is
    *meant* to be on the line really is, so a mapping that silently dropped
    it is caught.
    """
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as handle:
            return handle.read().replace(b"\x00", b" ").decode(
                "utf-8", "replace").strip()
    except OSError:
        pass
    try:
        done = subprocess.run(["ps", "-o", "command=", "-p", str(pid)],
                              capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return done.stdout.strip()


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
            # The real `TunnelSupervisor.status()` reports these three
            # beside the SOCKS pair, from the same block, so the fake the
            # route tests use carries them too. Off here, which is how
            # the feature ships; the real one's own tests cover it on.
            "shell_port_first": None,
            "shell_port_last": None,
            "shell_transcripts": None,
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
        # Two processes, two paths, and the row carries both: the
        # endpoint's as its HELLO reported it, this team server's as the
        # tunnel-server process read its own. A row that carried one
        # under the name `crypto` said the server's and was read as the
        # endpoint's.
        "endpoint_crypto": "pure-python",
        "server_crypto": "openssl",
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
        # The sibling port that carries a terminal. Its own secret, and
        # distinct from the SOCKS one on purpose: a fixture that reused
        # the value could not tell a panel that printed the wrong one.
        "shell": {"identity": identity, "port": 40300, "serving": True,
                  "sessions": 1, "max_sessions": 4, "pending": 0,
                  "max_pending": 8, "accepted": 3, "carried": 2,
                  "bytes_in": 512, "bytes_out": 1024, "refused": 2,
                  "refused_auth": 2},
        "shell_password": "shell-password-for-tests",
        "shell_detail": "",
        "shell_recording": False,
    }
    row.update(over)
    return row


def _recording(cls, made):
    """`cls`, with every front it builds appended to `made`.

    A factory rather than a replacement, so the class under the test is
    the real one: `ShellFront`'s arguments past `password` are
    keyword-only and a wiring that passed one positionally would raise
    here rather than pass against a stub that took `**kw`.
    """

    def build(*args, **kwargs):
        front = cls(*args, **kwargs)
        made.append(front)
        return front

    return build


class _FakeFront:
    """A front that binds nothing and remembers how it was called.

    Used where what is under test is the reconciliation -- which identity
    gets a front, what credential it was given -- rather than a bound
    port. Two subclasses because the two real classes differ in their
    positional tail: a SOCKS front takes a username before its password
    and a shell front takes only the password, so a stub that accepted
    both shapes would hide exactly the mistake worth catching.
    """

    def __init__(self, identity, bind_port, password, kwargs):
        self.identity = identity
        self.port = bind_port
        self.password = password
        self.kwargs = kwargs
        self.started = 0
        self.stopped = 0

    def start(self):
        self.started += 1

    def stop(self):
        self.stopped += 1

    def stats(self):
        return {"identity": self.identity, "port": self.port,
                "serving": True, "sessions": 0, "refused": 0}


class _FakeSocksFront(_FakeFront):
    def __init__(self, tunnel, identity, bind_port, username, password, **kw):
        _FakeFront.__init__(self, identity, bind_port, password, kw)
        self.username = username


class _FakeShellFront(_FakeFront):
    def __init__(self, tunnel, identity, bind_port, password, **kw):
        _FakeFront.__init__(self, identity, bind_port, password, kw)


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

    def spawn(self, control_token=_CONTROL_TOKEN, socks=None, shell=None,
              transcript_dir=None):
        # The SOCKS range is one probed port, not a literal: this process
        # binds a port out of that range the moment an endpoint connects.
        # No endpoint connects in these tests, so nothing is bound -- and
        # the range still comes from a probe, because the note in
        # test_tunnel_config.py asked this task to re-apply that rule
        # rather than inherit the assumption that the range is inert.
        # A caller that also wants a shell range probes both itself, so
        # that the two cannot come back the same number: the process
        # refuses to start on overlapping ranges, and rightly.
        socks = _free_port() if socks is None else socks
        command = [sys.executable, "-m", "software.c2.tunnel",
                   "--bind-host", "127.0.0.1", "--bind-port", "0",
                   "--socks-port-first", str(socks),
                   "--socks-port-last", str(socks),
                   "--key-store", str(self.root / "keys.json"),
                   "--state-path", str(self.root / "ports.json"),
                   "--control-port", "0"]
        # Absent by default, which is this feature's off state: a shell
        # port is opened because the range was given and for no other
        # reason.
        if shell is not None:
            command += ["--shell-port-first", str(shell[0]),
                        "--shell-port-last", str(shell[1])]
        if transcript_dir is not None:
            command += ["--shell-transcript-dir", str(transcript_dir)]
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

    def _rows(self, count=1, state="connected", shell_detail="", **over):
        """`count` endpoint rows as the tunnel server reports them.

        `shell_port` is what Task 3's port table assigned, and
        `shell_detail` is that table's own reason for there being none.
        Probed ports, because some of these rows are handed to the real
        fronts below and a literal would be a fixed number bound on a
        shared machine.

        **The probes are deduplicated**, the way the two tests that spin
        `while len(ports) < 3` already do: two consecutive probes can
        return the same number, and a row whose SOCKS and shell ports
        were equal would bind one, fail the other, and read as a wiring
        bug rather than as the timing accident it is.
        """
        ports = set()
        while len(ports) < 2 * count:
            ports.add(_free_port())
        ports = sorted(ports)
        rows = []
        for number in range(count):
            row = {"identity": "id-%d" % number,
                   "port": ports[2 * number],
                   "shell_port": ports[2 * number + 1],
                   "state": state, "shell_detail": shell_detail}
            row.update(over)
            rows.append(row)
        return rows

    def test_a_configured_range_opens_a_shell_front_per_connected_identity(self):
        """The reconciliation again, with both real fronts bound.

        Not stubs: `ShellFront` takes its password positionally and
        everything after it by keyword, and its `stats()` has to come out
        in the SOCKS row's shape because the panel reads the two with one
        renderer. A stub taking `**kw` would pass against a call that got
        either of those wrong.
        """
        from software.c2.tunnel import __main__ as tunnel_main
        from software.c2.tunnel.shell import ShellFront
        from software.c2.tunnel.socks import SocksFront

        socks_made, shell_made = [], []
        fronts = tunnel_main._Fronts(
            object(), factory=_recording(SocksFront, socks_made),
            shell_factory=_recording(ShellFront, shell_made),
            shell_enabled=True)
        self.addCleanup(fronts.stop_all)
        rows = self._rows(2)
        rows[1]["state"] = "disconnected"
        fronts.reconcile(rows)
        fronts.reconcile(rows)

        # One shell front, for the connected identity, on the port the
        # shell port table assigned it -- and opened once.
        self.assertEqual([(f.identity, f.port) for f in shell_made],
                         [("id-0", rows[0]["shell_port"])])
        self.assertTrue(shell_made[0].is_serving())
        self.assertEqual(len(socks_made), 1)

        row = fronts.decorate(rows[0])
        self.assertEqual(row["shell"]["port"], rows[0]["shell_port"])
        self.assertTrue(row["shell"]["serving"])
        # The SOCKS row's shape, which is what the panel reads.
        self.assertEqual(row["shell"]["sessions"], 0)
        self.assertEqual(row["shell"]["refused"], 0)
        self.assertTrue(row["shell_password"])
        self.assertEqual(row["shell_detail"], "",
                         "an open shell port carries a reason it has not "
                         "got")
        # And the two ports are two ports: a shell front that bound the
        # SOCKS number would have taken the pivot with it.
        self.assertNotEqual(row["shell"]["port"], row["socks"]["port"])

        # The disconnected identity has neither, and says so.
        quiet = fronts.decorate(rows[1])
        self.assertIsNone(quiet["shell"])
        self.assertIsNone(quiet["shell_password"])
        self.assertTrue(quiet["shell_detail"])

    def test_a_shell_port_that_cannot_be_bound_costs_only_the_shell(self):
        """One unusable number must not take the pivot with it.

        The likeliest failure this wiring has: another process holding
        the number. It is recorded against the row and logged, and the
        SOCKS port -- which is the pivot, and the thing an engagement is
        actually running through -- opens regardless.
        """
        from software.c2.tunnel import __main__ as tunnel_main
        from software.c2.tunnel.shell import ShellFront

        # Held open for the duration, so this is not the probe-then-bind
        # race: the port is in use because this test is using it.
        taken = socket.socket()
        self.addCleanup(taken.close)
        taken.bind(("127.0.0.1", 0))
        taken.listen(1)
        held = taken.getsockname()[1]

        fronts = tunnel_main._Fronts(
            object(), factory=_FakeSocksFront, shell_factory=ShellFront,
            shell_enabled=True)
        self.addCleanup(fronts.stop_all)
        rows = self._rows(1, shell_port=held)
        with self.assertLogs(tunnel_main.logger, level="WARNING") as logged:
            fronts.reconcile(rows)

        row = fronts.decorate(rows[0])
        self.assertIsNone(row["shell"])
        self.assertIn(str(held), row["shell_detail"])
        self.assertIn("could not be opened", row["shell_detail"])
        self.assertIn(str(held), "\n".join(logged.output),
                      "the operator was not told which port it was")
        # The pivot opened, with its own credential, and the row is whole.
        self.assertEqual(row["socks"]["port"], rows[0]["port"])
        self.assertTrue(row["password"])
        self.assertEqual(row["socks_detail"], "")

    def test_no_range_opens_no_shell_front_and_the_status_says_so(self):
        """The single switch, on both sides of it.

        No range configured is not "a front that failed to bind": nothing
        is attempted at all, and the reason an operator reads is the port
        table's own. A shell port is a root shell on the implant host, so
        it opens because somebody configured a range on the server and
        for no other reason -- the listeners' compose profile, again.
        """
        from software.c2.tunnel import __main__ as tunnel_main

        def never(*args, **kwargs):
            raise AssertionError("a shell front was opened with no range "
                                 "configured")

        fronts = tunnel_main._Fronts(
            object(), factory=_FakeSocksFront, shell_factory=never)
        self.addCleanup(fronts.stop_all)
        # What Task 3's row carries when no range is configured: no port,
        # and the reason in `shell_detail`.
        rows = self._rows(1, shell_port=None,
                          shell_detail="no shell_port_range is configured")
        fronts.reconcile(rows)
        row = fronts.decorate(rows[0])
        self.assertIsNone(row["shell"])
        self.assertIsNone(row["shell_password"])
        self.assertFalse(row["shell_recording"])
        self.assertEqual(row["shell_detail"],
                         "no shell_port_range is configured",
                         "the row's own reason was overwritten")
        # The pivot is untouched by any of that.
        self.assertEqual(row["socks"]["port"], rows[0]["port"])

        # And the awkward case: a port table written while a range *was*
        # configured keeps its entries, so a row can arrive with a shell
        # port, no reason of its own, and no port that will ever open.
        # Saying "one opens when the endpoint connects" about an endpoint
        # that is connected would be false.
        stale = self._rows(1)
        fronts.reconcile(stale)
        detail = fronts.decorate(stale[0])["shell_detail"]
        self.assertIn("no shell port range is configured", detail)
        self.assertNotIn("when the endpoint connects", detail)

        # And the process says which it is, over its control socket, with
        # no shell argument on its command line.
        child = self.spawn()
        port = int(child.stdout.readline().strip().split(" ", 1)[1])
        answer = self._ask(port, _CONTROL_TOKEN)
        self.assertIsNone(answer["shell_port_first"], answer)
        self.assertIsNone(answer["shell_port_last"], answer)
        self.assertIsNone(answer["shell_transcripts"], answer)
        # Nothing was created for a feature nobody switched on: the
        # process opened no port and wrote no transcript directory.
        self.assertEqual([p.name for p in self.root.iterdir() if p.is_dir()],
                         [], "a directory was created for a feature that "
                             "is off")

        # Configured, and the same question answers with the range. Three
        # distinct probed ports, so the SOCKS range and the shell range
        # cannot come back as the same number -- an overlap is refused by
        # the process and would be a flake rather than a finding.
        ports = set()
        while len(ports) < 3:
            ports.add(_free_port())
        socks, first, last = sorted(ports)
        recordings = self.root / "recordings"
        served = self.spawn(socks=socks, shell=(first, last),
                            transcript_dir=recordings)
        port = int(served.stdout.readline().strip().split(" ", 1)[1])
        answer = self._ask(port, _CONTROL_TOKEN)
        self.assertEqual([answer["shell_port_first"],
                          answer["shell_port_last"]], [first, last], answer)
        self.assertEqual(answer["shell_transcripts"], str(recordings))

    def test_the_shell_password_is_not_the_socks_password(self):
        """Two ports, two secrets, minted separately.

        Somebody handed the SOCKS credential for a pivot must not thereby
        hold a root terminal on the host, and both are read off the same
        panel row -- so the separation has to be in the mint and not in
        how carefully a row is copied. Twelve identities rather than one,
        because a single pair differing proves nothing about where the
        second one came from.
        """
        from software.c2.tunnel import __main__ as tunnel_main

        fronts = tunnel_main._Fronts(
            object(), factory=_FakeSocksFront,
            shell_factory=_FakeShellFront, shell_enabled=True)
        self.addCleanup(fronts.stop_all)
        rows = self._rows(12)
        fronts.reconcile(rows)
        decorated = [fronts.decorate(row) for row in rows]

        socks = {row["password"] for row in decorated}
        shell = {row["shell_password"] for row in decorated}
        self.assertEqual(len(socks), 12, "a SOCKS password was reused")
        self.assertEqual(len(shell), 12, "a shell password was reused")
        self.assertFalse(socks & shell,
                         "a shell port is held by a SOCKS credential")
        # Each front was given its own row's password and nothing else:
        # the username, which is the identity and not a secret, is the
        # SOCKS front's alone.
        for row in decorated:
            self.assertEqual(row["username"], row["identity"])
            self.assertNotEqual(row["shell_password"], row["identity"])
            self.assertGreaterEqual(len(row["shell_password"]), 16)

    def test_the_recording_flag_is_the_deployments_answer_not_the_rows(self):
        """`shell_recording` answers "is this engagement recorded".

        Deliberately **not** "does this row have a session to record": it
        is True on a row whose shell port failed to bind and on a
        disconnected one, and `shell_detail` beside it says why there is
        no port. Task 6's `Transcripts` owns that reading -- one answer
        for the whole deployment, because "is this engagement recorded"
        is how the question is actually asked, and an operator looking at
        the panel before anybody has attached still needs the answer.
        Pinned here because Task 9 renders this field per row, where the
        other reading would be the natural guess.
        """
        from software.c2.tunnel import __main__ as tunnel_main
        from software.c2.tunnel.shell import ShellFront, Transcripts

        taken = socket.socket()
        self.addCleanup(taken.close)
        taken.bind(("127.0.0.1", 0))
        taken.listen(1)

        directory = self.root / "transcripts"
        fronts = tunnel_main._Fronts(
            object(), factory=_FakeSocksFront, shell_factory=ShellFront,
            shell_enabled=True, transcripts=Transcripts(str(directory)))
        self.addCleanup(fronts.stop_all)
        rows = self._rows(2)
        rows[0]["shell_port"] = taken.getsockname()[1]
        rows[1]["state"] = "disconnected"
        with self.assertLogs(tunnel_main.logger, level="WARNING"):
            fronts.reconcile(rows)

        failed = fronts.decorate(rows[0])
        self.assertIsNone(failed["shell"], "the held port was bound anyway")
        self.assertTrue(
            failed["shell_recording"],
            "the flag was read as a property of this row's port rather "
            "than of the deployment")
        self.assertIn("could not be opened", failed["shell_detail"],
                      "the row says the badge is on but not why there is "
                      "nothing to record")

        away = fronts.decorate(rows[1])
        self.assertIsNone(away["shell"])
        self.assertTrue(away["shell_recording"])
        self.assertTrue(away["shell_detail"])

    def test_the_decorated_row_reports_recording_when_a_directory_is_configured(self):
        """Recording is one switch with a path behind it, and off is off.

        `shell_recording` is what the panel badges, so it has to be the
        answer to "would this session be recorded" rather than "is a key
        set somewhere". Absent means no recording: no directory is
        created and nothing is written, which is asserted on the
        filesystem rather than on the flag.
        """
        from software.c2.tunnel import __main__ as tunnel_main
        from software.c2.tunnel.shell import Transcripts

        directory = self.root / "transcripts"
        recording = Transcripts(str(directory))
        made = []
        fronts = tunnel_main._Fronts(
            object(), factory=_FakeSocksFront,
            shell_factory=_recording(_FakeShellFront, made),
            shell_enabled=True, transcripts=recording)
        self.addCleanup(fronts.stop_all)
        rows = self._rows(1)
        fronts.reconcile(rows)

        self.assertTrue(fronts.decorate(rows[0])["shell_recording"])
        # The front holds the recorder itself, which is the only way a
        # session ever reaches a file; a flag on the row that nothing was
        # wired to would badge a panel and record nothing.
        self.assertIs(made[0].kwargs.get("transcripts"), recording)
        # And not before a session: the directory is created when a
        # transcript is opened, so a configured deployment with nobody
        # attached leaves no trace of which builds exist.
        self.assertFalse(directory.exists())

        # Off, which is the default. The front is still handed a
        # `Transcripts`, and it is one that records nothing: `None` is
        # passed through rather than a path being defaulted anywhere.
        quiet_made = []
        quiet = tunnel_main._Fronts(
            object(), factory=_FakeSocksFront,
            shell_factory=_recording(_FakeShellFront, quiet_made),
            shell_enabled=True, transcripts=Transcripts(None))
        self.addCleanup(quiet.stop_all)
        rows = self._rows(1)
        quiet.reconcile(rows)
        self.assertFalse(quiet.decorate(rows[0])["shell_recording"])
        handed = quiet_made[0].kwargs.get("transcripts")
        self.assertFalse(handed.enabled)
        self.assertIsNone(handed.directory)
        self.assertIsNone(handed.open("id-0", 1, "127.0.0.1:1"))
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), [],
                         "recording that is off created something anyway")


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

    def test_a_configured_shell_range_and_transcript_dir_are_reported(self):
        """The block the team server read, reported where the panel reads.

        `status()` is the only thing a deployment with no endpoint
        connected can ask whether this feature is on at all, so the three
        shell fields are reported there beside the SOCKS pair the panel
        already renders -- before the child is started as well as after,
        because "configured" is a fact about the block and not about a
        process.

        That `status()` answers is not the same as the child having been
        built from the same numbers; the test below holds that half, by
        handing the child a range it has to refuse.
        """
        ports = set()
        while len(ports) < 3:
            ports.add(_free_port())
        socks, first, last = sorted(ports)
        directory = self.data_dir / "transcripts"
        supervisor = self.supervisor(
            socks_port_first=socks, socks_port_last=socks,
            shell_port_first=first, shell_port_last=last,
            shell_transcript_dir=str(directory))

        stopped = supervisor.status()
        self.assertEqual(stopped["state"], "stopped")
        self.assertEqual([stopped["shell_port_first"],
                          stopped["shell_port_last"]], [first, last],
                         "a configured range is invisible until the "
                         "process is running")

        state = supervisor.start()
        self.assertEqual(state["state"], "running")
        self.assertEqual([state["shell_port_first"],
                          state["shell_port_last"]], [first, last])
        self.assertEqual(state["shell_transcripts"], str(directory))
        # Beside the SOCKS pair, which the panel reads from the same
        # block: two ranges, reported the same way.
        self.assertEqual(state["socks_port_first"], socks)
        # Configured is not created: a deployment with recording on and
        # nobody attached writes nothing, so the directory appears with
        # the first session and not with the process.
        self.assertFalse(directory.exists())

    def test_a_shell_range_the_child_refuses_comes_back_in_its_own_words(self):
        """The other half: the two numbers became arguments.

        `status()` reports the block the team server read, and would
        answer the same whether or not it ever reached a command line. A
        shell range overlapping the SOCKS one is one the tunnel server
        refuses to be built with, and that refusal is carried up from the
        child's stderr -- so a child that refuses for that reason is a
        child that was given those numbers.

        A hand-made block: `tunnel_server_config` refuses an overlap by
        field name long before a child is spawned.
        """
        from software.c2.tunnel.supervisor import SupervisorError

        port = _free_port()
        supervisor = self.supervisor(
            socks_port_first=port, socks_port_last=port,
            shell_port_first=port, shell_port_last=port)
        with self.assertRaises(SupervisorError) as caught:
            supervisor.start()
        reason = str(caught.exception)
        self.assertIn("overlaps", reason)
        self.assertIn(str(port), reason)
        # And nothing is left behind claiming to be running.
        self.assertEqual(supervisor.status()["state"], "stopped")

    def test_the_transcript_dir_is_handed_to_the_child_as_an_argument(self):
        """`--shell-transcript-dir` reaches the child, or nothing recorded.

        `status()` reports `shell_transcripts` from the block the team
        server read, so it answers the same whether or not that value ever
        became a command-line argument -- the exact gap that let the
        mapping lose its only coverage. The transcript dir carries no
        refusal the child could raise on it the way an overlapping range
        does (`Transcripts` accepts any path and only touches it, lazily,
        when a session is recorded), so this reads it off the argv of the
        running child instead: the directory the supervisor was configured
        with has to appear after `--shell-transcript-dir` on the line the
        child is actually running. Drop that pair from `_Child.spawn` and
        the directory is nowhere on the line, and this fails.

        A shell range is configured alongside it, because a transcript dir
        with no range is the misconfiguration the child only warns about;
        the two together are the shape a recording deployment runs.
        """
        ports = set()
        while len(ports) < 3:
            ports.add(_free_port())
        socks, first, last = sorted(ports)
        directory = self.data_dir / "transcripts-on-the-argv"
        supervisor = self.supervisor(
            socks_port_first=socks, socks_port_last=socks,
            shell_port_first=first, shell_port_last=last,
            shell_transcript_dir=str(directory))

        pid = supervisor.start()["pid"]
        command = _child_command_line(pid)
        self.assertTrue(command, "the probe read no command line at all, so "
                                 "finding the argument would prove nothing")
        self.assertIn("--shell-transcript-dir %s" % directory, command,
                      "the transcript directory did not reach the child's "
                      "command line, so a deployment that configured "
                      "recording would record nothing: %r" % command)

    def test_a_block_with_no_shell_keys_says_so_in_the_status_it_reports(self):
        # The shipped state, through the real supervisor: the keys are
        # absent from the block, so the command line carries none of them
        # and the reported block says the feature is off. That the child
        # then opens no shell port for anybody is
        # `TestTheTunnelProcess.test_no_range_opens_no_shell_front_and_
        # the_status_says_so`, which asks a real child directly.
        supervisor = self.supervisor()
        state = supervisor.start()
        self.assertEqual(state["state"], "running")
        self.assertIsNone(state["shell_port_first"])
        self.assertIsNone(state["shell_port_last"])
        self.assertIsNone(state["shell_transcripts"])
        # The SOCKS pair is still reported, so this is the shell feature
        # being off and not the block having gone missing.
        self.assertTrue(state["socks_port_first"])

    def test_a_shell_range_with_one_end_is_refused_rather_than_dropped(self):
        from software.c2.tunnel.supervisor import SupervisorError

        # `tunnel_server_config` refuses this by field name long before a
        # child is spawned, so this is a block built by hand. Spawning
        # anyway and quietly opening no shell port would make "the shell
        # port I configured never appeared" unattributable.
        for field, over in (("shell_port_last",
                             {"shell_port_first": _free_port()}),
                            ("shell_port_first",
                             {"shell_port_last": _free_port()})):
            with self.subTest(over=over):
                supervisor = self.supervisor(**over)
                with self.assertRaises(SupervisorError) as caught:
                    supervisor.start()
                self.assertIn(field, str(caught.exception))
                self.assertEqual(supervisor.status()["state"], "stopped")

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

    def test_get_tunnel_lists_endpoints_with_port_sessions_and_crypto_paths(self):
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
        # Both crypto paths, on the row, and not folded into one. A
        # tunnel on the pure-Python cipher runs at 50-200 KB/s, and
        # without this the operator debugs a network fault for an
        # afternoon -- which is what a row saying `openssl` about the
        # *server* did in exactly the case an `allow_slow_crypto` build
        # creates.
        self.assertEqual(row["endpoint_crypto"], "pure-python")
        self.assertEqual(row["server_crypto"], "openssl")
        # And the fleet link the child could not make for itself.
        self.assertEqual(row["agent"], name)
        self.assertTrue(row["linked"])
        self.assertEqual(row["interval"], 300)

    def test_the_row_carries_the_shell_fields_through_unchanged(self):
        """Four fields the panel reads, all of them copied and none made.

        Three rows, because the three states are three different stories
        and a copy that special-cased any of them would pass on one: an
        open shell port, a disconnected endpoint, and one whose front
        could not bind. `shell_recording` is the same on all three -- it
        is the deployment's answer and not the row's -- and is pinned
        here as received so that a route which "tidied" it per row would
        fail.
        """
        opened = _endpoint("open-one", shell_recording=True)
        away = _endpoint("away-one", port=19051, state="disconnected",
                         shell=None, shell_password=None,
                         shell_detail="no shell port is open yet",
                         shell_recording=True)
        failed = _endpoint("failed-one", port=19052, shell=None,
                           shell_password=None,
                           shell_detail="the shell port 40301 could not be "
                                        "opened: address already in use",
                           shell_recording=True)
        sent = [opened, away, failed]
        supervisor = _FakeTunnelSupervisor(endpoints=sent)
        body = self.client(supervisor).get(
            "/api/server/tunnel", headers=self.auth()).get_json()

        got = {row["identity"]: row for row in body["endpoints"]}
        for row in sent:
            for key in ("shell", "shell_password", "shell_detail",
                        "shell_recording"):
                with self.subTest(identity=row["identity"], key=key):
                    self.assertIn(key, got[row["identity"]])
                    self.assertEqual(got[row["identity"]][key], row[key])
        # And the two credentials arrive as two credentials.
        self.assertNotEqual(got["open-one"]["shell_password"],
                            got["open-one"]["password"])

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


def _served_page():
    """The operator page as the server actually serves it."""
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
            return response.read().decode("utf-8", "replace")
    finally:
        server.shutdown()
        server.server_close()
        tmp.cleanup()
        quiet.setLevel(previous)


class TestTheTunnelPanel(unittest.TestCase):
    """What the served page says about the two objects.

    Read out of the page the server serves, not out of the source, so a
    change that breaks the template fails here rather than in a browser.
    """

    @classmethod
    def setUpClass(cls):
        cls.page = _served_page()
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

    def test_the_row_shows_both_crypto_paths_and_any_refusal(self):
        # Both halves encrypt every relayed byte, so either one bounds
        # the throughput and the row has to name which is which. The
        # endpoint's is the one an `allow_slow_crypto` build is about and
        # the one this process cannot know for itself.
        self.assertIn("esc(String(row.endpoint_crypto", self.body)
        self.assertIn("esc(String(row.server_crypto", self.body)
        self.assertIn("esc(row.refusal)", self.body)
        anchor = self.body.index("esc(String(row.endpoint_crypto")
        slow = self.body[anchor - 900:anchor + 900]
        self.assertIn("pure-python", slow,
                      "the panel never says which path is the slow one")
        self.assertIn("endpoint", slow,
                      "the panel does not say which half a path belongs to")
        self.assertIn("server", slow,
                      "the panel does not say which half a path belongs to")

    def test_every_value_an_endpoint_influences_is_escaped(self):
        # A row's hostname, OS and peer come from a HELLO written by
        # whatever is at the far end of the tunnel, and its refusal from a
        # child process. Each goes through esc(), and the handlers are
        # attached in JavaScript rather than built into an attribute.
        for field in ("identity", "state", "hostname", "os", "peer",
                      "refusal"):
            self.assertIn("esc(row.%s)" % field, self.body,
                          "row.%s reaches the page unescaped" % field)
        # These two carry a default, so they are escaped through String()
        # rather than directly -- `endpoint_crypto` is a HELLO field and
        # so is written by the far end of the tunnel like the five above.
        for field in ("endpoint_crypto", "server_crypto"):
            self.assertIn("esc(String(row.%s" % field, self.body,
                          "row.%s reaches the page unescaped" % field)
        self.assertNotIn('onclick="tunnel', self.body,
                         "a handler body is built as a string")
        self.assertIn("addEventListener", self.body)

    def test_the_panel_names_the_socks_credential_for_proxychains(self):
        # The port authenticates per RFC 1929, so the operator needs the
        # credential where they are looking at the port.
        self.assertIn("esc(row.username)", self.body)
        self.assertIn("esc(row.password)", self.body)

    def test_the_panel_shows_the_shell_port_and_its_password(self):
        """The port from the `shell` object, the credential from its own field.

        And the label saying the credential is not the SOCKS one: the two
        sit a few lines apart on one row, and copying the wrong one would
        be refused with nothing to say why. The refusal detail goes
        through the reader the SOCKS half uses; a second one is a second
        place to get the nine kinds wrong.
        """
        self.assertIn("esc(String(shell.port))", self.body)
        self.assertIn("esc(row.shell_password)", self.body)
        flat = " ".join(self.body.split())
        label = flat.index("not the SOCKS5 password")
        self.assertLess(label, flat.index("esc(row.shell_password)"))
        self.assertLess(flat.index("esc(row.shell_password)") - label, 300,
                        "the label is not beside the credential")
        self.assertIn("refusals(shell)", self.body)
        self.assertEqual(self.body.count('indexOf("refused_")'), 1,
                         "the shell half grew its own refusal reader")

    def test_the_panel_shows_the_ssh_forward_before_the_attach_command(self):
        # The port is on the team server and the panel is reached over a
        # forward, so a command that opens with the attach line sends the
        # operator to a port their workstation does not have.
        forward = self.body.index("ssh -L ")
        attach = self.body.index("python3 tools/raccoon_shell.py 127.0.0.1 ")
        self.assertLess(forward, attach)
        self.assertIn("not on your workstation", self.body)
        self.assertLess(self.body.index("not on your workstation"), forward)
        self.assertIn("' + port + ':127.0.0.1:' + port", self.body,
                      "the forward does not name the shell port at both ends")

    def test_the_panel_names_the_attach_client_and_the_socat_fallback(self):
        socat = ("socat -,raw,echo=0,escape=0x1d TCP:127.0.0.1:' + port")
        self.assertIn(socat, self.body)
        client = self.body.index("python3 tools/raccoon_shell.py 127.0.0.1 ")
        self.assertLess(client, self.body.index(socat),
                        "the fallback is offered before the client")
        self.assertIn("Fallback", self.body)
        # What each one does about the way out, which is different and
        # which an operator cannot guess: the client has no escape key
        # and the socat line's is Ctrl-].
        self.assertIn("sends your terminal size", self.body)
        self.assertIn("no escape key", self.body)
        self.assertIn("Ctrl-]", self.body)
        self.assertIn("socat cannot send a terminal size", self.body)

    def test_the_panel_says_the_session_is_a_root_shell_on_the_implant_host(self):
        self.assertIn("root shell on the implant host", self.body)
        warning = self.body.index("root shell on the implant host")
        window = self.body[warning:warning + 300]
        self.assertIn("Forwarding the port", window)
        self.assertIn("loopback", window)

    def test_a_row_without_a_shell_port_shows_the_reason(self):
        """`shell_detail` stands in for the port when there is none.

        Guarded on the absence of the `shell` object, so an open port is
        never shown beside a reason it does not have, and escaped: it
        carries an OS error string from a bind that failed.
        """
        self.assertRegex(
            self.body,
            r"(?s)row\.shell\s*\?\s*shellBlock\(row\)\s*:\s*"
            r"\(row\.shell_detail\s*\?.{0,200}?esc\(row\.shell_detail\)",
            "the reason is not the else branch of the port")

    def test_the_panel_shows_a_recording_badge_only_when_recording_is_on(self):
        """A badge about the deployment, read off the server block.

        Recording is the deployment's answer -- a transcript directory
        and a shell range are configured -- so it comes from the status
        block, which carries both in every state the server can be in. A
        value read back off the rows loses exactly the cases with no row:
        no endpoint yet, the server stopped, unmanaged or died. Both
        halves are required, because a directory with no range records
        nothing.

        The test cannot run the JavaScript, so it cannot prove the
        empty-endpoints case; what it can hold is that the condition is
        computed before the rows loop and names no `rows` at all.
        """
        match = re.search(r"const recording = (.*?);", self.body, re.S)
        self.assertIsNotNone(match, "no recording condition is computed")
        condition = match.group(1)
        for key in ("shell_transcripts", "shell_port_first",
                    "shell_port_last"):
            self.assertIn("srv.%s" % key, condition)
        self.assertRegex(condition, r"srv\.shell_port_first\s*!=\s*null")
        self.assertRegex(condition, r"srv\.shell_port_last\s*!=\s*null")
        self.assertNotIn("rows", condition,
                         "the condition is derived from the rows")
        self.assertNotIn("rows.some", self.body)
        self.assertNotIn("r.shell_recording", self.body)
        self.assertLess(match.start(), self.body.index("rows.forEach(row"),
                        "the condition is computed after the rows loop")

        self.assertRegex(
            self.body,
            r'\(recording\s*\?\s*\'<div id="tunnel-recording-badge"')
        badge = self.body.index("tunnel-recording-badge")
        rows = self.body.index("rows.forEach(row")
        self.assertLess(badge, rows,
                        "the badge is drawn inside the per-row markup")
        per_row = self.body[rows:self.body.index("panel.innerHTML = html;",
                                                 rows)]
        shell_half = self.body[self.body.index("const shellBlock"):
                               self.body.index("let html = head")]
        for name, text in (("a row", per_row), ("the shell half", shell_half)):
            self.assertNotIn("record", text.lower(),
                             "%s says it is recording" % name)


def _js_function(page, name):
    """The source of the top-level function `name`, up to the next one.

    Cut at the next line that starts a top-level function rather than
    matched on braces: the page is a Python string full of HTML in JS
    strings, and counting braces through that is a parser this file does
    not need to be.
    """
    start = re.search(r"^(?:async )?function %s\(" % re.escape(name),
                      page, re.M)
    if start is None:
        raise AssertionError("the page has no function %s()" % name)
    end = re.compile(r"^(?:async )?function \w+\(", re.M).search(
        page, start.end())
    return page[start.start():end.start() if end else len(page)]


class TestTheBeaconGenTunnelForm(unittest.TestCase):
    """The Beacon Gen form asking for a tunnel, on both delivery paths.

    `_tunnel_config_for_build` is the authority on what a tunnel request
    may say; these tests hold only that the form sends it, that the two
    delivery paths each send it, and that the one client-side check
    mirrors the route's refusals and adds none.

    **What this cannot hold.** The page is a Python string and there is
    no JavaScript runner in this repository, so every assertion is on the
    served source: that a function calls another, that a key is written
    in one place and not another, that a value passes through `esc()`.
    None of it executes the form. A check whose condition is inverted, an
    `||` where the code wants `&&`, or a field read from the wrong id
    would pass. The route-level test in `test_tunnel_config.py` holds the
    other half: a body shaped as this form builds it really does produce
    a tunnel build.
    """

    @classmethod
    def setUpClass(cls):
        cls.page = _served_page()

    # Looked up per test rather than in `setUpClass`, so that a function
    # the page lacks fails the test about it and not the whole class.
    gen = property(lambda self: _js_function(self.page, "runBeaconGen"))
    gist = property(lambda self: _js_function(self.page, "runBeaconGist"))
    collect = property(lambda self: _js_function(self.page, "bgCollectTunnel"))
    validate = property(
        lambda self: _js_function(self.page, "bgValidateTunnel"))
    attach = property(lambda self: _js_function(self.page, "bgWithTunnel"))

    @staticmethod
    def _request_body(function_source):
        """The argument of the `JSON.stringify(` that builds the request."""
        start = function_source.index("JSON.stringify(")
        return function_source[start:function_source.index("\n", start)]

    def test_the_form_has_a_tunnel_section_with_server_and_port(self):
        # `assertIn` against the page would print the whole page on
        # failure, so the needle is tested and the message names it.
        for element in ("bg-tunnel", "bg-tunnel-server", "bg-tunnel-port",
                        "bg-tunnel-keepalive", "bg-tunnel-slow"):
            with self.subTest(element=element):
                self.assertTrue('id="%s"' % element in self.page,
                                "the form has no %s field" % element)

        # A section of its own between the proxy and the delivery choice,
        # drawn the way the Egress Proxy section beside it is.
        proxy = self.page.index('>Egress Proxy</div>')
        tunnel = self.page.index('>Tunnel</div>')
        delivery = self.page.index('>Delivery Method</div>')
        self.assertLess(proxy, tunnel)
        self.assertLess(tunnel, delivery)
        section = self.page[tunnel:delivery]

        # Off until asked for, and the four fields stay hidden until then.
        checkbox = re.search(r'<input[^>]*id="bg-tunnel"[^>]*>', section)
        self.assertIsNotNone(checkbox)
        self.assertNotIn("checked", checkbox.group(0),
                         "the tunnel box is ticked before anyone asked")
        self.assertRegex(
            section,
            r'id="bg-tunnel-opts"[^>]*style="display:none"')

        # The route's own words as the hints, and the warning that the
        # slow path is slow rather than broken.
        flat = " ".join(section.split())
        self.assertIn("bare hostname or IP", flat)
        self.assertIn("as the target", flat)
        self.assertIn("pure Python", flat)
        self.assertIn("50-200 KB/s", flat)
        # The shape of the keepalive field: empty means the endpoint's own
        # default, which is the route's, so no number is repeated here.
        self.assertRegex(
            section, r'id="bg-tunnel-keepalive"[^>]*placeholder="[^"]*default')
        self.assertNotRegex(section, r'id="bg-tunnel-keepalive"[^>]*value=')
        # And nothing in it lets the operator type a credential: the PSK,
        # identity and public key are minted per build.
        for refused in ("psk", "public_key", "tunnel-identity"):
            self.assertNotIn(refused, section.lower())

    def test_both_delivery_paths_post_the_tunnel_block(self):
        # A tunnel wired into only the first would vanish the moment an
        # operator picked gist delivery: a build with no tunnel, and no
        # indication why. So each function's own request body is read.
        for name, source in (("runBeaconGen", self.gen),
                             ("runBeaconGist", self.gist)):
            with self.subTest(function=name):
                self.assertIn("bgCollectTunnel()", source)
                body = self._request_body(source)
                self.assertIn("bgWithTunnel(", body,
                              "%s builds a request body that cannot carry "
                              "a tunnel" % name)
                self.assertIn("tunnel", body.split("bgWithTunnel(", 1)[1])
        # And both go to the routes that run the same config builder.
        self.assertIn('"/api/server/beacon-gen"', self.gen)
        self.assertIn('"/api/server/beacon-gist"', self.gist)
        # What the helper adds is the collected block, under the key the
        # route reads.
        self.assertRegex(self.attach, r"\.tunnel\s*=\s*tunnel\b|"
                                      r"\btunnel\s*:\s*tunnel\b")

    def test_the_form_posts_no_tunnel_key_when_the_box_is_unchecked(self):
        # Not an empty object and not `{enabled: false}`: the key is
        # absent. Held at its two ends -- the collector answers null for a
        # clear box, and the only place the key is ever written is behind
        # a test of that answer.
        self.assertRegex(
            self.collect,
            r'if\(!document\.getElementById\("bg-tunnel"\)\?\.checked\)'
            r'\s*return null;')
        self.assertRegex(self.attach, r"if\s*\(\s*tunnel\s*\)")
        self.assertLess(self.attach.index("if"),
                        self.attach.index(".tunnel"),
                        "the key is written before the box is looked at")
        for name, source in (("runBeaconGen", self.gen),
                             ("runBeaconGist", self.gist)):
            with self.subTest(function=name):
                self.assertNotRegex(
                    source, r"\btunnel\s*:",
                    "%s writes a tunnel key into its body directly, "
                    "around the helper that leaves it out" % name)
        for source in (self.collect, self.attach):
            self.assertNotRegex(source, r"enabled\s*:\s*false")
        # And the switch itself, positively. The route reads this key and
        # nothing else to decide whether a build gets a tunnel at all --
        # `if not asked.get("enabled"): return None` -- so the negative
        # above passes just as happily on a block that lost the key as on
        # one that sets it. A dropped or renamed `enabled` would make
        # every tunnel build a successful build with no tunnel: no
        # `tunnel_identity` comes back, so the result line omits itself
        # and the page says nothing was wrong. The pair pins both
        # directions.
        self.assertRegex(self.collect, r"enabled\s*:\s*true")

    def test_a_url_shaped_server_is_refused_before_the_request(self):
        # The route refuses a URL, a path or an embedded space, because
        # the value is dialled directly and written into a CONNECT line.
        # The form says so first. It mirrors that and nothing else: no
        # host-name grammar, no port-class judgement of its own.
        self.assertIn('"/"', self.validate.replace("'", '"'))
        self.assertRegex(self.validate, r"\\s")
        self.assertIn("bare hostname or IP address", self.validate)
        self.assertRegex(self.validate, r"65535")
        self.assertIn("required", self.validate)
        for invented in ("://", "localhost", "127.", "match("):
            self.assertNotIn(invented, self.validate,
                             "the form invents a refusal of its own: %r"
                             % invented)
        # A blacklist cannot catch a refusal written with the same idiom
        # as the legitimate one -- a host-name grammar as
        # `/^[a-z0-9.-]+$/i.test(server)` would pass every line above --
        # so the counts are pinned as well: one pattern tested, and
        # exactly the route's three refusals.
        self.assertEqual(self.validate.count(".test("), 1,
                         "the form tests a pattern besides the one the "
                         "route refuses")
        self.assertEqual(self.validate.count("return false"), 3,
                         "the form refuses something the route does not, "
                         "or stopped refusing something it does")

        # Asked before anything is sent, on both paths.
        for name, source in (("runBeaconGen", self.gen),
                             ("runBeaconGist", self.gist)):
            with self.subTest(function=name):
                self.assertIn("bgValidateTunnel(", source)
                self.assertLess(source.index("bgValidateTunnel("),
                                source.index("api("),
                                "%s sends the request before it has "
                                "checked the tunnel" % name)
        # And a refusal the form did not catch is the route's text,
        # unchanged: the existing error toast carries `data.error`.
        self.assertIn("data.error", self.gen)
        self.assertIn("data.error", self.gist)

    def test_the_result_renders_the_tunnel_identity(self):
        # Both result blocks, because both routes return it.
        for name, source in (("runBeaconGen", self.gen),
                             ("runBeaconGist", self.gist)):
            with self.subTest(function=name):
                # Every mention is the escaped one: it comes back from the
                # server and is rendered.
                self.assertIn("esc(data.tunnel_identity)", source)
                self.assertEqual(source.count("data.tunnel_identity"),
                                 source.count("esc(data.tunnel_identity)"),
                                 "%s renders tunnel_identity unescaped"
                                 % name)
                flat = " ".join(source.split())
                self.assertIn("SOCKS and shell port", flat)
                self.assertIn("delete", flat.lower())
                self.assertNotIn("psk", flat.lower(),
                                 "the result talks about the credential")


# New test classes belong above this guard; never append below it.
if __name__ == "__main__":
    unittest.main()
