#!/usr/bin/env python3
"""
Unit tests for the gsocket carrier process: its argv, its binary check,
its lifecycle and its probe.

What these tests are careful about.

**Nothing here touches the Global Socket Relay Network.** A suite that
needed the GSRN would be a suite that sends traffic to a third-party
relay from whatever machine runs it, which is the one thing this feature's
constraints say carries OPSEC meaning. So every process these tests spawn
is `software/tests/data/fake_gs_netcat.sh`, a stand-in that parses `-p`,
listens on that loopback port until it is killed, and records the argv
and the environment it was handed. The recording is what makes the two
properties below testable against a real spawn rather than against the
argv builder alone.

**The secret is never on a command line.** `gs-netcat` accepts
`-s <secret>` and its own documentation warns against it, because `ps` is
world-readable. The carrier is handed a path and passes `-k <path>`, so
these tests assert both halves: `-s` appears in no argv, and the secret's
*value* appears in no argv entry -- of `argv()`, of the implant-side
argv, or of the line the spawned process actually recorded. Checking only
for `-s` would pass against a module that invented its own way to spell
the same mistake.

**The carrier holds no encryption key.** This is the property that makes
a carrier safe to run somewhere exposed: it forwards a sealed stream and
cannot read it. The team server *does* hold the beacon's AES key, in
`RACCOON_KEY` in its own environment, and it is the process that
constructs the carrier -- so an inherited environment is the obvious way
for that key to end up in the most exposed process in the arrangement.
One test therefore sets `RACCOON_KEY` in this process, starts a carrier,
and reads the child's environment back off disk.

**A reason, not an exception.** `verify_binary` returns a string the
caller may decide is fatal, and the reasons are asserted on their
content -- both digests in a mismatch, the path in every one -- because
Task 6 reimplements this check inside `beacon.py`, which may import
nothing from this repository, and a later test compares the two wordings.
A test that only asserted "some reason was returned" would pass against
reasons not worth copying.
"""

import hashlib
import os
import shutil
import socket
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from software.c2.gsocket.carrier import (
    CarrierError,
    GsocketCarrier,
    binary_problem,
    implant_argv,
)
from software.c2.gsocket.config import CarrierSpec, LEG_DEFAULTS
from software.c2.gsocket.secrets import SecretStore

FAKE_GS_NETCAT = Path(__file__).resolve().parent / "data" / "fake_gs_netcat.sh"


def _free_port() -> int:
    """A port that was free a moment ago.

    Racy by nature, which is why `beacon_port: 0` is refused in a
    configuration file and used freely here: an operator needs a fixed
    port, a test needs a port nobody else is using right now.
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


class CarrierFixture(unittest.TestCase):
    """A carrier over the fake binary, with its recordings and its cleanup."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="raccoon-gsocket-carrier-")
        self.addCleanup(self._clean)
        self.secret = SecretStore.generate()
        store = SecretStore(os.path.join(self.root, "gsocket", "secrets.json"))
        store.register_implant("raccoon-01", self.secret)
        self.secret_path = str(store.secret_file_for("raccoon-01"))
        self.argv_file = os.path.join(self.root, "argv.txt")
        self.env_file = os.path.join(self.root, "env.txt")
        self.pid_file = os.path.join(self.root, "pid.txt")
        self._record = mock.patch.dict(os.environ, {
            "FAKE_GS_NETCAT_ARGV_FILE": self.argv_file,
            "FAKE_GS_NETCAT_ENV_FILE": self.env_file,
            "FAKE_GS_NETCAT_PID_FILE": self.pid_file,
        })
        self._record.start()
        self.addCleanup(self._record.stop)
        self._carriers = []

    def _clean(self):
        for carrier in getattr(self, "_carriers", []):
            try:
                carrier.stop()
            except Exception:
                pass
        shutil.rmtree(self.root, ignore_errors=True)

    def spec(self, **overrides) -> CarrierSpec:
        fields = {
            "name": "raccoon-01-carrier",
            "identity": "raccoon-01",
            "enabled": True,
            "beacon_host": "127.0.0.1",
            "beacon_port": 8443,
            "binary_path": str(FAKE_GS_NETCAT),
            "sha256": "",
        }
        fields.update(overrides)
        return CarrierSpec(**fields)

    def carrier(self, **overrides) -> GsocketCarrier:
        built = GsocketCarrier(self.spec(**overrides), self.secret_path)
        self._carriers.append(built)
        return built

    def recorded_argv(self, timeout=5.0):
        """The argv the spawned process saw, waited for."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                text = Path(self.argv_file).read_text(encoding="utf-8")
            except FileNotFoundError:
                text = ""
            if text.strip():
                return text.strip().split("\n")
            time.sleep(0.02)
        self.fail("the fake gs-netcat never recorded its argv at %s"
                  % self.argv_file)

    def recorded_environment(self, timeout=5.0):
        """The child's environment as a dict, read back off disk.

        Parsed into names and values rather than handed back as text,
        because a failing assertion prints its container: a test that
        compared whole `env` output would print the environment of
        whatever machine it failed on into a CI log, and on a CI machine
        that is a page of credentials. So the assertions below compare
        names against names, and check values without printing them.
        """
        deadline = time.time() + timeout
        text = ""
        while time.time() < deadline:
            try:
                text = Path(self.env_file).read_text(encoding="utf-8")
            except FileNotFoundError:
                text = ""
            if text.strip():
                break
            time.sleep(0.02)
        if not text.strip():
            self.fail("the fake gs-netcat never recorded its environment at "
                      "%s" % self.env_file)
        environment = {}
        name = None
        for line in text.split("\n"):
            if "=" in line:
                name, _, value = line.partition("=")
                environment[name] = value
            elif name is not None:
                # A value with a newline in it; `env` prints it raw.
                environment[name] += "\n" + line
        return environment

    def recorded_pid(self, timeout=5.0) -> int:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                text = Path(self.pid_file).read_text(encoding="utf-8")
            except FileNotFoundError:
                text = ""
            if text.strip():
                return int(text.strip())
            time.sleep(0.02)
        self.fail("the fake gs-netcat never recorded its pid at %s"
                  % self.pid_file)

    def binary(self, content=b"#!/bin/sh\nexit 0\n", mode=0o755) -> str:
        """A file standing in for `gs-netcat`, with a mode of our choosing."""
        path = os.path.join(self.root, "gs-netcat-%s" % os.urandom(4).hex())
        with open(path, "wb") as handle:
            handle.write(content)
        os.chmod(path, mode)
        return path


class TestArgv(CarrierFixture):

    def test_the_secret_is_never_in_argv(self):
        # -k and a path, never -s. `ps` is world-readable on every machine
        # a carrier might run on, and gsocket's own documentation says so.
        # Both halves are asserted: the flag gsocket would accept, and the
        # secret's value -- a module that spelled the mistake its own way
        # would pass a check for `-s` alone.
        server = self.carrier().argv()
        implant = implant_argv(str(FAKE_GS_NETCAT), self.secret_path,
                               LEG_DEFAULTS["local_port"])
        for argv in (server, implant):
            self.assertIn("-k", argv, argv)
            self.assertEqual(argv[argv.index("-k") + 1], self.secret_path)
            self.assertNotIn("-s", argv, argv)
            for entry in argv:
                self.assertNotIn(self.secret, entry,
                                 "the secret itself reached argv: %r" % argv)

    def test_the_server_side_argv_forwards_into_the_beacon_socket(self):
        # -l -d <beacon_host> -p <beacon_port>: this side listens on the
        # relay network and connects what arrives straight into the team
        # server's own beacon socket, so it opens no forward of its own.
        argv = self.carrier(beacon_host="127.0.0.1", beacon_port=8443).argv()
        self.assertEqual(argv[0], str(FAKE_GS_NETCAT))
        self.assertIn("-l", argv, argv)
        self.assertEqual(argv[argv.index("-d") + 1], "127.0.0.1")
        self.assertEqual(argv[argv.index("-p") + 1], "8443")
        # Not a client: `-w` would make this end dial instead of listen,
        # and nothing would ever answer an implant.
        self.assertNotIn("-w", argv, argv)

    def test_the_implant_side_argv_waits_for_the_far_side(self):
        # -w, so a carrier started before the server's -- an implant that
        # boots while the team server is down, which is the normal case --
        # waits for the peer rather than failing at once.
        argv = implant_argv(str(FAKE_GS_NETCAT), self.secret_path, 16443)
        self.assertEqual(argv[0], str(FAKE_GS_NETCAT))
        self.assertIn("-w", argv, argv)
        self.assertEqual(argv[argv.index("-p") + 1], "16443")
        # The implant opens a local forward and has nowhere to forward
        # *to*: `-l` or `-d` here would be the server's shape on the
        # client's side of the relay.
        self.assertNotIn("-l", argv, argv)
        self.assertNotIn("-d", argv, argv)

    def test_the_implant_side_forward_defaults_to_the_configured_leg_port(self):
        # The number is `LEG_DEFAULTS["local_port"]` and not a literal
        # here, because `beacon.py` carries a copy of these defaults and
        # the only thing keeping the two from drifting is that both are
        # read from the same place by whatever can import it.
        argv = implant_argv(str(FAKE_GS_NETCAT), self.secret_path,
                            LEG_DEFAULTS["local_port"])
        self.assertEqual(argv[argv.index("-p") + 1], "16443")


class TestVerifyBinary(CarrierFixture):

    def test_a_missing_binary_is_a_reason_not_an_exception(self):
        missing = os.path.join(self.root, "not-installed", "gs-netcat")
        reason = self.carrier(binary_path=missing).verify_binary()
        self.assertIsNotNone(reason)
        self.assertIn(missing, reason)
        # The caller decides whether a reason is fatal: the supervisor
        # turns it into a status row, the implant's copy turns it into a
        # `binary_missing` rescue record. Raising here would take that
        # decision away from both.
        self.assertIsInstance(reason, str)

    def test_a_directory_where_the_binary_should_be_is_a_reason(self):
        # A directory carries the executable bit, so an exec-bit check
        # alone would pass it and the failure would arrive from `Popen`
        # as a bare PermissionError.
        directory = os.path.join(self.root, "gs-netcat-dir")
        os.makedirs(directory)
        reason = self.carrier(binary_path=directory).verify_binary()
        self.assertIsNotNone(reason)
        self.assertIn(directory, reason)

    def test_a_binary_without_the_executable_bit_is_a_reason(self):
        path = self.binary(mode=0o644)
        reason = self.carrier(binary_path=path).verify_binary()
        self.assertIsNotNone(reason)
        self.assertIn(path, reason)
        # The mode is printed: "not executable" sends an operator looking
        # for the wrong file, while 0o644 says exactly what to change.
        self.assertIn("644", reason)

    def test_a_wrong_sha256_is_refused_with_both_digests_in_the_reason(self):
        path = self.binary(content=b"#!/bin/sh\nexit 0\n")
        actual = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        expected = "0" * 64
        reason = self.carrier(binary_path=path,
                              sha256=expected).verify_binary()
        self.assertIsNotNone(reason)
        # Both, because the two mistakes behind a mismatch are opposite
        # and the reason has to tell them apart: a stale digest in the
        # config (paste the actual one) against a binary that is not the
        # one that was measured (replace the binary).
        self.assertIn(expected, reason)
        self.assertIn(actual, reason)
        self.assertIn(path, reason)

    def test_an_empty_sha256_skips_the_check(self):
        # Exactly as `c2.sliver.sha256` does. A deployment that never
        # measured its binary still has to be able to run one.
        path = self.binary()
        self.assertIsNone(
            self.carrier(binary_path=path, sha256="").verify_binary())

    def test_a_matching_sha256_passes(self):
        path = self.binary()
        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        self.assertIsNone(
            self.carrier(binary_path=path, sha256=digest).verify_binary())

    def test_an_upper_case_configured_digest_still_matches(self):
        # `config._checked_sha256` lower-cases what it reads, but this
        # check is also called with digests from elsewhere -- the
        # implant's copy reads one out of a generated config -- and an
        # upper-case digest pasted out of a Windows tool matching nothing
        # would read as a replaced binary.
        path = self.binary()
        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        self.assertIsNone(binary_problem(path, digest.upper()))

    def test_an_unconfigured_binary_path_says_so_rather_than_naming_nothing(self):
        # An empty `binary_path` is what a leg configured before anybody
        # installed gs-netcat carries, and `os.stat("")` would make the
        # reason a sentence with no subject.
        reason = binary_problem("", "")
        self.assertIsNotNone(reason)
        self.assertIn("binary_path is empty", reason)

    def test_the_reason_for_a_mismatch_names_the_digests_in_a_fixed_order(self):
        # Task 6 reimplements this check inside `beacon.py`, which may
        # import nothing from this repository, and a later test compares
        # the two wordings. So the reason is pinned here as a whole
        # string and not only by the substrings it contains.
        path = self.binary()
        actual = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        reason = binary_problem(path, "a" * 64)
        self.assertEqual(
            reason,
            "%s: its sha256 is %s, but the configuration expects %s. Either "
            "the digest in the configuration is stale, or this is not the "
            "binary that was measured -- and the second one is a gs-netcat "
            "somebody else put there, which would be handed the secret that "
            "fronts the beacon socket" % (path, actual, "a" * 64))


class TestLifecycle(CarrierFixture):

    def test_start_then_is_running_then_stop(self):
        carrier = self.carrier(beacon_port=_free_port())
        self.assertFalse(carrier.is_running())
        carrier.start()
        self.assertTrue(carrier.is_running())
        pid = carrier.status()["pid"]
        self.assertIsInstance(pid, int)
        carrier.stop()
        self.assertFalse(carrier.is_running())
        # Not merely "the handle says stopped": a `stop` that returned
        # while the process kept running would leave the relay address
        # occupied and look identical to a carrier that never started.
        deadline = time.time() + 5.0
        while time.time() < deadline and _alive(pid):
            time.sleep(0.02)
        self.assertFalse(_alive(pid),
                         "pid %d survived stop()" % pid)

    def test_stop_is_safe_when_nothing_is_running(self):
        carrier = self.carrier()
        carrier.stop()          # never started
        carrier.stop()          # and again
        self.assertFalse(carrier.is_running())

    def test_the_spawned_process_is_handed_the_argv_the_carrier_reports(self):
        # `argv()` is what the tests above assert, so the spawn has to be
        # the same list: a `start` that built its own would make every
        # argv assertion in this file a statement about an unused method.
        carrier = self.carrier(beacon_port=_free_port())
        carrier.start()
        self.assertEqual(self.recorded_argv(), carrier.argv()[1:])

    def test_start_refuses_an_unusable_binary_and_says_why(self):
        missing = os.path.join(self.root, "not-installed", "gs-netcat")
        carrier = self.carrier(binary_path=missing)
        with self.assertRaises(CarrierError) as caught:
            carrier.start()
        self.assertIn(missing, str(caught.exception))
        self.assertFalse(carrier.is_running())

    def test_start_refuses_to_run_a_second_process(self):
        # Two carriers under one secret means the relay network pairs an
        # implant with whichever of them it happened to choose, which is
        # a coin toss on every check-in rather than an error anybody sees.
        carrier = self.carrier(beacon_port=_free_port())
        carrier.start()
        with self.assertRaises(CarrierError) as caught:
            carrier.start()
        self.assertIn("already running", str(caught.exception))
        self.assertTrue(carrier.is_running())

    def test_status_reports_the_exit_code_of_a_process_that_died(self):
        # A carrier that exits on its own is the failure the supervisor
        # restarts, and the code is the only thing that distinguishes
        # "the relay refused us" from "we were killed".
        path = self.binary(content=b"#!/bin/sh\nexit 3\n")
        carrier = self.carrier(binary_path=path)
        carrier.start()
        deadline = time.time() + 5.0
        while time.time() < deadline and carrier.is_running():
            time.sleep(0.02)
        self.assertFalse(carrier.is_running())
        status = carrier.status()
        self.assertEqual(status["exit_code"], 3)
        self.assertIn("3", status["detail"])

    def test_status_describes_a_carrier_that_was_never_started(self):
        status = self.carrier().status()
        self.assertEqual(status["name"], "raccoon-01-carrier")
        self.assertEqual(status["identity"], "raccoon-01")
        self.assertFalse(status["running"])
        self.assertIsNone(status["pid"])
        self.assertIsNone(status["exit_code"])
        self.assertTrue(status["detail"])

    def test_no_status_field_carries_the_secret(self):
        # A status dict becomes an API response and from there a
        # screenshot. The identity is a name and belongs there; the
        # credential does not, and neither does the path to the file
        # holding it.
        carrier = self.carrier(beacon_port=_free_port())
        carrier.start()
        text = repr(carrier.status())
        self.assertNotIn(self.secret, text)
        self.assertNotIn(self.secret_path, text)


class TestProbe(CarrierFixture):

    def test_probe_is_true_when_the_binary_reports_a_listener(self):
        with mock.patch.dict(os.environ, {"FAKE_GS_NETCAT_PROBE_EXIT": "0"}):
            self.assertTrue(self.carrier().probe())
        argv = self.recorded_argv()
        self.assertIn("-t", argv, argv)
        # The probe is a question, not a connection: `-l` would make it
        # a second listener on the same relay address, racing the
        # carrier it is supposed to be reporting on.
        self.assertNotIn("-l", argv, argv)
        # And it carries the secret the same way everything else does.
        self.assertIn("-k", argv, argv)
        self.assertNotIn("-s", argv, argv)
        for entry in argv:
            self.assertNotIn(self.secret, entry, argv)

    def test_probe_is_false_when_the_binary_reports_no_listener(self):
        # Not an error: an implant that is powered off is the ordinary
        # answer, and raising would make the panel show a fault where it
        # should show a dash.
        with mock.patch.dict(os.environ, {"FAKE_GS_NETCAT_PROBE_EXIT": "1"}):
            self.assertFalse(self.carrier().probe())

    def test_probe_gives_up_on_a_binary_that_does_not_answer(self):
        # `-t` reaches the relay network, so it can hang for as long as
        # the network lets it. An unbounded probe would wedge the panel
        # request that called it.
        with mock.patch.dict(os.environ, {"FAKE_GS_NETCAT_PROBE_HANG": "1"}):
            started = time.time()
            self.assertFalse(self.carrier().probe(timeout=0.5))
            self.assertLess(time.time() - started, 15.0)
        # And the process it gave up on is gone, rather than left
        # holding the relay address for the rest of the day. The pid is
        # the one the stand-in recorded for itself, so this cannot pass
        # by matching nothing.
        pid = self.recorded_pid()
        deadline = time.time() + 5.0
        while time.time() < deadline and _alive(pid):
            time.sleep(0.02)
        self.assertFalse(_alive(pid),
                         "the probe left pid %d behind" % pid)

    def test_probe_refuses_an_unusable_binary_rather_than_answering_no(self):
        # "No listener" and "no binary to ask with" are different
        # answers, and a probe that returned False for both would have
        # the panel report every implant down the moment `gs-netcat`
        # was moved.
        missing = os.path.join(self.root, "not-installed", "gs-netcat")
        with self.assertRaises(CarrierError) as caught:
            self.carrier(binary_path=missing).probe()
        self.assertIn(missing, str(caught.exception))


class TestNoEncryptionKey(CarrierFixture):

    def test_the_carrier_never_holds_the_encryption_key(self):
        # The property every listener in this project rests on, and the
        # reason a carrier is safe to run somewhere exposed: it forwards
        # a stream sealed in the beacon's AES-256-GCM envelope and cannot
        # open it. The team server holds that key in `RACCOON_KEY` and is
        # the process that constructs the carrier, so an inherited
        # environment is the obvious way for the key to reach the most
        # exposed process in the arrangement.
        key = "s3cret-aes-key-material-not-for-the-carrier"
        token = "operator-token-not-for-the-carrier-either"
        with mock.patch.dict(os.environ, {"RACCOON_KEY": key,
                                          "RACCOON_TOKEN": token}):
            carrier = self.carrier(beacon_port=_free_port())
            self.assertNotIn(key, repr(sorted(vars(carrier).items())),
                             "an attribute of the carrier holds the key")
            for entry in carrier.argv():
                self.assertNotIn(key, entry, carrier.argv())
            carrier.start()
            environment = self.recorded_environment()
        # By name, and by value without printing the value: an
        # assertion that failed by dumping an environment would be a
        # leak of its own on any machine with credentials in one.
        self.assertNotIn("RACCOON_KEY", sorted(environment))
        self.assertNotIn("RACCOON_TOKEN", sorted(environment))
        self.assertFalse(
            [name for name, value in environment.items() if key in value],
            "the encryption key reached the child's environment under "
            "another name")
        self.assertFalse(
            [name for name, value in environment.items() if token in value],
            "the operator token reached the child's environment under "
            "another name")

    def test_the_child_environment_drops_everything_this_project_sets(self):
        # `gs-netcat` is a third-party binary that has never heard of
        # this project, so no RACCOON_* variable is of any use to it --
        # which makes "drop them all" both correct and the rule that
        # keeps covering us when the next credential variable is added.
        with mock.patch.dict(os.environ, {"RACCOON_SOMETHING_NEW": "x"}):
            carrier = self.carrier(beacon_port=_free_port())
            carrier.start()
            environment = self.recorded_environment()
        self.assertEqual(
            [name for name in environment if name.startswith("RACCOON_")], [])
        # PATH survives, because withholding something `gs-netcat` needs
        # produces a carrier that joins the relay and never finds its
        # peer -- the one failure in this feature nobody can diagnose.
        self.assertIn("PATH", environment)

    def test_an_inherited_gsocket_args_does_not_reach_the_child(self):
        # gsocket's tools read GSOCKET_ARGS and append it to their own
        # argv. An inherited one would add arguments nobody here chose,
        # and the shape it could add includes `-s <secret>` -- the exact
        # thing this module exists to never do.
        with mock.patch.dict(os.environ, {"GSOCKET_ARGS": "-s leaked-secret"}):
            carrier = self.carrier(beacon_port=_free_port())
            carrier.start()
            environment = self.recorded_environment()
        self.assertNotIn("GSOCKET_ARGS", sorted(environment))
        self.assertFalse(
            [name for name, value in environment.items()
             if "leaked-secret" in value],
            "GSOCKET_ARGS reached the child under another name")


class TestFakeBinaryFixture(unittest.TestCase):
    """The fixture itself, since every test above rests on it."""

    def test_the_fake_binary_is_executable_in_the_checkout(self):
        # Tracked with its mode, because a fixture that arrives 0644
        # fails every lifecycle test above as a PermissionError that
        # looks like a bug in the carrier.
        self.assertTrue(FAKE_GS_NETCAT.exists(), FAKE_GS_NETCAT)
        self.assertTrue(stat.S_IMODE(FAKE_GS_NETCAT.stat().st_mode) & 0o111,
                        "%s is not executable" % FAKE_GS_NETCAT)

    def test_the_fake_binary_listens_on_the_port_it_is_given(self):
        # The stand-in has to be a process that stays up, or
        # `is_running()` would be reporting on something that had
        # already exited for its own reasons.
        port = _free_port()
        process = subprocess.Popen(
            [str(FAKE_GS_NETCAT), "-k", "/dev/null", "-w", "-p", str(port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
        try:
            deadline = time.time() + 5.0
            connected = False
            while time.time() < deadline and not connected:
                probe = socket.socket()
                probe.settimeout(0.2)
                try:
                    probe.connect(("127.0.0.1", port))
                    connected = True
                except OSError:
                    time.sleep(0.05)
                finally:
                    probe.close()
            self.assertTrue(connected,
                            "the fake gs-netcat never listened on %d" % port)
            self.assertIsNone(process.poll())
        finally:
            try:
                os.killpg(os.getpgid(process.pid), 15)
            except (ProcessLookupError, PermissionError):
                process.kill()
            process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
