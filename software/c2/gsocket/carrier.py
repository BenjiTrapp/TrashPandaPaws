"""One `gs-netcat` process: its argument vector, its binary check, its
lifecycle and its probe.

This is the wrapper, not the policy. It builds a command line, verifies
the binary it is about to exec, spawns it, stops it, reports what it
knows and asks the relay network one question. It deliberately does
**not** restart anything: the restart loop, the delay between attempts
and the attempt ceiling belong to the supervisor above this, which is
also where an operator's start and stop verbs arrive. A carrier that
restarted itself would restart in two places once the supervisor existed,
and the symptom of that is a `gs-netcat` reappearing after an operator
stopped it.

Four properties are deliberate.

**The secret never reaches a command line.** `gs-netcat` accepts
`-s <secret>` and its own documentation warns against it, because `ps` is
world-readable on every machine a carrier might run on. Everything here
passes `-k <path>` instead, and the path comes from
`secrets.SecretStore.secret_file_for`, which writes a 0600 file. The
probe's argv is built the same way, because a rule that holds for the
long-lived process and not for the five-second health check is not a
rule.

**The carrier holds no encryption key, and neither does its child.**
This is the property the whole arrangement rests on: what travels through
the carrier is sealed in the beacon's AES-256-GCM envelope, so a carrier
can be run somewhere exposed and still cannot read or forge a single
message. The team server, however, *does* hold that key -- in
`RACCOON_KEY` in its own environment -- and the team server is the
process that constructs these objects. So the child's environment is
built rather than inherited whole: every `RACCOON_*` variable is dropped,
not just the ones that hold a credential today. `gs-netcat` is a
third-party binary that has never heard of this project, so none of them
can be of use to it, which makes the broad rule both correct and the one
that still covers us when the next credential variable is added.
`GSOCKET_ARGS` goes too: gsocket's tools read it and append it to their
own argv, and the shape it could add includes the `-s <secret>` this
module exists never to produce.

**A reason, not an exception, from `verify_binary`.** The caller decides
whether a reason is fatal. The supervisor turns one into a status row an
operator can read; the implant's own copy of this check turns one into a
`binary_missing` rescue record. Raising would take that decision away
from both. The reasons are written to be read by an operator at three in
the morning and are worded to be copied verbatim: `beacon.py` is served
to a target as source text and may import nothing from this repository,
so the implant's check is a deliberate copy of this one, and two checks
that disagree about wording are two checks that will disagree about
behaviour next.

**`sha256` empty means "do not verify".** The meaning `c2.sliver.sha256`
already has in the same configuration file. A deployment that never
measured its binary still has to be able to run one.

Stdlib only, like the rest of this package.
"""

import hashlib
import os
import signal
import stat
import subprocess
from typing import Dict, List, Optional

from .config import CarrierSpec

# How much of the binary to hash at a time. `gs-netcat` is a couple of
# megabytes statically linked, which would be fine to slurp whole, but
# this is also the code the implant's copy is taken from and an implant
# is a Raspberry Pi Zero.
_HASH_CHUNK = 1024 * 1024

# SIGTERM, then this long, then SIGKILL. A `gs-netcat` that will not
# leave holds the relay address against the next start, and a carrier
# that returned from `stop` with the process still up looks exactly like
# one that was never started.
_TERM_GRACE = 5.0

# Environment variables that must not reach the child. The `RACCOON_`
# prefix is a rule rather than a list on purpose -- see the module
# docstring -- and `GSOCKET_ARGS` is named because dropping it is about
# what gsocket would *add* to our argv, not about what we would leak.
_ENVIRONMENT_PREFIX_DENIED = "RACCOON_"
_ENVIRONMENT_DENIED = frozenset({"GSOCKET_ARGS"})


class CarrierError(Exception):
    """A carrier could not be started, stopped or probed, and why.

    Every one of these names the carrier and carries the underlying
    reason, because the four unrelated faults behind a quiet failure
    here -- no binary, a replaced binary, a dead child, a relay that
    never answered -- all surface later as a beacon that does not check
    in, and an operator chasing that has nothing to tell them apart.
    """


def binary_problem(binary_path: str, sha256: str) -> Optional[str]:
    """Why this `gs-netcat` cannot be exec'd, or `None` when it can.

    Existence, the executable bit and the SHA-256, in that order, each
    returning a reason rather than raising.

    `sha256` empty skips the digest check, exactly as
    `c2.sliver.sha256` does. An upper-case digest is accepted: the
    config validator lower-cases what it reads, but this function is
    also called with digests from elsewhere, and one pasted out of a
    Windows tool matching nothing would read as a replaced binary --
    which is the one finding here nobody should get wrong.

    Module-level rather than a method so that the implant's copy of this
    check has a single function to be compared against, and so that the
    team server can ask about a binary before it has a spec to wrap it
    in.
    """
    path = os.fspath(binary_path)
    if not path.strip():
        # An empty `binary_path`, which is what a configuration written
        # before anybody installed gs-netcat holds. Said plainly,
        # because `os.stat("")` would otherwise produce a reason whose
        # subject is an empty string -- a sentence beginning ": no such
        # file", which reads as a bug in this check rather than as a
        # missing setting.
        return ("no gs-netcat binary is configured: binary_path is empty, so "
                "there is nothing for the carrier to exec")
    try:
        status = os.stat(path)
    except FileNotFoundError:
        return ("%s: no such file, so there is no gs-netcat to exec. Install "
                "the binary at that path, or correct the configured "
                "binary_path" % path)
    except OSError as exc:
        return ("%s: cannot be examined: %s. Until that is answered the "
                "carrier cannot know what it would be exec'ing" % (path, exc))

    if not stat.S_ISREG(status.st_mode):
        # A directory carries the executable bit, so an exec-bit check
        # on its own passes one and the failure arrives from the spawn
        # as a bare permission error against a path that looks right.
        return ("%s: not a regular file, so it is not a binary this carrier "
                "can exec" % path)

    if not os.access(path, os.X_OK):
        return ("%s: mode is 0o%03o, and the user running this process may "
                "not execute it. The carrier execs gs-netcat directly, so "
                "either chmod +x that file or point binary_path at a copy "
                "this user may run" % (path, stat.S_IMODE(status.st_mode)))

    expected = (sha256 or "").strip().lower()
    if not expected:
        # Empty is "do not verify", the meaning c2.sliver.sha256 has.
        return None

    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(_HASH_CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        return ("%s: cannot be read to check its sha256: %s. An unverifiable "
                "binary is treated as a failed check and not as a passed "
                "one" % (path, exc))

    actual = digest.hexdigest()
    if actual != expected:
        return ("%s: its sha256 is %s, but the configuration expects %s. "
                "Either the digest in the configuration is stale, or this is "
                "not the binary that was measured -- and the second one is a "
                "gs-netcat somebody else put there, which would be handed "
                "the secret that fronts the beacon socket"
                % (path, actual, expected))
    return None


def implant_argv(binary_path: str, secret_path: str,
                 local_port: int) -> List[str]:
    """The *implant* side: a local forward that comes out at the server.

    `gs-netcat -k <secret_file> -w -p <local_port>`.

    `-w` is the one flag worth explaining. It makes this end a client
    that **waits** for its peer instead of failing when the peer is not
    there yet, and the normal case is exactly that: an implant powers up
    in a cupboard long before anybody starts the team server, and a
    carrier that exited at once would spend the whole engagement being
    restarted on a timer. See the note above `GsocketCarrier.argv` for
    what is and is not known about the address `-p` binds.

    Lives here, next to the server side, because this is the one place
    the two shapes are written down together. `beacon.py` cannot import
    it -- it is served to a target as source text -- so the implant runs
    a copy; having both shapes in one file is what gives a reviewer
    something to compare that copy against.
    """
    return [os.fspath(binary_path),
            "-k", os.fspath(secret_path),
            "-w",
            "-p", str(local_port)]


def _child_environment() -> Dict[str, str]:
    """The environment a `gs-netcat` child gets: ours, less our secrets.

    A deny rule and not an allow list, and the choice is not cosmetic.
    An allow list is the stronger construction in general, but
    `gs-netcat` is a third-party binary whose environment needs are not
    ours to enumerate -- it reads `HOME`, the proxy variables and the
    relay overrides -- and a variable we withheld would produce a
    carrier that joins the relay network and never finds its peer. That
    is the one failure in this feature that nobody can diagnose: it
    looks identical to a hostile network, a wrong secret and a peer that
    is simply off.

    So everything is inherited except what this project itself sets --
    every `RACCOON_*` variable, which includes the beacon's AES key in
    `RACCOON_KEY` and the operator token in `RACCOON_TOKEN` -- and
    `GSOCKET_ARGS`, which gsocket would append to the argv we so
    carefully built.
    """
    return {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(_ENVIRONMENT_PREFIX_DENIED)
        and name not in _ENVIRONMENT_DENIED
    }


class GsocketCarrier:
    """One `gs-netcat` beside the team server's beacon socket.

    `spec` says which implant's secret this carrier listens under and
    where the beacon socket is; `secret_path` is the 0600 file
    `SecretStore.secret_file_for` just wrote, which is what `-k` is
    pointed at. The secret's *value* is never passed here, which is why
    nothing in this class can put it on a command line even by accident.
    """

    def __init__(self, spec: CarrierSpec, secret_path: str):
        self.spec = spec
        self.secret_path = os.fspath(secret_path)
        self._process = None    # type: Optional[subprocess.Popen]
        self._exit_code = None  # type: Optional[int]

    # ── the command lines ──

    # Which address `gs-netcat`'s own `-p` forward binds is **not
    # verified**. The man page does not say whether a client's local
    # forward binds `127.0.0.1` or every interface, and this repository's
    # *Known limits* says exactly that rather than asserting loopback:
    # the entry records the forward as reachable by any local user on the
    # implant, with its reachability from *off* the host unverified, and
    # names the check below as the thing that settles it.
    #
    # The check that would settle it, in one line: start a real
    # `gs-netcat -k <file> -w -p <port>` -- the implant's own shape, `-w`
    # included, because a differently-shaped process is a different
    # answer -- and look at the listening socket: `ss -ltnp` on Linux,
    # `lsof -nP -iTCP -sTCP:LISTEN` on macOS. Read the local address off
    # it.
    #
    # It has not been run. `gs-netcat` is not installed here, and the
    # two ways to answer it are both side effects nobody asked for:
    # installing a third-party binary system-wide, or running one, which
    # dials the Global Socket Relay Network from the operator's own
    # machine. That traffic has real OPSEC meaning for this project, so
    # the question is recorded rather than guessed at.
    #
    # What depends on the answer: if the forward binds every interface,
    # an implant exposes a path to the team server's beacon socket to
    # its whole subnet, and the fix is a host firewall rule on the
    # implant plus a corrected *Known limits* entry. It is not a redesign
    # and it does not change this argv -- the server side below opens no
    # forward at all -- which is why the work proceeded without it.
    #
    # Note the asymmetry while reading the two shapes: this side is
    # `-l -d <host> -p <port>`, where `-p` is a *destination* port on
    # this machine and binds nothing. Only `implant_argv`'s `-p` opens a
    # listening socket.
    def argv(self) -> List[str]:
        """The *server* side: forward what arrives into the beacon socket.

        `gs-netcat -k <secret_file> -l -d <beacon_host> -p <beacon_port>`.

        `-l` listens on the relay network under this implant's secret,
        and `-d`/`-p` say where to connect what arrives: the team
        server's own beacon socket, usually `127.0.0.1:8443`. So this
        side opens no local forward, which is why `CarrierSpec` has no
        `local_port` to read.
        """
        return [self.spec.binary_path,
                "-k", self.secret_path,
                "-l",
                "-d", self.spec.beacon_host,
                "-p", str(self.spec.beacon_port)]

    def _probe_argv(self) -> List[str]:
        """`-t`: ask the relay network, without connecting anything.

        No `-l` and no `-w`, so the probe neither listens on the relay
        address -- which would race the carrier it is reporting on --
        nor opens a forward. `-k` all the same: the probe is as
        world-visible in `ps` as the long-lived process is.
        """
        return [self.spec.binary_path, "-k", self.secret_path, "-t"]

    # ── the binary ──

    def verify_binary(self) -> Optional[str]:
        """Why this carrier's `gs-netcat` cannot be exec'd, or `None`.

        See `binary_problem`, which is where the reasons live so that
        the implant's copy of this check has one function to be
        compared against.
        """
        return binary_problem(self.spec.binary_path, self.spec.sha256)

    # ── the process ──

    def start(self) -> None:
        """Spawn the carrier, or raise `CarrierError` having spawned nothing.

        Verifies the binary first and refuses otherwise, which is the
        order that matters: a hash check performed after the exec is a
        hash check of something already running.
        """
        if self.is_running():
            raise CarrierError(
                "carrier %r is already running as pid %d; stop it first. Two "
                "gs-netcat processes under one implant's secret means its "
                "connections land on whichever of them the relay network "
                "paired them with, which is a coin toss on every check-in "
                "rather than an error anybody sees"
                % (self.spec.name, self._process.pid))

        reason = self.verify_binary()
        if reason is not None:
            raise CarrierError(
                "carrier %r will not start: %s" % (self.spec.name, reason))

        try:
            self._process = subprocess.Popen(
                self.argv(),
                stdin=subprocess.DEVNULL,
                # `gs-netcat` is a pipe tool: anything it wrote to our
                # stdout would land in the team server's own log stream,
                # interleaved with it. Discarded rather than captured
                # because a captured stream nobody drains fills its pipe
                # buffer and blocks the child -- and the supervisor above
                # is where a carrier's diagnostics belong if they are
                # wanted, since it is the thing that watches the process
                # die.
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=_child_environment(),
                close_fds=True,
                # Its own session, so `stop` can signal the whole group:
                # a `gs-netcat` that spawned anything would otherwise
                # leave it behind holding the relay address, and a
                # SIGINT typed at the team server's terminal would reach
                # every carrier before the server could stop them in
                # order.
                start_new_session=True)
        except OSError as exc:
            self._process = None
            raise CarrierError(
                "carrier %r could not exec %s: %s"
                % (self.spec.name, self.spec.binary_path, exc))
        self._exit_code = None

    def stop(self) -> None:
        """SIGTERM the carrier's process group, then SIGKILL it.

        Safe when nothing is running, and deliberately so: the
        supervisor's shutdown path calls this for every configured
        carrier without first working out which of them it managed to
        start, and a stop that raised for an absent process would make
        the first missing one hide the rest.
        """
        process = self._process
        if process is None:
            return

        if process.poll() is None:
            self._signal_group(process, signal.SIGTERM)
            try:
                process.wait(timeout=_TERM_GRACE)
            except subprocess.TimeoutExpired:
                self._signal_group(process, signal.SIGKILL)
                try:
                    process.wait(timeout=_TERM_GRACE)
                except subprocess.TimeoutExpired:
                    # Nothing left to escalate to, so say so rather than
                    # returning as though the carrier were down. It still
                    # holds the relay address, and the next start would
                    # otherwise be the thing that reported the problem.
                    raise CarrierError(
                        "carrier %r (pid %d) survived SIGTERM and SIGKILL "
                        "and is still running; its relay address is still "
                        "taken" % (self.spec.name, process.pid))

        self._exit_code = process.poll()
        self._process = None

    def is_running(self) -> bool:
        """Whether this carrier's process is up, reaping it if it is not."""
        if self._process is None:
            return False
        code = self._process.poll()
        if code is None:
            return True
        # Reaped here rather than left for the next caller: a zombie
        # would keep `poll` answering for a process that is gone, and
        # the exit code is the only thing distinguishing "the relay
        # refused us" from "somebody killed it".
        self._exit_code = code
        return False

    def status(self) -> Dict[str, object]:
        """What this carrier is, and what its process is doing.

        One row's worth of facts for the supervisor to assemble a panel
        from; it decides what an operator may do about them.

        The secret is absent, and so is the *path* to it: this dict
        becomes an API response and from there a screenshot, and the
        file holding an implant's credential is nothing an operator
        needs to read off a panel. `identity` is a name and belongs
        here -- it is how the supervisor finds the secret, not the
        secret.
        """
        running = self.is_running()
        entry = {
            "name": self.spec.name,
            "identity": self.spec.identity,
            "enabled": self.spec.enabled,
            "beacon_host": self.spec.beacon_host,
            "beacon_port": self.spec.beacon_port,
            "binary_path": self.spec.binary_path,
            "running": running,
            "pid": self._process.pid if running else None,
            "exit_code": self._exit_code,
            "detail": "",
        }  # type: Dict[str, object]

        if running:
            entry["detail"] = "running as pid %d" % self._process.pid
        elif self._exit_code is None:
            entry["detail"] = "configured, not started"
        elif self._exit_code < 0:
            entry["detail"] = "exited on signal %d" % -self._exit_code
        else:
            entry["detail"] = "exited with code %d" % self._exit_code
        return entry

    def probe(self, timeout: float = 5.0) -> bool:
        """Whether the relay network reports a listener on this address.

        `gs-netcat -t` asks the Global Socket Relay Network whether an
        address is being listened on and exits without connecting
        anything to it, which is what makes it usable as a health check:
        the panel can ask it on every page load without touching the
        beacon stream.

        Read the answer for what it is. A zero exit means the relay
        network answered that *somebody* is listening under this
        implant's secret, which on the team server's side is most often
        this very carrier -- so a true here is "our end is on the relay
        and reachable", not "the implant is up". Taken from gsocket's
        documentation rather than from an observation: `gs-netcat` is
        not installed on the machine this was written on, and running
        one would have dialled the relay network to find out.

        A non-zero exit is `False` and not an error: an implant that is
        powered off is the ordinary answer, and a panel that showed a
        fault there would show one for most of every engagement. A probe
        that does not answer within `timeout` is `False` for the same
        reason -- a relay that is slow and a peer that is absent are
        indistinguishable from here -- and the process is killed, since
        `-t` reaches the network and can otherwise hang for as long as
        the network lets it.

        An unusable binary is a `CarrierError`, not a `False`. "No
        listener" and "nothing to ask with" are different answers, and
        collapsing them would have the panel report every implant down
        the moment `gs-netcat` was moved.
        """
        reason = self.verify_binary()
        if reason is not None:
            raise CarrierError(
                "carrier %r cannot be probed: %s" % (self.spec.name, reason))

        try:
            process = subprocess.Popen(
                self._probe_argv(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=_child_environment(),
                close_fds=True,
                start_new_session=True)
        except OSError as exc:
            raise CarrierError(
                "carrier %r could not exec %s to probe: %s"
                % (self.spec.name, self.spec.binary_path, exc))

        try:
            return process.wait(timeout=timeout) == 0
        except subprocess.TimeoutExpired:
            self._signal_group(process, signal.SIGKILL)
            try:
                process.wait(timeout=_TERM_GRACE)
            except subprocess.TimeoutExpired:
                pass
            return False

    @staticmethod
    def _signal_group(process: subprocess.Popen, number: int) -> None:
        """Signal the child's whole process group, or the child alone.

        The group, because `start_new_session=True` made the child a
        group leader and anything it spawned is in there with it. The
        fallbacks are the two races worth surviving: the child exited
        between our `poll` and our signal, or its group is no longer
        ours to signal.
        """
        try:
            os.killpg(os.getpgid(process.pid), number)
        except ProcessLookupError:
            pass
        except OSError:
            # The group is not ours to signal, or the pid has been
            # recycled out from under us. Fall back to the child alone,
            # which is the process we actually care about.
            try:
                process.send_signal(number)
            except ProcessLookupError:
                pass
