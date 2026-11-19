"""Starting, stopping and reporting on the team server's gsocket carriers.

The team server runs this. It hands each configured carrier the path to
its implant's secret, spawns it, kills it on request, and assembles the
row an operator reads in the 📡 panel beside the listeners'.

**Why this is not a `c2.listeners` entry**, which is the first question
anybody reading it asks. `listeners/registry.py` is built on `bind_host`,
`bind_port` and `relay_url`: it refuses a port outside 1-65535, a missing
`relay_url`, and a `bind_port` equal to the relay's. A carrier binds
nothing and POSTs nothing -- it is a TCP forward from the Global Socket
Relay Network into the beacon socket this server already serves -- so
every one of those validations would have to be special-cased away, and
that module exists to refuse configurations that cannot work. So the
carrier gets its own config block and its own supervisor, the way the
reverse SOCKS tunnel server does.

Three properties are kept from `listeners/supervisor.py`, each learned
from a failure somewhere in this project:

  * **Every refusal carries a reason, with the name or the pid in it.** A
    carrier that silently fails to start shows up later as a beacon that
    does not check in, and at least four unrelated faults produce exactly
    that symptom: no `gs-netcat`, a replaced one, an implant with no
    secret registered, and a child that joined the relay network and
    never found its peer. An operator chasing that symptom has no way to
    tell them apart, so nothing here returns quietly having done nothing.

  * **`managed=False` is a first-class state, not an error.** The compose
    file deliberately does not mount the Docker socket, so a team server
    in a container cannot start a sibling. In that mode `status` still
    reports every configured carrier and says why it cannot act, and the
    panel disables its buttons with that reason showing. A control that
    silently does nothing is the anti-goal.

  * **No secret on a command line.** The secret reaches a carrier as a
    *file path*, from `SecretStore.secret_file_for`, which writes a 0600
    file. Nothing here ever holds the secret's value, which is why
    nothing here can leak one into an argv or a status row.

And one property of its own: **the carrier holds no encryption key, and
neither does this supervisor.** It constructs `GsocketCarrier` objects
and asks the secret store for paths; it never reads `RACCOON_KEY` and has
nothing to do with the beacon's envelope. That is what makes a carrier
safe to run somewhere exposed, and a supervisor that acquired a key
"while it was there" would be the first step in losing it.

Two things this deliberately does **not** do.

*It does not restart anything.* No timer, no attempt ceiling, no health
poller. `carrier.py` says the same about itself, for the same reason: a
restart loop in two places is a `gs-netcat` that reappears after an
operator stopped it. Starting and stopping are operator verbs here, as
they are for the listeners, which is also why `enabled` is reported in
the row and not acted on -- nothing in this arrangement starts a process
by itself.

*It does not probe.* `GsocketCarrier.probe()` re-hashes the binary on
every call, because it verifies before it execs, and a configured
`sha256` re-reads a multi-megabyte file. A panel page load must not pay
that -- and worse than the cost, a status row that re-verified would
report a replaced binary for a carrier that is running perfectly well,
which is the one finding in this feature nobody should get wrong. If a
relay-level health indicator is wanted, it needs its own route or an
explicit operator action.

Stdlib only, like the rest of this package. Nothing here may import from
`software.c2.server`.
"""

import logging
import threading
import time
from typing import Dict, List

from .carrier import CarrierError, GsocketCarrier
from .config import CarrierSpec

# The one logger in this package, and it exists for exactly one message:
# the carrier that could not be stopped on the way out. `secrets.py` says
# in as many words that it has no logger, and `carrier.py` has none
# either -- both of them answer their callers with a reason instead, and
# a caller is always there to read it. `stop_all` is the exception: it is
# called from the team server's shutdown path, after the serving loop has
# returned, so there is nobody left to hand a refusal to. Without this
# the one failure that path exists to prevent -- a `gs-netcat` that
# survived SIGTERM and SIGKILL, still holding its implant's address on
# the relay network -- would be noticed first by the *next* start, which
# would pair that implant against a process with nothing behind it and no
# antecedent anywhere in the log.
logger = logging.getLogger("raccoon.gsocket.supervisor")

# What the panel calls this transport. One spelling, here, because the
# row is merged into a list of listener rows and the page branches on it.
TRANSPORT = "gsocket"


class CarrierSupervisor:
    """Own the `gs-netcat` carrier processes this deployment is responsible for.

    `specs` are validated `CarrierSpec`s from `config.load_carriers`;
    `store` is the `secrets.SecretStore` the identities are looked up in.
    The store is asked on every start rather than read once: the build
    generator registers an implant's secret in one process while this
    long-lived one reads it, so a supervisor holding a copy taken at
    start-up would answer "no such implant" for a build generated a
    minute ago.
    """

    def __init__(self, specs: List[CarrierSpec], store, *,
                 managed: bool = True):
        self.specs = {spec.name: spec for spec in specs}
        self.store = store
        self.managed = managed
        self._carriers = {}  # type: Dict[str, GsocketCarrier]
        # When each running carrier was started, by the monotonic clock:
        # `uptime` is a duration, and a wall-clock step -- an operator
        # fixing the server's time, or NTP catching up on a drop-box --
        # would otherwise put a negative number on the panel.
        self._started = {}   # type: Dict[str, float]
        # What last happened to a carrier that its process cannot tell
        # us: the reason a start was refused, or the fact that this
        # server stopped it. Both exist because the process alone gives a
        # misleading answer. A `GsocketCarrier` whose start failed still
        # holds the *previous* run's exit code, so a row assembled from
        # it would report "exited on signal 15" for what is really a
        # binary that could not be exec'd -- the previous event, read as
        # this one. Cleared by a start that works.
        self._notes = {}     # type: Dict[str, str]
        self._lock = threading.Lock()

    # ── the three the panel calls ──

    def start(self, name: str) -> dict:
        """Spawn one carrier, or raise `CarrierError` saying why not."""
        spec = self._spec(name)
        self._require_managed("start", name)
        with self._lock:
            carrier = self._carriers.get(name)
            if carrier is not None and carrier.is_running():
                # Not recorded as a note: the carrier is up, and this
                # refusal is about the request rather than about it.
                raise CarrierError(
                    "carrier %r is already running as pid %d; stop it "
                    "first. Two gs-netcat processes under one implant's "
                    "secret means its connections land on whichever of "
                    "them the relay network paired them with, which is a "
                    "coin toss on every check-in rather than an error "
                    "anybody sees" % (name, carrier.status()["pid"]))
            try:
                # A fresh object per attempt, so a successful start never
                # inherits a previous run's exit code, and the secret
                # file is rewritten from the store each time -- a key
                # file left from an earlier registration is one the store
                # no longer agrees with.
                fresh = GsocketCarrier(spec, str(self._secret_file(spec)))
                fresh.start()
            except CarrierError as exc:
                self._notes[name] = "start refused: %s" % exc
                raise
            self._carriers[name] = fresh
            self._started[name] = time.monotonic()
            self._notes.pop(name, None)
            return self._row(spec)

    def stop(self, name: str) -> dict:
        """Signal one carrier away, or raise `CarrierError` saying why not."""
        spec = self._spec(name)
        self._require_managed("stop", name)
        with self._lock:
            carrier = self._carriers.get(name)
            if carrier is None or not carrier.is_running():
                raise CarrierError(
                    "carrier %r is not running, so there is nothing to "
                    "stop" % name)
            # Read before the signal, because afterwards there is no
            # process left to ask -- and the pid is what makes the note
            # below something an operator can check in `ps`.
            pid = carrier.status()["pid"]
            # Raises if the child survived SIGTERM and SIGKILL, and that
            # propagates: it would still hold its implant's relay address,
            # so an answer saying the carrier is down would be a lie that
            # the next start is the first thing to notice.
            carrier.stop()
            self._started.pop(name, None)
            self._notes[name] = (
                "stopped from the panel: this server signalled pid %d and "
                "it is gone" % pid)
            return self._row(spec)

    def status(self) -> List[dict]:
        """One row per configured carrier, in name order.

        Cheap on purpose: a `poll` per carrier and no more. See the module
        docstring on why this path does not probe the relay network or
        re-hash a binary.
        """
        with self._lock:
            return [self._row(self.specs[name]) for name in sorted(self.specs)]

    def stop_all(self) -> None:
        """Tear everything down. Used on shutdown and by every test.

        Every carrier is signalled without first working out which of
        them started, and a failure to stop one does not abandon the
        rest: a `gs-netcat` left behind holds its implant's relay address
        against the next start, and there would be no panel left to stop
        it from.

        A carrier that could not be stopped is **logged**, not swallowed.
        `GsocketCarrier.stop` raises in one case only -- a child that
        survived SIGTERM and SIGKILL -- and that is exactly the orphan
        this method exists to prevent, so it is the one message here
        worth more than the rest. Everything else in this module hands
        its reason to a caller; this path has none, because it runs after
        the serving loop has returned.
        """
        with self._lock:
            for name in list(self._carriers):
                carrier = self._carriers.pop(name)
                self._started.pop(name, None)
                try:
                    carrier.stop()
                except Exception as exc:
                    # Broad on purpose: the next carrier must be stopped
                    # whatever went wrong with this one, and a shutdown
                    # path that raised would leave the rest running. What
                    # changes with the log line is only that the reason
                    # survives.
                    logger.warning(
                        "carrier %s could not be stopped on shutdown: %s",
                        name, exc)

    # ── internals ──

    def _spec(self, name: str) -> CarrierSpec:
        spec = self.specs.get(name)
        if spec is None:
            # Asked before `_require_managed`, so that an operator who
            # mistyped a name is told that, rather than being told about
            # Docker sockets for a carrier that does not exist.
            raise CarrierError(
                "no carrier called %r is configured; have %s"
                % (name, ", ".join(sorted(self.specs)) or "none"))
        return spec

    def _require_managed(self, action: str, name: str) -> None:
        if not self.managed:
            raise CarrierError(
                "this deployment does not manage carrier processes, so it "
                "cannot %s carrier %r. The team server is running without "
                "the privilege to start a sibling process -- in Docker that "
                "is deliberate, because mounting the Docker socket would "
                "give the container control of its host. Start and stop the "
                "carriers the same way the team server itself is started."
                % (action, name))

    def _secret_file(self, spec: CarrierSpec):
        """The 0600 file `gs-netcat -k` is pointed at, or `CarrierError`.

        The store's two refusals are kept apart deliberately. A missing
        registration is retryable the moment a build has been generated;
        a key file other users can read is a disclosure, and what it
        calls for is a new secret and a reflashed implant rather than
        another attempt. One "could not start" covering both would hide
        the difference between "do this next" and "that credential is
        burned".
        """
        try:
            return self.store.secret_file_for(spec.identity)
        except KeyError as exc:
            # KeyError stringifies to the repr of its argument, which
            # would wrap a whole sentence in quotes.
            reason = exc.args[0] if exc.args else "it has no secret"
            raise CarrierError(
                "carrier %r will not start: %s. Nothing can listen under an "
                "implant's secret before that implant has one: generate "
                "that implant's build, which registers a secret, and start "
                "this carrier afterwards" % (spec.name, reason))
        except ValueError as exc:
            raise CarrierError(
                "carrier %r will not start, and this one is not to be "
                "retried: %s" % (spec.name, exc))
        except OSError as exc:
            raise CarrierError(
                "carrier %r will not start: its secret could not be written "
                "for gs-netcat to read: %s. The carrier is handed a file "
                "path rather than the secret itself, so without that file "
                "there is nothing to pass" % (spec.name, exc))

    def _row(self, spec: CarrierSpec) -> dict:
        """One panel row. The caller holds the lock.

        The keys a listener row has are here too -- `transport`, `state`,
        `can_control`, `detail` -- because this row is merged into that
        list and the panel's renderer reads them. `state` carries the
        same four words a listener's does rather than only the boolean
        `running`, and `unmanaged` is why: a deployment that cannot act
        is a state an operator has to be able to see, and a boolean
        cannot say it.

        `socket` is always `None`, and it is the field that tells the two
        kinds of row apart. A carrier binds nothing: it listens on the
        relay network under one implant's secret and connects what
        arrives to the beacon socket, so there is no host and port to
        report and `identity` is the only address it has.

        Neither the secret nor the path to it appears. This dict becomes
        an API response and from there a screenshot.
        """
        name = spec.name
        carrier = self._carriers.get(name)
        inner = carrier.status() if carrier is not None else None
        running = bool(inner and inner["running"])
        started = self._started.get(name)
        row = {
            "name": name,
            "transport": TRANSPORT,
            "identity": spec.identity,
            "enabled": spec.enabled,
            "socket": None,
            "running": running,
            "state": "running" if running else "stopped",
            "can_control": self.managed,
            "pid": inner["pid"] if running else None,
            "uptime": (int(time.monotonic() - started)
                       if running and started is not None else None),
            "detail": "",
        }  # type: Dict[str, object]

        if not self.managed:
            # Reported, not hidden, and with the reason in the row: the
            # panel renders it beside a disabled button.
            row["state"] = "unmanaged"
            row["detail"] = (
                "this deployment does not manage carrier processes; start "
                "and stop them the way the team server is started")
            return row

        note = self._notes.get(name)
        if running:
            row["detail"] = "running as pid %d" % inner["pid"]
            if row["uptime"] is not None:
                # Said in the row because a carrier that has been up all
                # week and one that is being restarted in a loop look
                # identical without it. Guarded rather than assumed: a
                # row that raised a TypeError here would take the whole
                # panel down, which is a worse answer than a row with no
                # duration in it.
                row["detail"] += ", up %ds" % row["uptime"]
        elif note is not None:
            row["detail"] = note
        elif inner is None:
            row["detail"] = "configured, not started"
        else:
            # It died on its own, and the honest row says only that much.
            # The child's stderr goes to DEVNULL, as sliver.py's does, so
            # the characteristic failure here -- it joined the relay
            # network and never found its peer -- arrives as an exit
            # status with no message, and a row that named a cause would
            # be guessing at the one thing an operator cannot check.
            row["state"] = "died"
            row["detail"] = (
                "%s, and that is all this server knows: a carrier's output "
                "is discarded, as a listener's is, so even the failure that "
                "matters most here -- a relay that never paired it with its "
                "implant -- would leave no message behind" % inner["detail"])
        return row
