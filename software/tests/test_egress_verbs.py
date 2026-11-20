#!/usr/bin/env python3
"""The three verbs that change how a stuck implant gets out.

The beacon dispatched twenty-six verbs and, until these three, offered an
operator almost nothing to decide between when an implant cannot reach the
team server: `software/agent/tools/egress.py` states the limit in its own
comment -- "the implant has no command that changes its proxy or its
transport". Three sub-verbs under one `egress` key change that:

    egress rediscover           re-run proxy discovery, report the list
    egress proxy <index|url>    make a discovered proxy the active one
    egress gsocket              bring the carrier up now, not at the latch

and one standing prohibition: a build whose `c2.proxy.mode` is `none` was
given a deliberate instruction about how it talks, so both proxy verbs are
refused on it.

What these tests are careful about.

**Nothing here reaches a network.** The proxies are URLs in this process's
own environment, which is where `ProxyDiscovery._detect_env_proxy` reads
them; the one that has to exist is a loopback listener that accepts a
connection and closes it. The carrier's child is the shipped stand-in,
`software/tests/data/fake_gs_netcat.sh`, in its client shape -- nothing
joins the Global Socket Relay Network, which is the one side effect this
leg's constraints call out.

**The discovery is the real one.** `discover_all()` is not stood in for,
because the property under test is that the list an operator reads out of
`egress rediscover` and the index `egress proxy` accepts are the same
list. A test against a stubbed list would hold while the numbering drifted
by one.

**The environment is pinned, not inherited.** The machine running the
suite may have `http_proxy` in its shell, and a discovery whose result
depends on that is a test that passes on a laptop and fails in CI. So all
six variables the detector reads are set on every test that discovers
anything, and `no_proxy` with them: `urllib` consults `no_proxy` when
deciding whether a request bypasses the proxy at all, so a developer with
`no_proxy=*` exported would see the last test here never reach the
listener it is about.

**Extra discovered entries are tolerated, never assumed away.** The host
running the suite may have something on `127.0.0.1:3128`, `:8080` or
`:8888`, which `_detect_px_proxy` finds and reports as a candidate. Every
assertion below is about where *our* URL sits in the list the beacon
built, read out of that list, so a host with a proxy of its own changes
nothing.

**No orphans.** Every beacon is torn down through `Beacon.stop`, which
takes the carrier's child with it, and the listener is closed from its
own cleanup.
"""

import base64
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
from software.c2.beacon import Beacon

FAKE_GS_NETCAT = (pathlib.Path(__file__).resolve().parent / "data"
                  / "fake_gs_netcat.sh")

# The six `ProxyDiscovery._detect_env_proxy` reads, in its own order.
_PROXY_ENV = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
              "ALL_PROXY", "all_proxy")

# Not a proxy and not reachable: link-local, so a refusal that leaked into
# a connection attempt would fail locally rather than leave this machine.
_NEVER_DISCOVERED = "http://169.254.169.254:8080"


def _proxy_env(url: str = "") -> dict:
    """The environment the detector reads, holding `url` or no proxy at all."""
    env = {name: "" for name in _PROXY_ENV}
    env["no_proxy"] = ""
    env["NO_PROXY"] = ""
    if url:
        # Both, because a corporate deployment sets both and because the
        # beacon's own callback is https: one variable would discover a
        # proxy the request would then not use.
        env["HTTPS_PROXY"] = url
        env["HTTP_PROXY"] = url
    return env


def _free_port() -> int:
    """A port that was free a moment ago."""
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def _alive(pid: int) -> bool:
    """Whether `pid` exists, without reaping or signalling it."""
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


class _ProxyThatCarriesNothing:
    """A listener that accepts a connection, counts it, and closes it.

    What a corporate proxy looks like from a stuck implant's side when it
    is there and will not carry this traffic: the TCP connect succeeds, so
    selecting it is a sensible thing for an operator to have done, and the
    request through it still fails. The count is what proves the selection
    reached the request path rather than only the beacon's own fields.
    """

    def __init__(self):
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self.port = self._listener.getsockname()[1]
        self.connections = 0
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True,
                                        name="dead-proxy")
        self._thread.start()

    @property
    def url(self) -> str:
        return "http://127.0.0.1:%d" % self.port

    def _serve(self):
        while self._running:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            self.connections += 1
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._running = False
        try:
            self._listener.close()
        except OSError:
            pass
        self._thread.join(timeout=5)


class EgressCase(unittest.TestCase):
    """A beacon with every leg off but what a test turns on, and no orphans."""

    def setUp(self):
        self._beacons = []
        self.addCleanup(self._stop_beacons)

    def _stop_beacons(self):
        for beacon in self._beacons:
            beacon.stop()

    def a_beacon(self, proxy_mode: str = "auto", **c2) -> Beacon:
        config = {"c2": {
            "beacon_interval_seconds": 300,
            "jitter_percent": 0,
            "encryption_key": base64.b64encode(b"\x2a" * 32).decode(),
            "proxy": {"mode": proxy_mode},
            "https": {"enabled": False},
            "dns": {"enabled": False},
            "smb": {"enabled": False},
            "quic": {"enabled": False},
        }}
        config["c2"].update(c2)
        beacon = Beacon(config)
        self._beacons.append(beacon)
        return beacon

    def index_of(self, beacon: Beacon, url: str) -> int:
        """Where `url` sits in what the beacon discovered, as the operator reads it.

        Computed rather than written down as `1`: `_detect_px_proxy` runs
        first and finds whatever the host has on 3128, 8080 or 8888, so
        the position of our own entry is a property of the machine. What
        the tests then assert is that this number -- the one `summary()`
        printed -- is the one the verb takes.
        """
        urls = [p.get("url") for p in beacon._proxy.proxies]
        self.assertIn(url, urls,
                      "the environment's proxy was not discovered at all")
        return urls.index(url) + 1


class TestRediscovery(EgressCase):
    """`egress rediscover`: run discovery again and report the result."""

    def test_rediscover_reports_what_it_found(self):
        url = "http://127.0.0.1:%d" % _free_port()
        beacon = self.a_beacon()

        # Before: nothing has run a discovery, so `proxyinfo` -- the verb
        # this one reports like -- has nothing to show.
        self.assertIn("No proxies discovered", beacon._exec_proxyinfo())

        with mock.patch.dict(os.environ, _proxy_env(url)):
            found = beacon._exec_egress("rediscover")
        self.assertNotIn("[error]", found)
        self.assertIn(url, found)
        self.assertIn("env:HTTPS_PROXY", found)
        # The numbering is in the output, because it is the argument the
        # selection verb takes.
        self.assertIn("[%d] %s" % (self.index_of(beacon, url), url), found)

        # And the point of the verb: the list is refreshed, not added to.
        # The same discovery with the variable gone must lose the entry,
        # or an operator reading a second `rediscover` would be choosing
        # between candidates that no longer exist.
        with mock.patch.dict(os.environ, _proxy_env()):
            again = beacon._exec_egress("rediscover")
        self.assertNotIn(url, again)
        self.assertNotIn(url, [p.get("url")
                               for p in beacon._proxy.proxies])

    def test_egress_is_a_verb_the_beacon_dispatches_on(self):
        # Reachable from tasking and not only from a helper, because
        # tasking is the only way an operator or the orchestrator can
        # reach it. Driven through the real dispatcher: "Unknown command:
        # egress" would leave the discovery unrun, which is what this
        # asserts against.
        url = "http://127.0.0.1:%d" % _free_port()
        beacon = self.a_beacon()
        with mock.patch.dict(os.environ, _proxy_env(url)):
            beacon._process_tasking({"cmd": "egress", "args": "rediscover",
                                     "id": ""})
        self.assertIn(url, [p.get("url") for p in beacon._proxy.proxies])


class TestSelectingADiscoveredProxy(EgressCase):
    """`egress proxy <index|url>`: one of them becomes the active one."""

    def discovered(self, url: str) -> Beacon:
        """A beacon that has just discovered `url` through the real detector.

        The environment is patched for the discovery and not for the
        selection that follows, which pins a decision: the selection
        reads the **last** discovery rather than running one of its own.
        An index an operator read out of `rediscover` has to still mean
        the same candidate when they send it.
        """
        beacon = self.a_beacon()
        with mock.patch.dict(os.environ, _proxy_env(url)):
            beacon._exec_egress("rediscover")
        return beacon

    def test_select_by_index_makes_that_proxy_active(self):
        url = "http://127.0.0.1:%d" % _free_port()
        beacon = self.discovered(url)

        output = beacon._exec_egress("proxy %d" % self.index_of(beacon, url))

        self.assertNotIn("[error]", output)
        self.assertIn(url, output)
        # Both halves move, and both matter. `_active_proxy` is what
        # `proxyinfo` and the check-in's `proxy_active` field report; the
        # session is what `_https_post` actually posts through. A verb
        # that set only the first would report a change it had not made.
        self.assertEqual(beacon._proxy._active_proxy["url"], url)
        self.assertIsNotNone(beacon._proxy_session)
        self.assertEqual(beacon._proxy_session.proxies,
                         {"http": url, "https": url})

    def test_select_by_url_is_matched_against_discovery(self):
        url = "http://127.0.0.1:%d" % _free_port()
        beacon = self.discovered(url)

        output = beacon._exec_egress("proxy %s" % url)

        self.assertNotIn("[error]", output)
        self.assertEqual(beacon._proxy._active_proxy["url"], url)
        self.assertEqual(beacon._proxy_session.proxies,
                         {"http": url, "https": url})
        # Matched against the list and not merely accepted: the entry the
        # verb selected is the discovered one, so its source came along.
        self.assertEqual(beacon._proxy._active_proxy.get("source"),
                         "env:HTTPS_PROXY")

    def test_a_url_discovery_never_found_is_refused_with_the_url_in_the_reason(self):
        url = "http://127.0.0.1:%d" % _free_port()
        beacon = self.discovered(url)

        output = beacon._exec_egress("proxy %s" % _NEVER_DISCOVERED)

        self.assertIn("[error]", output)
        self.assertIn(_NEVER_DISCOVERED, output)
        # Refused, so nothing moved. An arbitrary proxy URL from tasking
        # is the affordance this gate exists to withhold.
        self.assertIsNone(beacon._proxy._active_proxy)
        self.assertIsNone(beacon._proxy_session)

    def test_an_index_outside_the_list_is_refused_with_the_index_in_the_reason(self):
        url = "http://127.0.0.1:%d" % _free_port()
        beacon = self.discovered(url)
        over = len(beacon._proxy.proxies) + 1

        output = beacon._exec_egress("proxy %d" % over)

        self.assertIn("[error]", output)
        self.assertIn(str(over), output)
        self.assertIsNone(beacon._proxy._active_proxy)
        self.assertIsNone(beacon._proxy_session)

    def test_proxy_with_no_argument_is_refused_with_the_list_to_read(self):
        # Refused before any discovery runs, so the message has to point
        # at the verb that prints the numbering rather than at a list it
        # did not build.
        beacon = self.a_beacon()

        output = beacon._exec_egress("proxy")

        self.assertIn("[error]", output)
        self.assertIn("''", output)
        self.assertIn("egress rediscover", output)
        self.assertEqual(beacon._proxy.proxies, [])
        self.assertIsNone(beacon._proxy._active_proxy)
        self.assertIsNone(beacon._proxy_session)

    def test_a_pac_url_is_refused_because_it_is_not_a_proxy_to_post_through(self):
        # Written into the list rather than discovered: a PAC entry comes
        # from the Windows registry, from GNOME or from a WPAD answer, and
        # none of the three can be produced on a test host without asking
        # its network something. The shape is `_detect_wpad`'s own.
        #
        # `_init_proxy` already filters these out before it selects, and
        # for a reason that outlives it: urllib would take
        # `http://host/wpad.dat` apart into a proxy host of
        # `host/wpad.dat`, so the selection would read as done and no
        # request would ever leave.
        beacon = self.a_beacon()
        pac = "http://10.1.2.3/wpad.dat"
        beacon._proxy._discovered = [{"url": pac, "source": "wpad-dns",
                                      "auth": "wpad", "is_pac": True}]

        output = beacon._exec_egress("proxy %s" % pac)

        self.assertIn("[error]", output)
        self.assertIn(pac, output)
        self.assertIsNone(beacon._proxy._active_proxy)
        self.assertIsNone(beacon._proxy_session)

    def test_a_selection_that_carries_no_traffic_is_reported_as_the_leg_failing(self):
        """The verb succeeded and the leg did not; the two must read differently.

        A selection is not a test of the proxy. The operator -- or a
        decider above them -- has to be able to tell "I changed which
        proxy this implant uses" from "and it still cannot get out", and
        a verb that answered "proxy working" would collapse the two.
        """
        proxy = _ProxyThatCarriesNothing()
        self.addCleanup(proxy.stop)
        beacon = self.a_beacon(https={
            "enabled": True,
            # Deliberately not a loopback host: urllib bypasses a proxy
            # for one, so a loopback callback would prove nothing about
            # the selection being in the request path.
            "callback_url": "https://c2.test/api/v1/beacon",
        })

        with mock.patch.dict(os.environ, _proxy_env(proxy.url)):
            beacon._exec_egress("rediscover")
            selected = beacon._exec_egress("proxy %s" % proxy.url)
            self.assertNotIn("[error]", selected)
            self.assertIn(proxy.url, selected)
            # The verb says what it did and what it did not do.
            self.assertIn("the next check-in", selected)

            # Now the leg, through the proxy that was just selected.
            self.assertIsNone(beacon._beacon_https())

        self.assertGreater(proxy.connections, 0,
                           "the selected proxy was never connected to, so the "
                           "selection did not reach the request path")
        self.assertIn("https", beacon._leg_status)
        klass, _code = beacon._leg_status["https"]
        self.assertNotEqual(klass,
                            beacon_mod._RESCUE_CLASSES["not_attempted"])
        self.assertNotEqual(klass, beacon_mod._RESCUE_CLASSES["answered"])


class TestTheProxyProhibition(EgressCase):
    """`c2.proxy.mode: none` is an instruction, and the verbs obey it.

    `_init_proxy` reads that mode as a deliberate statement about how this
    implant talks: it turns `trust_env` off and logs "Proxy: disabled
    (direct connection)". An implant that then selected a proxy for itself
    would contradict an explicit instruction with nobody watching.

    The gate is in the verb and not in whatever sends it, so it binds
    tasking as well as a decider: an operator or an orchestrator queueing
    `egress proxy 1` against such a build is refused by the implant.
    """

    def test_both_proxy_verbs_are_refused_when_proxy_mode_is_none(self):
        url = "http://127.0.0.1:%d" % _free_port()
        beacon = self.a_beacon(proxy_mode="none")

        with mock.patch.dict(os.environ, _proxy_env(url)):
            for args in ("rediscover", "proxy 1", "proxy %s" % url):
                with self.subTest(args=args):
                    output = beacon._exec_egress(args)
                    self.assertIn("[error]", output)
                    # The offending value, by the name the operator set it
                    # under, so the refusal names what to change.
                    self.assertIn("none", output)
                    self.assertIn("c2.proxy.mode", output)

            # And from tasking, through the real dispatcher: a gate that
            # lived only in a decider would leave the same change
            # reachable from a queued task.
            for args in ("rediscover", "proxy 1"):
                beacon._process_tasking({"cmd": "egress", "args": args,
                                         "id": ""})

        self.assertEqual(beacon._proxy.proxies, [],
                         "a refused rediscover ran a discovery anyway")
        self.assertIsNone(beacon._proxy._active_proxy)
        self.assertIsNone(beacon._proxy_session)


class TestTheCarrierVerb(EgressCase):
    """`egress gsocket`: bring the carrier up now, not at the latch.

    The carrier starts today only where `_beacon_loop` concludes that no
    upstream leg delivered. This verb is the operator's own copy of that
    decision, and it goes through the same `_gsocket_start` -- which is
    idempotent, and holds the restart delay and the latched binary
    problem.
    """

    def setUp(self):
        super().setUp()
        self.root = tempfile.mkdtemp(prefix="raccoon-egress-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

        # The secret is a file and never a value on a command line, so the
        # leg needs a path that exists and nothing more.
        self.secret_file = os.path.join(self.root, "gsocket-secret")
        with open(self.secret_file, "w") as handle:
            handle.write("Th1s-Is-N0t-A-Real-Secret\n")
        os.chmod(self.secret_file, 0o600)

        self.binary = os.path.join(self.root, "gs-netcat")
        shutil.copy(FAKE_GS_NETCAT, self.binary)
        os.chmod(self.binary, 0o755)

    def a_carrier_beacon(self, proxy_mode: str = "auto") -> Beacon:
        self.forward_port = _free_port()
        return self.a_beacon(proxy_mode=proxy_mode, gsocket={
            "enabled": True,
            "secret_file": self.secret_file,
            "binary_path": self.binary,
            "local_port": self.forward_port,
        })

    def test_gsocket_starts_the_carrier_now(self):
        beacon = self.a_carrier_beacon()
        self.assertIsNone(beacon._gsocket_proc)

        output = beacon._exec_egress("gsocket")

        self.assertNotIn("[error]", output)
        self.assertIsNotNone(beacon._gsocket_proc)
        pid = beacon._gsocket_proc.pid
        self.assertIn(str(pid), output)
        self.assertTrue(_alive(pid))
        # The stand-in binds `-p` in the implant's client shape, so a
        # forward that accepts is the observable half of a carrier that
        # came up.
        self.assertTrue(_accepts(self.forward_port),
                        "the carrier's forward never accepted")
        self.assertIn(str(self.forward_port), output)

        # Idempotent, as the latch's own caller relies on: asked twice,
        # one child.
        again = beacon._exec_egress("gsocket")
        self.assertNotIn("[error]", again)
        self.assertEqual(beacon._gsocket_proc.pid, pid)
        self.assertEqual(beacon._gsocket_starts, 1)

    def test_gsocket_on_a_build_without_the_leg_reports_that_and_changes_nothing(self):
        # No gsocket block at all, which is every build generated before
        # this leg existed and every build that ships it disabled.
        beacon = self.a_beacon()

        output = beacon._exec_egress("gsocket")

        self.assertIn("[error]", output)
        self.assertIn("gsocket", output)
        self.assertIsNone(beacon._gsocket_proc)
        self.assertEqual(beacon._gsocket_starts, 0)

    def test_the_carrier_verb_is_not_covered_by_the_proxy_prohibition(self):
        # The prohibition is about proxies. A build told to connect
        # directly still has a fifth leg, and a gate that covered this
        # verb too would withhold the one sub-verb that still works on
        # exactly the deployment the prohibition describes.
        beacon = self.a_carrier_beacon(proxy_mode="none")

        output = beacon._exec_egress("gsocket")

        self.assertNotIn("[error]", output)
        self.assertNotIn("c2.proxy.mode", output)
        self.assertIsNotNone(beacon._gsocket_proc)
        self.assertTrue(_accepts(self.forward_port))

    def test_a_carrier_whose_binary_is_missing_reports_the_latched_reason(self):
        beacon = self.a_beacon(gsocket={
            "enabled": True,
            "secret_file": self.secret_file,
            "binary_path": os.path.join(self.root, "not-installed"),
            "local_port": _free_port(),
        })

        # Inside `assertLogs` because `_gsocket_start` latches the reason
        # and warns once when it does. Asserted rather than silenced: the
        # one log line is the other half of this answer on a host whose
        # operator can read neither.
        with self.assertLogs(beacon_mod.logger, level="WARNING") as caught:
            output = beacon._exec_egress("gsocket")

        self.assertIn("[error]", output)
        self.assertIn("not-installed", output)
        self.assertIsNone(beacon._gsocket_proc)
        self.assertEqual(len(caught.records), 1)
        self.assertIn("not-installed", caught.records[0].getMessage())


class TestTheVerbsOwnArgument(EgressCase):
    """One key, three sub-verbs, and a refusal that lists them."""

    def test_an_unknown_egress_argument_is_refused(self):
        beacon = self.a_beacon()
        # The third is the one that matters: `sleep` is a verb the beacon
        # really has, and a decider reaching for it under `egress` must be
        # refused rather than quietly retiming the implant.
        for args, offending in (("", "''"), ("transport smb", "transport"),
                                ("sleep 600", "sleep")):
            with self.subTest(args=args):
                output = beacon._exec_egress(args)
                self.assertIn("[error]", output)
                # The offending value, as every refusal in this file
                # carries it. An empty argument is a value too, and a
                # message that dropped it would read as a bug in the verb.
                self.assertIn(offending, output)
                # The three forms in full, not the bare words: an
                # assertion on "proxy" alone would pass against a message
                # that only echoed the argument back.
                self.assertIn("'egress rediscover'", output)
                self.assertIn("'egress proxy", output)
                self.assertIn("'egress gsocket'", output)
        self.assertEqual(beacon._proxy.proxies, [])
        self.assertIsNone(beacon._proxy._active_proxy)
        self.assertIsNone(beacon._proxy_session)
        self.assertIsNone(beacon._gsocket_proc)


if __name__ == "__main__":
    unittest.main()
