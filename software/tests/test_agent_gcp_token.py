#!/usr/bin/env python3
"""
Tests for the Google token source: caching and the refresh window, the lock
that keeps concurrent callers to one fetch, each of the three sources, and
above all that no message carries a token, a response body, a URL or a
subprocess's output.

The metadata tests talk to a real HTTP server on the loopback interface
rather than a stub of urllib, so the header, the timeout and the status
handling are the ones a real request exercises. The clock, the fetchers and
the file reader are injected; nothing here touches the network beyond
127.0.0.1, spawns gcloud, or reads a file outside a temporary directory.
Every credential in here is an obvious fake.
"""

import datetime
import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent import secret
from software.agent.llm import gcp_token

_SKEW = gcp_token.SKEW_SECONDS


def _chain(exc):
    """Everything a hand-written error serialiser could reach from `exc`:
    each link's repr, its attributes, and the bytes a decode error holds."""
    parts, seen, current = [], set(), exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        parts.append(repr(current))
        parts.append(repr(getattr(current, "__dict__", {})))
        parts.append(repr(getattr(current, "object", None)))
        parts.append(repr(getattr(current, "output", None)))
        parts.append(repr(getattr(current, "stderr", None)))
        current = current.__context__ or current.__cause__
    return " ".join(parts)


class _Clock:
    def __init__(self, start=0.0):
        self.t = start

    def __call__(self):
        return self.t


class _Counting:
    """A fetcher that hands out tok-1, tok-2, ... and counts its calls."""

    def __init__(self, lifetime=3600, delay=0.0):
        self.calls = 0
        self.lifetime = lifetime
        self.delay = delay
        self._lock = threading.Lock()

    def __call__(self):
        with self._lock:
            self.calls += 1
            n = self.calls
        if self.delay:
            time.sleep(self.delay)
        return "tok-%d" % n, self.lifetime


def _with(fetcher, kind="metadata", clock=None):
    return gcp_token.TokenSource(kind, now=clock or _Clock(),
                                 fetchers={kind: fetcher})


def _failing(message):
    def fetch():
        raise gcp_token.TokenUnavailable(message)
    return fetch


class _MetadataServer:
    """A loopback server standing in for the metadata server."""

    def __init__(self, status=200, body=b"", delay=0.0):
        outer = self
        self.requests = []
        self.status, self.body, self.delay = status, body, delay

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requests.append((self.path, dict(self.headers)))
                if outer.delay:
                    time.sleep(outer.delay)
                try:
                    self.send_response(outer.status)
                    self.send_header("Content-Length", str(len(outer.body)))
                    self.end_headers()
                    self.wfile.write(outer.body)
                except OSError:
                    pass  # the client gave up first

            def log_message(self, *args):
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._server.block_on_close = False
        self.url = "http://127.0.0.1:%d/token" % self._server.server_address[1]

    def __enter__(self):
        threading.Thread(target=self._server.serve_forever, args=(0.01,),
                         daemon=True).start()
        patcher = unittest.mock.patch.object(gcp_token, "METADATA_URL", self.url)
        patcher.start()
        self._patcher = patcher
        return self

    def __exit__(self, *exc):
        self._patcher.stop()
        self._server.shutdown()
        self._server.server_close()


def _completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(
        ["gcloud"], returncode, stdout=stdout, stderr=stderr)


class TestCaching(unittest.TestCase):
    def test_a_cached_token_is_reused_until_the_skew_window(self):
        fetcher = _Counting(lifetime=3600)
        clock = _Clock()
        src = _with(fetcher, clock=clock)

        self.assertEqual(src.bearer(), "tok-1")
        clock.t = 3600 - _SKEW - 1
        self.assertEqual(src.bearer(), "tok-1")
        self.assertEqual(fetcher.calls, 1)

        clock.t = 3600 - _SKEW
        self.assertEqual(src.bearer(), "tok-2")
        self.assertEqual(fetcher.calls, 2)

    def test_the_window_is_measured_from_the_new_fetch(self):
        fetcher = _Counting(lifetime=3600)
        clock = _Clock()
        src = _with(fetcher, clock=clock)
        src.bearer()
        clock.t = 4000
        self.assertEqual(src.bearer(), "tok-2")
        clock.t = 4000 + 3600 - _SKEW - 1
        self.assertEqual(src.bearer(), "tok-2")
        self.assertEqual(fetcher.calls, 2)

    def test_concurrent_callers_meeting_an_expired_token_fetch_once(self):
        fetcher = _Counting(delay=0.05)
        src = _with(fetcher)
        results = []
        barrier = threading.Barrier(8)

        def call():
            barrier.wait()
            results.append(src.bearer())

        threads = [threading.Thread(target=call) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(fetcher.calls, 1)
        self.assertEqual(results, ["tok-1"] * 8)

    def _blocked_refresh(self):
        """A source whose second fetch blocks until `release` is set.

        Returns (source, clock, release, started). `started` is set once the
        refreshing thread is inside the fetch, holding the lock. The first
        token is fetched at t=0 and lives to 3600.
        """
        clock = _Clock()
        started, release = threading.Event(), threading.Event()
        calls = []

        def fetch():
            calls.append(1)
            if len(calls) == 2:
                started.set()
                release.wait(5)
            return "tok-%d" % len(calls), 3600

        src = _with(fetch, clock=clock)
        src.calls = calls
        self.assertEqual(src.bearer(), "tok-1")
        return src, clock, release, started

    def test_a_caller_with_a_usable_token_does_not_queue_behind_a_refresh(self):
        src, clock, release, started = self._blocked_refresh()
        clock.t = 3600 - 10  # inside the skew window, not expired
        refresher = threading.Thread(target=src.bearer)
        refresher.start()
        self.addCleanup(refresher.join)
        self.addCleanup(release.set)
        self.assertTrue(started.wait(5))

        answered = []
        waiter = threading.Thread(target=lambda: answered.append(src.bearer()))
        waiter.start()
        waiter.join(1.0)
        self.assertFalse(waiter.is_alive(), "queued behind the refresh")
        self.assertEqual(answered, ["tok-1"])
        self.assertEqual(len(src.calls), 2)

    def test_a_caller_with_an_expired_token_waits_and_shares_the_one_fetch(self):
        src, clock, release, started = self._blocked_refresh()
        clock.t = 3600 + 1  # expired
        answered = []
        refresher = threading.Thread(
            target=lambda: answered.append(src.bearer()))
        refresher.start()
        self.addCleanup(refresher.join)
        self.addCleanup(release.set)
        self.assertTrue(started.wait(5))

        waiter = threading.Thread(target=lambda: answered.append(src.bearer()))
        waiter.start()
        self.addCleanup(waiter.join)
        waiter.join(0.2)
        self.assertTrue(waiter.is_alive(), "returned an expired token")

        release.set()
        waiter.join(5)
        refresher.join(5)
        self.assertEqual(answered, ["tok-2", "tok-2"])
        self.assertEqual(len(src.calls), 2)

    def test_a_failed_refresh_inside_the_skew_window_returns_the_cached_token(self):
        clock = _Clock()
        outcomes = [("tok-1", 3600), gcp_token.TokenUnavailable("down"),
                    ("tok-2", 3600)]
        calls = []

        def fetch():
            calls.append(1)
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        src = _with(fetch, clock=clock)
        self.assertEqual(src.bearer(), "tok-1")
        # Inside the window (refresh due) but one second short of expiry.
        clock.t = 3600 - 1
        self.assertEqual(src.bearer(), "tok-1")
        self.assertEqual(len(calls), 2)
        # The failure did not poison the cache: the next call retries.
        self.assertEqual(src.bearer(), "tok-2")
        self.assertEqual(len(calls), 3)

    def test_a_failed_refresh_at_the_start_of_the_window_returns_the_cached_token(self):
        clock = _Clock()
        outcomes = [("tok-1", 3600), gcp_token.TokenUnavailable("down")]

        def fetch():
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        src = _with(fetch, clock=clock)
        src.bearer()
        clock.t = 3600 - _SKEW
        self.assertEqual(src.bearer(), "tok-1")

    def test_a_failed_refresh_past_expiry_raises(self):
        for at in (3600, 3601, 10 ** 6):
            with self.subTest(at=at):
                clock = _Clock()
                outcomes = [("tok-1", 3600),
                            gcp_token.TokenUnavailable("down")]

                def fetch():
                    outcome = outcomes.pop(0)
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome

                src = _with(fetch, clock=clock)
                self.assertEqual(src.bearer(), "tok-1")
                clock.t = at
                with self.assertRaises(gcp_token.TokenUnavailable) as caught:
                    src.bearer()
                self.assertIn("down", str(caught.exception))

    def test_a_failed_first_fetch_raises(self):
        with self.assertRaises(gcp_token.TokenUnavailable):
            _with(_failing("down")).bearer()

    def test_a_failed_refresh_then_recovery_after_expiry(self):
        clock = _Clock()
        outcomes = [("tok-1", 3600), gcp_token.TokenUnavailable("down"),
                    ("tok-2", 3600)]

        def fetch():
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        src = _with(fetch, clock=clock)
        src.bearer()
        clock.t = 3600
        with self.assertRaises(gcp_token.TokenUnavailable):
            src.bearer()
        self.assertEqual(src.bearer(), "tok-2")

    def test_the_shared_source_is_returned_per_kind_and_path(self):
        self.addCleanup(gcp_token._shared.clear)
        self.assertIs(gcp_token.source("gcloud"), gcp_token.source("gcloud"))
        self.assertIsNot(gcp_token.source("file", key_file="/a"),
                         gcp_token.source("file", key_file="/b"))
        self.assertIsNot(gcp_token.source("gcloud"),
                         gcp_token.source("metadata"))

    def test_the_source_reports_its_kind(self):
        self.addCleanup(gcp_token._shared.clear)
        self.assertEqual(gcp_token.source("metadata").kind, "metadata")

    def test_an_unknown_kind_is_refused(self):
        self.addCleanup(gcp_token._shared.clear)
        with self.assertRaises(gcp_token.TokenUnavailable):
            gcp_token.source("kerberos")
        with self.assertRaises(gcp_token.TokenUnavailable):
            gcp_token.validate("kerberos")


class TestLifetimeClamp(unittest.TestCase):
    def _recorded(self, raw):
        """The expiry the cache records for a token reported with `raw`,
        fetched at t=0."""
        src = _with(_Counting(lifetime=raw), clock=_Clock())
        src.bearer()
        return src._cached[1]

    def test_a_reported_lifetime_is_believed_up_to_an_hour(self):
        for raw, recorded in ((1, 1), (_SKEW, _SKEW), (_SKEW + 1, _SKEW + 1),
                              (3000, 3000), ("3000", 3000), (1800.7, 1800),
                              (3600, 3600), (10 ** 9, 3600)):
            with self.subTest(raw=raw):
                self.assertEqual(self._recorded(raw), recorded)

    def test_an_unreadable_lifetime_gets_the_assumed_one(self):
        for raw in (None, 0, -5, "soon", True, float("nan"), float("inf")):
            with self.subTest(raw=raw):
                self.assertEqual(self._recorded(raw),
                                 gcp_token.GCLOUD_ASSUMED_LIFETIME)

    def test_a_short_lived_token_is_never_returned_past_its_real_expiry(self):
        # A token reported with a minute left, and a refresh that fails.
        # The fallback hands out the cached token while it is alive and not
        # after: a floor that recorded five minutes would hand it out dead.
        clock = _Clock()
        outcomes = [("tok-1", 60)]

        def fetch():
            if outcomes:
                return outcomes.pop(0)
            raise gcp_token.TokenUnavailable("down")

        src = _with(fetch, clock=clock)
        self.assertEqual(src.bearer(), "tok-1")
        clock.t = 59
        self.assertEqual(src.bearer(), "tok-1")
        clock.t = 60
        with self.assertRaises(gcp_token.TokenUnavailable):
            src.bearer()

    def test_a_short_lived_token_is_fetched_again_on_the_next_call(self):
        fetcher = _Counting(lifetime=_SKEW)
        src = _with(fetcher, clock=_Clock())
        self.assertEqual(src.bearer(), "tok-1")
        self.assertEqual(src.bearer(), "tok-2")
        self.assertEqual(fetcher.calls, 2)


class TestMetadata(unittest.TestCase):
    def _source(self):
        return gcp_token.TokenSource("metadata", now=_Clock())

    def test_the_token_and_lifetime_come_from_the_json_body(self):
        body = b'{"access_token": "tok-fake", "expires_in": 3599}'
        with _MetadataServer(body=body):
            self.assertEqual(self._source().bearer(), "tok-fake")

    def test_the_request_carries_the_metadata_flavor_header(self):
        body = b'{"access_token": "tok-fake", "expires_in": 3599}'
        with _MetadataServer(body=body) as server:
            self._source().bearer()
        self.assertEqual(len(server.requests), 1)
        headers = {k.lower(): v for k, v in server.requests[0][1].items()}
        self.assertEqual(headers.get("metadata-flavor"), "Google")

    def test_an_absent_metadata_server_raises_promptly(self):
        # Bind and release a port: nothing listens there, so the connection
        # is refused.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        with unittest.mock.patch.object(
                gcp_token, "METADATA_URL", "http://127.0.0.1:%d/t" % port):
            with self.assertRaises(gcp_token.TokenUnavailable):
                self._source().bearer()

    def test_a_metadata_server_that_never_answers_raises_within_its_timeout(self):
        # The server would answer after 5 s, far past the bound, and what it
        # would say is a valid body: only the timeout can make this fail, so
        # the test proves the timeout is applied.
        body = b'{"access_token": "tok-fake", "expires_in": 3599}'
        with _MetadataServer(delay=5.0, body=body):
            with unittest.mock.patch.object(gcp_token, "METADATA_TIMEOUT", 0.3):
                started = time.monotonic()
                with self.assertRaises(gcp_token.TokenUnavailable) as caught:
                    self._source().bearer()
                elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1.0)
        self.assertIn("unreachable", str(caught.exception))

    def test_the_request_does_not_go_through_a_proxy(self):
        # A proxy that is set but dead: a request that honoured it would
        # fail, and one that did not reaches the server.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        dead = "http://127.0.0.1:%d" % probe.getsockname()[1]
        probe.close()
        body = b'{"access_token": "tok-fake", "expires_in": 3599}'
        env = {"http_proxy": dead, "HTTP_PROXY": dead,
               "no_proxy": "", "NO_PROXY": ""}
        with _MetadataServer(body=body) as server, \
                unittest.mock.patch.dict(os.environ, env):
            self.assertEqual(self._source().bearer(), "tok-fake")
        self.assertEqual(len(server.requests), 1)

    def test_a_failure_message_holds_no_body_and_no_url(self):
        body = b'{"access_token": "tok-SECRET"}'
        with _MetadataServer(status=500, body=body) as server:
            with self.assertRaises(gcp_token.TokenUnavailable) as caught:
                self._source().bearer()
        message = str(caught.exception)
        self.assertIn("500", message)
        self.assertNotIn("SECRET", message)
        self.assertNotIn("metadata.google.internal", message)
        self.assertNotIn(server.url, message)
        self.assertNotIn("127.0.0.1", message)

    def test_a_failure_leaves_no_context_to_walk(self):
        body = b'{"access_token": "tok-SECRET"}'
        with _MetadataServer(status=500, body=body):
            with self.assertRaises(gcp_token.TokenUnavailable) as caught:
                self._source().bearer()
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)

    def test_a_body_that_is_not_json_is_unavailable(self):
        with _MetadataServer(body=b"tok-SECRET is not json"):
            with self.assertRaises(gcp_token.TokenUnavailable) as caught:
                self._source().bearer()
        self.assertNotIn("SECRET", str(caught.exception))

    def test_a_body_that_is_not_an_object_is_unavailable(self):
        with _MetadataServer(body=b'["tok-SECRET"]'):
            with self.assertRaises(gcp_token.TokenUnavailable) as caught:
                self._source().bearer()
        self.assertNotIn("SECRET", str(caught.exception))

    def test_a_body_without_a_token_is_unavailable(self):
        with _MetadataServer(body=b'{"expires_in": 3600}'):
            with self.assertRaises(gcp_token.TokenUnavailable):
                self._source().bearer()


_HELPER = ["gcloud", "config", "config-helper", "--format=json"]
_PRINT = ["gcloud", "auth", "print-access-token"]
# Fixed, so an expiry string and the clock it is compared with agree.
_WALL0 = 1_800_000_000.0


def _expiry(seconds_from_wall0):
    when = datetime.datetime.fromtimestamp(_WALL0 + seconds_from_wall0,
                                           datetime.timezone.utc)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def _helper_json(token, expires_in=None, expiry=None):
    """What `gcloud config config-helper --format=json` prints. The id_token
    and the account are there because the real output carries them, and
    neither may ever reach a message."""
    credential = {"access_token": token, "id_token": "idtok-SECRET"}
    if expiry is not None:
        credential["token_expiry"] = expiry
    elif expires_in is not None:
        credential["token_expiry"] = _expiry(expires_in)
    return json.dumps({"configuration": {"properties": {"core": {
        "account": "bob@corp.example"}}}, "credential": credential})


class _Gcloud:
    """subprocess.run standing in for gcloud, answering per subcommand."""

    def __init__(self, helper=None, plain=None):
        self.helper, self.plain = helper, plain
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), kwargs))
        answer = self.helper if args == _HELPER else self.plain
        if callable(answer):
            answer = answer()
        if isinstance(answer, BaseException):
            raise answer
        if answer is None:
            raise AssertionError("unexpected gcloud call %r" % (args,))
        return answer


class TestGcloud(unittest.TestCase):
    def setUp(self):
        self.clock = _Clock()
        # The wall clock moves with the cache's clock, as it would.
        wall = unittest.mock.patch.object(
            gcp_token, "_wall_clock", lambda: _WALL0 + self.clock.t)
        wall.start()
        self.addCleanup(wall.stop)

    def _source(self):
        return gcp_token.TokenSource("gcloud", now=self.clock)

    def _run(self, fake):
        return unittest.mock.patch.object(gcp_token.subprocess, "run", fake)

    # ── config-helper, which says when the token expires ──

    def test_config_helper_is_asked_first_and_its_token_is_used(self):
        fake = _Gcloud(helper=_completed(_helper_json("tok-fake", 3000)))
        with self._run(fake):
            self.assertEqual(self._source().bearer(), "tok-fake")
        self.assertEqual([c[0] for c in fake.calls], [_HELPER])
        kwargs = fake.calls[0][1]
        self.assertEqual(kwargs["timeout"], gcp_token.GCLOUD_TIMEOUT)
        self.assertTrue(kwargs["capture_output"])
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)

    def test_the_real_expiry_sets_the_lifetime(self):
        # Ten minutes left: refreshed five minutes in, not twenty-five.
        # And fifty-eight minutes left: not refreshed after one, as the
        # short assumption for an unknown expiry would.
        for left, quiet_at, due_at in ((600, 250, 350),
                                       (3480, 3000, 3200)):
            with self.subTest(left=left):
                self.clock.t = 0
                fake = _Gcloud(helper=lambda: _completed(
                    _helper_json("tok-%d" % len(fake.calls), left)))
                src = self._source()
                with self._run(fake):
                    src.bearer()
                    self.clock.t = quiet_at
                    src.bearer()
                    self.assertEqual(len(fake.calls), 1)
                    self.clock.t = due_at
                    src.bearer()
                    self.assertEqual(len(fake.calls), 2)

    def test_gcloud_handing_back_its_cached_token_never_outlives_it(self):
        # The reviewer's sequence. gcloud prints the token it holds until
        # that one is within five minutes of expiry, then a new one for an
        # hour. Under a fixed assumed lifetime the same token was re-cached
        # at every refresh and handed out after it had died. Walked over two
        # hours, a token is never handed out at or past its real expiry.
        issued = [("tok-0", 3600.0)]  # (token, expiry in seconds from _WALL0)

        def gcloud():
            token, expiry = issued[-1]
            if expiry - self.clock.t <= 300:
                token, expiry = "tok-%d" % len(issued), self.clock.t + 3600
                issued.append((token, expiry))
            return _completed(_helper_json(token, expiry=_expiry(expiry)))

        expiries = {}
        src = self._source()
        with self._run(_Gcloud(helper=gcloud)):
            for t in range(0, 7200, 30):
                self.clock.t = t
                token = src.bearer()
                expiries.update(issued)
                self.assertGreater(expiries[token], t,
                                   "%s handed out at t=%d, dead at %d"
                                   % (token, t, expiries[token]))
        self.assertGreater(len(issued), 1)

    def test_an_unreadable_expiry_gets_the_short_assumed_lifetime(self):
        for expiry in ("soon", "", "2026-13-45T99:00:00Z", 12345):
            with self.subTest(expiry=expiry):
                self.clock.t = 0
                payload = json.loads(_helper_json("tok-fake"))
                payload["credential"]["token_expiry"] = expiry
                fake = _Gcloud(helper=_completed(json.dumps(payload)))
                src = self._source()
                life = gcp_token.GCLOUD_ASSUMED_LIFETIME
                with self._run(fake):
                    src.bearer()
                    self.clock.t = life - _SKEW - 1
                    src.bearer()
                    self.assertEqual(len(fake.calls), 1)
                    self.clock.t = life - _SKEW
                    src.bearer()
                    self.assertEqual(len(fake.calls), 2)
                # The token was there; nothing ran a second command for it.
                self.assertEqual({tuple(c[0]) for c in fake.calls},
                                 {tuple(_HELPER)})

    def test_config_helper_output_that_is_not_json_holds_nothing(self):
        # A JSONDecodeError keeps the whole document in `.doc`, and the
        # document is the token, an id_token and the account.
        broken = _helper_json("tok-SECRET", 3000)[:-7]
        fake = _Gcloud(helper=_completed(broken),
                       plain=_completed("", "bob@corp.example", 1))
        with self._run(fake):
            with self.assertRaises(gcp_token.TokenUnavailable) as caught:
                self._source().bearer()
        message = str(caught.exception)
        self.assertIn("JSONDecodeError", message)
        self.assertIn("not JSON", message)
        for secret_text in ("SECRET", "bob@corp.example"):
            self.assertNotIn(secret_text, message)
            self.assertNotIn(secret_text, _chain(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)

    def test_a_failing_config_helper_falls_back_to_print_access_token(self):
        for helper in (_completed("", "ERROR: unknown command", 2),
                       _completed("not json"),
                       _completed(json.dumps({"credential": {}})),
                       _completed(json.dumps(["tok-SECRET"])),
                       UnicodeDecodeError("utf-8", b"tok-SECRET", 0, 1, "x")):
            with self.subTest(helper=helper):
                fake = _Gcloud(helper=helper, plain=_completed("tok-plain\n"))
                with self._run(fake):
                    self.assertEqual(self._source().bearer(), "tok-plain")
                self.assertEqual([c[0] for c in fake.calls], [_HELPER, _PRINT])
                self.assertIs(fake.calls[1][1]["stdin"], subprocess.DEVNULL)

    def test_the_fallback_assumes_a_short_lifetime(self):
        fake = _Gcloud(helper=_completed("", "", 2),
                       plain=_completed("tok-plain\n"))
        src = self._source()
        life = gcp_token.GCLOUD_ASSUMED_LIFETIME
        # Short, and so is the window past the skew: a printed token may
        # have only a few minutes left.
        self.assertLessEqual(life, _SKEW + 120)
        with self._run(fake):
            src.bearer()
            self.clock.t = life - _SKEW - 1
            src.bearer()
            self.assertEqual(len(fake.calls), 2)
            self.clock.t = life - _SKEW
            src.bearer()
            self.assertEqual(len(fake.calls), 4)

    def test_a_gcloud_that_cannot_run_is_not_run_twice(self):
        # The fallback is the same binary; after a hang it would most likely
        # sit out the same thirty seconds again.
        hung = subprocess.TimeoutExpired(
            ["gcloud"], 30.0, output="tok-SECRET", stderr="bob@corp.example")
        missing = FileNotFoundError(2, "no such file", "/secret/path/gcloud")
        for failure, said in ((hung, "timed out"),
                              (missing, "FileNotFoundError")):
            with self.subTest(failure=type(failure).__name__):
                fake = _Gcloud(helper=failure, plain=_completed("tok-plain"))
                with self._run(fake):
                    with self.assertRaises(gcp_token.TokenUnavailable) as caught:
                        self._source().bearer()
                self.assertEqual(len(fake.calls), 1)
                message = str(caught.exception)
                self.assertIn(said, message)
                for leaked in ("SECRET", "bob@corp.example", "/secret/path"):
                    self.assertNotIn(leaked, message)
                self.assertIsNone(caught.exception.__context__)

    # ── print-access-token, the fallback ──

    def test_both_failing_reports_both_return_codes_and_no_output(self):
        stderr = "ERROR: account bob@corp.example has no credentials"
        fake = _Gcloud(helper=_completed("tok-SECRET", stderr, 3),
                       plain=_completed("tok-SECRET", stderr, 2))
        with self._run(fake):
            with self.assertRaises(gcp_token.TokenUnavailable) as caught:
                self._source().bearer()
        message = str(caught.exception)
        self.assertIn("status 3", message)
        self.assertIn("status 2", message)
        for leaked in ("SECRET", "bob@corp.example", "credentials"):
            self.assertNotIn(leaked, message)
        self.assertIsNone(caught.exception.__context__)

    def test_a_hanging_fallback_is_killed_and_reported(self):
        hung = subprocess.TimeoutExpired(
            ["gcloud"], 30.0, output="tok-SECRET", stderr="bob@corp.example")
        fake = _Gcloud(helper=_completed("", "", 2), plain=hung)
        with self._run(fake):
            with self.assertRaises(gcp_token.TokenUnavailable) as caught:
                self._source().bearer()
        message = str(caught.exception)
        self.assertIn("timed out", message)
        self.assertNotIn("SECRET", message)
        self.assertNotIn("bob@corp.example", message)
        self.assertIsNone(caught.exception.__context__)

    def test_undecodable_output_is_unavailable_and_holds_no_bytes(self):
        real_run = subprocess.run

        def emit_bad_bytes(args, **kwargs):
            # A real child whose stdout is not UTF-8, so the real decode
            # error is the one raised, for both commands.
            return real_run(
                [sys.executable, "-c",
                 "import sys; "
                 "sys.stdout.buffer.write(b'tok-SECRET\\xff\\xfe')"],
                **kwargs)

        with self._run(emit_bad_bytes):
            with self.assertRaises(gcp_token.TokenUnavailable) as caught:
                self._source().bearer()
        self.assertIn("decoded", str(caught.exception))
        self.assertIn("UnicodeDecodeError", str(caught.exception))
        self.assertNotIn("SECRET", _chain(caught.exception))
        self.assertIsNone(caught.exception.__context__)

    def test_undecodable_output_lets_auto_fall_through(self):
        bad = UnicodeDecodeError("utf-8", b"tok-SECRET", 0, 1, "invalid")
        src = gcp_token.TokenSource(
            "auto", now=self.clock,
            fetchers={"metadata": _failing("down"),
                      "file": lambda: ("tok-file", 3600)})
        with self._run(_Gcloud(helper=bad, plain=bad)):
            self.assertEqual(src.bearer(), "tok-file")

    def test_a_failure_on_refresh_keeps_a_cached_token_that_is_still_alive(self):
        src = self._source()
        with self._run(_Gcloud(helper=_completed(_helper_json("tok-1", 600)))):
            self.assertEqual(src.bearer(), "tok-1")
        self.clock.t = 600 - 10
        bad = UnicodeDecodeError("utf-8", b"tok-SECRET", 0, 1, "invalid")
        with self._run(_Gcloud(helper=bad, plain=bad)):
            self.assertEqual(src.bearer(), "tok-1")


class TestFile(unittest.TestCase):
    def test_the_key_file_is_read_through_the_injected_reader(self):
        seen = []

        def read(path):
            seen.append(path)
            return "tok-fake"

        src = gcp_token.TokenSource("file", key_file="/some/key", read=read,
                                    now=_Clock())
        self.assertEqual(src.bearer(), "tok-fake")
        self.assertEqual(seen, ["/some/key"])

    def test_the_file_is_reread_after_its_interval(self):
        clock = _Clock()
        reads = []

        def read(path):
            reads.append(path)
            return "tok-%d" % len(reads)

        src = gcp_token.TokenSource("file", key_file="/k", read=read, now=clock)
        src.bearer()
        clock.t = gcp_token.FILE_REREAD_SECONDS - _SKEW - 1
        src.bearer()
        self.assertEqual(len(reads), 1)
        clock.t = gcp_token.FILE_REREAD_SECONDS - _SKEW
        self.assertEqual(src.bearer(), "tok-2")

    def test_no_key_file_is_unavailable(self):
        with self.assertRaises(gcp_token.TokenUnavailable):
            gcp_token.TokenSource("file", now=_Clock()).bearer()

    def test_the_default_reader_is_the_mode_checking_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "key")
            with open(path, "w") as f:
                f.write("tok-fake\n")
            os.chmod(path, 0o644)
            src = gcp_token.TokenSource("file", key_file=path, now=_Clock())
            with self.assertRaises(gcp_token.TokenUnavailable) as caught:
                src.bearer()
            self.assertNotIn("tok-fake", str(caught.exception))
            self.assertIn("0644", str(caught.exception))

            os.chmod(path, 0o600)
            self.assertEqual(src.bearer(), "tok-fake")

    def test_a_reader_failure_message_is_the_readers_and_nothing_more(self):
        def read(path):
            raise secret.SecretError("api_key_file %s is empty" % path)

        src = gcp_token.TokenSource("file", key_file="/k", read=read,
                                    now=_Clock())
        with self.assertRaises(gcp_token.TokenUnavailable) as caught:
            src.bearer()
        self.assertIn("is empty", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)


class TestEmptyAndBlank(unittest.TestCase):
    def test_an_empty_or_blank_token_is_unavailable(self):
        for raw in ("", "   ", "\n"):
            with self.subTest(source="metadata", raw=raw):
                body = ('{"access_token": %s, "expires_in": 3600}'
                        % json.dumps(raw)).encode()
                with _MetadataServer(body=body):
                    with self.assertRaises(gcp_token.TokenUnavailable):
                        gcp_token.TokenSource("metadata", now=_Clock()).bearer()
            with self.subTest(source="gcloud", raw=raw):
                with unittest.mock.patch.object(
                        gcp_token.subprocess, "run",
                        return_value=_completed(raw)):
                    with self.assertRaises(gcp_token.TokenUnavailable):
                        gcp_token.TokenSource("gcloud", now=_Clock()).bearer()
            with self.subTest(source="file", raw=raw):
                src = gcp_token.TokenSource(
                    "file", key_file="/k", read=lambda path, r=raw: r,
                    now=_Clock())
                with self.assertRaises(gcp_token.TokenUnavailable):
                    src.bearer()

    def test_an_empty_token_is_not_cached(self):
        outcomes = ["", "tok-fake"]
        src = _with(lambda: (outcomes.pop(0), 3600))
        with self.assertRaises(gcp_token.TokenUnavailable):
            src.bearer()
        self.assertEqual(src.bearer(), "tok-fake")

    def test_a_token_is_stripped(self):
        self.assertEqual(_with(lambda: ("  tok-fake\n", 3600)).bearer(),
                         "tok-fake")


class TestAuto(unittest.TestCase):
    def _auto(self, **fetchers):
        return gcp_token.TokenSource("auto", now=_Clock(), fetchers=fetchers)

    def test_auto_tries_metadata_then_gcloud_then_file(self):
        order = []

        def failing(name):
            def fetch():
                order.append(name)
                raise gcp_token.TokenUnavailable("down")
            return fetch

        def last():
            order.append("file")
            return "tok-fake", 3600

        src = self._auto(metadata=failing("metadata"),
                         gcloud=failing("gcloud"), file=last)
        self.assertEqual(src.bearer(), "tok-fake")
        self.assertEqual(order, ["metadata", "gcloud", "file"])

    def test_auto_stops_at_the_first_source_that_works(self):
        order = []

        def metadata():
            order.append("metadata")
            return "tok-meta", 3600

        def gcloud():
            order.append("gcloud")
            return "tok-gcloud", 3600

        src = self._auto(metadata=metadata, gcloud=gcloud)
        self.assertEqual(src.bearer(), "tok-meta")
        self.assertEqual(order, ["metadata"])

    def test_auto_falls_through_an_empty_token(self):
        src = self._auto(metadata=lambda: ("  ", 3600),
                         gcloud=lambda: ("tok-gcloud", 3600))
        self.assertEqual(src.bearer(), "tok-gcloud")

    def test_auto_reports_all_three_when_every_source_fails(self):
        src = self._auto(metadata=_failing("metadata server answered HTTP 404"),
                         gcloud=_failing("gcloud exited with status 2"),
                         file=_failing("no key file is configured"))
        with self.assertRaises(gcp_token.TokenUnavailable) as caught:
            src.bearer()
        message = str(caught.exception)
        for word in ("metadata", "gcloud", "file", "404", "status 2"):
            self.assertIn(word, message)
        self.assertIsNone(caught.exception.__context__)

    def test_auto_with_the_real_sources_all_unavailable_names_all_three(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        with unittest.mock.patch.object(
                gcp_token, "METADATA_URL", "http://127.0.0.1:%d/t" % port), \
                unittest.mock.patch.object(
                    gcp_token.subprocess, "run",
                    return_value=_completed("tok-SECRET", "bob@corp.example", 1)):
            with self.assertRaises(gcp_token.TokenUnavailable) as caught:
                gcp_token.TokenSource("auto", now=_Clock()).bearer()
        message = str(caught.exception)
        for word in ("metadata", "gcloud", "file"):
            self.assertIn(word, message)
        self.assertNotIn("SECRET", message)
        self.assertNotIn("bob@corp.example", message)
        self.assertNotIn("127.0.0.1", message)


class TestValidate(unittest.TestCase):
    def test_validate_does_no_io(self):
        def boom(*args, **kwargs):
            raise AssertionError("validate performed I/O")

        # Patched at the socket and process level, so any route to the
        # network or a child process is caught, whichever library it takes.
        with unittest.mock.patch.object(gcp_token, "_fetch_metadata", boom), \
                unittest.mock.patch.object(gcp_token, "_fetch_gcloud", boom), \
                unittest.mock.patch.object(socket.socket, "connect", boom), \
                unittest.mock.patch.object(socket, "create_connection", boom), \
                unittest.mock.patch.object(socket, "getaddrinfo", boom), \
                unittest.mock.patch.object(subprocess, "Popen", boom), \
                unittest.mock.patch.object(secret, "read_keyfile", boom), \
                unittest.mock.patch.object(
                    gcp_token.shutil, "which", return_value="/usr/bin/gcloud"):
            gcp_token.validate("auto")
            gcp_token.validate("metadata")
            gcp_token.validate("gcloud")
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "key")
                with open(path, "w") as f:
                    f.write("tok-fake")
                os.chmod(path, 0o600)
                gcp_token.validate("file", key_file=path)

    def test_auto_passes_with_neither_gcloud_nor_a_key_file(self):
        with unittest.mock.patch.object(
                gcp_token.shutil, "which", return_value=None):
            gcp_token.validate("auto")

    def test_gcloud_not_on_path_is_a_configuration_error(self):
        with unittest.mock.patch.object(
                gcp_token.shutil, "which", return_value=None):
            with self.assertRaises(gcp_token.TokenUnavailable) as caught:
                gcp_token.validate("gcloud")
        self.assertIn("gcloud", str(caught.exception))

    def test_file_validate_needs_a_key_file(self):
        with self.assertRaises(gcp_token.TokenUnavailable):
            gcp_token.validate("file")

    def test_file_validate_refuses_a_world_readable_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "key")
            with open(path, "w") as f:
                f.write("tok-fake")
            for mode in (0o644, 0o640, 0o604):
                os.chmod(path, mode)
                with self.subTest(mode=oct(mode)):
                    with self.assertRaises(gcp_token.TokenUnavailable) as caught:
                        gcp_token.validate("file", key_file=path)
                    self.assertIn("%04o" % mode, str(caught.exception))
                    self.assertNotIn("tok-fake", str(caught.exception))

    def test_file_validate_refuses_a_missing_file_and_a_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(gcp_token.TokenUnavailable) as missing:
                gcp_token.validate("file", key_file=os.path.join(tmp, "nope"))
            os.chmod(tmp, 0o700)
            with self.assertRaises(gcp_token.TokenUnavailable) as directory:
                gcp_token.validate("file", key_file=tmp)
        self.assertIn("cannot be checked", str(missing.exception))
        self.assertNotIn("opened", str(missing.exception))
        self.assertIn("not a regular file", str(directory.exception))
        for caught in (missing, directory):
            self.assertIsNone(caught.exception.__context__)

    def test_file_validate_and_the_reader_apply_the_same_check(self):
        calls = []
        real = secret.check_keyfile_mode

        def spy(path, st_mode):
            calls.append(path)
            return real(path, st_mode)

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "key")
            with open(path, "w") as f:
                f.write("tok-fake")
            os.chmod(path, 0o600)
            with unittest.mock.patch.object(secret, "check_keyfile_mode", spy):
                gcp_token.validate("file", key_file=path)
                secret.read_keyfile(path)
        self.assertEqual(calls, [path, path])

    def test_file_validate_accepts_an_owner_only_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "key")
            with open(path, "w") as f:
                f.write("tok-fake")
            for mode in (0o600, 0o400):
                os.chmod(path, mode)
                gcp_token.validate("file", key_file=path)


class TestReadKeyfile(unittest.TestCase):
    """The reader moved here from config; test_agent_config pins its text."""

    def test_secret_error_is_what_it_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "key")
            with open(path, "w") as f:
                f.write("tok-fake")
            os.chmod(path, 0o644)
            with self.assertRaises(secret.SecretError) as caught:
                secret.read_keyfile(path)
            self.assertNotIn("tok-fake", str(caught.exception))
            os.chmod(path, 0o600)
            self.assertEqual(secret.read_keyfile(path), "tok-fake")

    def test_an_undecodable_file_leaves_no_key_bytes_on_the_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "key")
            with open(path, "wb") as f:
                f.write(b"tok-SECRET\xff\xfe")
            os.chmod(path, 0o600)
            with self.assertRaises(secret.SecretError) as caught:
                secret.read_keyfile(path)
        self.assertIn("cannot be read as text", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn("SECRET", _chain(caught.exception))

    def test_a_failing_fstat_is_a_secret_error_and_closes_the_descriptor(self):
        opened, closed = [], []
        real_open, real_close = os.open, os.close

        def spy_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened.append(fd)
            return fd

        def spy_close(fd):
            closed.append(fd)
            real_close(fd)

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "key")
            with open(path, "w") as f:
                f.write("tok-fake")
            os.chmod(path, 0o600)
            with unittest.mock.patch.object(secret.os, "open", spy_open), \
                    unittest.mock.patch.object(secret.os, "close", spy_close), \
                    unittest.mock.patch.object(
                        secret.os, "fstat",
                        side_effect=OSError(5, "Input/output error")):
                with self.assertRaises(secret.SecretError) as caught:
                    secret.read_keyfile(path)
        self.assertIn("cannot be checked", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(len(opened), 1)
        self.assertEqual(closed, opened)


if __name__ == "__main__":
    unittest.main()
