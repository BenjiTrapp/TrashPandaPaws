#!/usr/bin/env python3
"""A Google Cloud access token that refreshes itself.

Every other provider here authenticates with a static key held for the
client's whole life. Google does not: its access token lives about an hour,
and a campaign runs up to two. This is the one piece of machinery that
exists only for that, a blocking `bearer()` that returns a current token,
caches it, and fetches a new one shortly before the old one expires. The
HTTP client awaits it off the event loop through asyncio.to_thread.

Where the token comes from is a choice of source, ordered by what it costs to
try: the metadata server (a one-second timeout; answers only on Google's own
machines), the `gcloud` command line (a subprocess, up to thirty seconds), and
a key file (a read). "auto" tries them in that order and, when none works,
names all three, because "no token" tells an operator nothing about which of
the three they were supposed to have.

Each source says how long its token lives where it can: the metadata server
in `expires_in`, `gcloud config config-helper` in `token_expiry`. Where it
cannot, the lifetime assumed is short, because a token cached past its real
expiry is a run that fails on every turn until the cache lets go of it.

Standard library only: a token fetch is one small GET or one subprocess, and
`requests` is imported lazily elsewhere in this package for a reason that
holds here too.

Every message raised here is built from a status code, an exception class
name or a return code, and nothing else. `gcloud`'s stdout *is* the token,
its stderr can name accounts and paths, and a metadata error body can echo a
token; this project writes LLM interactions to SQLite, so none of it may
reach an exception message. As in `provider.http_post_json`, each failure is
raised after the `except` block that caught the original has exited, so the
exception's `__context__` is genuinely empty: a `TimeoutExpired` carries the
partial stdout, and an `HTTPError` carries the response.

Usage:
    from software.agent.llm import gcp_token

    gcp_token.validate("auto")                    # cheap; no I/O
    src = gcp_token.source("auto")                # shared per (kind, key_file)
    header = "Bearer " + src.bearer()             # blocking; call in a thread
"""

import datetime
import http.client
import json
import os
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

from software.agent import secret

# A token is refreshed when less than this remains, so one that is handed to a
# request is still good by the time the request has been read and answered.
SKEW_SECONDS = 300
# The lifetime assumed for a token whose real expiry is unknown: what
# `gcloud auth print-access-token` prints, or a metadata answer with an
# unreadable `expires_in`. Short on purpose. gcloud prints the token it
# already holds for as long as that one is not close to expiry, so a printed
# token is only known to have a few minutes left, not most of an hour. An
# assumption of half an hour was the bug this replaces: the same token was
# re-cached at every refresh, each time for another half hour, and died while
# the cache still vouched for it, leaving a quarter of an hour of 401s per
# cycle. Six minutes leaves one minute fresh past the skew, so the source is
# asked again about once a turn, and the cost of that is a subprocess; the
# cost of assuming longer is a run that fails.
GCLOUD_ASSUMED_LIFETIME = SKEW_SECONDS + 60
# A key file can be rotated underneath a running job, so it is re-read well
# inside the life of anything that would replace it.
FILE_REREAD_SECONDS = 600
METADATA_TIMEOUT = 1.0
GCLOUD_TIMEOUT = 30.0
KINDS = ("auto", "metadata", "gcloud", "file")

_MAX_LIFETIME = 3600
_ORDER = ("metadata", "gcloud", "file")
METADATA_URL = ("http://metadata.google.internal/computeMetadata/v1/"
                "instance/service-accounts/default/token")
# The machine's clock, read through a name so a test can move it. An expiry
# is a time of day; the cache itself runs on the monotonic clock.
_wall_clock = time.time


class TokenUnavailable(Exception):
    """No access token could be obtained, with a message safe to show.

    Built from a status code, an exception class name or a return code, never
    from a body, a URL or a subprocess's output.
    """


# () -> (token, lifetime in seconds as the source reported it, unvalidated)
Fetcher = Callable[[], Tuple[Any, Any]]


def _lifetime(raw: Any) -> int:
    """Seconds this token may be cached, clamped into a safe range.

    The floor keeps a token from being refetched on every call; the ceiling
    keeps a wrong `expires_in` from outliving the real token. A value that is
    missing, not a number, or not positive says nothing usable about the
    token, so it gets the assumed lifetime rather than either extreme.

    Zero and negative values are deliberately not clamped up to the floor.
    A floor of SKEW_SECONDS + 1 is cached for one second, which for a value
    the server got wrong is a fetch on every call, the very thing the clamp
    is there to prevent. Only a positive number is believed, and it is
    clamped into [SKEW_SECONDS + 1, 3600].
    """
    seconds = None
    if not isinstance(raw, bool):
        try:
            seconds = int(raw)
        except (TypeError, ValueError, OverflowError):
            seconds = None
    if seconds is None or seconds <= 0:
        seconds = GCLOUD_ASSUMED_LIFETIME
    return max(SKEW_SECONDS + 1, min(_MAX_LIFETIME, seconds))


# ── Sources ──


def _fetch_metadata() -> Tuple[Any, Any]:
    # A link-local address that is never behind a proxy; honouring
    # http_proxy would send the request, and the token that answers it,
    # through one.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(
        METADATA_URL, headers={"Metadata-Flavor": "Google"})
    failure = None
    payload = None
    try:
        with opener.open(request, timeout=METADATA_TIMEOUT) as resp:
            payload = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        failure = "metadata server answered HTTP %d" % exc.code
        exc.close()
    except (OSError, http.client.HTTPException) as exc:
        failure = "metadata server unreachable (%s)" % type(exc).__name__
    except ValueError:
        failure = "metadata response was not JSON"
    if failure is not None:
        raise TokenUnavailable(failure)
    if not isinstance(payload, dict):
        raise TokenUnavailable("metadata response was not a JSON object")
    return payload.get("access_token"), payload.get("expires_in")


class _GcloudCannotRun(TokenUnavailable):
    """gcloud itself could not be run or did not finish.

    Not worth a second command: the fallback is the same binary, and after
    a timeout it would most likely sit out the same thirty seconds again.
    """


def _run_gcloud(args: List[str]) -> "subprocess.CompletedProcess":
    failure = None
    proc = None
    try:
        # stdin closed: a reauthentication prompt would otherwise wait on the
        # terminal of whatever process started this one.
        proc = subprocess.run(
            ["gcloud"] + args, capture_output=True,
            text=True, timeout=GCLOUD_TIMEOUT, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        failure = _GcloudCannotRun("gcloud timed out after %g seconds"
                                   % GCLOUD_TIMEOUT)
    except OSError as exc:
        failure = _GcloudCannotRun("gcloud could not be run (%s)"
                                   % type(exc).__name__)
    except ValueError as exc:
        # text=True decodes stdout, which is the token, and a
        # UnicodeDecodeError keeps the bytes it failed on in `.object`.
        failure = TokenUnavailable("gcloud output could not be decoded (%s)"
                                   % type(exc).__name__)
    if failure is not None:
        raise failure
    if proc.returncode != 0:
        raise TokenUnavailable("gcloud exited with status %d"
                               % proc.returncode)
    return proc


def _expiry_seconds(raw: Any) -> Optional[float]:
    """Seconds from now until an RFC 3339 UTC time, or None if unreadable.

    gcloud writes `token_expiry` as 2026-11-09T12:34:56Z, from this machine's
    own clock plus the lifetime Google gave, so comparing it with this
    machine's clock is comparing like with like.
    """
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        when = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    return when.timestamp() - _wall_clock()


def _fetch_gcloud_helper() -> Tuple[Any, Any]:
    # `config-helper` is the one gcloud command that says when its token
    # expires. Its JSON also holds an id_token and the account, so neither
    # the output nor a parse error's message is ever shown: a JSONDecodeError
    # keeps the whole document it failed on in `.doc`.
    proc = _run_gcloud(["config", "config-helper", "--format=json"])
    failure = None
    payload = None
    try:
        payload = json.loads(proc.stdout)
    except ValueError as exc:
        failure = ("gcloud config-helper output was not JSON (%s)"
                   % type(exc).__name__)
    if failure is not None:
        raise TokenUnavailable(failure)
    credential = None
    if isinstance(payload, dict):
        credential = payload.get("credential")
    if not isinstance(credential, dict):
        raise TokenUnavailable("gcloud config-helper output had no credential")
    token = credential.get("access_token")
    if not isinstance(token, str) or not token.strip():
        raise TokenUnavailable("gcloud config-helper output had no token")
    # An unreadable expiry leaves the token usable for the short assumed
    # lifetime, which is what the fallback would have given it anyway, and
    # without running gcloud a second time.
    return token, _expiry_seconds(credential.get("token_expiry"))


def _fetch_gcloud() -> Tuple[Any, Any]:
    cannot_run = None
    helper_said = None
    try:
        return _fetch_gcloud_helper()
    except _GcloudCannotRun as exc:
        cannot_run = exc
    except TokenUnavailable as exc:
        # An older gcloud, or one whose config-helper is broken: the plain
        # command still yields a token, only without its expiry.
        helper_said = str(exc)
    if cannot_run is not None:
        raise cannot_run
    failure = None
    proc = None
    try:
        proc = _run_gcloud(["auth", "print-access-token"])
    except TokenUnavailable as exc:
        failure = "config-helper: %s; print-access-token: %s" % (helper_said,
                                                                 exc)
    if failure is not None:
        raise TokenUnavailable(failure)
    # stdout is the token: returned, never formatted into anything. Its
    # expiry is unknown, so the short assumption applies.
    return proc.stdout, GCLOUD_ASSUMED_LIFETIME


def _file_fetcher(key_file: Optional[str],
                  read: Callable[[str], str]) -> Fetcher:
    def fetch() -> Tuple[Any, Any]:
        if not key_file:
            raise TokenUnavailable("no key file is configured")
        failure = None
        token = None
        try:
            token = read(key_file)
        except secret.SecretError as exc:
            # Names the path and the mode, never the content.
            failure = str(exc)
        if failure is not None:
            raise TokenUnavailable(failure)
        return token, FILE_REREAD_SECONDS
    return fetch


class TokenSource:
    """A cached Google access token and the means to renew it.

    One instance is shared by a coordinator and several concurrent workers.
    The lock covers the check and the fetch together: covering only the fetch
    would let four callers meeting an expired token each start a `gcloud`.
    """

    def __init__(self, kind: str, *, key_file: Optional[str] = None,
                 read: Optional[Callable[[str], str]] = None,
                 now: Optional[Callable[[], float]] = None,
                 fetchers: Optional[Dict[str, Fetcher]] = None):
        _check_kind(kind)
        self.kind = kind
        self._now = time.monotonic if now is None else now
        self._lock = threading.Lock()
        # (token, expires_at) as one tuple, so a caller that does not hold
        # the lock can read both from one consistent object.
        self._cached = None  # type: Optional[Tuple[str, float]]
        # Looked up by name at call time, so a replacement of the module
        # functions is seen, as well as the injected ones.
        self._fetchers = {
            "metadata": lambda: _fetch_metadata(),
            "gcloud": lambda: _fetch_gcloud(),
            "file": _file_fetcher(key_file, read or secret.read_keyfile),
        }  # type: Dict[str, Fetcher]
        self._fetchers.update(fetchers or {})

    def bearer(self) -> str:
        """A token with more than SKEW_SECONDS left. Blocks while fetching."""
        if not self._lock.acquire(blocking=False):
            # Someone is fetching, possibly a gcloud that will hang for its
            # full timeout. A caller whose token is still good has no reason
            # to queue behind it; five of them waiting out thirty seconds
            # each is the last one waiting two and a half minutes for
            # nothing. A caller with no usable token does queue, so the
            # fetch still happens once.
            held = self._cached
            if held is not None and held[1] - self._now() > 0:
                return held[0]
            self._lock.acquire()
        try:
            return self._bearer_locked()
        finally:
            self._lock.release()

    def invalidate(self, token: str) -> None:
        """Forget `token`, because the server refused it. Blocks briefly.

        The second net behind a source's expiry: if the expiry was wrong, the
        next call fetches again instead of handing out the refused token
        until the cache believes it has aged out. Only that token is
        forgotten. Another caller may already have replaced it with a fresh
        one, and throwing that away would cost a fetch for nothing. No
        retry and no count: the caller's request has failed either way.
        """
        with self._lock:
            held = self._cached
            if held is not None and held[0] == token:
                self._cached = None

    def _bearer_locked(self) -> str:
        started = self._now()
        cached = self._cached
        if cached is not None and cached[1] - started > SKEW_SECONDS:
            return cached[0]
        failure = None
        token = lifetime = None
        try:
            token, lifetime = self._fetch()
        except TokenUnavailable as exc:
            failure = exc
        if failure is not None:
            # The refresh runs SKEW_SECONDS early, so a token inside the
            # skew window is still good and the caller gets a working
            # credential. Raising here would throw it away, and a job that
            # runs two hours on a one-hour token would be marked dead for a
            # blip in gcloud. The failure is not lost: the cache is left as
            # it was, so the next call retries, and once the token has
            # really expired that retry's failure reaches the caller. A
            # token at or past its expiry is never returned. One attempt per
            # call; no loop, no backoff.
            if cached is not None and cached[1] - self._now() > 0:
                return cached[0]
            raise failure
        # Measured from before the fetch: a slow gcloud must not make the
        # token look younger than it is.
        self._cached = (token, started + lifetime)
        return token

    def _fetch(self) -> Tuple[str, int]:
        if self.kind != "auto":
            return self._run(self.kind)
        failures = []  # type: List[str]
        for name in _ORDER:
            failure = None
            result = None
            try:
                result = self._run(name)
            except TokenUnavailable as exc:
                failure = str(exc)
            if failure is None:
                return result
            failures.append(failure)
        raise TokenUnavailable("no Google token source worked: %s"
                               % "; ".join(failures))

    def _run(self, name: str) -> Tuple[str, int]:
        failure = None
        token = lifetime = None
        try:
            token, lifetime = self._fetchers[name]()
        except TokenUnavailable as exc:
            failure = str(exc)
        if failure is None and (not isinstance(token, str)
                                or not token.strip()):
            failure = "returned an empty token"
        if failure is not None:
            raise TokenUnavailable("%s: %s" % (name, failure))
        return token.strip(), _lifetime(lifetime)


# ── Shared instances ──
#
# Each job builds its LLM client afresh. A source per client would be a cache
# per job, and every one of them would fetch and refresh the same token.

_shared = {}  # type: Dict[Tuple[str, Optional[str]], TokenSource]
_shared_lock = threading.Lock()


def source(kind: str, *, key_file: Optional[str] = None,
           read: Optional[Callable[[str], str]] = None,
           now: Optional[Callable[[], float]] = None,
           fetchers: Optional[Dict[str, Fetcher]] = None) -> TokenSource:
    """The shared source for (kind, key_file), created on first request.

    `read`, `now` and `fetchers` are for tests and take effect only when this
    call creates the instance; build a TokenSource directly to be sure of
    them.
    """
    _check_kind(kind)
    with _shared_lock:
        found = _shared.get((kind, key_file))
        if found is None:
            found = TokenSource(kind, key_file=key_file, read=read, now=now,
                                fetchers=fetchers)
            _shared[(kind, key_file)] = found
        return found


# ── Validation ──


def _check_kind(kind: str) -> None:
    if kind not in KINDS:
        raise TokenUnavailable("unknown token source %r; valid values: %s"
                               % (kind, ", ".join(KINDS)))


def validate(kind: str, *, key_file: Optional[str] = None) -> None:
    """The cheap local check; raises TokenUnavailable.

    No network and no subprocess: this runs at startup from a synchronous,
    frequently polled path, and a probe there would stall the UI. Whether a
    token can actually be obtained is a different question. "auto" always
    passes, because the metadata server cannot be ruled out without asking it.
    """
    _check_kind(kind)
    if kind == "gcloud":
        if shutil.which("gcloud") is None:
            raise TokenUnavailable("gcloud is not on PATH")
    elif kind == "file":
        _validate_file(key_file)


def _validate_file(key_file: Optional[str]) -> None:
    if not key_file:
        raise TokenUnavailable("no key file is configured")
    path = os.path.expanduser(key_file)
    failure = None
    info = None
    try:
        info = os.stat(path)
    except OSError as exc:
        failure = ("api_key_file %s cannot be checked (%s)"
                   % (path, exc.strerror))
    if failure is None:
        # The reader's own test, so the two cannot disagree.
        try:
            secret.check_keyfile_mode(path, info.st_mode)
        except secret.SecretError as exc:
            failure = str(exc)
    if failure is not None:
        raise TokenUnavailable(failure)
