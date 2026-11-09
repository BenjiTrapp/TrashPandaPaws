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
machines), the `gcloud` command line (a subprocess, up to thirty seconds),
and a key file (a read). "auto" tries them in that order and, when none
works, names all three, because "no token" tells an operator nothing about
which of the three they were supposed to have.

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

import http.client
import json
import os
import shutil
import stat
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
# `gcloud auth print-access-token` does not say how old the token it prints
# is. Its tokens are issued for an hour, so half of that is assumed.
GCLOUD_ASSUMED_LIFETIME = 1800
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


def _fetch_gcloud() -> Tuple[Any, Any]:
    failure = None
    proc = None
    try:
        # stdin closed: a reauthentication prompt would otherwise wait on the
        # terminal of whatever process started this one.
        proc = subprocess.run(
            ["gcloud", "auth", "print-access-token"], capture_output=True,
            text=True, timeout=GCLOUD_TIMEOUT, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        failure = "gcloud timed out after %g seconds" % GCLOUD_TIMEOUT
    except OSError as exc:
        failure = "gcloud could not be run (%s)" % type(exc).__name__
    if failure is not None:
        raise TokenUnavailable(failure)
    if proc.returncode != 0:
        raise TokenUnavailable("gcloud exited with status %d" % proc.returncode)
    # stdout is the token: returned, never formatted into anything.
    return proc.stdout, GCLOUD_ASSUMED_LIFETIME


def _file_fetcher(key_file: Optional[str], read: Callable[[str], str]) -> Fetcher:
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
        self._token = None  # type: Optional[str]
        self._expires_at = 0.0
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
        with self._lock:
            started = self._now()
            if self._token is not None and \
                    self._expires_at - started > SKEW_SECONDS:
                return self._token
            token, lifetime = self._fetch()
            # Measured from before the fetch: a slow gcloud must not make the
            # token look younger than it is.
            self._token = token
            self._expires_at = started + lifetime
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
    try:
        info = os.stat(path)
    except OSError as exc:
        raise TokenUnavailable("api_key_file %s cannot be opened (%s)"
                               % (path, exc.strerror)) from None
    if not stat.S_ISREG(info.st_mode):
        raise TokenUnavailable("api_key_file %s is not a regular file" % path)
    if info.st_mode & 0o077:
        raise TokenUnavailable(
            "api_key_file %s has mode %04o; it holds a secret and must be "
            "readable by its owner only (chmod 600)"
            % (path, stat.S_IMODE(info.st_mode)))
