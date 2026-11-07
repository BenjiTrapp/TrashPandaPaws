#!/usr/bin/env python3
"""Typed client for the Raccoon C2's HTTP API.

Lets the agent list beacons, queue work on them, run server-side tools and
poll for what comes back. It is a transport and nothing more: it does not
classify commands, check scope or decide what may run. Those are done by the
router and the gate, which sit between the model and this client precisely so
that nothing here can be talked out of them.

The C2 is a Flask app, so this speaks plain JSON over HTTP(S) with a Bearer
token (`Authorization: Bearer <token>`). It uses `requests`, already a
declared dependency, run off the event loop with asyncio.to_thread. No async
HTTP library is added: the C2 has to keep working with no new dependency, and
llm/provider.py made the same call for the same reason. The session is the
seam: the client takes any object with a `request(method, url, headers=...,
json=..., timeout=..., verify=..., allow_redirects=...)` method that returns
something with `status_code` and `json()`, so a test can stand in for the
network.

Endpoints (the two marked * are the shape the C2 gets in Task 9; this client
is written to that shape and does not support the old one):

    GET  /api/agents                       list_agents
    GET  /api/agents/<id>                  get_agent
    POST /api/agents/<id>/task             queue_task      (takes a `lane`*)
    GET  /api/tasks/<task_id>              get_task_result
    POST /api/server/exec                  exec_server_tool  (argv, origin*)
    GET  /api/server/exec/result/<run_id>  get_server_tool_result*

Usage:
    from software.agent import c2client

    # The C2's operator socket: loopback only by default, so the agent
    # runs on the C2 host (or reaches it through an SSH tunnel).
    c2 = c2client.C2Client("https://127.0.0.1:8444", token)
    task_id = await c2.queue_task("raccoon-fox", "shell", "id")
    result = await c2.await_task(task_id, timeout=120)
"""

import asyncio
import ipaddress
import threading
import warnings
from typing import Any, Awaitable, Callable, List, Optional, Sequence
from urllib.parse import quote, urlparse

from software.agent.secret import Secret

# ── Errors ──
#
# Every message is built from the host, the status code or the exception
# class, never from a URL, a header or a response body. The token travels in
# the Authorization header, and a server can echo that header back in an
# error body.


class C2Unavailable(Exception):
    """The C2 could not be reached, or answered with something unusable."""


class C2Unauthorized(Exception):
    """The C2 rejected the operator token (HTTP 401 or 403)."""


class BeaconGone(Exception):
    """The beacon a task was sent to is not there to answer it."""


# ── Session ──

_REQUEST_TIMEOUT_SECONDS = 30


def _is_loopback(host: Optional[str]) -> bool:
    if host in ("localhost", "localhost.localdomain"):
        return True
    try:
        return ipaddress.ip_address(host or "").is_loopback
    except ValueError:
        return False

# The C2 serves a self-signed certificate (spec §18), so verify=False is the
# default and urllib3 warns on every request.
#
# The obvious suppression is a `catch_warnings` block around the call, and
# that is wrong here: the block saves and restores the process-wide filter
# list, so two worker threads doing it at once can interleave such that the
# "ignore" filter is restored as if it had been there all along, and stays
# installed for everything. Serialising the calls with a lock fixes the race
# but holds that lock across a network call with a 30-second timeout — so one
# hung request would stall every other request in the agent, liveness polls
# included, which is the starvation this client exists to avoid elsewhere.
#
# So the filter is installed once, on first use, and never removed. It is
# process-wide, and that is acceptable because the agent is its own process
# (spec §7: a separate asyncio service on 127.0.0.1:8099) — the C2 runs
# elsewhere and is unaffected. The only other HTTP user in this process is
# the LLM transport, which verifies TLS against real endpoints and would
# never raise this warning anyway.
_filter_installed = False
_INSTALL_LOCK = threading.Lock()


def _silence_insecure_request_warning(requests_module) -> None:
    global _filter_installed
    if _filter_installed:
        return
    with _INSTALL_LOCK:
        if _filter_installed:
            return
        warnings.simplefilter(
            "ignore",
            requests_module.packages.urllib3.exceptions.InsecureRequestWarning)
        _filter_installed = True


class _RequestsSession:
    """The default session: `requests.request`, one call per request.

    Not a `requests.Session`. A Session pools connections and is not safe to
    share between threads, and a poll every couple of seconds gains nothing
    from reuse.
    """

    def request(self, method: str, url: str, **kwargs):
        # Imported here, not at module level: importing requests is noisy on
        # some platforms (urllib3 warns about LibreSSL), and the agent
        # package has to import cleanly on a C2 that never runs the agent.
        import requests

        if kwargs.get("verify") is False:
            _silence_insecure_request_warning(requests)
        return requests.request(method, url, **kwargs)


# ── Client ──

_POLL_INTERVAL_SECONDS = 2.0
# Consecutive negative liveness answers before a wait is abandoned. One
# transient failure must not kill a task that is merely slow; an unbounded
# wait on a beacon that will never answer holds an executor's concurrency
# slot forever and starves every other executor.
_DEAD_AFTER = 3

# The statuses that mean "not finished yet". A task is "pending" until the
# beacon posts its result; a server-side tool run is "running" meanwhile.
_TASK_IN_FLIGHT = ("pending",)
_TOOL_IN_FLIGHT = ("pending", "running")

IsAlive = Callable[[], Awaitable[bool]]


def _segment(value: Any, what: str) -> str:
    """Quote an id for use as one path segment.

    The id comes from the model. Unquoted, "../server/exec" would turn a
    beacon lookup into a request against a different endpoint, and the dot
    segments would be normalised away by the HTTP stack before the server
    saw them.
    """
    if not isinstance(value, str) or value in ("", ".", ".."):
        raise ValueError("%s must be a non-empty id, got %r" % (what, value))
    return quote(value, safe="")


def _finished(payload: dict) -> dict:
    # One shape for the model to read: a result that arrived and one that
    # timed out both carry `success`.
    result = dict(payload)
    result.setdefault("success", payload.get("status") == "ok")
    return result


class C2Client:
    def __init__(self, base_url: str, token: str, *, verify_tls: bool = False,
                 session: Any = None):
        parts = urlparse(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("base_url must be an http(s) URL")
        # A URL with userinfo would put that credential into _base_url and so
        # into any dump of the client.
        if parts.username or parts.password:
            raise ValueError("base_url must not contain credentials")
        host = parts.hostname
        if ":" in host:
            host = "[%s]" % host
        self._host = host + (":%d" % parts.port if parts.port else "")
        self._base_url = base_url.rstrip("/")
        self._token = Secret(token)
        self._verify_tls = bool(verify_tls)
        self._session = session if session is not None else _RequestsSession()
        if token and parts.scheme == "http" and not _is_loopback(parts.hostname):
            # Warn rather than refuse. The LLM transport refuses this, but the
            # C2 is the operator's own infrastructure and plain http over a
            # container network is a normal deployment, so a refusal would
            # block a legitimate setup. It is still worth saying: during an
            # engagement the route to the C2 may cross the client's network,
            # and a bearer token in cleartext there is a real exposure.
            warnings.warn(
                "the C2 token is sent over plain http to %s; use https, or "
                "keep the route on loopback or a private container network"
                % self._host, UserWarning, stacklevel=2)

    def __repr__(self) -> str:
        return "<C2Client host=%r>" % self._host

    # ── Transport ──

    async def _request(self, method: str, path: str,
                       body: Optional[dict] = None, *,
                       allow_missing: bool = False) -> Any:
        """Send one request, return the parsed JSON, or None on a tolerated 404."""
        headers = {"Authorization": "Bearer " + (self._token.reveal() or "")}
        # Each failure is captured and raised once the except block has
        # exited, so the C2 error has no __context__ at all. `from None`
        # would hide the original from every normal rendering but leave it on
        # the object, and a requests exception holds a .request whose
        # .headers carry the token. See provider.http_post_json.
        failure = None
        try:
            # allow_redirects=False: a redirect would carry the token to
            # whichever host answered.
            resp = await asyncio.to_thread(
                self._session.request, method, self._base_url + path,
                headers=headers, json=body, timeout=_REQUEST_TIMEOUT_SECONDS,
                verify=self._verify_tls, allow_redirects=False)
        except Exception as exc:
            # Only the class: a message from the library under it may hold
            # the URL or the headers.
            failure = "request failed (%s)" % type(exc).__name__
        if failure is not None:
            raise C2Unavailable(self._said(failure))
        status = resp.status_code
        if status in (401, 403):
            raise C2Unauthorized(self._said(
                "rejected the operator token (HTTP %d)" % status))
        if status == 404 and allow_missing:
            return None
        if not 200 <= status < 300:
            raise C2Unavailable(self._said("answered HTTP %d" % status))
        not_json = False
        try:
            payload = resp.json()
        except ValueError:
            # A JSONDecodeError carries the document it failed on.
            not_json = True
        if not_json:
            raise C2Unavailable(self._said("answered with something that was not JSON"))
        return payload

    def _said(self, what: str) -> str:
        return "C2 at %s %s" % (self._host, what)

    def _bad_shape(self, what: str) -> C2Unavailable:
        return C2Unavailable(self._said("answered without %s" % what))

    def _expect_dict(self, payload: Any, what: str) -> dict:
        if not isinstance(payload, dict):
            raise self._bad_shape("a JSON object for %s" % what)
        return payload

    def _expect_text(self, payload: Any, key: str, what: str) -> str:
        value = self._expect_dict(payload, what).get(key)
        if not isinstance(value, str) or not value:
            raise self._bad_shape("a %r for %s" % (key, what))
        return value

    # ── Beacons ──

    async def list_agents(self) -> List[dict]:
        payload = await self._request("GET", "/api/agents")
        if not isinstance(payload, list):
            raise self._bad_shape("a list of beacons")
        return payload

    async def get_agent(self, agent_id: str) -> Optional[dict]:
        """One beacon, or None when the C2 does not know the id.

        An unknown beacon is an answer rather than a failure: the caller is
        asking, among other things, whether the beacon still exists.
        """
        payload = await self._request(
            "GET", "/api/agents/" + _segment(agent_id, "agent_id"),
            allow_missing=True)
        if payload is None:
            return None
        return self._expect_dict(payload, "a beacon")

    # ── Tasks ──

    async def queue_task(self, agent_id: str, cmd: str, args: str = "",
                         data: str = "", timeout: int = 300,
                         lane: str = "agent") -> str:
        """Queue a task on a beacon and return its id."""
        # `lane` defaults to "agent" so the C2 can tell agent work from the
        # operator's, and schedule the operator's first.
        payload = await self._request(
            "POST", "/api/agents/%s/task" % _segment(agent_id, "agent_id"),
            {"cmd": cmd, "args": args, "data": data, "timeout": timeout,
             "lane": lane},
            allow_missing=True)
        if payload is None:
            raise BeaconGone(self._said("does not know beacon %r" % agent_id))
        return self._expect_text(payload, "id", "the queued task")

    async def get_task_result(self, task_id: str) -> Optional[dict]:
        """The result, or None while the task is still pending."""
        payload = await self._request(
            "GET", "/api/tasks/" + _segment(task_id, "task_id"))
        payload = self._expect_dict(payload, "a task result")
        if payload.get("status") in _TASK_IN_FLIGHT:
            return None
        return _finished(payload)

    async def await_task(self, task_id: str, *, timeout: float,
                         poll_interval: float = _POLL_INTERVAL_SECONDS,
                         is_alive: Optional[IsAlive] = None) -> dict:
        """Poll until the task has a result, or `timeout` seconds have passed.

        A timeout returns a result with success=False instead of raising: a
        slow command and a broken one must look different to the model, and
        an exception would make them the same. `is_alive`, when given, is
        asked after every poll that found nothing; three negative answers in
        a row raise BeaconGone.
        """
        return await self._poll(
            lambda: self.get_task_result(task_id), "task_id", task_id,
            timeout, poll_interval, is_alive)

    # ── Beacon configuration ──

    async def set_beacon_interval(self, agent_id: str, seconds: float,
                                  jitter: float) -> None:
        """Queue a `sleep <seconds> <jitter%>` task, as the operator GUI does.

        There is no endpoint for it: the GUI's "Apply Sleep" button
        (applySleepConfig) queues an ordinary `sleep` task, and the beacon
        reads it as seconds and a jitter percentage. The task is queued, not
        awaited, so the interval changes when the beacon next checks in.
        """
        for name, value in (("seconds", seconds), ("jitter", jitter)):
            # A string would let "30 20" ride into the beacon's args as two
            # values.
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError("%s must be a number, got %s"
                                % (name, type(value).__name__))
        await self.queue_task(agent_id, "sleep", "%g %g" % (seconds, jitter))

    # ── Server-side tools ──

    async def exec_server_tool(self, argv: Sequence[str], *, tool: str,
                               timeout: int, origin: str = "agent") -> str:
        """Start a tool on the C2 host and return its run id."""
        # The check comes first, before any request is built. The spec
        # forbids the agent the string form, which the C2 would run through
        # a shell; a type error at the call site is the cheapest way to
        # enforce that. A str is a Sequence of str, so it has to be refused
        # by name.
        if (isinstance(argv, (str, bytes)) or not isinstance(argv, (list, tuple))
                or not all(isinstance(part, str) for part in argv)):
            raise TypeError("argv must be a list of strings, not a command string")
        # `origin` keeps agent output out of the operator's panel.
        payload = await self._request(
            "POST", "/api/server/exec",
            {"argv": list(argv), "tool": tool, "timeout": timeout,
             "origin": origin})
        # A C2 that answers {"status": "started"} without a run id is the
        # old one-slot server; carrying on would let two runs overwrite each
        # other's output.
        return self._expect_text(payload, "run_id", "the started run")

    async def get_server_tool_result(self, run_id: str) -> Optional[dict]:
        """The run's state, or None while it is still running."""
        payload = await self._request(
            "GET", "/api/server/exec/result/" + _segment(run_id, "run_id"))
        payload = self._expect_dict(payload, "a tool run")
        if payload.get("status") in _TOOL_IN_FLIGHT:
            return None
        return _finished(payload)

    async def await_server_tool(self, run_id: str, *, timeout: float,
                                poll_interval: float = _POLL_INTERVAL_SECONDS
                                ) -> dict:
        """Poll until the run has finished, or `timeout` seconds have passed."""
        return await self._poll(
            lambda: self.get_server_tool_result(run_id), "run_id", run_id,
            timeout, poll_interval, None)

    # ── Polling ──

    async def _poll(self, fetch: Callable[[], Awaitable[Optional[dict]]],
                    id_key: str, ident: str, timeout: float,
                    poll_interval: float,
                    is_alive: Optional[IsAlive]) -> dict:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        negatives = 0
        while True:
            # Result first, liveness second: a beacon that answered and then
            # went away has still answered. A zero timeout polls once.
            result = await fetch()
            if result is not None:
                return result
            if is_alive is not None:
                if await is_alive():
                    negatives = 0
                else:
                    negatives += 1
                    if negatives >= _DEAD_AFTER:
                        raise BeaconGone(
                            "beacon stopped responding while waiting for "
                            "%s %s (%d liveness checks failed in a row)"
                            % (id_key, ident, negatives))
            remaining = deadline - loop.time()
            if remaining <= 0:
                return {"success": False, "status": "timeout", id_key: ident,
                        "output": "Timeout: no result for %s %s after %gs"
                                  % (id_key, ident, timeout)}
            await asyncio.sleep(min(poll_interval, remaining))
