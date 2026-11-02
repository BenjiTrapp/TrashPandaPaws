#!/usr/bin/env python3
"""The agent as a process: the campaign manager behind HTTP.

The C2 proxies `/api/ai/<path>` here with the prefix stripped, so the routes
sit at the root:

    GET  /status                         can a campaign start, and why not
    GET  /beacons                        the fleet and what each can do
    POST /campaign                       start one; {"run_id"}
    GET  /campaign/<id>                  Campaign.status()
    GET  /campaign/<id>/stream?since=N   {"events": [...], "next": N}
    GET  /campaign/<id>/approvals        requests waiting for the operator
    POST /campaign/<id>/approve          {"approval_id", "allowed"}
    POST /campaign/<id>/pause | resume | stop

    GET  /schedules                      every schedule, with its last result
    POST /schedules                      {"schedule", "prompt", "campaign"}
    DELETE /schedules/<id>
    POST /schedules/<id>/pause | resume

Errors are `{"error": ...}` with a status that says what kind: 400 for a form
that cannot be used, 401/403 for the token, 404 for an unknown run, approval
or schedule, 409 for a state change that does not apply or a beacon that
another campaign holds, 503 for a service or a C2 that is not ready. A 503
from POST /campaign also carries `reason`, which is what /status reports.

No response carries a secret. /status names the provider and the model, never
the key, and /beacons passes on a fixed list of fields rather than whatever
the C2 happens to attach to a beacon record.

Usage:
    app = service.make_app(cfg, conn, c2, manager)
    web.run_app(app, host=cfg.bind_host, port=cfg.bind_port)
"""

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import sqlite3
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from aiohttp import web

from software.agent import c2client, config, scheduler
from software.agent.llm import provider
from software.agent.orchestrator import Campaign, restore_orphans
from software.agent.store import queries

logger = logging.getLogger(__name__)

# ── Constants ──

TOKEN_HEADER = "X-Agent-Token"

# What the campaign form reads from a beacon record. Listed, not filtered
# down from the record: the C2 keeps more on a beacon than the form shows,
# and a field added there later should not start crossing this service's
# boundary because nobody looked.
_BEACON_FIELDS = ("id", "hostname", "os", "arch", "user", "status",
                  "interval", "uplink_iface")

# How long a schedule's description may be. It is shown in a list and in a
# notification; it is not given to the model.
_PROMPT_MAX = 500


# ── Responses ──


def _json(data, status=200) -> web.Response:
    return web.json_response(data, status=status)


def _error(status, message, **extra) -> web.Response:
    return _json(dict(extra, error=message), status)


def _loads(text) -> Any:
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


# ── Token ──


def _peer_is_loopback(request) -> bool:
    """Whether the TCP peer is this machine.

    Read from the transport, which holds what the kernel reported for the
    connection. Not `request.host` (the Host header), not X-Forwarded-For,
    Forwarded or X-Real-IP: the client writes every one of those. Not
    `request.remote` either: it is the same peername today, but it can be
    overridden by `clone(remote=...)`, and the transport cannot.
    """
    transport = request.transport
    peer = transport.get_extra_info("peername") if transport is not None else None
    # A Unix socket reports a path or None; neither is an address to trust.
    if not isinstance(peer, tuple) or not peer:
        return False
    try:
        address = ipaddress.ip_address(peer[0])
    except (TypeError, ValueError):
        return False
    # A dual-stack socket reports a local IPv4 client as ::ffff:127.0.0.1,
    # which Python does not call loopback.
    mapped = getattr(address, "ipv4_mapped", None)
    return (address if mapped is None else mapped).is_loopback


def _same_token(presented, expected) -> bool:
    # Digests of both, not the strings: compare_digest leaks the length when
    # the lengths differ, and a digest is always the same length. The
    # encoding errors are the client's to cause (a header can hold surrogate
    # escapes) and mean "does not match", not a 500.
    try:
        given = presented.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(hashlib.sha256(given).digest(),
                               hashlib.sha256(expected.encode("utf-8")).digest())


def _is_browser_request(request) -> bool:
    """Whether a browser sent this, which no legitimate caller here is.

    The only clients are the C2's proxy, which uses urllib, and an operator
    with curl. A browser attaches `Origin` to every cross-origin request and
    to any POST, and a page cannot suppress it — so its presence is the
    signal, and absence is what the real callers produce.

    This matters because the service listens on loopback and the operator
    browses the web on the same machine. Without it, a page they visit can
    POST to the campaign endpoint and start a run: no token is needed in
    loopback mode, and a no-cors form POST needs no preflight.
    """
    return bool(request.headers.get("Origin"))


def _host_is_local(request, cfg) -> bool:
    """Whether the Host header names this service rather than someone's domain.

    The defence against DNS rebinding: the attacker points their own name at
    127.0.0.1, so the connection really is from loopback and the peer check
    passes, but the Host header still carries their name. Only checked when
    no token is configured — with a token the token is the authority, and a
    deployment reaching the agent across a container network legitimately
    uses a Host this could not predict.
    """
    host = (request.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
    return host.lower() in _LOCAL_HOSTS or host == str(cfg.bind_host)


_LOCAL_HOSTS = frozenset(("127.0.0.1", "::1", "localhost",
                          "localhost.localdomain", ""))

# What a page can POST without a CORS preflight. Requiring JSON closes the
# form-shaped submissions; it costs a correct caller one header.
_SIMPLE_CONTENT_TYPES = ("text/plain", "application/x-www-form-urlencoded",
                         "multipart/form-data")


@web.middleware
async def require_agent_token(request, handler):
    """Every route, the unknown ones included, answers to the token.

    With no token configured the service is reachable from this machine only.
    That default is for a developer running it by hand; a deployment where
    the C2 reaches the agent across a container network has to set
    RACCOON_AGENT_TOKEN on both sides.
    """
    cfg = request.app[_SERVICE].cfg
    # Before the token, because these refuse a shape no real caller has and
    # the reason should not depend on whether a token happens to be set.
    if _is_browser_request(request):
        return _error(403, "requests from a browser are not accepted; this "
                           "service is reached by the C2 proxy")
    if request.method not in ("GET", "HEAD"):
        kind = (request.headers.get("Content-Type") or "").split(";")[0].strip()
        if kind.lower() in _SIMPLE_CONTENT_TYPES:
            return _error(415, "send application/json")
    token = cfg.agent_token
    if token:
        if not _same_token(request.headers.get(TOKEN_HEADER, ""), token):
            return _error(401, "missing or wrong %s" % TOKEN_HEADER)
    elif not _peer_is_loopback(request):
        return _error(403, "no agent token is configured, so only this "
                           "machine may connect; set RACCOON_AGENT_TOKEN")
    elif not _host_is_local(request, cfg):
        return _error(403, "the Host header does not name this service; set "
                           "RACCOON_AGENT_TOKEN to allow another name")
    return await handler(request)


# ── Handlers ──


class _Service:
    def __init__(self, cfg, conn, c2, manager, client_factory):
        self.cfg = cfg
        self.conn = conn
        self.c2 = c2
        self.manager = manager
        self.client_factory = client_factory

    # ── Status ──

    async def status(self, request):
        ok, reason = self.cfg.available()
        tier = self.cfg.capability_tier
        return _json({
            "available": ok, "reason": reason,
            "provider": self.cfg.provider, "model": self.cfg.model,
            # With the highest phase the tier allows, so the form can say
            # why phase 5 is locked instead of only greying it out.
            "tier": tier,
            "max_phase": provider.TIER_LIMITS.get(tier, {}).get("max_phase"),
            "db_ready": self._db_ready(),
            "opsec_warnings": self._opsec_by_profile(),
            "campaigns": self._campaigns()})

    def _db_ready(self) -> bool:
        try:
            self.conn.execute("SELECT 1 FROM runs LIMIT 1").fetchone()
        except sqlite3.Error:
            return False
        return True

    def _opsec_by_profile(self) -> Dict[str, List[str]]:
        """What each profile would not deliver with this configuration.

        For all of them, because the form needs it before a profile is
        chosen: "quiet" beside a hosted model is a promise it cannot keep,
        and the operator should read that while picking it, not after.
        """
        return {name: config.opsec_warnings(
                    self.cfg, SimpleNamespace(opsec_profile=name))
                for name in config.OPSEC_PROFILES}

    def _campaigns(self) -> List[Dict[str, Any]]:
        """Every unfinished campaign, each with its own status.

        "status" is the campaign's own state, so a paused run is told apart
        from a running one. The set of ids the scheduler's overlap lock reads
        counts both as taken, which is right for a lock and no use here.
        """
        out = []
        for entry in self.manager.active():
            campaign = self.manager.get(entry["run_id"])
            if campaign is not None:
                entry["opsec_profile"] = campaign.config.opsec_profile
                entry["opsec_warnings"] = config.opsec_warnings(
                    self.cfg, campaign.config)
            out.append(entry)
        return out

    async def beacons(self, request):
        try:
            agents = await self.c2.list_agents()
        except (c2client.C2Unavailable, c2client.C2Unauthorized) as exc:
            # The client's messages are built to carry no token or URL.
            return _error(503, str(exc))
        return _json({"beacons": [_beacon(a) for a in agents
                                  if isinstance(a, dict)]})

    # ── Campaigns ──

    async def start_campaign(self, request):
        # In this order: an unusable service is reported as that, whatever
        # else is wrong with the request. And no run row exists until all
        # three checks have passed.
        ok, reason = self.cfg.available()
        if not ok:
            return _error(503, "the agent is not available", reason=reason)
        try:
            form = await request.json()
        except ValueError:
            return _error(400, "the request body is not valid JSON")
        try:
            campaign_cfg = config.CampaignConfig.from_form(
                form, tier=self.cfg.capability_tier)
        except config.ConfigError as exc:
            return _error(400, str(exc))
        # After the form, so a bad one is still a 400, and before anything is
        # created. Nothing from here to manager.add() suspends (start() has no
        # suspension point either), so no other request can start a campaign
        # in the gap.
        held = scheduler.beacons_in_use(self.manager)
        for beacon in campaign_cfg.beacons:
            if beacon in held:
                # 409, not 400: the form is fine, the state is not. Paused
                # campaigns hold their beacons too; they will be resumed.
                return _error(409, "beacon %s is already in use by campaign %d"
                                   % (beacon, held[beacon]),
                              run_id=held[beacon])
        try:
            client = self.client_factory(self.cfg)
        except provider.ProviderError as exc:
            # available() builds the same client, so this is a configuration
            # that changed in between, but it must not become a stacktrace.
            return _error(503, "the agent is not available", reason=str(exc))
        campaign = Campaign(self.cfg, campaign_cfg, self.conn, self.c2, client)
        run_id = await campaign.start()
        # After start(), so a start that fails leaves nothing in the manager
        # that would never finish and never be pruned. start() has no
        # suspension point, so the job cannot end before it is registered.
        self.manager.add(campaign)
        return _json({"run_id": run_id})

    def _find(self, request) -> Optional[Campaign]:
        return self.manager.get(int(request.match_info["run_id"]))

    async def campaign_status(self, request):
        campaign = self._find(request)
        if campaign is None:
            return _error(404, "no such campaign")
        return _json(campaign.status())

    async def stream(self, request):
        campaign = self._find(request)
        if campaign is None:
            return _error(404, "no such campaign")
        raw = request.query.get("since", "0")
        try:
            since = int(raw)
        except ValueError:
            return _error(400, "since must be a whole number")
        events = campaign.stream(since)
        # seq counts from 1 and `since` is the last one seen, so the next
        # request asks from the last event returned, or from where it was.
        return _json({"events": events,
                      "next": events[-1]["seq"] if events else max(since, 0)})

    async def approvals(self, request):
        campaign = self._find(request)
        if campaign is None:
            return _error(404, "no such campaign")
        rows = campaign.gate.pending() if campaign.gate is not None else []
        return _json({"approvals": [_approval(row) for row in rows]})

    async def approve(self, request):
        campaign = self._find(request)
        if campaign is None:
            return _error(404, "no such campaign")
        try:
            answer = await request.json()
        except ValueError:
            return _error(400, "the request body is not valid JSON")
        if not isinstance(answer, dict):
            return _error(400, "the answer must be a JSON object")
        approval_id = answer.get("approval_id")
        allowed = answer.get("allowed")
        # bool is an int to Python, and "false" is a truthy string: an
        # approval is only ever given by an unmistakable true.
        if isinstance(approval_id, bool) or not isinstance(approval_id, int):
            return _error(400, "approval_id must be a whole number")
        if not isinstance(allowed, bool):
            return _error(400, "allowed must be true or false")
        if campaign.gate is None or not campaign.gate.answer(approval_id, allowed):
            return _error(404, "no such open approval request")
        return _json({"approval_id": approval_id, "allowed": allowed})

    async def pause(self, request):
        campaign = self._find(request)
        if campaign is None:
            return _error(404, "no such campaign")
        if campaign.state != "running":
            return _error(409, "only a running campaign can be paused "
                               "(this one is %s)" % campaign.state)
        # A request, not a state change: the campaign reads "paused" once its
        # orchestrator reaches the next model call.
        campaign.pause()
        return _json({"run_id": campaign.run_id, "status": campaign.state})

    async def resume(self, request):
        campaign = self._find(request)
        if campaign is None:
            return _error(404, "no such campaign")
        try:
            await campaign.resume()
        except RuntimeError as exc:
            return _error(409, str(exc))
        return _json({"run_id": campaign.run_id, "status": campaign.state})

    async def stop(self, request):
        campaign = self._find(request)
        if campaign is None:
            return _error(404, "no such campaign")
        # Not awaited: ending a run restores the beacons' intervals through
        # the C2, which can take as long as a timeout, and the operator's
        # click should not wait on it. The row reads "aborted" when it is done.
        campaign.stop()
        return _json({"run_id": campaign.run_id, "status": campaign.state})

    # ── Schedules ──

    async def list_schedules(self, request):
        return _json({"schedules": [_schedule(row)
                                    for row in queries.list_schedules(self.conn)]})

    async def create_schedule(self, request):
        try:
            body = await request.json()
        except ValueError:
            return _error(400, "the request body is not valid JSON")
        if not isinstance(body, dict):
            return _error(400, "the request body must be a JSON object")
        # Everything is checked now. The alternative is finding out at the
        # first slot, at whatever hour that is, that nothing will ever fire.
        expression = body.get("schedule")
        problem = scheduler.validate_cron(expression)
        if problem is not None:
            return _error(400, problem)
        prompt = body.get("prompt")
        if not isinstance(prompt, str) or not prompt.strip():
            return _error(400, "prompt must be a non-empty description of the "
                               "schedule")
        if len(prompt) > _PROMPT_MAX:
            return _error(400, "prompt is longer than %d characters"
                               % _PROMPT_MAX)
        try:
            campaign_cfg = config.CampaignConfig.from_form(
                body.get("campaign"), tier=self.cfg.capability_tier)
        except config.ConfigError as exc:
            return _error(400, str(exc))
        sid = queries.create_schedule(
            self.conn, prompt.strip(),
            json.dumps(scheduler.campaign_form(campaign_cfg)),
            " ".join(expression.split()))
        return _json({"id": sid,
                      "next_run": queries.get_schedule(self.conn, sid)["next_run"]})

    def _find_schedule(self, request) -> Optional[Dict[str, Any]]:
        return queries.get_schedule(self.conn, int(request.match_info["sid"]))

    async def delete_schedule(self, request):
        row = self._find_schedule(request)
        if row is None:
            return _error(404, "no such schedule")
        # The row only: a campaign it started is not stopped. That run is the
        # operator's to stop, and is listed with the others.
        queries.delete_schedule(self.conn, row["id"])
        return _json({"id": row["id"]})

    async def pause_schedule(self, request):
        row = self._find_schedule(request)
        if row is None:
            return _error(404, "no such schedule")
        if not queries.pause_schedule(self.conn, row["id"]):
            return _error(409, "only an active schedule can be paused "
                               "(this one is %s)" % row["status"])
        return _json({"id": row["id"], "status": "paused"})

    async def resume_schedule(self, request):
        row = self._find_schedule(request)
        if row is None:
            return _error(404, "no such schedule")
        if not queries.resume_schedule(self.conn, row["id"]):
            return _error(409, "only a paused schedule can be resumed "
                               "(this one is %s)" % row["status"])
        return _json({"id": row["id"], "status": "active",
                      "next_run": queries.get_schedule(
                          self.conn, row["id"])["next_run"]})


def _beacon(agent) -> Dict[str, Any]:
    out = {key: agent.get(key) for key in _BEACON_FIELDS}
    reported = agent.get("caps")
    out["caps"] = list(reported) if isinstance(reported, list) else []
    return out


def _approval(row) -> Dict[str, Any]:
    return {"id": row["id"], "action": row["action"],
            "requested_at": row["requested_at"],
            "classification": _loads(row["classification_json"]),
            "ev": _loads(row["ev_json"])}


def _schedule(row) -> Dict[str, Any]:
    # A named handful, as with beacons. `campaign` is the stored form, which
    # holds the campaign's settings and, by how it is built, nothing else.
    out = {key: row[key] for key in (
        "id", "prompt", "schedule", "status", "next_run", "last_run",
        "last_result", "running_run_id", "created_at")}
    out["campaign"] = _loads(row["config_json"])
    return out


# ── Startup and shutdown ──


async def on_startup(cfg, conn, c2, manager) -> None:
    """Put right what a crash left: runs marked running, intervals still low.

    Catches everything. The service has to come up when the C2 is down, and
    that is a case restore_orphans already survives; this also covers the one
    it does not expect. A service that will not start because it could not
    tidy up leaves the operator with no status page to read the reason from.
    `cfg` is unused here; the hook takes the service's four arguments.
    """
    try:
        handled = await restore_orphans(conn, c2)
    except Exception as exc:
        # The class only, as everywhere in this package that a message from
        # the layer below might name a URL or a header.
        logger.warning("orphan recovery failed (%s); the service starts "
                       "anyway, beacon polling intervals may need resetting "
                       "by hand", type(exc).__name__)
        logger.debug("orphan recovery failure", exc_info=True)
        return
    if handled:
        logger.info("recovered %d unfinished run(s) from a previous process: "
                    "%s", len(handled), ", ".join(str(i) for i in handled))


async def _stop_running(manager) -> None:
    """End the campaigns that are running when the service shuts down.

    A running one is stopped, which puts the beacons' intervals back; left
    alone it would be cancelled with the loop and never get to. A paused one
    is not touched: pause is the exit that stays resumable, and it holds no
    task. On the next start restore_orphans tidies whatever this missed.
    """
    running = [c for c in (manager.get(e["run_id"]) for e in manager.active())
               if c is not None and c.state == "running"]
    for campaign in running:
        campaign.stop()
    # The result is not wanted, only that each has ended; a failure in one
    # must not keep the others from being waited for.
    await asyncio.gather(*(c.wait() for c in running), return_exceptions=True)


# ── Application ──

_SERVICE = web.AppKey("service", _Service)


def make_app(cfg, conn, c2, manager, *,
             client_factory=provider.create_client) -> web.Application:
    """The service for one agent configuration.

    `client_factory` builds the model client for each campaign. It is a
    parameter so a test can hand over a scripted one; the default is the
    real thing, which is what available() has already checked.
    """
    service = _Service(cfg, conn, c2, manager, client_factory)
    app = web.Application(middlewares=[require_agent_token])
    app[_SERVICE] = service
    app.add_routes([
        web.get("/status", service.status),
        web.get("/beacons", service.beacons),
        web.post("/campaign", service.start_campaign),
        web.get(r"/campaign/{run_id:\d+}", service.campaign_status),
        web.get(r"/campaign/{run_id:\d+}/stream", service.stream),
        web.get(r"/campaign/{run_id:\d+}/approvals", service.approvals),
        web.post(r"/campaign/{run_id:\d+}/approve", service.approve),
        web.post(r"/campaign/{run_id:\d+}/pause", service.pause),
        web.post(r"/campaign/{run_id:\d+}/resume", service.resume),
        web.post(r"/campaign/{run_id:\d+}/stop", service.stop),
        web.get("/schedules", service.list_schedules),
        web.post("/schedules", service.create_schedule),
        web.delete(r"/schedules/{sid:\d+}", service.delete_schedule),
        web.post(r"/schedules/{sid:\d+}/pause", service.pause_schedule),
        web.post(r"/schedules/{sid:\d+}/resume", service.resume_schedule),
    ])

    # A list and not an attribute of the app: setting a key on an application
    # that has started is deprecated, and startup is exactly when this is set.
    polling = []  # type: List[asyncio.Task]

    async def _startup(_app):
        # In this order: the poll must not see a run that restore_orphans is
        # about to mark failed, nor start one it would then take for a crash.
        await on_startup(cfg, conn, c2, manager)
        polling.append(scheduler.start_loop(
            conn, manager, cfg, c2=c2, client_factory=client_factory))

    async def _cleanup(_app):
        # Before the campaigns are stopped: a poll running during the
        # shutdown could start one the stop below would not know about.
        for task in polling:
            task.cancel()
        await asyncio.gather(*polling, return_exceptions=True)
        polling.clear()
        await _stop_running(manager)

    app.on_startup.append(_startup)
    app.on_cleanup.append(_cleanup)
    return app
