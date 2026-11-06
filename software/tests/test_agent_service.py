#!/usr/bin/env python3
"""
Tests for the agent's HTTP service: the endpoints, the token check, startup.

Nothing here reaches beyond aiohttp's own loopback test server: the C2 is the
orchestrator tests' FakeC2 and the model is a scripted client handed to
make_app through its `client_factory` seam.

The assertions that carry the most weight:

  * an unconfigured provider is a 503 with a reason, never a stacktrace, and
    the checks in POST /campaign run in the order the spec gives;
  * the token is compared in constant time, and with no token configured only
    the connection's *peer address* decides, never a header the client sets;
  * no GET endpoint ever returns a configured secret;
  * `paused` and `running` are told apart per campaign, and the opsec
    warnings the configuration computes reach /status;
  * nothing is left pending when a test ends. The base class checks before
    IsolatedAsyncioTestCase can quietly cancel a leaked task.
"""

import asyncio
import hmac
import json
import sys
import unittest
import unittest.mock
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, make_mocked_request

from software.agent import config, orchestrator, safety, service
from software.agent.llm import mock
from software.agent.llm.provider import ProviderError
from software.agent.store import db, queries
from software.tests import test_agent_orchestrator as _orch

# Distinctive on purpose: a test that greps a response for a secret is only as
# good as the secret is unlikely to appear by chance.
_TOKEN = "ZZ-not-a-real-agent-token"
_API_KEY = "ZZ-not-a-real-api-key"
_C2_TOKEN = "ZZ-not-a-real-c2-token"
_SECRETS = (_TOKEN, _API_KEY, _C2_TOKEN)
_H = {"X-Agent-Token": _TOKEN}


# ── Builders ──


def _cfg(**fields):
    """A configured agent; pass `provider=None` for an unconfigured one."""
    values = dict(provider="anthropic", model="test-model", api_key=_API_KEY,
                  c2_token=_C2_TOKEN, agent_token=_TOKEN,
                  capability_tier="reduced", approval_timeout=5.0)
    values.update(fields)
    return config.AgentConfig(**values)


def _form(**fields):
    form = {"beacons": ["raccoon-fox"], "scope_allow": ["10.0.1.0/24"],
            "campaign_interval": 15, "restore_interval": 300}
    form.update(fields)
    return form


class _FleetC2(_orch.FakeC2):
    async def list_agents(self):
        self._reachable()
        return list(self.agents.values())


def _env(c2_down=False):
    return db.open_store(":memory:"), _FleetC2(down=c2_down)


def _manager():
    return orchestrator.CampaignManager()


def _slow_client(delay=0.1):
    # 0.1s a turn: long enough that a campaign is still running when the
    # test looks at it, short enough that the turn limit ends the run.
    return _orch._SlowClient(delay=delay)


class _Rig(NamedTuple):
    app: web.Application
    cfg: config.AgentConfig
    conn: object
    c2: object
    manager: orchestrator.CampaignManager


def _rig(cfg=None, client=None, c2_down=False, **cfg_fields):
    cfg = cfg if cfg is not None else _cfg(**cfg_fields)
    conn, c2 = _env(c2_down=c2_down)
    manager = _manager()
    app = service.make_app(cfg, conn, c2, manager,
                           client_factory=lambda _cfg: client)
    return _Rig(app, cfg, conn, c2, manager)


def _app(**kwargs):
    return _rig(**kwargs).app


async def _until(check, what, timeout=5.0):
    """Poll an async predicate; fail loudly, naming what never happened."""
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        value = await check()
        if value:
            return value
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("timed out waiting for %s" % what)
        await asyncio.sleep(0.01)


async def _pending_tasks():
    me = asyncio.current_task()
    return [t for t in asyncio.all_tasks() if t is not me and not t.done()]


class _ServiceCase(AioHTTPTestCase):
    """The loopback server, and a look for leaked tasks once it is closed."""

    rig = None

    async def asyncTearDown(self):
        await super().asyncTearDown()
        left = await _pending_tasks()
        names = [repr(t.get_coro()) for t in left]
        for t in left:
            t.cancel()
        self.assertEqual(names, [], "tasks still pending at the end of the test")

    async def get(self, path, **kw):
        return await self.client.get(path, headers=_H, **kw)

    async def post(self, path, payload=None, **kw):
        return await self.client.post(path, json=payload, headers=_H, **kw)

    async def start_campaign(self, **form):
        resp = await self.post("/campaign", _form(**form))
        self.assertEqual(resp.status, 200, await resp.text())
        return (await resp.json())["run_id"]

    async def campaign_states(self):
        body = await (await self.get("/status")).json()
        return {c["run_id"]: c["status"] for c in body["campaigns"]}


async def _start_campaign_awaiting_approval(case):
    """A supervised campaign stopped at the gate; returns its run id."""
    rid = await case.start_campaign(mode="supervised")

    async def listed():
        body = await (await case.get("/campaign/%d/approvals" % rid)).json()
        return body["approvals"]

    await _until(listed, "an approval request")
    return rid


# ── No provider ──


class TestStatusWithoutProvider(_ServiceCase):
    """Spec §19.1: the service runs with no provider configured."""

    async def get_application(self):
        self.rig = _rig(provider=None)
        return self.rig.app

    async def test_status_reports_unavailable_with_reason(self):
        body = await (await self.get("/status")).json()
        self.assertFalse(body["available"])
        self.assertIn("provider", body["reason"].lower())

    async def test_status_names_no_provider_and_no_model(self):
        body = await (await self.get("/status")).json()
        self.assertIsNone(body["provider"])

    async def test_campaign_start_is_refused_cleanly(self):
        resp = await self.post("/campaign", _form())
        self.assertEqual(resp.status, 503)
        text = await resp.text()
        self.assertIn("provider", json.loads(text)["reason"].lower())
        self.assertNotIn("Traceback", text)

    async def test_a_refused_start_leaves_no_run_behind(self):
        await self.post("/campaign", _form())
        self.assertEqual(queries.list_unfinished_runs(self.rig.conn), [])

    async def test_availability_is_checked_before_the_form(self):
        # An unusable form on an unusable service is still the 503: the
        # operator fixes the provider first, whatever else is wrong.
        resp = await self.post("/campaign", _form(scope_allow=[]))
        self.assertEqual(resp.status, 503)

    async def test_the_tier_one_list_is_there_without_a_provider(self):
        # The form is greyed out then, but it still reads the list.
        body = await (await self.get("/status")).json()
        self.assertTrue(body["tier1_actions"])

    async def test_database_is_still_initialised(self):
        body = await (await self.get("/status")).json()
        self.assertTrue(body["db_ready"])

    async def test_beacons_are_still_listed(self):
        body = await (await self.get("/beacons")).json()
        self.assertEqual([b["id"] for b in body["beacons"]], ["raccoon-fox"])


class TestStatusWithProvider(_ServiceCase):
    async def get_application(self):
        self.rig = _rig(client=mock.MockClient([]), capability_tier="reduced")
        return self.rig.app

    async def test_status_reports_provider_model_and_tier(self):
        body = await (await self.get("/status")).json()
        self.assertTrue(body["available"])
        self.assertEqual(body["reason"], "")
        self.assertEqual(body["provider"], "anthropic")
        self.assertEqual(body["model"], "test-model")
        self.assertEqual(body["tier"], "reduced")

    async def test_status_gives_the_highest_phase_the_tier_allows(self):
        # What the form needs to say why phase 5 is locked.
        body = await (await self.get("/status")).json()
        self.assertEqual(body["max_phase"], 4)

    async def test_status_lists_the_tier_one_actions_from_the_risk_table(self):
        # The form shows what the agent can never do. A copy of that list in
        # JavaScript would drift from the classifier; this one is derived.
        body = await (await self.get("/status")).json()
        listed = {a["key"]: a["reason"] for a in body["tier1_actions"]}
        expected = {key: row.reason for key, row in safety.RISK_TABLE.items()
                    if row.tier == safety.TIER_HARD}
        self.assertEqual(listed, expected)
        self.assertIn("beacon_control", listed)
        self.assertNotIn("lsass_dump", listed)  # tier 2: gated, not blocked
        self.assertTrue(all(listed.values()), "every entry carries its reason")

    async def test_db_ready_is_false_when_the_store_is_unusable(self):
        self.rig.conn.close()
        body = await (await self.get("/status")).json()
        self.assertFalse(body["db_ready"])

    async def test_a_sliver_drop_box_is_explained_in_the_reason(self):
        self.rig.cfg.sliver_enabled = True
        body = await (await self.get("/status")).json()
        self.assertFalse(body["available"])
        self.assertIn("Sliver", body["reason"])


# ── Opsec warnings ──


class TestOpsecWarningsReachStatus(_ServiceCase):
    async def get_application(self):
        self.rig = _rig(client=_slow_client())
        return self.rig.app

    async def test_each_profile_is_answered_for_the_configured_provider(self):
        warnings = (await (await self.get("/status")).json())["opsec_warnings"]
        self.assertEqual(set(warnings), set(config.OPSEC_PROFILES))
        self.assertEqual(warnings["normal"], [])
        # quiet with a hosted model: the finding still goes to the provider
        self.assertTrue(any("anthropic" in w for w in warnings["quiet"]))
        self.assertTrue(any("scan rate" in w for w in warnings["yolo"]))

    async def test_status_agrees_with_the_function_that_computes_them(self):
        warnings = (await (await self.get("/status")).json())["opsec_warnings"]
        for name in config.OPSEC_PROFILES:
            expected = config.opsec_warnings(
                self.rig.cfg, unittest.mock.Mock(opsec_profile=name))
            self.assertEqual(warnings[name], expected, name)

    async def test_a_running_quiet_campaign_carries_its_own_warning(self):
        await self.start_campaign(opsec_profile="quiet")
        [entry] = (await (await self.get("/status")).json())["campaigns"]
        self.assertEqual(entry["opsec_profile"], "quiet")
        self.assertTrue(any("anthropic" in w for w in entry["opsec_warnings"]))

    async def test_a_normal_campaign_carries_none(self):
        await self.start_campaign()
        [entry] = (await (await self.get("/status")).json())["campaigns"]
        self.assertEqual(entry["opsec_warnings"], [])


class TestLocalProviderIsQuiet(_ServiceCase):
    async def get_application(self):
        self.rig = _rig(provider="local", api_key=None,
                        client=mock.MockClient([]))
        return self.rig.app

    async def test_quiet_with_a_local_model_warns_of_nothing(self):
        warnings = (await (await self.get("/status")).json())["opsec_warnings"]
        self.assertEqual(warnings["quiet"], [])


# ── Authentication ──


class TestAuth(_ServiceCase):
    async def get_application(self):
        self.rig = _rig(agent_token="right-token")
        return self.rig.app

    async def test_missing_token_is_401(self):
        self.assertEqual((await self.client.get("/status")).status, 401)

    async def test_wrong_token_is_401(self):
        resp = await self.client.get("/status",
                                     headers={"X-Agent-Token": "wrong-token"})
        self.assertEqual(resp.status, 401)

    async def test_a_prefix_of_the_token_is_401(self):
        resp = await self.client.get("/status",
                                     headers={"X-Agent-Token": "right-toke"})
        self.assertEqual(resp.status, 401)

    async def test_an_empty_token_is_401(self):
        resp = await self.client.get("/status", headers={"X-Agent-Token": ""})
        self.assertEqual(resp.status, 401)

    async def test_correct_token_passes(self):
        resp = await self.client.get("/status",
                                     headers={"X-Agent-Token": "right-token"})
        self.assertEqual(resp.status, 200)

    async def test_every_route_is_behind_the_token(self):
        for method, path in (("GET", "/beacons"), ("POST", "/campaign"),
                             ("GET", "/campaign/1"), ("GET", "/campaign/1/stream"),
                             ("GET", "/campaign/1/approvals"),
                             ("POST", "/campaign/1/approve"),
                             ("POST", "/campaign/1/pause"),
                             ("POST", "/campaign/1/resume"),
                             ("POST", "/campaign/1/stop"),
                             ("GET", "/no-such-route")):
            resp = await self.client.request(method, path)
            self.assertEqual(resp.status, 401, "%s %s" % (method, path))

    async def test_the_comparison_is_constant_time(self):
        with unittest.mock.patch.object(
                service.hmac, "compare_digest",
                wraps=hmac.compare_digest) as compare:
            await self.client.get("/status",
                                  headers={"X-Agent-Token": "wrong-token"})
        compare.assert_called_once()

    async def test_the_rejection_names_neither_token(self):
        resp = await self.client.get("/status",
                                     headers={"X-Agent-Token": "wrong-token"})
        text = await resp.text()
        self.assertNotIn("right-token", text)


class TestTokenMiddlewareDirectly(unittest.IsolatedAsyncioTestCase):
    """The middleware against a request whose transport we control.

    A real connection to the test server always comes from loopback, so the
    other case needs a request that says it did not.
    """

    def _request(self, *, peer, headers=None, token=None):
        app = _app(agent_token=token)
        transport = unittest.mock.Mock()
        transport.get_extra_info.side_effect = (
            lambda name, default=None: peer if name == "peername" else default)
        return make_mocked_request("GET", "/status", headers=headers,
                                   transport=transport, app=app)

    async def _status(self, **kw):
        async def reached(request):
            return web.Response(text="reached")
        resp = await service.require_agent_token(self._request(**kw), reached)
        return resp.status

    async def test_no_token_accepts_a_loopback_peer(self):
        for peer in (("127.0.0.1", 5000), ("::1", 5000, 0, 0),
                     ("127.9.9.9", 5000)):
            self.assertEqual(await self._status(peer=peer), 200, peer)

    async def test_no_token_accepts_an_ipv4_mapped_loopback_peer(self):
        # What a dual-stack socket reports for a local IPv4 client.
        self.assertEqual(
            await self._status(peer=("::ffff:127.0.0.1", 5000, 0, 0)), 200)

    async def test_no_token_refuses_a_remote_peer(self):
        for peer in (("203.0.113.9", 5000), ("10.0.0.5", 5000),
                     ("2001:db8::1", 5000, 0, 0),
                     ("::ffff:203.0.113.9", 5000, 0, 0)):
            self.assertEqual(await self._status(peer=peer), 403, peer)

    async def test_the_client_cannot_claim_to_be_local(self):
        # Every header a client controls says "loopback"; the peer does not.
        headers = {"Host": "127.0.0.1:8099", "X-Forwarded-For": "127.0.0.1",
                   "Forwarded": "for=127.0.0.1", "X-Real-IP": "127.0.0.1",
                   "X-Agent-Token": _TOKEN}
        self.assertEqual(
            await self._status(peer=("203.0.113.9", 5000), headers=headers), 403)

    async def test_no_token_refuses_a_peer_it_cannot_read(self):
        # A Unix socket reports a path or nothing; neither is loopback.
        for peer in (None, "", "/run/agent.sock", ("not-an-address", 1)):
            self.assertEqual(await self._status(peer=peer), 403, repr(peer))

    async def test_a_configured_token_does_not_look_at_the_peer(self):
        ok = {"X-Agent-Token": "right-token"}
        self.assertEqual(await self._status(
            peer=("203.0.113.9", 5000), headers=ok, token="right-token"), 200)

    async def test_a_token_that_is_not_ascii_is_refused_not_an_error(self):
        self.assertEqual(await self._status(
            peer=("127.0.0.1", 1), headers={"X-Agent-Token": "r\u00efght-token"},
            token="right-token"), 401)

    def test_a_header_that_cannot_be_encoded_does_not_match(self):
        # A lone surrogate is what a malformed header can decode to; it
        # cannot be built into a mocked request, so the comparison is called.
        self.assertFalse(service._same_token("right-token\udcff", "right-token"))
        self.assertTrue(service._same_token("right-token", "right-token"))

    async def test_a_configured_token_that_is_not_ascii_still_works(self):
        self.assertEqual(await self._status(
            peer=("127.0.0.1", 1), headers={"X-Agent-Token": "t\u00f6ken"},
            token="t\u00f6ken"), 200)


class TestNoTokenOverLoopback(_ServiceCase):
    """The real server, no token: a loopback connection is accepted."""

    async def get_application(self):
        self.rig = _rig(agent_token=None)
        return self.rig.app

    async def test_a_local_client_needs_no_header(self):
        self.assertEqual((await self.client.get("/status")).status, 200)


# ── Campaigns ──


class TestCampaignEndpoints(_ServiceCase):
    async def get_application(self):
        self.rig = _rig(client=mock.MockClient([mock.text("done")]))
        return self.rig.app

    async def test_start_returns_a_run_id(self):
        body = await (await self.post("/campaign", _form())).json()
        self.assertIsInstance(body["run_id"], int)
        self.assertEqual(
            queries.get_run(self.rig.conn, body["run_id"])["id"], body["run_id"])

    async def test_empty_scope_is_a_400(self):
        resp = await self.post("/campaign", _form(scope_allow=[]))
        self.assertEqual(resp.status, 400)
        self.assertIn("scope_allow", (await resp.json())["error"])

    async def test_no_beacons_is_a_400(self):
        self.assertEqual(
            (await self.post("/campaign", _form(beacons=[]))).status, 400)

    async def test_a_malformed_scope_is_a_400(self):
        self.assertEqual(
            (await self.post("/campaign", _form(scope_allow=["nonsense"]))).status,
            400)

    async def test_a_body_that_is_not_json_is_a_400(self):
        resp = await self.client.post("/campaign", data=b"{not json",
                                      headers=_H)
        self.assertEqual(resp.status, 400)

    async def test_a_body_that_is_not_an_object_is_a_400(self):
        self.assertEqual((await self.post("/campaign", [1, 2])).status, 400)

    async def test_a_refused_form_leaves_no_run_behind(self):
        await self.post("/campaign", _form(scope_allow=[]))
        self.assertEqual(queries.list_unfinished_runs(self.rig.conn), [])

    async def test_status_of_unknown_run_is_404(self):
        self.assertEqual((await self.get("/campaign/9999")).status, 404)

    async def test_a_run_id_that_is_not_a_number_is_404(self):
        self.assertEqual((await self.get("/campaign/abc")).status, 404)

    async def test_campaign_status_is_the_campaigns_own(self):
        rid = await self.start_campaign()
        body = await (await self.get("/campaign/%d" % rid)).json()
        self.assertEqual(body["run_id"], rid)
        self.assertIn(body["status"], ("running", "completed"))
        self.assertIn("budgets", body)

    async def test_stream_is_incremental(self):
        rid = await self.start_campaign()
        first = await (await self.get("/campaign/%d/stream" % rid)).json()
        self.assertGreater(len(first["events"]), 0)
        self.assertEqual(first["next"], first["events"][-1]["seq"])
        second = await (await self.get(
            "/campaign/%d/stream?since=%d" % (rid, first["next"]))).json()
        self.assertEqual(second["events"], [])

    async def test_stream_since_returns_only_what_is_new(self):
        rid = await self.start_campaign()
        everything = await _until(
            lambda: self._finished_stream(rid), "the campaign to finish")
        tail = await (await self.get(
            "/campaign/%d/stream?since=1" % rid)).json()
        self.assertEqual(tail["events"], everything[1:])

    async def _finished_stream(self, rid):
        status = await (await self.get("/campaign/%d" % rid)).json()
        if status["status"] != "completed":
            return None
        return (await (await self.get("/campaign/%d/stream" % rid)).json())["events"]

    async def test_stream_since_that_is_not_a_number_is_a_400(self):
        rid = await self.start_campaign()
        resp = await self.get("/campaign/%d/stream?since=soon" % rid)
        self.assertEqual(resp.status, 400)

    async def test_stream_of_unknown_run_is_404(self):
        self.assertEqual((await self.get("/campaign/9999/stream")).status, 404)

    async def test_beacons_endpoint_exposes_capabilities(self):
        body = await (await self.get("/beacons")).json()
        self.assertEqual(body["beacons"][0]["caps"], ["batch"])
        self.assertEqual(body["beacons"][0]["id"], "raccoon-fox")

    async def test_beacons_carry_only_the_fields_the_form_needs(self):
        self.rig.c2.agents["raccoon-fox"]["session_key"] = "internal"
        self.rig.c2.agents["raccoon-fox"]["_last_seen_ts"] = 1.0
        [beacon] = (await (await self.get("/beacons")).json())["beacons"]
        self.assertNotIn("session_key", beacon)
        self.assertNotIn("_last_seen_ts", beacon)


class TestWhenTheProviderFailsAfterTheCheck(_ServiceCase):
    """available() passed, then building the client refused anyway."""

    async def get_application(self):
        def refuse(_cfg):
            raise ProviderError("provider 'anthropic' went away")

        self.rig = _rig()
        app = service.make_app(self.rig.cfg, self.rig.conn, self.rig.c2,
                               self.rig.manager, client_factory=refuse)
        return app

    async def test_it_is_a_503_not_a_stacktrace(self):
        resp = await self.post("/campaign", _form())
        self.assertEqual(resp.status, 503)
        text = await resp.text()
        self.assertIn("went away", json.loads(text)["reason"])
        self.assertNotIn("Traceback", text)
        self.assertEqual(queries.list_unfinished_runs(self.rig.conn), [])


class TestBeaconsWithC2Down(_ServiceCase):
    async def get_application(self):
        self.rig = _rig(c2_down=True)
        return self.rig.app

    async def test_it_is_a_503_that_says_why(self):
        resp = await self.get("/beacons")
        self.assertEqual(resp.status, 503)
        self.assertIn("C2", (await resp.json())["error"])

    async def test_status_still_answers(self):
        self.assertEqual((await self.get("/status")).status, 200)


# ── Approvals ──


class TestApprovalFlow(_ServiceCase):
    async def get_application(self):
        self.rig = _rig(client=mock.MockClient([
            mock.calls(("dispatch_task", {"task_name": "t",
                                          "task_description": "d"})),
            mock.calls(("run_command", {"command": "useradd tester",
                                        "beacon_id": "raccoon-fox"})),
            mock.text("TASK: t\nSTATUS: success"),
            mock.text("campaign over")]))
        return self.rig.app

    async def test_pending_approval_is_listed_and_can_be_answered(self):
        rid = await _start_campaign_awaiting_approval(self)
        pend = await (await self.get("/campaign/%d/approvals" % rid)).json()
        self.assertEqual(len(pend["approvals"]), 1)
        item = pend["approvals"][0]
        self.assertEqual(item["action"], "persist")
        self.assertIsInstance(item["classification"], dict)
        self.assertIn("ev", item["ev"])
        resp = await self.post("/campaign/%d/approve" % rid,
                               {"approval_id": item["id"], "allowed": True})
        self.assertEqual(resp.status, 200)
        self.assertEqual(await resp.json(),
                         {"approval_id": item["id"], "allowed": True})

    async def test_the_answer_reaches_the_campaign(self):
        rid = await _start_campaign_awaiting_approval(self)
        [item] = (await (await self.get(
            "/campaign/%d/approvals" % rid)).json())["approvals"]
        await self.post("/campaign/%d/approve" % rid,
                        {"approval_id": item["id"], "allowed": True})

        async def done():
            body = await (await self.get("/campaign/%d" % rid)).json()
            return body["status"] == "completed"

        await _until(done, "the approved campaign to finish")
        self.assertEqual(len(self.rig.c2.queued), 1)
        row = self.rig.conn.execute(
            "SELECT decision, decided_by FROM approvals").fetchone()
        self.assertEqual((row["decision"], row["decided_by"]),
                         ("approved", "operator"))

    async def test_a_refusal_reaches_the_campaign(self):
        rid = await _start_campaign_awaiting_approval(self)
        [item] = (await (await self.get(
            "/campaign/%d/approvals" % rid)).json())["approvals"]
        resp = await self.post("/campaign/%d/approve" % rid,
                               {"approval_id": item["id"], "allowed": False})
        self.assertEqual(resp.status, 200)

        async def answered():
            body = await (await self.get(
                "/campaign/%d/approvals" % rid)).json()
            return body["approvals"] == []

        await _until(answered, "the request to leave the pending list")
        self.assertEqual(self.rig.c2.queued, [])

    async def test_answering_twice_is_404(self):
        rid = await _start_campaign_awaiting_approval(self)
        [item] = (await (await self.get(
            "/campaign/%d/approvals" % rid)).json())["approvals"]
        answer = {"approval_id": item["id"], "allowed": True}
        self.assertEqual(
            (await self.post("/campaign/%d/approve" % rid, answer)).status, 200)
        self.assertEqual(
            (await self.post("/campaign/%d/approve" % rid, answer)).status, 404)

    async def test_answering_an_unknown_approval_is_404(self):
        rid = await self.start_campaign()
        resp = await self.post("/campaign/%d/approve" % rid,
                               {"approval_id": 9999, "allowed": True})
        self.assertEqual(resp.status, 404)

    async def test_answering_for_an_unknown_run_is_404(self):
        resp = await self.post("/campaign/9999/approve",
                               {"approval_id": 1, "allowed": True})
        self.assertEqual(resp.status, 404)

    async def test_allowed_must_be_a_real_boolean(self):
        # "false" is a truthy string; an approval has to be unmistakable.
        rid = await _start_campaign_awaiting_approval(self)
        [item] = (await (await self.get(
            "/campaign/%d/approvals" % rid)).json())["approvals"]
        for allowed in ("false", "true", 1, 0, None):
            resp = await self.post("/campaign/%d/approve" % rid,
                                   {"approval_id": item["id"],
                                    "allowed": allowed})
            self.assertEqual(resp.status, 400, repr(allowed))
        pend = await (await self.get("/campaign/%d/approvals" % rid)).json()
        self.assertEqual(len(pend["approvals"]), 1)

    async def test_approval_id_must_be_a_whole_number(self):
        rid = await self.start_campaign()
        for bad in ("1", 1.5, True, None, [1]):
            resp = await self.post("/campaign/%d/approve" % rid,
                                   {"approval_id": bad, "allowed": True})
            self.assertEqual(resp.status, 400, repr(bad))

    async def test_an_answer_that_is_not_an_object_is_a_400(self):
        rid = await self.start_campaign()
        self.assertEqual(
            (await self.post("/campaign/%d/approve" % rid, [1])).status, 400)


# ── Lifecycle ──


class TestLifecycleEndpoints(_ServiceCase):
    async def get_application(self):
        self.rig = _rig(client=_slow_client())
        return self.rig.app

    async def _paused(self, rid):
        async def check():
            return (await self.campaign_states()).get(rid) == "paused"
        await _until(check, "campaign %d to pause" % rid)

    async def test_pause_then_resume(self):
        rid = await self.start_campaign()
        resp = await self.post("/campaign/%d/pause" % rid)
        self.assertEqual(resp.status, 200)
        # A pause is a request: it takes effect at the next model call.
        await self._paused(rid)
        resp = await self.post("/campaign/%d/resume" % rid)
        self.assertEqual(resp.status, 200)
        self.assertEqual((await self.campaign_states())[rid], "running")

    async def test_resume_of_a_running_campaign_is_a_409(self):
        rid = await self.start_campaign()
        resp = await self.post("/campaign/%d/resume" % rid)
        self.assertEqual(resp.status, 409)
        self.assertIn("running", (await resp.json())["error"])

    async def test_pause_of_a_paused_campaign_is_a_409(self):
        rid = await self.start_campaign()
        await self.post("/campaign/%d/pause" % rid)
        await self._paused(rid)
        self.assertEqual(
            (await self.post("/campaign/%d/pause" % rid)).status, 409)

    async def test_stop_marks_the_run_aborted(self):
        rid = await self.start_campaign()
        self.assertEqual(
            (await self.post("/campaign/%d/stop" % rid)).status, 200)

        async def aborted():
            body = await (await self.get("/campaign/%d" % rid)).json()
            return body["status"] == "aborted"

        await _until(aborted, "the stopped campaign to be aborted")
        self.assertEqual(
            queries.get_run(self.rig.conn, rid)["status"], "aborted")
        self.assertEqual(self.rig.c2.interval_calls[-1][1], 300)

    async def test_stop_of_a_stopped_campaign_is_harmless(self):
        rid = await self.start_campaign()
        await self.post("/campaign/%d/stop" % rid)
        again = await self.post("/campaign/%d/stop" % rid)
        self.assertEqual(again.status, 200)

    async def test_a_paused_campaign_can_be_stopped(self):
        rid = await self.start_campaign()
        await self.post("/campaign/%d/pause" % rid)
        await self._paused(rid)
        self.assertEqual(
            (await self.post("/campaign/%d/stop" % rid)).status, 200)

        async def aborted():
            return queries.get_run(self.rig.conn, rid)["status"] == "aborted"

        await _until(aborted, "the paused campaign to be aborted")

    async def test_the_lifecycle_routes_know_unknown_runs(self):
        for verb in ("pause", "resume", "stop"):
            resp = await self.post("/campaign/9999/%s" % verb)
            self.assertEqual(resp.status, 404, verb)

    async def test_paused_and_running_are_told_apart_in_the_list(self):
        # Its own beacon: two campaigns do not share one.
        self.rig.c2.agents["raccoon-owl"] = dict(
            self.rig.c2.agents["raccoon-fox"], id="raccoon-owl")
        first = await self.start_campaign()
        second = await self.start_campaign(beacons=["raccoon-owl"])
        await self.post("/campaign/%d/pause" % first)
        await self._paused(first)
        states = await self.campaign_states()
        self.assertEqual(states, {first: "paused", second: "running"})


class TestCampaignsLeaveTheList(_ServiceCase):
    async def get_application(self):
        self.rig = _rig(client=mock.MockClient([mock.text("done")]))
        return self.rig.app

    async def test_a_finished_campaign_is_no_longer_listed_but_still_readable(self):
        rid = await self.start_campaign()

        async def finished():
            return rid not in await self.campaign_states()

        await _until(finished, "the campaign to leave the list")
        body = await (await self.get("/campaign/%d" % rid)).json()
        self.assertEqual(body["status"], "completed")


# ── No secret in any response ──


class TestNoSecretInAnyResponse(_ServiceCase):
    async def get_application(self):
        self.rig = _rig(client=mock.MockClient([mock.text("done")]))
        return self.rig.app

    async def test_the_secrets_are_really_configured(self):
        # Without this the test below could pass for the wrong reason.
        cfg = self.rig.cfg
        self.assertEqual({cfg.api_key, cfg.c2_token, cfg.agent_token},
                         set(_SECRETS))

    async def test_no_get_endpoint_returns_a_secret(self):
        rid = await self.start_campaign()
        paths = ["/status", "/beacons", "/campaign/%d" % rid,
                 "/campaign/%d/stream" % rid,
                 "/campaign/%d/approvals" % rid,
                 "/campaign/9999", "/no-such-route"]
        for path in paths:
            resp = await self.get(path)
            text = await resp.text()
            self.assertTrue(text, path)
            for secret in _SECRETS:
                self.assertNotIn(secret, text, "%s leaked a secret" % path)

    async def test_a_refused_request_does_not_return_a_secret(self):
        for resp in (await self.client.get("/status"),
                     await self.client.get(
                         "/status", headers={"X-Agent-Token": "wrong-token"})):
            text = await resp.text()
            for secret in _SECRETS:
                self.assertNotIn(secret, text)

    async def test_status_names_the_provider_never_the_key(self):
        text = await (await self.get("/status")).text()
        self.assertIn("anthropic", text)
        for secret in _SECRETS:
            self.assertNotIn(secret, text)


class TestNoSecretWhenTheProviderIsMisconfigured(_ServiceCase):
    """The reason is built from the provider's own error text."""

    async def get_application(self):
        self.rig = _rig(provider="no-such-provider")
        return self.rig.app

    async def test_neither_status_nor_the_503_carries_a_secret(self):
        for resp in (await self.get("/status"),
                     await self.post("/campaign", _form())):
            text = await resp.text()
            self.assertIn("no-such-provider", text)
            for secret in _SECRETS:
                self.assertNotIn(secret, text)


# ── Startup and shutdown ──


class TestStartup(unittest.IsolatedAsyncioTestCase):
    def _orphan(self, conn, **extra):
        record = {"beacons": ["raccoon-fox"], "restore_interval": 300}
        record.update(extra)
        return queries.create_run(conn, "campaign", None, "auto",
                                  json.dumps(record))

    async def test_startup_runs_orphan_recovery(self):
        conn, c2 = _env()
        rid = self._orphan(conn)
        await service.on_startup(_cfg(provider=None), conn, c2, _manager())
        self.assertEqual(c2.interval_calls[-1][1], 300)
        self.assertEqual(queries.get_run(conn, rid)["status"], "failed")

    async def test_startup_succeeds_without_a_reachable_c2(self):
        # With an orphan to restore: without one the C2 is never asked, and
        # the test would prove nothing about the C2 being down.
        conn, c2 = _env(c2_down=True)
        rid = self._orphan(conn)
        with unittest.mock.patch.object(orchestrator, "logger"):
            await service.on_startup(_cfg(provider=None), conn, c2, _manager())
        self.assertEqual(c2.interval_calls, [])
        self.assertEqual(queries.get_run(conn, rid)["status"], "failed")

    async def test_startup_survives_recovery_itself_failing(self):
        conn, c2 = _env()
        with unittest.mock.patch.object(
                service, "restore_orphans",
                side_effect=RuntimeError("boom")), \
                unittest.mock.patch.object(service, "logger") as log:
            await service.on_startup(_cfg(provider=None), conn, c2, _manager())
        log.warning.assert_called()
        self.assertIn("RuntimeError", str(log.warning.call_args))

    async def test_startup_survives_a_closed_database(self):
        conn, c2 = _env()
        conn.close()
        with unittest.mock.patch.object(service, "logger"):
            await service.on_startup(_cfg(provider=None), conn, c2, _manager())

    async def test_cancellation_is_not_swallowed(self):
        conn, c2 = _env()
        with unittest.mock.patch.object(
                service, "restore_orphans", side_effect=asyncio.CancelledError):
            with self.assertRaises(asyncio.CancelledError):
                await service.on_startup(_cfg(provider=None), conn, c2,
                                         _manager())

    async def test_the_app_runs_recovery_when_it_starts(self):
        rig = _rig(provider=None)
        self._orphan(rig.conn)
        rig.app.freeze()
        await rig.app.startup()
        try:
            self.assertEqual(rig.c2.interval_calls[-1][1], 300)
        finally:
            await rig.app.cleanup()


class TestShutdown(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        self.assertEqual(await _pending_tasks(), [])

    async def _run(self, rig, form=None):
        # Started first: restore_orphans, which the app runs at startup,
        # would take a campaign that is already running for a crashed one.
        rig.app.freeze()
        await rig.app.startup()
        camp = orchestrator.Campaign(
            rig.cfg, config.CampaignConfig.from_form(
                form or _form(), tier=rig.cfg.capability_tier),
            rig.conn, rig.c2, _slow_client())
        rig.manager.add(camp)
        await camp.start()
        return camp

    async def _shut_down(self, rig):
        await asyncio.sleep(0.05)
        await rig.app.cleanup()

    async def test_a_running_campaign_is_stopped_and_its_interval_restored(self):
        rig = _rig(client=None)
        camp = await self._run(rig)
        await self._shut_down(rig)
        self.assertEqual(
            queries.get_run(rig.conn, camp.run_id)["status"], "aborted")
        self.assertEqual(rig.c2.interval_calls[-1][1], 300)

    async def test_a_paused_campaign_is_left_to_be_resumed(self):
        # Pause is the one exit that keeps a run resumable; shutting the
        # service down must not turn it into an abort.
        rig = _rig(client=None)
        camp = await self._run(rig)
        camp.pause()
        await camp.wait()
        await self._shut_down(rig)
        self.assertEqual(
            queries.get_run(rig.conn, camp.run_id)["status"], "paused")
        camp.stop()
        await camp.wait()

    async def test_shutdown_with_the_c2_down_still_finishes(self):
        rig = _rig(client=None)
        camp = await self._run(rig)
        await asyncio.sleep(0.05)
        rig.c2.down = True
        with unittest.mock.patch.object(orchestrator, "logger"):
            await self._shut_down(rig)
        self.assertEqual(
            queries.get_run(rig.conn, camp.run_id)["status"], "aborted")



class TestABrowserCannotReachTheService(_ServiceCase):
    """The service listens on loopback, and the operator browses the web there.

    Without this, a page they visit can POST to the campaign endpoint and
    start a run: in loopback mode no token is needed, and a form-shaped POST
    needs no CORS preflight. Measured before the fix: an attacker Origin got
    200 and a rebound Host got 200.

    The three signals are all things no real caller produces. The C2's proxy
    uses urllib, which sends no Origin; an operator with curl sends none
    either.
    """

    async def get_application(self):
        self.rig = _rig(agent_token=None)
        return self.rig.app

    EVIL = "https://evil.example"

    async def test_an_origin_header_is_refused_on_a_read(self):
        resp = await self.client.get("/status", headers={"Origin": self.EVIL})
        self.assertEqual(resp.status, 403)
        self.assertIn("browser", (await resp.json())["error"])

    async def test_an_origin_header_is_refused_on_a_write(self):
        resp = await self.client.post("/campaign", json=_form(),
                                      headers={"Origin": self.EVIL})
        self.assertEqual(resp.status, 403)

    async def test_a_form_shaped_post_is_refused_even_without_an_origin(self):
        # The shapes a page can send with no preflight. Belt and braces: a
        # future browser that omits Origin would still be stopped here.
        for kind in ("text/plain", "application/x-www-form-urlencoded",
                     "multipart/form-data"):
            resp = await self.client.post("/campaign", data="{}",
                                          headers={"Content-Type": kind})
            self.assertEqual(resp.status, 415, kind)

    async def test_a_rebound_host_is_refused(self):
        # DNS rebinding: the attacker's name resolves to 127.0.0.1, so the
        # peer really is loopback and that check passes. The Host header is
        # what still carries their name.
        resp = await self.client.get("/status", headers={"Host": self.EVIL})
        self.assertEqual(resp.status, 403)
        self.assertIn("Host", (await resp.json())["error"])

    async def test_the_real_caller_still_works(self):
        self.assertEqual((await self.client.get("/status")).status, 200)
        self.assertIn((await self.client.post("/campaign", json=_form())).status,
                      (200, 503))

    async def test_an_unknown_route_is_also_covered(self):
        resp = await self.client.get("/nope", headers={"Origin": self.EVIL})
        self.assertEqual(resp.status, 403)


class TestWithATokenTheTokenIsTheAuthority(_ServiceCase):
    """The Host check is deliberately only for the no-token mode.

    With a token set, a browser page does not have it and gets 401, so
    rebinding buys nothing — while a deployment reaching the agent across a
    container network legitimately uses a Host this service cannot predict.
    Checking it there would break that for no gain.
    """

    TOKEN = "ZZ-not-a-real-token"

    async def get_application(self):
        self.rig = _rig(agent_token=self.TOKEN)
        return self.rig.app

    async def test_a_browser_is_still_refused(self):
        resp = await self.client.get(
            "/status", headers={"X-Agent-Token": self.TOKEN,
                                "Origin": "https://evil.example"})
        self.assertEqual(resp.status, 403)

    async def test_a_rebound_host_without_the_token_is_401(self):
        resp = await self.client.get("/status", headers={"Host": "evil.example"})
        self.assertEqual(resp.status, 401)

    async def test_an_unpredictable_host_with_the_token_is_accepted(self):
        resp = await self.client.get(
            "/status", headers={"X-Agent-Token": self.TOKEN,
                                "Host": "agent.internal:8099"})
        self.assertEqual(resp.status, 200)


class TestABeaconIsOfferedUnderTheIdThatWorks(_ServiceCase):
    """The C2 record carries two identifiers and only one is addressable.

    `agent_id` ("raccoon-bandit") is what /api/agents/<id>/task reaches;
    `id` is the raw beacon hash. The form offered the hash, so a campaign
    started from it failed on its first dispatch with "beacon ... is not
    known to the C2". Found by running it: every test here faked a C2 whose
    two ids were the same string, which is exactly why none of them caught
    it.
    """

    REAL = {"agent_id": "raccoon-bandit", "id": "3948e54c95459fd4",
            "hostname": "box.local", "os": "Darwin", "arch": "arm64",
            "user": "u", "status": "online", "interval": 3,
            "uplink_iface": None, "caps": ["batch", "dropbox"]}

    async def get_application(self):
        self.rig = _rig()
        # Keyed the way the real C2 keys it: by the addressable name, with
        # the raw hash sitting in the record under `id`.
        self.rig.c2.agents.clear()
        self.rig.c2.agents["raccoon-bandit"] = dict(self.REAL)
        return self.rig.app

    async def test_the_offered_id_is_the_addressable_one(self):
        body = await (await self.get("/beacons")).json()
        self.assertEqual(body["beacons"][0]["id"], "raccoon-bandit")

    async def test_the_raw_beacon_hash_is_still_reported_separately(self):
        body = await (await self.get("/beacons")).json()
        self.assertEqual(body["beacons"][0]["beacon_id"], "3948e54c95459fd4")

    async def test_a_record_with_only_one_id_still_works(self):
        # An older C2, or a record restored from a state file.
        self.rig.c2.agents.clear()
        self.rig.c2.agents["only-this"] = {"id": "only-this", "caps": []}
        body = await (await self.get("/beacons")).json()
        self.assertEqual(body["beacons"][0]["id"], "only-this")


class TestTheStatusNamesTheFallbackChain(_ServiceCase):
    """A chain nobody can see is a chain nobody trusts.

    The GUI's model line shows one provider. With a chain configured, an
    operator has no way to tell that a second one exists, which it will
    switch to, or that the primary is currently cooling down -- and the
    moment that matters is the moment a campaign is running on the
    fallback and the token counts are filed under a different model than
    the form shows.
    """

    LINKS = ()

    async def get_application(self):
        return _rig(fallbacks=self.LINKS).app

    async def test_no_chain_reports_an_empty_list(self):
        body = await (await self.get("/status")).json()
        self.assertEqual(body.get("fallbacks"), [])


class TestEachFallbackLinkIsNamed(_ServiceCase):
    async def get_application(self):
        return _rig(fallbacks=(
            config.FallbackLink(provider="local", model="qwen",
                                base_url="http://127.0.0.1:11434/v1"),)).app

    async def test_each_link_is_named_in_order(self):
        body = await (await self.get("/status")).json()
        self.assertEqual([f["provider"] for f in body["fallbacks"]], ["local"])
        self.assertEqual(body["fallbacks"][0]["model"], "qwen")


class TestAFallbackKeyNeverReachesTheResponse(_ServiceCase):
    """/status is reachable by anything holding the operator token."""

    async def get_application(self):
        return _rig(fallbacks=(
            config.FallbackLink(provider="anthropic", model="claude",
                                api_key="sk-fallback-secret"),)).app

    async def test_no_key_and_no_key_field(self):
        body = await (await self.get("/status")).json()
        self.assertNotIn("sk-fallback-secret", json.dumps(body))
        self.assertNotIn("api_key", json.dumps(body["fallbacks"]))


class TestTheReportIsServedAsMarkdown(_ServiceCase):
    """The deliverable has to leave the machine somehow.

    Markdown as text rather than inside a JSON string: an operator saves
    it, pastes it into a ticket, or commits it next to the engagement
    notes, and a JSON envelope makes all three worse.
    """

    async def get_application(self):
        self.rig = _rig()
        return self.rig.app

    async def test_a_run_produces_a_report(self):
        rid = queries.create_run(self.rig.conn, "campaign", None, "auto", "{}")
        resp = await self.get("/campaign/%d/report" % rid)
        self.assertEqual(resp.status, 200)
        body = await resp.text()
        self.assertIn("# Campaign report", body)

    async def test_it_is_served_as_text_not_json(self):
        rid = queries.create_run(self.rig.conn, "campaign", None, "auto", "{}")
        resp = await self.get("/campaign/%d/report" % rid)
        self.assertIn("markdown", resp.headers.get("Content-Type", ""))

    async def test_it_offers_a_filename_so_a_browser_saves_it(self):
        rid = queries.create_run(self.rig.conn, "campaign", None, "auto", "{}")
        resp = await self.get("/campaign/%d/report" % rid)
        disposition = resp.headers.get("Content-Disposition", "")
        self.assertIn("attachment", disposition)
        self.assertIn(str(rid), disposition)

    async def test_an_unknown_run_is_a_404_not_an_empty_report(self):
        # An empty report for a run that never existed would be filed as
        # evidence that a campaign found nothing.
        resp = await self.get("/campaign/9999/report")
        self.assertEqual(resp.status, 404)

    async def test_the_findings_reach_the_report(self):
        rid = queries.create_run(self.rig.conn, "campaign", None, "auto", "{}")
        queries.log_finding(self.rig.conn, rid, "10.0.1.5", "service",
                            "vsftpd 2.3.4", "executor",
                            evidence="2121/tcp open ftp",
                            proof_basis="executed-live")
        body = await (await self.get("/campaign/%d/report" % rid)).text()
        self.assertIn("vsftpd 2.3.4", body)
        self.assertIn("executed-live", body)
        self.assertIn("2121/tcp open ftp", body)


class TestFinishedRunsAreStillListed(_ServiceCase):
    """Found by trying to screenshot the report button.

    /status listed only unfinished campaigns, which is right for the
    manager's own view: a finished run has nothing to pause or stop. But
    the report button hangs off that list, so the deliverable was
    unreachable for exactly the runs that have one -- a finished campaign
    is precisely when an operator wants it.
    """

    async def get_application(self):
        self.rig = _rig()
        return self.rig.app

    async def test_a_completed_run_appears(self):
        rid = queries.create_run(self.rig.conn, "campaign", None, "auto", "{}")
        queries.set_run_status(self.rig.conn, rid, "completed")
        body = await (await self.get("/status")).json()
        ids = [r["run_id"] for r in body.get("recent", [])]
        self.assertIn(rid, ids)

    async def test_it_carries_its_status_so_the_gui_can_say_so(self):
        rid = queries.create_run(self.rig.conn, "campaign", None, "auto", "{}")
        queries.set_run_status(self.rig.conn, rid, "aborted")
        body = await (await self.get("/status")).json()
        row = [r for r in body["recent"] if r["run_id"] == rid][0]
        self.assertEqual(row["status"], "aborted")

    async def test_an_unfinished_run_is_not_in_both_lists(self):
        # It would render twice in the panel, with two Report buttons.
        rid = queries.create_run(self.rig.conn, "campaign", None, "auto", "{}")
        body = await (await self.get("/status")).json()
        recent = [r["run_id"] for r in body.get("recent", [])]
        self.assertNotIn(rid, recent)

    async def test_the_list_is_bounded(self):
        for _ in range(40):
            rid = queries.create_run(self.rig.conn, "campaign", None, "auto",
                                     "{}")
            queries.set_run_status(self.rig.conn, rid, "completed")
        body = await (await self.get("/status")).json()
        self.assertLessEqual(len(body["recent"]), 10)

    async def test_the_newest_come_first(self):
        ids = []
        for _ in range(3):
            rid = queries.create_run(self.rig.conn, "campaign", None, "auto",
                                     "{}")
            queries.set_run_status(self.rig.conn, rid, "completed")
            ids.append(rid)
        body = await (await self.get("/status")).json()
        listed = [r["run_id"] for r in body["recent"]]
        self.assertEqual(listed[0], ids[-1])

if __name__ == "__main__":
    unittest.main()
