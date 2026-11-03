#!/usr/bin/env python3
"""
Tests for the tool surfaces the model is given. Nothing here reaches the
network, a subprocess or a real C2: the router is a stub that records what it
was asked, the CVE sources and searchsploit are replaced at the one seam each
module exposes for them, and the clock the NVD limiter reads is a fake.

Two things carry most of the weight. The surfaces are asymmetric on purpose —
an executor cannot dispatch or score, the orchestrator cannot run a command —
and the tools are only a surface: whatever the router refuses stays refused,
and the exceptions that end a campaign pass through the tool unswallowed.
"""

import contextlib
import inspect
import json
import sys
import unittest
from pathlib import Path
from unittest import IsolatedAsyncioTestCase, mock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent import gate, safety
from software.agent.executor import ActionResult, blocked
from software.agent.llm import provider
from software.agent.store import db, queries
from software.agent.tools import Entry, memory, registry, scoring, vuln


# ── Fixtures ──


def _conn():
    return db.open_store(":memory:")


def _run(conn):
    return queries.create_run(conn, "operator", "{}", "supervised", "{}")


async def _noop(*args, **kwargs):
    return {}


def _scope(*allow):
    return memory.scope_key(list(allow) or ["10.0.1.0/24"])


class _RouterStub:
    """Records every call, answers with a canned result or raises."""

    def __init__(self, blocks=False, raises=None):
        self.blocks = blocks
        self.raises = raises
        self.calls = []

    async def run_command(self, command, **kwargs):
        self.calls.append((command, kwargs))
        if self.raises is not None:
            raise self.raises
        if self.blocks:
            return blocked("scope: refused")
        path = "server" if kwargs.get("server_side") else "beacon"
        return ActionResult(True, "ran " + command, 0, False, path)


def _router_stub(blocks=False, raises=None):
    return _RouterStub(blocks=blocks, raises=raises)


def _executor(router=None, conn=None, run_id=1, caps=("batch",), tier="full",
              scope_key=None):
    return registry.executor_tools(
        router or _router_stub(), conn or _conn(), run_id, caps=list(caps),
        tier=tier, scope_key=scope_key or _scope())


def _orchestrator(conn=None, run_id=1, dispatch_single=_noop,
                  dispatch_parallel=_noop, tier="full"):
    return registry.orchestrator_tools(
        conn or _conn(), run_id, dispatch_single=dispatch_single,
        dispatch_parallel=dispatch_parallel, tier=tier, scope_key=_scope())


def _names(tools):
    return [t.spec.name for t in tools]


async def _call(tools, tool_name, /, **kwargs):
    tool = next(t for t in tools if t.spec.name == tool_name)
    return await tool.fn(**kwargs)


def _iso_days_ago(days):
    from datetime import datetime, timedelta, timezone
    return queries._iso(datetime.now(timezone.utc) - timedelta(days=days))


# ── CVE sources ──


def _cve(cve_id, score, summary="a vulnerability"):
    """An OSV record. The score rides along under a private key for the fake
    NVD to answer with: real OSV gives a vector, never a base score."""
    return {"id": cve_id, "aliases": [], "summary": summary,
            "published": "2021-12-10T00:00:00Z",
            "severity": [{"type": "CVSS_V3",
                          "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
            "references": [{"type": "WEB", "url": "https://example.test/" + cve_id}],
            "_score": score}


def _nvd_item(cve_id, score):
    return {"cve": {
        "id": cve_id, "published": "2021-12-10T00:00:00Z",
        "descriptions": [{"lang": "en", "value": "from nvd"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "baseScore": score,
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
        "references": [{"url": "https://nvd.example.test/" + cve_id}]}}


class _Calls(list):
    """The OSV queries made; `.nvd` holds the NVD parameter sets."""

    def __init__(self):
        super().__init__()
        self.nvd = []
        self.sleeps = []


class _FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@contextlib.contextmanager
def _fake_osv(hits=(), unreachable=False, nvd_unreachable=None,
              nvd_items=None, osv_payload=None, osv_raises=None,
              nvd_raises=None):
    """Replace both CVE sources and the NVD limiter's clock and sleep.

    OSV answers `hits`. NVD answers a `cveId` query with the score the hit
    carries, and a CPE query with `nvd_items`.
    """
    calls = _Calls()
    clock = _FakeClock()
    by_id = {}
    for h in hits:
        for name in [h["id"]] + list(h.get("aliases") or []):
            by_id[name] = h.get("_score")
    down = unreachable if nvd_unreachable is None else nvd_unreachable

    def osv(body):
        calls.append(body)
        if osv_raises is not None:
            raise osv_raises
        if unreachable:
            raise provider.TransportError("request failed (ConnectionError)")
        if osv_payload is not None:
            return osv_payload
        return {"vulns": list(hits)} if hits else {}

    def nvd(params):
        calls.nvd.append(params)
        if nvd_raises is not None:
            raise nvd_raises
        if down:
            raise provider.TransportError("request failed (ConnectionError)")
        if "cveId" in params:
            score = by_id.get(params["cveId"])
            items = [_nvd_item(params["cveId"], score)] if score else []
            return {"vulnerabilities": items}
        return {"vulnerabilities": list(nvd_items or [])}

    async def sleep(seconds):
        calls.sleeps.append(seconds)
        clock.now += seconds

    with mock.patch.object(vuln, "_osv_query", osv), \
            mock.patch.object(vuln, "_nvd_query", nvd), \
            mock.patch.object(vuln, "_clock", clock), \
            mock.patch.object(vuln, "_sleep", sleep), \
            mock.patch.object(vuln, "_next_nvd_slot", 0.0):
        yield calls


@contextlib.contextmanager
def _no_searchsploit():
    async def missing(arg):
        raise FileNotFoundError("searchsploit")
    with mock.patch.object(vuln, "_run_searchsploit", missing):
        yield


@contextlib.contextmanager
def _fake_searchsploit(results=(), returncode=0, stdout=None):
    calls = []

    async def run(arg):
        calls.append(arg)
        out = stdout if stdout is not None else json.dumps(
            {"SEARCH": arg, "RESULTS_EXPLOIT": list(results),
             "RESULTS_SHELLCODE": []})
        return returncode, out
    with mock.patch.object(vuln, "_run_searchsploit", run):
        yield calls


# ── Surfaces ──


class TestToolSurfaces(unittest.TestCase):
    def test_executor_has_no_dispatch_tools(self):
        names = _names(_executor())
        self.assertNotIn("dispatch_task", names)
        self.assertNotIn("dispatch_parallel_tasks", names)

    def test_executor_has_no_scoring_tools(self):
        names = _names(_executor())
        self.assertNotIn("log_score", names)
        self.assertNotIn("get_score_context", names)

    def test_orchestrator_has_no_run_command(self):
        self.assertNotIn("run_command", _names(_orchestrator()))

    def test_orchestrator_surface_matches_the_spec_count(self):
        # Spec §14 names eleven, and the count is pinned against that list
        # rather than against whatever the catalogue happens to hold.
        self.assertEqual(sorted(_names(_orchestrator())), sorted([
            "dispatch_task", "dispatch_parallel_tasks", "set_phase",
            "remember_finding", "recall_findings", "get_run_summary",
            "log_score", "get_score_context", "save_script",
            "search_scripts", "run_script"]))

    def test_executor_full_surface_matches_the_spec(self):
        self.assertEqual(sorted(_names(_executor())), sorted([
            "run_command", "log_discovery", "save_script", "search_scripts",
            "run_script", "check_exploit", "lookup_cve", "save_memory",
            "search_memory"]))

    def test_wire_tool_absent_without_sniffer_cap(self):
        self.assertNotIn("get_wire_intel", _names(_executor(caps=["batch"])))

    def test_reduced_tier_offers_fewer_tools_than_full(self):
        full = _names(_executor(tier="full"))
        red = _names(_executor(tier="reduced"))
        mini = _names(_executor(tier="minimal"))
        self.assertLess(len(red), len(full))
        self.assertLess(len(mini), len(red))
        self.assertIn("run_command", mini)
        self.assertIn("log_discovery", mini)

    def test_minimal_executor_is_exactly_the_two_spec_tools(self):
        self.assertEqual(sorted(_names(_executor(tier="minimal"))),
                         ["log_discovery", "run_command"])

    def test_every_tier_is_a_subset_of_the_stronger_one(self):
        for role in ("executor", "orchestrator"):
            sets = [set(s.name for s in registry.specs(role, ["batch"], t))
                    for t in ("minimal", "reduced", "full")]
            self.assertLessEqual(sets[0], sets[1], role)
            self.assertLessEqual(sets[1], sets[2], role)

    def test_every_orchestrator_tier_can_still_dispatch(self):
        for tier in provider.TIER_LIMITS:
            self.assertIn("dispatch_task", _names(_orchestrator(tier=tier)), tier)

    def test_every_tool_spec_has_a_description_and_schema(self):
        for t in _executor() + _orchestrator():
            self.assertTrue(t.spec.description.strip(), t.spec.name)
            self.assertEqual(t.spec.parameters["type"], "object")

    def test_every_schema_property_is_an_argument_of_the_function(self):
        # The loop binds the model's arguments to the signature before the
        # call; a property the function does not take would fail every time
        # the model used it.
        for t in _executor() + _orchestrator():
            params = inspect.signature(t.fn).parameters
            props = t.spec.parameters.get("properties", {})
            required = t.spec.parameters.get("required", [])
            for name in props:
                self.assertIn(name, params, "%s.%s" % (t.spec.name, name))
            for name in required:
                self.assertIn(name, props, t.spec.name)
                self.assertIs(params[name].default, inspect.Parameter.empty,
                              "%s.%s" % (t.spec.name, name))
            for name, p in params.items():
                if p.default is inspect.Parameter.empty:
                    self.assertIn(name, required, "%s.%s" % (t.spec.name, name))

    def test_tool_names_are_unique_within_a_surface(self):
        for tools in (_executor(), _orchestrator()):
            self.assertEqual(len(_names(tools)), len(set(_names(tools))))

    def test_unknown_tier_is_an_error_not_a_default(self):
        with self.assertRaises(ValueError):
            _executor(tier="enormous")


class TestCapabilityFilter(unittest.TestCase):
    """The filter works off what each entry declares, so a tool this task
    does not define is admitted the moment someone declares it."""

    @staticmethod
    def _entry(name, requires, levels=("all",)):
        spec = provider.ToolSpec(name, "Test tool. Nothing else.",
                                 {"type": "object", "properties": {}})
        return Entry(spec=spec, roles=("executor",), levels=levels,
                     build=lambda ctx: _noop, requires_caps=tuple(requires))

    def test_a_declared_tool_is_admitted_with_its_capability(self):
        extra = self._entry("get_wire_intel", ["sniffer"])
        with mock.patch.object(registry, "_CATALOGUE",
                               registry._CATALOGUE + [extra]):
            self.assertIn("get_wire_intel",
                          _names(_executor(caps=["batch", "sniffer"])))

    def test_a_declared_tool_is_withheld_without_its_capability(self):
        extra = self._entry("get_wire_intel", ["sniffer"])
        with mock.patch.object(registry, "_CATALOGUE",
                               registry._CATALOGUE + [extra]):
            self.assertNotIn("get_wire_intel", _names(_executor(caps=["batch"])))

    def test_every_required_capability_is_needed(self):
        extra = self._entry("run_airodump", ["wifi:scan", "wifi:monitor"])
        with mock.patch.object(registry, "_CATALOGUE",
                               registry._CATALOGUE + [extra]):
            self.assertNotIn("run_airodump",
                             _names(_executor(caps=["wifi:scan"])))
            self.assertIn("run_airodump", _names(
                _executor(caps=["wifi:scan", "wifi:monitor"])))

    def test_capability_is_checked_before_tier(self):
        # Present at every level but missing its capability: still absent.
        extra = self._entry("get_wire_intel", ["sniffer"],
                            levels=("bare", "core", "all"))
        with mock.patch.object(registry, "_CATALOGUE",
                               registry._CATALOGUE + [extra]):
            for tier in provider.TIER_LIMITS:
                self.assertNotIn("get_wire_intel",
                                 _names(_executor(caps=["batch"], tier=tier)))

    def test_tier_still_applies_to_an_admitted_tool(self):
        extra = self._entry("get_wire_intel", ["sniffer"], levels=("all",))
        with mock.patch.object(registry, "_CATALOGUE",
                               registry._CATALOGUE + [extra]):
            self.assertNotIn("get_wire_intel", _names(
                _executor(caps=["sniffer"], tier="minimal")))
            self.assertIn("get_wire_intel", _names(
                _executor(caps=["sniffer"], tier="full")))

    def test_no_shipped_tool_requires_a_capability_that_does_not_exist_yet(self):
        # The wire and wifi tools belong to later sub-projects. If one of
        # them were declared here its test would be absent-by-accident.
        for entry in registry._CATALOGUE:
            self.assertEqual(entry.requires_caps, (), entry.spec.name)


# ── Behaviour ──


class TestToolBehaviour(IsolatedAsyncioTestCase):
    async def test_run_command_returns_success_false_on_block(self):
        tools = _executor(_router_stub(blocks=True))
        out = await _call(tools, "run_command", command="kill",
                          beacon_id="raccoon-fox")
        self.assertFalse(out["success"])
        self.assertIn("refused", out["blocked_reason"])

    async def test_run_command_passes_the_estimate_as_the_override(self):
        router = _router_stub()
        tools = _executor(router)
        await _call(tools, "run_command", command="whoami",
                    beacon_id="raccoon-fox", p_success_estimate=0.7)
        command, kwargs = router.calls[0]
        self.assertEqual(kwargs["p_success_override"], 0.7)
        self.assertEqual(kwargs["beacon_id"], "raccoon-fox")

    async def test_run_command_without_an_estimate_passes_none(self):
        router = _router_stub()
        await _call(_executor(router), "run_command", command="whoami",
                    server_side=True, timeout=30)
        _, kwargs = router.calls[0]
        self.assertIsNone(kwargs["p_success_override"])
        self.assertTrue(kwargs["server_side"])
        self.assertEqual(kwargs["timeout"], 30)

    async def test_the_estimate_is_the_only_input_to_the_ev_calculation(self):
        # A second path would be a second thing to clamp. The tool's whole
        # schema is the evidence: no other property can carry a probability.
        spec = next(t.spec for t in _executor() if t.spec.name == "run_command")
        props = set(spec.parameters["properties"])
        self.assertEqual(props, {"command", "beacon_id", "server_side",
                                 "timeout", "p_success_estimate"})
        for other in _executor():
            if other.spec.name != "run_command":
                self.assertFalse(
                    {"p_success", "p_detect", "ev", "risk"} &
                    set(other.spec.parameters.get("properties", {})),
                    other.spec.name)

    async def test_the_tool_does_not_swallow_the_exceptions_that_end_a_campaign(self):
        tools = _executor(_router_stub(raises=gate.GatePauseRequested("pause")))
        with self.assertRaises(gate.GatePauseRequested):
            await _call(tools, "run_command", command="whoami", server_side=True)

    async def test_router_abort_passes_through_the_tool(self):
        from software.agent.executor.router import RouterAborted
        tools = _executor(_router_stub(raises=RouterAborted("budget")))
        with self.assertRaises(RouterAborted):
            await _call(tools, "run_command", command="whoami",
                        server_side=True)

    async def test_log_discovery_records_a_finding_for_the_run(self):
        conn = _conn(); rid = _run(conn)
        tools = _executor(conn=conn, run_id=rid)
        out = await _call(tools, "log_discovery", host="10.0.1.5",
                          finding_type="service", data='{"port": 445}')
        self.assertTrue(out["logged"])
        rows = queries.get_findings_by_host(conn, "10.0.1.5")
        self.assertEqual(rows[0]["run_id"], rid)
        self.assertEqual(rows[0]["source"], "executor")

    async def test_log_discovery_accepts_a_structured_payload(self):
        conn = _conn(); rid = _run(conn)
        tools = _executor(conn=conn, run_id=rid)
        await _call(tools, "log_discovery", host="dc01", finding_type="host",
                    data={"ip": "10.0.1.5"})
        data = queries.get_findings_by_host(conn, "dc01")[0]["data"]
        self.assertEqual(json.loads(data), {"ip": "10.0.1.5"})

    async def test_log_discovery_without_a_host_cannot_name_a_target(self):
        conn = _conn(); rid = _run(conn)
        tools = _executor(conn=conn, run_id=rid)
        await _call(tools, "log_discovery", finding_type="credential",
                    data="x")
        host = conn.execute("SELECT host FROM findings").fetchone()["host"]
        self.assertTrue(safety.has_shell_metachars(host))

    async def test_log_score_rejects_unknown_action_and_lists_valid_ones(self):
        conn = _conn(); rid = _run(conn)
        tools = _orchestrator(conn, rid)
        out = await _call(tools, "log_score", action="hack_the_planet")
        self.assertIn("error", out)
        self.assertIn("host_discovered", str(out))
        self.assertEqual(sorted(out["valid_actions"]),
                         sorted(scoring.SCORE_ACTIONS))
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM score_events").fetchone()[0], 0)

    async def test_log_score_awards_the_spec_point_value(self):
        conn = _conn(); rid = _run(conn)
        tools = _orchestrator(conn, rid)
        self.assertEqual((await _call(tools, "log_score",
                                      action="rce_achieved"))["points"], 200)
        self.assertEqual((await _call(tools, "log_score",
                                      action="detection"))["points"], -100)

    async def test_a_reported_detection_tightens_the_gate(self):
        # Spec §10.6 source 2. The gate reads detections from score_events,
        # so the row has to be flagged or the report changes nothing.
        conn = _conn(); rid = _run(conn)
        tools = _orchestrator(conn, rid)
        await _call(tools, "log_score", action="detection")
        await _call(tools, "log_score", action="host_discovered")
        self.assertEqual(
            queries.get_score_context(conn, rid)["detection_count"], 1)

    async def test_wifi_score_actions_are_accepted(self):
        conn = _conn(); rid = _run(conn)
        tools = _orchestrator(conn, rid)
        for action, pts in (("ap_discovered", 5), ("handshake_captured", 30),
                            ("pmkid_captured", 30), ("wps_pin_found", 50),
                            ("psk_cracked", 75)):
            self.assertEqual((await _call(tools, "log_score", action=action))["points"],
                             pts)

    async def test_set_phase_persists_and_rejects_out_of_range(self):
        conn = _conn(); rid = _run(conn)
        tools = _orchestrator(conn, rid)
        await _call(tools, "set_phase", phase=3)
        self.assertEqual(queries.get_run(conn, rid)["phase"], 3)
        self.assertIn("error", await _call(tools, "set_phase", phase=99))
        self.assertIn("error", await _call(tools, "set_phase", phase=0))
        self.assertIn("error", await _call(tools, "set_phase", phase=True))
        self.assertIn("error", await _call(tools, "set_phase", phase="three"))
        self.assertEqual(queries.get_run(conn, rid)["phase"], 3)

    async def test_get_score_context_and_run_summary_read_the_store(self):
        conn = _conn(); rid = _run(conn)
        tools = _orchestrator(conn, rid)
        await _call(tools, "log_score", action="host_discovered")
        self.assertEqual((await _call(tools, "get_score_context"))["total_score"], 10)
        self.assertEqual((await _call(tools, "get_run_summary"))["total_score"], 10)

    async def test_run_script_validates_before_executing(self):
        conn = _conn()
        queries.save_script(conn, "bad", "rm -rf /opt/raccoon", "bash", "d", "[]")
        router = _router_stub()
        out = await _call(_executor(router, conn), "run_script", name="bad")
        self.assertFalse(out["success"])
        self.assertEqual(router.calls, [])

    async def test_run_script_sends_every_line_through_the_router(self):
        conn = _conn()
        queries.save_script(conn, "recon", "# header\nwhoami\n\nid\n", "bash",
                            "d", "[]")
        router = _router_stub()
        out = await _call(_executor(router, conn), "run_script", name="recon",
                          beacon_id="raccoon-fox", timeout=20)
        self.assertTrue(out["success"])
        self.assertEqual([c for c, _ in router.calls], ["whoami", "id"])
        self.assertEqual(router.calls[0][1]["beacon_id"], "raccoon-fox")
        self.assertFalse(router.calls[0][1]["server_side"])
        self.assertEqual(router.calls[0][1]["timeout"], 20)

    async def test_run_script_defaults_to_the_server_without_a_beacon(self):
        conn = _conn()
        queries.save_script(conn, "one", "whoami", "bash", "d", "[]")
        router = _router_stub()
        await _call(_executor(router, conn), "run_script", name="one")
        self.assertTrue(router.calls[0][1]["server_side"])
        self.assertIsNone(router.calls[0][1]["beacon_id"])

    async def test_run_script_stops_at_the_first_refused_line(self):
        conn = _conn()
        queries.save_script(conn, "two", "whoami\nid", "bash", "d", "[]")
        router = _router_stub(blocks=True)
        out = await _call(_executor(router, conn), "run_script", name="two")
        self.assertFalse(out["success"])
        self.assertEqual(len(router.calls), 1)
        self.assertEqual(out["failed_line"], 1)

    async def test_run_script_unknown_name_is_an_error(self):
        out = await _call(_executor(), "run_script", name="nope")
        self.assertFalse(out["success"])
        self.assertIn("error", out)

    async def test_a_stored_python_script_is_not_run_line_by_line(self):
        conn = _conn()
        queries.save_script(conn, "py", "print(1)", "python", "d", "[]")
        router = _router_stub()
        out = await _call(_executor(router, conn), "run_script", name="py")
        self.assertFalse(out["success"])
        self.assertEqual(router.calls, [])

    async def test_orchestrator_run_script_delegates_to_an_executor(self):
        conn = _conn()
        queries.save_script(conn, "recon", "whoami", "bash", "d", "[]")
        sent = []

        async def single(name, description):
            sent.append((name, description))
            return {"dispatched": True}
        tools = _orchestrator(conn, dispatch_single=single)
        out = await _call(tools, "run_script", name="recon")
        self.assertEqual(out, {"dispatched": True})
        self.assertIn("recon", sent[0][1])

    async def test_orchestrator_run_script_validates_before_dispatching(self):
        conn = _conn()
        queries.save_script(conn, "bad", "rm -rf /opt/raccoon", "bash", "d", "[]")
        sent = []

        async def single(name, description):
            sent.append(name)
        out = await _call(_orchestrator(conn, dispatch_single=single),
                          "run_script", name="bad")
        self.assertIn("error", out)
        self.assertEqual(sent, [])

    async def test_save_script_refuses_blocked_code(self):
        conn = _conn()
        out = await _call(_executor(conn=conn), "save_script", name="x",
                          code="rm -rf /", language="bash", description="d")
        self.assertIn("error", out)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM scripts").fetchone()[0], 0)

    async def test_save_script_stores_clean_code_and_search_finds_it(self):
        conn = _conn()
        tools = _executor(conn=conn)
        out = await _call(tools, "save_script", name="who", code="whoami",
                          language="bash", description="print the user",
                          tags=["recon"])
        self.assertTrue(out["saved"])
        found = await _call(tools, "search_scripts", query="user")
        self.assertEqual(found["scripts"][0]["name"], "who")

    async def test_save_script_refuses_a_language_it_cannot_run(self):
        conn = _conn()
        out = await _call(_executor(conn=conn), "save_script", name="p",
                          code="print(1)", language="python", description="d")
        self.assertIn("error", out)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM scripts").fetchone()[0], 0)

    async def test_recall_findings_returns_count_and_entries(self):
        conn = _conn(); rid = _run(conn)
        queries.log_finding(conn, rid, "10.0.1.5", "service", "SMB 3.1.1", "exec")
        tools = _orchestrator(conn, rid)
        out = await _call(tools, "recall_findings", host="10.0.1.5")
        self.assertEqual(out["count"], 1)
        self.assertEqual(out["findings"][0]["finding_type"], "service")

    async def test_recall_findings_does_not_cross_into_another_run(self):
        # Two clients both have a 10.0.1.5.
        conn = _conn(); first = _run(conn); second = _run(conn)
        queries.log_finding(conn, first, "10.0.1.5", "service", "old client", "x")
        out = await _call(_orchestrator(conn, second), "recall_findings",
                          host="10.0.1.5")
        self.assertEqual(out["count"], 0)

    async def test_remember_finding_is_attributed_to_the_orchestrator(self):
        conn = _conn(); rid = _run(conn)
        await _call(_orchestrator(conn, rid), "remember_finding",
                    host="10.0.1.5", finding_type="note", data="x")
        self.assertEqual(
            queries.get_findings_by_host(conn, "10.0.1.5")[0]["source"],
            "orchestrator")

    async def test_dispatch_tools_hand_over_and_validate(self):
        seen = {}

        async def single(name, description):
            seen["single"] = (name, description)
            return "one"

        async def parallel(tasks):
            seen["parallel"] = tasks
            return "many"
        tools = _orchestrator(dispatch_single=single, dispatch_parallel=parallel)
        self.assertEqual(await _call(tools, "dispatch_task", task_name="scan",
                                     task_description="scan 10.0.1.5"), "one")
        self.assertEqual(seen["single"], ("scan", "scan 10.0.1.5"))
        out = await _call(tools, "dispatch_parallel_tasks", tasks=[
            {"name": "a", "description": "x"}, {"name": "b", "description": "y"}])
        self.assertEqual(out, "many")
        self.assertEqual(len(seen["parallel"]), 2)
        for bad in ([], "x", [{"name": "a"}], [{"name": "", "description": "x"}],
                    [None]):
            self.assertIn("error", await _call(
                tools, "dispatch_parallel_tasks", tasks=bad), repr(bad))

    async def test_dispatch_task_rejects_a_blank_name_or_description(self):
        tools = _orchestrator()
        self.assertIn("error", await _call(tools, "dispatch_task",
                                           task_name=" ", task_description="x"))
        self.assertIn("error", await _call(tools, "dispatch_task",
                                           task_name="x", task_description=""))


# ── Scoring ──


class TestScoreTable(unittest.TestCase):
    # Spec §10.8, typed out here from the table rather than imported, so
    # the module cannot agree with itself while disagreeing with the spec.
    SPEC = {
        "host_discovered": 10, "port_found": 5, "service_identified": 15,
        "os_fingerprinted": 20, "vuln_detected": 25, "credential_captured": 50,
        "successful_login": 75, "privilege_escalation": 150,
        "rce_achieved": 200, "data_exfiltrated": 100, "detection": -100,
        "ap_discovered": 5, "handshake_captured": 30, "pmkid_captured": 30,
        "wps_pin_found": 50, "psk_cracked": 75,
    }

    def test_the_table_is_the_spec_table(self):
        self.assertEqual(scoring.SCORE_ACTIONS, self.SPEC)
        self.assertEqual(len(scoring.SCORE_ACTIONS), 16)


# ── Memory ──


class TestMemoryScope(IsolatedAsyncioTestCase):
    def test_scope_key_ignores_order_spelling_and_repeats(self):
        self.assertEqual(
            memory.scope_key(["10.0.9.0/24", "10.0.1.0/24"]),
            memory.scope_key(["10.0.1.0/24", " 10.0.9.0/24", "10.0.1.0/24"]))
        self.assertEqual(memory.scope_key(["10.0.1.5"]),
                         memory.scope_key(["10.0.1.5/32"]))

    def test_different_scopes_have_different_keys(self):
        self.assertNotEqual(memory.scope_key(["10.0.1.0/24"]),
                            memory.scope_key(["10.0.2.0/24"]))
        self.assertNotEqual(memory.scope_key(["10.0.1.0/24"]),
                            memory.scope_key(["10.0.1.0/24", "10.0.2.0/24"]))

    def test_an_empty_scope_has_no_key(self):
        with self.assertRaises(ValueError):
            memory.scope_key([])

    async def test_a_second_campaign_on_the_same_scope_finds_the_notes(self):
        conn = _conn()
        key = memory.scope_key(["10.0.1.0/24"])
        first = _executor(conn=conn, run_id=1, scope_key=key)
        await _call(first, "save_memory",
                    content="dc01 is the domain controller", sector="semantic")
        second = _executor(conn=conn, run_id=2,
                           scope_key=memory.scope_key(["10.0.1.0/24"]))
        out = await _call(second, "search_memory", query="domain controller")
        self.assertEqual(out["count"], 1)
        self.assertIn("dc01", out["memories"][0]["content"])

    async def test_a_campaign_on_another_scope_does_not_see_them(self):
        conn = _conn()
        first = _executor(conn=conn, run_id=1,
                          scope_key=memory.scope_key(["10.0.1.0/24"]))
        await _call(first, "save_memory",
                    content="dc01 is the domain controller")
        other = _executor(conn=conn, run_id=2,
                          scope_key=memory.scope_key(["192.168.7.0/24"]))
        out = await _call(other, "search_memory", query="domain controller")
        self.assertEqual(out["count"], 0)

    async def test_save_memory_rejects_a_sector_outside_the_schema(self):
        conn = _conn()
        out = await _call(_executor(conn=conn), "save_memory", content="x",
                          sector="folklore")
        self.assertIn("error", out)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0], 0)

    async def test_save_memory_defaults_to_semantic(self):
        conn = _conn()
        await _call(_executor(conn=conn), "save_memory", content="x y z")
        self.assertEqual(conn.execute("SELECT sector FROM memories").fetchone()[0],
                         "semantic")

    async def test_search_memory_limit_is_bounded(self):
        conn = _conn()
        tools = _executor(conn=conn)
        for i in range(30):
            await _call(tools, "save_memory", content="note number %d" % i)
        self.assertLessEqual(
            (await _call(tools, "search_memory", query="note", limit=1000))["count"],
            20)


# ── Vulnerability pipeline ──


class TestVulnLookup(IsolatedAsyncioTestCase):
    async def test_lookup_cve_caches_and_reuses(self):
        conn = _conn()
        tools = _executor(conn=conn)
        with _fake_osv(hits=[_cve("CVE-2021-44228", 10.0)]) as calls:
            first = await _call(tools, "lookup_cve", service="log4j", version="2.14.1")
            second = await _call(tools, "lookup_cve", service="log4j", version="2.14.1")
        self.assertEqual(first["cves"][0]["cve_id"], "CVE-2021-44228")
        self.assertEqual(second["cves"][0]["severity"], "CRITICAL")
        self.assertEqual(len(calls), 1, "the second call must come from the cache")
        self.assertTrue(second["cached"])

    async def test_cache_key_is_normalised(self):
        conn = _conn()
        tools = _executor(conn=conn)
        with _fake_osv(hits=[_cve("CVE-2021-44228", 10.0)]) as calls:
            await _call(tools, "lookup_cve", service="Log4J", version="2.14.1")
            await _call(tools, "lookup_cve", service=" log4j ", version="2.14.1")
        self.assertEqual(len(calls), 1)

    async def test_a_different_version_is_a_different_entry(self):
        conn = _conn()
        tools = _executor(conn=conn)
        with _fake_osv(hits=[_cve("CVE-2021-44228", 10.0)]) as calls:
            await _call(tools, "lookup_cve", service="log4j", version="2.14.1")
            await _call(tools, "lookup_cve", service="log4j", version="2.15.0")
        self.assertEqual(len(calls), 2)

    async def test_expired_cache_entry_is_refetched(self):
        conn = _conn()
        tools = _executor(conn=conn)
        with _fake_osv(hits=[_cve("CVE-2021-44228", 10.0)]):
            await _call(tools, "lookup_cve", service="log4j", version="2.14.1")
        conn.execute("UPDATE cve_cache SET fetched_at = ?", (_iso_days_ago(8),))
        with _fake_osv(hits=[_cve("CVE-2021-44228", 10.0)]) as calls:
            await _call(tools, "lookup_cve", service="log4j", version="2.14.1")
        self.assertEqual(len(calls), 1)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0], 1,
                         "a refetch replaces the stale rows rather than adding to them")

    async def test_a_six_day_old_entry_is_still_fresh(self):
        conn = _conn()
        tools = _executor(conn=conn)
        with _fake_osv(hits=[_cve("CVE-2021-44228", 10.0)]):
            await _call(tools, "lookup_cve", service="log4j", version="2.14.1")
        conn.execute("UPDATE cve_cache SET fetched_at = ?", (_iso_days_ago(6),))
        with _fake_osv(hits=[_cve("CVE-2021-44228", 10.0)]) as calls:
            await _call(tools, "lookup_cve", service="log4j", version="2.14.1")
        self.assertEqual(len(calls), 0)

    async def test_unreachable_cve_source_returns_a_warning_not_an_error(self):
        tools = _executor()
        with _fake_osv(unreachable=True):
            out = await _call(tools, "lookup_cve", service="log4j", version="2.14.1")
        self.assertEqual(out["cves"], [])
        self.assertIn("warning", out)
        self.assertNotIn("error", out)

    async def test_a_failed_lookup_is_not_cached(self):
        conn = _conn()
        tools = _executor(conn=conn)
        with _fake_osv(unreachable=True):
            await _call(tools, "lookup_cve", service="log4j", version="2.14.1")
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0], 0)

    async def test_osv_failure_still_tries_the_nvd_cpe_query(self):
        tools = _executor()
        items = [_nvd_item("CVE-2020-1", 7.5)]
        with _fake_osv(osv_raises=provider.TransportError("HTTP 500"),
                       nvd_unreachable=False, nvd_items=items) as calls:
            out = await _call(tools, "lookup_cve", service="openssh", version="8.2")
        self.assertEqual(out["cves"][0]["cve_id"], "CVE-2020-1")
        self.assertEqual(out["cves"][0]["severity"], "HIGH")
        self.assertIn("warning", out)
        self.assertIn("virtualMatchString", calls.nvd[0])

    async def test_osv_empty_falls_back_to_nvd_cpe(self):
        tools = _executor()
        with _fake_osv(hits=[], nvd_items=[_nvd_item("CVE-2020-2", 5.0)]) as calls:
            out = await _call(tools, "lookup_cve", service="openssh", version="8.2")
        self.assertEqual([c["cve_id"] for c in out["cves"]], ["CVE-2020-2"])
        self.assertEqual(out["cves"][0]["source"], "nvd")
        self.assertEqual(
            calls.nvd[0]["virtualMatchString"], "cpe:2.3:a:*:openssh:8.2:*:*:*:*:*:*:*")
        self.assertNotIn("warning", out)

    async def test_nvd_is_not_consulted_when_osv_answers_with_scores(self):
        tools = _executor()
        with _fake_osv(hits=[_cve("CVE-2021-44228", 10.0)]) as calls:
            await _call(tools, "lookup_cve", service="log4j", version="2.14.1")
        # One fill call for the missing score, and no CPE query.
        self.assertEqual([p.get("cveId") for p in calls.nvd], ["CVE-2021-44228"])

    async def test_nvd_fill_is_capped_at_five_calls(self):
        hits = [_cve("CVE-2020-%04d" % i, 5.0) for i in range(8)]
        with _fake_osv(hits=hits) as calls:
            out = await _call(_executor(), "lookup_cve", service="x", version="1")
        self.assertEqual(len(calls.nvd), 5)
        self.assertEqual(len(out["cves"]), 8)
        scored = [c for c in out["cves"] if c["cvss_score"] is not None]
        self.assertEqual(len(scored), 5)
        self.assertEqual(sum(1 for c in out["cves"] if c["severity"] == "UNKNOWN"), 3)

    async def test_nvd_calls_keep_a_minimum_gap(self):
        hits = [_cve("CVE-2020-000%d" % i, 5.0) for i in range(3)]
        with _fake_osv(hits=hits) as calls:
            await _call(_executor(), "lookup_cve", service="x", version="1")
        # The first call goes straight out; each later one waits out the gap.
        self.assertEqual(calls.sleeps, [vuln.NVD_MIN_GAP_SECONDS] * 2)

    async def test_an_nvd_outage_stops_the_fill_after_one_try(self):
        hits = [_cve("CVE-2020-000%d" % i, 5.0) for i in range(4)]
        with _fake_osv(hits=hits, nvd_unreachable=True) as calls:
            out = await _call(_executor(), "lookup_cve", service="x", version="1")
        self.assertEqual(len(calls.nvd), 1)
        self.assertEqual(len(out["cves"]), 4)
        self.assertIn("warning", out)

    async def test_non_cve_osv_records_are_resolved_through_their_aliases(self):
        record = _cve("GHSA-xxxx-yyyy-zzzz", 9.8)
        record["aliases"] = ["CVE-2022-0001"]
        other = _cve("OSV-2020-744", 5.0)
        with _fake_osv(hits=[record, other]) as calls:
            out = await _call(_executor(), "lookup_cve", service="x", version="1")
        self.assertEqual([c["cve_id"] for c in out["cves"]], ["CVE-2022-0001"])
        self.assertEqual(calls.nvd[0]["cveId"], "CVE-2022-0001")

    async def test_results_are_sorted_by_score_and_capped(self):
        hits = [_cve("CVE-2020-%04d" % i, 1.0 + i / 10.0) for i in range(5)]
        with _fake_osv(hits=hits):
            out = await _call(_executor(), "lookup_cve", service="x", version="1")
        scores = [c["cvss_score"] for c in out["cves"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    # ── No stage raises ──

    async def test_malformed_osv_payloads_do_not_raise(self):
        for payload in ([], "text", {"vulns": "nope"}, {"vulns": [None, 3]},
                        {"vulns": [{"id": None}]}, {"vulns": {"a": 1}}):
            with _fake_osv(osv_payload=payload, unreachable=False,
                           nvd_unreachable=True):
                out = await _call(_executor(), "lookup_cve", service="x", version="1")
            self.assertEqual(out["cves"], [], repr(payload))

    async def test_an_unexpected_exception_in_a_source_is_a_warning(self):
        with _fake_osv(osv_raises=RuntimeError("boom"), nvd_raises=ValueError("x")):
            out = await _call(_executor(), "lookup_cve", service="x", version="1")
        self.assertEqual(out["cves"], [])
        self.assertIn("warning", out)

    async def test_the_warning_names_the_class_and_not_the_message(self):
        with _fake_osv(osv_raises=RuntimeError("secret-token-123"),
                       nvd_raises=RuntimeError("secret-token-123")):
            out = await _call(_executor(), "lookup_cve", service="x", version="1")
        self.assertNotIn("secret-token-123", json.dumps(out))
        self.assertIn("RuntimeError", out["warning"])

    async def test_an_unusable_cache_is_a_warning_not_a_failure(self):
        conn = _conn()
        tools = _executor(conn=conn)
        conn.close()
        with _fake_osv(hits=[_cve("CVE-2021-44228", 10.0)]):
            out = await _call(tools, "lookup_cve", service="log4j", version="2.14.1")
        self.assertEqual(out["cves"][0]["cve_id"], "CVE-2021-44228")
        self.assertIn("warning", out)

    async def test_nvd_returning_garbage_for_the_fill_is_a_warning(self):
        def garbage(params):
            return {"vulnerabilities": "nope"}
        hit = _cve("CVE-2021-44228", 10.0)
        with _fake_osv(hits=[hit]):
            with mock.patch.object(vuln, "_nvd_query", garbage):
                out = await _call(_executor(), "lookup_cve", service="log4j",
                                  version="2.14.1")
        self.assertEqual(out["cves"][0]["cve_id"], "CVE-2021-44228")
        self.assertEqual(out["cves"][0]["severity"], "UNKNOWN")

    async def test_inputs_are_checked_before_anything_leaves_the_host(self):
        for service, version in (("", "1"), ("x", ""), ("a b;c", "1"),
                                 ("x", "1\n2"), ("x" * 200, "1"),
                                 ("x/../y", "1"), (None, "1"), ("x", 5)):
            with _fake_osv(hits=[_cve("CVE-2021-1", 5.0)]) as calls:
                out = await _call(_executor(), "lookup_cve", service=service,
                                  version=version)
            self.assertEqual(out["cves"], [], (service, version))
            self.assertIn("warning", out, (service, version))
            self.assertEqual((len(calls), len(calls.nvd)), (0, 0), (service, version))

    async def test_severity_follows_the_cvss_score(self):
        for score, expected in ((10.0, "CRITICAL"), (9.0, "CRITICAL"),
                                (8.9, "HIGH"), (7.0, "HIGH"), (6.9, "MEDIUM"),
                                (4.0, "MEDIUM"), (3.9, "LOW"), (0.1, "LOW"),
                                (0.0, "UNKNOWN"), (None, "UNKNOWN")):
            self.assertEqual(vuln.severity_for(score), expected, score)


class TestExploitCheck(IsolatedAsyncioTestCase):
    async def test_check_exploit_reports_missing_searchsploit_as_warning(self):
        tools = _executor()
        with _no_searchsploit():
            out = await _call(tools, "check_exploit", cve_id="CVE-2021-44228")
        self.assertFalse(out["has_exploit"])
        self.assertIn("searchsploit", out["warning"])

    async def test_check_exploit_accepts_both_cve_spellings(self):
        tools = _executor()
        with _fake_searchsploit(results=[{"Title": "x", "EDB-ID": "48745",
                                          "Type": "remote"}]) as calls:
            await _call(tools, "check_exploit", cve_id="CVE-2021-44228")
            await _call(tools, "check_exploit", cve_id="2021-44228")
        self.assertEqual(calls, ["2021-44228", "2021-44228"])

    async def test_output_is_parsed_even_when_searchsploit_exits_non_zero(self):
        result = {"Title": "Log4Shell RCE", "EDB-ID": "50592", "Type": "remote",
                  "Platform": "java"}
        with _fake_searchsploit(results=[result], returncode=2):
            out = await _call(_executor(), "check_exploit", cve_id="CVE-2021-44228")
        self.assertTrue(out["has_exploit"])
        self.assertEqual(out["exploits"][0]["edb_id"], "50592")
        self.assertEqual(out["exploits"][0]["title"], "Log4Shell RCE")

    async def test_no_results_is_a_clean_negative(self):
        with _fake_searchsploit(results=[]):
            out = await _call(_executor(), "check_exploit", cve_id="CVE-2021-44228")
        self.assertFalse(out["has_exploit"])
        self.assertNotIn("warning", out)

    async def test_unparseable_output_is_a_warning_naming_the_exit_code(self):
        with _fake_searchsploit(returncode=3, stdout="not json"):
            out = await _call(_executor(), "check_exploit", cve_id="CVE-2021-44228")
        self.assertFalse(out["has_exploit"])
        self.assertIn("3", out["warning"])

    async def test_an_unexpected_failure_to_run_is_a_warning(self):
        async def boom(arg):
            raise OSError("exec format error")
        with mock.patch.object(vuln, "_run_searchsploit", boom):
            out = await _call(_executor(), "check_exploit", cve_id="CVE-2021-44228")
        self.assertFalse(out["has_exploit"])
        self.assertIn("warning", out)

    async def test_a_malformed_id_never_reaches_the_command_line(self):
        for bad in ("--help", "CVE-2021-44228; id", "", "x", "-1-2", None, 5):
            with _fake_searchsploit() as calls:
                out = await _call(_executor(), "check_exploit", cve_id=bad)
            self.assertIn("error", out, repr(bad))
            self.assertEqual(calls, [], repr(bad))


class TestCveCacheQueries(unittest.TestCase):
    def _entry(self, cve_id, score):
        return {"cve_id": cve_id, "description": "d", "cvss_score": score,
                "cvss_vector": "v", "severity": "HIGH",
                "references": ["https://a.test"], "published": "2021"}

    def test_round_trip(self):
        conn = _conn()
        queries.cache_cves(conn, "k", "osv", [self._entry("CVE-1", 7.0),
                                              self._entry("CVE-2", 9.0)])
        rows = queries.get_cached_cves(conn, "k", 7)
        self.assertEqual([r["cve_id"] for r in rows], ["CVE-2", "CVE-1"])
        self.assertEqual(rows[0]["source"], "osv")
        self.assertEqual(json.loads(rows[0]["references_json"]), ["https://a.test"])

    def test_caching_again_replaces_rather_than_appends(self):
        conn = _conn()
        queries.cache_cves(conn, "k", "osv", [self._entry("CVE-1", 7.0)])
        queries.cache_cves(conn, "k", "osv", [self._entry("CVE-2", 7.0)])
        self.assertEqual([r["cve_id"] for r in queries.get_cached_cves(conn, "k", 7)],
                         ["CVE-2"])

    def test_keys_are_independent(self):
        conn = _conn()
        queries.cache_cves(conn, "a", "osv", [self._entry("CVE-1", 7.0)])
        queries.cache_cves(conn, "b", "osv", [self._entry("CVE-2", 7.0)])
        self.assertEqual(len(queries.get_cached_cves(conn, "a", 7)), 1)

    def test_age_limit(self):
        conn = _conn()
        queries.cache_cves(conn, "k", "osv", [self._entry("CVE-1", 7.0)])
        conn.execute("UPDATE cve_cache SET fetched_at = ?", (_iso_days_ago(8),))
        self.assertEqual(queries.get_cached_cves(conn, "k", 7), [])
        self.assertEqual(len(queries.get_cached_cves(conn, "k", 9)), 1)

    def test_nothing_cached_is_an_empty_list(self):
        self.assertEqual(queries.get_cached_cves(_conn(), "k", 7), [])


class TestNoNetworkAtImport(unittest.TestCase):
    def test_the_tool_modules_do_not_import_an_http_library(self):
        import subprocess
        script = ("import sys\n"
                  "import software.agent.tools.registry, software.agent.prompts\n"
                  "bad = [m for m in ('requests', 'urllib3', 'httpx', 'aiohttp')"
                  " if m in sys.modules]\n"
                  "print(bad)")
        repo = Path(__file__).resolve().parent.parent.parent
        r = subprocess.run([sys.executable, "-c", script], cwd=str(repo),
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr[-1500:])
        self.assertEqual(r.stdout.strip(), "[]")


if __name__ == "__main__":
    unittest.main()


class TestQuietProfileDropsTheOnlineTool(unittest.TestCase):
    """The quiet OpSec profile removes the tool, rather than refusing it.

    A tool the model never sees costs no turn and cannot be attempted; the
    preamble describes the tools it was offered, so dropping it keeps the
    two consistent. The local exploit check stays, because it touches
    nothing.
    """

    def _names(self, online):
        return [s.name for s in
                registry.specs("executor", ["batch"], "full", online)]

    def test_lookup_cve_is_absent_when_offline(self):
        self.assertNotIn("lookup_cve", self._names(False))
        self.assertIn("lookup_cve", self._names(True))

    def test_the_local_exploit_check_survives(self):
        self.assertIn("check_exploit", self._names(False))

    def test_nothing_else_is_lost(self):
        online, offline = set(self._names(True)), set(self._names(False))
        self.assertEqual(online - offline, {"lookup_cve"})

    def test_the_built_tool_list_honours_it_too(self):
        built = [t.spec.name for t in registry.executor_tools(
            _router_stub(), _conn(), 1, caps=["batch"], tier="full",
            scope_key="scope:10.0.1.0/24", online=False)]
        self.assertNotIn("lookup_cve", built)
        self.assertIn("check_exploit", built)


class TestTheModelSeesTheCommandThatRan(unittest.IsolatedAsyncioTestCase):
    """run_command's result must carry the rewrite, not just the router's.

    The limiter narrows -p- to --top-ports and adds -T2 --max-rate 50. If
    the tool result does not say so, the model reports having scanned all
    65535 ports under FINDINGS, and the campaign record is wrong in a way
    nobody can see afterwards.
    """

    class _Rewriting:
        async def run_command(self, command, **kwargs):
            return ActionResult(
                True, "open: 22", 0, False, "server",
                effective_command="nmap -T2 --max-rate 50 --top-ports 1000 "
                                  "10.0.1.5")

    class _Plain:
        async def run_command(self, command, **kwargs):
            return ActionResult(True, "root", 0, False, "beacon")

    async def _call(self, router):
        tools = {t.spec.name: t for t in _executor(router=router)}
        return await tools["run_command"].fn(command="nmap -p- 10.0.1.5")

    async def test_the_rewrite_is_in_the_result(self):
        out = await self._call(self._Rewriting())
        self.assertIn("--top-ports", out["effective_command"])

    async def test_an_untouched_command_adds_no_key(self):
        out = await self._call(self._Plain())
        self.assertNotIn("effective_command", out)
