#!/usr/bin/env python3
"""
Tests for the execution router and the two executors. Nothing here touches
the network, DNS or a real C2: the router gets a FakeC2 that records what it
is asked to run, and the gate is the real one over an in-memory store, so the
tests that say "the gate was never consulted" assert on the approvals table.

The assertion that carries the most weight is the same in almost every
blocking test: the fake C2 saw nothing. A block that merely returns a
refusal while the command also runs would pass every other check.
"""

import ast
import json
import socket
import sys
import unittest
import unittest.mock
from pathlib import Path
from unittest import IsolatedAsyncioTestCase

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent import c2client, gate, safety, scope
from software.agent.executor import ActionResult, beacon, router, server_tool
from software.agent.store import db, queries


class FakeC2:
    """Stands in for C2Client: records every call, replays canned answers."""

    def __init__(self, output="ok", exit_code=0, dies=False, down=False,
                 unauthorized=False, server_truncated=False, boom=False):
        self.output = output
        self.exit_code = exit_code
        self.dies = dies
        self.down = down
        self.unauthorized = unauthorized
        self.server_truncated = server_truncated
        self.boom = boom
        self.queued = []
        self.exec_calls = []
        self.awaits = []
        self.liveness = []

    def _check_reachable(self):
        if self.down:
            raise c2client.C2Unavailable("C2 at fake:0 request failed (X)")
        if self.unauthorized:
            raise c2client.C2Unauthorized("C2 at fake:0 rejected the token")
        if self.boom:
            raise RuntimeError("unexpected")

    def _payload(self, **extra):
        payload = {"success": self.exit_code == 0,
                   "status": "ok" if self.exit_code == 0 else "error",
                   "output": self.output}
        if self.exit_code:
            payload["exit_code"] = self.exit_code
        payload.update(extra)
        return payload

    async def get_agent(self, agent_id):
        return {"id": agent_id, "status": "offline" if self.dies else "online"}

    async def queue_task(self, agent_id, cmd, args="", data="", timeout=300,
                         lane="agent"):
        self._check_reachable()
        self.queued.append({"agent_id": agent_id, "cmd": cmd, "args": args,
                            "timeout": timeout, "lane": lane})
        return "task%d" % len(self.queued)

    async def await_task(self, task_id, *, timeout, poll_interval=2.0,
                         is_alive=None):
        self.awaits.append({"id": task_id, "timeout": timeout})
        self._check_reachable()
        if self.dies:
            # What C2Client._poll does once the liveness answer stays
            # negative. Asking is_alive here is what proves the executor
            # wired it to the agent record.
            alive = await is_alive() if is_alive is not None else False
            self.liveness.append(alive)
            if not alive:
                raise c2client.BeaconGone("beacon stopped responding")
        return self._payload()

    async def exec_server_tool(self, argv, *, tool, timeout, origin="agent"):
        self._check_reachable()
        self.exec_calls.append({"argv": argv, "tool": tool,
                                "timeout": timeout, "origin": origin})
        return "run%d" % len(self.exec_calls)

    async def await_server_tool(self, run_id, *, timeout, poll_interval=2.0):
        self.awaits.append({"id": run_id, "timeout": timeout})
        self._check_reachable()
        return self._payload(truncated=self.server_truncated)

    def nothing_ran(self):
        return not self.queued and not self.exec_calls


def _router(gate_allows=True, caps=None, beacon_output="ok", beacon_exit=0,
            beacon_dies=False, c2_down=False, detection_budget=3,
            truncate_chars=4000, uplinks=None, phase5_enabled=True,
            allow=("10.0.1.0/24",), deny=(), unattended="decide",
            beacon_ids=("raccoon-fox", "raccoon-pi"), mode="auto"):
    conn = db.open_store(":memory:")
    run_id = queries.create_run(conn, "campaign", None, "auto", "{}")
    g = gate.Gate(
        conn, run_id, mode=mode,
        ev_threshold=-1e9 if gate_allows else 1e9, p_detect_prior=0.15,
        detection_budget=detection_budget, unattended_behavior=unattended,
        approval_timeout=0.2)
    c2 = FakeC2(output=beacon_output, exit_code=beacon_exit,
                dies=beacon_dies, down=c2_down)
    r = router.Router(
        c2, g, scope.Scope(list(allow), list(deny)), conn=conn, run_id=run_id,
        beacon_ids=list(beacon_ids),
        caps_by_beacon=caps if caps is not None else {
            "raccoon-fox": ["batch"], "raccoon-pi": ["batch", "dropbox"]},
        uplink_by_beacon=uplinks if uplinks is not None else {},
        phase5_enabled=phase5_enabled, truncate_chars=truncate_chars)
    return r, c2


def _log(r, host, data):
    queries.log_finding(r._conn, r._run_id, host, "host", json.dumps(data),
                        "test")


def _approvals(r):
    return r._conn.execute("SELECT COUNT(*) FROM approvals").fetchone()[0]


# ── Gating ──


class TestGating(IsolatedAsyncioTestCase):
    async def test_tier_one_is_blocked_before_any_execution(self):
        r, c2 = _router()
        res = await r.run_command("kill", beacon_id="raccoon-fox")
        self.assertFalse(res.success)
        self.assertIsNotNone(res.blocked_reason)
        self.assertTrue(c2.nothing_ran())

    async def test_out_of_scope_target_is_blocked_before_execution(self):
        r, c2 = _router()
        res = await r.run_command("nmap -sV 172.16.0.5", beacon_id="raccoon-fox")
        self.assertFalse(res.success)
        self.assertIn("172.16.0.5", res.blocked_reason)
        self.assertTrue(c2.nothing_ran())

    async def test_shell_metachars_are_blocked(self):
        r, c2 = _router()
        res = await r.run_command("shell whoami; id", beacon_id="raccoon-fox")
        self.assertFalse(res.success)
        self.assertTrue(c2.nothing_ran())

    async def test_tier_two_consults_the_gate(self):
        r, c2 = _router(gate_allows=False)
        res = await r.run_command("lsassy -u a -p b 10.0.1.5", server_side=True)
        self.assertFalse(res.success)
        self.assertIn("gate", res.blocked_reason.lower())
        self.assertTrue(c2.nothing_ran())

    async def test_approved_tier_two_executes(self):
        r, c2 = _router(gate_allows=True)
        res = await r.run_command("lsassy -u a -p b 10.0.1.5", server_side=True)
        self.assertTrue(res.success)
        self.assertEqual(_approvals(r), 1)
        self.assertEqual(len(c2.exec_calls), 1)

    async def test_blocked_result_is_a_value_not_an_exception(self):
        r, _ = _router()
        self.assertIsInstance(
            await r.run_command("kill", beacon_id="raccoon-fox"), ActionResult)
        self.assertIs(router.ActionResult, ActionResult)

    async def test_a_free_command_never_asks_the_gate(self):
        r, c2 = _router()
        await r.run_command("whoami", beacon_id="raccoon-fox")
        self.assertEqual(_approvals(r), 0)
        self.assertEqual(len(c2.queued), 1)

    async def test_every_block_leaves_the_fake_c2_untouched(self):
        cases = [
            ("kill", {"beacon_id": "raccoon-fox"}),
            ("whoami; id", {"beacon_id": "raccoon-fox"}),
            ("nmap 172.16.0.5", {"beacon_id": "raccoon-fox"}),
            ("whoami", {}),
            ("whoami", {"beacon_id": "raccoon-fox", "server_side": True}),
            ("whoami", {"beacon_id": "no-such-beacon"}),
            ("systemctl stop raccoon", {"beacon_id": "raccoon-pi"}),
            ("nmap 'unterminated 10.0.1.5", {"server_side": True}),
        ]
        for command, kwargs in cases:
            r, c2 = _router()
            res = await r.run_command(command, **kwargs)
            self.assertFalse(res.success, command)
            self.assertIsNotNone(res.blocked_reason, command)
            self.assertTrue(c2.nothing_ran(), command)

    async def test_a_crashing_check_is_a_block_not_an_exception(self):
        r, c2 = _router()
        with unittest.mock.patch.object(
                safety, "classify", side_effect=RuntimeError("bug")):
            res = await r.run_command("whoami", beacon_id="raccoon-fox")
        self.assertFalse(res.success)
        self.assertIn("RuntimeError", res.blocked_reason)
        self.assertTrue(c2.nothing_ran())

    async def test_a_gate_pause_is_a_signal_not_a_block(self):
        r, c2 = _router(unattended="pause")
        with self.assertRaises(gate.GatePauseRequested):
            await r.run_command("lsassy -u a -p b 10.0.1.5", server_side=True)
        self.assertTrue(c2.nothing_ran())


class TestCheckOrder(IsolatedAsyncioTestCase):
    """The order of the checks is the specification."""

    async def test_full_pipeline_runs_in_the_specified_order(self):
        r, c2 = _router(beacon_output="x" * 10)
        seen = []

        def spy(name, fn):
            def inner(*args, **kwargs):
                seen.append(name)
                return fn(*args, **kwargs)
            return inner

        async def spy_request(classification, **kwargs):
            seen.append("gate")
            return await real_request(classification, **kwargs)

        real_request = r.gate.request
        real_run = router.run_on_server
        async def spy_run(*args, **kwargs):
            seen.append("execute")
            return await real_run(*args, **kwargs)

        with unittest.mock.patch.object(
                safety, "has_shell_metachars",
                spy("metachars", safety.has_shell_metachars)), \
             unittest.mock.patch.object(
                r._scope, "check", spy("scope", r._scope.check)), \
             unittest.mock.patch.object(
                safety, "classify", spy("classify", safety.classify)), \
             unittest.mock.patch.object(r.gate, "request", spy_request), \
             unittest.mock.patch.object(
                safety, "enforce_scan_limits",
                spy("limits", safety.enforce_scan_limits)), \
             unittest.mock.patch.object(router, "run_on_server", spy_run), \
             unittest.mock.patch.object(
                router, "scan_for_detection",
                spy("detect", router.scan_for_detection)), \
             unittest.mock.patch.object(
                router, "truncate", spy("truncate", router.truncate)):
            res = await r.run_command("lsassy -u a -p b 10.0.1.5",
                                      server_side=True)
        self.assertTrue(res.success)
        self.assertEqual(
            seen, ["metachars", "scope", "classify", "gate", "limits",
                   "execute", "detect", "truncate"])

    async def test_metachars_are_screened_before_scope(self):
        r, _ = _router()
        res = await r.run_command("nmap 172.16.0.5; id", server_side=True)
        self.assertNotIn("172.16.0.5", res.blocked_reason)

    async def test_scope_is_checked_before_classification(self):
        # Tier 1 and out of scope at once: the reason has to be the scope's.
        r, c2 = _router()
        res = await r.run_command("kill 172.16.0.5", beacon_id="raccoon-fox")
        self.assertIn("172.16.0.5", res.blocked_reason)
        self.assertTrue(c2.nothing_ran())

    async def test_scope_refuses_a_harmless_action_on_a_foreign_target(self):
        r, c2 = _router()
        res = await r.run_command("ping 172.16.0.5", server_side=True)
        self.assertIn("172.16.0.5", res.blocked_reason)

    async def test_out_of_scope_tier_two_never_reaches_the_gate(self):
        r, c2 = _router()
        await r.run_command("lsassy -u a -p b 172.16.0.5", server_side=True)
        self.assertEqual(_approvals(r), 0)

    async def test_tier_one_never_reaches_the_gate(self):
        r, c2 = _router()
        await r.run_command("kill", beacon_id="raccoon-fox")
        self.assertEqual(_approvals(r), 0)

    async def test_the_gate_is_asked_before_the_path_is_chosen(self):
        # The gate needs the risk numbers, so it runs on the classification
        # and not on a routable command: a tier-2 command with no usable
        # path has already asked.
        r, c2 = _router()
        res = await r.run_command("lsassy -u a -p b 10.0.1.5")
        self.assertFalse(res.success)
        self.assertEqual(_approvals(r), 1)
        self.assertTrue(c2.nothing_ran())


# ── Scan limits ──


class TestScanLimitsApplied(IsolatedAsyncioTestCase):
    async def test_nmap_is_rewritten_before_dispatch(self):
        r, c2 = _router()
        await r.run_command("nmap -T5 -sV 10.0.1.5", server_side=True)
        sent = " ".join(c2.exec_calls[-1]["argv"])
        self.assertIn("-T2", sent)
        self.assertIn("--max-rate 50", sent)
        self.assertNotIn("-T5", sent)

    async def test_the_beacon_path_is_rewritten_too(self):
        r, c2 = _router()
        await r.run_command("shell nmap -T5 10.0.1.5", beacon_id="raccoon-fox")
        self.assertIn("-T2", c2.queued[-1]["args"])
        self.assertNotIn("-T5", c2.queued[-1]["args"])


# ── Path selection ──


class TestPathSelection(IsolatedAsyncioTestCase):
    async def test_beacon_path_queues_an_agent_lane_task(self):
        r, c2 = _router()
        await r.run_command("netscan 10.0.1.0/24", beacon_id="raccoon-fox")
        self.assertEqual(c2.queued[-1]["lane"], "agent")
        self.assertEqual(c2.queued[-1]["agent_id"], "raccoon-fox")
        self.assertEqual(c2.queued[-1]["cmd"], "netscan")
        self.assertEqual(c2.queued[-1]["args"], "10.0.1.0/24")

    async def test_server_path_sends_argv(self):
        r, c2 = _router()
        await r.run_command("nmap -sV 10.0.1.5", server_side=True)
        self.assertIsInstance(c2.exec_calls[-1]["argv"], list)
        self.assertEqual(c2.exec_calls[-1]["tool"], "nmap")
        self.assertEqual(c2.queued, [])

    async def test_the_result_names_the_path_taken(self):
        r, _ = _router()
        self.assertEqual(
            (await r.run_command("whoami", beacon_id="raccoon-fox")).path,
            "beacon")
        self.assertEqual(
            (await r.run_command("nmap 10.0.1.5", server_side=True)).path,
            "server")

    async def test_both_or_neither_target_is_refused(self):
        r, c2 = _router()
        both = await r.run_command("whoami", beacon_id="raccoon-fox",
                                   server_side=True)
        neither = await r.run_command("whoami")
        self.assertIsNotNone(both.blocked_reason)
        self.assertIsNotNone(neither.blocked_reason)

    async def test_an_unknown_beacon_is_refused(self):
        r, c2 = _router()
        res = await r.run_command("whoami", beacon_id="raccoon-ghost")
        self.assertIn("raccoon-ghost", res.blocked_reason)
        self.assertTrue(c2.nothing_ran())


class TestTargetKind(unittest.TestCase):
    def test_dropbox_target_kind_is_detected_from_caps(self):
        r, _ = _router(caps={"raccoon-pi": ["dropbox", "batch"],
                             "raccoon-fox": ["batch"]})
        self.assertEqual(r.target_kind("raccoon-pi"), "dropbox")
        self.assertEqual(r.target_kind("raccoon-fox"), "beacon")

    def test_the_sniffer_capability_does_not_make_a_dropbox(self):
        # The plan keyed on "sniffer", which no beacon advertises; the
        # dropbox_lifeline rule would never have engaged.
        r, _ = _router(caps={"raccoon-fox": ["batch", "sniffer"]})
        self.assertEqual(r.target_kind("raccoon-fox"), "beacon")

    def test_unknown_caps_fail_safe_to_dropbox(self):
        r, _ = _router(caps={"empty": [], "none": None, "text": "batch",
                             "number": 3})
        for beacon_id in ("empty", "none", "text", "number", "unlisted", None):
            self.assertEqual(r.target_kind(beacon_id), "dropbox", beacon_id)

    def test_tuple_and_set_caps_are_read(self):
        r, _ = _router(caps={"a": ("batch",), "b": {"batch", "dropbox"}})
        self.assertEqual(r.target_kind("a"), "beacon")
        self.assertEqual(r.target_kind("b"), "dropbox")

    def test_a_server_side_run_is_a_server(self):
        r, _ = _router()
        self.assertEqual(r.target_kind(None, server_side=True), "server")

    def test_the_whole_flag_list_matches_scopes(self):
        self.assertEqual(router._WHOLE_FLAGS, scope._TARGET_FLAG_PREFIXES)


class TestDropboxLifelineEngages(IsolatedAsyncioTestCase):
    """The consequence of target_kind, end to end."""

    CMD = "systemctl stop raccoon"

    async def test_a_dropbox_is_protected(self):
        r, c2 = _router()
        res = await r.run_command(self.CMD, beacon_id="raccoon-pi")
        self.assertIn("drop-box", res.blocked_reason.lower())
        self.assertTrue(c2.nothing_ran())

    async def test_a_beacon_with_unknown_caps_is_protected(self):
        r, c2 = _router(caps={})
        res = await r.run_command(self.CMD, beacon_id="raccoon-fox")
        self.assertIsNotNone(res.blocked_reason)
        self.assertTrue(c2.nothing_ran())

    async def test_an_ordinary_beacon_is_not_over_blocked(self):
        r, c2 = _router()
        res = await r.run_command(self.CMD, beacon_id="raccoon-fox")
        self.assertIsNone(res.blocked_reason)
        self.assertEqual(len(c2.queued), 1)

    async def test_the_server_is_not_a_dropbox(self):
        r, c2 = _router()
        res = await r.run_command(self.CMD, server_side=True)
        self.assertIsNone(res.blocked_reason)


# ── The uplink ──


class TestUplink(IsolatedAsyncioTestCase):
    MONITOR = "iw dev wlan1 set type monitor"

    async def test_unknown_uplink_refuses_every_monitor_switch(self):
        r, c2 = _router(uplinks={})
        res = await r.run_command(self.MONITOR, beacon_id="raccoon-fox")
        self.assertFalse(res.success)
        self.assertIsNotNone(res.blocked_reason)
        self.assertTrue(c2.nothing_ran())

    async def test_an_empty_uplink_counts_as_unknown(self):
        for value in ("", None, "  "):
            r, c2 = _router(uplinks={"raccoon-fox": value})
            res = await r.run_command(self.MONITOR, beacon_id="raccoon-fox")
            self.assertIsNotNone(res.blocked_reason, repr(value))
            self.assertTrue(c2.nothing_ran())

    async def test_unknown_uplink_refuses_the_server_path_too(self):
        r, c2 = _router(uplinks={})
        res = await r.run_command(self.MONITOR, server_side=True)
        self.assertIsNotNone(res.blocked_reason)

    async def test_the_uplink_itself_is_refused(self):
        r, c2 = _router(uplinks={"raccoon-fox": "wlan1"})
        res = await r.run_command(self.MONITOR, beacon_id="raccoon-fox")
        self.assertIn("wlan1", res.blocked_reason)
        self.assertTrue(c2.nothing_ran())

    async def test_the_comparison_ignores_case(self):
        r, c2 = _router(uplinks={"raccoon-fox": "WLAN1"})
        res = await r.run_command(self.MONITOR, beacon_id="raccoon-fox")
        self.assertIsNotNone(res.blocked_reason)

    async def test_another_interface_is_gated_not_refused(self):
        r, c2 = _router(uplinks={"raccoon-fox": "eth0"})
        res = await r.run_command(self.MONITOR, beacon_id="raccoon-fox")
        self.assertIsNone(res.blocked_reason)
        self.assertEqual(_approvals(r), 1)
        self.assertEqual(len(c2.queued), 1)

    async def test_one_beacons_uplink_does_not_vouch_for_another(self):
        r, c2 = _router(uplinks={"raccoon-fox": "eth0"})
        res = await r.run_command(self.MONITOR, beacon_id="raccoon-pi")
        self.assertIsNotNone(res.blocked_reason)


# ── Hostname resolution ──


class TestResolveHost(IsolatedAsyncioTestCase):
    def setUp(self):
        # Any attempt to resolve a name through the OS fails the test.
        self._patches = []
        for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex",
                     "gethostbyaddr", "getfqdn"):
            p = unittest.mock.patch.object(
                socket, name, side_effect=AssertionError("DNS used: " + name))
            p.start()
            self._patches.append(p)
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    async def test_an_unseen_hostname_is_refused(self):
        r, c2 = _router()
        res = await r.run_command("nmap dc01.corp.local", server_side=True)
        self.assertFalse(res.success)
        self.assertIn("dc01.corp.local", res.blocked_reason)
        self.assertIn("finding", res.blocked_reason)
        self.assertTrue(c2.nothing_ran())

    async def test_a_hostname_with_a_finding_resolves(self):
        r, c2 = _router()
        _log(r, "dc01.corp.local", {"ip": "10.0.1.5"})
        res = await r.run_command("nmap dc01.corp.local", server_side=True)
        self.assertTrue(res.success, res.blocked_reason)
        self.assertEqual(len(c2.exec_calls), 1)

    async def test_a_hostname_tied_to_an_address_out_of_scope_is_refused(self):
        r, c2 = _router()
        _log(r, "dc01.corp.local", {"ip": "172.16.0.5"})
        res = await r.run_command("nmap dc01.corp.local", server_side=True)
        self.assertIn("172.16.0.5", res.blocked_reason)
        self.assertTrue(c2.nothing_ran())

    async def test_every_address_must_be_in_scope(self):
        r, c2 = _router()
        _log(r, "dc01.corp.local", {"ips": ["10.0.1.5", "172.16.0.5"]})
        res = await r.run_command("nmap dc01.corp.local", server_side=True)
        self.assertIsNotNone(res.blocked_reason)
        self.assertTrue(c2.nothing_ran())

    def test_resolve_returns_everything_the_findings_give(self):
        r, _ = _router()
        _log(r, "dc01.corp.local", {"ip": "10.0.1.5"})
        _log(r, "dc01.corp.local", {"addresses": ["10.0.1.6", "10.0.1.5"]})
        self.assertEqual(sorted(r._resolve_host("dc01.corp.local")),
                         ["10.0.1.5", "10.0.1.6"])

    def test_resolve_returns_none_for_an_unseen_name(self):
        r, _ = _router()
        self.assertIsNone(r._resolve_host("never-seen.corp.local"))

    def test_a_finding_without_an_address_does_not_resolve(self):
        r, _ = _router()
        _log(r, "dc01.corp.local", {"os": "Windows Server 2019"})
        self.assertIsNone(r._resolve_host("dc01.corp.local"))

    def test_garbage_in_a_finding_is_not_an_address(self):
        r, _ = _router()
        _log(r, "dc01.corp.local", {"ip": "not-an-address", "ips": [1, None]})
        queries.log_finding(r._conn, r._run_id, "dc01.corp.local", "host",
                            "{not json", "test")
        queries.log_finding(r._conn, r._run_id, "dc01.corp.local", "host",
                            "[1, 2]", "test")
        self.assertIsNone(r._resolve_host("dc01.corp.local"))

    def test_the_router_source_has_no_dns_call(self):
        tree = ast.parse(Path(router.__file__).read_text())
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        imports = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                   for a in n.names}
        self.assertNotIn("socket", imports | names)
        for fn in ("getaddrinfo", "gethostbyname", "gethostbyname_ex",
                   "gethostbyaddr"):
            self.assertNotIn(fn, names)


# ── Fail-opens routed here from the scope module ──


class TestRoutedFailOpens(IsolatedAsyncioTestCase):
    """Each shape passes scope.check unaided; the router has to close it."""

    async def test_a_hostname_after_equals_is_checked(self):
        r, c2 = _router()
        res = await r.run_command("nxc smb 10.0.1.5 RHOSTS=dc.corp.local",
                                  server_side=True)
        self.assertIn("dc.corp.local", res.blocked_reason)
        self.assertTrue(c2.nothing_ran())

    async def test_a_hostname_in_script_args_is_checked(self):
        r, c2 = _router()
        res = await r.run_command(
            "nmap --script-args target=dc01.corp.local 10.0.1.5",
            server_side=True)
        self.assertIn("dc01.corp.local", res.blocked_reason)
        self.assertTrue(c2.nothing_ran())

    async def test_a_hostname_after_a_second_equals_is_checked(self):
        r, c2 = _router()
        res = await r.run_command(
            "nmap --script-args=target=dc01.corp.local 10.0.1.5",
            server_side=True)
        self.assertIn("dc01.corp.local", res.blocked_reason)
        self.assertTrue(c2.nothing_ran())

    async def test_an_address_after_equals_is_checked(self):
        r, c2 = _router()
        res = await r.run_command("nxc smb 10.0.1.5 RHOSTS=172.16.0.9",
                                  server_side=True)
        self.assertIn("172.16.0.9", res.blocked_reason)

    async def test_a_hostname_after_equals_passes_once_a_finding_ties_it(self):
        r, c2 = _router()
        _log(r, "dc.corp.local", {"ip": "10.0.1.7"})
        res = await r.run_command("nxc smb 10.0.1.5 RHOSTS=dc.corp.local",
                                  server_side=True)
        self.assertIsNone(res.blocked_reason)
        self.assertEqual(len(c2.exec_calls), 1)

    async def test_a_short_flag_with_an_attached_path_is_refused(self):
        for command in ("nmap -oA/tmp/out 10.0.1.5",
                        "masscan -c/tmp/conf 10.0.1.5"):
            r, c2 = _router()
            res = await r.run_command(command, server_side=True)
            self.assertFalse(res.success, command)
            self.assertIsNotNone(res.blocked_reason, command)
            self.assertTrue(c2.nothing_ran(), command)

    async def test_a_short_flag_with_an_attached_hostname_is_checked(self):
        r, c2 = _router()
        res = await r.run_command("nmap -Sdc01.corp.local 10.0.1.5",
                                  server_side=True)
        self.assertIn("dc01.corp.local", res.blocked_reason)

    async def test_ordinary_attached_short_flag_values_still_run(self):
        r, c2 = _router()
        res = await r.run_command("nmap -p22,80 -T4 -sV -Pn 10.0.1.5",
                                  server_side=True)
        self.assertIsNone(res.blocked_reason)
        self.assertEqual(len(c2.exec_calls), 1)

    async def test_an_address_after_a_comma_in_a_url_is_checked(self):
        r, c2 = _router()
        res = await r.run_command("curl http://10.0.1.5/x,10.9.9.9",
                                  server_side=True)
        self.assertIn("10.9.9.9", res.blocked_reason)
        self.assertTrue(c2.nothing_ran())

    async def test_a_nested_url_is_checked(self):
        r, c2 = _router()
        res = await r.run_command(
            "curl http://10.0.1.5/go?next=http://10.9.9.9/", server_side=True)
        self.assertIn("10.9.9.9", res.blocked_reason)
        self.assertTrue(c2.nothing_ran())

    async def test_an_ordinary_url_still_runs(self):
        r, c2 = _router()
        res = await r.run_command("curl http://10.0.1.5/index.html?a=b",
                                  server_side=True)
        self.assertIsNone(res.blocked_reason)
        self.assertEqual(len(c2.exec_calls), 1)

    async def test_normalisation_does_not_change_what_is_sent(self):
        r, c2 = _router()
        await r.run_command("nmap -p22 10.0.1.5 --script-args a=b",
                            server_side=True)
        self.assertEqual(c2.exec_calls[-1]["argv"][-3:],
                         ["10.0.1.5", "--script-args", "a=b"])


# ── Detection ──


class TestDetection(IsolatedAsyncioTestCase):
    async def test_reset_in_output_is_recorded_as_detection(self):
        r, c2 = _router(beacon_output="connection reset by peer")
        await r.run_command("netscan 10.0.1.0/24", beacon_id="raccoon-fox")
        self.assertEqual(r.gate.detection_count, 1)

    async def test_clean_output_records_nothing(self):
        r, c2 = _router(beacon_output="445/tcp open microsoft-ds")
        await r.run_command("netscan 10.0.1.0/24", beacon_id="raccoon-fox")
        self.assertEqual(r.gate.detection_count, 0)

    async def test_budget_exhaustion_aborts_the_campaign(self):
        r, c2 = _router(beacon_output="connection reset by peer",
                        detection_budget=1)
        with self.assertRaises(router.RouterAborted):
            await r.run_command("netscan 10.0.1.0/24", beacon_id="raccoon-fox")

    async def test_a_detection_under_budget_does_not_abort(self):
        r, c2 = _router(beacon_output="connection reset by peer",
                        detection_budget=2)
        res = await r.run_command("netscan 10.0.1.0/24", beacon_id="raccoon-fox")
        self.assertTrue(res.success)

    async def test_the_signal_is_found_before_truncation(self):
        r, _ = _router(
            beacon_output="connection reset by peer" + "X" * 9000,
            truncate_chars=200)
        res = await r.run_command("whoami", beacon_id="raccoon-fox")
        self.assertTrue(res.truncated)
        self.assertEqual(r.gate.detection_count, 1)

    async def test_a_vanished_host_counts_if_it_answered_before(self):
        r, c2 = _router(beacon_output="No route to host")
        _log(r, "10.0.1.5", {"ports": [445]})
        await r.run_command("ping -c1 10.0.1.5", server_side=True)
        self.assertEqual(r.gate.detection_count, 1)

    async def test_a_host_that_never_answered_is_a_bad_target_not_a_defence(self):
        r, c2 = _router(beacon_output="No route to host")
        await r.run_command("ping -c1 10.0.1.5", server_side=True)
        self.assertEqual(r.gate.detection_count, 0)

    async def test_a_name_counts_through_the_address_that_answered(self):
        # The finding that ties the name to an address says where the name
        # points, not that anything answered there.
        r, c2 = _router(beacon_output="No route to host")
        _log(r, "dc01.corp.local", {"ip": "10.0.1.5"})
        await r.run_command("ping -c1 dc01.corp.local", server_side=True)
        self.assertEqual(r.gate.detection_count, 0)
        _log(r, "10.0.1.5", {"ports": [445]})
        await r.run_command("ping -c1 dc01.corp.local", server_side=True)
        self.assertEqual(r.gate.detection_count, 1)

    async def test_a_blocked_command_scans_nothing(self):
        r, c2 = _router(beacon_output="connection reset by peer")
        await r.run_command("kill", beacon_id="raccoon-fox")
        self.assertEqual(r.gate.detection_count, 0)


# ── Failure mapping ──


class TestBeaconGoesOffline(IsolatedAsyncioTestCase):
    """Review Focus 3: no executor hanging on a dead beacon."""

    async def test_dead_beacon_returns_a_failed_result_not_a_hang(self):
        r, c2 = _router(beacon_dies=True)
        res = await r.run_command("netscan 10.0.1.0/24", beacon_id="raccoon-fox")
        self.assertFalse(res.success)
        self.assertIn("offline", res.output.lower())
        self.assertEqual(c2.liveness, [False])

    async def test_c2_unavailable_is_reported_as_a_value(self):
        r, c2 = _router(c2_down=True)
        res = await r.run_command("whoami", beacon_id="raccoon-fox")
        self.assertFalse(res.success)
        self.assertIn("c2", res.output.lower())
        self.assertIsNone(res.blocked_reason)


class TestExecutors(IsolatedAsyncioTestCase):
    async def test_beacon_offline_text(self):
        c2 = FakeC2(dies=True)
        res = await beacon.run_on_beacon(c2, "raccoon-fox", "whoami", timeout=5)
        self.assertEqual((res.success, res.output), (False, "[beacon offline]"))

    async def test_beacon_liveness_uses_the_agent_record(self):
        c2 = FakeC2()
        res = await beacon.run_on_beacon(c2, "raccoon-fox", "whoami", timeout=5)
        self.assertTrue(res.success)

    async def test_beacon_unknown_to_the_c2_is_not_alive(self):
        c2 = FakeC2(dies=True)

        async def missing(agent_id):
            return None
        c2.get_agent = missing
        res = await beacon.run_on_beacon(c2, "raccoon-fox", "whoami", timeout=5)
        self.assertEqual(res.output, "[beacon offline]")

    async def test_beacon_c2_unavailable_text(self):
        res = await beacon.run_on_beacon(FakeC2(down=True), "raccoon-fox",
                                         "whoami", timeout=5)
        self.assertFalse(res.success)
        self.assertTrue(res.output.startswith("[c2 unavailable: "))

    async def test_beacon_unauthorized_is_a_value(self):
        res = await beacon.run_on_beacon(FakeC2(unauthorized=True),
                                         "raccoon-fox", "whoami", timeout=5)
        self.assertFalse(res.success)
        self.assertIn("token", res.output)

    async def test_beacon_unexpected_error_is_a_value_naming_the_class(self):
        res = await beacon.run_on_beacon(FakeC2(boom=True), "raccoon-fox",
                                         "whoami", timeout=5)
        self.assertFalse(res.success)
        self.assertIn("RuntimeError", res.output)
        self.assertNotIn("unexpected", res.output)

    async def test_beacon_waits_longer_than_the_task_timeout(self):
        c2 = FakeC2()
        await beacon.run_on_beacon(c2, "raccoon-fox", "whoami", timeout=100)
        self.assertEqual(c2.queued[-1]["timeout"], 100)
        self.assertGreater(c2.awaits[-1]["timeout"], 100)

    async def test_beacon_default_timeout(self):
        c2 = FakeC2()
        await beacon.run_on_beacon(c2, "raccoon-fox", "whoami", timeout=None)
        self.assertEqual(c2.queued[-1]["timeout"], 300)

    async def test_nonsense_timeouts_fall_back_to_the_default(self):
        for bad in (0, -5, True, float("nan"), "60", float("inf")):
            c2 = FakeC2()
            await beacon.run_on_beacon(c2, "raccoon-fox", "whoami", timeout=bad)
            self.assertEqual(c2.queued[-1]["timeout"], 300, repr(bad))

    async def test_nonzero_exit_is_not_an_exception(self):
        r, _ = _router(beacon_exit=1, beacon_output="permission denied")
        res = await r.run_command("whoami", beacon_id="raccoon-fox")
        self.assertFalse(res.success)
        self.assertEqual(res.exit_code, 1)

    async def test_failure_without_an_exit_code_reports_minus_one(self):
        c2 = FakeC2(exit_code=1)
        c2._payload = lambda **kw: {"success": False, "status": "error",
                                    "output": "x"}
        res = await beacon.run_on_beacon(c2, "raccoon-fox", "whoami", timeout=5)
        self.assertEqual(res.exit_code, -1)

    async def test_success_reports_exit_zero(self):
        res = await beacon.run_on_beacon(FakeC2(), "raccoon-fox", "whoami",
                                         timeout=5)
        self.assertEqual(res.exit_code, 0)

    async def test_non_string_output_is_made_a_string(self):
        c2 = FakeC2()
        c2._payload = lambda **kw: {"success": True, "output": None}
        res = await beacon.run_on_beacon(c2, "raccoon-fox", "whoami", timeout=5)
        self.assertEqual(res.output, "")

    # ── server executor ──

    async def test_server_splits_the_command_with_shlex(self):
        c2 = FakeC2()
        await server_tool.run_on_server(
            c2, ["nmap", "-sV", "10.0.1.5"], tool="nmap", timeout=None)
        self.assertEqual(c2.exec_calls[-1]["argv"], ["nmap", "-sV", "10.0.1.5"])
        self.assertEqual(c2.exec_calls[-1]["origin"], "agent")

    async def test_server_timeout_resolves_from_the_basename(self):
        cases = [
            (["nmap", "-sV"], 900),
            (["sudo", "nmap", "-sV"], 900),
            (["/usr/bin/nmap", "-sV"], 900),
            (["sudo", "-u", "root", "/usr/sbin/tcpdump", "-i", "eth0"], 30),
            (["doas", "aircrack-ng", "x.cap"], 1800),
            (["sudo", "-n", "aircrack-ng", "x.cap"], 1800),
            (["whois", "example.com"], 60),
            (["sudo"], 60),
        ]
        for argv, expected in cases:
            c2 = FakeC2()
            await server_tool.run_on_server(c2, argv, tool="t", timeout=None)
            self.assertEqual(c2.exec_calls[-1]["timeout"], expected, argv)

    async def test_an_explicit_timeout_wins_over_the_tool_default(self):
        c2 = FakeC2()
        await server_tool.run_on_server(c2, ["nmap", "x"], tool="nmap",
                                        timeout=120)
        self.assertEqual(c2.exec_calls[-1]["timeout"], 120)

    async def test_server_waits_longer_than_the_tool_timeout(self):
        # The C2 reports its own "[timeout after Ns, partial output]"; a
        # client that gave up at exactly N would throw that output away.
        c2 = FakeC2()
        await server_tool.run_on_server(c2, ["nmap", "x"], tool="nmap",
                                        timeout=100)
        self.assertGreater(c2.awaits[-1]["timeout"], 100)

    async def test_server_flags_the_c2s_own_truncation(self):
        c2 = FakeC2(server_truncated=True)
        res = await server_tool.run_on_server(c2, ["nmap", "x"], tool="nmap",
                                              timeout=None)
        self.assertTrue(res.truncated)

    async def test_server_failures_are_values(self):
        for kwargs, text in ((dict(down=True), "[c2 unavailable: "),
                             (dict(unauthorized=True), "token"),
                             (dict(boom=True), "RuntimeError")):
            res = await server_tool.run_on_server(
                FakeC2(**kwargs), ["nmap", "x"], tool="nmap", timeout=None)
            self.assertFalse(res.success)
            self.assertIn(text, res.output)

    async def test_an_empty_argv_is_a_value(self):
        res = await server_tool.run_on_server(FakeC2(), [], tool="x",
                                              timeout=None)
        self.assertFalse(res.success)

    async def test_the_router_splits_a_quoted_argument_as_one_word(self):
        r, c2 = _router()
        await r.run_command("nmap --script-args 'a=b c' 10.0.1.5",
                            server_side=True)
        self.assertIn("a=b c", c2.exec_calls[-1]["argv"])


# ── Output handling ──


class TestOutputHandling(IsolatedAsyncioTestCase):
    async def test_long_output_is_truncated_with_flag(self):
        r, _ = _router(beacon_output="X" * 9000, truncate_chars=4000)
        res = await r.run_command("whoami", beacon_id="raccoon-fox")
        self.assertTrue(res.truncated)
        self.assertLess(len(res.output), 4200)

    async def test_short_output_is_untouched(self):
        r, _ = _router(beacon_output="short")
        res = await r.run_command("whoami", beacon_id="raccoon-fox")
        self.assertFalse(res.truncated)
        self.assertEqual(res.output, "short")

    async def test_the_c2s_truncation_flag_survives_a_short_output(self):
        r, c2 = _router()
        c2.server_truncated = True
        res = await r.run_command("nmap 10.0.1.5", server_side=True)
        self.assertTrue(res.truncated)

    async def test_nonzero_exit_is_not_an_exception(self):
        r, _ = _router(beacon_exit=1, beacon_output="permission denied")
        res = await r.run_command("whoami", beacon_id="raccoon-fox")
        self.assertFalse(res.success)
        self.assertEqual(res.exit_code, 1)
        self.assertIsNone(res.blocked_reason)


if __name__ == "__main__":
    unittest.main()
