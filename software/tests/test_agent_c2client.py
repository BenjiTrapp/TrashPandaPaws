#!/usr/bin/env python3
"""
Tests for the C2 client. Nothing here touches the network: every client gets
a FakeC2 session, which stands in for the one method the client calls on it,
`session.request(...)`. The tests assert on the request the client *builds*
and on how it reads the answer, which is how the wire shapes are pinned
without a live server. The one test of the real session replaces the
`requests` module wholesale, because importing the real one warns under
-W error on some platforms and would make a network call besides.
"""

import ast
import asyncio
import subprocess
import sys
import time
import types
import unittest
import unittest.mock
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent import c2client

# Distinctive on purpose: "tok" is a substring of "token", so a leak check
# against it would trip on the word in a perfectly safe message.
_TOKEN = "tok-SECRET-0123456789abcdef"


class FakeC2:
    """A session that records what it is asked and replays canned answers."""

    def __init__(self, post_response=None, get_response=None,
                 get_sequence=None, status=200, raise_connect=False):
        self.post_response = (post_response if post_response is not None
                              else {"id": "task0", "run_id": "run0"})
        self.get_response = get_response if get_response is not None else []
        self.get_sequence = list(get_sequence or [])
        self.status = status
        self.raise_connect = raise_connect
        self.calls = []
        self.last_url = self.last_headers = self.last_json = None
        self.last_kwargs = {}

    def request(self, method, url, headers=None, json=None, **kwargs):
        self.calls.append((method, url))
        self.last_url, self.last_headers, self.last_json = url, headers, json
        self.last_kwargs = kwargs
        if self.raise_connect:
            raise _ConnectError(url, headers)
        if method == "POST":
            payload = self.post_response
        elif self.get_sequence:
            payload = self.get_sequence.pop(0)
        else:
            payload = self.get_response
        return types.SimpleNamespace(
            status_code=self.status, json=lambda: payload,
            text="body echoes Authorization: " + _TOKEN)


class _ConnectError(Exception):
    """Models a requests exception: it holds the request, headers and all."""

    def __init__(self, url, headers):
        super().__init__("cannot reach %s with %r" % (url, headers))
        self.request = types.SimpleNamespace(url=url, headers=dict(headers))


def _client(fake, token="tok", **kw):
    return c2client.C2Client("http://c2", token, session=fake, **kw)


def _walk_chain(exc) -> str:
    """Everything a hand-written error serialiser could reach from `exc`."""
    parts, seen, current = [], set(), exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        parts.append(repr(current))
        parts.append(repr(getattr(current, "__dict__", {})))
        for attr in ("request", "response"):
            held = getattr(current, attr, None)
            parts.append(repr(held))
            parts.append(repr(getattr(held, "headers", None)))
        current = current.__context__ or current.__cause__
    return " ".join(parts)


# ── Tasking ──


class TestTasking(unittest.IsolatedAsyncioTestCase):
    async def test_queue_task_sends_agent_lane(self):
        fake = FakeC2()
        await _client(fake).queue_task("raccoon-fox", "netscan", "10.0.1.0/24")
        self.assertEqual(fake.last_json["lane"], "agent")

    async def test_queue_task_posts_the_whole_task_to_the_agent_route(self):
        fake = FakeC2()
        await _client(fake).queue_task(
            "raccoon-fox", "shell", "id", data="d", timeout=60)
        self.assertEqual(fake.calls, [
            ("POST", "http://c2/api/agents/raccoon-fox/task")])
        self.assertEqual(fake.last_json, {
            "cmd": "shell", "args": "id", "data": "d", "timeout": 60,
            "lane": "agent"})

    async def test_queue_task_returns_task_id(self):
        fake = FakeC2(post_response={"id": "ab12cd34"})
        self.assertEqual(
            await _client(fake).queue_task("raccoon-fox", "whoami"), "ab12cd34")

    async def test_queue_task_without_an_id_in_the_answer_is_an_error(self):
        fake = FakeC2(post_response={"queued": True})
        with self.assertRaises(c2client.C2Unavailable):
            await _client(fake).queue_task("raccoon-fox", "whoami")

    async def test_queueing_for_an_unknown_agent_is_beacon_gone(self):
        with self.assertRaises(c2client.BeaconGone):
            await _client(FakeC2(status=404)).queue_task("nope", "whoami")

    async def test_bearer_token_is_sent(self):
        fake = FakeC2()
        await _client(fake).list_agents()
        self.assertEqual(fake.last_headers["Authorization"], "Bearer tok")

    async def test_list_agents_returns_the_list(self):
        fake = FakeC2(get_response=[{"id": "a"}, {"id": "b"}])
        self.assertEqual(await _client(fake).list_agents(),
                         [{"id": "a"}, {"id": "b"}])
        self.assertEqual(fake.calls, [("GET", "http://c2/api/agents")])

    async def test_list_agents_rejects_an_answer_that_is_not_a_list(self):
        with self.assertRaises(c2client.C2Unavailable):
            await _client(FakeC2(get_response={"oops": 1})).list_agents()

    async def test_get_agent_returns_the_beacon(self):
        fake = FakeC2(get_response={"id": "raccoon-fox", "interval": 30})
        agent = await _client(fake).get_agent("raccoon-fox")
        self.assertEqual(agent["interval"], 30)
        self.assertEqual(fake.last_url, "http://c2/api/agents/raccoon-fox")

    async def test_unknown_agent_returns_none(self):
        self.assertIsNone(await _client(FakeC2(status=404)).get_agent("nope"))

    async def test_an_id_cannot_climb_out_of_its_path_segment(self):
        # The id comes from the model. Unquoted, "../server/exec" would turn
        # a beacon lookup into a request against a different endpoint.
        fake = FakeC2(get_response={})
        await _client(fake).get_agent("../server/exec")
        self.assertEqual(fake.last_url,
                         "http://c2/api/agents/..%2Fserver%2Fexec")

    async def test_dot_segments_and_empty_ids_are_refused_before_any_request(self):
        fake = FakeC2()
        c = _client(fake)
        for bad in ("", ".", ".."):
            with self.assertRaises(ValueError):
                await c.get_agent(bad)
            with self.assertRaises(ValueError):
                await c.get_task_result(bad)
        self.assertEqual(fake.calls, [])

    async def test_set_beacon_interval_queues_the_sleep_command_the_gui_sends(self):
        fake = FakeC2()
        await _client(fake).set_beacon_interval("raccoon-fox", 30, 20)
        self.assertEqual(fake.calls, [
            ("POST", "http://c2/api/agents/raccoon-fox/task")])
        self.assertEqual(fake.last_json["cmd"], "sleep")
        self.assertEqual(fake.last_json["args"], "30 20")

    async def test_set_beacon_interval_returns_nothing(self):
        self.assertIsNone(
            await _client(FakeC2()).set_beacon_interval("a", 5, 0))

    async def test_set_beacon_interval_refuses_a_string_for_the_numbers(self):
        # "1 2" would otherwise ride into the beacon's args as two values.
        fake = FakeC2()
        with self.assertRaises(TypeError):
            await _client(fake).set_beacon_interval("a", "30 20", 10)
        self.assertEqual(fake.calls, [])


# ── Results and polling ──


class TestResults(unittest.IsolatedAsyncioTestCase):
    async def test_pending_result_is_none(self):
        fake = FakeC2(get_response={"status": "pending"})
        self.assertIsNone(await _client(fake).get_task_result("ab12cd34"))
        self.assertEqual(fake.last_url, "http://c2/api/tasks/ab12cd34")

    async def test_a_finished_result_carries_success(self):
        ok = FakeC2(get_response={"status": "ok", "output": "root"})
        err = FakeC2(get_response={"status": "error", "output": "boom"})
        self.assertTrue((await _client(ok).get_task_result("t"))["success"])
        self.assertFalse((await _client(err).get_task_result("t"))["success"])

    async def test_await_task_polls_until_done(self):
        fake = FakeC2(get_sequence=[{"status": "pending"}, {"status": "pending"},
                                    {"status": "ok", "output": "root"}])
        res = await _client(fake).await_task(
            "ab12cd34", timeout=10, poll_interval=0.01)
        self.assertEqual(res["output"], "root")
        self.assertEqual(len(fake.calls), 3)

    async def test_await_task_times_out_with_marker(self):
        fake = FakeC2(get_response={"status": "pending"})
        res = await _client(fake).await_task(
            "ab12cd34", timeout=0.05, poll_interval=0.01)
        self.assertFalse(res["success"])
        self.assertIn("timeout", res["output"].lower())
        self.assertEqual(res["task_id"], "ab12cd34")

    async def test_a_timeout_is_not_an_exception_even_with_a_liveness_check(self):
        async def alive():
            return True
        fake = FakeC2(get_response={"status": "pending"})
        res = await _client(fake).await_task(
            "t", timeout=0.05, poll_interval=0.01, is_alive=alive)
        self.assertFalse(res["success"])

    async def test_a_zero_timeout_still_polls_once(self):
        fake = FakeC2(get_response={"status": "ok", "output": "fast"})
        res = await _client(fake).await_task("t", timeout=0, poll_interval=0.01)
        self.assertEqual(res["output"], "fast")

    async def test_no_task_is_left_behind(self):
        fake = FakeC2(get_response={"status": "pending"})
        await _client(fake).await_task("t", timeout=0.05, poll_interval=0.01)
        pending = [t for t in asyncio.all_tasks()
                   if t is not asyncio.current_task()]
        self.assertEqual(pending, [])


class TestBeaconGoneOffline(unittest.IsolatedAsyncioTestCase):
    """Review Focus 3: kein Endlos-Poll auf einem toten Beacon."""

    def _alive(self, answers):
        calls = {"n": 0}

        async def is_alive():
            answer = answers[min(calls["n"], len(answers) - 1)]
            calls["n"] += 1
            return answer
        return is_alive, calls

    async def test_await_task_aborts_when_liveness_check_fails(self):
        fake = FakeC2(get_response={"status": "pending"})
        calls = {"n": 0}

        async def is_alive():
            calls["n"] += 1
            return calls["n"] < 3
        with self.assertRaises(c2client.BeaconGone):
            await _client(fake).await_task(
                "ab12cd34", timeout=30, poll_interval=0.01, is_alive=is_alive)

    async def test_three_consecutive_negatives_raise_on_the_third(self):
        fake = FakeC2(get_response={"status": "pending"})
        is_alive, calls = self._alive([True, False, False, False, True])
        with self.assertRaises(c2client.BeaconGone):
            await _client(fake).await_task(
                "t", timeout=30, poll_interval=0.01, is_alive=is_alive)
        self.assertEqual(calls["n"], 4)

    async def test_two_negatives_in_a_row_do_not_raise(self):
        fake = FakeC2(get_sequence=[{"status": "pending"}] * 2
                      + [{"status": "ok", "output": "done"}])
        is_alive, _ = self._alive([False])
        res = await _client(fake).await_task(
            "t", timeout=30, poll_interval=0.01, is_alive=is_alive)
        self.assertEqual(res["output"], "done")

    async def test_a_positive_answer_resets_the_count(self):
        # Never three in a row, but six negatives in all: a counter that is
        # not reset would raise on the third.
        answers = [False, False, True, False, False, True, False, False, True]
        fake = FakeC2(get_sequence=[{"status": "pending"}] * len(answers)
                      + [{"status": "ok", "output": "slow but alive"}])
        is_alive, calls = self._alive(answers)
        res = await _client(fake).await_task(
            "t", timeout=30, poll_interval=0.01, is_alive=is_alive)
        self.assertEqual(res["output"], "slow but alive")
        self.assertEqual(calls["n"], len(answers))

    async def test_a_result_that_has_arrived_wins_over_a_dead_beacon(self):
        # A beacon that answered and then died has still answered.
        fake = FakeC2(get_response={"status": "ok", "output": "last words"})
        is_alive, calls = self._alive([False])
        res = await _client(fake).await_task(
            "t", timeout=30, poll_interval=0.01, is_alive=is_alive)
        self.assertEqual(res["output"], "last words")
        self.assertEqual(calls["n"], 0)

    async def test_beacon_gone_names_the_task_not_the_token(self):
        fake = FakeC2(get_response={"status": "pending"})
        is_alive, _ = self._alive([False])
        with self.assertRaises(c2client.BeaconGone) as cm:
            await _client(fake, token=_TOKEN).await_task(
                "ab12cd34", timeout=30, poll_interval=0.01, is_alive=is_alive)
        self.assertIn("ab12cd34", str(cm.exception))
        self.assertNotIn(_TOKEN, _walk_chain(cm.exception))


# ── Server-side tools ──


class TestServerTools(unittest.IsolatedAsyncioTestCase):
    async def test_exec_sends_argv_not_cmd_string(self):
        fake = FakeC2(post_response={"run_id": "r1"})
        await _client(fake).exec_server_tool(
            ["nmap", "-sV", "10.0.1.5"], tool="nmap", timeout=900)
        self.assertEqual(fake.last_json["argv"], ["nmap", "-sV", "10.0.1.5"])
        self.assertNotIn("cmd", fake.last_json)
        self.assertEqual(fake.calls, [("POST", "http://c2/api/server/exec")])

    async def test_exec_marks_the_run_as_agent_origin(self):
        """Sonst landet Agent-Ausgabe im Operator-Panel."""
        fake = FakeC2(post_response={"run_id": "r1"})
        await _client(fake).exec_server_tool(
            ["nmap", "-sV", "10.0.1.5"], tool="nmap", timeout=900)
        self.assertEqual(fake.last_json["origin"], "agent")

    async def test_exec_sends_tool_and_timeout_and_returns_the_run_id(self):
        fake = FakeC2(post_response={"run_id": "r1", "status": "started"})
        run_id = await _client(fake).exec_server_tool(
            ["nmap", "10.0.1.5"], tool="nmap", timeout=900)
        self.assertEqual(run_id, "r1")
        self.assertEqual(fake.last_json["tool"], "nmap")
        self.assertEqual(fake.last_json["timeout"], 900)

    async def test_exec_without_a_run_id_in_the_answer_is_an_error(self):
        # The old endpoint answers {"status": "started"}: one global slot.
        # Treating that as success would let two runs overwrite each other.
        fake = FakeC2(post_response={"status": "started", "tool": "nmap"})
        with self.assertRaises(c2client.C2Unavailable):
            await _client(fake).exec_server_tool(
                ["nmap"], tool="nmap", timeout=900)

    async def test_string_command_is_refused_by_type(self):
        c = _client(FakeC2())
        with self.assertRaises(TypeError):
            await c.exec_server_tool("nmap -sV 10.0.1.5", tool="nmap",
                                     timeout=900)

    async def test_the_type_error_fires_before_any_request_is_built(self):
        fake = FakeC2()
        c = _client(fake)
        for bad in ("nmap -sV 10.0.1.5", b"nmap", ["nmap", 5], [["nmap"]], None):
            with self.assertRaises(TypeError):
                await c.exec_server_tool(bad, tool="nmap", timeout=900)
        self.assertEqual(fake.calls, [])
        self.assertIsNone(fake.last_json)

    async def test_a_tuple_of_strings_is_accepted(self):
        fake = FakeC2(post_response={"run_id": "r1"})
        await _client(fake).exec_server_tool(
            ("nmap", "-sV"), tool="nmap", timeout=900)
        self.assertEqual(fake.last_json["argv"], ["nmap", "-sV"])

    async def test_running_result_is_none(self):
        fake = FakeC2(get_response={"status": "running", "output": ""})
        self.assertIsNone(await _client(fake).get_server_tool_result("r1"))
        self.assertEqual(fake.last_url, "http://c2/api/server/exec/result/r1")

    async def test_finished_result_is_returned_with_success(self):
        fake = FakeC2(get_response={"status": "ok", "output": "Nmap done"})
        res = await _client(fake).get_server_tool_result("r1")
        self.assertEqual(res["output"], "Nmap done")
        self.assertTrue(res["success"])

    async def test_await_server_tool_polls_until_done(self):
        fake = FakeC2(get_sequence=[{"status": "running"}, {"status": "running"},
                                    {"status": "error", "output": "refused"}])
        res = await _client(fake).await_server_tool(
            "r1", timeout=10, poll_interval=0.01)
        self.assertEqual(res["output"], "refused")
        self.assertFalse(res["success"])

    async def test_await_server_tool_times_out_with_marker(self):
        fake = FakeC2(get_response={"status": "running"})
        res = await _client(fake).await_server_tool(
            "r1", timeout=0.05, poll_interval=0.01)
        self.assertFalse(res["success"])
        self.assertIn("timeout", res["output"].lower())
        self.assertEqual(res["run_id"], "r1")


# ── Failure modes ──


class TestFailureModes(unittest.IsolatedAsyncioTestCase):
    async def test_connection_refused_raises_c2_unavailable(self):
        c = _client(FakeC2(raise_connect=True))
        with self.assertRaises(c2client.C2Unavailable):
            await c.list_agents()

    async def test_401_raises_unauthorized(self):
        with self.assertRaises(c2client.C2Unauthorized):
            await _client(FakeC2(status=401)).list_agents()

    async def test_403_raises_unauthorized(self):
        with self.assertRaises(c2client.C2Unauthorized):
            await _client(FakeC2(status=403)).list_agents()

    async def test_a_server_error_names_host_and_status(self):
        with self.assertRaises(c2client.C2Unavailable) as cm:
            await _client(FakeC2(status=500)).list_agents()
        self.assertIn("500", str(cm.exception))
        self.assertIn("c2", str(cm.exception))

    async def test_a_redirect_is_an_error_not_followed(self):
        fake = FakeC2(status=302)
        with self.assertRaises(c2client.C2Unavailable) as cm:
            await _client(fake).list_agents()
        self.assertIn("302", str(cm.exception))
        self.assertIs(fake.last_kwargs["allow_redirects"], False)

    async def test_tls_is_not_verified_by_default(self):
        fake = FakeC2()
        await _client(fake).list_agents()
        self.assertIs(fake.last_kwargs["verify"], False)

    async def test_tls_verification_can_be_switched_on(self):
        fake = FakeC2()
        await _client(fake, verify_tls=True).list_agents()
        self.assertIs(fake.last_kwargs["verify"], True)

    async def test_every_request_has_a_timeout(self):
        fake = FakeC2()
        await _client(fake).list_agents()
        self.assertGreater(fake.last_kwargs["timeout"], 0)

    async def test_the_exceptions_are_distinct(self):
        self.assertFalse(issubclass(c2client.C2Unauthorized,
                                    c2client.C2Unavailable))
        self.assertFalse(issubclass(c2client.BeaconGone, c2client.C2Unavailable))

    async def test_an_answer_that_is_not_json_is_an_error_without_the_body(self):
        def bad_json():
            raise ValueError("Expecting value: " + _TOKEN)
        session = unittest.mock.Mock()
        session.request.return_value = types.SimpleNamespace(
            status_code=200, json=bad_json, text="BODY-" + _TOKEN)
        with self.assertRaises(c2client.C2Unavailable) as cm:
            await _client(session, token=_TOKEN).list_agents()
        self.assertNotIn(_TOKEN, _walk_chain(cm.exception))
        self.assertNotIn("BODY-", str(cm.exception))
        self.assertIsNone(cm.exception.__context__)


# ── The token stays out of everything ──


class TestTokenIsNeverExposed(unittest.IsolatedAsyncioTestCase):
    def test_repr_and_str_of_the_client_hold_no_token(self):
        c = _client(FakeC2(), token=_TOKEN)
        for text in (repr(c), str(c), repr(vars(c))):
            self.assertNotIn(_TOKEN, text)

    def test_repr_names_the_host(self):
        self.assertIn("c2", repr(_client(FakeC2())))

    def test_the_repr_names_host_and_port_only(self):
        c = c2client.C2Client("https://c2.example:8443/", "t", session=FakeC2())
        self.assertIn("c2.example:8443", repr(c))

    def test_a_url_with_credentials_is_refused(self):
        # They would sit in _base_url, so in any dump of the client.
        with self.assertRaises(ValueError):
            c2client.C2Client("https://user:hunter2@c2.example/", "t",
                              session=FakeC2())

    def test_a_base_url_that_is_not_http_is_refused(self):
        for bad in ("c2.example", "ftp://c2.example", "http://"):
            with self.assertRaises(ValueError):
                c2client.C2Client(bad, "t", session=FakeC2())

    async def test_connection_failure_leaks_nothing_through_the_chain(self):
        # The connect error holds a .request whose .headers carry the token.
        c = _client(FakeC2(raise_connect=True), token=_TOKEN)
        with self.assertRaises(c2client.C2Unavailable) as cm:
            await c.list_agents()
        self.assertNotIn(_TOKEN, str(cm.exception))
        self.assertIsNone(cm.exception.__cause__)
        # Empty rather than merely hidden: `from None` would leave it here.
        self.assertIsNone(cm.exception.__context__)
        self.assertNotIn(_TOKEN, _walk_chain(cm.exception))

    async def test_a_rejected_token_leaks_nothing_through_message_or_chain(self):
        # The fake's response body echoes the Authorization value back.
        c = _client(FakeC2(status=401), token=_TOKEN)
        with self.assertRaises(c2client.C2Unauthorized) as cm:
            await c.list_agents()
        self.assertIn("401", str(cm.exception))
        self.assertIn("c2", str(cm.exception))
        self.assertNotIn(_TOKEN, str(cm.exception))
        self.assertNotIn("echoes", str(cm.exception))
        self.assertIsNone(cm.exception.__context__)
        self.assertNotIn(_TOKEN, _walk_chain(cm.exception))

    async def test_an_unknown_error_class_is_named_but_not_its_message(self):
        class Odd(Exception):
            pass
        session = unittest.mock.Mock()
        session.request.side_effect = Odd("Bearer " + _TOKEN)
        with self.assertRaises(c2client.C2Unavailable) as cm:
            await _client(session, token=_TOKEN).list_agents()
        self.assertIn("Odd", str(cm.exception))
        self.assertNotIn(_TOKEN, _walk_chain(cm.exception))


# ── The real session ──


class TestRealSession(unittest.IsolatedAsyncioTestCase):
    """The default session, against a fake `requests` module."""

    class _InsecureRequestWarning(Warning):
        pass

    def _fake_requests(self, request):
        mod = types.ModuleType("requests")
        mod.request = request
        urllib3 = types.SimpleNamespace(exceptions=types.SimpleNamespace(
            InsecureRequestWarning=self._InsecureRequestWarning))
        mod.packages = types.SimpleNamespace(urllib3=urllib3)
        return mod

    def _answer(self, **kw):
        return types.SimpleNamespace(status_code=200, json=lambda: [])

    async def _list(self, request, **kw):
        fake = self._fake_requests(request)
        with unittest.mock.patch.dict(sys.modules, {"requests": fake}):
            return await c2client.C2Client("http://c2", "tok", **kw).list_agents()

    async def test_the_request_goes_through_requests_request(self):
        request = unittest.mock.Mock(return_value=self._answer())
        self.assertEqual(await self._list(request), [])
        args, kwargs = request.call_args
        self.assertEqual(args, ("GET", "http://c2/api/agents"))
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer tok")
        self.assertIs(kwargs["verify"], False)
        self.assertIs(kwargs["allow_redirects"], False)

    async def test_the_insecure_request_warning_is_silenced_for_the_call_only(self):
        def request(*a, **kw):
            warnings.warn("unverified", self._InsecureRequestWarning)
            return self._answer()
        before = list(warnings.filters)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            await self._list(request)
            # The filter that did the silencing is gone again afterwards.
            warnings.warn("later", self._InsecureRequestWarning)
        self.assertEqual([str(w.message) for w in caught], ["later"])
        self.assertEqual(warnings.filters, before)

    async def test_other_warnings_inside_the_call_still_get_through(self):
        def request(*a, **kw):
            warnings.warn("something else", UserWarning)
            return self._answer()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            await self._list(request)
        self.assertEqual([str(w.message) for w in caught], ["something else"])

    async def test_a_verified_connection_has_nothing_silenced(self):
        def request(*a, **kw):
            warnings.warn("unverified", self._InsecureRequestWarning)
            return self._answer()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            await self._list(request, verify_tls=True)
        self.assertEqual(len(caught), 1)

    async def test_concurrent_calls_leave_the_filters_as_they_were(self):
        # catch_warnings saves and restores global state; two threads doing
        # that interleaved can leave the ignore filter installed for good.
        def request(*a, **kw):
            time.sleep(0.02)  # long enough for the threads to overlap
            warnings.warn("unverified", self._InsecureRequestWarning)
            return self._answer()
        before = list(warnings.filters)
        fake = self._fake_requests(request)
        with unittest.mock.patch.dict(sys.modules, {"requests": fake}):
            c = c2client.C2Client("http://c2", "tok")
            await asyncio.gather(*[c.list_agents() for _ in range(16)])
        self.assertEqual(warnings.filters, before)


# ── Status quo: no new dependency, no import-time cost ──


class TestNoNewDependencies(unittest.TestCase):
    _FORBIDDEN = {"aiohttp", "httpx"}

    def test_the_module_imports_no_async_http_library(self):
        path = Path(c2client.__file__)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module or ""]
            else:
                continue
            for name in names:
                self.assertNotIn(name.split(".")[0], self._FORBIDDEN)

    def test_requests_is_not_imported_until_a_request_is_made(self):
        code = ("import sys\n"
                "import software.agent.c2client\n"
                "sys.exit(1 if 'requests' in sys.modules else 0)\n")
        root = str(Path(__file__).parent.parent.parent)
        result = subprocess.run([sys.executable, "-c", code], cwd=root)
        self.assertEqual(result.returncode, 0)

    def test_requirements_txt_gains_no_async_http_library(self):
        req = Path(__file__).parent.parent / "requirements.txt"
        text = req.read_text(encoding="utf-8").lower()
        for name in self._FORBIDDEN:
            self.assertNotIn(name, text)


if __name__ == "__main__":
    unittest.main()
