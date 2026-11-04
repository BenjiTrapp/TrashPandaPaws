#!/usr/bin/env python3
"""
Tests for the tool-calling loop and its mock client: truncation, turn
structure, the five ways a tool call can fail without taking the run down,
the text-protocol fallback for models without native tool calling, and the
interaction log. Nothing here touches the network; the one test that uses a
real client gives it a stub transport.
"""

import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest import IsolatedAsyncioTestCase

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent.control import ControlSignal
from software.agent.executor import router
from software.agent import gate
from software.agent.llm import loop, mock, openai_client, provider
from software.agent.llm.provider import Completion, ToolCall, ToolSpec
from software.agent.store import db, queries


# ── Helpers ──

def _tool(name, fn, params):
    """A Tool whose spec requires every parameter in `params` (name -> type)."""
    spec = ToolSpec(name, "test tool %s" % name, {
        "type": "object",
        "properties": {k: {"type": v} for k, v in params.items()},
        "required": list(params)})
    return loop.Tool(spec, fn)


class _CapturingMock(mock.MockClient):
    """Records what the loop sent, so tests can assert on the model's view."""

    def __init__(self, captured, responses, supports_tools=True):
        super().__init__(responses, supports_tools=supports_tools)
        self._captured = captured
        captured.update(systems=[], tool_messages=[], user_messages=[])

    async def complete(self, system, messages, tools, max_tokens, temperature):
        c = self._captured
        c["systems"].append(system)
        c["tool_names"] = [t.name for t in tools]
        if messages[-1]["role"] == "tool":
            # The trailing run of tool messages is the previous turn's answers.
            batch = []
            for m in reversed(messages):
                if m["role"] != "tool":
                    break
                batch.insert(0, m)
            c["tool_messages"] = batch
            c["last_tool_result"] = batch[-1]["content"]
        elif messages[-1]["role"] == "user":
            c["user_messages"].append(messages[-1]["content"])
        return await super().complete(system, messages, tools, max_tokens,
                                      temperature)


def _capturing_mock(captured, responses, supports_tools=True):
    return _CapturingMock(captured, responses, supports_tools)


def _fresh_run():
    conn = db.open_store(":memory:")
    return conn, queries.create_run(conn, "campaign", None, "auto", "{}")


def _bad_call(call_id="bad1", name="echo", raw="{not json"):
    """A tool call as the real clients produce it from unreadable arguments."""
    return provider.normalize_tool_call(
        {"id": call_id, "name": name, "arguments": raw})


def _completion(calls, text=""):
    return Completion(text, calls, 100, 20, 120, "tool_use")


async def _noop():
    return {}


# ── Truncation ──

class TestTruncation(unittest.TestCase):
    def test_short_output_untouched(self):
        out, trunc = loop.truncate("kurz", 4000)
        self.assertEqual(out, "kurz")
        self.assertFalse(trunc)

    def test_output_exactly_at_the_limit_is_untouched(self):
        out, trunc = loop.truncate("A" * 4000, 4000)
        self.assertFalse(trunc)
        self.assertEqual(len(out), 4000)

    def test_long_output_keeps_head_and_tail(self):
        src = "A" * 3000 + "B" * 3000
        out, trunc = loop.truncate(src, 4000)
        self.assertTrue(trunc)
        self.assertTrue(out.startswith("A" * 2000))
        self.assertTrue(out.endswith("B" * 2000))
        self.assertIn("OUTPUT TRUNCATED", out)

    def test_truncation_counts_characters_not_bytes(self):
        """Non-ASCII must not be cut mid-character, nor counted by bytes."""
        # 6000 characters is over the 4000 limit, like the ASCII case above.
        # (3000 would be under it, and not truncate at all.) In UTF-8 this is
        # 12000 bytes, so a byte count would also cut at the wrong place.
        src = "ü" * 6000
        out, trunc = loop.truncate(src, 4000)
        self.assertTrue(trunc)
        self.assertEqual(out.count("ü"), 4000)
        self.assertTrue(out.startswith("ü" * 2000))
        self.assertTrue(out.endswith("ü" * 2000))

    def test_marker_reports_how_much_was_omitted(self):
        out, _ = loop.truncate("x" * 5000, 4000)
        self.assertIn("1000", out)

    def test_zero_limit_does_not_return_the_whole_text(self):
        # text[-0:] is the whole string; a naive tail slice would defeat the cap.
        out, trunc = loop.truncate("x" * 50, 0)
        self.assertTrue(trunc)
        self.assertNotIn("x", out)


# ── Mock client ──

class TestMockClient(IsolatedAsyncioTestCase):
    async def test_empty_queue_raises_assertion_error_naming_the_problem(self):
        c = mock.MockClient([mock.text("one")])
        await c.complete("s", [], [], 10, 0.0)
        with self.assertRaises(AssertionError) as ctx:
            await c.complete("s", [], [], 10, 0.0)
        self.assertIn("no responses left", str(ctx.exception))

    async def test_remaining_counts_down(self):
        c = mock.MockClient([mock.text("a"), mock.text("b")])
        self.assertEqual(c.remaining, 2)
        await c.complete("s", [], [], 10, 0.0)
        self.assertEqual(c.remaining, 1)

    async def test_constructor_list_is_not_consumed(self):
        queued = [mock.text("a")]
        mock.MockClient(queued)
        self.assertEqual(len(queued), 1)

    def test_supports_tools_defaults_true_and_is_settable(self):
        self.assertTrue(mock.MockClient([]).supports_tools)
        self.assertFalse(mock.MockClient([], supports_tools=False).supports_tools)

    def test_text_and_calls_builders(self):
        t = mock.text("hi", total_tokens=300)
        self.assertEqual((t.text, t.tool_calls, t.total_tokens), ("hi", [], 300))
        self.assertEqual(t.input_tokens + t.output_tokens, 300)
        c = mock.calls(("a", {"x": 1}), ("b", {}))
        self.assertEqual([(x.name, x.arguments) for x in c.tool_calls],
                         [("a", {"x": 1}), ("b", {})])
        self.assertEqual(len({x.id for x in c.tool_calls}), 2)
        self.assertEqual(c.stop_reason, "tool_use")
        self.assertEqual(c.total_tokens, 120)

    async def test_failing_client_raises_provider_error(self):
        with self.assertRaises(provider.ProviderError) as ctx:
            await mock.FailingClient("kein Kontakt").complete("s", [], [], 1, 0.0)
        self.assertIn("kein Kontakt", str(ctx.exception))


# ── Turn structure ──

class TestBasicLoop(IsolatedAsyncioTestCase):
    async def test_text_only_response_returns_immediately(self):
        c = mock.MockClient([mock.text("fertig")])
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[],
                                        max_turns=8), "fertig")
        self.assertEqual(c.remaining, 0)

    async def test_tool_call_then_text(self):
        seen = []

        async def echo(value):
            seen.append(value)
            return {"echoed": value}
        t = _tool("echo", echo, {"value": "string"})
        c = mock.MockClient([mock.calls(("echo", {"value": "hi"})), mock.text("ok")])
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[t],
                                        max_turns=8), "ok")
        self.assertEqual(seen, ["hi"])

    async def test_parallel_tool_calls_in_one_turn_all_execute(self):
        seen = []

        async def note(n):
            seen.append(n)
            return {"ok": n}
        t = _tool("note", note, {"n": "string"})
        c = mock.MockClient([
            mock.calls(("note", {"n": "a"}), ("note", {"n": "b"})),
            mock.text("done")])
        await loop.run(c, system="s", prompt="p", tools=[t], max_turns=8)
        self.assertEqual(sorted(seen), ["a", "b"])

    async def test_calls_in_one_turn_run_concurrently(self):
        gate = asyncio.Event()

        async def first():
            await gate.wait()
            return {"who": "first"}

        async def second():
            gate.set()
            return {"who": "second"}
        tools = [_tool("first", first, {}), _tool("second", second, {})]
        c = mock.MockClient([mock.calls(("first", {}), ("second", {})),
                             mock.text("done")])
        # Sequential execution would wait on the gate forever.
        out = await asyncio.wait_for(
            loop.run(c, system="s", prompt="p", tools=tools, max_turns=4), 5)
        self.assertEqual(out, "done")

    async def test_results_map_back_to_the_call_that_produced_them(self):
        """The same tool twice in a turn: each id gets its own answer."""
        async def slow_echo(value, delay):
            await asyncio.sleep(delay)
            return {"echoed": value}
        t = _tool("echo", slow_echo, {"value": "string", "delay": "number"})
        captured = {}
        c = _capturing_mock(captured, [
            mock.calls(("echo", {"value": "first", "delay": 0.05}),
                       ("echo", {"value": "second", "delay": 0})),
            mock.text("done")])
        await loop.run(c, system="s", prompt="p", tools=[t], max_turns=4)
        by_id = {m["tool_call_id"]: json.loads(m["content"])["echoed"]
                 for m in captured["tool_messages"]}
        self.assertEqual(by_id, {"mock_call_0": "first", "mock_call_1": "second"})
        # And the answers keep the order the model asked in.
        self.assertEqual([m["tool_call_id"] for m in captured["tool_messages"]],
                         ["mock_call_0", "mock_call_1"])

    async def test_system_prompt_and_tool_specs_reach_the_client(self):
        async def ok():
            return {}
        captured = {}
        c = _capturing_mock(captured, [mock.text("x")])
        await loop.run(c, system="be brief", prompt="p",
                       tools=[_tool("ok", ok, {})], max_turns=2)
        self.assertEqual(captured["systems"], ["be brief"])
        self.assertEqual(captured["tool_names"], ["ok"])
        self.assertEqual(captured["user_messages"], ["p"])

    async def test_no_task_is_left_pending(self):
        async def boom():
            raise RuntimeError("x")
        tools = [_tool("boom", boom, {}), _tool("ok", _noop, {})]
        c = mock.MockClient([mock.calls(("boom", {}), ("ok", {}), ("nope", {})),
                             mock.text("done")])
        await loop.run(c, system="s", prompt="p", tools=tools, max_turns=4)
        others = asyncio.all_tasks() - {asyncio.current_task()}
        self.assertEqual(others, set())

    async def test_works_with_a_real_client_over_a_stub_transport(self):
        requests = []
        replies = [
            {"choices": [{"message": {"content": None, "tool_calls": [
                {"id": "c1", "type": "function", "function": {
                    "name": "echo", "arguments": '{"value": "hi"}'}}]},
                "finish_reason": "tool_calls"}], "usage": {}},
            {"choices": [{"message": {"content": "fertig"},
                          "finish_reason": "stop"}], "usage": {}},
        ]

        def transport(url, headers, body):
            requests.append(body)
            return replies[len(requests) - 1]

        async def echo(value):
            return {"echoed": value}
        client = openai_client.OpenAiCompatibleClient(
            "local", "m", None, "http://127.0.0.1:11434/v1", transport)
        out = await loop.run(client, system="s", prompt="p",
                             tools=[_tool("echo", echo, {"value": "string"})],
                             max_turns=4)
        self.assertEqual(out, "fertig")
        tool_msg = requests[1]["messages"][-1]
        self.assertEqual(tool_msg["role"], "tool")
        self.assertEqual(tool_msg["tool_call_id"], "c1")
        self.assertEqual(json.loads(tool_msg["content"]), {"echoed": "hi"})


# ── Failing tool calls ──

class TestBrokenToolCalling(IsolatedAsyncioTestCase):
    """Every tool failure is answered to the model by call id, never raised."""

    async def test_unknown_tool_name_returns_error_and_continues(self):
        c = mock.MockClient([mock.calls(("nope", {})), mock.text("weiter")])
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[],
                                        max_turns=8), "weiter")

    async def test_unknown_tool_error_names_the_available_tools(self):
        captured = {}
        t = _tool("real_tool", _noop, {})
        c = _capturing_mock(captured, [mock.calls(("nope", {})), mock.text("x")])
        await loop.run(c, system="s", prompt="p", tools=[t], max_turns=8)
        result = json.loads(captured["last_tool_result"])
        self.assertEqual(result["error"], "unknown tool 'nope'")
        self.assertEqual(result["available"], ["real_tool"])
        self.assertEqual(captured["tool_messages"][0]["tool_call_id"], "mock_call_0")

    async def test_missing_required_argument_is_reported_not_raised(self):
        entered = []

        async def needs(value):
            entered.append(value)
            return {"v": value}
        t = _tool("needs", needs, {"value": "string"})
        captured = {}
        c = _capturing_mock(captured, [mock.calls(("needs", {})), mock.text("weiter")])
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[t],
                                        max_turns=8), "weiter")
        self.assertEqual(entered, [])
        self.assertIn("value", json.loads(captured["last_tool_result"])["error"])

    async def test_tool_raising_is_reported_not_raised(self):
        async def boom():
            raise RuntimeError("kaputt")
        t = _tool("boom", boom, {})
        captured = {}
        c = _capturing_mock(captured, [mock.calls(("boom", {})), mock.text("weiter")])
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[t],
                                        max_turns=8), "weiter")
        self.assertEqual(json.loads(captured["last_tool_result"]),
                         {"error": "RuntimeError: kaputt"})

    async def test_unexpected_extra_argument_is_rejected_cleanly(self):
        entered = []

        async def one(value):
            entered.append(value)
            return {"v": value}
        t = _tool("one", one, {"value": "string"})
        captured = {}
        c = _capturing_mock(captured, [
            mock.calls(("one", {"value": "a", "bogus": 1})), mock.text("weiter")])
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[t],
                                        max_turns=8), "weiter")
        self.assertEqual(entered, [])
        self.assertIn("bogus", json.loads(captured["last_tool_result"])["error"])

    async def test_one_failure_does_not_spoil_the_other_calls_in_the_turn(self):
        async def boom():
            raise ValueError("nein")

        async def fine():
            return {"fine": True}
        tools = [_tool("boom", boom, {}), _tool("fine", fine, {})]
        captured = {}
        c = _capturing_mock(captured, [
            mock.calls(("boom", {}), ("fine", {}), ("nope", {})),
            mock.text("weiter")])
        await loop.run(c, system="s", prompt="p", tools=tools, max_turns=8)
        results = [json.loads(m["content"]) for m in captured["tool_messages"]]
        self.assertEqual(results[0], {"error": "ValueError: nein"})
        self.assertEqual(results[1], {"fine": True})
        self.assertIn("unknown tool", results[2]["error"])

    async def test_unserialisable_result_is_reported_not_raised(self):
        async def cyclic():
            d = {}
            d["self"] = d
            return d
        captured = {}
        c = _capturing_mock(captured, [mock.calls(("cyclic", {})), mock.text("ok")])
        out = await loop.run(c, system="s", prompt="p",
                             tools=[_tool("cyclic", cyclic, {})], max_turns=4)
        self.assertEqual(out, "ok")
        self.assertIn("error", json.loads(captured["last_tool_result"]))

    async def test_oversized_tool_result_is_truncated(self):
        async def big():
            return {"blob": "x" * 20000}
        captured = {}
        c = _capturing_mock(captured, [mock.calls(("big", {})), mock.text("ok")])
        await loop.run(c, system="s", prompt="p", tools=[_tool("big", big, {})],
                       max_turns=4, truncate_chars=1000)
        self.assertIn("OUTPUT TRUNCATED", captured["last_tool_result"])
        self.assertLess(len(captured["last_tool_result"]), 1400)


# ── Calls whose arguments could not be read ──

class TestUnreadableArguments(IsolatedAsyncioTestCase):
    """ToolCall.error is checked; the sentinel keys are only the backstop."""

    async def test_call_with_error_is_answered_and_the_tool_is_never_entered(self):
        entered = []

        async def echo(value="default"):
            entered.append(value)
            return {"echoed": value}
        # value has a default, so a dispatcher that ignored the error and
        # passed an empty dict would run it happily on that default.
        t = _tool("echo", echo, {})
        call = _bad_call("bad1", "echo", "{not json")
        self.assertIsNotNone(call.error)
        captured = {}
        c = _capturing_mock(captured, [_completion([call]), mock.text("weiter")])
        out = await loop.run(c, system="s", prompt="p", tools=[t], max_turns=4)
        self.assertEqual(out, "weiter")
        self.assertEqual(entered, [])
        (msg,) = captured["tool_messages"]
        self.assertEqual(msg["tool_call_id"], "bad1")
        self.assertIn("not valid JSON", json.loads(msg["content"])["error"])

    async def test_arguments_that_are_not_an_object_are_refused_too(self):
        entered = []

        async def echo(value="default"):
            entered.append(value)
            return {}
        call = _bad_call("bad2", "echo", "[1, 2]")
        captured = {}
        c = _capturing_mock(captured, [_completion([call]), mock.text("x")])
        await loop.run(c, system="s", prompt="p",
                       tools=[_tool("echo", echo, {})], max_turns=4)
        self.assertEqual(entered, [])
        self.assertIn("not an object",
                      json.loads(captured["last_tool_result"])["error"])

    async def test_error_is_checked_even_when_the_arguments_look_fine(self):
        """The field is the contract, not the sentinel keys in the dict."""
        entered = []

        async def echo(value="default"):
            entered.append(value)
            return {}
        call = ToolCall("x1", "echo", {}, error="arguments were unreadable")
        captured = {}
        c = _capturing_mock(captured, [_completion([call]), mock.text("x")])
        await loop.run(c, system="s", prompt="p",
                       tools=[_tool("echo", echo, {})], max_turns=4)
        self.assertEqual(entered, [])
        self.assertIn("unreadable", captured["last_tool_result"])

    async def test_well_formed_call_beside_a_bad_one_still_dispatches(self):
        seen = []

        async def echo(value):
            seen.append(value)
            return {"echoed": value}
        t = _tool("echo", echo, {"value": "string"})
        good = ToolCall("good1", "echo", {"value": "hi"})
        bad = _bad_call("bad1", "echo", "{oops")
        captured = {}
        c = _capturing_mock(captured, [_completion([bad, good]), mock.text("x")])
        await loop.run(c, system="s", prompt="p", tools=[t], max_turns=4)
        self.assertEqual(seen, ["hi"])
        by_id = {m["tool_call_id"]: json.loads(m["content"])
                 for m in captured["tool_messages"]}
        self.assertIn("error", by_id["bad1"])
        self.assertEqual(by_id["good1"], {"echoed": "hi"})

    async def test_unreadable_call_to_an_unknown_tool_reports_the_arguments(self):
        # Both things are wrong; one answer, and it must not dispatch.
        call = _bad_call("bad3", "nope", "{")
        captured = {}
        c = _capturing_mock(captured, [_completion([call]), mock.text("x")])
        await loop.run(c, system="s", prompt="p", tools=[], max_turns=4)
        self.assertIn("error", json.loads(captured["last_tool_result"]))


# ── Turn budget ──

class TestTurnBudget(IsolatedAsyncioTestCase):
    async def test_exhausted_budget_returns_marker_not_exception(self):
        t = _tool("spin", _noop, {})
        c = mock.MockClient([mock.calls(("spin", {}))] * 10)
        out = await loop.run(c, system="s", prompt="p", tools=[t], max_turns=3)
        self.assertIn("MAX_TURNS", out)
        self.assertIn("after 3 turns", out)
        self.assertEqual(c.remaining, 7)

    async def test_marker_carries_the_last_text(self):
        t = _tool("spin", _noop, {})
        c = mock.MockClient([_completion([ToolCall("a", "spin", {})], "thinking")])
        out = await loop.run(c, system="s", prompt="p", tools=[t], max_turns=1)
        self.assertEqual(out, "[MAX_TURNS reached after 1 turns]\nthinking")

    async def test_budget_counts_completions_not_tool_calls(self):
        t = _tool("spin", _noop, {})
        c = mock.MockClient([mock.calls(("spin", {}), ("spin", {})),
                             mock.text("fertig")])
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[t],
                                        max_turns=2), "fertig")


# ── Text-protocol fallback ──

class TestTextProtocolFallback(IsolatedAsyncioTestCase):
    async def test_parses_tool_block_from_plain_text(self):
        seen = []

        async def echo(value):
            seen.append(value)
            return {"ok": True}
        t = _tool("echo", echo, {"value": "string"})
        c = mock.MockClient(
            [mock.text('TOOL_CALL\n{"name": "echo", "arguments": {"value": "hi"}}\nEND'),
             mock.text("fertig")], supports_tools=False)
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[t],
                                        max_turns=8), "fertig")
        self.assertEqual(seen, ["hi"])

    async def test_system_prompt_gets_the_protocol_and_the_tool_list(self):
        t = _tool("echo", _noop, {"value": "string"})
        captured = {}
        c = _capturing_mock(captured, [mock.text("x")], supports_tools=False)
        await loop.run(c, system="be brief", prompt="p", tools=[t], max_turns=2)
        sent = captured["systems"][0]
        self.assertTrue(sent.startswith("be brief"))
        self.assertIn("TOOL_CALL", sent)
        self.assertIn("END", sent)
        self.assertIn("echo", sent)
        self.assertIn("test tool echo", sent)

    async def test_native_clients_get_the_system_prompt_untouched(self):
        captured = {}
        c = _capturing_mock(captured, [mock.text("x")])
        await loop.run(c, system="be brief", prompt="p", tools=[], max_turns=2)
        self.assertEqual(captured["systems"], ["be brief"])

    async def test_results_come_back_as_a_user_message(self):
        # A server with no tool support has no "tool" role to receive them.
        async def echo(value):
            return {"echoed": value}
        t = _tool("echo", echo, {"value": "string"})
        captured = {}
        c = _capturing_mock(captured, [
            mock.text('TOOL_CALL\n{"name": "echo", "arguments": {"value": "hi"}}\nEND'),
            mock.text("fertig")], supports_tools=False)
        await loop.run(c, system="s", prompt="p", tools=[t], max_turns=4)
        self.assertEqual(captured["tool_messages"], [])
        self.assertEqual(len(captured["user_messages"]), 2)
        self.assertIn('"echoed": "hi"', captured["user_messages"][1])

    async def test_several_blocks_in_one_reply_all_run_in_order(self):
        seen = []

        async def note(n):
            seen.append(n)
            return {}
        t = _tool("note", note, {"n": "string"})
        text = ('I will do two things.\n'
                'TOOL_CALL\n{"name": "note", "arguments": {"n": "a"}}\nEND\n'
                'TOOL_CALL\n{"name": "note", "arguments": {"n": "b"}}\nEND\n')
        c = mock.MockClient([mock.text(text), mock.text("fertig")],
                            supports_tools=False)
        await loop.run(c, system="s", prompt="p", tools=[t], max_turns=4)
        self.assertEqual(sorted(seen), ["a", "b"])

    async def test_end_inside_a_json_string_does_not_close_the_block(self):
        seen = []

        async def echo(value):
            seen.append(value)
            return {}
        t = _tool("echo", echo, {"value": "string"})
        c = mock.MockClient([
            mock.text('TOOL_CALL\n{"name": "echo", "arguments": {"value": "THE END"}}\nEND'),
            mock.text("fertig")], supports_tools=False)
        await loop.run(c, system="s", prompt="p", tools=[t], max_turns=4)
        self.assertEqual(seen, ["THE END"])

    async def test_malformed_json_in_block_is_reported_and_loop_continues(self):
        async def echo(value):
            return {}
        t = _tool("echo", echo, {"value": "string"})
        captured = {}
        c = _capturing_mock(captured, [mock.text("TOOL_CALL\n{nicht json}\nEND"),
                                       mock.text("fertig")], supports_tools=False)
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[t],
                                        max_turns=8), "fertig")
        self.assertIn("not valid JSON", captured["user_messages"][1])

    async def test_blocks_that_are_not_well_formed_calls_are_never_dispatched(self):
        entered = []

        async def echo(value="default"):
            entered.append(value)
            return {}
        t = _tool("echo", echo, {})
        bodies = ['[1, 2]',
                  '{"arguments": {"value": "x"}}',
                  '{"name": 7, "arguments": {}}',
                  '{"name": "echo", "arguments": "value=x"}']
        for body in bodies:
            captured = {}
            c = _capturing_mock(captured, [
                mock.text("TOOL_CALL\n%s\nEND" % body), mock.text("fertig")],
                supports_tools=False)
            out = await loop.run(c, system="s", prompt="p", tools=[t], max_turns=4)
            self.assertEqual(out, "fertig")
            self.assertIn("error", captured["user_messages"][1], body)
        self.assertEqual(entered, [])

    async def test_text_without_block_is_treated_as_final_answer(self):
        c = mock.MockClient([mock.text("nur prosa")], supports_tools=False)
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[],
                                        max_turns=8), "nur prosa")

    async def test_end_inside_an_argument_does_not_close_the_block(self):
        # This is the property the line-anchored pattern exists for, and it
        # holds because that pattern is tried first. The earlier version of
        # this test asserted a consequence instead — that a single-line block
        # is not a block at all — which is a different claim and is no longer
        # true; see test_a_single_line_block_is_still_honoured.
        entered = []

        async def echo(value="d"):
            entered.append(value)
            return {}
        c = mock.MockClient(
            [mock.text('TOOL_CALL\n{"name": "echo", "arguments": '
                       '{"value": "END"}}\nEND'),
             mock.text("fertig")], supports_tools=False)
        out = await loop.run(c, system="s", prompt="p",
                             tools=[_tool("echo", echo, {"value": "string"})],
                             max_turns=4)
        self.assertEqual(out, "fertig")
        self.assertEqual(entered, ["END"])

    async def test_a_single_line_block_is_still_honoured(self):
        # The fallback exists for models too weak for native tool calling,
        # and those are the ones that put both markers on one line. Refusing
        # the shape made the fallback fail for its own audience.
        entered = []

        async def echo(value="d"):
            entered.append(value)
            return {}
        c = mock.MockClient(
            [mock.text('TOOL_CALL {"name": "echo", '
                       '"arguments": {"value": "hi"}} END'),
             mock.text("fertig")], supports_tools=False)
        out = await loop.run(c, system="s", prompt="p",
                             tools=[_tool("echo", echo, {"value": "string"})],
                             max_turns=4)
        self.assertEqual(out, "fertig")
        self.assertEqual(entered, ["hi"])

    async def test_an_unclosed_block_is_corrected_not_returned_as_an_answer(self):
        # Returning the raw attempt would hand the caller a TOOL_CALL string
        # as if it were a result. The nudge costs one turn and the model can
        # act on it.
        captured = {}

        async def echo(value="d"):
            return {}
        c = _capturing_mock(captured, [
            mock.text('TOOL_CALL\n{"name": "echo", "arguments": {"value": "hi"}}'),
            mock.text("fertig")], supports_tools=False)
        out = await loop.run(c, system="s", prompt="p",
                             tools=[_tool("echo", echo, {"value": "string"})],
                             max_turns=4)
        self.assertEqual(out, "fertig")
        # A client with no tool support has no "tool" role, so the loop sends
        # results back as a user message; that is where the nudge lands.
        self.assertIn("own line", captured["user_messages"][-1])

    async def test_prose_that_merely_mentions_the_marker_is_corrected(self):
        # The cost of this one: a reply that talks about TOOL_CALL without
        # using it spends a turn being corrected. Accepted, because the
        # alternative is returning a half-written call as the final answer.
        async def echo(value="d"):
            return {}
        c = mock.MockClient([mock.text("I will use TOOL_CALL in a moment"),
                             mock.text("fertig")], supports_tools=False)
        out = await loop.run(c, system="s", prompt="p",
                             tools=[_tool("echo", echo, {"value": "string"})],
                             max_turns=4)
        self.assertEqual(out, "fertig")

    async def test_plain_prose_is_still_a_final_answer(self):
        c = mock.MockClient([mock.text("nur prosa")], supports_tools=False)
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[],
                                        max_turns=4), "nur prosa")


# ── Observability ──

class TestObservability(IsolatedAsyncioTestCase):
    async def test_each_completion_is_logged_with_tokens(self):
        conn, rid = _fresh_run()
        c = mock.MockClient([mock.text("fertig", total_tokens=300)])
        await loop.run(c, system="s", prompt="p", tools=[], max_turns=8,
                       conn=conn, run_id=rid, caller_context="orchestrator")
        row = conn.execute("SELECT caller_context, status, total_tokens, run_id, "
                           "provider, model FROM llm_interactions").fetchone()
        self.assertEqual(row["caller_context"], "orchestrator")
        self.assertEqual(row["status"], "success")
        self.assertEqual(row["total_tokens"], 300)
        self.assertEqual(row["run_id"], rid)
        self.assertEqual((row["provider"], row["model"]), (c.provider, c.model))

    async def test_one_row_per_completion(self):
        conn, rid = _fresh_run()
        t = _tool("spin", _noop, {})
        c = mock.MockClient([mock.calls(("spin", {})), mock.calls(("spin", {})),
                             mock.text("fertig")])
        await loop.run(c, system="s", prompt="p", tools=[t], max_turns=8,
                       conn=conn, run_id=rid)
        count = conn.execute("SELECT COUNT(*) FROM llm_interactions").fetchone()[0]
        self.assertEqual(count, 3)

    async def test_off_still_writes_the_row_but_not_the_text(self):
        conn, rid = _fresh_run()
        await loop.run(mock.MockClient([mock.text("antwort")]), system="s",
                       prompt="geheim", tools=[], max_turns=8,
                       conn=conn, run_id=rid, log_level="off")
        row = conn.execute("SELECT * FROM llm_interactions").fetchone()
        self.assertEqual(row["status"], "success")
        self.assertEqual(row["total_tokens"], 120)
        self.assertIsNone(row["prompt_text"])
        self.assertIsNone(row["response_text"])

    async def test_default_log_level_is_off(self):
        conn, rid = _fresh_run()
        await loop.run(mock.MockClient([mock.text("antwort")]), system="s",
                       prompt="geheim", tools=[], max_turns=8,
                       conn=conn, run_id=rid)
        row = conn.execute("SELECT * FROM llm_interactions").fetchone()
        self.assertIsNotNone(row)
        self.assertIsNone(row["prompt_text"])
        self.assertIsNone(row["response_text"])

    async def test_prompt_text_only_persisted_at_full_level(self):
        conn, rid = _fresh_run()
        await loop.run(mock.MockClient([mock.text("x")]), system="s", prompt="geheim",
                       tools=[], max_turns=8, conn=conn, run_id=rid, log_level="off")
        self.assertIsNone(
            conn.execute("SELECT prompt_text FROM llm_interactions").fetchone()[0])
        await loop.run(mock.MockClient([mock.text("x")]), system="s", prompt="geheim",
                       tools=[], max_turns=8, conn=conn, run_id=rid, log_level="full")
        texts = [r[0] for r in conn.execute("SELECT prompt_text FROM llm_interactions")]
        self.assertIn("geheim", "".join(t or "" for t in texts))

    async def test_full_level_stores_the_response_too(self):
        conn, rid = _fresh_run()
        await loop.run(mock.MockClient([mock.text("die antwort")]), system="sys",
                       prompt="p", tools=[], max_turns=8,
                       conn=conn, run_id=rid, log_level="full")
        row = conn.execute("SELECT prompt_text, response_text "
                           "FROM llm_interactions").fetchone()
        self.assertIn("die antwort", row["response_text"])
        self.assertIn("sys", row["prompt_text"])

    async def test_unrecognised_log_level_does_not_persist_text(self):
        # A typo must fail toward not writing a credential-bearing prompt.
        conn, rid = _fresh_run()
        await loop.run(mock.MockClient([mock.text("x")]), system="s",
                       prompt="geheim", tools=[], max_turns=8,
                       conn=conn, run_id=rid, log_level="ful")
        self.assertIsNone(
            conn.execute("SELECT prompt_text FROM llm_interactions").fetchone()[0])

    async def test_provider_error_is_logged_as_error_row(self):
        conn, rid = _fresh_run()
        with self.assertRaises(provider.ProviderError):
            await loop.run(mock.FailingClient("kein Kontakt"), system="s", prompt="p",
                           tools=[], max_turns=8, conn=conn, run_id=rid)
        row = conn.execute("SELECT status, error_message FROM llm_interactions").fetchone()
        self.assertEqual(row["status"], "error")
        self.assertIn("kein Kontakt", row["error_message"])

    async def test_without_a_connection_nothing_is_logged_and_nothing_fails(self):
        out = await loop.run(mock.MockClient([mock.text("fertig")]), system="s",
                             prompt="p", tools=[], max_turns=8, run_id=1,
                             log_level="full")
        self.assertEqual(out, "fertig")

    async def test_without_a_run_id_nothing_is_logged_and_nothing_fails(self):
        conn, _ = _fresh_run()
        out = await loop.run(mock.MockClient([mock.text("fertig")]), system="s",
                             prompt="p", tools=[], max_turns=8, conn=conn)
        self.assertEqual(out, "fertig")
        count = conn.execute("SELECT COUNT(*) FROM llm_interactions").fetchone()[0]
        self.assertEqual(count, 0)

    async def test_provider_error_without_a_connection_still_propagates(self):
        with self.assertRaises(provider.ProviderError):
            await loop.run(mock.FailingClient("down"), system="s", prompt="p",
                           tools=[], max_turns=8)



class TestControlSignalsEscapeTheLoop(IsolatedAsyncioTestCase):
    """Two things must not become a tool result the model reads and ignores.

    The detection budget is an abort condition, not a statistic (spec
    §10.6), and an operator pause is an instruction. Both were raised by a
    tool and swallowed by the loop's catch-all, so the run carried on after
    the budget was measured as spent. They are a ControlSignal now, and the
    loop re-raises anything deriving from it.
    """

    def _tool(self, fn):
        return loop.Tool(
            spec=provider.ToolSpec(
                name="act", description="d",
                parameters={"type": "object", "properties": {}}),
            fn=fn)

    async def _run(self, fn):
        client = mock.MockClient(
            [mock.calls(("act", {})), mock.text("carried on")])
        return await loop.run(client, system="s", prompt="p",
                              tools=[self._tool(fn)], max_turns=4)

    async def test_a_control_signal_propagates(self):
        class Stop(ControlSignal):
            pass

        async def abort():
            raise Stop("budget spent")
        with self.assertRaises(Stop):
            await self._run(abort)

    async def test_the_routers_abort_propagates(self):
        async def abort():
            raise router.RouterAborted("budget spent")
        with self.assertRaises(router.RouterAborted):
            await self._run(abort)

    async def test_the_gates_pause_propagates(self):
        async def pause():
            raise gate.GatePauseRequested("lsass_dump")
        with self.assertRaises(gate.GatePauseRequested):
            await self._run(pause)

    async def test_an_ordinary_failure_is_still_a_tool_result(self):
        async def boom():
            raise RuntimeError("just a bad step")
        self.assertEqual(await self._run(boom), "carried on")

    async def test_one_control_signal_among_several_calls_still_escapes(self):
        async def ok():
            return {"ok": True}

        async def abort():
            raise router.RouterAborted("budget spent")
        tools = [
            loop.Tool(spec=provider.ToolSpec(
                name="fine", description="d",
                parameters={"type": "object", "properties": {}}), fn=ok),
            self._tool(abort)]
        client = mock.MockClient(
            [mock.calls(("fine", {}), ("act", {})), mock.text("carried on")])
        with self.assertRaises(router.RouterAborted):
            await loop.run(client, system="s", prompt="p", tools=tools,
                           max_turns=4)

if __name__ == "__main__":
    unittest.main()
