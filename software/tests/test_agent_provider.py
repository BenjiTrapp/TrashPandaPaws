#!/usr/bin/env python3
"""
Tests for the LLM provider layer: client selection, capability tiers, and the
two wire formats. Nothing here touches the network. Every client is built
with a stub transport, so the tests assert on the request the code *builds*
and the response it *parses* — which is how the wire formats are pinned
without a live API. The one test of the real transport function replaces the
`requests` module wholesale, because importing the real one warns under
-W error on some platforms and would make a network call besides.
"""

import ast
import asyncio
import json
import sys
import traceback
import types
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent.llm import anthropic_client, openai_client, provider

_KEY = "sk-live-SECRET-0123456789abcdef"


def _cfg(provider=None, api_key=None, model=None, base_url=None):
    return types.SimpleNamespace(
        provider=provider, api_key=api_key, model=model, base_url=base_url)


class _Stub:
    """A transport that records its calls and replays queued answers."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, url, headers, body):
        self.calls.append((url, headers, body))
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


def _anthropic(stub, **kw):
    return anthropic_client.AnthropicClient(
        model="claude-sonnet-4", api_key=_KEY, transport=stub, **kw)


def _openai(stub, name="openrouter", api_key=_KEY, **kw):
    return openai_client.OpenAiCompatibleClient(
        provider=name, model="vendor/model", api_key=api_key,
        base_url="https://gateway.example/v1", transport=stub, **kw)


def _run(coro):
    return asyncio.run(coro)


_TOOL = provider.ToolSpec(
    "run_nmap", "Scan a host",
    {"type": "object", "properties": {"host": {"type": "string"}},
     "required": ["host"]})


# ── Client selection ──


class TestClientSelection(unittest.TestCase):
    def test_anthropic_provider(self):
        c = provider.create_client(_cfg(provider="anthropic", api_key="k",
                                        model="claude-sonnet-4"))
        self.assertEqual(c.provider, "anthropic")
        self.assertTrue(c.supports_tools)
        self.assertIsInstance(c, anthropic_client.AnthropicClient)

    def test_openrouter_requires_explicit_model(self):
        with self.assertRaises(provider.ProviderError) as cm:
            provider.create_client(
                _cfg(provider="openrouter", api_key="k", model=None))
        self.assertIn("model", str(cm.exception).lower())

    def test_opencode_zen_uses_openai_protocol(self):
        c = provider.create_client(_cfg(
            provider="opencode", api_key="k", model="grok-code",
            base_url="https://zen.example/v1"))
        self.assertIsInstance(c, openai_client.OpenAiCompatibleClient)

    def test_opencode_without_base_url_says_what_to_set(self):
        with self.assertRaises(provider.ProviderError) as cm:
            provider.create_client(
                _cfg(provider="opencode", api_key="k", model="grok-code"))
        self.assertIn("base_url", str(cm.exception))

    def test_local_provider_needs_no_api_key(self):
        c = provider.create_client(_cfg(provider="local", api_key=None,
                                        model="qwen2.5:14b",
                                        base_url="http://127.0.0.1:11434/v1"))
        self.assertEqual(c.provider, "local")

    def test_local_defaults_to_loopback_ollama(self):
        stub = _Stub({"choices": [{"message": {"content": "x"},
                                   "finish_reason": "stop"}]})
        c = provider.create_client(
            _cfg(provider="local", model="qwen2.5:14b"))
        c._transport = stub
        _run(c.complete("", [{"role": "user", "content": "hi"}], [], 10, 0))
        self.assertEqual(stub.calls[0][0],
                         "http://127.0.0.1:11434/v1/chat/completions")

    def test_openrouter_default_base_url(self):
        stub = _Stub({"choices": [{"message": {"content": "x"},
                                   "finish_reason": "stop"}]})
        c = provider.create_client(
            _cfg(provider="openrouter", api_key="k", model="m"))
        c._transport = stub
        _run(c.complete("", [{"role": "user", "content": "hi"}], [], 10, 0))
        self.assertEqual(stub.calls[0][0],
                         "https://openrouter.ai/api/v1/chat/completions")

    def test_missing_api_key_names_the_provider(self):
        with self.assertRaises(provider.ProviderError) as cm:
            provider.create_client(_cfg(provider="anthropic", api_key=None,
                                        model="claude-sonnet-4"))
        self.assertIn("anthropic", str(cm.exception).lower())

    def test_empty_api_key_counts_as_missing(self):
        with self.assertRaises(provider.ProviderError):
            provider.create_client(_cfg(provider="openrouter", api_key="",
                                        model="m"))

    def test_unknown_provider_lists_the_supported_ones(self):
        with self.assertRaises(provider.ProviderError) as cm:
            provider.create_client(
                _cfg(provider="hal9000", api_key="k", model="m"))
        for name in ("anthropic", "openrouter", "opencode", "local"):
            self.assertIn(name, str(cm.exception))

    def test_no_provider_configured_is_a_clean_error(self):
        with self.assertRaises(provider.ProviderError):
            provider.create_client(
                _cfg(provider=None, api_key=None, model=None))

    def test_provider_name_is_case_insensitive(self):
        c = provider.create_client(
            _cfg(provider=" Anthropic ", api_key="k", model="m"))
        self.assertEqual(c.provider, "anthropic")

    def test_a_key_is_not_sent_over_cleartext_http_to_a_remote_host(self):
        with self.assertRaises(provider.ProviderError) as cm:
            provider.create_client(_cfg(
                provider="openrouter", api_key=_KEY, model="m",
                base_url="http://gateway.example/v1"))
        self.assertNotIn(_KEY, str(cm.exception))

    def test_cleartext_http_is_fine_on_loopback(self):
        provider.create_client(_cfg(
            provider="local", api_key="k", model="m",
            base_url="http://localhost:11434/v1"))

    def test_a_non_http_base_url_is_refused(self):
        with self.assertRaises(provider.ProviderError):
            provider.create_client(_cfg(
                provider="local", model="m", base_url="file:///etc/passwd"))


# ── Capability tiers ──


class TestCapabilityTiers(unittest.TestCase):
    def test_frontier_models_get_full_tier(self):
        for m in ("claude-sonnet-4", "anthropic/claude-sonnet-4", "gpt-4o"):
            self.assertEqual(provider.capability_tier(m, "openrouter"), "full")

    def test_allowlisted_families_across_naming_styles(self):
        for m in ("claude-opus-4-1", "claude-sonnet-4-5-20250929",
                  "anthropic/claude-sonnet-4.5", "claude-opus-5",
                  "openai/gpt-4o-2024-08-06", "gpt-4.1", "gpt-5",
                  "google/gemini-2.5-pro", "gemini-3-pro-preview"):
            self.assertEqual(provider.capability_tier(m, "openrouter"),
                             "full", m)

    def test_models_outside_the_allowlist_are_reduced(self):
        # Older Claude generations, the small siblings of allowlisted
        # families, and families nobody has vetted all fall to reduced.
        for m in ("claude-3-5-sonnet", "claude-3-opus", "claude-haiku-4-5",
                  "gpt-4o-mini", "gpt-4.1-nano", "gpt-5-mini", "gpt-3.5-turbo",
                  "gemini-2.5-flash", "gemini-pro", "gemini-1.5-pro",
                  "meta-llama/llama-3.3-70b-instruct", "grok-code", ""):
            self.assertEqual(provider.capability_tier(m, "openrouter"),
                             "reduced", m)

    def test_digit_suffix_does_not_fake_a_generation(self):
        # "claude-sonnet-20240229" is a date, not generation 20240229.
        self.assertEqual(
            provider.capability_tier("claude-sonnet-20240229", "anthropic"),
            "reduced")

    def test_local_models_are_not_full(self):
        self.assertIn(provider.capability_tier("qwen2.5:14b", "local"),
                      ("reduced", "minimal"))

    def test_local_never_reaches_full_even_under_a_frontier_name(self):
        # The model name on a local endpoint is whatever the operator typed;
        # it vouches for nothing. Overriding is a config decision (Task 7).
        for m in ("claude-sonnet-4", "gpt-4o", "gemini-2.5-pro"):
            self.assertNotEqual(provider.capability_tier(m, "local"), "full")

    def test_small_local_models_are_minimal(self):
        for m in ("qwen2.5:14b", "llama3.1:8b", "phi3:3.8b",
                  "deepseek-r1-distill-qwen-7b", "gemma2:2b",
                  "mixtral-8x3b", "qwen2.5-coder:29b"):
            self.assertEqual(provider.capability_tier(m, "local"),
                             "minimal", m)

    def test_large_or_unsized_local_models_are_reduced(self):
        for m in ("llama3.3:70b", "qwen2.5:32b", "qwen2.5-coder:30b",
                  "mixtral:8x7b", "llama3"):
            self.assertEqual(provider.capability_tier(m, "local"),
                             "reduced", m)

    def test_parameter_count_only_counts_for_local(self):
        self.assertEqual(
            provider.capability_tier("llama-3.1-8b-instruct", "openrouter"),
            "reduced")

    def test_every_answer_is_a_defined_tier(self):
        for m in ("claude-sonnet-4", "qwen2.5:7b", "mystery", "", None):
            for p in ("anthropic", "openrouter", "opencode", "local"):
                self.assertIn(provider.capability_tier(m, p),
                              provider.TIER_LIMITS)

    def test_tier_limits_shrink_monotonically(self):
        full = provider.TIER_LIMITS["full"]
        red = provider.TIER_LIMITS["reduced"]
        mini = provider.TIER_LIMITS["minimal"]
        self.assertGreater(full["orchestrator_turns"], red["orchestrator_turns"])
        self.assertGreater(red["orchestrator_turns"], mini["orchestrator_turns"])
        self.assertGreater(full["truncate_chars"], red["truncate_chars"])
        self.assertGreater(full["max_phase"], red["max_phase"])

    def test_every_limit_shrinks_down_the_whole_ladder(self):
        # TIER_LIMITS is ordered strongest first. Walking the ladder, rather
        # than naming three tiers, is what makes a fourth tier inserted in
        # the wrong place (or with one limit forgotten) fail here.
        rank = {"all": 3, "core": 2, "bare": 1}
        tiers = list(provider.TIER_LIMITS)
        self.assertEqual(tiers[0], "full")
        keys = set(provider.TIER_LIMITS[tiers[0]])
        for t in tiers:
            self.assertEqual(set(provider.TIER_LIMITS[t]), keys, t)
        for stronger, weaker in zip(tiers, tiers[1:]):
            a, b = provider.TIER_LIMITS[stronger], provider.TIER_LIMITS[weaker]
            for k in keys:
                if k == "tool_set":
                    self.assertGreater(rank[a[k]], rank[b[k]],
                                       (stronger, weaker, k))
                else:
                    self.assertGreater(a[k], b[k], (stronger, weaker, k))

    def test_executor_never_gets_more_turns_than_orchestrator(self):
        for name, limits in provider.TIER_LIMITS.items():
            self.assertLessEqual(limits["executor_turns"],
                                 limits["orchestrator_turns"], name)

    def test_only_full_tier_allows_phase_five(self):
        self.assertGreaterEqual(provider.TIER_LIMITS["full"]["max_phase"], 5)
        self.assertLess(provider.TIER_LIMITS["reduced"]["max_phase"], 5)

    def test_phase_five_is_reserved_to_the_strongest_tier(self):
        tiers = list(provider.TIER_LIMITS)
        for t in tiers[1:]:
            self.assertLess(provider.TIER_LIMITS[t]["max_phase"], 5, t)


# ── Anthropic wire format ──
#
# Shape under test: the Anthropic Messages API, POST /v1/messages
# (https://docs.anthropic.com/en/api/messages). Headers x-api-key and
# anthropic-version; system as a top-level string; tool definitions with
# input_schema; tool calls as assistant "tool_use" blocks; results as
# "tool_result" blocks inside a *user* message.


_ANTHROPIC_REPLY = {
    "content": [
        {"type": "text", "text": "Scanning."},
        {"type": "tool_use", "id": "toolu_1", "name": "run_nmap",
         "input": {"host": "10.0.0.5"}},
    ],
    "stop_reason": "tool_use",
    "usage": {"input_tokens": 120, "output_tokens": 30},
}


class TestAnthropicRequest(unittest.TestCase):
    def _call(self, messages, tools=(_TOOL,), **kw):
        stub = _Stub(_ANTHROPIC_REPLY)
        _run(_anthropic(stub, **kw).complete(
            "You are careful.", messages, list(tools), 512, 0.2))
        return stub.calls[0]

    def test_endpoint_and_headers(self):
        url, headers, _ = self._call([{"role": "user", "content": "hi"}])
        self.assertEqual(url, "https://api.anthropic.com/v1/messages")
        self.assertEqual(headers["x-api-key"], _KEY)
        self.assertEqual(headers["anthropic-version"], "2023-06-01")
        self.assertEqual(headers["content-type"], "application/json")
        self.assertNotIn("Authorization", headers)

    def test_custom_base_url(self):
        stub = _Stub(_ANTHROPIC_REPLY)
        c = anthropic_client.AnthropicClient(
            model="m", api_key="k", base_url="https://proxy.example/",
            transport=stub)
        _run(c.complete("", [{"role": "user", "content": "x"}], [], 5, 0))
        self.assertEqual(stub.calls[0][0], "https://proxy.example/v1/messages")

    def test_body_top_level(self):
        _, _, body = self._call([{"role": "user", "content": "hi"}])
        self.assertEqual(body["model"], "claude-sonnet-4")
        self.assertEqual(body["max_tokens"], 512)
        self.assertEqual(body["temperature"], 0.2)
        self.assertEqual(body["system"], "You are careful.")
        self.assertEqual(body["messages"],
                         [{"role": "user", "content": "hi"}])

    def test_tools_use_input_schema(self):
        _, _, body = self._call([{"role": "user", "content": "hi"}])
        self.assertEqual(body["tools"], [{
            "name": "run_nmap", "description": "Scan a host",
            "input_schema": _TOOL.parameters}])

    def test_no_tools_key_when_there_are_none(self):
        _, _, body = self._call([{"role": "user", "content": "hi"}], tools=())
        self.assertNotIn("tools", body)

    def test_empty_system_is_omitted(self):
        stub = _Stub(_ANTHROPIC_REPLY)
        _run(_anthropic(stub).complete(
            "", [{"role": "user", "content": "x"}], [], 5, 0))
        self.assertNotIn("system", stub.calls[0][2])

    def test_tool_round_trip_becomes_content_blocks(self):
        messages = [
            {"role": "user", "content": "scan it"},
            {"role": "assistant", "content": "",
             "tool_calls": [
                 {"id": "toolu_1", "name": "run_nmap",
                  "arguments": {"host": "10.0.0.5"}},
                 {"id": "toolu_2", "name": "run_nmap",
                  "arguments": {"host": "10.0.0.6"}}]},
            {"role": "tool", "tool_call_id": "toolu_1", "content": "open: 22"},
            {"role": "tool", "tool_call_id": "toolu_2", "content": "open: 80"},
            {"role": "user", "content": "and then?"},
        ]
        _, _, body = self._call(messages)
        self.assertEqual(body["messages"], [
            {"role": "user", "content": "scan it"},
            # No empty text block: the API rejects a blank one.
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "toolu_1", "name": "run_nmap",
                 "input": {"host": "10.0.0.5"}},
                {"type": "tool_use", "id": "toolu_2", "name": "run_nmap",
                 "input": {"host": "10.0.0.6"}}]},
            # Both results in ONE user message, results before any text.
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_1",
                 "content": "open: 22"},
                {"type": "tool_result", "tool_use_id": "toolu_2",
                 "content": "open: 80"},
                {"type": "text", "text": "and then?"}]},
        ])

    def test_assistant_text_precedes_its_tool_use_blocks(self):
        _, _, body = self._call([
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": "Scanning.",
             "tool_calls": [{"id": "t", "name": "run_nmap", "arguments": {}}]},
        ])
        self.assertEqual(body["messages"][1]["content"][0],
                         {"type": "text", "text": "Scanning."})

    def test_openai_nested_tool_calls_are_accepted_too(self):
        _, _, body = self._call([
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": "",
             "tool_calls": [{"id": "t", "type": "function", "function": {
                 "name": "run_nmap", "arguments": '{"host": "h"}'}}]},
        ])
        self.assertEqual(body["messages"][1]["content"], [
            {"type": "tool_use", "id": "t", "name": "run_nmap",
             "input": {"host": "h"}}])

    def test_unknown_role_is_a_provider_error(self):
        with self.assertRaises(provider.ProviderError) as cm:
            self._call([{"role": "system", "content": "x"}])
        self.assertIn("anthropic", str(cm.exception))


class TestAnthropicResponse(unittest.TestCase):
    def _complete(self, reply):
        return _run(_anthropic(_Stub(reply)).complete(
            "", [{"role": "user", "content": "x"}], [], 5, 0))

    def test_text_tool_call_and_usage(self):
        c = self._complete(_ANTHROPIC_REPLY)
        self.assertEqual(c.text, "Scanning.")
        self.assertEqual(c.tool_calls, [
            provider.ToolCall("toolu_1", "run_nmap", {"host": "10.0.0.5"})])
        self.assertEqual((c.input_tokens, c.output_tokens, c.total_tokens),
                         (120, 30, 150))
        self.assertEqual(c.stop_reason, "tool_use")

    def test_stop_reasons_use_the_shared_vocabulary(self):
        for vendor, ours in (("end_turn", "end_turn"),
                             ("max_tokens", "max_tokens"),
                             ("tool_use", "tool_use"),
                             ("stop_sequence", "stop_sequence")):
            c = self._complete({"content": [], "stop_reason": vendor,
                                "usage": {}})
            self.assertEqual(c.stop_reason, ours)

    def test_unhandled_block_types_are_ignored(self):
        c = self._complete({"content": [
            {"type": "thinking", "thinking": "hmm"},
            {"type": "text", "text": "ok"}], "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}})
        self.assertEqual(c.text, "ok")

    def test_tool_input_that_is_not_an_object_is_marked(self):
        c = self._complete({"content": [
            {"type": "tool_use", "id": "t", "name": "n", "input": "oops"}],
            "stop_reason": "tool_use", "usage": {}})
        self.assertIn(provider.ARGUMENTS_ERROR_KEY, c.tool_calls[0].arguments)

    def test_unexpected_shape_is_a_provider_error_without_the_body(self):
        with self.assertRaises(provider.ProviderError) as cm:
            self._complete({"unexpected": "BODY-CANARY"})
        self.assertIn("anthropic", str(cm.exception))
        self.assertNotIn("BODY-CANARY", str(cm.exception))


# ── OpenAI-compatible wire format ──
#
# Shape under test: Chat Completions, POST {base_url}/chat/completions
# (https://platform.openai.com/docs/api-reference/chat). Bearer auth; system
# as the first message; tools as {"type": "function", "function": {...}};
# assistant tool_calls whose function.arguments is a JSON *string*; results
# as role "tool" messages carrying tool_call_id.


def _oa_reply(message, finish="stop", usage=None):
    reply = {"choices": [{"message": message, "finish_reason": finish}]}
    if usage is not None:
        reply["usage"] = usage
    return reply


class TestOpenAiRequest(unittest.TestCase):
    def _call(self, messages, tools=(_TOOL,), **kw):
        stub = _Stub(_oa_reply({"content": "ok"}))
        _run(_openai(stub, **kw).complete(
            "You are careful.", messages, list(tools), 512, 0.2))
        return stub.calls[0]

    def test_endpoint_and_headers(self):
        url, headers, _ = self._call([{"role": "user", "content": "hi"}])
        self.assertEqual(url, "https://gateway.example/v1/chat/completions")
        self.assertEqual(headers["Authorization"], "Bearer " + _KEY)
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_no_authorization_header_without_a_key(self):
        stub = _Stub(_oa_reply({"content": "ok"}))
        _run(_openai(stub, name="local", api_key=None).complete(
            "", [{"role": "user", "content": "x"}], [], 5, 0))
        self.assertNotIn("Authorization", stub.calls[0][1])

    def test_system_prompt_is_the_first_message(self):
        _, _, body = self._call([{"role": "user", "content": "hi"}])
        self.assertEqual(body["messages"], [
            {"role": "system", "content": "You are careful."},
            {"role": "user", "content": "hi"}])
        self.assertEqual(body["model"], "vendor/model")
        self.assertEqual(body["max_tokens"], 512)
        self.assertEqual(body["temperature"], 0.2)

    def test_empty_system_adds_no_message(self):
        stub = _Stub(_oa_reply({"content": "ok"}))
        _run(_openai(stub).complete(
            "", [{"role": "user", "content": "x"}], [], 5, 0))
        self.assertEqual(stub.calls[0][2]["messages"][0]["role"], "user")

    def test_tools_are_wrapped_as_functions(self):
        _, _, body = self._call([{"role": "user", "content": "hi"}])
        self.assertEqual(body["tools"], [{
            "type": "function",
            "function": {"name": "run_nmap", "description": "Scan a host",
                         "parameters": _TOOL.parameters}}])

    def test_no_tools_key_when_there_are_none(self):
        _, _, body = self._call([{"role": "user", "content": "hi"}], tools=())
        self.assertNotIn("tools", body)

    def test_a_client_without_tool_support_sends_no_tools(self):
        stub = _Stub(_oa_reply({"content": "ok"}))
        c = _openai(stub, supports_tools=False)
        self.assertFalse(c.supports_tools)
        _run(c.complete("", [{"role": "user", "content": "x"}],
                        [_TOOL], 5, 0))
        self.assertNotIn("tools", stub.calls[0][2])

    def test_tool_calls_get_json_string_arguments(self):
        _, _, body = self._call([
            {"role": "user", "content": "scan it"},
            {"role": "assistant", "content": "",
             "tool_calls": [{"id": "call_1", "name": "run_nmap",
                             "arguments": {"host": "10.0.0.5"}}]},
            {"role": "tool", "tool_call_id": "call_1", "content": "open: 22"},
        ])
        assistant = body["messages"][2]
        call = assistant["tool_calls"][0]
        self.assertEqual(call["id"], "call_1")
        self.assertEqual(call["type"], "function")
        self.assertEqual(call["function"]["name"], "run_nmap")
        self.assertIsInstance(call["function"]["arguments"], str)
        self.assertEqual(json.loads(call["function"]["arguments"]),
                         {"host": "10.0.0.5"})
        self.assertEqual(body["messages"][3], {
            "role": "tool", "tool_call_id": "call_1", "content": "open: 22"})

    def test_already_nested_tool_calls_pass_through(self):
        nested = {"id": "c", "type": "function", "function": {
            "name": "run_nmap", "arguments": '{"host": "h"}'}}
        _, _, body = self._call([
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": "", "tool_calls": [nested]}])
        self.assertEqual(body["messages"][2]["tool_calls"], [nested])

    def test_unknown_role_is_a_provider_error(self):
        with self.assertRaises(provider.ProviderError) as cm:
            self._call([{"role": "wizard", "content": "x"}])
        self.assertIn("openrouter", str(cm.exception))


class TestOpenAiResponse(unittest.TestCase):
    def _complete(self, reply):
        return _run(_openai(_Stub(reply)).complete(
            "", [{"role": "user", "content": "x"}], [], 5, 0))

    def _call_with_arguments(self, arguments):
        return self._complete(_oa_reply(
            {"content": None, "tool_calls": [
                {"id": "call_1", "type": "function",
                 "function": {"name": "run_nmap", "arguments": arguments}}]},
            finish="tool_calls"))

    def test_text_and_usage(self):
        c = self._complete(_oa_reply(
            {"content": "hello"}, usage={"prompt_tokens": 7,
                                         "completion_tokens": 3,
                                         "total_tokens": 10}))
        self.assertEqual(c.text, "hello")
        self.assertEqual(c.tool_calls, [])
        self.assertEqual((c.input_tokens, c.output_tokens, c.total_tokens),
                         (7, 3, 10))
        self.assertEqual(c.stop_reason, "end_turn")

    def test_missing_usage_is_zero_not_an_error(self):
        c = self._complete(_oa_reply({"content": "hi"}))
        self.assertEqual((c.input_tokens, c.output_tokens, c.total_tokens),
                         (0, 0, 0))

    def test_total_is_derived_when_the_server_omits_it(self):
        c = self._complete(_oa_reply(
            {"content": "hi"}, usage={"prompt_tokens": 7,
                                      "completion_tokens": 3}))
        self.assertEqual(c.total_tokens, 10)

    def test_string_arguments_are_parsed_to_a_dict(self):
        c = self._call_with_arguments('{"host": "10.0.0.5", "ports": [22]}')
        self.assertEqual(c.text, "")
        self.assertEqual(c.tool_calls, [provider.ToolCall(
            "call_1", "run_nmap", {"host": "10.0.0.5", "ports": [22]})])
        self.assertEqual(c.stop_reason, "tool_use")

    def test_object_arguments_are_accepted(self):
        # Some local servers return the object rather than a string.
        c = self._call_with_arguments({"host": "h"})
        self.assertEqual(c.tool_calls[0].arguments, {"host": "h"})

    def test_empty_arguments_mean_no_arguments(self):
        for raw in ("", "   ", "{}"):
            c = self._call_with_arguments(raw)
            self.assertEqual(c.tool_calls[0].arguments, {}, repr(raw))

    def test_malformed_arguments_are_marked_not_dropped(self):
        c = self._call_with_arguments('{"host": "10.0.0.5"')  # unterminated
        args = c.tool_calls[0].arguments
        self.assertIn(provider.ARGUMENTS_ERROR_KEY, args)
        self.assertIn("JSON", args[provider.ARGUMENTS_ERROR_KEY])
        self.assertEqual(args[provider.RAW_ARGUMENTS_KEY],
                         '{"host": "10.0.0.5"')
        # The call itself survives, so the loop can answer it by id.
        self.assertEqual(c.tool_calls[0].id, "call_1")
        self.assertEqual(c.tool_calls[0].name, "run_nmap")

    def test_malformed_arguments_do_not_fall_back_to_empty(self):
        # {} would let a tool run with defaults the model never chose.
        c = self._call_with_arguments("not json at all")
        self.assertNotEqual(c.tool_calls[0].arguments, {})

    def test_valid_json_that_is_not_an_object_is_marked(self):
        for raw in ("[1, 2]", '"text"', "42", "null"):
            c = self._call_with_arguments(raw)
            self.assertIn(provider.ARGUMENTS_ERROR_KEY,
                          c.tool_calls[0].arguments, raw)

    def test_the_raw_text_kept_in_the_marker_is_bounded(self):
        c = self._call_with_arguments("{" + "x" * 10000)
        raw = c.tool_calls[0].arguments[provider.RAW_ARGUMENTS_KEY]
        self.assertLessEqual(len(raw), 300)

    def test_one_bad_call_does_not_spoil_the_good_one(self):
        c = self._complete(_oa_reply({"content": "", "tool_calls": [
            {"id": "a", "type": "function",
             "function": {"name": "n", "arguments": "{bad"}},
            {"id": "b", "type": "function",
             "function": {"name": "n", "arguments": '{"k": 1}'}}]},
            finish="tool_calls"))
        self.assertIn(provider.ARGUMENTS_ERROR_KEY, c.tool_calls[0].arguments)
        self.assertEqual(c.tool_calls[1].arguments, {"k": 1})

    def test_missing_tool_call_id_is_synthesised(self):
        c = self._complete(_oa_reply({"content": "", "tool_calls": [
            {"type": "function",
             "function": {"name": "n", "arguments": "{}"}}]}))
        self.assertTrue(c.tool_calls[0].id)

    def test_finish_reasons_use_the_shared_vocabulary(self):
        for vendor, ours in (("stop", "end_turn"), ("length", "max_tokens"),
                             ("tool_calls", "tool_use"),
                             ("content_filter", "content_filter")):
            c = self._complete(_oa_reply({"content": "x"}, finish=vendor))
            self.assertEqual(c.stop_reason, ours)

    def test_unexpected_shape_is_a_provider_error_without_the_body(self):
        for reply in ({"error": {"message": "BODY-CANARY"}},
                      {"choices": []}):
            with self.assertRaises(provider.ProviderError) as cm:
                self._complete(reply)
            self.assertIn("openrouter", str(cm.exception))
            self.assertNotIn("BODY-CANARY", str(cm.exception))


# ── Errors and credential hygiene ──


class TestErrorsNameProviderAndModelNotTheKey(unittest.TestCase):
    def _fail(self, client):
        with self.assertRaises(provider.ProviderError) as cm:
            _run(client.complete(
                "", [{"role": "user", "content": "x"}], [], 5, 0))
        return cm.exception

    def _clients(self, exc):
        return (_anthropic(_Stub(exc)), _openai(_Stub(exc)))

    def test_error_names_provider_and_model(self):
        err = self._fail(_anthropic(_Stub(provider.TransportError("HTTP 500"))))
        self.assertIn("anthropic", str(err))
        self.assertIn("claude-sonnet-4", str(err))
        self.assertIn("HTTP 500", str(err))

    def test_key_never_appears_when_the_transport_blows_up(self):
        # A requests exception can carry the URL and headers; model the worst
        # case, a message that contains the key in several formats.
        nasty = RuntimeError(
            "POST https://x/?key=%s failed; headers {'x-api-key': '%s', "
            "'Authorization': 'Bearer %s'}" % (_KEY, _KEY, _KEY))
        for client in self._clients(nasty):
            err = self._fail(client)
            self.assertNotIn(_KEY, str(err))
            self.assertNotIn(_KEY, repr(err))
            self.assertNotIn(_KEY, repr(err.args))
            rendered = "".join(traceback.format_exception(
                type(err), err, err.__traceback__))
            self.assertNotIn(_KEY, rendered)
            self.assertIn("RuntimeError", str(err))  # the class, only

    def test_the_original_exception_is_not_chained(self):
        for client in self._clients(RuntimeError(_KEY)):
            err = self._fail(client)
            self.assertIsNone(err.__cause__)
            self.assertTrue(err.__suppress_context__)

    def test_key_is_absent_from_every_rendering_of_a_client(self):
        for client in (_anthropic(_Stub()), _openai(_Stub())):
            self.assertNotIn(_KEY, repr(client))
            self.assertNotIn(_KEY, str(client))
            self.assertNotIn(_KEY, repr(vars(client)))
            self.assertIn(client.model, repr(client))

    def test_key_is_absent_from_construction_errors(self):
        with self.assertRaises(provider.ProviderError) as cm:
            provider.create_client(_cfg(provider="opencode", api_key=_KEY,
                                        model="m"))
        self.assertNotIn(_KEY, str(cm.exception))


class TestRealTransport(unittest.TestCase):
    """The default transport, against a fake `requests` module."""

    class _RequestException(Exception):
        pass

    def _fake_requests(self, post):
        mod = types.ModuleType("requests")
        mod.RequestException = self._RequestException
        mod.post = post
        return mod

    def _resp(self, status=200, payload=None, text="", json_error=False):
        def _json():
            if json_error:
                raise ValueError("no json " + text)
            return payload
        return types.SimpleNamespace(status_code=status, text=text, json=_json)

    def _post(self, post, url="https://x/y", body=None):
        fake = self._fake_requests(post)
        with unittest.mock.patch.dict(sys.modules, {"requests": fake}):
            return provider.http_post_json(
                url, {"x-api-key": _KEY}, body or {"a": 1})

    def test_success_returns_the_parsed_json(self):
        post = unittest.mock.Mock(return_value=self._resp(payload={"ok": 1}))
        self.assertEqual(self._post(post), {"ok": 1})

    def test_request_is_sent_without_following_redirects(self):
        # A redirect would forward a custom auth header such as x-api-key to
        # whichever host answered.
        post = unittest.mock.Mock(return_value=self._resp(payload={}))
        self._post(post)
        _, kwargs = post.call_args
        self.assertIs(kwargs["allow_redirects"], False)
        self.assertEqual(kwargs["json"], {"a": 1})
        self.assertEqual(kwargs["headers"], {"x-api-key": _KEY})
        self.assertGreater(kwargs["timeout"], 0)

    def test_a_requests_exception_does_not_leak_through(self):
        post = unittest.mock.Mock(side_effect=self._RequestException(
            "url https://x/?k=%s headers Authorization: Bearer %s"
            % (_KEY, _KEY)))
        with self.assertRaises(provider.TransportError) as cm:
            self._post(post)
        self.assertNotIn(_KEY, str(cm.exception))
        self.assertNotIn("https://x", str(cm.exception))
        self.assertIsNone(cm.exception.__cause__)
        self.assertTrue(cm.exception.__suppress_context__)

    def test_an_http_error_reports_the_status_not_the_body(self):
        # Servers do echo the Authorization header in error bodies.
        post = unittest.mock.Mock(return_value=self._resp(
            status=401, text='{"error": "bad key %s"}' % _KEY))
        with self.assertRaises(provider.TransportError) as cm:
            self._post(post)
        self.assertIn("401", str(cm.exception))
        self.assertNotIn(_KEY, str(cm.exception))

    def test_a_redirect_is_an_error(self):
        post = unittest.mock.Mock(return_value=self._resp(status=302))
        with self.assertRaises(provider.TransportError) as cm:
            self._post(post)
        self.assertIn("302", str(cm.exception))

    def test_a_non_json_body_is_an_error_without_the_body(self):
        post = unittest.mock.Mock(return_value=self._resp(
            text="BODY-" + _KEY, json_error=True))
        with self.assertRaises(provider.TransportError) as cm:
            self._post(post)
        self.assertNotIn(_KEY, str(cm.exception))
        self.assertNotIn("BODY-", str(cm.exception))

    def test_a_json_body_that_is_not_an_object_is_an_error(self):
        post = unittest.mock.Mock(return_value=self._resp(payload=[1, 2]))
        with self.assertRaises(provider.TransportError):
            self._post(post)

    def test_the_client_default_transport_is_the_real_one(self):
        c = anthropic_client.AnthropicClient(model="m", api_key="k")
        self.assertIs(c._transport, provider.http_post_json)


# ── Status quo: no SDK, no new dependency, no import-time cost ──


class TestNoNewDependencies(unittest.TestCase):
    _FORBIDDEN = {"anthropic", "openai", "httpx", "aiohttp"}

    def test_no_llm_module_imports_a_vendor_sdk_or_async_http_library(self):
        llm_dir = Path(provider.__file__).parent
        for path in sorted(llm_dir.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [node.module or ""]
                else:
                    continue
                for name in names:
                    self.assertNotIn(name.split(".")[0], self._FORBIDDEN,
                                     "%s imports %s" % (path.name, name))

    def test_requests_is_not_imported_until_a_request_is_made(self):
        # The agent package must import on a machine where requests is
        # absent or noisy; only an actual call may need it.
        import subprocess
        code = ("import sys\n"
                "import software.agent.llm.provider\n"
                "import software.agent.llm.anthropic_client\n"
                "import software.agent.llm.openai_client\n"
                "sys.exit(1 if 'requests' in sys.modules else 0)\n")
        root = str(Path(__file__).parent.parent.parent)
        result = subprocess.run([sys.executable, "-c", code], cwd=root)
        self.assertEqual(result.returncode, 0)

    def test_requirements_txt_gains_no_sdk(self):
        req = Path(__file__).parent.parent / "requirements.txt"
        text = req.read_text(encoding="utf-8").lower()
        for name in self._FORBIDDEN:
            self.assertNotIn(name, text)


if __name__ == "__main__":
    unittest.main()
