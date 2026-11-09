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
import copy
import json
import os
import sys
import tempfile
import threading
import traceback
import types
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent.llm import (bedrock_client, anthropic_client, gcp_token,
                                openai_client, provider)

_KEY = "sk-live-SECRET-0123456789abcdef"


def _cfg(provider=None, api_key=None, model=None, base_url=None,
         vertex_project=None, vertex_location="europe-west4",
         token_source="auto", api_key_file=None, static_bearer=False):
    return types.SimpleNamespace(
        provider=provider, api_key=api_key, model=model, base_url=base_url,
        vertex_project=vertex_project, vertex_location=vertex_location,
        token_source=token_source, api_key_file=api_key_file,
        static_bearer=static_bearer)


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


def _walk_chain(exc) -> str:
    """Everything a hand-written error serialiser could reach from `exc`.

    Walks the exception chain and, at each link, the attributes that carry
    request state. A crash reporter that does this is the one path `from
    None` does not cover.
    """
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

    def test_ollama_defaults_to_loopback_and_needs_no_key(self):
        c = provider.create_client(_cfg(provider="ollama", model="qwen2.5:14b"))
        self.assertEqual(c.provider, "ollama")
        self.assertIsInstance(c, openai_client.OpenAiCompatibleClient)
        stub = _Stub({"choices": [{"message": {"content": "hi"}}]})
        c._transport = stub
        _run(c.complete("", [{"role": "user", "content": "x"}], [], 16, 0.0))
        self.assertEqual(stub.calls[0][0],
                         "http://127.0.0.1:11434/v1/chat/completions")
        self.assertNotIn("Authorization", stub.calls[0][1])

    def test_ollama_is_a_local_provider(self):
        self.assertIn("ollama", provider.LOCAL_PROVIDERS)
        self.assertIn("local", provider.LOCAL_PROVIDERS)

    def test_a_local_provider_gets_the_long_timeout(self):
        c = provider.create_client(_cfg(provider="ollama", model="qwen2.5:14b"))
        self.assertEqual(c._timeout, provider.LOCAL_TIMEOUT_SECONDS)

    def test_a_remote_provider_keeps_the_default_timeout(self):
        c = provider.create_client(_cfg(provider="openrouter", api_key="k",
                                        model="vendor/model"))
        self.assertEqual(c._timeout, provider._TIMEOUT_SECONDS)

    def test_an_injected_transport_is_kept_as_given(self):
        stub = _Stub({"choices": [{"message": {"content": "hi"}}]})
        c = openai_client.OpenAiCompatibleClient(
            provider="ollama", model="m", api_key=None,
            base_url="http://127.0.0.1:11434/v1", transport=stub)
        self.assertIs(c._transport, stub)

    def test_gemini_posts_to_the_openai_compatible_endpoint(self):
        c = provider.create_client(_cfg(provider="gemini", api_key=_KEY,
                                        model="gemini-3-pro"))
        stub = _Stub({"choices": [{"message": {"content": "hi"}}]})
        c._transport = stub
        _run(c.complete("", [{"role": "user", "content": "x"}], [], 16, 0.0))
        url, headers, _ = stub.calls[0]
        self.assertEqual(url, "https://generativelanguage.googleapis.com"
                              "/v1beta/openai/chat/completions")
        self.assertEqual(headers["Authorization"], "Bearer " + _KEY)

    def test_gemini_requires_a_key(self):
        with self.assertRaises(provider.ProviderError) as cm:
            provider.create_client(_cfg(provider="gemini", api_key=None,
                                        model="gemini-3-pro"))
        self.assertIn("requires an api_key", str(cm.exception))
        self.assertNotIn(_KEY, str(cm.exception))


# ── Capability tiers ──


class TestABrokenToolCallCannotBeDispatchedByAccident(unittest.TestCase):
    """A malformed `arguments` must be impossible to miss, not merely visible.

    The next task writes the dispatcher. Returning `{}` would let a tool run
    on its defaults with parameters the model never chose, and a convention
    that the dispatcher "must remember to check a key" is the kind that gets
    forgotten. So two independent mechanisms carry the failure: the sentinel
    keys make a `**arguments` dispatch raise, and `ToolCall.error` puts it in
    the type for a dispatcher that passes the dict whole.
    """

    def _broken(self, raw):
        return provider.normalize_tool_call(
            {"id": "c1", "function": {"name": "run_cmd", "arguments": raw}})

    def test_the_error_is_a_field_not_only_a_key(self):
        for raw in ("{not json", "[1, 2]", '"a string"', "17", 17, []):
            call = self._broken(raw)
            self.assertIsNotNone(call.error, repr(raw))
            self.assertEqual(call.error,
                             call.arguments[provider.ARGUMENTS_ERROR_KEY])

    def test_a_kwargs_dispatch_raises(self):
        def run_cmd(cmd):
            return cmd
        call = self._broken("{not json")
        with self.assertRaises(TypeError):
            run_cmd(**call.arguments)

    def test_a_whole_dict_dispatch_has_the_field_to_check(self):
        # The failure mode this guards: a tool that reads arguments.get(...)
        # would otherwise run with None and never know why.
        call = self._broken("{not json")
        self.assertIsNone(call.arguments.get("cmd"))
        self.assertTrue(call.error)

    def test_a_good_call_carries_no_error(self):
        call = provider.normalize_tool_call(
            {"id": "c1", "function": {"name": "run_cmd",
                                      "arguments": '{"cmd": "id"}'}})
        self.assertIsNone(call.error)
        self.assertEqual(call.arguments, {"cmd": "id"})

    def test_an_empty_argument_list_is_not_an_error(self):
        for raw in ("", "   ", "{}", None, {}):
            call = self._broken(raw)
            self.assertIsNone(call.error, repr(raw))
            self.assertEqual(call.arguments, {})

    def test_the_raw_text_is_bounded_and_kept(self):
        call = self._broken("{" + "x" * 5000)
        self.assertLessEqual(
            len(call.arguments[provider.RAW_ARGUMENTS_KEY]), 200)
        self.assertIn("x", call.arguments[provider.RAW_ARGUMENTS_KEY])

    def test_the_anthropic_path_sets_the_field_too(self):
        # Anthropic sends `input` as an object, so the failure shape differs:
        # a non-object input is the case that reaches here.
        client = provider.create_client(_cfg(
            provider="anthropic", api_key="k", model="claude-sonnet-4"))
        payload = {"content": [{"type": "tool_use", "id": "t1",
                                "name": "run_cmd", "input": "not an object"}],
                   "usage": {"input_tokens": 1, "output_tokens": 1},
                   "stop_reason": "tool_use"}
        completion = client._parse_response(payload)
        self.assertIsNotNone(completion.tool_calls[0].error)


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

    def test_gemini_pro_is_full_and_the_small_variants_are_not(self):
        # Pinned, not earned: flash and lite fall out through _SMALL_VARIANT.
        # A free flash model must never reach "full", which permits phase 5.
        self.assertEqual(provider.capability_tier("gemini-3-pro", "gemini"),
                         "full")
        self.assertEqual(provider.capability_tier("gemini-3-pro-preview",
                                                  "gemini"), "full")
        for small in ("gemini-3-flash", "gemini-2.5-flash-lite"):
            self.assertEqual(provider.capability_tier(small, "gemini"),
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

    def test_a_local_provider_never_reaches_full_on_its_model_name(self):
        for name in sorted(provider.LOCAL_PROVIDERS):
            self.assertEqual(provider.capability_tier("gpt-4o", name),
                             "reduced")

    def test_a_small_model_on_any_local_provider_is_minimal(self):
        for name in sorted(provider.LOCAL_PROVIDERS):
            self.assertEqual(provider.capability_tier("qwen2.5:14b", name),
                             "minimal")

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
        # Asserting the property, not the mechanism. `from None` only sets
        # __suppress_context__, which hides the original from every standard
        # rendering while leaving it on the object — and a transport
        # exception can hold the request headers. The failure is raised once
        # the except block has exited, so there is no chain to suppress.
        for client in self._clients(RuntimeError(_KEY)):
            err = self._fail(client)
            self.assertIsNone(err.__cause__)
            self.assertIsNone(err.__context__)
            self.assertNotIn(_KEY, _walk_chain(err))

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
        # The RequestException holds a .request whose .headers carry the key,
        # so the chain has to be empty rather than merely hidden.
        self.assertIsNone(cm.exception.__context__)
        self.assertNotIn(_KEY, _walk_chain(cm.exception))

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

    def test_the_transport_timeout_is_per_client(self):
        seen = {}

        class _FakeRequests:
            class RequestException(Exception):
                pass

            @staticmethod
            def post(url, headers=None, json=None, timeout=None,
                     allow_redirects=None):
                seen["timeout"] = timeout
                raise _FakeRequests.RequestException()

        with unittest.mock.patch.dict(sys.modules,
                                      {"requests": _FakeRequests}):
            with self.assertRaises(provider.TransportError):
                provider.http_post_json("https://x.example", {}, {},
                                        timeout=7)
        self.assertEqual(seen["timeout"], 7)

    def _timeout_on_the_wire(self, client):
        """The timeout `requests.post` receives for one client turn."""
        seen = {}

        class _FakeRequests:
            class RequestException(Exception):
                pass

            @staticmethod
            def post(url, headers=None, json=None, timeout=None,
                     allow_redirects=None):
                seen["timeout"] = timeout
                raise _FakeRequests.RequestException()

        with unittest.mock.patch.dict(sys.modules,
                                      {"requests": _FakeRequests}):
            with self.assertRaises(provider.ProviderError):
                _run(client.complete("", [{"role": "user", "content": "x"}],
                                     [], 16, 0.0))
        return seen["timeout"]

    def test_a_local_client_sends_300_seconds_on_the_wire(self):
        c = provider.create_client(_cfg(provider="ollama", model="qwen2.5:14b"))
        self.assertEqual(self._timeout_on_the_wire(c), 300)

    def test_a_remote_client_sends_120_seconds_on_the_wire(self):
        c = provider.create_client(_cfg(provider="openrouter", api_key="k",
                                        model="vendor/model"))
        self.assertEqual(self._timeout_on_the_wire(c), 120)

    def test_a_client_sends_its_own_timeout_on_the_wire(self):
        c = openai_client.OpenAiCompatibleClient(
            provider="ollama", model="m", api_key=None,
            base_url="http://127.0.0.1:11434/v1", timeout=7)
        self.assertEqual(self._timeout_on_the_wire(c), 7)


class _FakeSource:
    kind = "fake"

    def __init__(self, *tokens):
        self.tokens = list(tokens)
        self.calls = 0
        self.threads = []

    def bearer(self):
        self.calls += 1
        self.threads.append(threading.get_ident())
        if isinstance(self.tokens[0], BaseException):
            raise self.tokens[0]
        return self.tokens.pop(0) if len(self.tokens) > 1 else self.tokens[0]


def _vertex(source, stub):
    return openai_client.OpenAiCompatibleClient(
        provider="vertex", model="google/gemini-3-pro", api_key=None,
        base_url="https://x-aiplatform.googleapis.com/v1/p/openapi",
        transport=stub, token_source=source)


_TURN = ("", [{"role": "user", "content": "x"}], [], 16, 0.0)


class TestATokenSourceSuppliesTheCredential(unittest.TestCase):
    def test_a_token_source_supplies_the_authorization_header(self):
        src = _FakeSource("tok-first", "tok-second")
        stub = _Stub({"choices": [{"message": {"content": "a"}}]},
                     {"choices": [{"message": {"content": "b"}}]})
        c = _vertex(src, stub)
        _run(c.complete(*_TURN))
        _run(c.complete(*_TURN))
        self.assertEqual(stub.calls[0][1]["Authorization"], "Bearer tok-first")
        self.assertEqual(stub.calls[1][1]["Authorization"],
                         "Bearer tok-second")

    def test_the_token_is_resolved_off_the_event_loop(self):
        src = _FakeSource("tok")
        c = _vertex(src, _Stub({"choices": [{"message": {"content": "a"}}]}))
        _run(c.complete(*_TURN))
        self.assertNotEqual(src.threads, [threading.get_ident()])

    def test_the_resolved_token_stays_out_of_the_repr(self):
        src = _FakeSource("tok-SECRET-value")
        c = _vertex(src, _Stub({"choices": [{"message": {"content": "a"}}]}))
        _run(c.complete(*_TURN))
        self.assertNotIn("tok-SECRET-value", repr(c))
        self.assertNotIn("tok-SECRET-value", repr(c._bearer))

    def test_a_token_source_failure_is_a_provider_error_naming_the_model(self):
        src = _FakeSource(gcp_token.TokenUnavailable("no source answered"))
        stub = _Stub()
        c = _vertex(src, stub)
        with self.assertRaises(provider.ProviderError) as cm:
            _run(c.complete(*_TURN))
        self.assertIn("google/gemini-3-pro", str(cm.exception))
        self.assertEqual(
            _walk_chain(cm.exception).count("no source answered"), 1)
        self.assertEqual(stub.calls, [])

    def test_a_token_source_failure_leaves_no_exception_chain(self):
        for failure in (gcp_token.TokenUnavailable("no source answered"),
                        RuntimeError("Bearer tok-LEAK in a library message")):
            with self.subTest(failure=type(failure).__name__):
                c = _vertex(_FakeSource(failure), _Stub())
                with self.assertRaises(provider.ProviderError) as cm:
                    _run(c.complete(*_TURN))
                self.assertIsNone(cm.exception.__context__)
                self.assertIsNone(cm.exception.__cause__)
                self.assertNotIn("tok-LEAK", _walk_chain(cm.exception))

    def test_a_client_without_a_token_source_keeps_its_key(self):
        stub = _Stub({"choices": [{"message": {"content": "a"}}]})
        _run(_openai(stub).complete(*_TURN))
        self.assertEqual(stub.calls[0][1]["Authorization"], "Bearer " + _KEY)

    def test_the_token_wins_over_a_key_given_to_the_same_client(self):
        # A key and a source together is a configuration that happens (an
        # explicit token_source beats a key that was left in the environment),
        # and a stale key winning would send a credential the operator had
        # replaced.
        stub = _Stub({"choices": [{"message": {"content": "a"}}]})
        c = openai_client.OpenAiCompatibleClient(
            provider="vertex", model="google/m", api_key=_KEY,
            base_url="https://x-aiplatform.googleapis.com/v1/p/openapi",
            transport=stub, token_source=_FakeSource("tok-from-source"))
        _run(c.complete(*_TURN))
        self.assertEqual(stub.calls[0][1]["Authorization"],
                         "Bearer tok-from-source")

    def test_a_failed_resolution_keeps_the_previous_bearer(self):
        # Not cleared: the next turn gets a fresh try, and nothing between
        # the two may find the client holding an empty credential.
        src = _FakeSource("tok-first")
        c = _vertex(src, _Stub({"choices": [{"message": {"content": "a"}}]}))
        _run(c.complete(*_TURN))
        src.tokens = [gcp_token.TokenUnavailable("gone")]
        with self.assertRaises(provider.ProviderError):
            _run(c.complete(*_TURN))
        self.assertEqual(c._bearer.reveal(), "tok-first")


class TestCleartextGuardCountsATokenSource(unittest.TestCase):
    def test_a_token_source_counts_as_a_credential_for_the_cleartext_guard(
            self):
        with self.assertRaises(provider.ProviderError) as cm:
            provider._checked_base_url("vertex", "http://proxy.example/v1",
                                       has_credential=True)
        self.assertIn("https", str(cm.exception))

    def test_no_credential_at_all_may_use_plain_http(self):
        url = "http://proxy.example/v1"
        self.assertEqual(provider._checked_base_url("local", url, has_credential=False), url)


# ── vertex ──

_HOSTILE_IDENTIFIERS = (
    "", " ", "a", "-proj", "proj-", "Proj", "EU_WEST", "eu west4", "eu\twest4",
    "proj\n", "proj\nx", "\nproj", "proj\r\nHost: evil.example",
    "proj.evil.example", "europe-west4.evil.example", "proj/x", "eu/../x",
    "../../admin", "..", "proj?x=1", "proj#x", "proj@evil.example",
    "evil.example@proj", "proj:8443", "proj\\x", "proj%2fx", "proj%2e%2e",
    "proj\x00", "pr\u043ej", "\uff50roj", "proj\u2024evil", "x" * 64,
)


class TestTheVertexEndpointIsComputedAndValidated(unittest.TestCase):
    def test_the_vertex_endpoint_is_computed_from_project_and_location(self):
        self.assertEqual(
            provider.vertex_base_url("my-proj", "europe-west4"),
            "https://europe-west4-aiplatform.googleapis.com/v1/projects/"
            "my-proj/locations/europe-west4/endpoints/openapi")

    def test_a_different_location_moves_both_places_it_appears(self):
        url = provider.vertex_base_url("my-proj", "us-central1")
        self.assertEqual(url.count("us-central1"), 2)
        self.assertNotIn("europe", url)

    def test_the_longest_and_shortest_identifiers_are_accepted(self):
        for ok in ("ab", "x" * 63, "a1-b2", "0abc"):
            provider.vertex_base_url(ok, ok)

    def test_a_location_that_would_move_the_host_is_refused(self):
        for bad in _HOSTILE_IDENTIFIERS:
            with self.subTest(location=bad):
                with self.assertRaises(provider.ProviderError) as cm:
                    provider.vertex_base_url("proj", bad)
                self.assertIn("vertex_location", str(cm.exception))

    def test_a_project_that_would_move_the_path_is_refused(self):
        for bad in _HOSTILE_IDENTIFIERS:
            with self.subTest(project=bad):
                with self.assertRaises(provider.ProviderError) as cm:
                    provider.vertex_base_url(bad, "europe-west4")
                self.assertIn("vertex_project", str(cm.exception))

    def test_a_value_that_is_not_a_string_is_refused(self):
        for bad in (None, 7, b"proj", ["proj"]):
            with self.subTest(value=bad):
                with self.assertRaises(provider.ProviderError):
                    provider.vertex_base_url(bad, "europe-west4")
                with self.assertRaises(provider.ProviderError):
                    provider.vertex_base_url("proj", bad)

    def test_nothing_accepted_can_change_the_host_or_leave_the_path(self):
        # The property the validation exists for, checked on what it lets
        # through rather than on a list of what it should stop.
        for value in ("a1", "us-central1", "x" * 63, "0-0"):
            parts = provider.urlparse(provider.vertex_base_url(value, value))
            self.assertEqual(parts.hostname, value + "-aiplatform.googleapis.com")
            self.assertEqual(parts.scheme, "https")
            self.assertEqual(parts.path.split("/")[1:6],
                             ["v1", "projects", value, "locations", value])
            self.assertEqual((parts.query, parts.fragment, parts.username,
                              parts.port), ("", "", None, None))


class TestCreateClientBuildsVertex(unittest.TestCase):
    def setUp(self):
        # token_source="gcloud" is checked against PATH at construction, and
        # the machine running the suite may have no gcloud.
        patch = unittest.mock.patch.object(
            gcp_token.shutil, "which", return_value="/usr/bin/gcloud")
        patch.start()
        self.addCleanup(patch.stop)

    def _vertex(self, **kw):
        values = dict(provider="vertex", model="google/gemini-3-pro",
                      vertex_project="proj", token_source="gcloud")
        values.update(kw)
        return provider.create_client(_cfg(**values))

    def test_a_vertex_model_without_a_publisher_prefix_is_refused(self):
        for bare in ("gemini-3-pro", "/gemini-3-pro", "google/", "google",
                     "Google/gemini", "g o/x", "google//x"):
            with self.subTest(model=bare):
                with self.assertRaises(provider.ProviderError) as cm:
                    self._vertex(model=bare)
                self.assertIn("google/", str(cm.exception))

    def test_other_publishers_are_accepted(self):
        for model in ("meta/llama-3.3-70b-instruct-maas",
                      "anthropic/claude-sonnet-4@20250514"):
            with self.subTest(model=model):
                self.assertEqual(self._vertex(model=model).model, model)

    def test_vertex_without_a_project_says_what_to_set(self):
        for missing in (None, ""):
            with self.subTest(project=missing):
                with self.assertRaises(provider.ProviderError) as cm:
                    self._vertex(vertex_project=missing)
                self.assertIn("AGENT_VERTEX_PROJECT", str(cm.exception))

    def test_a_config_without_the_vertex_attributes_still_says_what_to_set(
            self):
        # create_client reads them with getattr, as it reads everything: a
        # config object that has never heard of vertex must not raise
        # AttributeError.
        bare = types.SimpleNamespace(provider="vertex", model="google/m",
                                     api_key=None, base_url=None)
        with self.assertRaises(provider.ProviderError) as cm:
            provider.create_client(bare)
        self.assertIn("AGENT_VERTEX_PROJECT", str(cm.exception))

    def test_a_bad_location_or_project_is_refused_by_create_client_too(self):
        for field, bad in (("vertex_location", "eu.evil.example"),
                           ("vertex_project", "proj/x")):
            with self.subTest(field=field):
                with self.assertRaises(provider.ProviderError) as cm:
                    self._vertex(**{field: bad})
                self.assertIn(field, str(cm.exception))

    def test_vertex_builds_a_client_with_a_token_source_and_no_key(self):
        c = self._vertex(vertex_location="europe-west4")
        self.assertEqual(c.provider, "vertex")
        self.assertIsNotNone(c._token_source)
        self.assertFalse(bool(c._bearer))
        self.assertEqual(
            c._base_url, provider.vertex_base_url("proj", "europe-west4"))

    def test_an_explicit_base_url_is_used_instead_of_the_computed_one(self):
        c = self._vertex(vertex_project=None,
                         base_url="https://gateway.example/v1")
        self.assertEqual(c._base_url, "https://gateway.example/v1")

    def test_the_token_source_is_the_shared_one_for_that_kind(self):
        a, b = self._vertex(), self._vertex()
        self.assertIs(a._token_source, b._token_source)
        self.assertIs(a._token_source, gcp_token.source("gcloud"))

    def test_a_key_does_not_ride_along_with_a_token_source(self):
        c = self._vertex(api_key=_KEY)
        self.assertIsNotNone(c._token_source)
        self.assertFalse(bool(c._bearer))

    def test_a_static_bearer_gets_no_source_and_keeps_its_key(self):
        c = self._vertex(api_key=_KEY, token_source="auto", static_bearer=True)
        self.assertIsNone(c._token_source)
        self.assertEqual(c._bearer.reveal(), _KEY)

    def test_the_static_bearer_still_counts_as_a_credential_for_the_guard(
            self):
        with self.assertRaises(provider.ProviderError) as cm:
            self._vertex(api_key=_KEY, token_source="auto", static_bearer=True,
                         base_url="http://proxy.example/v1")
        self.assertNotIn(_KEY, str(cm.exception))

    def test_a_vertex_client_over_plain_http_is_refused_though_it_has_no_key(
            self):
        # It is about to be handed a live OAuth bearer. Without counting the
        # token source the guard sees no credential and lets it through.
        for source in ("auto", "gcloud"):
            with self.subTest(token_source=source):
                with self.assertRaises(provider.ProviderError) as cm:
                    self._vertex(token_source=source,
                                 base_url="http://proxy.example/v1")
                self.assertIn("https", str(cm.exception))

    def test_a_vertex_client_may_use_loopback_http(self):
        c = self._vertex(base_url="http://127.0.0.1:9000/v1")
        self.assertEqual(c._base_url, "http://127.0.0.1:9000/v1")


class TestCreateClientChecksTheTokenSourceAtStartup(unittest.TestCase):
    def _vertex(self, **kw):
        values = dict(provider="vertex", model="google/gemini-3-pro",
                      vertex_project="proj")
        values.update(kw)
        return provider.create_client(_cfg(**values))

    def test_the_file_source_without_a_key_file_is_a_configuration_error(self):
        with self.assertRaises(provider.ProviderError) as cm:
            self._vertex(token_source="file", api_key_file=None)
        message = str(cm.exception)
        self.assertIn("token_source", message)
        self.assertIn("api_key_file", message)
        self.assertIn("vertex", message)

    def test_a_key_file_that_is_missing_is_refused_at_startup(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(provider.ProviderError):
                self._vertex(token_source="file",
                             api_key_file=os.path.join(tmp, "absent"))

    def test_a_key_file_that_others_can_read_is_refused_at_startup(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k")
            with open(path, "w") as handle:
                handle.write(_KEY)
            os.chmod(path, 0o644)
            with self.assertRaises(provider.ProviderError) as cm:
                self._vertex(token_source="file", api_key_file=path)
            self.assertNotIn(_KEY, _walk_chain(cm.exception))

    def test_a_usable_key_file_builds_a_client_on_the_file_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k")
            with open(path, "w") as handle:
                handle.write(_KEY)
            os.chmod(path, 0o600)
            c = self._vertex(token_source="file", api_key_file=path)
            self.assertIs(c._token_source,
                          gcp_token.source("file", key_file=path))

    def test_gcloud_that_is_not_installed_is_refused_at_startup(self):
        with unittest.mock.patch.object(gcp_token.shutil, "which",
                                        return_value=None):
            with self.assertRaises(provider.ProviderError) as cm:
                self._vertex(token_source="gcloud")
        self.assertIn("gcloud", str(cm.exception))

    def test_an_unknown_token_source_is_refused_naming_the_valid_ones(self):
        with self.assertRaises(provider.ProviderError) as cm:
            self._vertex(token_source="magic")
        for kind in gcp_token.KINDS:
            self.assertIn(kind, str(cm.exception))

    def test_the_refusal_leaves_no_exception_chain(self):
        with self.assertRaises(provider.ProviderError) as cm:
            self._vertex(token_source="file", api_key_file=None)
        self.assertIsNone(cm.exception.__context__)
        self.assertIsNone(cm.exception.__cause__)

    def test_auto_passes_startup_without_touching_the_network(self):
        with unittest.mock.patch.object(
                gcp_token, "_fetch_metadata",
                side_effect=AssertionError("network")), \
                unittest.mock.patch.object(
                    gcp_token, "_fetch_gcloud",
                    side_effect=AssertionError("subprocess")):
            self.assertIsNotNone(self._vertex(token_source="auto"))

    def test_a_provider_that_is_not_vertex_ignores_the_token_source(self):
        c = provider.create_client(_cfg(
            provider="openrouter", api_key="k", model="m",
            token_source="file", api_key_file=None))
        self.assertIsNone(c._token_source)


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



# ── Bedrock: the Converse API ──

_BEDROCK_MODEL = "eu.anthropic.claude-sonnet-4-5-20250929-v1:0"

_BEDROCK_REPLY = {
    "output": {"message": {"role": "assistant", "content": [
        {"text": "looking"},
        {"toolUse": {"toolUseId": "tooluse_abc", "name": "run_command",
                     "input": {"command": "whoami", "beacon_id": "b1"}}}]}},
    "stopReason": "tool_use",
    "usage": {"inputTokens": 585, "outputTokens": 75, "totalTokens": 660},
}


def _bedrock(stub, **kw):
    return bedrock_client.BedrockClient(
        model=_BEDROCK_MODEL, api_key=_KEY, transport=stub, **kw)


class TestBedrockWireFormat(unittest.IsolatedAsyncioTestCase):
    """The four places Converse differs from the Anthropic Messages API.

    Each one is where an implementation copied from the Anthropic client
    would break, so each one is asserted against the documented shape rather
    than against whatever the code happens to produce. Verified once against
    the live endpoint before these were written.
    """

    def _request(self, messages=None, tools=None, system="sys"):
        stub = _Stub(_BEDROCK_REPLY)
        client = _bedrock(stub)
        return client._build_request(
            system, messages if messages is not None
            else [{"role": "user", "content": "go"}],
            tools or [], 300, 0.25)

    def test_the_model_id_is_in_the_path_not_the_body(self):
        url, _, body = self._request()
        self.assertTrue(url.endswith("/model/%s/converse" % _BEDROCK_MODEL), url)
        self.assertNotIn("model", body)

    def test_the_region_prefixed_id_survives_the_url(self):
        # A bare id is rejected by the API, and the "-v1:0" suffix must not
        # be read as a port.
        url, _, _ = self._request()
        self.assertIn("eu.anthropic.", url)
        self.assertIn("-v1:0/converse", url)

    def test_system_is_a_list_of_blocks(self):
        _, _, body = self._request(system="be careful")
        self.assertEqual(body["system"], [{"text": "be careful"}])

    def test_no_system_key_when_there_is_no_system_prompt(self):
        _, _, body = self._request(system="")
        self.assertNotIn("system", body)

    def test_limits_go_in_inference_config(self):
        _, _, body = self._request()
        self.assertEqual(body["inferenceConfig"],
                         {"maxTokens": 300, "temperature": 0.25})

    def test_a_tool_is_wrapped_in_a_toolspec_with_a_json_schema(self):
        spec = provider.ToolSpec(
            name="run_command", description="run it",
            parameters={"type": "object", "properties": {}})
        _, _, body = self._request(tools=[spec])
        self.assertEqual(body["toolConfig"]["tools"], [{"toolSpec": {
            "name": "run_command", "description": "run it",
            "inputSchema": {"json": {"type": "object", "properties": {}}}}}])

    def test_the_token_travels_as_a_bearer_header(self):
        _, headers, _ = self._request()
        self.assertEqual(headers["Authorization"], "Bearer " + _KEY)

    def test_blocks_are_single_key_objects_not_tagged_ones(self):
        # {"text": ...}, not {"type": "text", "text": ...}.
        _, _, body = self._request()
        block = body["messages"][0]["content"][0]
        self.assertEqual(block, {"text": "go"})

    def test_a_tool_result_is_a_block_in_a_user_message(self):
        _, _, body = self._request(messages=[
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": "",
             "tool_calls": [{"id": "t1", "name": "run_command",
                             "arguments": {"command": "whoami"}}]},
            {"role": "tool", "tool_call_id": "t1", "content": "root"}])
        last = body["messages"][-1]
        self.assertEqual(last["role"], "user")
        self.assertEqual(last["content"], [{"toolResult": {
            "toolUseId": "t1", "content": [{"text": "root"}],
            "status": "success"}}])

    def test_results_for_one_turn_merge_into_a_single_user_message(self):
        _, _, body = self._request(messages=[
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": "",
             "tool_calls": [{"id": "t1", "name": "a", "arguments": {}},
                            {"id": "t2", "name": "b", "arguments": {}}]},
            {"role": "tool", "tool_call_id": "t1", "content": "one"},
            {"role": "tool", "tool_call_id": "t2", "content": "two"}])
        self.assertEqual(len(body["messages"]), 3)
        self.assertEqual(len(body["messages"][-1]["content"]), 2)

    def test_tool_results_come_first_in_a_user_message(self):
        _, _, body = self._request(messages=[
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": "",
             "tool_calls": [{"id": "t1", "name": "a", "arguments": {}}]},
            {"role": "user", "content": "and also this"},
            {"role": "tool", "tool_call_id": "t1", "content": "root"}])
        content = body["messages"][-1]["content"]
        self.assertIn("toolResult", content[0])

    def test_an_assistant_turn_is_never_an_empty_content_list(self):
        # The API rejects one, and a turn with neither text nor a call is
        # what a failed completion leaves behind.
        _, _, body = self._request(messages=[
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": ""}])
        self.assertEqual(body["messages"][-1]["content"], [{"text": ""}])

    def test_an_unsupported_role_is_a_provider_error(self):
        with self.assertRaises(provider.ProviderError):
            self._request(messages=[{"role": "system", "content": "no"}])


class TestBedrockResponse(unittest.IsolatedAsyncioTestCase):
    async def _complete(self, payload):
        stub = _Stub(payload)
        return await _bedrock(stub).complete(
            "sys", [{"role": "user", "content": "go"}], [], 300, 0.0)

    async def test_text_and_tool_use_are_both_read(self):
        out = await self._complete(_BEDROCK_REPLY)
        self.assertEqual(out.text, "looking")
        self.assertEqual(len(out.tool_calls), 1)

    async def test_tool_use_input_arrives_already_parsed(self):
        # Unlike OpenAI, which sends a JSON string. parse_arguments passes a
        # dict through, so this must not end up double-decoded.
        call = (await self._complete(_BEDROCK_REPLY)).tool_calls[0]
        self.assertEqual(call.arguments,
                         {"command": "whoami", "beacon_id": "b1"})
        self.assertIsNone(call.error)
        self.assertEqual(call.id, "tooluse_abc")

    async def test_token_counts_use_the_camel_case_names(self):
        out = await self._complete(_BEDROCK_REPLY)
        self.assertEqual((out.input_tokens, out.output_tokens), (585, 75))
        self.assertEqual(out.total_tokens, 660)

    async def test_a_missing_total_is_derived(self):
        payload = copy.deepcopy(_BEDROCK_REPLY)
        del payload["usage"]["totalTokens"]
        out = await self._complete(payload)
        self.assertEqual(out.total_tokens, 585 + 75)

    async def test_the_stop_reason_passes_through(self):
        self.assertEqual((await self._complete(_BEDROCK_REPLY)).stop_reason,
                         "tool_use")

    async def test_blocks_the_loop_does_not_use_are_ignored(self):
        payload = copy.deepcopy(_BEDROCK_REPLY)
        payload["output"]["message"]["content"].insert(
            0, {"reasoningContent": {"reasoningText": {"text": "thinking"}}})
        out = await self._complete(payload)
        self.assertEqual(out.text, "looking")
        self.assertEqual(len(out.tool_calls), 1)

    async def test_an_unreadable_tool_input_is_reported_on_the_call(self):
        payload = copy.deepcopy(_BEDROCK_REPLY)
        payload["output"]["message"]["content"][1]["toolUse"]["input"] = "nope"
        call = (await self._complete(payload)).tool_calls[0]
        self.assertIsNotNone(call.error)

    async def test_an_empty_output_is_a_provider_error_not_a_crash(self):
        with self.assertRaises(provider.ProviderError):
            await self._complete({"stopReason": "end_turn"})


class TestBedrockSelection(unittest.TestCase):
    def test_the_provider_is_offered(self):
        self.assertIn("bedrock", provider._PROVIDERS)

    def test_create_client_builds_a_bedrock_client(self):
        client = provider.create_client(
            _cfg(provider="bedrock", api_key=_KEY, model=_BEDROCK_MODEL))
        self.assertIsInstance(client, bedrock_client.BedrockClient)

    def test_the_default_endpoint_is_regional(self):
        self.assertEqual(provider.bedrock_base_url("eu-west-1"),
                         "https://bedrock-runtime.eu-west-1.amazonaws.com")

    def test_a_key_is_required(self):
        with self.assertRaises(provider.ProviderError):
            provider.create_client(
                _cfg(provider="bedrock", api_key=None, model=_BEDROCK_MODEL))

    def test_a_model_is_required(self):
        with self.assertRaises(provider.ProviderError):
            provider.create_client(
                _cfg(provider="bedrock", api_key=_KEY, model=None))

    def test_a_bedrock_model_id_reaches_the_full_tier(self):
        # The region prefix must not stop the allowlist matching.
        self.assertEqual(provider.capability_tier(_BEDROCK_MODEL, "bedrock"),
                         "full")

    def test_the_key_is_absent_from_every_rendering(self):
        client = provider.create_client(
            _cfg(provider="bedrock", api_key=_KEY, model=_BEDROCK_MODEL))
        self.assertNotIn(_KEY, repr(client))
        self.assertNotIn(_KEY, str(client))
        self.assertNotIn(_KEY, repr(vars(client)))

    def test_a_failure_leaks_neither_the_key_nor_a_chain(self):
        import asyncio
        stub = _Stub(RuntimeError("headers %r" % {"Authorization": _KEY}))
        client = _bedrock(stub)
        with self.assertRaises(provider.ProviderError) as caught:
            asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
                client.complete("s", [{"role": "user", "content": "x"}],
                                [], 10, 0.0))
        self.assertNotIn(_KEY, _walk_chain(caught.exception))

if __name__ == "__main__":
    unittest.main()
