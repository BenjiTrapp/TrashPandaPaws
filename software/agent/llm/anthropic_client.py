#!/usr/bin/env python3
"""Anthropic client: the Messages API over the shared transport.

Wire format implemented (https://docs.anthropic.com/en/api/messages):

    POST {base_url}/v1/messages
    headers  x-api-key, anthropic-version, content-type
    body     {"model", "max_tokens", "temperature", "system": "<string>",
              "messages": [...], "tools": [{"name", "description",
              "input_schema"}]}

    A tool call is an assistant content block
        {"type": "tool_use", "id", "name", "input": {<object>}}
    and its result is a block inside a *user* message
        {"type": "tool_result", "tool_use_id", "content": "<string>"}

    reply    {"content": [{"type": "text", "text"} | {"type": "tool_use",
              ...}], "stop_reason": "end_turn" | "tool_use" | "max_tokens" |
              "stop_sequence", "usage": {"input_tokens", "output_tokens"}}
"""

from typing import Dict, List, Optional, Tuple

from software.agent.llm import provider
from software.agent.llm.provider import Completion, ToolCall, ToolSpec

# The API version header is required and pins the wire format above.
_API_VERSION = "2023-06-01"

# ── Request ──


def _tool_use_block(call: ToolCall) -> dict:
    return {"type": "tool_use", "id": call.id, "name": call.name,
            "input": call.arguments}


def _translate(messages: List[dict]) -> List[dict]:
    """Internal messages -> Anthropic messages with content blocks."""
    out = []  # type: List[dict]
    for m in messages:
        role = m.get("role")
        text = m.get("content") or ""
        if role == "assistant":
            calls = [provider.normalize_tool_call(c, i)
                     for i, c in enumerate(m.get("tool_calls") or [])]
            if not calls:
                out.append({"role": "assistant", "content": text})
                continue
            # No text block when there is no text: the API rejects an empty
            # one, and a tool-only turn is the normal case.
            blocks = [{"type": "text", "text": text}] if text else []
            blocks += [_tool_use_block(c) for c in calls]
            out.append({"role": "assistant", "content": blocks})
        elif role in ("user", "tool"):
            if role == "tool":
                block = {"type": "tool_result",
                         "tool_use_id": m.get("tool_call_id", ""),
                         "content": text}
            else:
                block = {"type": "text", "text": text}
            # Tool results travel as user content, and every result for one
            # assistant turn has to sit in the single user message that
            # follows it. So consecutive user/tool messages merge into one.
            if out and out[-1]["role"] == "user" \
                    and isinstance(out[-1]["content"], list):
                out[-1]["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
        else:
            raise ValueError("unsupported message role %r" % (role,))
    for m in out:
        if m["role"] != "user":
            continue
        # tool_result blocks must come first in a user message; stable sort.
        m["content"].sort(key=lambda b: b["type"] != "tool_result")
        # A lone text block is sent as a plain string, the simple form.
        if len(m["content"]) == 1 and m["content"][0]["type"] == "text":
            m["content"] = m["content"][0]["text"]
    return out


class AnthropicClient(provider.HttpLlmClient):
    def __init__(self, model: str, api_key: Optional[str],
                 base_url: Optional[str] = None,
                 transport: Optional[provider.Transport] = None,
                 supports_tools: bool = True):
        super().__init__("anthropic", model, api_key,
                         base_url or "https://api.anthropic.com",
                         transport, supports_tools)

    def _build_request(self, system: str, messages: List[dict],
                       tools: List[ToolSpec], max_tokens: int,
                       temperature: float) -> Tuple[str, Dict[str, str], dict]:
        try:
            translated = _translate(messages)
        except ValueError as exc:
            raise self._fail(str(exc)) from None
        body = {"model": self.model, "max_tokens": max_tokens,
                "temperature": temperature, "messages": translated}
        if system:
            body["system"] = system
        if tools:
            body["tools"] = [{"name": t.name, "description": t.description,
                              "input_schema": t.parameters} for t in tools]
        headers = {"x-api-key": self._api_key.reveal() or "",
                   "anthropic-version": _API_VERSION,
                   "content-type": "application/json"}
        return self._base_url + "/v1/messages", headers, body

    def _parse_response(self, payload: dict) -> Completion:
        text_parts = []
        calls = []  # type: List[ToolCall]
        for block in payload["content"]:
            # Other block types (thinking, ...) carry nothing the loop uses.
            if block["type"] == "text":
                text_parts.append(block["text"])
            elif block["type"] == "tool_use":
                arguments = provider.parse_arguments(block.get("input"))
                calls.append(ToolCall(
                    str(block["id"]), str(block["name"]), arguments,
                    arguments.get(provider.ARGUMENTS_ERROR_KEY)))
        usage = payload.get("usage") or {}
        # Cached-prompt tokens are reported separately by the API and are not
        # counted here; no request sets cache_control.
        in_tok = provider.usage_tokens(usage, "input_tokens")
        out_tok = provider.usage_tokens(usage, "output_tokens")
        return Completion("".join(text_parts), calls, in_tok, out_tok,
                          in_tok + out_tok, str(payload.get("stop_reason", "")))
