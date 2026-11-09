#!/usr/bin/env python3
"""OpenAI-compatible client: Chat Completions over the shared transport.

Serves OpenRouter, OpenCode Zen and local servers such as Ollama; they all
speak this protocol.

Wire format implemented (https://platform.openai.com/docs/api-reference/chat):

    POST {base_url}/chat/completions
    headers  Authorization: Bearer <key>   (omitted when there is no key)
    body     {"model", "max_tokens", "temperature",
              "messages": [{"role": "system", "content"}, ...],
              "tools": [{"type": "function", "function": {"name",
              "description", "parameters"}}]}

    An assistant tool call is
        {"id", "type": "function",
         "function": {"name", "arguments": "<JSON *string*, not an object>"}}
    and its result is a message {"role": "tool", "tool_call_id", "content"}.

    reply    {"choices": [{"message": {"content": str | null,
              "tool_calls": [...]}, "finish_reason": "stop" | "length" |
              "tool_calls" | ...}],
              "usage": {"prompt_tokens", "completion_tokens", "total_tokens"}}
"""

import json
from typing import Dict, List, Optional, Tuple

from software.agent.llm import provider
from software.agent.llm.provider import Completion, ToolCall, ToolSpec

# finish_reason -> the vocabulary shared with the Anthropic client.
_STOP_REASONS = {"stop": "end_turn", "length": "max_tokens",
                 "tool_calls": "tool_use"}

# ── Request ──


def _wire_tool_call(entry: dict, index: int) -> dict:
    # Already in the wire shape: leave it exactly as it came.
    if isinstance(entry.get("function"), dict):
        return entry
    call = provider.normalize_tool_call(entry, index)
    return {"id": call.id, "type": "function",
            "function": {"name": call.name,
                         "arguments": json.dumps(call.arguments)}}


def _translate(messages: List[dict]) -> List[dict]:
    out = []  # type: List[dict]
    for m in messages:
        role = m.get("role")
        text = m.get("content") or ""
        if role == "user":
            out.append({"role": "user", "content": text})
        elif role == "assistant":
            msg = {"role": "assistant", "content": text}
            if m.get("tool_calls"):
                msg["tool_calls"] = [_wire_tool_call(c, i)
                                     for i, c in enumerate(m["tool_calls"])]
            out.append(msg)
        elif role == "tool":
            out.append({"role": "tool",
                        "tool_call_id": m.get("tool_call_id", ""),
                        "content": text})
        else:
            raise ValueError("unsupported message role %r" % (role,))
    return out


class OpenAiCompatibleClient(provider.HttpLlmClient):
    def __init__(self, provider: str, model: str, api_key: Optional[str],
                 base_url: str, transport=None, supports_tools: bool = True,
                 timeout: Optional[float] = None):
        super().__init__(provider, model, api_key, base_url, transport,
                         supports_tools, timeout)

    def _build_request(self, system: str, messages: List[dict],
                       tools: List[ToolSpec], max_tokens: int,
                       temperature: float) -> Tuple[str, Dict[str, str], dict]:
        try:
            translated = _translate(messages)
        except ValueError as exc:
            raise self._fail(str(exc)) from None
        if system:
            translated.insert(0, {"role": "system", "content": system})
        # max_tokens, not max_completion_tokens: the newer name is what
        # OpenAI's own reasoning models want, and none of the three targets
        # here is OpenAI's own endpoint.
        body = {"model": self.model, "max_tokens": max_tokens,
                "temperature": temperature, "messages": translated}
        if tools:
            body["tools"] = [
                {"type": "function",
                 "function": {"name": t.name, "description": t.description,
                              "parameters": t.parameters}} for t in tools]
        headers = {"Content-Type": "application/json"}
        key = self._bearer.reveal()
        if key:
            headers["Authorization"] = "Bearer " + key
        return self._base_url + "/chat/completions", headers, body

    def _parse_response(self, payload: dict) -> Completion:
        choice = payload["choices"][0]
        message = choice["message"]
        calls = [provider.normalize_tool_call(c, i)
                 for i, c in enumerate(message.get("tool_calls") or [])]
        usage = payload.get("usage") or {}
        in_tok = provider.usage_tokens(usage, "prompt_tokens")
        out_tok = provider.usage_tokens(usage, "completion_tokens")
        # Servers that report usage at all report the total, but not all do.
        total = provider.usage_tokens(usage, "total_tokens") \
            or in_tok + out_tok
        finish = str(choice.get("finish_reason") or "")
        return Completion(message.get("content") or "", calls, in_tok,
                          out_tok, total, _STOP_REASONS.get(finish, finish))
