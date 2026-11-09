#!/usr/bin/env python3
"""Bedrock client: the Converse API over the shared transport.

Wire format implemented
(https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html):

    POST {base_url}/model/{modelId}/converse
    headers  Authorization: Bearer <AWS_BEARER_TOKEN_BEDROCK>, Content-Type
    body     {"system": [{"text": "<string>"}],
              "messages": [{"role", "content": [block, ...]}],
              "inferenceConfig": {"maxTokens", "temperature"},
              "toolConfig": {"tools": [{"toolSpec": {"name", "description",
                  "inputSchema": {"json": <schema>}}}]}}

    A tool call is an assistant content block
        {"toolUse": {"toolUseId", "name", "input": {<object>}}}
    and its result is a block inside a *user* message
        {"toolResult": {"toolUseId", "content": [{"text"}], "status"}}

    reply    {"output": {"message": {"content": [...]}},
              "stopReason": "end_turn" | "tool_use" | "max_tokens" | ...,
              "usage": {"inputTokens", "outputTokens", "totalTokens"}}

Four things differ from the Anthropic Messages API, and each one is a place
a copied implementation would break:

  · the model id is in the **path**, not the body, and it carries a region
    prefix — a bare id is rejected
  · `system` is a **list of blocks**, not a string
  · every content block is a single-key object (`{"text": ...}`), not a
    tagged one (`{"type": "text", ...}`)
  · `toolUse.input` arrives as a **parsed object**, where OpenAI sends a
    JSON string

Authentication is a bearer token rather than SigV4: Bedrock API keys, which
is why this needs no AWS SDK and fits the shared `requests` transport.
"""

from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

from software.agent.llm import provider
from software.agent.llm.provider import Completion, ToolCall, ToolSpec

# ── Request ──


def _tool_use_block(call: ToolCall) -> dict:
    return {"toolUse": {"toolUseId": call.id, "name": call.name,
                        "input": call.arguments}}


def _translate(messages: List[dict]) -> List[dict]:
    """Internal messages -> Converse messages with content blocks."""
    out = []  # type: List[dict]
    for message in messages:
        role = message.get("role")
        text = message.get("content") or ""
        if role == "assistant":
            calls = [provider.normalize_tool_call(c, i)
                     for i, c in enumerate(message.get("tool_calls") or [])]
            blocks = [{"text": text}] if text else []
            blocks += [_tool_use_block(c) for c in calls]
            # An assistant turn with neither text nor a call would be an
            # empty content list, which the API rejects.
            out.append({"role": "assistant",
                        "content": blocks or [{"text": ""}]})
        elif role in ("user", "tool"):
            if role == "tool":
                block = {"toolResult": {
                    "toolUseId": message.get("tool_call_id", ""),
                    "content": [{"text": text}],
                    "status": "success"}}
            else:
                block = {"text": text}
            # Every result for one assistant turn must sit in the single user
            # message that follows it, so consecutive user/tool messages
            # merge — the same rule as the Anthropic API.
            if out and out[-1]["role"] == "user":
                out[-1]["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
        else:
            raise ValueError("unsupported message role %r" % (role,))
    for message in out:
        if message["role"] != "user":
            continue
        # toolResult blocks first in a user message; stable sort.
        message["content"].sort(key=lambda b: "toolResult" not in b)
    return out


class BedrockClient(provider.HttpLlmClient):
    """Anthropic (and others) through Amazon Bedrock's Converse API."""

    def __init__(self, model: str, api_key: Optional[str],
                 base_url: Optional[str] = None,
                 transport: Optional[provider.Transport] = None,
                 supports_tools: bool = True):
        super().__init__("bedrock", model, api_key,
                         base_url or provider.bedrock_base_url(),
                         transport, supports_tools)

    def _build_request(self, system: str, messages: List[dict],
                       tools: List[ToolSpec], max_tokens: int,
                       temperature: float) -> Tuple[str, Dict[str, str], dict]:
        try:
            translated = _translate(messages)
        except ValueError as exc:
            raise self._fail(str(exc)) from None
        body = {"messages": translated,
                "inferenceConfig": {"maxTokens": max_tokens,
                                    "temperature": temperature}}
        if system:
            body["system"] = [{"text": system}]
        if tools:
            body["toolConfig"] = {"tools": [
                {"toolSpec": {"name": t.name, "description": t.description,
                              "inputSchema": {"json": t.parameters}}}
                for t in tools]}
        headers = {"Authorization": "Bearer %s" % (self._bearer.reveal() or ""),
                   "Content-Type": "application/json"}
        # The id goes in the path and may contain a colon (…-v1:0), which is
        # legal in a path segment but must not be read as a port.
        url = "%s/model/%s/converse" % (
            self._base_url, quote(self.model, safe=".-:"))
        return url, headers, body

    def _parse_response(self, payload: dict) -> Completion:
        # Indexed, not .get(): a reply with no message is malformed, and
        # treating it as empty text would make the loop read it as a final
        # answer and return "" as the campaign's result. The base class
        # turns the KeyError into a ProviderError naming provider and model.
        message = payload["output"]["message"]
        text_parts = []
        calls = []  # type: List[ToolCall]
        for block in message["content"]:
            if "text" in block:
                text_parts.append(block["text"])
            elif "toolUse" in block:
                use = block["toolUse"]
                # Already an object here, unlike OpenAI's JSON string;
                # parse_arguments passes a dict through unchanged and still
                # catches a server that sends something else.
                arguments = provider.parse_arguments(use.get("input"))
                calls.append(ToolCall(
                    str(use.get("toolUseId", "")), str(use.get("name", "")),
                    arguments, arguments.get(provider.ARGUMENTS_ERROR_KEY)))
            # reasoningContent and guardrail blocks carry nothing the loop uses.
        usage = payload.get("usage") or {}
        in_tok = provider.usage_tokens(usage, "inputTokens")
        out_tok = provider.usage_tokens(usage, "outputTokens")
        total = provider.usage_tokens(usage, "totalTokens") or (in_tok + out_tok)
        return Completion("".join(text_parts), calls, in_tok, out_tok, total,
                          str(payload.get("stopReason") or ""))
