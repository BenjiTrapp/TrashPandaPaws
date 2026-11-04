#!/usr/bin/env python3
"""Scripted LLM clients for tests: no network, no model, no randomness.

A MockClient answers each `complete` call with the next Completion from a
queue, so a test states in advance what the model will say and asserts on
what the agent did with it.

Usage:
    from software.agent.llm import loop, mock

    client = mock.MockClient([
        mock.calls(("scan", {"host": "10.0.0.5"})),
        mock.text("done"),
    ])
    answer = await loop.run(client, system=..., prompt=..., tools=[...], max_turns=8)
    assert client.remaining == 0
"""

from collections import deque
from typing import Any, Dict, List, Tuple

from software.agent.llm.provider import (Completion, LlmClient, ProviderError,
                                         ToolCall)

# ── Completion builders ──


def _split_tokens(total_tokens: int) -> Tuple[int, int]:
    # A prompt is usually the larger side; the exact split is irrelevant to
    # callers, which sum the two or read the total.
    output = total_tokens // 6
    return total_tokens - output, output


def text(s: str, *, total_tokens: int = 120) -> Completion:
    """A final answer with no tool calls."""
    inp, out = _split_tokens(total_tokens)
    return Completion(s, [], inp, out, total_tokens, "end_turn")


def calls(*pairs: Tuple[str, Dict[str, Any]],
          total_tokens: int = 120) -> Completion:
    """A turn that calls tools: one (name, arguments) pair per call."""
    # Ids are positional, not random: a failing test then names the same
    # call every run.
    tool_calls = [ToolCall("mock_call_%d" % i, name, arguments)
                  for i, (name, arguments) in enumerate(pairs)]
    inp, out = _split_tokens(total_tokens)
    return Completion("", tool_calls, inp, out, total_tokens, "tool_use")


# ── Clients ──


class MockClient(LlmClient):
    provider = "mock"
    model = "mock-model"

    def __init__(self, responses: List[Completion], supports_tools: bool = True):
        # A copy, so `[x] * 10` or a list the test reuses is not consumed.
        self._queue = deque(responses)
        self._served = 0
        self.supports_tools = supports_tools

    @property
    def remaining(self) -> int:
        return len(self._queue)

    async def complete(self, system, messages, tools, max_tokens, temperature):
        # Loud on purpose. Returning an empty Completion here would end an
        # orchestrator test with a blank answer and no hint that the script
        # was one response short.
        if not self._queue:
            raise AssertionError(
                "MockClient has no responses left: complete() was called "
                "again after all %d queued response(s) were used; queue "
                "one more or lower max_turns" % self._served)
        self._served += 1
        return self._queue.popleft()


class FailingClient(LlmClient):
    provider = "mock"
    model = "mock-model"

    def __init__(self, message: str):
        self._message = message

    async def complete(self, system, messages, tools, max_tokens, temperature):
        raise ProviderError(self._message)
