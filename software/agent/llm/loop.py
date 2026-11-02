#!/usr/bin/env python3
"""Tool-calling loop: drives a model through turns of tool use to an answer.

Each turn is one completion. If the model answers in text, that text is the
result; if it asks for tools, they all run together, every result goes back
tagged with the id of the call that produced it, and the next turn starts.

Every way a tool call can go wrong becomes a tool result the model can read
and correct, never an exception: an exception here would end a whole run for
one malformed call. The one failure that does propagate is the provider's
own (ProviderError), because what a dead provider means is the caller's
decision, not the loop's.

The loop knows nothing about what the tools do. Gating, scope and
classification belong to whoever builds the tools' functions; this module
only dispatches them.

Usage:
    from software.agent.llm import loop

    tools = [loop.Tool(spec, fn)]  # fn: async, keyword arguments from the model
    answer = await loop.run(client, system="...", prompt="...", tools=tools,
                            max_turns=8, conn=conn, run_id=run_id)
"""

import asyncio
import inspect
import json
import re
import time
from typing import Any, Awaitable, Callable, Dict, List, NamedTuple, Tuple

from software.agent.llm.provider import (Completion, LlmClient, ProviderError,
                                         ToolCall, ToolSpec)
from software.agent.store import queries

# ── Shapes ──


class Tool(NamedTuple):
    spec: ToolSpec
    fn: Callable[..., Awaitable[Any]]


# ── Truncation ──


def truncate(text: str, limit: int) -> Tuple[str, bool]:
    """Keep the head and the tail of text that is over `limit` characters.

    Slices characters, not bytes: encoding first would count "ü" twice and
    could cut inside a multi-byte sequence. Both ends are kept because the
    start of a tool's output says what it was and the end says how it
    finished.
    """
    if len(text) <= limit:
        return text, False
    half = max(limit, 0) // 2
    # text[len(text) - half:], not text[-half:]: with half == 0 the latter
    # is the whole string.
    tail = text[len(text) - half:]
    omitted = len(text) - 2 * half
    marker = "\n[... OUTPUT TRUNCATED: %d characters omitted ...]\n" % omitted
    return text[:half] + marker + tail, True


# ── Text-protocol fallback ──
#
# For a model with no native tool calling, tools are described in the system
# prompt and called as a block in the reply. Both markers must sit on a line
# of their own. That is what lets "END" appear inside an argument ("echo
# END" in a command): a JSON string cannot contain a raw newline, so a line
# that is only END can never be part of a well-formed argument. The
# alternative, a lazy match up to the first END anywhere, cuts such a call
# short and turns a valid request into a parse error.
_TEXT_BLOCK = re.compile(
    r"^[ \t]*TOOL_CALL[ \t\r]*\n(.*?)^[ \t]*END[ \t\r]*$",
    re.DOTALL | re.MULTILINE)

# Tried only when the anchored pattern finds nothing. The text protocol is
# there for models too weak for native tool calling, and those are exactly
# the ones that put both markers on one line or forget END — so refusing the
# shape outright means the fallback fails for its own audience. This match is
# lazy, which reintroduces the END-inside-an-argument problem the anchored
# pattern avoids; in that case the JSON arrives cut short and comes back as a
# readable parse error, which the model can act on. Silently returning the
# attempt as a final answer is the outcome worth avoiding.
_TEXT_BLOCK_LOOSE = re.compile(r"TOOL_CALL[ \t\r\n]*(.*?)[ \t\r\n]*END",
                               re.DOTALL)

# A reply that mentions the marker but parses to nothing is a format mistake,
# not an answer. Nudging costs a turn; treating it as the final answer hands
# the caller a raw TOOL_CALL string as if it were a result.
_TEXT_MENTION = re.compile(r"TOOL_CALL")

_TEXT_PROTOCOL = """\

You can call tools. To call one, write a block in your reply, with each \
marker alone on its own line:

TOOL_CALL
{"name": "<tool name>", "arguments": {"<parameter>": <value>}}
END

You may write several blocks in one reply; they run together. Each result \
comes back in the next message. When you have your final answer, write it \
as plain text with no TOOL_CALL block.

Tools:
"""


def _text_system(system: str, tools: List[Tool]) -> str:
    lines = [system.rstrip(), _TEXT_PROTOCOL.rstrip("\n")]
    for t in tools:
        lines.append("- %s: %s\n  parameters: %s" % (
            t.spec.name, t.spec.description,
            json.dumps(t.spec.parameters, ensure_ascii=False)))
    return "\n".join(lines)


def _parse_text_calls(text: str, turn: int) -> List[ToolCall]:
    calls = []  # type: List[ToolCall]
    for pattern in (_TEXT_BLOCK, _TEXT_BLOCK_LOOSE):
        for i, m in enumerate(pattern.finditer(text)):
            call_id = "text_%d_%d" % (turn, i)
            calls.append(_read_block(call_id, m.group(1)))
        if calls:
            return calls
    if _TEXT_MENTION.search(text):
        return [ToolCall(
            "text_%d_0" % turn, "", {},
            "a TOOL_CALL block was started but could not be read: write "
            "TOOL_CALL alone on its own line, then one JSON object, then END "
            "alone on its own line. If you meant this as your final answer, "
            "write it again without the word TOOL_CALL.")]
    return calls


def _read_block(call_id: str, body: str) -> ToolCall:
    def unreadable(reason):
        return ToolCall(call_id, "", {}, "TOOL_CALL block was " + reason)

    try:
        value = json.loads(body)
    except ValueError as exc:
        return unreadable("not valid JSON (%s)"
                          % getattr(exc, "msg", "parse error"))
    if not isinstance(value, dict):
        return unreadable("valid JSON but not an object (got %s)"
                          % type(value).__name__)
    name = value.get("name")
    if not isinstance(name, str) or not name:
        return unreadable("missing a string \"name\"")
    arguments = value.get("arguments", {})
    if not isinstance(arguments, dict):
        return ToolCall(call_id, name, {},
                        "TOOL_CALL block's \"arguments\" was not an object "
                        "(got %s)" % type(arguments).__name__)
    return ToolCall(call_id, name, arguments)


# ── Dispatch ──


async def _invoke(by_name: Dict[str, Tool], call: ToolCall) -> Any:
    """The tool's result, or an error dict for a call that cannot run.

    Raises only what the tool itself raised; `run` collects that through
    gather(return_exceptions=True) and reports it.
    """
    # Checked first and by field, not by looking for sentinel keys in the
    # arguments. A call whose arguments could not be read must never reach a
    # tool, which would run on its defaults with parameters the model did not
    # choose.
    if call.error:
        return {"error": "arguments for %r could not be read: %s"
                         % (call.name, call.error)}
    tool = by_name.get(call.name)
    if tool is None:
        # Naming what exists lets the model correct itself; a bare refusal
        # makes it guess again.
        return {"error": "unknown tool %r" % call.name,
                "available": list(by_name)}
    try:
        inspect.signature(tool.fn).bind(**call.arguments)
    except TypeError as exc:
        return {"error": "invalid arguments for %r: %s" % (call.name, exc)}
    return await tool.fn(**call.arguments)


def _render(outcome: Any, limit: int) -> str:
    if isinstance(outcome, BaseException):
        outcome = {"error": "%s: %s" % (type(outcome).__name__, outcome)}
    try:
        content = json.dumps(outcome, ensure_ascii=False, default=str)
    except (TypeError, ValueError) as exc:
        content = json.dumps(
            {"error": "result could not be serialised (%s)"
                      % type(exc).__name__})
    return truncate(content, limit)[0]


# ── Interaction log ──

# "off" is the default and everything but "full" behaves as "off". The prompt
# carries whatever the run has gathered, which can include credentials
# recovered from a target, so writing it to SQLite is the operator's explicit
# choice; a typo in the setting must land on the side of not writing.
_FULL = "full"


def _log(conn, run_id, client, caller_context, log_level, started, *,
         completion=None, prompt=None, error=None) -> None:
    if conn is None or run_id is None:
        return
    fields = dict(
        run_id=run_id, provider=client.provider, model=client.model,
        caller_context=caller_context,
        latency_ms=int((time.monotonic() - started) * 1000),
        status="error" if error else "success")
    if error:
        fields["error_message"] = error
    if completion is not None:
        fields.update(input_tokens=completion.input_tokens,
                      output_tokens=completion.output_tokens,
                      total_tokens=completion.total_tokens)
    if log_level == _FULL:
        fields["prompt_text"] = prompt
        if completion is not None:
            fields["response_text"] = _response_text(completion)
    queries.log_llm_interaction(conn, **fields)


def _response_text(completion: Completion) -> str:
    if not completion.tool_calls:
        return completion.text
    asked = [{"id": c.id, "name": c.name, "arguments": c.arguments}
             for c in completion.tool_calls]
    return "%s\nTOOL_CALLS: %s" % (
        completion.text, json.dumps(asked, ensure_ascii=False, default=str))


# ── Loop ──


async def run(client: LlmClient, *, system: str, prompt: str,
              tools: List[Tool], max_turns: int, max_tokens: int = 4096,
              temperature: float = 0.3, conn=None, run_id=None,
              caller_context: str = "", log_level: str = "off",
              truncate_chars: int = 4000) -> str:
    by_name = {t.spec.name: t for t in tools}
    specs = [t.spec for t in tools]
    native = client.supports_tools
    sent_system = system if native else _text_system(system, tools)
    messages = [{"role": "user", "content": prompt}]  # type: List[dict]
    last_text = ""

    for turn in range(1, max_turns + 1):
        started = time.monotonic()
        # The full request, not just what is new this turn: it is what the
        # model actually saw, which is the point of logging it. Only built
        # when it will be stored.
        request = (json.dumps({"system": sent_system, "messages": messages},
                              ensure_ascii=False, default=str)
                   if log_level == _FULL else None)
        try:
            completion = await client.complete(
                sent_system, messages, specs, max_tokens, temperature)
        except ProviderError as exc:
            _log(conn, run_id, client, caller_context, log_level, started,
                 prompt=request, error=str(exc))
            raise
        _log(conn, run_id, client, caller_context, log_level, started,
             completion=completion, prompt=request)

        last_text = completion.text
        calls = (completion.tool_calls if native
                 else _parse_text_calls(completion.text, turn))
        if not calls:
            return completion.text

        if native:
            messages.append({
                "role": "assistant", "content": completion.text,
                "tool_calls": [{"id": c.id, "name": c.name,
                                "arguments": c.arguments} for c in calls]})
        else:
            messages.append({"role": "assistant", "content": completion.text})

        outcomes = await asyncio.gather(
            *(_invoke(by_name, c) for c in calls), return_exceptions=True)
        # zip against the call list, not a lookup by name: gather keeps
        # order, and a turn can call the same tool twice.
        results = [(c, _render(o, truncate_chars))
                   for c, o in zip(calls, outcomes)]

        if native:
            for call, content in results:
                messages.append({"role": "tool", "tool_call_id": call.id,
                                 "content": content})
        else:
            # A server with no tool support has no "tool" role to receive
            # these, so they come back as one user message.
            messages.append({"role": "user", "content": "\n\n".join(
                "TOOL_RESULT for call %s (%s):\n%s"
                % (c.id, c.name or "unnamed", content)
                for c, content in results)})

    return "[MAX_TURNS reached after %d turns]\n%s" % (max_turns, last_text)
