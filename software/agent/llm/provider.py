#!/usr/bin/env python3
"""LLM provider abstraction: shared types, transport, client selection, tiers.

Four backends (Anthropic, OpenRouter, OpenCode Zen, a local OpenAI-compatible
server) behind one `await client.complete(...)`. The agent loop sees only
ToolSpec / ToolCall / Completion, so a provider can be swapped without
touching anything above this package.

No vendor SDK is used. Both APIs are JSON over HTTPS, and the C2 has to keep
working with no model attached and no new dependency, so the clients build
and parse the wire formats themselves and send them through one transport
function, `http_post_json`, built on `requests` (already a declared
dependency) and run off the event loop with asyncio.to_thread. The transport
is the single seam: a client takes any `(url, headers, body) -> dict`
callable, so the HTTP layer can be replaced, or stubbed in a test, without
touching request building or response parsing.

Messages are kept in one internal shape, the OpenAI-like one:

    {"role": "user" | "assistant" | "tool", "content": str,
     "tool_calls": [{"id": str, "name": str, "arguments": dict}],   # assistant
     "tool_call_id": str}                                           # tool

An assistant tool call is also accepted in OpenAI's nested form
({"id", "type": "function", "function": {"name", "arguments"}}), so history
that already came from a Chat Completions server can be replayed unchanged.

Usage:
    from software.agent.llm import provider

    client = provider.create_client(cfg)   # cfg: provider/api_key/model/base_url
    tier = provider.capability_tier(client.model, client.provider)
    completion = await client.complete(system, messages, tools, 1024, 0.2)
"""

import abc
import asyncio
import ipaddress
import json
import re
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Tuple
from urllib.parse import urlparse

from software.agent.llm import gcp_token
from software.agent.secret import Secret

# ── Shapes ──


class ToolSpec(NamedTuple):
    name: str
    description: str
    parameters: dict


class ToolCall(NamedTuple):
    id: str
    name: str
    arguments: dict
    # Set when the model's arguments could not be read. Two independent
    # mechanisms guard this, because a convention a later caller has to
    # remember is the kind that gets forgotten: the sentinel keys below make
    # a `**arguments` dispatch raise, and this field makes the failure part
    # of the type, so a dispatcher that passes the dict whole still has
    # something to check that it cannot help seeing.
    error: Optional[str] = None


class Completion(NamedTuple):
    text: str
    tool_calls: List[ToolCall]
    input_tokens: int
    output_tokens: int
    total_tokens: int
    # One vocabulary for both wire formats: "end_turn", "max_tokens",
    # "tool_use", anything else passed through as the vendor wrote it.
    stop_reason: str


class ProviderError(Exception):
    """A readable failure naming the provider and model.

    Never carries the API key, request headers, or a response body: a server
    can echo an Authorization value back in an error body, and an exception
    message ends up in logs and in the audit trail.
    """


class TransportError(Exception):
    """A transport failure with a message that is safe to show.

    The transport knows neither provider nor model, so the client adds them
    when it turns this into a ProviderError. Anyone writing a replacement
    transport raises this, with a message that holds no URL, header or body.
    """


# (url, headers, json_body) -> parsed JSON object. Blocking; run in a thread.
Transport = Callable[[str, Dict[str, str], dict], dict]

# ── Malformed tool arguments ──
#
# ToolCall.arguments is a dict, but a model can emit arguments that are not
# JSON, or JSON that is not an object. Returning {} would let a tool run on
# its defaults with parameters the model never chose, and dropping the call
# would leave an assistant turn with no answer. So the call survives with
# these two keys as its only arguments: no tool declares them, so dispatching
# it fails loudly, and the loop can check for ARGUMENTS_ERROR_KEY and answer
# the model by call id with the reason instead of executing anything.
ARGUMENTS_ERROR_KEY = "_arguments_error"
RAW_ARGUMENTS_KEY = "_raw_arguments"
_RAW_ARGUMENTS_MAX = 200


def parse_arguments(raw: Any) -> dict:
    """Turn a wire-format tool-call argument value into a dict."""
    if isinstance(raw, dict):
        return raw
    # No-argument tools arrive as "", "{}" or null depending on the server.
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return {}
    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except ValueError as exc:
            return _bad_arguments(
                raw, "arguments were not valid JSON (%s)"
                % getattr(exc, "msg", "parse error"))
        if isinstance(value, dict):
            return value
        return _bad_arguments(
            raw, "arguments were valid JSON but not an object (got %s)"
            % type(value).__name__)
    return _bad_arguments(
        repr(raw), "arguments were not an object (got %s)" % type(raw).__name__)


def _bad_arguments(raw: str, reason: str) -> dict:
    return {ARGUMENTS_ERROR_KEY: reason,
            RAW_ARGUMENTS_KEY: raw[:_RAW_ARGUMENTS_MAX]}


def normalize_tool_call(entry: dict, index: int = 0) -> ToolCall:
    """Read one assistant tool call in either accepted shape."""
    fn = entry.get("function")
    if isinstance(fn, dict):
        name, raw = fn.get("name", ""), fn.get("arguments")
    else:
        name, raw = entry.get("name", ""), entry.get("arguments")
    # A local server that omits the id would otherwise fail a response that
    # is fine apart from that; the loop only needs ids to be unique per turn.
    call_id = entry.get("id") or "call_%d" % index
    arguments = parse_arguments(raw)
    return ToolCall(str(call_id), str(name), arguments,
                    arguments.get(ARGUMENTS_ERROR_KEY))


# ── Transport ──

_TIMEOUT_SECONDS = 120
# A 14B model answering from a CPU over Ollama routinely takes longer than
# two minutes. That is the normal case for a local endpoint, not a fault, so
# a timeout there would fail answers that were working.
LOCAL_TIMEOUT_SECONDS = 300
_STATUS_HINTS = {
    401: " (the API key was rejected)",
    403: " (the API key was rejected or lacks access)",
    429: " (rate limited)",
}


def http_post_json(url: str, headers: Dict[str, str], body: dict, *,
                   timeout: float = _TIMEOUT_SECONDS) -> dict:
    """POST a JSON body, return the JSON object that answers.

    Every message raised here is built from the status code or the exception
    class alone. `requests` exceptions can carry the request URL, and error
    bodies can echo the Authorization header, so neither is ever formatted
    into a message.

    The failure is also raised *outside* the except block. `from None` keeps
    the original off every normal path — traceback, `format_exception` and
    `logging(exc_info=True)` all honour `__suppress_context__` — but it does
    not clear `__context__` on the object, and a `requests.RequestException`
    holds a `.request` whose `.headers` contain the key. An error serialiser
    that walks the chain by hand would reach it. Raising once the except
    block has exited leaves `__context__` genuinely empty, which makes the
    guarantee independent of how any future caller formats errors. This
    project writes LLM interactions to SQLite, so that matters.
    """
    # Imported here, not at module level: importing requests is noisy on some
    # platforms (urllib3 warns about LibreSSL), and the agent package has to
    # import cleanly on a C2 that never talks to a model.
    import requests

    failure = None
    try:
        # allow_redirects=False: a redirect would carry a custom auth header
        # such as x-api-key to whichever host answered. requests only strips
        # the standard Authorization header on a cross-host redirect.
        resp = requests.post(url, headers=headers, json=body,
                             timeout=timeout, allow_redirects=False)
    except requests.RequestException as exc:
        failure = "request failed (%s)" % type(exc).__name__
    if failure is not None:
        raise TransportError(failure)
    if resp.status_code != 200:
        raise TransportError("HTTP %d%s" % (
            resp.status_code, _STATUS_HINTS.get(resp.status_code, "")))
    try:
        payload = resp.json()
    except ValueError:
        raise TransportError("response was not JSON") from None
    if not isinstance(payload, dict):
        raise TransportError("response was not a JSON object")
    return payload


# Re-exported from software.agent.secret: two modules carry live
# credentials and both need the same guarantee, so the holder does not
# live in either of them.



# ── Client base ──


class LlmClient(abc.ABC):
    provider = ""  # type: str
    model = ""  # type: str
    supports_tools = True  # type: bool

    @abc.abstractmethod
    async def complete(self, system: str, messages: List[dict],
                       tools: List[ToolSpec], max_tokens: int,
                       temperature: float) -> Completion:
        """One model turn. Raises ProviderError on any failure."""


class HttpLlmClient(LlmClient):
    """An LlmClient that talks JSON over HTTP through an injectable transport.

    Subclasses supply the two vendor-specific halves: building the request
    and parsing the reply. Everything between them, including the error
    handling that keeps the key out of messages, lives here once.
    """

    def __init__(self, provider: str, model: str, api_key: Optional[str],
                 base_url: str, transport: Optional[Transport] = None,
                 supports_tools: bool = True,
                 timeout: Optional[float] = None,
                 token_source: Optional[Any] = None):
        self.provider = provider
        self.model = model
        self.supports_tools = supports_tools
        self._base_url = base_url.rstrip("/")
        # The credential currently in use. A token source replaces it before
        # each turn, which is why the subclasses read it at request-build
        # time and never keep a copy.
        self._bearer = Secret(api_key)
        self._token_source = token_source
        self._timeout = _TIMEOUT_SECONDS if timeout is None else timeout
        if transport is None:
            # The timeout is bound into the default transport rather than
            # passed through the Transport signature, which stubs depend on.
            # An injected transport is the caller's own, so it is kept as is.
            transport = (lambda url, headers, body:
                         http_post_json(url, headers, body,
                                        timeout=self._timeout))
        self._transport = transport

    def __repr__(self) -> str:
        return "<%s provider=%r model=%r>" % (
            type(self).__name__, self.provider, self.model)

    def _fail(self, message: str) -> ProviderError:
        return ProviderError("provider %r, model %r: %s"
                             % (self.provider, self.model, message))

    @abc.abstractmethod
    def _build_request(self, system: str, messages: List[dict],
                       tools: List[ToolSpec], max_tokens: int,
                       temperature: float) -> Tuple[str, Dict[str, str], dict]:
        """Return (url, headers, body) for one turn."""

    @abc.abstractmethod
    def _parse_response(self, payload: dict) -> Completion:
        """Turn the vendor's reply into a Completion."""

    async def complete(self, system, messages, tools, max_tokens, temperature):
        if self._token_source is not None:
            # Off the event loop: bearer() may run gcloud or fetch from the
            # metadata server. Nothing is awaited between storing the token
            # and _build_request reading it, so two turns on one client
            # cannot swap each other's credential.
            #
            # Captured and raised outside the except, as below. A token
            # source's failure is a library exception whose message may hold
            # a URL or a response, so only a TokenUnavailable message (built
            # to be safe) is shown and anything else is named by class.
            failure = None
            try:
                token = await asyncio.to_thread(self._token_source.bearer)
            except gcp_token.TokenUnavailable as exc:
                failure = "no access token: %s" % exc
            except Exception as exc:
                failure = "no access token (%s)" % type(exc).__name__
            if failure is not None:
                raise self._fail(failure)
            self._bearer = Secret(token)
        url, headers, body = self._build_request(
            system, messages, list(tools) if self.supports_tools else [],
            max_tokens, temperature)
        # Each failure is captured and raised once the except block has
        # exited, so the resulting ProviderError has no __context__ at all.
        # See http_post_json's docstring: `from None` hides the original from
        # every normal path but leaves it reachable on the object, and a
        # transport exception can hold the request headers.
        failure = None
        try:
            payload = await asyncio.to_thread(
                self._transport, url, headers, body)
        except TransportError as exc:
            failure = str(exc)
        except ProviderError:
            raise
        except Exception as exc:
            # Only the class: a message from an arbitrary transport, or from
            # the library under it, may hold the URL or the headers.
            failure = "request failed (%s)" % type(exc).__name__
        if failure is not None:
            raise self._fail(failure)
        bad_shape = False
        try:
            return self._parse_response(payload)
        except ProviderError:
            raise
        except (KeyError, IndexError, TypeError, AttributeError, ValueError):
            # Not formatting the payload: it is the one thing here that a
            # hostile or buggy server controls.
            bad_shape = True
        if bad_shape:
            raise self._fail("the response did not have the expected shape")


def usage_tokens(usage: Any, key: str) -> int:
    try:
        return int(usage.get(key) or 0)
    except (AttributeError, TypeError, ValueError):
        return 0


# ── Capability tiers ──

# Strongest first; test_agent_provider walks this order and requires every
# limit to shrink along it. Spec §13.
TIER_LIMITS = {
    "full":    {"orchestrator_turns": 20, "executor_turns": 16,
                "truncate_chars": 4000, "max_phase": 5, "tool_set": "all"},
    "reduced": {"orchestrator_turns": 12, "executor_turns": 8,
                "truncate_chars": 2000, "max_phase": 4, "tool_set": "core"},
    "minimal": {"orchestrator_turns": 8,  "executor_turns": 6,
                "truncate_chars": 1000, "max_phase": 3, "tool_set": "bare"},
}  # type: Dict[str, dict]

# The allowlist for "full". Phase 5 is exploitation, so this is a safety
# boundary: a model that cannot be relied on to follow the rules must not
# be handed the most consequential actions. Everything that is not clearly
# on the list is "reduced", which is the safe direction to be wrong in, and
# an operator who knows better can override per run (Task 7).
#
# Each pattern is anchored so a prefix cannot vouch for a different model
# ("chatgpt-4o" is not "gpt-4o"), and the small siblings of an allowlisted
# family (mini, nano, haiku, flash) are excluded by name below.
_FULL_PATTERNS = (
    # Claude Sonnet / Opus from generation 4. {1,2} digits and a trailing
    # (?!\d) keep a date such as claude-sonnet-20240229 from passing as
    # generation 20240229. Older "claude-3-5-sonnet" has the family after
    # the number and so does not match: the plan says "ab 4".
    re.compile(r"(?<![a-z0-9])claude-(?:sonnet|opus)-(\d{1,2})(?!\d)"),
    # GPT-4o and its successors: 4.1 and the 5 line.
    re.compile(r"(?<![a-z0-9])gpt-(?:4o|4\.1|5)(?![a-z0-9])"),
    # Gemini Pro from 2: gemini-pro and 1.x Pro are too weak at tool use to
    # count as the same family.
    re.compile(r"(?<![a-z0-9])gemini-[2-9](?:\.\d+)?-pro(?![a-z0-9])"),
)
_SMALL_VARIANT = re.compile(r"(?<![a-z0-9])(?:mini|nano|lite|haiku|flash)"
                            r"(?![a-z0-9])")
_FULL_MIN_CLAUDE_GENERATION = 4

# "14b", "3.8b", "8x7b" in a model name. Not preceded by a letter, digit or
# dot, so "2.5:14b" yields 14 and not 5.
_PARAMS = re.compile(r"(?<![a-z0-9.])(?:(\d+)x)?(\d+(?:\.\d+)?)b(?![a-z0-9])")
_MINIMAL_BELOW_BILLION = 30


def _parameter_count_billions(model: str) -> Optional[float]:
    sizes = []
    for experts, size in _PARAMS.findall(model):
        sizes.append(float(size) * (int(experts) if experts else 1))
    # The smallest one named: several sizes in a name (a distill of a larger
    # model) are described by the one that actually runs.
    return min(sizes) if sizes else None


def _on_full_allowlist(model: str) -> bool:
    if _SMALL_VARIANT.search(model):
        return False
    for i, pattern in enumerate(_FULL_PATTERNS):
        m = pattern.search(model)
        if not m:
            continue
        if i == 0 and int(m.group(1)) < _FULL_MIN_CLAUDE_GENERATION:
            continue
        return True
    return False


def capability_tier(model, provider_name) -> str:
    """"full", "reduced" or "minimal" for the model driving the agent."""
    name = (model or "").strip().lower()
    local = (provider_name or "").strip().lower() in LOCAL_PROVIDERS
    # A local endpoint never reaches "full" on its name alone. The name is
    # whatever the operator typed; the server behind it may be anything,
    # while openrouter and opencode route to the model they are asked for.
    if not local and _on_full_allowlist(name):
        return "full"
    if local:
        size = _parameter_count_billions(name)
        if size is not None and size < _MINIMAL_BELOW_BILLION:
            return "minimal"
    return "reduced"


# ── Client selection ──

_LOOPBACK_NAMES = ("localhost",)

# name -> (client kind, default base_url, key required, base_url required).
# model is required for every provider: a default id would go stale, and a
# wrong one fails only at the first call, long after configuration.
_PROVIDERS = {
    "anthropic":  ("anthropic", "https://api.anthropic.com", True, False),
    # Bedrock's default endpoint is regional, so it is computed rather than
    # written here; see bedrock_base_url.
    "bedrock":    ("bedrock", None, True, False),
    "openrouter": ("openai", "https://openrouter.ai/api/v1", True, False),
    "opencode":   ("openai", None, True, True),
    "local":      ("openai", "http://127.0.0.1:11434/v1", False, False),
    "ollama":     ("openai", "http://127.0.0.1:11434/v1", False, False),
    "gemini":     ("openai",
                   "https://generativelanguage.googleapis.com/v1beta/openai",
                   True, False),
    # Computed from the project and location, like bedrock's; see
    # vertex_base_url. No key: the bearer is a short-lived token that a
    # token source supplies.
    "vertex":     ("openai", None, False, False),
}

# Providers whose endpoint is whatever the operator typed, so the model name
# vouches for nothing: a server named "gpt-4o" may be a 7B model. openrouter
# and opencode route to the model they are asked for and are not in here.
# "local" is LM Studio and llama.cpp; "ollama" is its own name for the same
# shape of endpoint.
LOCAL_PROVIDERS = frozenset(("local", "ollama"))


def _is_loopback(host: Optional[str]) -> bool:
    if host in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host or "").is_loopback
    except ValueError:
        return False


def _checked_base_url(name: str, url: str, has_credential: bool) -> str:
    parts = urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ProviderError(
            "provider %r: base_url must be an http(s) URL" % name)
    # The credential goes wherever base_url points. Over cleartext HTTP to
    # anything but this machine it would cross the network readable.
    if (has_credential and parts.scheme == "http"
            and not _is_loopback(parts.hostname)):
        raise ProviderError(
            "provider %r: refusing to send a credential over plain http to "
            "%s; use https" % (name, parts.hostname))
    return url


# ── Bedrock's regional endpoint ──

_BEDROCK_DEFAULT_REGION = "eu-central-1"


def bedrock_base_url(region=None) -> str:
    """The Converse endpoint for a region.

    Regional rather than fixed, and defaulting to an EU region: a model id
    carries its own region prefix (eu., us.), and sending an EU id to a US
    endpoint fails at the first call rather than at configuration. The
    environment's AWS_REGION is read here because that is where an AWS
    caller already keeps it; the config cascade can still override it with
    an explicit base_url.
    """
    if not region:
        import os
        region = (os.environ.get("AWS_REGION")
                  or os.environ.get("AWS_DEFAULT_REGION")
                  or _BEDROCK_DEFAULT_REGION)
    return "https://bedrock-runtime.%s.amazonaws.com" % region


# ── Vertex's per-project, per-region endpoint ──

# Google's own shape for a project id and for a location: lowercase letters,
# digits and hyphens, starting and ending with a letter or digit. Both values
# are interpolated into a URL, and the bearer goes wherever that URL points,
# so this is a credential boundary and not a tidiness check. A dot in the
# location moves the host ("europe-west4.evil.example"), a slash or "?" in
# the project moves the path, an "@" turns the host into userinfo. \Z and
# not $: "$" also matches before a trailing newline.
_GCP_IDENTIFIER = re.compile(r"\A[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\Z")

# The location is also the front of a host label, "<location>-aiplatform",
# and a DNS label is at most 63 characters. The project is only ever a path
# segment, so it keeps the identifier's own limit.
_VERTEX_HOST_SUFFIX = "-aiplatform"
_VERTEX_MAX_LOCATION = 63 - len(_VERTEX_HOST_SUFFIX)

# Google's non-regional location. Its host has no regional prefix:
# "global-aiplatform.googleapis.com" does not exist.
_VERTEX_GLOBAL = "global"


def _vertex_identifier(field: str, env: str, value: Any,
                       longest: int = 63) -> str:
    if value is None or value == "":
        raise ProviderError(
            "provider 'vertex': %s is not set; set %s" % (field, env))
    if (not isinstance(value, str) or not _GCP_IDENTIFIER.match(value)
            or len(value) > longest):
        raise ProviderError(
            "provider 'vertex': %s (%s) must be 2 to %d lowercase letters, "
            "digits or hyphens, starting and ending with a letter or digit; "
            "got %.40r" % (field, env, longest, value))
    return value


def vertex_base_url(project: Any, location: Any) -> str:
    """The OpenAI-compatible endpoint for a project in a location.

    Computed rather than written, as bedrock_base_url is, because the
    location appears twice (in the host and in the path) and the two must
    agree: a mismatch is a 404 at the first call, not a configuration error.

    "global" is mapped to the unprefixed host rather than refused: it is a
    real location that Google documents, some models are served only from
    it, and an operator who typed it meant exactly that host.

    "v1" is the stable path. "v1beta1" is the documented alternative on this
    endpoint if tool calling misbehaves on v1; this is the only place the
    version appears, so switching is a one-word change here.
    """
    project = _vertex_identifier("vertex_project", "AGENT_VERTEX_PROJECT",
                                 project)
    location = _vertex_identifier("vertex_location", "AGENT_VERTEX_LOCATION",
                                  location, _VERTEX_MAX_LOCATION)
    host = ("aiplatform.googleapis.com" if location == _VERTEX_GLOBAL
            else location + _VERTEX_HOST_SUFFIX + ".googleapis.com")
    return ("https://%s/v1/projects/%s/locations/%s/endpoints/openapi"
            % (host, project, location))


# Vertex's openapi endpoint takes "publisher/model". A bare id is a 404 at
# the first call, which on an unattended run nobody is there to see.
_VERTEX_MODEL = re.compile(r"\A[a-z0-9][a-z0-9-]*/[^/\s][^\s]*\Z")


def _vertex_token_source(kind: str, key_file: Optional[str]):
    # The failure is captured and raised once the except has exited, as in
    # http_post_json, so the ProviderError has no __context__ to walk.
    failure = None
    try:
        gcp_token.validate(kind, key_file=key_file)
    except gcp_token.TokenUnavailable as exc:
        failure = str(exc)
    if failure is not None:
        hint = ""
        if kind == "file" and not key_file:
            hint = "; set api_key_file (AGENT_API_KEY_FILE)"
        raise ProviderError(
            "provider 'vertex': token_source %r cannot be used: %s%s"
            % (kind, failure, hint))
    return gcp_token.source(kind, key_file=key_file)


def create_client(cfg) -> LlmClient:
    """Build the client for cfg.provider, or raise ProviderError."""
    # Imported here: the client modules import this one for the shared types.
    from software.agent.llm import (anthropic_client, bedrock_client,
                                    openai_client)

    name = str(getattr(cfg, "provider", None) or "").strip().lower()
    if not name:
        raise ProviderError(
            "no LLM provider configured; set one of: %s"
            % ", ".join(_PROVIDERS))
    if name not in _PROVIDERS:
        raise ProviderError("unknown LLM provider %r; supported: %s"
                            % (name, ", ".join(_PROVIDERS)))
    kind, default_url, needs_key, needs_url = _PROVIDERS[name]

    api_key = getattr(cfg, "api_key", None) or None
    model = str(getattr(cfg, "model", None) or "").strip()
    base_url = getattr(cfg, "base_url", None) or default_url
    if kind == "bedrock" and not base_url:
        base_url = bedrock_base_url()
    if needs_key and not api_key:
        raise ProviderError("provider %r requires an api_key" % name)
    if not model:
        raise ProviderError("provider %r requires an explicit model" % name)
    token_source = None
    if name == "vertex":
        if not _VERTEX_MODEL.match(model):
            raise ProviderError(
                "provider 'vertex': model %.60r needs a publisher prefix, "
                "as in google/gemini-3-pro; a bare id is a 404 at the first "
                "call" % model)
        if not base_url:
            base_url = vertex_base_url(
                getattr(cfg, "vertex_project", None),
                getattr(cfg, "vertex_location", None) or "europe-west4")
        # A fixed key, which the configuration has already labelled for the
        # operator as one that will not be refreshed, is used as it stands.
        # Otherwise the token comes from a source, and that choice is checked
        # now: `file` with no api_key_file would load cleanly and fail at
        # the first model call.
        if not getattr(cfg, "static_bearer", False):
            token_source = _vertex_token_source(
                getattr(cfg, "token_source", None) or "auto",
                getattr(cfg, "api_key_file", None) or None)
    if needs_url and not base_url:
        raise ProviderError(
            "provider %r has no default endpoint; set base_url to its "
            "OpenAI-compatible endpoint" % name)
    # A token source is a credential too. Without counting it, a provider
    # with no key at construction, such as vertex, would pass this guard on
    # an http:// base URL and then be handed a live OAuth bearer in cleartext.
    base_url = _checked_base_url(
        name, base_url, bool(api_key) or token_source is not None)
    if token_source is not None:
        # The source's token replaces the key before every turn; keeping both
        # would leave a credential the operator has superseded in memory.
        api_key = None

    if kind == "anthropic":
        return anthropic_client.AnthropicClient(
            model=model, api_key=api_key, base_url=base_url)
    if kind == "bedrock":
        return bedrock_client.BedrockClient(
            model=model, api_key=api_key, base_url=base_url)
    return openai_client.OpenAiCompatibleClient(
        provider=name, model=model, api_key=api_key, base_url=base_url,
        timeout=LOCAL_TIMEOUT_SECONDS if name in LOCAL_PROVIDERS else None,
        token_source=token_source)
