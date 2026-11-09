#!/usr/bin/env python3
"""The pre-engagement check of the provider chain.

    python3 -m software.agent.llm.preflight [--ping] [-c raccoon.yaml] [flags]

A "doctor" command: the thing an operator runs before an engagement to
learn, with a person waiting for the answer, whether the configured chain
will hold. It is the other half of `AgentConfig.available()`, and it is
deliberately everything that method is not.

`available()` is synchronous and polled by the status endpoint, so it does
no network I/O: it builds every link and reports what cannot be built, and
that is all it can afford. A probe in there would run once per poll, and
against a local server that is not running it would sit out its timeout
every time, freezing the UI on a page that is only meant to say "not
configured". So nothing here is called from `available()`, and nothing
should be moved there. This module may touch the network because it runs
once, on request.

Three things it adds, and what each costs:

  * **A local server is asked for its models.** The commonest local failure
    is a model that was never pulled, and it is invisible until the first
    call of the first turn, which is mid-engagement. Reading the list is
    free, so it always happens for a local link. The two local names are
    different servers: `ollama` is asked for `/api/tags`, `local` (LM Studio,
    llama.cpp) for the OpenAI-compatible `/v1/models`. One endpoint per
    name, so a working LM Studio link is not reported as down.
  * **A link with a token source is asked for a token.** Building the link
    checks only that the source is a sensible choice, and `available()` can
    afford no more, so a logged-out `gcloud` passes it. A token costs no
    model tokens, so this always happens too.
  * **`--ping` sends one tiny completion per link.** Opt-in, because it
    spends tokens on a metered provider, and a health check that costs money
    is one nobody runs. Without it nothing here calls a model, and a hosted
    link's "ok" means it is well-formed and, if it has a token source, that
    a token could be had.

Every link is built and reported on its own. `failover.create_chain` stops at
the first link it cannot build, which is right for startup and wrong here:
the operator wants to hear about all of them in one run.

The config carries live keys and this prints a line per link, so no line is
built from anything but a provider name, a model name, a host and port, a
status code, an exception class, a ProviderError or a TokenUnavailable, and
never from a token. The URL itself is never
printed, because a base_url may carry userinfo, and every detail is scrubbed
of the configured keys as a last line of defence.
"""

import argparse
import asyncio
import json
import sys
import urllib.error
import urllib.request
from typing import (Any, Callable, Dict, List, NamedTuple, Optional,
                    Tuple)
from urllib.parse import urlparse

from software.agent import config
from software.agent.llm import failover, gcp_token, provider
from software.agent.llm.provider import ProviderError

# A person is waiting, and a local server that has not answered in this long
# is not going to; the model transport has its own, much longer, timeout.
PROBE_TIMEOUT = 5.0

# Larger than any tag list a person has, small enough that a server which
# answers with something else cannot make this read without limit.
_MAX_PROBE_BYTES = 1 << 20

_PING_MAX_TOKENS = 16
_LISTED_MODELS = 5

# GET url -> parsed JSON. Blocking. Raises on any failure.
Probe = Callable[[str, float], Any]


def _http_get_json(url: str, timeout: float) -> Any:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read(_MAX_PROBE_BYTES).decode("utf-8"))


# ── One link ──


def _endpoint(name: str, base_url: Optional[str]) -> str:
    return (base_url or provider._PROVIDERS[name][1] or "").rstrip("/")


def _strip_v1(base_url: str) -> str:
    root = base_url.rstrip("/")
    return root[:-len("/v1")] if root.endswith("/v1") else root


def _ollama_url(base_url: str) -> str:
    # The client talks to `<root>/v1`; Ollama's own tag list is at
    # `<root>/api/tags`.
    return _strip_v1(base_url) + "/api/tags"


def _openai_url(base_url: str) -> str:
    # LM Studio and llama.cpp serve the OpenAI-compatible `<root>/v1/models`.
    # The base URL usually ends in /v1 already; stripping and re-adding it
    # takes either spelling to the same URL without doubling the segment.
    return _strip_v1(base_url) + "/v1/models"


def _ollama_names(payload: Any) -> Optional[List[str]]:
    """Ollama: {"models": [{"name": "qwen2.5:14b"}, ...]}"""
    return _names(payload, "models", "name")


def _openai_names(payload: Any) -> Optional[List[str]]:
    """OpenAI-compatible: {"data": [{"id": "qwen2.5-14b"}, ...]}"""
    return _names(payload, "data", "id")


def _is_pulled_ollama(model: str, names: List[str]) -> bool:
    # `ollama pull llama3.2` is stored, and listed, as `llama3.2:latest`.
    return (model if ":" in model else model + ":latest") in names


def _is_listed(model: str, names: List[str]) -> bool:
    return model in names


# One endpoint per provider name, chosen by the name: (URL from the base URL,
# path shown in a report, reader for the list it returns, "is this model
# there"). The two servers differ in all four, which is why "local" cannot
# borrow Ollama's.
_LOCAL_LISTS = {
    "ollama": (_ollama_url, "/api/tags", _ollama_names, _is_pulled_ollama),
    "local": (_openai_url, "/v1/models", _openai_names, _is_listed),
}  # type: Dict[str, Tuple[Callable, str, Callable, Callable]]
assert set(_LOCAL_LISTS) == set(provider.LOCAL_PROVIDERS)


def _host_port(url: str) -> str:
    parts = urlparse(url)
    try:
        port = parts.port
    except ValueError:
        port = None
    host = parts.hostname or "?"
    return "%s:%d" % (host, port) if port else host


def _names(payload: Any, list_key: str, name_key: str) -> Optional[List[str]]:
    """The names in a model list, or None if it is not the expected shape."""
    entries = payload.get(list_key) if isinstance(payload, dict) else None
    if not isinstance(entries, list):
        return None
    names = []
    for entry in entries:
        name = entry.get(name_key) if isinstance(entry, dict) else None
        if not isinstance(name, str):
            return None
        names.append(name)
    return names


# A server that answers these is up and wants a credential.
_NEEDS_CREDENTIALS = (401, 403)


def _probe_failure(exc: Exception, where: str, path: str) -> str:
    """What a failed GET means, without the URL or the exception's text."""
    if isinstance(exc, urllib.error.HTTPError):
        return "%s answered HTTP %d for %s" % (where, exc.code, path)
    if isinstance(exc, ValueError):
        return ("reachable at %s, but its model list is unreadable "
                "(%s was not JSON)" % (where, path))
    return "no server answering at %s (%s)" % (where, type(exc).__name__)


def _check_local(client, name: str, endpoint: str, probe: Probe,
                 has_key: bool) -> Tuple[bool, str]:
    url_for, path, read_names, is_there = _LOCAL_LISTS[name]
    where = _host_port(endpoint)
    try:
        payload = probe(url_for(endpoint), PROBE_TIMEOUT)
    except urllib.error.HTTPError as exc:
        if exc.code not in _NEEDS_CREDENTIALS:
            return False, _probe_failure(exc, where, path)
        # llama.cpp --api-key and LM Studio can require one. The probe sends
        # none, deliberately: a credential goes only to the model transport.
        # So this is a healthy server, not a broken one, and calling it down
        # would teach the operator to ignore the tool. It is ok only if the
        # link has a key to send; with none, the first model call is a 401.
        said = ("reachable at %s, but %s needs credentials and this probe "
                "does not send one; the model list was not checked"
                % (where, path))
        if has_key:
            return True, said + " (--ping tests the key)"
        return False, said + ", and this link has no api_key"
    except Exception as exc:
        return False, _probe_failure(exc, where, path)
    names = read_names(payload)
    if names is None:
        # Reachable is not the same as healthy, and an answer this code
        # cannot read must not pass as a model being there.
        return False, ("reachable at %s, but its model list is unreadable "
                       "(%s was not the expected shape)" % (where, path))
    if is_there(client.model, names):
        return True, "server at %s lists %r" % (where, client.model)
    if name == "local":
        # llama-server in single-model mode ignores the request's model and
        # advertises its file path, or --alias, as the id. A working link
        # with any label would otherwise fail here. One model listed is
        # reported ok with both names shown, so the operator can judge the
        # mismatch; a choice that lacks yours is a real misconfiguration.
        if not names:
            return False, ("server at %s is up, but lists no models; load "
                           "one" % where)
        if len(names) == 1:
            return True, ("server at %s lists one model %r; the configured "
                          "%r may be ignored"
                          % (where, names[0][:60], client.model))
    shown = ", ".join(repr(n[:60]) for n in names[:_LISTED_MODELS])
    if len(names) > _LISTED_MODELS:
        shown += ", ..."
    absent = ("not pulled" if name == "ollama"
              else "not in its model list")
    return False, ("server at %s is up, but %r is %s (it has: %s)"
                   % (where, client.model, absent, shown or "nothing"))


def _token(source) -> Tuple[bool, str]:
    # The token itself is dropped here: this prints a line per link, and the
    # only thing worth saying about a token is whether there was one.
    failure = None
    try:
        source.bearer()
    except gcp_token.TokenUnavailable as exc:
        failure = "no access token: %s" % exc
    except Exception as exc:
        failure = "no access token (%s)" % type(exc).__name__
    if failure is not None:
        return False, failure
    return True, "a token was obtained"


def _ping(client) -> Tuple[bool, str]:
    try:
        completion = asyncio.run(client.complete(
            "Reply with the single word: ok.",
            [{"role": "user", "content": "ping"}],
            [], _PING_MAX_TOKENS, 0.0))
    except ProviderError as exc:
        return False, "ping failed: %s" % exc
    except Exception as exc:
        return False, "ping failed (%s)" % type(exc).__name__
    return True, "answered (%d tokens in, %d out)" % (
        completion.input_tokens, completion.output_tokens)


def _secrets(cfg) -> List[str]:
    keys = [getattr(cfg, "api_key", None)]
    keys += [link.api_key for link in getattr(cfg, "fallbacks", ()) or ()]
    return [k for k in keys
            if isinstance(k, str) and len(k) >= config._SCRUB_MIN_LENGTH]


class _Link(NamedTuple):
    provider: str
    model: str
    build: Callable[[], Any]
    base_url: Optional[str]
    has_key: bool


def _links(cfg) -> List[_Link]:
    """The primary and each fallback, in the order they are tried."""
    links = [_Link(str(getattr(cfg, "provider", None) or "(none)").lower(),
                   str(getattr(cfg, "model", None) or ""),
                   lambda: provider.create_client(cfg),
                   getattr(cfg, "base_url", None),
                   bool(getattr(cfg, "api_key", None)))]
    for number, link in enumerate(getattr(cfg, "fallbacks", ()) or (), 1):
        links.append(_Link(
            link.provider, link.model,
            lambda l=link, n=number: failover.link_client(l, n),
            link.base_url, bool(link.api_key)))
    return links


def _check_built(client, name: str, base_url: Optional[str], probe: Probe,
                 has_key: bool, ping: bool) -> Tuple[bool, str]:
    """What a link that could be built can show, cheapest step first."""
    said = []
    source = getattr(client, "_token_source", None)
    if source is not None:
        # Free, unlike a ping: a token costs no model tokens, and whether one
        # can be had is the question this command exists to answer for a
        # link that has a source. Construction checked only that the choice
        # of source was well-formed, and a logged-out gcloud passes that.
        ok, detail = _token(source)
        if not ok:
            return False, detail
        said.append(detail)
    if name in provider.LOCAL_PROVIDERS:
        ok, detail = _check_local(client, name, _endpoint(name, base_url),
                                  probe, has_key)
        said.append(detail)
        if not ok:
            return False, "; ".join(said)
    elif not ping:
        said.insert(0, "built")
        said.append("nothing was sent (--ping sends one request)")
    if ping:
        ok, detail = _ping(client)
        said.append(detail)
        return ok, "; ".join(said)
    return True, "; ".join(said)


def check(cfg, *, ping: bool = False,
          probe: Optional[Probe] = None) -> List[Dict[str, Any]]:
    """One {provider, model, ok, detail} per link, primary first.

    Blocking. Never raises for a problem with a link: a link that cannot be
    built, a server that is down and a ping that fails are all rows. `probe`
    is the GET used for a local server's model list; the tests inject it so
    that none of them touches the network.
    """
    # Looked up here and not bound as a default, so a replacement of the
    # module's function is honoured.
    probe = probe or _http_get_json
    secrets = _secrets(cfg)
    rows = []
    for name, model, build, base_url, has_key in _links(cfg):
        try:
            client = build()
        except ProviderError as exc:
            ok, detail = False, str(exc)
        else:
            ok, detail = _check_built(client, name, base_url, probe, has_key,
                                      ping)
        for secret in secrets:
            detail = detail.replace(secret, "<redacted>")
        rows.append({"provider": name, "model": model, "ok": ok,
                     "detail": detail})
    return rows


# ── The command ──


def _format(rows: List[Dict[str, Any]]) -> List[str]:
    width_p = max(len(r["provider"]) for r in rows)
    width_m = max(len(r["model"]) for r in rows)
    return [("%-6s %-*s %-*s %s" % ("ok" if r["ok"] else "NOT OK",
                                    width_p, r["provider"],
                                    width_m, r["model"], r["detail"])).rstrip()
            for r in rows]


def main(argv=None) -> int:
    # The flags this command owns; everything else is config.load's, so a
    # typo in a configuration flag is still the configuration's error.
    pre = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    pre.add_argument("-c", "--config")
    pre.add_argument("--ping", action="store_true")
    known, rest = pre.parse_known_args(argv)

    # Imported here: the service entry point pulls in the web stack, which
    # this check has no other use for, and the YAML search order should
    # stay the service's own so the two can never read different files.
    from software.agent.__main__ import _yaml_path
    try:
        cfg = config.load(rest, yaml_path=_yaml_path(known.config))
    except (config.ConfigError, ValueError) as exc:
        print("cannot load the configuration: %s" % exc, file=sys.stderr)
        return 2

    rows = check(cfg, ping=known.ping)
    for line in _format(rows):
        print(line)
    return 0 if all(r["ok"] for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
