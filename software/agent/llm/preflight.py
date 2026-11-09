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

Two things it adds, and what each costs:

  * **A local server is asked for its models.** The commonest local failure
    is a model that was never pulled, and it is invisible until the first
    call of the first turn, which is mid-engagement. Reading the tag list is
    free, so it always happens for a local link.
  * **`--ping` sends one tiny completion per link.** Opt-in, because it
    spends tokens on a metered provider, and a health check that costs money
    is one nobody runs. Without it nothing here calls a model, and a hosted
    link's "ok" means only that it is well-formed.

Every link is built and reported on its own. `failover.create_chain` stops at
the first link it cannot build, which is right for startup and wrong here:
the operator wants to hear about all of them in one run.

The config carries live keys and this prints a line per link, so no line is
built from anything but a provider name, a model name, a host and port, a
status code, an exception class or a ProviderError. The URL itself is never
printed, because a base_url may carry userinfo, and every detail is scrubbed
of the configured keys as a last line of defence.
"""

import argparse
import asyncio
import json
import sys
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from software.agent import config
from software.agent.llm import failover, provider
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


def tags_url(base_url: str) -> str:
    """Ollama's model list, from the OpenAI-compatible base URL.

    The client talks to `<root>/v1`; the tag list lives at `<root>/api/tags`.
    """
    root = base_url.rstrip("/")
    if root.endswith("/v1"):
        root = root[:-len("/v1")]
    return root + "/api/tags"


def _host_port(url: str) -> str:
    parts = urlparse(url)
    try:
        port = parts.port
    except ValueError:
        port = None
    host = parts.hostname or "?"
    return "%s:%d" % (host, port) if port else host


def _model_names(payload: Any) -> Optional[List[str]]:
    """The names in a tag list, or None if it is not one."""
    models = payload.get("models") if isinstance(payload, dict) else None
    if not isinstance(models, list):
        return None
    names = []
    for entry in models:
        name = entry.get("name") if isinstance(entry, dict) else None
        if not isinstance(name, str):
            return None
        names.append(name)
    return names


def _is_pulled(model: str, names: List[str]) -> bool:
    # `ollama pull llama3.2` is stored, and listed, as `llama3.2:latest`.
    wanted = model if ":" in model else model + ":latest"
    return wanted in names


def _probe_failure(exc: Exception, where: str) -> str:
    """What a failed GET means, without the URL or the exception's text."""
    if isinstance(exc, urllib.error.HTTPError):
        return ("%s answered HTTP %d for the model list; is it an Ollama "
                "server?" % (where, exc.code))
    if isinstance(exc, ValueError):
        return "%s answered, but not with JSON" % where
    return "no server answering at %s (%s)" % (where, type(exc).__name__)


def _check_local(client, endpoint: str,
                 probe: Probe) -> Tuple[bool, str]:
    where = _host_port(endpoint)
    try:
        payload = probe(tags_url(endpoint), PROBE_TIMEOUT)
    except Exception as exc:
        return False, _probe_failure(exc, where)
    names = _model_names(payload)
    if names is None:
        return False, "%s answered, but not with a model list" % where
    if _is_pulled(client.model, names):
        return True, "server at %s has %r" % (where, client.model)
    shown = ", ".join(repr(n[:60]) for n in names[:_LISTED_MODELS])
    if len(names) > _LISTED_MODELS:
        shown += ", ..."
    return False, ("server at %s is up, but %r is not pulled (it has: %s)"
                   % (where, client.model, shown or "nothing"))


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


def _links(cfg) -> List[Tuple[str, str, Callable[[], Any], Optional[str]]]:
    """(provider, model, build, base_url) for the primary and each fallback."""
    links = [(str(getattr(cfg, "provider", None) or "(none)").lower(),
              str(getattr(cfg, "model", None) or ""),
              lambda: provider.create_client(cfg),
              getattr(cfg, "base_url", None))]
    for number, link in enumerate(getattr(cfg, "fallbacks", ()) or (), 1):
        links.append((link.provider, link.model,
                      lambda n=number: failover.link_client(cfg, n),
                      link.base_url))
    return links


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
    for name, model, build, base_url in _links(cfg):
        try:
            client = build()
        except ProviderError as exc:
            ok, detail = False, str(exc)
        else:
            if name in provider.LOCAL_PROVIDERS:
                ok, detail = _check_local(client, _endpoint(name, base_url),
                                          probe)
                if ok and ping:
                    ok, said = _ping(client)
                    detail = "%s; %s" % (detail, said)
            elif ping:
                ok, detail = _ping(client)
            else:
                ok, detail = True, ("built; nothing was sent (--ping sends "
                                    "one request)")
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
