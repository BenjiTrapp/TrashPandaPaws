#!/usr/bin/env python3
"""A chain of providers, walked until one of them answers.

Before this, llm/loop.py logged a ProviderError and re-raised it, so one
rate-limited or revoked key ended the campaign. On a drop-box with a
single engagement window that is the difference between a result and
nothing, and the operator is not there to restart it.

Two behaviours, and they pull against each other:

  * **Move on when a link cannot serve.** Any ProviderError from an
    attempt counts, not a chosen subset of them. The transport reports
    HTTP status only inside a message, so classifying would mean parsing
    it back out, and the classification would be a guess either way: a
    401 is a revoked key *or* a header this code got wrong, and both are
    reasons to try the next link. Nothing is hidden by this, because
    every attempt is already written to `llm_interactions`, and when the
    chain runs out the error names every link that was tried.

  * **Do not keep paying for a link that is down.** A campaign is
    twenty-odd turns; retrying a dead head of the chain on each one costs
    twenty round trips and twenty timeouts, which is most of the delay
    the chain exists to remove. So a link that fails `trip_after` times
    in a row is skipped until `cooldown` has passed.

The chain reports the identity of whichever link answered, because
loop.py files every interaction row and token count under
`client.provider` and `client.model`.
"""

import time
from typing import Callable, List, NamedTuple, Optional

from software.agent.llm import provider as _provider
from software.agent.llm.provider import Completion, LlmClient, ProviderError

# Two, not one: a single transient failure is normal and tripping on it
# would take a healthy provider out of the chain for the cooldown.
DEFAULT_TRIP_AFTER = 2

# Long enough that a rate-limit window passes, short enough that a
# campaign still returns to the operator's preferred provider.
DEFAULT_COOLDOWN = 120.0


class _Link:
    __slots__ = ("client", "failures", "tripped_at")

    def __init__(self, client):
        self.client = client
        self.failures = 0
        self.tripped_at = None  # type: Optional[float]


class FailoverClient(LlmClient):
    """Walks `clients` in order on every turn."""

    def __init__(self, clients: List[LlmClient], *,
                 trip_after: int = DEFAULT_TRIP_AFTER,
                 cooldown: float = DEFAULT_COOLDOWN,
                 now: Optional[Callable[[], float]] = None):
        if not clients:
            # At construction, not at the first call: an empty chain
            # discovered mid-campaign is a campaign that cannot run.
            raise ValueError("a failover chain needs at least one client")
        self._links = [_Link(c) for c in clients]
        self._trip_after = max(1, int(trip_after))
        self._cooldown = float(cooldown)
        self._now = now or time.monotonic
        self._active = self._links[0]
        # A chain that claimed tools and then fell through to a link
        # without them would describe tools the model cannot call.
        self.supports_tools = all(
            getattr(c, "supports_tools", True) for c in clients)

    # ── Identity of whichever link is serving ──

    @property
    def provider(self) -> str:
        return self._active.client.provider

    @property
    def model(self) -> str:
        return self._active.client.model

    def health(self):
        """Per-link state, for the status endpoint."""
        now = self._now()
        out = []
        for link in self._links:
            tripped = self._is_tripped(link, now)
            out.append({
                "provider": link.client.provider,
                "model": link.client.model,
                "failures": link.failures,
                "tripped": tripped,
                "retry_in": (round(self._cooldown - (now - link.tripped_at), 1)
                             if tripped else 0.0),
            })
        return out

    # ── The walk ──

    def _is_tripped(self, link, now) -> bool:
        if link.tripped_at is None:
            return False
        if now - link.tripped_at >= self._cooldown:
            # The cooldown has passed: let it be tried again, and let a
            # single failure trip it straight back rather than giving it
            # a fresh allowance of trip_after.
            link.tripped_at = None
            link.failures = self._trip_after - 1
            return False
        return True

    async def complete(self, system, messages, tools, max_tokens, temperature):
        now = self._now()
        problems = []
        skipped = []
        for link in self._links:
            if self._is_tripped(link, now):
                skipped.append(link.client.provider)
                continue
            self._active = link
            try:
                answer = await link.client.complete(
                    system, messages, tools, max_tokens, temperature)
            except ProviderError as exc:
                link.failures += 1
                if link.failures >= self._trip_after:
                    link.tripped_at = now
                problems.append("%s: %s" % (link.client.provider, exc))
                continue
            link.failures = 0
            link.tripped_at = None
            return answer

        detail = "; ".join(problems) if problems else "none were tried"
        if skipped:
            detail += " (cooling down: %s)" % ", ".join(skipped)
        raise ProviderError("every provider in the chain failed -- " + detail)


def chain(clients, **kwargs) -> LlmClient:
    """The chain, or the bare client when there is only one.

    A single-link FailoverClient behaves identically, but wrapping is not
    free to read in a traceback or a repr, and most deployments configure
    one provider.
    """
    clients = list(clients)
    if len(clients) == 1:
        return clients[0]
    return FailoverClient(clients, **kwargs)


class _LinkConfig(NamedTuple):
    """The four attributes create_client reads, and nothing else.

    A shim rather than an AgentConfig: config.py imports this package's
    provider module, so importing config here would close a cycle.
    """
    provider: str
    model: str
    api_key: Optional[str]
    base_url: Optional[str]


def create_chain(cfg, **kwargs) -> LlmClient:
    """The primary provider followed by cfg.fallbacks, in order.

    Every link is built here, at startup, so a fallback that cannot be
    constructed -- a missing key, an unknown provider, no model -- is a
    configuration error reported now rather than at the first failover,
    which by definition happens when the primary has already gone.
    """
    # Called through the module, not an imported name: a test that patches
    # provider.create_client -- the one guarding that a leaked key never
    # reaches an availability reason -- would otherwise not reach this.
    clients = [_provider.create_client(cfg)]
    for number, link in enumerate(getattr(cfg, "fallbacks", ()) or (), 1):
        try:
            clients.append(_provider.create_client(_LinkConfig(
                provider=link.provider, model=link.model,
                api_key=link.api_key, base_url=link.base_url)))
        except ProviderError as exc:
            raise ProviderError(
                "fallback %d (%s / %s) cannot be used: %s"
                % (number, link.provider, link.model, exc)) from None
    return chain(clients, **kwargs)
