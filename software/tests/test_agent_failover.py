#!/usr/bin/env python3
"""Failover across a chain of providers.

Before this, loop.py logged a ProviderError and re-raised it: one
rate-limited or revoked key ended the campaign. For an unattended
drop-box with a single engagement window that is the difference between
a result and nothing.

What is pinned here is the behaviour that makes a chain worth having and
the behaviour that makes it honest: it moves on when a provider cannot
serve, it does not keep paying for a provider that is down, and when
every link fails it raises rather than returning something empty.
"""

import asyncio
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent.llm import failover
from software.agent.llm.provider import Completion, LlmClient, ProviderError


class _Stub(LlmClient):
    """A client that answers, or fails, on command."""

    def __init__(self, name, *, fails=0, pattern=None, text=None):
        self.provider = name
        self.model = name + "-model"
        self.supports_tools = True
        self._fails = fails
        # An explicit per-call pattern, for the cases where "the first N
        # fail" cannot express the thing under test: alternating failure
        # is the only way to show that a success clears the count.
        self._pattern = list(pattern) if pattern else None
        self._text = text or ("answered by " + name)
        self.calls = 0

    async def complete(self, system, messages, tools, max_tokens, temperature):
        self.calls += 1
        if self._pattern is not None:
            fail = self._pattern[(self.calls - 1) % len(self._pattern)]
            if fail:
                raise ProviderError("provider %r is down" % self.provider)
        elif self._fails > 0:
            self._fails -= 1
            raise ProviderError("provider %r is down" % self.provider)
        return Completion(self._text, [], 10, 5, 15, "end_turn")


def _run(coro):
    return asyncio.run(coro)


def _complete(chain):
    return _run(chain.complete("sys", [{"role": "user", "content": "hi"}],
                               [], 100, 0.0))


class TestTheChainIsWalkedInOrder(unittest.TestCase):
    def test_the_first_one_that_works_is_used(self):
        a, b = _Stub("a"), _Stub("b")
        answer = _complete(failover.FailoverClient([a, b]))
        self.assertEqual(answer.text, "answered by a")
        self.assertEqual((a.calls, b.calls), (1, 0))

    def test_a_failure_moves_to_the_next(self):
        a, b = _Stub("a", fails=1), _Stub("b")
        answer = _complete(failover.FailoverClient([a, b]))
        self.assertEqual(answer.text, "answered by b")
        self.assertEqual((a.calls, b.calls), (1, 1))

    def test_every_link_failing_raises(self):
        a, b = _Stub("a", fails=1), _Stub("b", fails=1)
        with self.assertRaises(ProviderError) as caught:
            _complete(failover.FailoverClient([a, b]))
        # The message has to name what was tried, or an operator reading
        # the log sees one provider's failure and not that the chain ran out.
        message = str(caught.exception)
        self.assertIn("a", message)
        self.assertIn("b", message)

    def test_an_empty_chain_is_refused_at_construction(self):
        # Not at the first call, which would be mid-campaign.
        with self.assertRaises(ValueError):
            failover.FailoverClient([])

    def test_a_single_link_behaves_like_the_bare_client(self):
        a = _Stub("a", fails=1)
        with self.assertRaises(ProviderError):
            _complete(failover.FailoverClient([a]))
        self.assertEqual(a.calls, 1)


class TestTheActiveLinkIsVisible(unittest.TestCase):
    """llm_loop logs `client.provider` and `client.model` on every turn.

    If the chain reported the first link's identity while the second one
    answered, every interaction row and every token count would be filed
    against a provider that did not serve it -- and the drawer's model
    line would be wrong exactly when it matters most.
    """

    def test_it_reports_the_link_that_answered(self):
        a, b = _Stub("a", fails=1), _Stub("b")
        chain = failover.FailoverClient([a, b])
        _complete(chain)
        self.assertEqual(chain.provider, "b")
        self.assertEqual(chain.model, "b-model")

    def test_before_the_first_call_it_reports_the_head(self):
        chain = failover.FailoverClient([_Stub("a"), _Stub("b")])
        self.assertEqual(chain.provider, "a")

    def test_tools_are_supported_only_if_every_link_supports_them(self):
        # A chain that claims tools and then falls through to a link
        # without them would hand the model a prompt describing tools it
        # cannot call.
        a, b = _Stub("a"), _Stub("b")
        b.supports_tools = False
        self.assertFalse(failover.FailoverClient([a, b]).supports_tools)
        self.assertTrue(failover.FailoverClient([a]).supports_tools)


class TestADeadLinkIsNotPaidForEveryTurn(unittest.TestCase):
    """Without this, a dead first link costs a request on every turn.

    A campaign is twenty-odd turns. Retrying a revoked key at the head of
    the chain each time means twenty wasted round trips and twenty times
    its timeout, which is most of the delay the chain was supposed to
    remove.
    """

    def test_a_link_is_skipped_after_enough_consecutive_failures(self):
        a, b = _Stub("a", fails=99), _Stub("b")
        chain = failover.FailoverClient([a, b], trip_after=2, cooldown=60.0)
        for _ in range(4):
            _complete(chain)
        # Two failures trip it; the next two turns skip it entirely.
        self.assertEqual(a.calls, 2)
        self.assertEqual(b.calls, 4)

    def test_a_success_clears_the_count(self):
        # Alternating, and asserted over enough turns to matter. The
        # first version used fails=1 and trip_after=2, so the count never
        # reached the threshold whether it reset or not -- the test was
        # named for the reset and could not see it. A mutation that
        # removed the reset left it green.
        a = _Stub("a", pattern=[True, False])      # fail, work, fail, work
        b = _Stub("b")
        chain = failover.FailoverClient([a, b], trip_after=2, cooldown=60.0)
        for _ in range(6):
            _complete(chain)
        # Without the reset: fail(1), ok, fail(2) trips it, and a is never
        # called again. With it, a is tried on all six turns.
        self.assertEqual(a.calls, 6, "a was tripped, so the count did not reset")
        self.assertEqual(b.calls, 3, "b served only the turns a failed")

    def test_a_tripped_link_is_tried_again_after_the_cooldown(self):
        a, b = _Stub("a", fails=2), _Stub("b")
        clock = [1000.0]
        chain = failover.FailoverClient([a, b], trip_after=2, cooldown=30.0,
                                        now=lambda: clock[0])
        _complete(chain)
        _complete(chain)              # a is tripped here
        self.assertEqual(a.calls, 2)
        _complete(chain)
        self.assertEqual(a.calls, 2, "a was retried before its cooldown")
        clock[0] += 31.0
        _complete(chain)
        self.assertEqual(a.calls, 3, "a was not retried after its cooldown")

    def test_after_a_cooldown_one_failure_trips_it_straight_back(self):
        # The choice this pins: a link that comes back from a cooldown and
        # fails again does not get a fresh allowance of trip_after. A
        # revoked key is still revoked, and giving it two more attempts
        # every cooldown is the cost the trip exists to avoid.
        a, b = _Stub("a", fails=99), _Stub("b")
        clock = [1000.0]
        chain = failover.FailoverClient([a, b], trip_after=2, cooldown=30.0,
                                        now=lambda: clock[0])
        _complete(chain)
        _complete(chain)
        self.assertEqual(a.calls, 2, "it should be tripped by now")
        clock[0] += 31.0
        _complete(chain)
        self.assertEqual(a.calls, 3, "the cooldown should allow one attempt")
        _complete(chain)
        self.assertEqual(a.calls, 3, "that one failure should re-trip it")

    def test_every_link_tripped_still_raises_rather_than_hanging(self):
        a, b = _Stub("a", fails=99), _Stub("b", fails=99)
        chain = failover.FailoverClient([a, b], trip_after=1, cooldown=60.0)
        with self.assertRaises(ProviderError):
            _complete(chain)
        with self.assertRaises(ProviderError) as caught:
            _complete(chain)
        self.assertIn("cooling", str(caught.exception).lower())


class TestTheHealthOfTheChainIsReadable(unittest.TestCase):
    """The status endpoint should be able to say which link is serving."""

    def test_it_reports_each_link_and_its_state(self):
        a, b = _Stub("a", fails=99), _Stub("b")
        chain = failover.FailoverClient([a, b], trip_after=1, cooldown=60.0)
        _complete(chain)
        health = chain.health()
        self.assertEqual([h["provider"] for h in health], ["a", "b"])
        self.assertTrue(health[0]["tripped"])
        self.assertFalse(health[1]["tripped"])

    def test_a_fresh_chain_reports_nothing_tripped(self):
        chain = failover.FailoverClient([_Stub("a"), _Stub("b")])
        self.assertFalse(any(h["tripped"] for h in chain.health()))


class TestTheChainIsBuiltFromTheConfig(unittest.TestCase):
    """create_chain lives here, not in provider.py: config imports
    provider, so provider importing failover would close a cycle."""

    def _cfg(self, **kw):
        from software.agent import config
        base = dict(provider="bedrock", model="eu.anthropic.x",
                    api_key="primary")
        base.update(kw)
        return config.AgentConfig(**base)

    def test_no_fallbacks_gives_the_bare_client(self):
        chain = failover.create_chain(self._cfg())
        self.assertNotIsInstance(chain, failover.FailoverClient)
        self.assertEqual(chain.provider, "bedrock")

    def test_a_fallback_produces_a_chain_in_order(self):
        from software.agent import config
        cfg = self._cfg(fallbacks=(
            config.FallbackLink(provider="anthropic", model="claude",
                                api_key="second"),))
        chain = failover.create_chain(cfg)
        self.assertIsInstance(chain, failover.FailoverClient)
        self.assertEqual([h["provider"] for h in chain.health()],
                         ["bedrock", "anthropic"])

    def test_a_link_that_cannot_be_built_is_reported_with_its_place(self):
        # A fallback missing its key is a configuration error, and it has
        # to surface at startup rather than at the first failover.
        from software.agent import config
        from software.agent.llm.provider import ProviderError
        cfg = self._cfg(fallbacks=(
            config.FallbackLink(provider="anthropic", model="claude",
                                api_key=None),))
        with self.assertRaises(ProviderError) as caught:
            failover.create_chain(cfg)
        self.assertIn("fallback", str(caught.exception).lower())

    def test_a_local_link_needs_no_key(self):
        from software.agent import config
        cfg = self._cfg(fallbacks=(
            config.FallbackLink(provider="local", model="qwen",
                                base_url="http://127.0.0.1:11434/v1"),))
        chain = failover.create_chain(cfg)
        self.assertEqual([h["provider"] for h in chain.health()],
                         ["bedrock", "local"])

    def test_a_vertex_link_without_a_base_url_says_it_needs_one(self):
        # A link carries provider, model, key and base_url and nothing else,
        # so it cannot inherit the primary's project. The old message said
        # "set AGENT_VERTEX_PROJECT", which is already set in this case.
        from software.agent import config
        from software.agent.llm.provider import ProviderError
        cfg = self._cfg(vertex_project="my-proj", fallbacks=(
            config.FallbackLink(provider="vertex",
                                model="google/gemini-3-pro"),))
        with self.assertRaises(ProviderError) as caught:
            failover.create_chain(cfg)
        message = str(caught.exception)
        self.assertIn("explicit base_url", message)
        self.assertIn("fallback 1", message)
        self.assertNotIn("AGENT_VERTEX_PROJECT", message)
        # A reader copying the shape must not build the one URL that does
        # not resolve.
        self.assertIn("global", message)
        self.assertIn("no prefix", message)

    def test_link_client_takes_the_link_and_its_place(self):
        from software.agent import config
        from software.agent.llm.provider import ProviderError
        link = config.FallbackLink(provider="anthropic", model="claude",
                                   api_key=None)
        with self.assertRaises(ProviderError) as caught:
            failover.link_client(link, 3)
        self.assertIn("fallback 3 (anthropic / claude)", str(caught.exception))
        built = failover.link_client(
            config.FallbackLink(provider="anthropic", model="claude",
                                api_key="k"), 1)
        self.assertEqual(built.provider, "anthropic")

    def test_a_vertex_link_with_a_base_url_is_built(self):
        import unittest.mock
        from software.agent import config
        from software.agent.llm import gcp_token, provider
        base = provider.vertex_base_url("my-proj", "europe-west4")
        cfg = self._cfg(token_source="gcloud", fallbacks=(
            config.FallbackLink(provider="vertex",
                                model="google/gemini-3-pro",
                                base_url=base),))
        with unittest.mock.patch.object(gcp_token.shutil, "which",
                                        return_value="/usr/bin/gcloud"):
            chain = failover.create_chain(cfg)
        self.assertEqual([h["provider"] for h in chain.health()],
                         ["bedrock", "vertex"])


if __name__ == "__main__":
    unittest.main()
