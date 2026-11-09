#!/usr/bin/env python3
"""The pre-engagement check of the provider chain.

What is pinned here: every link is reported and one broken link does not
hide the rest; a local server is asked for its models so a model that was
never pulled shows up before the first call; a dead server is a report and
not a traceback; nothing is sent to a model unless asked; and no line it
prints can carry a credential. No test touches the network: `probe` is
injected, and the model transport is patched to raise if it is reached.
"""

import contextlib
import io
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent import config
from software.agent.llm import preflight, provider

_KEY = "sk-live-0123456789abcdef"
_OTHER_KEY = "sk-other-fedcba9876543210"
_TAGS = {"models": [{"name": "qwen2.5:14b"}, {"name": "llama3.2:latest"}]}
# What LM Studio and llama.cpp return from /v1/models: a different list key
# and a different name key from Ollama's tags.
_MODELS = {"object": "list",
           "data": [{"id": "qwen2.5-14b-instruct", "object": "model"},
                    {"id": "llama-3.2-3b", "object": "model"}]}


def _cfg(**kw):
    values = dict(provider="anthropic", model="claude-sonnet-4-5",
                  api_key=_KEY)
    values.update(kw)
    return config.AgentConfig(**values)


def _ollama(**kw):
    values = dict(provider="ollama", model="qwen2.5:14b", api_key=None)
    values.update(kw)
    return _cfg(**values)


class _Probe:
    """Records what it was asked for and answers with `payload`."""

    def __init__(self, payload=None, raises=None):
        self.payload = payload
        self.raises = raises
        self.calls = []

    def __call__(self, url, timeout):
        self.calls.append((url, timeout))
        if self.raises is not None:
            raise self.raises
        return self.payload


def _local(**kw):
    values = dict(provider="local", model="qwen2.5-14b-instruct",
                  api_key=None)
    values.update(kw)
    return _cfg(**values)


class TestEveryLinkIsReported(unittest.TestCase):
    def test_every_link_in_the_chain_is_reported(self):
        cfg = _cfg(fallbacks=(
            config.FallbackLink(provider="openrouter", model="m/one",
                                api_key=_OTHER_KEY),
            config.FallbackLink(provider="ollama", model="qwen2.5:14b"),
        ))
        rows = preflight.check(cfg, probe=_Probe(_TAGS))
        self.assertEqual([r["provider"] for r in rows],
                         ["anthropic", "openrouter", "ollama"])
        self.assertEqual([r["model"] for r in rows],
                         ["claude-sonnet-4-5", "m/one", "qwen2.5:14b"])
        for row in rows:
            self.assertEqual(sorted(row), ["detail", "model", "ok", "provider"])
            self.assertTrue(row["ok"], row)

    def test_a_construction_failure_is_reported_per_link_not_raised(self):
        # The primary and the last link are fine; the middle one has no key.
        # create_chain would stop at the middle one and say nothing of the
        # third.
        cfg = _cfg(fallbacks=(
            config.FallbackLink(provider="openrouter", model="m/one",
                                api_key=None),
            config.FallbackLink(provider="ollama", model="qwen2.5:14b"),
        ))
        rows = preflight.check(cfg, probe=_Probe(_TAGS))
        self.assertEqual([r["ok"] for r in rows], [True, False, True])
        self.assertIn("api_key", rows[1]["detail"])

    def test_a_primary_that_cannot_be_built_does_not_hide_the_fallbacks(self):
        cfg = _cfg(api_key=None, fallbacks=(
            config.FallbackLink(provider="ollama", model="qwen2.5:14b"),))
        rows = preflight.check(cfg, probe=_Probe(_TAGS))
        self.assertEqual([r["ok"] for r in rows], [False, True])

    def test_no_provider_at_all_is_a_report(self):
        rows = preflight.check(_cfg(provider=None, model=None, api_key=None),
                               probe=_Probe(_TAGS))
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["ok"])
        self.assertIn("no LLM provider", rows[0]["detail"])

    def test_a_vertex_fallback_without_a_base_url_says_it_needs_one(self):
        cfg = _cfg(vertex_project="proj", fallbacks=(
            config.FallbackLink(provider="vertex",
                                model="google/gemini-3-pro"),))
        rows = preflight.check(cfg, probe=_Probe(_TAGS))
        self.assertFalse(rows[1]["ok"])
        self.assertIn("explicit base_url", rows[1]["detail"])

    def test_a_link_that_is_fine_but_unprobed_says_so(self):
        # "ok" for a hosted link means it is well-formed, and the line must
        # not let a reader take it for "the provider answered".
        row = preflight.check(_cfg(), probe=_Probe(_TAGS))[0]
        self.assertTrue(row["ok"])
        self.assertIn("--ping", row["detail"])


class TestALocalServerIsAskedForItsModels(unittest.TestCase):
    def test_an_ollama_link_is_checked_for_a_server_and_a_pulled_model(self):
        probe = _Probe(_TAGS)
        row = preflight.check(_ollama(), probe=probe)[0]
        self.assertTrue(row["ok"], row)
        self.assertIn("qwen2.5:14b", row["detail"])

        row = preflight.check(_ollama(model="mistral:7b"),
                              probe=_Probe(_TAGS))[0]
        self.assertFalse(row["ok"])
        self.assertIn("mistral:7b", row["detail"])
        self.assertIn("not pulled", row["detail"])

    def test_the_missing_model_is_reported_with_what_is_there(self):
        row = preflight.check(_ollama(model="mistral:7b"),
                              probe=_Probe(_TAGS))[0]
        self.assertIn("qwen2.5:14b", row["detail"])

    def test_a_bare_name_means_latest(self):
        # `ollama pull llama3.2` is stored as llama3.2:latest.
        row = preflight.check(_ollama(model="llama3.2"),
                              probe=_Probe(_TAGS))[0]
        self.assertTrue(row["ok"], row)

    def test_a_different_tag_is_not_the_same_model(self):
        row = preflight.check(_ollama(model="qwen2.5:7b"),
                              probe=_Probe(_TAGS))[0]
        self.assertFalse(row["ok"])

    def test_the_tags_url_is_derived_from_the_base_url(self):
        for base in ("http://127.0.0.1:11434/v1", "http://127.0.0.1:11434/v1/",
                     "http://127.0.0.1:11434"):
            with self.subTest(base_url=base):
                probe = _Probe(_TAGS)
                preflight.check(_ollama(base_url=base), probe=probe)
                self.assertEqual([c[0] for c in probe.calls],
                                 ["http://127.0.0.1:11434/api/tags"])

    def test_the_default_endpoint_is_used_when_none_is_configured(self):
        probe = _Probe(_TAGS)
        preflight.check(_ollama(base_url=None), probe=probe)
        self.assertEqual(probe.calls[0][0],
                         "http://127.0.0.1:11434/api/tags")

    def test_a_fallback_links_own_base_url_is_the_one_probed(self):
        cfg = _cfg(fallbacks=(config.FallbackLink(
            provider="ollama", model="qwen2.5:14b",
            base_url="http://127.0.0.1:9999/v1"),))
        probe = _Probe(_TAGS)
        preflight.check(cfg, probe=probe)
        self.assertEqual([c[0] for c in probe.calls],
                         ["http://127.0.0.1:9999/api/tags"])

    def test_ollama_is_never_asked_for_the_openai_list(self):
        probe = _Probe(_TAGS)
        preflight.check(_ollama(), probe=probe)
        self.assertNotIn("/models", probe.calls[0][0])

    def test_the_request_has_a_short_timeout(self):
        probe = _Probe(_TAGS)
        preflight.check(_ollama(), probe=probe)
        self.assertLessEqual(probe.calls[0][1], 10)

    def test_a_hosted_provider_is_never_probed(self):
        probe = _Probe(_TAGS)
        preflight.check(_cfg(), probe=probe)
        self.assertEqual(probe.calls, [])


class TestLocalIsAskedForTheOpenAiList(unittest.TestCase):
    """`local` is LM Studio and llama.cpp. They have no /api/tags, so
    routing them there reports a working server as down."""

    def test_a_local_link_whose_model_is_listed_is_ok(self):
        probe = _Probe(_MODELS)
        row = preflight.check(_local(), probe=probe)[0]
        self.assertTrue(row["ok"], row)
        self.assertIn("qwen2.5-14b-instruct", row["detail"])

    def test_a_local_link_whose_model_is_absent_names_it(self):
        row = preflight.check(_local(model="mistral-7b"),
                              probe=_Probe(_MODELS))[0]
        self.assertFalse(row["ok"])
        self.assertIn("mistral-7b", row["detail"])
        self.assertIn("not in its model list", row["detail"])
        self.assertIn("llama-3.2-3b", row["detail"])

    def test_the_models_url_is_the_same_with_or_without_v1(self):
        for base in ("http://127.0.0.1:1234/v1", "http://127.0.0.1:1234/v1/",
                     "http://127.0.0.1:1234", "http://127.0.0.1:1234/"):
            with self.subTest(base_url=base):
                probe = _Probe(_MODELS)
                preflight.check(_local(base_url=base), probe=probe)
                self.assertEqual([c[0] for c in probe.calls],
                                 ["http://127.0.0.1:1234/v1/models"])

    def test_the_default_endpoint_is_used_when_none_is_configured(self):
        probe = _Probe(_MODELS)
        preflight.check(_local(base_url=None), probe=probe)
        self.assertEqual(probe.calls[0][0],
                         "http://127.0.0.1:11434/v1/models")

    def test_local_is_never_asked_for_ollamas_tags(self):
        probe = _Probe(_MODELS)
        preflight.check(_local(), probe=probe)
        self.assertNotIn("/api/tags", probe.calls[0][0])

    def test_a_fallback_local_link_is_probed_at_its_own_url(self):
        cfg = _cfg(fallbacks=(config.FallbackLink(
            provider="local", model="qwen2.5-14b-instruct",
            base_url="http://127.0.0.1:1234/v1"),))
        probe = _Probe(_MODELS)
        rows = preflight.check(cfg, probe=probe)
        self.assertTrue(rows[1]["ok"], rows)
        self.assertEqual([c[0] for c in probe.calls],
                         ["http://127.0.0.1:1234/v1/models"])

    def test_the_four_cases_of_what_a_local_server_lists(self):
        # llama-server in single-model mode ignores the request's model and
        # lists its file path or --alias, so one listed model that is not the
        # configured name is still a working link.
        def lists(*ids):
            return {"data": [{"id": i} for i in ids]}

        match = preflight.check(
            _local(model="qwen"), probe=_Probe(lists("qwen", "other")))[0]
        self.assertTrue(match["ok"], match)
        self.assertIn("lists 'qwen'", match["detail"])

        one = preflight.check(
            _local(model="qwen"), probe=_Probe(lists("/models/q.gguf")))[0]
        self.assertTrue(one["ok"], one)
        self.assertIn("one model '/models/q.gguf'", one["detail"])
        self.assertIn("'qwen' may be ignored", one["detail"])

        many = preflight.check(
            _local(model="qwen"), probe=_Probe(lists("a.gguf", "b.gguf")))[0]
        self.assertFalse(many["ok"])
        self.assertIn("'qwen'", many["detail"])
        self.assertIn("not in its model list", many["detail"])
        self.assertNotIn("may be ignored", many["detail"])

        none = preflight.check(_local(model="qwen"),
                               probe=_Probe(lists()))[0]
        self.assertFalse(none["ok"])
        self.assertIn("lists no models", none["detail"])
        self.assertNotIn("not in its model list", none["detail"])

    def test_one_model_that_is_not_the_configured_one_is_still_not_ok_on_ollama(
            self):
        # Ollama honours the model field, so an absent model is not pulled.
        row = preflight.check(
            _ollama(model="mistral:7b"),
            probe=_Probe({"models": [{"name": "qwen2.5:14b"}]}))[0]
        self.assertFalse(row["ok"])
        self.assertIn("not pulled", row["detail"])

    def test_an_empty_ollama_list_stays_not_ok(self):
        row = preflight.check(_ollama(), probe=_Probe({"models": []}))[0]
        self.assertFalse(row["ok"])

    def test_the_name_is_matched_exactly_with_no_latest_rule(self):
        # Ollama's `llama3.2` means `llama3.2:latest`; an OpenAI-style id is
        # just a string.
        row = preflight.check(_local(model="llama-3.2"),
                              probe=_Probe(_MODELS))[0]
        self.assertFalse(row["ok"])

    def test_each_provider_reads_only_its_own_shape(self):
        # The tags shape from a `local` server, and the models shape from an
        # `ollama` one, are answers neither can read: not a pass.
        self.assertFalse(preflight.check(_local(), probe=_Probe(_TAGS))[0]["ok"])
        self.assertFalse(
            preflight.check(_ollama(), probe=_Probe(_MODELS))[0]["ok"])

    def test_an_unreachable_local_server_is_not_ok_and_does_not_raise(self):
        row = preflight.check(
            _local(), probe=_Probe(raises=ConnectionRefusedError()))[0]
        self.assertFalse(row["ok"])
        self.assertIn("127.0.0.1:11434", row["detail"])

    def test_a_local_link_that_is_ok_can_be_pinged(self):
        with unittest.mock.patch.object(provider, "http_post_json",
                                        _a_completion):
            row = preflight.check(_local(), ping=True,
                                  probe=_Probe(_MODELS))[0]
        self.assertTrue(row["ok"], row)
        self.assertIn("answered", row["detail"])


def _http_error(code):
    import urllib.error
    return urllib.error.HTTPError("http://x/v1/models", code, "x", {}, None)


class TestAServerThatNeedsCredentialsIsNotDown(unittest.TestCase):
    """The probe sends no Authorization header, so a server that requires
    one answers 401 -- which is a server that is up."""

    def test_a_401_with_a_key_configured_is_ok_and_says_what_was_not_done(self):
        for code in (401, 403):
            for make, path in ((_local, "/v1/models"), (_ollama, "/api/tags")):
                with self.subTest(code=code, path=path):
                    row = preflight.check(
                        make(api_key=_KEY),
                        probe=_Probe(raises=_http_error(code)))[0]
                    self.assertTrue(row["ok"], row)
                    self.assertIn("needs credentials", row["detail"])
                    self.assertIn("does not send one", row["detail"])
                    self.assertIn("not checked", row["detail"])
                    self.assertIn(path, row["detail"])
                    self.assertNotIn(_KEY, row["detail"])

    def test_a_401_with_no_key_is_not_ok(self):
        # The first model call would be this same 401.
        row = preflight.check(_local(),
                              probe=_Probe(raises=_http_error(401)))[0]
        self.assertFalse(row["ok"])
        self.assertIn("needs credentials", row["detail"])
        self.assertIn("no api_key", row["detail"])

    def test_it_is_not_the_line_for_down_unreadable_or_other_http_errors(self):
        auth = preflight.check(_local(api_key=_KEY),
                               probe=_Probe(raises=_http_error(401)))[0]
        self.assertNotIn("no server answering", auth["detail"])
        self.assertNotIn("unreadable", auth["detail"])
        self.assertNotIn("answered HTTP", auth["detail"])
        other = preflight.check(_local(api_key=_KEY),
                                probe=_Probe(raises=_http_error(500)))[0]
        self.assertFalse(other["ok"])
        self.assertIn("answered HTTP 500", other["detail"])

    def test_a_fallback_links_own_key_decides(self):
        cfg = _cfg(fallbacks=(
            config.FallbackLink(provider="local", model="m"),
            config.FallbackLink(provider="local", model="m",
                                api_key=_OTHER_KEY)))
        rows = preflight.check(cfg, probe=_Probe(raises=_http_error(401)))
        self.assertEqual([r["ok"] for r in rows], [True, False, True])
        self.assertTrue(all(_OTHER_KEY not in r["detail"] for r in rows))

    def test_the_ping_is_what_tests_the_key(self):
        with unittest.mock.patch.object(provider, "http_post_json",
                                        _a_completion):
            row = preflight.check(
                _local(api_key=_KEY), ping=True,
                probe=_Probe(raises=_http_error(401)))[0]
        self.assertTrue(row["ok"], row)
        self.assertIn("answered", row["detail"])


class TestAnUnreadableListIsSaidDistinctly(unittest.TestCase):
    """Reachable, model list unreadable: neither a crash nor a pass, and
    not the same line as a server that is down or a model that is absent."""

    def _unreadable(self):
        return ({}, {"models": "x"}, {"data": "x"}, [], None,
                {"models": [1, None]}, {"data": [{"name": "x"}]})

    def test_an_unreadable_payload_says_reachable_and_unreadable(self):
        for make in (_ollama, _local):
            for payload in self._unreadable():
                with self.subTest(provider=make().provider, payload=payload):
                    row = preflight.check(make(), probe=_Probe(payload))[0]
                    self.assertFalse(row["ok"])
                    self.assertIn("reachable", row["detail"])
                    self.assertIn("unreadable", row["detail"])

    def test_non_json_says_unreadable_too(self):
        for make in (_ollama, _local):
            with self.subTest(provider=make().provider):
                row = preflight.check(
                    make(), probe=_Probe(raises=ValueError("nope")))[0]
                self.assertFalse(row["ok"])
                self.assertIn("unreadable", row["detail"])

    def test_it_is_not_the_line_for_a_down_server_or_a_missing_model(self):
        unreadable = preflight.check(_local(), probe=_Probe({}))[0]["detail"]
        down = preflight.check(
            _local(), probe=_Probe(raises=OSError("x")))[0]["detail"]
        missing = preflight.check(
            _local(model="nope"), probe=_Probe(_MODELS))[0]["detail"]
        self.assertNotIn("no server answering", unreadable)
        self.assertNotIn("not in its model list", unreadable)
        self.assertNotIn("unreadable", down)
        self.assertNotIn("unreadable", missing)


class TestADeadServerIsAReport(unittest.TestCase):
    def test_an_unreachable_ollama_is_not_ok_and_does_not_raise(self):
        for exc in (ConnectionRefusedError(61, "refused"), OSError("down"),
                    TimeoutError("slow")):
            with self.subTest(exc=type(exc).__name__):
                row = preflight.check(_ollama(),
                                      probe=_Probe(raises=exc))[0]
                self.assertFalse(row["ok"])
                self.assertIn("127.0.0.1:11434", row["detail"])

    def test_an_http_error_names_the_status(self):
        import urllib.error
        exc = urllib.error.HTTPError("http://x/api/tags", 404, "Not Found",
                                     {}, None)
        row = preflight.check(_ollama(), probe=_Probe(raises=exc))[0]
        self.assertFalse(row["ok"])
        self.assertIn("404", row["detail"])
        self.assertIn("/api/tags", row["detail"])

    def test_an_http_error_from_local_names_its_own_endpoint(self):
        import urllib.error
        exc = urllib.error.HTTPError("http://x/v1/models", 404, "Not Found",
                                     {}, None)
        row = preflight.check(_local(), probe=_Probe(raises=exc))[0]
        self.assertFalse(row["ok"])
        self.assertIn("404", row["detail"])
        self.assertIn("/v1/models", row["detail"])

    def test_an_unreachable_link_does_not_hide_the_next(self):
        cfg = _ollama(fallbacks=(
            config.FallbackLink(provider="openrouter", model="m/one",
                                api_key=_OTHER_KEY),))
        rows = preflight.check(cfg, probe=_Probe(raises=OSError("down")))
        self.assertEqual([r["ok"] for r in rows], [False, True])

    def test_the_default_probe_reports_a_closed_port_without_raising(self):
        # The default probe, against a port nothing listens on: the
        # standard library is the only thing that can fail here.
        import socket
        with contextlib.closing(socket.socket()) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        row = preflight.check(
            _ollama(base_url="http://127.0.0.1:%d/v1" % port))[0]
        self.assertFalse(row["ok"])
        self.assertIn("127.0.0.1:%d" % port, row["detail"])


def _a_completion(url, headers, body, **kw):
    return {"choices": [{"message": {"content": "ok"},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 9, "completion_tokens": 1}}


def _fail_if_called(*args, **kwargs):
    raise AssertionError("a model was called")


class _TokenSource:
    """Stands in for a Google token source: hands out `token` or raises."""

    def __init__(self, token=None, raises=None):
        self.token, self.raises = token, raises
        self.calls = 0

    def bearer(self):
        self.calls += 1
        if self.raises is not None:
            raise self.raises
        return self.token


def _vertex(**kw):
    values = dict(provider="vertex", model="google/gemini-3-pro",
                  api_key=None, vertex_project="proj")
    values.update(kw)
    return _cfg(**values)


class TestALinkWithATokenSourceIsAskedForAToken(unittest.TestCase):
    """Without --ping. A token costs no model tokens, and a logged-out
    gcloud passes everything that building the link checks."""

    def _check(self, source, cfg=None, **kw):
        with unittest.mock.patch.object(
                provider.gcp_token, "source", return_value=source), \
                unittest.mock.patch.object(provider, "http_post_json",
                                           _fail_if_called):
            return preflight.check(cfg or _vertex(), probe=_Probe(_TAGS),
                                   **kw)

    def test_a_source_that_cannot_give_a_token_is_not_ok(self):
        src = _TokenSource(raises=provider.gcp_token.TokenUnavailable(
            "no Google token source worked: gcloud exited with status 1"))
        row = self._check(src)[0]
        self.assertEqual(src.calls, 1)
        self.assertFalse(row["ok"])
        self.assertIn("no access token", row["detail"])
        self.assertIn("gcloud exited with status 1", row["detail"])

    def test_a_source_that_gives_a_token_is_ok_and_the_token_is_not_shown(self):
        src = _TokenSource(token="ya29.tok-SECRET-value")
        row = self._check(src)[0]
        self.assertEqual(src.calls, 1)
        self.assertTrue(row["ok"], row)
        self.assertIn("token was obtained", row["detail"])
        self.assertIn("--ping", row["detail"])
        self.assertNotIn("tok-SECRET", row["detail"])

    def test_any_other_failure_is_named_by_class_only(self):
        src = _TokenSource(raises=RuntimeError("Bearer tok-LEAK"))
        row = self._check(src)[0]
        self.assertFalse(row["ok"])
        self.assertIn("RuntimeError", row["detail"])
        self.assertNotIn("tok-LEAK", row["detail"])

    def test_a_vertex_fallback_is_asked_too(self):
        src = _TokenSource(raises=provider.gcp_token.TokenUnavailable("down"))
        cfg = _cfg(fallbacks=(config.FallbackLink(
            provider="vertex", model="google/gemini-3-pro",
            base_url="https://europe-west4-aiplatform.googleapis.com/v1/"
                     "projects/p/locations/europe-west4/endpoints/openapi"),))
        rows = self._check(src, cfg=cfg)
        self.assertEqual([r["ok"] for r in rows], [True, False])
        self.assertIn("down", rows[1]["detail"])

    def test_without_a_token_there_is_no_ping(self):
        src = _TokenSource(raises=provider.gcp_token.TokenUnavailable("down"))
        row = self._check(src, ping=True)[0]
        self.assertFalse(row["ok"])
        self.assertEqual(src.calls, 1)

    def test_a_link_without_a_source_is_not_asked(self):
        # Only a client that carries a source: the other providers have a
        # static key and nothing to ask.
        with unittest.mock.patch.object(
                provider.gcp_token, "source",
                side_effect=AssertionError("a source was asked for")):
            row = preflight.check(_cfg(), probe=_Probe(_TAGS))[0]
        self.assertTrue(row["ok"], row)


class TestNothingIsSentToAModelUnlessAsked(unittest.TestCase):
    def test_nothing_is_pinged_unless_asked(self):
        cfg = _cfg(fallbacks=(
            config.FallbackLink(provider="openrouter", model="m/one",
                                api_key=_OTHER_KEY),))
        with unittest.mock.patch.object(provider, "http_post_json",
                                        _fail_if_called):
            rows = preflight.check(cfg, ping=False, probe=_Probe(_TAGS))
        self.assertTrue(all(r["ok"] for r in rows))

    def test_ping_sends_one_minimal_completion_per_link(self):
        posted = []

        def answer(url, headers, body, **kw):
            posted.append((url, body))
            return _a_completion(url, headers, body)

        cfg = _cfg(provider="openrouter", model="m/one", api_key=_KEY,
                   fallbacks=(config.FallbackLink(
                       provider="openrouter", model="m/two",
                       api_key=_OTHER_KEY),))
        with unittest.mock.patch.object(provider, "http_post_json", answer):
            rows = preflight.check(cfg, ping=True, probe=_Probe(_TAGS))
        self.assertEqual(len(posted), 2)
        self.assertTrue(all(r["ok"] for r in rows), rows)
        for url, body in posted:
            self.assertLessEqual(body["max_tokens"], 32)
        # The cost is visible in the report, since --ping is the one thing
        # here that spends tokens.
        self.assertIn("9", rows[0]["detail"])

    def test_a_failed_ping_is_not_ok_and_does_not_raise(self):
        def refuse(url, headers, body, **kw):
            raise provider.TransportError("HTTP 401 (the API key was rejected)")

        with unittest.mock.patch.object(provider, "http_post_json", refuse):
            row = preflight.check(_cfg(), ping=True, probe=_Probe(_TAGS))[0]
        self.assertFalse(row["ok"])
        self.assertIn("401", row["detail"])

    def test_a_local_link_that_is_down_is_not_pinged(self):
        # A completion against a dead local server is a long timeout for an
        # answer the probe already gave.
        with unittest.mock.patch.object(provider, "http_post_json",
                                        _fail_if_called):
            row = preflight.check(_ollama(), ping=True,
                                  probe=_Probe(raises=OSError("down")))[0]
        self.assertFalse(row["ok"])

    def test_a_model_that_was_never_pulled_is_not_pinged(self):
        with unittest.mock.patch.object(provider, "http_post_json",
                                        _fail_if_called):
            row = preflight.check(_ollama(model="mistral:7b"), ping=True,
                                  probe=_Probe(_TAGS))[0]
        self.assertFalse(row["ok"])


class TestNoDetailCarriesACredential(unittest.TestCase):
    def _assert_clean(self, rows, *secrets):
        for row in rows:
            for field, value in row.items():
                for secret in secrets:
                    self.assertNotIn(secret, str(value),
                                     "%s carries a credential" % field)

    def test_no_detail_carries_a_credential(self):
        cfg = _cfg(fallbacks=(
            config.FallbackLink(provider="openrouter", model="m/one",
                                api_key=_OTHER_KEY),
            config.FallbackLink(provider="ollama", model="qwen2.5:14b"),
        ))
        self._assert_clean(preflight.check(cfg, probe=_Probe(_TAGS)),
                           _KEY, _OTHER_KEY)

    def test_a_key_in_an_error_message_is_scrubbed(self):
        # ProviderError promises not to carry the key; this is not the place
        # to find out it broke the promise.
        leaky = provider.ProviderError("bad key %s" % _KEY)
        with unittest.mock.patch.object(provider, "create_client",
                                        side_effect=leaky):
            rows = preflight.check(_cfg(), probe=_Probe(_TAGS))
        self.assertFalse(rows[0]["ok"])
        self._assert_clean(rows, _KEY)

    def test_a_key_in_a_probe_failure_is_not_printed(self):
        rows = preflight.check(
            _ollama(api_key=_KEY),
            probe=_Probe(raises=OSError("refused for %s" % _KEY)))
        self.assertFalse(rows[0]["ok"])
        self._assert_clean(rows, _KEY)

    def test_a_key_in_a_ping_failure_is_not_printed(self):
        def leak(url, headers, body, **kw):
            raise RuntimeError("echoed %s" % _KEY)

        with unittest.mock.patch.object(provider, "http_post_json", leak):
            rows = preflight.check(_cfg(), ping=True, probe=_Probe(_TAGS))
        self.assertFalse(rows[0]["ok"])
        self._assert_clean(rows, _KEY)

    def test_userinfo_in_a_base_url_is_not_printed(self):
        base = "http://user:hunter2hunter2@127.0.0.1:11434/v1"
        rows = preflight.check(_ollama(base_url=base),
                               probe=_Probe(raises=OSError("down")))
        self._assert_clean(rows, "hunter2hunter2")

    def test_main_output_carries_no_credential(self):
        cfg = _cfg(fallbacks=(
            config.FallbackLink(provider="openrouter", model="m/one",
                                api_key=None),))
        out = io.StringIO()
        with unittest.mock.patch.object(config, "load", return_value=cfg), \
                contextlib.redirect_stdout(out):
            preflight.main([])
        self.assertNotIn(_KEY, out.getvalue())


class TestMain(unittest.TestCase):
    def _run(self, cfg, argv=()):
        out, err = io.StringIO(), io.StringIO()
        with unittest.mock.patch.object(config, "load", return_value=cfg), \
                unittest.mock.patch.object(
                    preflight, "_http_get_json", _Probe(_TAGS)), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            code = preflight.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_main_returns_zero_when_every_link_is_ok(self):
        code, out, _ = self._run(_ollama())
        self.assertEqual(code, 0)
        self.assertIn("ollama", out)

    def test_main_returns_nonzero_when_a_link_is_not_ok(self):
        cfg = _cfg(fallbacks=(
            config.FallbackLink(provider="openrouter", model="m/one",
                                api_key=None),))
        code, out, _ = self._run(cfg)
        self.assertEqual(code, 1)
        self.assertEqual(len(out.strip().splitlines()), 2)

    def test_one_aligned_line_per_link(self):
        cfg = _cfg(fallbacks=(
            config.FallbackLink(provider="ollama", model="qwen2.5:14b"),))
        _, out, _ = self._run(cfg)
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 2)
        # Columns line up: the model column starts at the same offset.
        self.assertEqual(lines[0].index("claude-sonnet-4-5"),
                         lines[1].index("qwen2.5:14b"))

    def test_a_bad_configuration_is_a_message_and_a_nonzero_exit(self):
        out, err = io.StringIO(), io.StringIO()
        with unittest.mock.patch.object(
                config, "load", side_effect=config.ConfigError("bad value")), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            code = preflight.main([])
        self.assertEqual(code, 2)
        self.assertIn("bad value", err.getvalue())

    def test_ping_is_a_flag_and_is_off_by_default(self):
        seen = []
        real = preflight.check

        def spy(cfg, **kw):
            seen.append(kw.get("ping"))
            return real(cfg, **kw)

        # --ping really pings here, so the transport is replaced.
        with unittest.mock.patch.object(provider, "http_post_json",
                                        _a_completion):
            for argv in ((), ("--ping",)):
                with unittest.mock.patch.object(preflight, "check", spy):
                    self._run(_ollama(), argv)
        self.assertEqual(seen, [False, True])

    def test_other_flags_are_handed_to_the_configuration(self):
        loaded = []

        def load(argv=None, yaml_path=None, env=None):
            loaded.append(list(argv))
            return _ollama()

        with unittest.mock.patch.object(config, "load", load), \
                unittest.mock.patch.object(
                    preflight, "_http_get_json", _Probe(_TAGS)), \
                unittest.mock.patch.object(provider, "http_post_json",
                                           _a_completion), \
                contextlib.redirect_stdout(io.StringIO()):
            preflight.main(["--provider", "ollama", "--ping"])
        self.assertEqual(loaded, [["--provider", "ollama"]])


class TestItStaysOutOfTheAvailabilityCheck(unittest.TestCase):
    def test_available_makes_no_network_call(self):
        # config.available() is polled by the status endpoint. A probe in
        # there would stall the UI once per poll against a dead server.
        with unittest.mock.patch.object(preflight, "_http_get_json",
                                        _fail_if_called):
            ok, _ = _ollama().available()
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
