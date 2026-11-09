#!/usr/bin/env python3
"""
Tests for the agent configuration: the four-level resolution cascade, the
secrets rules (an API key is never read from the YAML, never printed), the
risk profiles and the safety property they must keep, and the campaign form.

Every secret in here is an obvious fake and every keyfile lives under a
temporary directory. `config.load` is always given an explicit env dict: a
test that fell back to os.environ would depend on the machine it ran on.
"""

import contextlib
import io
import os
import re
import sys
import tempfile
import types
import unittest
import unittest.mock
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent import config, gate, safety
from software.agent.llm import failover, gcp_token, provider
from software.agent.store import db, queries

_FAKE_KEY = "sk-not-a-real-key"
_FAKE_AGENT_TOKEN = "tok-not-a-real-agent-token"
_FAKE_C2_TOKEN = "tok-not-a-real-c2-token"

_SHIPPED_YAML = Path(__file__).parent.parent.parent / "configs" / "raccoon.yaml"

_tmp = None


def setUpModule():
    global _tmp
    _tmp = tempfile.TemporaryDirectory()


def tearDownModule():
    _tmp.cleanup()


# ── Fixtures ──


def _raw_yaml(text):
    handle, path = tempfile.mkstemp(dir=_tmp.name, suffix=".yaml")
    with os.fdopen(handle, "w") as f:
        f.write(text)
    return path


def _yaml(data):
    return _raw_yaml(yaml.safe_dump(data))


def _keyfile(content, mode=0o600):
    handle, path = tempfile.mkstemp(dir=_tmp.name, suffix=".key")
    with os.fdopen(handle, "w") as f:
        f.write(content)
    # chmod rather than a mode on open: the umask would otherwise decide.
    os.chmod(path, mode)
    return path


def _quiet():
    return contextlib.redirect_stderr(io.StringIO())


def _load(argv=(), data=None, env=None):
    path = _yaml(data) if data is not None else None
    with _quiet():
        return config.load(argv=list(argv), yaml_path=path, env=env or {})


_FORM = {"scope_allow": ["10.0.1.0/24"], "beacons": ["a"]}


def _form(tier="full", **extra):
    payload = dict(_FORM)
    payload.update(extra)
    return config.CampaignConfig.from_form(payload, tier=tier)


# ── Resolution cascade ──

class TestResolutionCascade(unittest.TestCase):
    def test_yaml_beats_env(self):
        cfg = config.load(argv=[], yaml_path=_yaml({"agent": {"llm": {
            "provider": "anthropic", "model": "claude-sonnet-4"}}}),
            env={"AGENT_PROVIDER": "openrouter"})
        self.assertEqual(cfg.provider, "anthropic")

    def test_cli_beats_yaml(self):
        cfg = config.load(argv=["--provider", "local", "--model", "qwen2.5:14b"],
                          yaml_path=_yaml({"agent": {"llm": {"provider": "anthropic"}}}),
                          env={})
        self.assertEqual(cfg.provider, "local")

    def test_env_used_when_yaml_silent(self):
        cfg = config.load(argv=[], yaml_path=_yaml({"agent": {}}),
                          env={"AGENT_PROVIDER": "openrouter", "AGENT_MODEL": "m",
                               "AGENT_API_KEY": "k"})
        self.assertEqual(cfg.provider, "openrouter")

    def test_each_field_is_resolved_on_its_own(self):
        """A CLI flag for one field must not discard the YAML value of another."""
        cfg = config.load(
            argv=["--provider", "local"],
            yaml_path=_yaml({"agent": {
                "llm": {"provider": "anthropic", "model": "claude-sonnet-4",
                        "base_url": "https://llm.example.invalid"},
                "service": {"bind_port": 9000}}}),
            env={"AGENT_MODEL": "from-env", "AGENT_BIND_HOST": "10.9.8.7"})
        self.assertEqual(cfg.provider, "local")                 # CLI
        self.assertEqual(cfg.model, "claude-sonnet-4")          # YAML over env
        self.assertEqual(cfg.base_url, "https://llm.example.invalid")  # YAML
        self.assertEqual(cfg.bind_port, 9000)                   # YAML
        self.assertEqual(cfg.bind_host, "10.9.8.7")             # env
        self.assertEqual(cfg.max_concurrent_executors, 4)       # default

    def test_blank_yaml_value_does_not_shadow_env(self):
        """The shipped file carries `provider: ""`; that must mean unset."""
        cfg = config.load(argv=[], yaml_path=_yaml({"agent": {"llm": {
            "provider": "", "model": None}}}),
            env={"AGENT_PROVIDER": "openrouter", "AGENT_MODEL": "m"})
        self.assertEqual(cfg.provider, "openrouter")
        self.assertEqual(cfg.model, "m")

    def test_defaults(self):
        cfg = _load()
        self.assertIsNone(cfg.provider)
        self.assertIsNone(cfg.api_key)
        self.assertEqual(cfg.llm_log_level, "off")
        self.assertEqual(cfg.bind_host, "127.0.0.1")
        self.assertEqual(cfg.bind_port, 8099)
        self.assertEqual(cfg.max_concurrent_executors, 4)
        self.assertIs(cfg.c2_verify_tls, False)

    def test_missing_file_yields_defaults_without_raising(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            cfg = config.load(argv=[], yaml_path="/nonexistent/x.yaml", env={})
        self.assertIsNone(cfg.provider)
        self.assertNotEqual(err.getvalue(), "")

    def test_malformed_yaml_warns_and_falls_back(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            cfg = config.load(argv=[], yaml_path=_raw_yaml("agent: [unclosed"),
                              env={})
        self.assertIsNone(cfg.provider)
        self.assertNotEqual(err.getvalue(), "")

    def test_yaml_that_is_not_a_mapping_falls_back(self):
        with _quiet():
            cfg = config.load(argv=[], yaml_path=_raw_yaml("- just\n- a list\n"),
                              env={})
        self.assertIsNone(cfg.provider)

    def test_no_yaml_path_means_no_yaml(self):
        self.assertIsNone(config.load(argv=[], yaml_path=None, env={}).provider)

    def test_env_argument_is_what_is_read_not_the_process_environment(self):
        with unittest.mock.patch.dict(os.environ, {"AGENT_PROVIDER": "local"}):
            self.assertIsNone(config.load(argv=[], env={}).provider)
            self.assertEqual(config.load(argv=[], env=None).provider, "local")

    def test_bad_number_names_the_field(self):
        with self.assertRaises(config.ConfigError) as ctx:
            _load(env={"AGENT_BIND_PORT": "eighty"})
        self.assertIn("bind_port", str(ctx.exception))

    def test_port_out_of_range_is_refused(self):
        for bad in ("0", "65536", "-1"):
            with self.subTest(port=bad):
                with self.assertRaises(config.ConfigError):
                    _load(env={"AGENT_BIND_PORT": bad})

    def test_nonpositive_limits_are_refused(self):
        with self.assertRaises(config.ConfigError):
            _load(env={"AGENT_MAX_CONCURRENT_EXECUTORS": "0"})
        with self.assertRaises(config.ConfigError):
            _load(env={"AGENT_APPROVAL_TIMEOUT": "0"})

    def test_bool_spellings(self):
        for text, want in (("true", True), ("1", True), ("no", False),
                           ("OFF", False)):
            with self.subTest(text=text):
                self.assertIs(
                    _load(env={"AGENT_C2_VERIFY_TLS": text}).c2_verify_tls, want)
        with self.assertRaises(config.ConfigError):
            _load(env={"AGENT_C2_VERIFY_TLS": "maybe"})

    def test_cli_bool_flag(self):
        self.assertIs(_load(argv=["--c2-verify-tls"]).c2_verify_tls, True)
        self.assertIs(
            _load(argv=["--no-c2-verify-tls"],
                  data={"agent": {"c2": {"verify_tls": True}}}).c2_verify_tls,
            False)


class TestLogLevel(unittest.TestCase):
    """The loop treats anything but "full" as "off": safe, but silent."""

    def test_typo_is_refused_and_the_valid_values_are_named(self):
        with self.assertRaises(config.ConfigError) as ctx:
            _load(data={"agent": {"llm": {"llm_log_level": "ful"}}})
        message = str(ctx.exception)
        self.assertIn("llm_log_level", message)
        self.assertIn("off", message)
        self.assertIn("full", message)

    def test_typo_is_refused_from_every_level(self):
        with self.assertRaises(config.ConfigError):
            _load(argv=["--llm-log-level", "verbose"])
        with self.assertRaises(config.ConfigError):
            _load(env={"AGENT_LLM_LOG_LEVEL": "verbose"})

    def test_valid_values_are_accepted(self):
        for level in ("off", "full"):
            with self.subTest(level=level):
                cfg = _load(data={"agent": {"llm": {"llm_log_level": level}}})
                self.assertEqual(cfg.llm_log_level, level)

    def test_case_and_padding_are_forgiven(self):
        cfg = _load(env={"AGENT_LLM_LOG_LEVEL": " FULL "})
        self.assertEqual(cfg.llm_log_level, "full")


class TestCapabilityTier(unittest.TestCase):
    def test_derived_from_model_and_provider(self):
        cfg = _load(env={"AGENT_PROVIDER": "anthropic",
                         "AGENT_MODEL": "claude-sonnet-4"})
        self.assertEqual(cfg.capability_tier,
                         provider.capability_tier("claude-sonnet-4", "anthropic"))
        self.assertEqual(cfg.capability_tier, "full")

    def test_unknown_model_is_reduced(self):
        self.assertEqual(_load().capability_tier, "reduced")

    def test_operator_can_override_in_either_direction(self):
        up = _load(env={"AGENT_PROVIDER": "local", "AGENT_MODEL": "qwen2.5:14b",
                        "AGENT_CAPABILITY_TIER": "full"})
        down = _load(argv=["--capability-tier", "minimal"],
                     env={"AGENT_PROVIDER": "anthropic",
                          "AGENT_MODEL": "claude-sonnet-4"})
        self.assertEqual(up.capability_tier, "full")
        self.assertEqual(down.capability_tier, "minimal")

    def test_unknown_tier_is_refused(self):
        with self.assertRaises(config.ConfigError) as ctx:
            _load(env={"AGENT_CAPABILITY_TIER": "ultra"})
        for tier in provider.TIER_LIMITS:
            self.assertIn(tier, str(ctx.exception))


# ── Secrets ──

class TestSecrets(unittest.TestCase):
    def test_api_key_never_read_from_yaml_body(self):
        """Spec: Keys nur aus Env oder 0600-Datei."""
        cfg = _load(data={"agent": {"llm": {
            "provider": "anthropic", "api_key": "IM-REPO"}}})
        self.assertNotEqual(cfg.api_key, "IM-REPO")
        self.assertIsNone(cfg.api_key)

    def test_api_key_in_yaml_is_ignored_even_when_env_has_one(self):
        cfg = _load(data={"agent": {"llm": {"api_key": "IM-REPO"}}},
                    env={"AGENT_API_KEY": _FAKE_KEY})
        self.assertEqual(cfg.api_key, _FAKE_KEY)

    def test_api_key_in_yaml_warns_without_echoing_it(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            config.load(argv=[], yaml_path=_yaml({"agent": {"llm": {
                "api_key": "IM-REPO"}}}), env={})
        self.assertIn("api_key", err.getvalue())
        self.assertNotIn("IM-REPO", err.getvalue())

    def test_tokens_in_yaml_are_ignored_too(self):
        cfg = _load(data={"agent": {"c2": {"token": "IM-REPO"},
                                    "service": {"agent_token": "IM-REPO"}}})
        self.assertIsNone(cfg.c2_token)
        self.assertIsNone(cfg.agent_token)

    def test_api_key_from_env(self):
        self.assertEqual(_load(env={"AGENT_API_KEY": _FAKE_KEY}).api_key,
                         _FAKE_KEY)

    def test_tokens_come_from_the_environment_only(self):
        cfg = _load(env={"RACCOON_TOKEN": _FAKE_C2_TOKEN,
                         "RACCOON_AGENT_TOKEN": _FAKE_AGENT_TOKEN})
        self.assertEqual(cfg.c2_token, _FAKE_C2_TOKEN)
        self.assertEqual(cfg.agent_token, _FAKE_AGENT_TOKEN)

    def test_api_key_from_keyfile(self):
        path = _keyfile(_FAKE_KEY, mode=0o600)
        cfg = _load(data={"agent": {"llm": {
            "provider": "anthropic", "api_key_file": path}}})
        self.assertEqual(cfg.api_key, _FAKE_KEY)

    def test_keyfile_trailing_newline_is_stripped(self):
        path = _keyfile(_FAKE_KEY + "\n")
        self.assertEqual(
            _load(argv=["--api-key-file", path]).api_key, _FAKE_KEY)

    def test_keyfile_beats_env(self):
        path = _keyfile(_FAKE_KEY)
        cfg = _load(data={"agent": {"llm": {"api_key_file": path}}},
                    env={"AGENT_API_KEY": "sk-from-the-env"})
        self.assertEqual(cfg.api_key, _FAKE_KEY)

    def test_world_readable_keyfile_is_refused(self):
        path = _keyfile(_FAKE_KEY, mode=0o644)
        with self.assertRaises(config.ConfigError) as ctx:
            _load(data={"agent": {"llm": {"api_key_file": path}}})
        self.assertNotIn(_FAKE_KEY, str(ctx.exception))

    def test_any_group_or_other_permission_is_refused(self):
        for mode in (0o640, 0o604, 0o660, 0o602, 0o666, 0o777):
            with self.subTest(mode=oct(mode)):
                path = _keyfile(_FAKE_KEY, mode=mode)
                with self.assertRaises(config.ConfigError):
                    _load(argv=["--api-key-file", path])

    def test_owner_only_read_is_accepted(self):
        path = _keyfile(_FAKE_KEY, mode=0o400)
        self.assertEqual(_load(argv=["--api-key-file", path]).api_key, _FAKE_KEY)

    def test_missing_keyfile_is_refused(self):
        with self.assertRaises(config.ConfigError):
            _load(argv=["--api-key-file", os.path.join(_tmp.name, "absent")])

    def test_empty_keyfile_is_refused(self):
        path = _keyfile("\n")
        with self.assertRaises(config.ConfigError):
            _load(argv=["--api-key-file", path])

    def test_undecodable_keyfile_leaves_no_key_bytes_on_the_chain(self):
        # A UnicodeDecodeError holds the bytes it failed on in `.object`,
        # and here those are the key. Nothing on the ConfigError's chain may
        # reach them, however an error serialiser walks it.
        handle, path = tempfile.mkstemp(dir=_tmp.name, suffix=".key")
        with os.fdopen(handle, "wb") as f:
            f.write(_FAKE_KEY.encode() + b"\xff\xfe")
        os.chmod(path, 0o600)
        with self.assertRaises(config.ConfigError) as ctx:
            config._read_keyfile(path)
        seen, current = [], ctx.exception
        while current is not None:
            seen.append(current)
            self.assertNotIn(_FAKE_KEY, repr(current))
            self.assertNotIn(_FAKE_KEY, repr(vars(current)))
            self.assertNotIn(_FAKE_KEY, repr(getattr(current, "object", "")))
            current = current.__context__ or current.__cause__
        self.assertEqual(len(seen), 1, "the chain should hold nothing else")

    def test_directory_as_keyfile_is_refused(self):
        with self.assertRaises(config.ConfigError):
            _load(argv=["--api-key-file", _tmp.name])

    def test_no_secret_appears_in_repr_or_str(self):
        cfg = _load(env={"AGENT_PROVIDER": "anthropic", "AGENT_MODEL": "m",
                         "AGENT_API_KEY": _FAKE_KEY,
                         "RACCOON_TOKEN": _FAKE_C2_TOKEN,
                         "RACCOON_AGENT_TOKEN": _FAKE_AGENT_TOKEN})
        # Non-vacuous: the secrets really are held, only not printed.
        self.assertEqual(cfg.api_key, _FAKE_KEY)
        for text in (repr(cfg), str(cfg), "%s" % (cfg,), "%r" % ([cfg],)):
            for secret in (_FAKE_KEY, _FAKE_C2_TOKEN, _FAKE_AGENT_TOKEN):
                self.assertNotIn(secret, text)
        self.assertIn("anthropic", repr(cfg))


# ── Availability ──

class TestAvailability(unittest.TestCase):
    def test_unavailable_without_provider(self):
        ok, reason = config.load(argv=[], yaml_path=None, env={}).available()
        self.assertFalse(ok)
        self.assertIn("provider", reason.lower())

    def test_available_with_provider_and_key(self):
        ok, _ = config.load(argv=[], yaml_path=None,
                            env={"AGENT_PROVIDER": "anthropic",
                                 "AGENT_MODEL": "claude-sonnet-4",
                                 "AGENT_API_KEY": "k"}).available()
        self.assertTrue(ok)

    def test_local_provider_needs_no_key(self):
        ok, _ = _load(env={"AGENT_PROVIDER": "local",
                           "AGENT_MODEL": "qwen2.5:14b"}).available()
        self.assertTrue(ok)

    def test_missing_key_is_named(self):
        ok, reason = _load(env={"AGENT_PROVIDER": "anthropic",
                                "AGENT_MODEL": "claude-sonnet-4"}).available()
        self.assertFalse(ok)
        self.assertIn("api_key", reason)

    def test_unknown_provider_is_named(self):
        ok, reason = _load(env={"AGENT_PROVIDER": "anthrpic",
                                "AGENT_MODEL": "m",
                                "AGENT_API_KEY": _FAKE_KEY}).available()
        self.assertFalse(ok)
        self.assertIn("anthrpic", reason)

    def test_sliver_makes_the_agent_unavailable_and_says_why(self):
        cfg = _load(data={"c2": {"sliver": {"enabled": True}}},
                    env={"AGENT_PROVIDER": "anthropic",
                         "AGENT_MODEL": "claude-sonnet-4",
                         "AGENT_API_KEY": _FAKE_KEY})
        ok, reason = cfg.available()
        self.assertFalse(ok)
        self.assertIn("sliver", reason.lower())
        # The consequence and the way out, not only the rule.
        self.assertIn("checks in", reason)
        self.assertIn("c2.sliver.enabled", reason)

    def test_sliver_off_leaves_the_agent_available(self):
        cfg = _load(data={"c2": {"sliver": {"enabled": False}}},
                    env={"AGENT_PROVIDER": "anthropic",
                         "AGENT_MODEL": "claude-sonnet-4",
                         "AGENT_API_KEY": _FAKE_KEY})
        self.assertTrue(cfg.available()[0])

    def test_every_problem_is_reported_not_only_the_first(self):
        ok, reason = _load(data={"c2": {"sliver": {"enabled": True}}}
                           ).available()
        self.assertFalse(ok)
        self.assertIn("provider", reason.lower())
        self.assertIn("sliver", reason.lower())

    def test_the_reason_never_contains_the_key(self):
        cases = [
            ({"c2": {"sliver": {"enabled": True}}},
             {"AGENT_PROVIDER": "anthropic", "AGENT_MODEL": "m"}),
            (None, {"AGENT_PROVIDER": "nonesuch", "AGENT_MODEL": "m"}),
            (None, {"AGENT_PROVIDER": "anthropic"}),
            (None, {"AGENT_PROVIDER": "opencode", "AGENT_MODEL": "m"}),
            (None, {}),
        ]
        for data, env in cases:
            with self.subTest(env=sorted(env)):
                env = dict(env, AGENT_API_KEY=_FAKE_KEY)
                ok, reason = _load(data=data, env=env).available()
                self.assertFalse(ok)
                self.assertNotIn(_FAKE_KEY, reason)

    def test_a_key_leaking_into_a_reason_is_scrubbed(self):
        """Belt and braces: a reason is built from other people's messages."""
        cfg = _load(env={"AGENT_PROVIDER": "anthropic", "AGENT_MODEL": "m",
                         "AGENT_API_KEY": _FAKE_KEY})
        leaky = provider.ProviderError("boom %s boom" % _FAKE_KEY)
        with unittest.mock.patch.object(provider, "create_client",
                                        side_effect=leaky):
            ok, reason = cfg.available()
        self.assertFalse(ok)
        self.assertNotIn(_FAKE_KEY, reason)


# ── Risk profiles ──

_PROFILE_FIELDS = ("ev_threshold", "p_detect_prior", "detection_budget",
                   "risk_coefficient")


def _gate_for(conn, run_id, profile):
    return gate.Gate(
        conn, run_id, mode="auto", unattended_behavior="decide",
        approval_timeout=0.2, ev_threshold=profile["ev_threshold"],
        p_detect_prior=profile["p_detect_prior"],
        detection_budget=profile["detection_budget"],
        risk_coefficient=profile["risk_coefficient"])


class TestRiskProfiles(unittest.TestCase):
    def test_normal_profile_matches_spec(self):
        p = config.RISK_PROFILES["normal"]
        self.assertEqual(p["ev_threshold"], 0.0)
        self.assertAlmostEqual(p["p_detect_prior"], 0.15)
        self.assertEqual(p["detection_budget"], 3)
        self.assertEqual(p["risk_coefficient"], 33.0)

    def test_every_profile_sets_all_four_fields_and_nothing_else(self):
        self.assertEqual(set(config.RISK_PROFILES),
                         {"passive", "normal", "aggressive"})
        for name, p in config.RISK_PROFILES.items():
            with self.subTest(profile=name):
                self.assertEqual(set(p), set(_PROFILE_FIELDS))

    def test_passive_is_stricter_and_aggressive_looser(self):
        pas, nor, agg = (config.RISK_PROFILES[k]
                         for k in ("passive", "normal", "aggressive"))
        self.assertGreater(pas["ev_threshold"], nor["ev_threshold"])
        self.assertLess(agg["ev_threshold"], nor["ev_threshold"])
        self.assertLessEqual(pas["detection_budget"], nor["detection_budget"])
        self.assertLessEqual(nor["detection_budget"], agg["detection_budget"])
        self.assertGreater(pas["p_detect_prior"], nor["p_detect_prior"])
        self.assertGreater(nor["p_detect_prior"], agg["p_detect_prior"])
        self.assertGreater(pas["risk_coefficient"], nor["risk_coefficient"])
        self.assertGreater(nor["risk_coefficient"], agg["risk_coefficient"])

    def test_explicit_values_override_the_profile(self):
        c = config.CampaignConfig.from_form(
            {"risk_profile": "normal", "ev_threshold": 25.0,
             "scope_allow": ["10.0.1.0/24"], "beacons": ["a"]}, tier="full")
        self.assertEqual(c.ev_threshold, 25.0)


class TestZeroValueActionsStayRefused(unittest.IsolatedAsyncioTestCase):
    """No preset may make anti-forensics or backup destruction happen unwatched.

    The tier-2 actions whose `points` are zero (log_clear, shadow_copy_delete,
    device_write_unknown) unlock nothing the scoring table rewards, so their
    expected value is structurally negative at any sane coefficient:
    EV = 0 * p_success - R * p_detect < 0. A profile can only let one through
    by pushing its EV threshold below that figure, and that is exactly the
    quiet failure this test exists to stop: shadow_copy_delete reads, by its
    own classification, as ransomware. An operator who wants one of these can
    approve it by hand in supervised mode. A future change to a coefficient or
    a threshold must not be able to enable it unattended.

    The EV is computed by the real gate rather than re-derived here, so the
    test cannot drift from the arithmetic the router actually runs.
    """

    def _zero_value_rows(self):
        return [row for row in safety.RISK_TABLE.values()
                if row.tier == safety.TIER_KNOCK and row.points == 0]

    def test_the_table_still_has_zero_value_actions_to_walk(self):
        names = {row.action_key for row in self._zero_value_rows()}
        self.assertTrue({"log_clear", "shadow_copy_delete"} <= names, names)

    async def test_refused_under_every_profile(self):
        rows = self._zero_value_rows()
        for name, profile in config.RISK_PROFILES.items():
            conn = db.open_store(":memory:")
            try:
                run_id = queries.create_run(conn, "campaign", None, "auto", "{}")
                g = _gate_for(conn, run_id, profile)
                for row in rows:
                    # Also with the model's advisory p_success at its ceiling:
                    # it multiplies zero, and this pins that it stays so.
                    for override in (None, 1.0):
                        with self.subTest(profile=name, action=row.action_key,
                                          override=override):
                            d = await g.request(row, p_success_override=override)
                            self.assertFalse(
                                d.allowed,
                                "%s is reachable unattended under the %r "
                                "profile (EV %.1f, threshold %.1f)"
                                % (row.action_key, name, d.ev,
                                   profile["ev_threshold"]))
                            self.assertEqual(d.decided_by, "ev")
            finally:
                conn.close()

    async def test_the_walk_is_not_vacuous(self):
        """A gate that refused everything would pass the test above."""
        positive = safety.RISK_TABLE["exploit_known_poc"]
        for name, profile in config.RISK_PROFILES.items():
            conn = db.open_store(":memory:")
            try:
                run_id = queries.create_run(conn, "campaign", None, "auto", "{}")
                d = await _gate_for(conn, run_id, profile).request(positive)
                with self.subTest(profile=name):
                    self.assertTrue(d.allowed, d.reason)
            finally:
                conn.close()


# ── Campaign form ──

class TestCampaignForm(unittest.TestCase):
    def test_phase_five_off_by_default(self):
        c = config.CampaignConfig.from_form(
            {"scope_allow": ["10.0.1.0/24"], "beacons": ["a"]}, tier="full")
        self.assertNotIn(5, c.phases)
        self.assertEqual(c.phases, {1, 2, 3, 4})

    def test_tier_caps_requested_phases(self):
        c = config.CampaignConfig.from_form(
            {"scope_allow": ["10.0.1.0/24"], "beacons": ["a"],
             "phases": [1, 2, 3, 4, 5]}, tier="reduced")
        self.assertNotIn(5, c.phases)
        self.assertIn(4, c.phases)

    def test_every_tier_cap_follows_tier_limits(self):
        for tier, limits in provider.TIER_LIMITS.items():
            with self.subTest(tier=tier):
                c = _form(tier=tier, phases=[1, 2, 3, 4, 5])
                self.assertEqual(
                    c.phases,
                    {p for p in (1, 2, 3, 4, 5) if p <= limits["max_phase"]})

    def test_phase_five_survives_on_full_when_asked_for(self):
        self.assertIn(5, _form(phases=[1, 2, 3, 4, 5]).phases)

    def test_default_phases_are_capped_for_a_minimal_tier(self):
        self.assertEqual(_form(tier="minimal").phases, {1, 2, 3})

    def test_phases_that_leave_nothing_are_refused(self):
        with self.assertRaises(config.ConfigError):
            _form(tier="minimal", phases=[5])
        with self.assertRaises(config.ConfigError):
            _form(phases=[])

    def test_phases_must_be_known_integers(self):
        for bad in ([0], [-1], [9], ["x"], [True], "1234", 3):
            with self.subTest(phases=bad):
                with self.assertRaises(config.ConfigError):
                    _form(phases=bad)

    def test_unknown_tier_is_refused(self):
        with self.assertRaises(config.ConfigError):
            _form(tier="ultra")

    def test_empty_scope_is_refused(self):
        with self.assertRaises(config.ConfigError):
            config.CampaignConfig.from_form({"beacons": ["a"]}, tier="full")
        with self.assertRaises(config.ConfigError):
            _form(scope_allow=[])

    def test_deny_alone_is_not_a_scope(self):
        with self.assertRaises(config.ConfigError):
            config.CampaignConfig.from_form(
                {"beacons": ["a"], "scope_deny": ["10.0.0.0/8"]}, tier="full")

    def test_no_beacons_is_refused(self):
        with self.assertRaises(config.ConfigError):
            config.CampaignConfig.from_form(
                {"scope_allow": ["10.0.1.0/24"], "beacons": []}, tier="full")
        with self.assertRaises(config.ConfigError):
            config.CampaignConfig.from_form(
                {"scope_allow": ["10.0.1.0/24"]}, tier="full")

    def test_lists_must_be_lists_of_strings(self):
        # A bare string would otherwise be iterated one character at a time.
        for key, bad in (("scope_allow", "10.0.1.0/24"), ("beacons", "a"),
                         ("scope_deny", "10.0.0.0/8"),
                         ("beacons", [""]), ("beacons", [3])):
            with self.subTest(key=key, bad=bad):
                with self.assertRaises(config.ConfigError):
                    _form(**{key: bad})

    def test_malformed_scope_entry_is_refused_at_the_form(self):
        for key in ("scope_allow", "scope_deny"):
            with self.subTest(key=key):
                with self.assertRaises(config.ConfigError):
                    _form(**{key: ["not-a-network"]})

    def test_allow_entry_with_host_bits_is_refused(self):
        # Scope refuses it so a typo cannot widen the authorisation.
        with self.assertRaises(config.ConfigError):
            _form(scope_allow=["10.0.1.5/24"])

    def test_payload_must_be_a_mapping(self):
        with self.assertRaises(config.ConfigError):
            config.CampaignConfig.from_form(["scope_allow"], tier="full")

    def test_defaults_match_the_form_in_the_spec(self):
        # Section 17.2 is the Full Automated form, so the mode is named:
        # unattended_behavior defaults by mode, and "decide autonomously" is
        # that form's default rather than every form's.
        c = config.CampaignConfig.from_form(
            {"scope_allow": ["10.0.1.0/24"], "beacons": ["a"],
             "mode": "auto"}, tier="full")
        self.assertEqual(c.max_runtime_seconds, 7200)
        self.assertEqual(c.max_tokens_total, 500_000)
        self.assertEqual(c.campaign_interval, 15)
        self.assertEqual(c.unattended_behavior, "decide")

    def test_default_profile_is_normal(self):
        c = _form()
        self.assertEqual(c.risk_profile, "normal")
        for field in _PROFILE_FIELDS:
            self.assertEqual(getattr(c, field),
                             config.RISK_PROFILES["normal"][field])

    def test_mode_defaults_to_supervised(self):
        # Unattended operation has to be asked for.
        self.assertEqual(_form().mode, "supervised")
        self.assertEqual(_form(mode="auto").mode, "auto")

    def test_profile_is_the_base_for_all_four_fields(self):
        for name, profile in config.RISK_PROFILES.items():
            c = _form(risk_profile=name)
            with self.subTest(profile=name):
                self.assertEqual(c.risk_profile, name)
                for field in _PROFILE_FIELDS:
                    self.assertEqual(getattr(c, field), profile[field])

    def test_each_profile_field_can_be_overridden_alone(self):
        overrides = {"ev_threshold": 7.5, "p_detect_prior": 0.4,
                     "detection_budget": 9, "risk_coefficient": 12.0}
        for field, value in overrides.items():
            c = _form(risk_profile="passive", **{field: value})
            with self.subTest(field=field):
                self.assertEqual(getattr(c, field), value)
                for other in _PROFILE_FIELDS:
                    if other != field:
                        self.assertEqual(getattr(c, other),
                                         config.RISK_PROFILES["passive"][other])

    def test_null_in_the_payload_means_not_supplied(self):
        c = _form(risk_profile="passive", ev_threshold=None)
        self.assertEqual(c.ev_threshold, config.RISK_PROFILES["passive"]["ev_threshold"])

    def test_zero_is_a_value_not_an_absence(self):
        c = _form(risk_profile="passive", ev_threshold=0)
        self.assertEqual(c.ev_threshold, 0.0)

    def test_unknown_profile_names_the_valid_ones(self):
        with self.assertRaises(config.ConfigError) as ctx:
            _form(risk_profile="reckless")
        for name in config.RISK_PROFILES:
            self.assertIn(name, str(ctx.exception))

    def test_unknown_enum_values_are_refused(self):
        for key, bad in (("unattended_behavior", "yolo"), ("mode", "manual")):
            with self.subTest(key=key):
                with self.assertRaises(config.ConfigError) as ctx:
                    _form(**{key: bad})
                self.assertIn(key, str(ctx.exception))

    def test_numbers_are_range_checked(self):
        bad = [("p_detect_prior", -0.1), ("p_detect_prior", 1.5),
               ("risk_coefficient", 0), ("risk_coefficient", -5),
               ("detection_budget", 0), ("detection_budget", 2.5),
               ("max_runtime_seconds", 0), ("max_tokens_total", -1),
               ("campaign_interval", 0), ("restore_interval", 0),
               ("ev_threshold", float("nan")), ("ev_threshold", float("inf")),
               ("ev_threshold", "high"), ("ev_threshold", True),
               ("detection_budget", False)]
        for key, value in bad:
            with self.subTest(key=key, value=value):
                with self.assertRaises(config.ConfigError) as ctx:
                    _form(**{key: value})
                self.assertIn(key, str(ctx.exception))

    def test_numeric_strings_from_a_html_form_are_read(self):
        c = _form(ev_threshold="12.5", detection_budget="2")
        self.assertEqual(c.ev_threshold, 12.5)
        self.assertEqual(c.detection_budget, 2)

    def test_every_value_the_form_accepts_the_gate_accepts(self):
        """Gate re-validates mode and unattended_behavior with ValueError."""
        conn = db.open_store(":memory:")
        try:
            run_id = queries.create_run(conn, "campaign", None, "auto", "{}")
            for mode in ("supervised", "auto"):
                for behaviour in ("decide", "skip", "pause"):
                    c = _form(mode=mode, unattended_behavior=behaviour)
                    with self.subTest(mode=mode, behaviour=behaviour):
                        gate.Gate(
                            conn, run_id, mode=c.mode,
                            ev_threshold=c.ev_threshold,
                            p_detect_prior=c.p_detect_prior,
                            detection_budget=c.detection_budget,
                            unattended_behavior=c.unattended_behavior,
                            approval_timeout=1.0,
                            risk_coefficient=c.risk_coefficient)
        finally:
            conn.close()

    def test_lists_are_copied_not_shared_with_the_payload(self):
        allow = ["10.0.1.0/24"]
        c = _form(scope_allow=allow)
        allow.append("10.9.9.0/24")
        self.assertEqual(c.scope_allow, ["10.0.1.0/24"])


# ── The shipped configs/raccoon.yaml ──

class TestShippedYaml(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = _SHIPPED_YAML.read_text()
        cls.data = yaml.safe_load(cls.text)

    def test_the_agent_block_exists_and_is_off(self):
        self.assertIs(self.data["agent"]["enabled"], False)

    def test_there_is_no_api_key_anywhere_in_the_file(self):
        """Not even commented out: an example invites someone to fill it in."""
        self.assertIsNone(
            re.search(r"^\s*#?\s*api_key\s*:", self.text, re.MULTILINE))
        self.assertNotIn("api_key", self.data["agent"].get("llm", {}))

    def test_it_loads_cleanly(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            cfg = config.load(argv=[], yaml_path=str(_SHIPPED_YAML), env={})
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(cfg.bind_host, "127.0.0.1")
        self.assertEqual(cfg.bind_port, 8099)
        self.assertEqual(cfg.max_concurrent_executors, 4)
        self.assertIs(cfg.c2_verify_tls, False)
        self.assertIsNone(cfg.provider)

    def test_shipped_blank_llm_values_leave_env_in_charge(self):
        with _quiet():
            cfg = config.load(argv=[], yaml_path=str(_SHIPPED_YAML),
                              env={"AGENT_PROVIDER": "local",
                                   "AGENT_MODEL": "qwen2.5:14b"})
        self.assertEqual(cfg.provider, "local")

    def test_shipped_sliver_default_makes_the_agent_unavailable(self):
        """The file ships sliver.enabled: true; the status endpoint must say so."""
        self.assertIs(self.data["c2"]["sliver"]["enabled"], True)
        with _quiet():
            cfg = config.load(argv=[], yaml_path=str(_SHIPPED_YAML),
                              env={"AGENT_PROVIDER": "local",
                                   "AGENT_MODEL": "qwen2.5:14b"})
        ok, reason = cfg.available()
        self.assertFalse(ok)
        self.assertIn("sliver", reason.lower())

    def test_defaults_block_matches_what_the_form_falls_back_to(self):
        """config.py does not read `defaults`; this keeps the two from drifting."""
        shipped = self.data["agent"]["defaults"]
        c = _form()
        self.assertEqual(shipped["risk_profile"], c.risk_profile)
        self.assertEqual(set(shipped["phases"]), c.phases)
        for key in ("unattended_behavior", "max_runtime_seconds",
                    "max_tokens_total", "campaign_interval",
                    "restore_interval", "mode"):
            with self.subTest(key=key):
                self.assertEqual(shipped[key], getattr(c, key))

    def test_the_sliver_exclusion_is_documented_in_the_file(self):
        self.assertRegex(self.text, r"(?is)sliver.*agent.*unavailable"
                                    r"|agent.*unavailable.*sliver")



class TestOpsecProfilesAreNotSafetySwitches(unittest.TestCase):
    """A profile named "yolo" must not be readable as "safety off".

    That is exactly what the name invites, so the property is pinned rather
    than trusted. An OpSec profile governs what leaves the operator's host
    and how loud a scan is. It does not touch the tier-1 blocks, which are
    the irreversible actions, and it does not touch the approval gate.
    """

    FORM = {"beacons": ["a"], "scope_allow": ["10.0.1.0/24"]}

    def _campaign(self, profile):
        return config.CampaignConfig.from_form(
            dict(self.FORM, opsec_profile=profile), tier="full")

    def test_every_profile_is_covered(self):
        self.assertEqual(set(config.OPSEC_PROFILES),
                         {"quiet", "normal", "yolo"})

    def test_no_profile_changes_which_actions_are_tier_one(self):
        from software.agent import safety
        hard = {k for k, r in safety.RISK_TABLE.items()
                if r.tier == safety.TIER_HARD}
        self.assertTrue(hard, "no tier-1 rows to check")
        for profile in config.OPSEC_PROFILES:
            campaign = self._campaign(profile)
            # The profile carries two switches and neither is about tiers.
            self.assertEqual(
                set(config.OPSEC_PROFILES[profile]),
                {"online_lookups", "limit_scan_rate"},
                "%s gained a switch; check it is not a safety one" % profile)
            self.assertFalse(
                hasattr(campaign, "phase5_enabled")
                and profile == "yolo" and campaign.phases == {1, 2, 3, 4, 5},
                "yolo must not enable phase 5 by itself")

    def test_no_profile_enables_a_phase_on_its_own(self):
        for profile in config.OPSEC_PROFILES:
            self.assertEqual(self._campaign(profile).phases, {1, 2, 3, 4},
                             profile)

    def test_no_profile_changes_the_approval_behaviour(self):
        # The property, not a literal: every profile must agree, whatever
        # the value is. Pinning "decide" made this test about the default
        # rather than about the profiles, and it vetoed a correct change to
        # that default while a profile that moved it to "skip" would still
        # have passed.
        seen = {profile: self._campaign(profile).unattended_behavior
                for profile in config.OPSEC_PROFILES}
        self.assertEqual(len(set(seen.values())), 1, seen)

    def test_no_profile_changes_the_risk_numbers(self):
        normal = config.RISK_PROFILES["normal"]
        for profile in config.OPSEC_PROFILES:
            campaign = self._campaign(profile)
            self.assertEqual(campaign.ev_threshold, normal["ev_threshold"],
                             profile)
            self.assertEqual(campaign.detection_budget,
                             normal["detection_budget"], profile)
            self.assertEqual(campaign.risk_coefficient,
                             normal["risk_coefficient"], profile)

    def test_only_yolo_lifts_the_scan_rate_limit(self):
        self.assertTrue(self._campaign("quiet").limit_scan_rate)
        self.assertTrue(self._campaign("normal").limit_scan_rate)
        self.assertFalse(self._campaign("yolo").limit_scan_rate)

    def test_only_quiet_stops_third_party_lookups(self):
        self.assertFalse(self._campaign("quiet").online_lookups)
        self.assertTrue(self._campaign("normal").online_lookups)
        self.assertTrue(self._campaign("yolo").online_lookups)

    def test_a_typo_is_refused_and_lists_the_profiles(self):
        with self.assertRaises(config.ConfigError) as caught:
            config.CampaignConfig.from_form(
                dict(self.FORM, opsec_profile="quite"), tier="full")
        for name in config.OPSEC_PROFILES:
            self.assertIn(name, str(caught.exception))

    def test_a_single_switch_can_be_overridden(self):
        campaign = config.CampaignConfig.from_form(
            dict(self.FORM, opsec_profile="yolo", limit_scan_rate=True),
            tier="full")
        self.assertTrue(campaign.limit_scan_rate)
        self.assertTrue(campaign.online_lookups)


class TestOpsecWarningsSayWhatIsNotDelivered(unittest.TestCase):
    """"Quiet" with a hosted model is a promise the configuration cannot keep."""

    FORM = {"beacons": ["a"], "scope_allow": ["10.0.1.0/24"]}

    class _Agent:
        def __init__(self, provider):
            self.provider = provider

    def _warnings(self, provider, profile):
        campaign = config.CampaignConfig.from_form(
            dict(self.FORM, opsec_profile=profile), tier="full")
        return config.opsec_warnings(self._Agent(provider), campaign)

    def test_quiet_with_a_hosted_model_warns_about_the_provider(self):
        warnings = self._warnings("anthropic", "quiet")
        self.assertEqual(len(warnings), 1)
        self.assertIn("provider", warnings[0])
        self.assertIn("local", warnings[0])

    def test_quiet_with_a_local_model_is_silent(self):
        self.assertEqual(self._warnings("local", "quiet"), [])

    def test_a_quiet_profile_does_not_warn_about_any_local_provider(self):
        # "local" and "ollama" both keep the conversation on the box; telling
        # an ollama operator to "set provider to local" sends them where
        # they already are.
        campaign = types.SimpleNamespace(opsec_profile="quiet")
        for name in sorted(provider.LOCAL_PROVIDERS):
            with self.subTest(provider=name):
                agent = types.SimpleNamespace(provider=name)
                self.assertEqual(
                    [w for w in config.opsec_warnings(agent, campaign)
                     if "goes to it" in w], [])
        hosted = types.SimpleNamespace(provider="anthropic")
        self.assertTrue(any("goes to it" in w
                            for w in config.opsec_warnings(hosted, campaign)))

    def test_yolo_warns_about_the_scan_rate_and_says_what_is_untouched(self):
        warnings = self._warnings("local", "yolo")
        self.assertEqual(len(warnings), 1)
        self.assertIn("rate", warnings[0].lower())
        self.assertIn("gate", warnings[0].lower())

    def test_normal_with_a_hosted_model_is_silent(self):
        self.assertEqual(self._warnings("anthropic", "normal"), [])


class TestTheDefaultForAnUnansweredKnock(unittest.TestCase):
    """A supervised run nobody configured must not approve on a timeout.

    Design section 10.7 gives the timeout its own default: suspend the
    campaign. Section 17.2 gives the Full Automated form a different one,
    "decide autonomously", which is that form's business. One field, two
    defaults, chosen by the mode -- because in supervised mode the operator
    is the arbiter, and promoting the expected-value check to arbiter
    because somebody stepped away is not a default anyone asked for.
    """

    def _cfg(self, **payload):
        payload.setdefault("beacons", ["raccoon-fox"])
        payload.setdefault("scope_allow", ["10.0.1.0/24"])
        return config.CampaignConfig.from_form(payload, tier="full")

    def test_supervised_defaults_to_pausing(self):
        self.assertEqual(self._cfg(mode="supervised").unattended_behavior,
                         "pause")

    def test_the_mode_default_is_supervised_and_so_is_its_default(self):
        self.assertEqual(self._cfg().unattended_behavior, "pause")

    def test_full_automated_defaults_to_deciding(self):
        self.assertEqual(self._cfg(mode="auto").unattended_behavior, "decide")

    def test_an_explicit_choice_wins_in_either_mode(self):
        for mode in ("supervised", "auto"):
            for choice in ("decide", "skip", "pause"):
                self.assertEqual(
                    self._cfg(mode=mode,
                              unattended_behavior=choice).unattended_behavior,
                    choice, (mode, choice))



class TestAFallbackChainIsReadFromYaml(unittest.TestCase):
    """The chain names each link's key *variable*, never the key.

    A list of providers is the one place a config file would be tempted
    to hold several secrets, and this file is under git. So an entry
    carries `api_key_env` -- the name of an environment variable -- and a
    literal `api_key` in an entry is refused the same way
    `agent.llm.api_key` already is. A `local` link needs no key at all,
    which makes a model on the box itself a sensible last resort: it
    cannot be rate-limited and it cannot have its key revoked.

    Outside the _FIELDS cascade on purpose: a list of mappings has no
    sensible environment-variable form, and the api_key is already
    handled outside it for the same kind of reason.
    """

    def _load(self, fallbacks, env=None, provider="bedrock"):
        data = {"agent": {"llm": {"provider": provider, "model": "m",
                                  "fallbacks": fallbacks}}}
        return config.load(argv=[], yaml_path=_yaml(data),
                           env=dict(env or {"AGENT_API_KEY": "primary"}))

    def test_an_entry_becomes_a_link(self):
        cfg = self._load([{"provider": "anthropic", "model": "claude",
                           "api_key_env": "ANTHROPIC_KEY"}],
                         env={"AGENT_API_KEY": "primary",
                              "ANTHROPIC_KEY": "second"})
        self.assertEqual(len(cfg.fallbacks), 1)
        link = cfg.fallbacks[0]
        self.assertEqual((link.provider, link.model), ("anthropic", "claude"))
        self.assertEqual(link.api_key, "second")

    def test_the_variable_name_is_not_the_key(self):
        # The point of the whole design: what is written down is a name.
        cfg = self._load([{"provider": "anthropic", "model": "claude",
                           "api_key_env": "ANTHROPIC_KEY"}],
                         env={"AGENT_API_KEY": "primary"})
        self.assertIsNone(cfg.fallbacks[0].api_key)

    def test_a_literal_key_in_an_entry_is_refused(self):
        with self.assertRaises(config.ConfigError) as caught:
            self._load([{"provider": "anthropic", "model": "claude",
                         "api_key": "sk-literal-secret"}])
        message = str(caught.exception)
        self.assertIn("api_key_env", message)
        self.assertNotIn("sk-literal-secret", message)

    def test_a_local_link_needs_no_key(self):
        cfg = self._load([{"provider": "local", "model": "qwen",
                           "base_url": "http://127.0.0.1:11434/v1"}])
        self.assertEqual(cfg.fallbacks[0].provider, "local")
        self.assertIsNone(cfg.fallbacks[0].api_key)

    def test_an_entry_without_a_provider_is_refused(self):
        with self.assertRaises(config.ConfigError):
            self._load([{"model": "claude"}])

    def test_an_entry_without_a_model_is_refused(self):
        # create_client refuses a provider with no explicit model, and
        # finding that out at the first failover is finding it out
        # mid-campaign.
        with self.assertRaises(config.ConfigError):
            self._load([{"provider": "anthropic"}])

    def test_an_unknown_field_in_an_entry_is_refused_by_name(self):
        with self.assertRaises(config.ConfigError) as caught:
            self._load([{"provider": "anthropic", "model": "c",
                         "api_key_envv": "X"}])
        self.assertIn("api_key_envv", str(caught.exception))

    def test_no_fallbacks_is_the_normal_case(self):
        data = {"agent": {"llm": {"provider": "bedrock", "model": "m"}}}
        cfg = config.load(argv=[], yaml_path=_yaml(data),
                          env={"AGENT_API_KEY": "primary"})
        self.assertEqual(cfg.fallbacks, ())

    def test_a_fallbacks_value_that_is_not_a_list_is_refused(self):
        with self.assertRaises(config.ConfigError):
            self._load({"provider": "anthropic"})

    def test_a_broken_link_is_reported_by_available(self):
        # available()'s own docstring: "Every problem is reported, not the
        # first: an operator who fixes the provider only to meet the
        # Sliver conflict next has been sent round twice." A fallback that
        # cannot be built is such a problem, and the alternative is
        # discovering it at the first failover -- when the primary has
        # already gone and nobody is watching.
        cfg = config.AgentConfig(
            provider="bedrock", model="m", api_key="primary",
            fallbacks=(config.FallbackLink(provider="anthropic",
                                           model="claude", api_key=None),))
        ok, reason = cfg.available()
        self.assertFalse(ok)
        self.assertIn("fallback", reason.lower())

    def test_a_sound_chain_is_available(self):
        cfg = config.AgentConfig(
            provider="bedrock", model="m", api_key="primary",
            fallbacks=(config.FallbackLink(provider="local", model="qwen",
                                           base_url="http://127.0.0.1:1/v1"),))
        ok, reason = cfg.available()
        self.assertTrue(ok, reason)

    def test_the_chain_never_repeats_the_primary(self):
        # A fallback identical to the primary adds a second attempt at the
        # thing that just failed, and the trip logic then counts them
        # separately.
        with self.assertRaises(config.ConfigError) as caught:
            self._load([{"provider": "bedrock", "model": "m"}])
        self.assertIn("primary", str(caught.exception))


# ── Vertex ──

_VERTEX = {"AGENT_PROVIDER": "vertex", "AGENT_MODEL": "google/m",
           "AGENT_VERTEX_PROJECT": "proj"}


class TestVertexFieldsResolveThroughTheCascade(unittest.TestCase):
    """The three Vertex settings, none of them a credential."""

    # (field, command-line flag, YAML key, environment variable, default)
    FIELDS = (
        ("vertex_project", "--vertex-project", "vertex_project",
         "AGENT_VERTEX_PROJECT", None),
        ("vertex_location", "--vertex-location", "vertex_location",
         "AGENT_VERTEX_LOCATION", "europe-west4"),
        ("token_source", "--token-source", "token_source",
         "AGENT_TOKEN_SOURCE", "auto"),
    )
    VALUES = {"vertex_project": ("from-cli", "from-yaml", "from-env"),
              "vertex_location": ("us-east5", "asia-east1", "europe-west1"),
              "token_source": ("gcloud", "metadata", "file")}

    def test_the_defaults(self):
        cfg = _load()
        for name, _flag, _key, _env, default in self.FIELDS:
            with self.subTest(field=name):
                self.assertEqual(getattr(cfg, name), default)

    def test_each_level_supplies_its_field(self):
        for name, flag, key, env, _default in self.FIELDS:
            cli_value, yaml_value, env_value = self.VALUES[name]
            with self.subTest(field=name, level="command line"):
                self.assertEqual(
                    getattr(_load(argv=[flag, cli_value]), name), cli_value)
            with self.subTest(field=name, level="yaml"):
                cfg = _load(data={"agent": {"llm": {key: yaml_value}}})
                self.assertEqual(getattr(cfg, name), yaml_value)
            with self.subTest(field=name, level="environment"):
                cfg = _load(env={env: env_value})
                self.assertEqual(getattr(cfg, name), env_value)

    def test_the_levels_rank_command_line_yaml_environment(self):
        for name, flag, key, env, _default in self.FIELDS:
            cli_value, yaml_value, env_value = self.VALUES[name]
            with self.subTest(field=name):
                data = {"agent": {"llm": {key: yaml_value}}}
                cfg = _load(argv=[flag, cli_value], data=data,
                            env={env: env_value})
                self.assertEqual(getattr(cfg, name), cli_value)
                cfg = _load(data=data, env={env: env_value})
                self.assertEqual(getattr(cfg, name), yaml_value)

    def test_an_unknown_token_source_is_a_configuration_error(self):
        with self.assertRaises(config.ConfigError) as caught:
            _load(env={"AGENT_TOKEN_SOURCE": "magic"})
        message = str(caught.exception)
        self.assertIn("token_source", message)
        for kind in ("auto", "metadata", "gcloud", "file"):
            self.assertIn(kind, message)


class TestTheKeyfilePathSurvivesLoad(unittest.TestCase):
    """The `file` token source re-reads the path; startup still reads it once."""

    def test_the_api_key_file_path_survives_load(self):
        path = _keyfile(_FAKE_KEY)
        cfg = _load(env={"AGENT_API_KEY_FILE": path})
        self.assertEqual(cfg.api_key_file, path)
        self.assertEqual(cfg.api_key, _FAKE_KEY)

    def test_no_path_is_none(self):
        self.assertIsNone(_load().api_key_file)

    def test_the_path_is_not_the_key_and_the_key_stays_out_of_repr(self):
        path = _keyfile(_FAKE_KEY)
        cfg = _load(env={"AGENT_API_KEY_FILE": path})
        self.assertNotIn(_FAKE_KEY, repr(cfg))


class TestWhichVertexCredentialIsUsed(unittest.TestCase):
    """An explicit token source, else a present key as a labelled static
    bearer, else `auto`. The middle case is a deliberate opt-in for a quick
    supervised run; the point is that it is labelled and not discovered."""

    NOTE = "will not be refreshed"

    def test_an_explicit_token_source_beats_a_present_key(self):
        cfg = _load(env=dict(_VERTEX, AGENT_API_KEY=_FAKE_KEY,
                             AGENT_TOKEN_SOURCE="gcloud"))
        self.assertFalse(cfg.static_bearer)
        self.assertNotIn(self.NOTE, cfg.available()[1])

    def test_a_key_with_vertex_and_auto_is_a_labelled_static_bearer(self):
        cfg = _load(env=dict(_VERTEX, AGENT_API_KEY=_FAKE_KEY))
        self.assertTrue(cfg.static_bearer)
        ok, reason = cfg.available()
        self.assertIn(self.NOTE, reason)
        self.assertIn("hour", reason)
        self.assertNotIn(_FAKE_KEY, reason)

    def test_the_note_names_the_knobs_and_says_an_explicit_value_wins(self):
        reason = _load(env=dict(_VERTEX, AGENT_API_KEY=_FAKE_KEY)
                       ).available()[1]
        for knob in ("AGENT_TOKEN_SOURCE", "agent.llm.token_source",
                     "--token-source", "takes precedence"):
            self.assertIn(knob, reason)
        # Derived from the module, so the list cannot drift from it.
        for kind in gcp_token.KINDS:
            if kind != "auto":
                self.assertIn(kind, reason)

    def test_a_keyfile_with_vertex_and_auto_is_a_static_bearer_too(self):
        path = _keyfile(_FAKE_KEY)
        cfg = _load(env=dict(_VERTEX, AGENT_API_KEY_FILE=path))
        self.assertTrue(cfg.static_bearer)

    def test_no_key_leaves_auto_to_walk_its_sources(self):
        cfg = _load(env=dict(_VERTEX))
        self.assertFalse(cfg.static_bearer)
        self.assertNotIn(self.NOTE, cfg.available()[1])

    def test_another_provider_with_a_key_is_not_a_static_bearer(self):
        cfg = _load(env={"AGENT_PROVIDER": "anthropic", "AGENT_MODEL": "m",
                         "AGENT_API_KEY": _FAKE_KEY})
        self.assertFalse(cfg.static_bearer)
        self.assertEqual(cfg.available(), (True, ""))

    def test_the_label_does_not_make_a_usable_run_unusable(self):
        # Vertex is not a provider the client factory knows yet, so a chain
        # that builds is stood in for. What is pinned is that the label
        # rides beside a usable answer: refusing the run would turn the
        # opt-in into a prohibition.
        cfg = _load(env=dict(_VERTEX, AGENT_API_KEY=_FAKE_KEY))
        with unittest.mock.patch.object(failover, "create_chain"):
            ok, reason = cfg.available()
        self.assertTrue(ok)
        self.assertIn(self.NOTE, reason)
        self.assertNotIn(_FAKE_KEY, reason)

    def test_the_label_is_reported_beside_other_problems(self):
        cfg = _load(data={"c2": {"sliver": {"enabled": True}}},
                    env=dict(_VERTEX, AGENT_API_KEY=_FAKE_KEY))
        ok, reason = cfg.available()
        self.assertFalse(ok)
        self.assertIn(self.NOTE, reason)
        self.assertIn("sliver", reason.lower())


class TestAVertexFallbackLinkRefusesAStaticBearer(unittest.TestCase):
    def _data(self, link):
        return {"agent": {"llm": {
            "provider": "anthropic", "model": "claude-sonnet-4",
            "fallbacks": [link]}}}

    def test_a_vertex_fallback_link_refuses_api_key_env(self):
        with self.assertRaises(config.ConfigError) as caught:
            _load(data=self._data({
                "provider": "vertex", "model": "google/m",
                "base_url": "https://x.googleapis.com/v1/p/openapi",
                "api_key_env": "SOME_TOKEN"}),
                env={"SOME_TOKEN": _FAKE_KEY})
        message = str(caught.exception)
        self.assertIn("api_key_env", message)
        self.assertIn("vertex", message)
        self.assertIn("expir", message)
        self.assertNotIn(_FAKE_KEY, message)

    def test_a_vertex_link_without_api_key_env_is_read(self):
        cfg = _load(data=self._data({
            "provider": "vertex", "model": "google/m",
            "base_url": "https://x.googleapis.com/v1/p/openapi"}))
        link = cfg.fallbacks[0]
        self.assertEqual((link.provider, link.model), ("vertex", "google/m"))
        self.assertIsNone(link.api_key)

    def test_other_providers_still_name_their_key_variable(self):
        cfg = _load(data=self._data({
            "provider": "openrouter", "model": "m",
            "api_key_env": "SOME_TOKEN"}), env={"SOME_TOKEN": "second"})
        self.assertEqual(cfg.fallbacks[0].api_key, "second")


if __name__ == "__main__":
    unittest.main()
