#!/usr/bin/env python3
"""
Operator GUI for the agent layer: static assets and the degradation contract.

There is no JS test infrastructure in this repo, so only what Python can see
is checked here: that the files are served, that the index references them,
and that agent.js keeps the property the whole design rests on -- a missing or
broken agent layer costs the operator one button and nothing else. Behaviour
in the browser is checked by hand against a running C2.
"""

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent import config
from software.c2.server import ServerCrypto, create_app
from software.tests.test_c2_server import (
    TEST_TOKEN,
    ServerTestBase as _Harness,
    _derive_key,
    _reset_server_state,
)

_C2_DIR = Path(__file__).resolve().parent.parent / "c2"
AGENT_JS = _C2_DIR / "static" / "agent.js"
AGENT_CSS = _C2_DIR / "static" / "agent.css"
SERVER_PY = _C2_DIR / "server.py"

_AUTH = {"Authorization": f"Bearer {TEST_TOKEN}"}


class ServerTestBase(_Harness):
    """The shared harness without the live Flask thread on a fixed port."""

    @classmethod
    def setUpClass(cls):
        _reset_server_state()
        cls.crypto = ServerCrypto(_derive_key())
        cls.data_dir = Path(tempfile.mkdtemp())
        cls.app = create_app(cls.crypto, TEST_TOKEN, cls.data_dir)
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

    def setUp(self):
        _reset_server_state()
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("AGENT_URL", None)
        os.environ.pop("RACCOON_AGENT_TOKEN", None)


class TestStaticAssets(ServerTestBase):
    def test_agent_js_is_served(self):
        self.assertEqual(self.client.get("/static/agent.js").status_code, 200)

    def test_agent_css_is_served(self):
        self.assertEqual(self.client.get("/static/agent.css").status_code, 200)

    def test_index_references_both_assets(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn("/static/agent.js", html)
        self.assertIn("/static/agent.css", html)

    def test_script_is_deferred_and_after_the_inline_script(self):
        """defer runs it after parsing, so after the inline globals exist."""
        html = self.client.get("/").get_data(as_text=True)
        tag = '<script src="/static/agent.js" defer></script>'
        self.assertEqual(html.count(tag), 1)
        self.assertGreater(html.index(tag), html.index("const TOKEN"))
        self.assertLess(html.index(tag), html.index("</body>"))

    def test_stylesheet_is_linked_in_the_head(self):
        html = self.client.get("/").get_data(as_text=True)
        link = '<link rel="stylesheet" href="/static/agent.css">'
        self.assertEqual(html.count(link), 1)
        self.assertLess(html.index(link), html.index("</head>"))


class TestGuiDegradation(ServerTestBase):
    """Spec 19.2: without the agent service the GUI stays usable."""

    def test_index_still_renders_without_agent_service(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn(TEST_TOKEN, html)
        self.assertIn("Raccoon C2", html)

    def test_status_endpoint_answers_503_without_a_service(self):
        """The case the button has to render as disabled."""
        r = self.client.get("/api/ai/status", headers=_AUTH)
        self.assertEqual(r.status_code, 503)
        self.assertIn("error", r.get_json())

    def test_button_is_not_hardcoded_in_the_html_literal(self):
        """The button comes from agent.js: a missing file costs only it."""
        html = self.client.get("/").get_data(as_text=True)
        self.assertNotIn("Automated Attack", html)
        self.assertNotIn("Automated Attack", SERVER_PY.read_text())

    def test_server_py_only_names_the_two_assets(self):
        """No markup, handler or function for the agent in the 5,000-line literal."""
        source = SERVER_PY.read_text()
        self.assertEqual(source.count("/static/agent.js"), 1)
        self.assertEqual(source.count("/static/agent.css"), 1)
        for name in ("agentInit", "ai-pane", "ai-drawer", "ai-btn"):
            self.assertNotIn(name, source)

    def test_agent_js_inserts_the_button_itself(self):
        self.assertIn("Automated Attack", AGENT_JS.read_text())

    def test_every_ai_fetch_is_guarded(self):
        """A 503 must not tear down an existing setInterval loop."""
        js = AGENT_JS.read_text()
        calls = list(re.finditer(r"(?:fetch|api)\(\s*[`'\"]/api/ai", js))
        self.assertTrue(calls, "no /api/ai call found; the guard check is vacuous")
        for m in calls:
            self.assertIn("try", js[max(0, m.start() - 400):m.start()],
                          "unguarded call at offset %d" % m.start())

    def test_ai_calls_go_through_one_choke_point(self):
        """One place to guard is one place to get right."""
        js = AGENT_JS.read_text()
        self.assertEqual(len(re.findall(r"(?:fetch|api)\(\s*[`'\"]/api/ai", js)), 1)

    def test_status_is_not_polled_continuously(self):
        js = AGENT_JS.read_text()
        self.assertNotRegex(js, r"setInterval\([^)]*api/ai/status")
        self.assertNotRegex(js, r"(?:setInterval|setTimeout)\([^;]*agentLoadStatus")

    def test_no_interval_timers_for_the_campaign_polls(self):
        """Polls are rescheduled one at a time so a failure can back them off."""
        self.assertNotIn("setInterval(", AGENT_JS.read_text())

    def test_agent_js_does_not_touch_the_operator_token_in_a_url(self):
        js = AGENT_JS.read_text()
        self.assertNotRegex(js, r"[?&]token=")


def _js_table(js, name):
    """A `const NAME = { key: {field: value, ...}, ... };` literal as a dict.

    Only for the flat tables the form keeps in step with config.py, so a
    number changed there and not here is a failing test, not a form that
    shows one thing and submits another.
    """
    m = re.search(r"const %s\s*=\s*\{(.*?)\n\};" % name, js, re.S)
    assert m, "no table named %s in agent.js" % name
    table = {}
    for key, body in re.findall(r"(\w+):\s*\{([^}]*)\}", m.group(1)):
        row = {}
        for field, raw in re.findall(r"(\w+):\s*(-?[\w.]+)", body):
            row[field] = (raw == "true") if raw in ("true", "false") else float(raw)
        table[key] = row
    return table


def _js_list(js, name):
    m = re.search(r"const %s\s*=\s*\[(.*?)\];" % name, js, re.S)
    assert m, "no list named %s in agent.js" % name
    return re.findall(r"\"([^\"]*)\"", m.group(1))


class TestFullAutoForm(unittest.TestCase):
    """What Python can see of the configuration form; the rest is by hand."""

    @classmethod
    def setUpClass(cls):
        cls.js = AGENT_JS.read_text()

    def test_form_has_all_nine_sections_in_order(self):
        # Eight from the spec, in its order, and OpSec after them: it was
        # added later and is the one the operator must not be able to miss.
        self.assertEqual(_js_list(self.js, "FORM_SECTIONS"),
                         ["Target beacons", "Scope", "Phases", "Risk profile",
                          "Approvals", "Budget", "Model", "Schedule", "OpSec"])

    def test_the_form_is_in_english(self):
        for german in ("Ziel-Beacons", "Phasen", "Risikoprofil", "Anklopfen",
                       "Zeitplan", "Modell", "Entfesseln"):
            self.assertNotIn(german, self.js)

    def test_the_submit_button_is_unleash(self):
        self.assertRegex(self.js, r"(?:\\u26A1|\u26A1) ?Unleash")

    # ── Phases ──

    def test_phase_five_default_is_off_and_one_to_four_are_on(self):
        on = _js_table_flags(self.js, "DEFAULT_PHASES_ON")
        self.assertEqual({p for p, v in on.items() if v}, {1, 2, 3, 4})
        self.assertIs(on[5], False)

    def test_all_eight_phases_are_offered(self):
        self.assertEqual(set(_js_table_flags(self.js, "DEFAULT_PHASES_ON")),
                         set(range(1, 9)))

    def test_wifi_phases_are_gated_on_the_monitor_capability(self):
        self.assertIn("wifi:monitor", self.js)
        self.assertRegex(self.js, r"WIFI_PHASES\s*=\s*\[6,\s*7,\s*8\]")
        self.assertRegex(self.js, r"no monitor-capable adapter")

    def test_phase_five_is_locked_unless_the_tier_is_full(self):
        self.assertRegex(self.js, r"tier\s*!==\s*\"full\"")

    def test_a_locked_phase_says_why_in_a_title(self):
        # The model and the tier are named, not just a greyed box.
        self.assertRegex(self.js, r"capability tier")
        self.assertRegex(self.js, r"setAttribute\(\"title\"|\btitle:")

    # ── Scope ──

    def test_empty_scope_is_refused_client_side(self):
        self.assertRegex(self.js.lower(), r"scope[^\n]*(is empty|required)")

    def test_cidr_shape_is_checked_and_the_server_is_named_the_authority(self):
        self.assertIn("CIDR_V4", self.js)
        self.assertRegex(self.js.lower(), r"convenience[^\n]*server|server[^\n]*authority")

    # ── Risk profile: four numbers ──

    def test_the_three_risk_presets_match_the_config(self):
        table = _js_table(self.js, "RISK_PRESETS")
        self.assertEqual(set(table), set(config.RISK_PROFILES))
        for name, fields in config.RISK_PROFILES.items():
            self.assertEqual(table[name], {k: float(v) for k, v in fields.items()},
                             "%s drifted from config.RISK_PROFILES" % name)

    def test_the_profile_drives_four_numbers_including_the_risk_coefficient(self):
        fields = _js_list(self.js, "RISK_FIELDS")
        self.assertEqual(set(fields), set(config.RISK_PROFILES["normal"]))
        self.assertIn("risk_coefficient", fields)
        self.assertEqual(len(fields), 4)

    def test_a_touched_field_is_not_overwritten_by_a_profile(self):
        # One flag per field: the first field's edit must not pin the others.
        self.assertRegex(self.js, r"F\.dirty\[\s*\w+\s*\]\s*=\s*true")
        self.assertRegex(self.js, r"if\s*\(\s*!\s*F\.dirty\[")

    # ── Approvals ──

    def test_three_unattended_behaviours_are_offered(self):
        for b in ("decide", "skip", "pause"):
            self.assertIn('"%s"' % b, self.js)

    def test_the_form_starts_the_campaign_in_auto_mode(self):
        # Without it the service treats the run as supervised and the
        # unattended behaviour chosen above would have no effect.
        self.assertRegex(self.js, r"mode:\s*\"auto\"")

    # ── Budget ──

    def test_budget_defaults_match_the_spec(self):
        self.assertIn("7200", self.js)
        self.assertIn("500000", self.js)
        self.assertRegex(self.js, r"campaign_interval[^\n]*15")

    # ── OpSec ──

    def test_opsec_profiles_are_the_configured_ones(self):
        table = _js_table(self.js, "OPSEC_EFFECTS")
        self.assertEqual(set(table), set(config.OPSEC_PROFILES))
        for name, fields in config.OPSEC_PROFILES.items():
            self.assertEqual(table[name], fields,
                             "%s drifted from config.OPSEC_PROFILES" % name)

    def test_opsec_warning_is_read_from_status_for_the_chosen_profile(self):
        self.assertIn("opsec_warnings", self.js)
        self.assertRegex(self.js, r"opsec_warnings\[\s*\w+(?:\.\w+)*\s*\]")

    def test_yolo_is_explained_as_lifting_the_scan_rate_limit_only(self):
        text = self.js.lower()
        self.assertIn("tier-1", text)
        self.assertIn("approval gate", text)
        self.assertRegex(text, r"scan rate")
        self.assertRegex(text, r"nothing else")

    def test_opsec_profile_is_submitted(self):
        self.assertRegex(self.js, r"opsec_profile\s*:")

    # ── Hard blocks ──

    def test_hard_block_list_comes_from_status(self):
        self.assertIn("tier1_actions", self.js)

    def test_the_fallback_is_short_and_says_it_is_unconfirmed(self):
        fallback = _js_list(self.js, "HARD_BLOCK_FALLBACK")
        self.assertEqual(fallback, ["kill", "unpersist", "reconfig"])
        self.assertIn("could not be confirmed", self.js)

    def test_the_list_is_described_as_not_configurable_and_irreversible(self):
        text = self.js.lower()
        self.assertIn("not configurable", text)
        self.assertIn("irreversible", text)

    # ── Presets ──

    def test_presets_live_in_local_storage(self):
        self.assertIn("localStorage", self.js)
        for fn in ("agentSavePreset", "agentLoadPreset", "agentCollectForm",
                   "agentOpenFullAutoForm"):
            self.assertIn("function " + fn, self.js)

    def test_no_credential_reaches_local_storage(self):
        # Nothing on a line that touches localStorage may name the operator
        # token, the Authorization header or a key.
        for line in self.js.splitlines():
            if "localStorage" in line:
                for word in ("TOKEN", "Authorization", "Bearer", "api_key",
                             "agent_token", "H,", "headers"):
                    self.assertNotIn(word, line)

    def test_a_preset_is_a_whitelist_not_the_whole_form(self):
        fields = _js_list(self.js, "PRESET_FIELDS")
        for secret in ("token", "api_key", "key", "authorization", "headers"):
            self.assertNotIn(secret, [f.lower() for f in fields])
        # Not the beacon selection: a fleet changes between engagements.
        self.assertNotIn("beacons", fields)
        self.assertIn("scope_allow", fields)
        self.assertIn("opsec_profile", fields)

    # ── Submit ──

    def test_the_confirmation_names_beacons_and_scope(self):
        m = re.search(r"function unleashSummary.*?\n\}", self.js, re.S)
        self.assertTrue(m, "no unleashSummary()")
        body = m.group(0)
        self.assertIn("beacon", body)
        self.assertIn("scope", body.lower())
        self.assertRegex(self.js, r"confirm\(\s*unleashSummary")

    def test_a_bad_cron_is_shown_not_swallowed(self):
        self.assertIn("schedules", self.js)
        self.assertRegex(self.js, r"aiCall\(\s*\"schedules\"")
        self.assertRegex(self.js, r"reasonOf\(")

    def test_the_form_only_reaches_the_service_through_aicall(self):
        self.assertRegex(self.js, r"aiCall\(\s*\"campaign\"")
        self.assertRegex(self.js, r"aiCall\(\s*\"beacons\"")

    def test_form_state_survives_the_panel_being_replaced(self):
        # The stream's detail view opens in the same side panel, which would
        # take the form with it; the state is kept apart from the DOM.
        self.assertRegex(self.js, r"const F\s*=\s*\{")


def _js_table_flags(js, name):
    m = re.search(r"const %s\s*=\s*\{(.*?)\};" % name, js, re.S)
    assert m, "no table named %s in agent.js" % name
    return {int(k): v == "true" for k, v in re.findall(r"(\d):\s*(true|false)", m.group(1))}


class TestFormStyles(unittest.TestCase):
    def test_form_classes_are_styled(self):
        css = AGENT_CSS.read_text()
        for cls in (".ai-form", ".ai-sec", ".ai-tag", ".ai-tag.bad", ".ai-phase",
                    ".ai-unleash"):
            self.assertIn(cls, css)

    def test_the_form_does_not_redefine_the_palette(self):
        css = AGENT_CSS.read_text()
        self.assertNotRegex(css, r"--(?:red|green|yellow|orange)\s*:")


class TestAccentColours(unittest.TestCase):
    def test_no_second_variable_duplicates_orange(self):
        css = AGENT_CSS.read_text()
        self.assertNotRegex(css, r"--[\w-]+\s*:\s*#ff6600", "duplicates --orange")
        self.assertRegex(css, r"--ai\s*:\s*var\(--orange\)")

    def test_operator_accent_is_new(self):
        self.assertRegex(AGENT_CSS.read_text(), r"--op\s*:\s*#33ccff")

    def test_palette_is_inherited_not_redefined(self):
        css = AGENT_CSS.read_text()
        for inherited in ("--bg", "--red", "--text", "--text2", "--border",
                          "--mono", "--sans", "--surface"):
            self.assertNotRegex(css, re.escape(inherited) + r"\s*:",
                                "%s is redefined" % inherited)


if __name__ == "__main__":
    unittest.main()
