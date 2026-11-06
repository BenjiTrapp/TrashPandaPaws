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

from software.agent import config, prompts
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

    def test_form_has_every_section_in_order(self):
        # Eight from spec 17.2 in its order, OpSec after them because it
        # arrived later and must not be missable, and Mode first because it
        # decides what the rest of the form means: 17.1 (supervised) and
        # 17.2 (Full Automated) are both started here.
        self.assertEqual(_js_list(self.js, "FORM_SECTIONS"),
                         ["Mode", "Target beacons", "Scope", "Phases",
                          "Risk profile", "Approvals", "Budget", "Model",
                          "Schedule", "OpSec"])

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

    def test_the_form_starts_the_campaign_in_the_chosen_mode(self):
        # This test used to require mode: "auto" and carried the reasoning
        # that led there -- "otherwise the service treats the run as
        # supervised and the unattended behaviour would have no effect".
        # That had the cause backwards. The unattended choice belongs to
        # Full Automated (17.2); supervised (17.1) is a different mode whose
        # whole point is that knocks reach the operator. Hardcoding auto
        # meant the knock card could not be reached from the GUI at all, so
        # the test was pinning the defect.
        self.assertRegex(self.js, r"mode:\s*F\.mode")
        self.assertNotRegex(self.js, r"mode:\s*\"auto\"\s*,")

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



class TestDrawerAndDetailUseTheNewFields(unittest.TestCase):
    """The two gaps the GUI could not fill, now that the data exists.

    The drawer had rows with nothing behind them, and the detail panel said
    outright that the arguments and raw output were not exposed. Both were
    data gaps in the orchestrator and the service, not in the GUI.
    """

    @classmethod
    def setUpClass(cls):
        cls.js = AGENT_JS.read_text()

    def test_the_detail_panel_fetches_the_full_event(self):
        self.assertRegex(self.js, r"campaign/\"\s*\+\s*A\.rid\s*\+\s*\"/event/")
        self.assertIn("function fillEventDetail", self.js)

    def test_the_panel_no_longer_claims_the_data_is_unavailable(self):
        self.assertNotIn("not exposed by the agent service", self.js)

    def test_the_panel_names_arguments_and_raw_output(self):
        self.assertIn("Arguments the model chose", self.js)
        self.assertIn("Raw output", self.js)

    def test_an_aged_out_event_is_distinguished_from_an_unreachable_one(self):
        # One is the stream's bounded buffer, the other is a broken service,
        # and they call for different reactions.
        self.assertRegex(self.js, r"no longer held")
        self.assertRegex(self.js, r"could not be fetched")

    def test_the_drawer_shows_detections_against_their_limit(self):
        self.assertRegex(self.js, r"budgets\s*&&\s*c\.budgets\.detections")
        self.assertRegex(self.js, r"det\.used.*det\.limit")

    def test_the_drawer_shows_tasks_findings_and_the_scope(self):
        for label in ('"Tasks"', '"Findings"', '"Scope"', '"Excluded"',
                      '"Risk"', '"OpSec"'):
            self.assertIn(label, self.js)

    def test_yolo_is_marked_hot_in_the_drawer(self):
        self.assertRegex(self.js, r'c\.opsec_profile\s*===\s*"yolo"')


class TestThePhaseLabelsMatchThePhases(unittest.TestCase):
    """The checkbox the operator ticks must name what the model is told.

    Found while reading both sides against the design (spec section 12).
    The GUI had invented its own phase names -- "Credential access" for 3,
    "Lateral movement" for 4 -- and nothing compared them to anything. The
    prompt tells the model that phase 3 is Port and Service Enumeration and
    phase 4 is OS and Vulnerability Fingerprinting, which is what the spec
    specifies.

    So the phase list, which is the operator's main control over what the
    agent may do, was describing activities this agent has no phases for.
    An operator unticking 3 to keep the agent away from credentials was in
    fact switching off port scanning.
    """

    def _js_phase_names(self):
        js = AGENT_JS.read_text()
        block = re.search(r"const PHASE_NAMES = \{(.*?)\}", js, re.S)
        self.assertIsNotNone(block, "PHASE_NAMES not found in agent.js")
        return {int(n): label
                for n, label in re.findall(r'(\d+)\s*:\s*"([^"]+)"',
                                           block.group(1))}

    def test_every_phase_the_gui_offers_has_a_name(self):
        self.assertEqual(sorted(self._js_phase_names()), list(range(1, 9)))

    def test_the_gui_labels_are_the_names_the_prompt_uses(self):
        self.assertEqual(self._js_phase_names(), dict(prompts.PHASE_NAMES))

    def test_the_prompt_titles_are_built_from_the_same_table(self):
        # Otherwise the table could be corrected and the prose left behind.
        text = prompts._phase_section({"b": ["sniffer", "wifi:monitor"]},
                                      set(range(1, 9)))
        for number, name in prompts.PHASE_NAMES.items():
            self.assertIn("Phase %d - %s" % (number, name), text)


class TestTheFormOffersBothAgentModes(unittest.TestCase):
    """Design 17.1 is supervised; 17.2 is Full Automated. Both are startable.

    The form sent a hardcoded mode: "auto" with a comment explaining that
    otherwise "the unattended behaviour chosen above would never apply".
    The reasoning had the cause the wrong way round: that setting belongs to
    the Full Automated form (17.2, "knocking without an operator"), and
    supervised mode is a different mode with its own screen (17.1), whose
    mockup is the pinned knock card with [Allow][No] in the drawer.

    So "Automated Attack" started Full Automated, and the operator knock
    card -- implemented, polled for, and the whole point of watching a run
    -- could not be reached from the GUI at all. Every knock in testing had
    to be produced by posting to the API by hand.
    """

    def _js(self):
        return AGENT_JS.read_text()

    def test_the_mode_is_not_hardcoded(self):
        self.assertNotRegex(self._js(), r'mode:\s*"auto"\s*,')

    def test_both_modes_are_offered(self):
        js = self._js()
        self.assertIn("Automated Attack", js)
        self.assertIn("Full Automated", js)

    def test_the_mode_values_are_the_ones_the_service_accepts(self):
        js = self._js()
        block = re.search(r"const AGENT_MODES = \{(.*?)\n\};", js, re.S)
        self.assertIsNotNone(block, "AGENT_MODES not found in agent.js")
        offered = set(re.findall(r'(\w+):\s*\{', block.group(1)))
        self.assertEqual(offered, set(config._MODES))

    def test_the_payload_carries_the_chosen_mode(self):
        self.assertRegex(self._js(), r"mode:\s*F\.mode")

    def test_supervised_is_the_default_so_unattended_is_asked_for(self):
        self.assertRegex(self._js(), r'F\.mode\s*=\s*"supervised"')

    def test_the_unattended_default_follows_the_mode(self):
        # The choice is shown in both modes -- "what happens if nobody
        # answers" matters in a supervised run too, for the operator who
        # steps away -- but its default differs, the same rule config.py
        # applies. Hiding it would recreate the original fault: a setting
        # that silently does not apply.
        js = self._js()
        self.assertRegex(js, r'UNATTENDED_DEFAULT\s*=\s*\{')
        block = re.search(r"const UNATTENDED_DEFAULT = \{(.*?)\};", js, re.S)
        self.assertIsNotNone(block)
        pairs = dict(re.findall(r'(\w+):\s*"(\w+)"', block.group(1)))
        self.assertEqual(pairs, {"supervised": "pause", "auto": "decide"})


class TestTheReportIsReachableFromTheGui(unittest.TestCase):
    """A deliverable nobody can find is not a deliverable.

    The report is served at /campaign/<id>/report, and until this the
    only way to it was knowing the URL. An operator finishing a campaign
    should be one click from the thing they hand over.
    """

    @classmethod
    def setUpClass(cls):
        cls.js = AGENT_JS.read_text()

    def test_the_panel_offers_a_report_for_each_campaign(self):
        self.assertIn("/report", self.js)
        self.assertRegex(self.js, r'text:\s*"Report"')

    def test_it_goes_through_the_one_choke_point(self):
        # Two earlier versions of this test were wrong in opposite ways.
        # The first demanded the token in the URL so window.open would
        # work -- the worse design, since a token in a URL lands in the
        # browser's history and in every access log it passes. The second
        # looked for "headers" inside downloadReport, which is where the
        # header *was* before it went through aiCall. The property is
        # neither: the report uses the single function that builds an
        # /api/ai URL and attaches the operator header, which
        # test_ai_calls_go_through_one_choke_point already guards.
        self.assertRegex(self.js, r"function downloadReport")
        body = re.search(r"async function downloadReport[\s\S]{0,900}",
                         self.js).group(0)
        self.assertIn("aiCall(", body)
        self.assertNotIn("fetch(", body)

    def test_the_token_is_never_put_in_the_report_url(self):
        body = re.search(r"function downloadReport[\s\S]{0,900}", self.js)
        self.assertIsNotNone(body)
        self.assertNotIn("token=", body.group(0))

    def test_a_failure_says_so_instead_of_silently_doing_nothing(self):
        # A button that does nothing on a 404 or a dead service teaches
        # the operator not to trust it.
        self.assertRegex(self.js,
                         r"downloadReport[\s\S]{0,900}notify")


class TestTheFallbackChainIsVisible(unittest.TestCase):
    """A chain nobody can see is a chain nobody trusts.

    The status panel showed one model. With a chain configured, the
    operator had no way to know a second provider existed or which one
    was serving -- and the moment that matters is the moment a campaign
    is running on the fallback.
    """

    @classmethod
    def setUpClass(cls):
        cls.js = AGENT_JS.read_text()

    def test_the_panel_lists_the_chain(self):
        self.assertRegex(self.js, r"s\.fallbacks")

    def test_it_says_what_the_chain_is_for(self):
        # A bare list of provider names reads as a configuration dump.
        self.assertRegex(self.js, r"fallback|if the first")

    def test_a_single_provider_is_not_dressed_up_as_a_chain(self):
        self.assertRegex(self.js, r"fallbacks[\s\S]{0,200}length")

if __name__ == "__main__":
    unittest.main()
