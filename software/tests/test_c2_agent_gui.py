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
