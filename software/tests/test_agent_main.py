#!/usr/bin/env python3
"""
Tests for the agent's start-up messages.

Only what an operator reads on the console is checked here: `main` is run with
its configuration and its server replaced, because nothing about binding a
port is in question.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent import __main__ as agent_main
from software.agent import config

_FAKE_KEY = "ZZ-not-a-real-key"


class TestAUsableStartWithACaveatIsNotSilent(unittest.TestCase):
    def _run(self, available):
        cfg = config.AgentConfig(
            provider="vertex", model="google/m", api_key=_FAKE_KEY,
            agent_token="t", db_path=":memory:")
        with mock.patch.object(config, "load", return_value=cfg), \
                mock.patch.object(config.AgentConfig, "available",
                                  return_value=available), \
                mock.patch.object(agent_main.web, "run_app"), \
                mock.patch.object(agent_main.logging, "basicConfig"):
            with self.assertLogs("agent", level="INFO") as logged:
                self.assertEqual(agent_main.main([]), 0)
        return [(r.levelname, r.getMessage()) for r in logged.records]

    def test_the_caveat_is_a_warning_beside_the_model_line(self):
        records = self._run((True, "will not be refreshed"))
        self.assertIn(("WARNING", "will not be refreshed"), records)
        self.assertTrue(any(level == "INFO" and msg.startswith("model:")
                            for level, msg in records))

    def test_a_clean_start_logs_no_such_warning(self):
        records = self._run((True, ""))
        self.assertEqual([m for level, m in records
                          if level == "WARNING" and "refreshed" in m], [])
        self.assertTrue(any(msg.startswith("model:") for _l, msg in records))

    def test_an_unusable_start_still_says_no_campaign_can_start(self):
        records = self._run((False, "the reason"))
        self.assertIn(("WARNING", "no campaign can start: the reason"),
                      records)
        self.assertFalse(any(msg.startswith("model:") for _l, msg in records))


if __name__ == "__main__":
    unittest.main()
