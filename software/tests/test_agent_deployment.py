#!/usr/bin/env python3
"""Delivery: the agent ships as its own image beside the C2, not inside it.

The promise this file guards is goal 7 of the design: the existing C2 and
beacon keep working with no model attached and nothing new installed. That
is a packaging property as much as a code one, so it is asserted here --
the C2's image and requirements must not grow an LLM dependency, and the
agent's image must not grow the offensive arsenal it reaches through the
C2's API.

One deliberate divergence from the plan, which listed `anthropic` and
`openai` among the agent's requirements: the ruling recorded in the ledger
is that there is no vendor SDK at all. Both providers speak JSON over HTTPS
through `requests`, which the C2 already declares, so the agent runs the
moment it is configured rather than after a second install. The test below
therefore asserts the absence of those SDKs, which is the decision, rather
than the presence the plan assumed.
"""

import contextlib
import io
import logging
import re
import sys
import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
AGENT_DF = REPO / "software" / "agent" / "Dockerfile"
AGENT_REQS = REPO / "software" / "agent" / "requirements.txt"
C2_DF = REPO / "software" / "c2" / "Dockerfile"
C2_REQS = REPO / "software" / "requirements.txt"
COMPOSE = REPO / "software" / "c2" / "docker-compose.yml"

sys.path.insert(0, str(REPO))

from software import main  # noqa: E402


def _env_map(service) -> dict:
    """Compose accepts a list of KEY=VALUE or a mapping; read both."""
    raw = service.get("environment") or {}
    if isinstance(raw, dict):
        return {str(k): "" if v is None else str(v) for k, v in raw.items()}
    out = {}
    for item in raw:
        text = str(item)
        key, _, value = text.partition("=")
        out[key.strip()] = value.strip()
    return out


@contextlib.contextmanager
def _capture_logs():
    """Collect warning-level records from the module under test."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.WARNING)
    root = logging.getLogger()
    previous = root.level
    root.addHandler(handler)
    root.setLevel(logging.WARNING)
    lines = []
    try:
        yield lines
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)
        lines.extend(x for x in stream.getvalue().splitlines() if x.strip())


class TestAgentRequirements(unittest.TestCase):
    def setUp(self):
        self.reqs = AGENT_REQS.read_text().lower()

    def test_the_agent_declares_what_it_actually_imports(self):
        for package in ("aiohttp", "croniter", "requests", "pyyaml"):
            self.assertIn(package, self.reqs, package)

    def test_no_vendor_llm_sdk_is_declared(self):
        # The ruling: every provider is JSON over HTTPS through requests, so
        # an SDK would be a second install step and a second supply chain
        # for no capability. Four providers are implemented without one.
        for sdk in ("anthropic", "openai", "boto3", "botocore",
                    "google-generativeai", "litellm"):
            self.assertNotIn(sdk, self.reqs, sdk)

    def test_the_file_says_why_it_is_separate(self):
        # Someone will be tempted to merge this into the C2's list.
        self.assertRegex(self.reqs, r"c2'?s|must not grow|separate")


class TestTheC2SetDidNotGrow(unittest.TestCase):
    """Goal 7, as a packaging fact rather than a promise in prose."""

    def test_the_c2_requirements_carry_nothing_of_the_agent(self):
        text = C2_REQS.read_text().lower()
        for package in ("aiohttp", "croniter", "anthropic", "openai"):
            self.assertNotIn(package, text, package)

    def test_the_c2_image_installs_no_llm_dependency(self):
        text = C2_DF.read_text().lower()
        for package in ("anthropic", "openai", "aiohttp", "croniter"):
            self.assertNotIn(package, text, package)


class TestAgentImage(unittest.TestCase):
    def setUp(self):
        self.df = AGENT_DF.read_text()

    def test_the_image_carries_no_offensive_arsenal(self):
        # Design 18: a slim image. The tools are reached through the C2's
        # /api/server/exec, so a second copy here would be weight, a second
        # thing to keep patched, and a second thing to explain.
        #
        # Installation lines only, not the whole file: the Dockerfile names
        # these tools in a comment that explains why they are absent, and a
        # test that failed on that would be pressure to delete the
        # explanation. The property is "nothing installs them".
        lines = [ln.strip().lower() for ln in self.df.splitlines()
                 if re.match(r"\s*(RUN|COPY|ADD)\b", ln, re.I)]
        installs = "\n".join(lines)
        for package in ("impacket", "lsassy", "netexec", "responder",
                        "relayking", "nmap", "masscan"):
            self.assertNotIn(package, installs, package)

    def test_the_image_copies_the_agent_package(self):
        self.assertIn("software/agent", self.df)

    def test_the_image_runs_the_module(self):
        self.assertRegex(self.df, r"software\.agent")

    def test_the_image_installs_the_agents_own_requirements(self):
        self.assertIn("software/agent/requirements.txt", self.df)

    def test_the_image_does_not_run_as_root(self):
        # It holds an API key and a C2 token in its environment; there is no
        # reason for it to be root as well.
        self.assertRegex(self.df, r"(?im)^\s*USER\s+(?!root)\S+")

    def test_the_context_is_the_repo_root_and_the_file_says_so(self):
        # software/c2 as context cannot see software/agent, which is the
        # trap this comment exists to stop someone walking into.
        self.assertRegex(self.df.lower(), r"context|repo(sitory)? root")


class TestCompose(unittest.TestCase):
    def setUp(self):
        self.raw = COMPOSE.read_text()
        self.compose = yaml.safe_load(self.raw)
        self.services = self.compose["services"]

    def test_the_agent_is_a_service(self):
        self.assertIn("agent", self.services)

    def test_the_agent_publishes_no_port(self):
        # It binds loopback and is reached by the C2 on the same host. A
        # published port would put an API that runs commands on the network.
        self.assertFalse(self.services["agent"].get("ports"))

    def test_the_agent_shares_the_host_network(self):
        # The C2 needs network_mode: host for Responder and the relay
        # tooling, and that leaves no compose network for service names.
        self.assertEqual(self.services["agent"].get("network_mode"), "host")

    def test_neither_service_waits_for_the_other(self):
        # Design 19.1: the C2 must come up without the agent, and the agent
        # must survive a C2 that is not there yet.
        for name in ("raccoon-c2", "agent"):
            self.assertFalse(self.services[name].get("depends_on"), name)

    def test_the_agent_build_context_reaches_the_repo_root(self):
        build = self.services["agent"]["build"]
        self.assertIsInstance(build, dict)
        self.assertIn("..", str(build.get("context")))
        self.assertIn("software/agent/Dockerfile", str(build.get("dockerfile")))

    def test_the_c2_is_told_where_the_agent_is(self):
        env = _env_map(self.services["raccoon-c2"])
        self.assertIn("AGENT_URL", env)
        self.assertIn("127.0.0.1", env["AGENT_URL"])
        self.assertIn("8099", env["AGENT_URL"])

    def test_both_services_share_the_agent_token_variable(self):
        for name in ("raccoon-c2", "agent"):
            self.assertIn("RACCOON_AGENT_TOKEN", _env_map(self.services[name]),
                          name)

    def test_the_agent_keeps_its_database_across_restarts(self):
        volumes = self.services["agent"].get("volumes") or []
        self.assertTrue(any("agent" in str(v) for v in volumes), volumes)

    def test_no_credential_is_written_into_the_file(self):
        # Every secret is a ${VAR} reference. A literal here is a literal in
        # git, and this repo has a pre-commit hook for exactly that reason.
        for pattern in (r"sk-ant-[A-Za-z0-9]{8}", r"sk-[A-Za-z0-9]{20}",
                        r"(?i)AKIA[0-9A-Z]{10}", r"ABSK[A-Za-z0-9]{10}"):
            self.assertNotRegex(self.raw, pattern, pattern)

    def test_every_secret_is_a_variable_reference(self):
        env = _env_map(self.services["agent"])
        for key in ("AGENT_API_KEY", "RACCOON_TOKEN", "RACCOON_AGENT_TOKEN"):
            self.assertIn(key, env, key)
            self.assertRegex(env[key], r"^\$\{[A-Z_]+(:-[^}]*)?\}$", key)

    def test_the_fixed_token_requirement_is_written_down(self):
        # Without a fixed RACCOON_TOKEN the C2 invents one at startup and the
        # agent cannot authenticate -- the failure looks like "0 beacons",
        # which sends the reader looking in the wrong place.
        self.assertRegex(self.raw, r"(?is)RACCOON_TOKEN.{0,400}(fixed|random)")


class TestSliverWarning(unittest.TestCase):
    """A Sliver-managed box never checks in, so the agent cannot see it."""

    def test_both_configured_warns_and_names_sliver(self):
        cfg = {"c2": {"sliver": {"enabled": True}}, "agent": {"enabled": True}}
        with _capture_logs() as logs:
            main._check_agent_beacon_conflict(cfg)
        self.assertRegex("\n".join(logs).lower(), r"sliver")

    def test_the_shipped_default_stays_silent(self):
        # configs/raccoon.yaml ships sliver enabled and no agent block. The
        # status quo must not start emitting warnings.
        cfg = {"c2": {"sliver": {"enabled": True}}}
        with _capture_logs() as logs:
            main._check_agent_beacon_conflict(cfg)
        self.assertEqual(logs, [])

    def test_no_warning_when_sliver_is_off(self):
        cfg = {"c2": {"sliver": {"enabled": False}},
               "agent": {"enabled": True}}
        with _capture_logs() as logs:
            main._check_agent_beacon_conflict(cfg)
        self.assertEqual(logs, [])

    def test_a_missing_or_odd_config_is_not_an_error(self):
        # Called on whatever the config file contained.
        for cfg in ({}, None, {"c2": None}, {"agent": "yes"},
                    {"c2": {"sliver": "on"}, "agent": {"enabled": True}}):
            with _capture_logs():
                main._check_agent_beacon_conflict(cfg)


class TestLauncher(unittest.TestCase):
    def setUp(self):
        self.sh = (REPO / "software" / "c2" / "start_server.sh").read_text()

    def test_the_launcher_can_start_the_agent(self):
        self.assertIn("software.agent", self.sh)

    def test_starting_the_agent_is_a_choice_not_a_default(self):
        # The C2 has to keep starting the way it does today for someone who
        # has no model configured.
        self.assertRegex(self.sh, r"(?i)AGENT")
        self.assertRegex(self.sh, r"(?is)read\s+-\w*\s*\w*.{0,200}agent"
                                  r"|agent.{0,200}read\s+-")

    def test_the_launcher_exports_the_url_the_c2_reads(self):
        self.assertRegex(self.sh, r"AGENT_URL")


if __name__ == "__main__":
    unittest.main()
