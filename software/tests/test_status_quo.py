#!/usr/bin/env python3
"""
Status-quo guard: the C2 and the beacon behave exactly as before, with no
model attached and no agent service running.

Every assertion here was true before the agent layer existed and must stay
true while it is built. An operator who never enables the agent must not be
able to tell it is there.

Apart from TestAgentPackageContracts, nothing in this file may touch
software/agent/: not an import, not a path. These tests are the proof that
the C2 does not need the package, and a test that imports it cannot prove
that. TestAgentPackageContracts is skipped when the package directory is
absent, so deleting software/agent/ leaves every other test here running.

The harness is imported, not copied: the Flask-test-client-only ServerTestBase
(with _register_agent, _checkin, _operator_get_raw; it in turn wraps the
test_c2_server harness and resets its state) from test_c2_agent_support, and
the hermetic sysfs/route/config fixtures for building a Beacon from
test_beacon_caps. They are reached through their modules rather than by name
so that the imported base classes do not get collected a second time here.
"""

import json
import re
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.c2.beacon import Beacon
from software.tests import test_beacon_caps as _caps
from software.tests import test_c2_agent_support as _support

SERVER_SOURCE = REPO_ROOT / "software" / "c2" / "server.py"
AGENT_DIR = REPO_ROOT / "software" / "agent"
REQUIREMENTS = REPO_ROOT / "software" / "requirements.txt"
SHIPPED_CONFIG = REPO_ROOT / "configs" / "raccoon.yaml"


def _run(*cmd, timeout=600):
    return subprocess.run(
        [sys.executable, *cmd], cwd=str(REPO_ROOT),
        capture_output=True, text=True, timeout=timeout)


class TestExistingSuiteUnaffected(unittest.TestCase):
    """Promise: the pre-existing C2, beacon, sniffer and NAC-bypass suites
    still pass. They run together in one process because the failures worth
    catching are interference between modules that pass alone: shared module
    state, a leaked warning filter, a monkeypatch that is never undone.

    Slow by design (~2 minutes). Do not drop modules to speed it up.
    """

    MODULES = (
        "software.tests.test_c2_server",
        "software.tests.test_beacon",
        "software.tests.test_sniffer",
        "software.tests.test_nac_bypass",
    )

    def test_full_existing_suite_passes_in_one_process(self):
        # Retried once, deliberately. Several tests in test_c2_server spawn a
        # real beacon process and wait a fixed time for it to register, so on
        # a loaded machine they time out — two implementers and I each saw
        # that while other suites and servers were running, and all three of
        # us first read it as a regression. Measured: the same commit passes
        # 38/38 in 72s on an idle machine, and so does the pre-branch
        # baseline.
        #
        # A guard that cries wolf under load is a guard people learn to
        # ignore, which is worse than not having it. One retry tells the two
        # apart: a regression fails twice, timing noise does not. It does not
        # hide a flaky *product*, only a timing-sensitive test of one.
        first = _run("-m", "unittest", *self.MODULES)
        if first.returncode == 0:
            return
        second = _run("-m", "unittest", *self.MODULES)
        self.assertEqual(
            second.returncode, 0,
            "existing suites failed twice (exit %d, then %d), so this is not "
            "load: run them alone to see which. stderr tail:\n%s"
            % (first.returncode, second.returncode, second.stderr[-4000:]))


class TestC2WithoutAgentPackage(unittest.TestCase):
    """Promise: the C2 server does not depend on software/agent/ or on any
    LLM SDK. The agent is a separate process reached over HTTP; coupling the
    two through an import would make the agent a requirement of the C2.
    """

    def test_server_imports_with_the_agent_package_unavailable(self):
        r = _run("-c",
                 "import sys; sys.modules['software.agent'] = None;"
                 " import software.c2.server as s; print(s.__name__)")
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        self.assertEqual(r.stdout.strip(), "software.c2.server")

    def test_server_source_has_no_agent_import(self):
        # A literal substring check, deliberately. The source mentions
        # "software/agent/" in a comment, which a regex using the dot as a
        # wildcard would match.
        src = SERVER_SOURCE.read_text()
        self.assertNotIn("software.agent", src)

    def test_server_source_imports_no_llm_sdk_or_scheduler(self):
        src = SERVER_SOURCE.read_text()
        for mod in ("anthropic", "openai", "aiohttp", "croniter"):
            self.assertNotIn("import " + mod, src, mod)
            self.assertNotIn("from %s " % mod, src, mod)


class TestRequirementsHaveNotGrown(unittest.TestCase):
    """Promise: the LLM layer was built on the standard library and `requests`
    on purpose, so installing the C2 pulls in no vendor SDK. The easy way to
    lose that is a casual line in requirements.txt.
    """

    FORBIDDEN = {"anthropic", "openai", "aiohttp", "httpx", "croniter"}

    def test_requirements_name_no_vendor_sdk(self):
        names = set()
        for line in REQUIREMENTS.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            m = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", line)
            if m:
                names.add(m.group(0).lower().replace("_", "-"))
        self.assertTrue(names, "parsed no requirements from %s" % REQUIREMENTS)
        self.assertEqual(names & self.FORBIDDEN, set())


class TestC2WithoutAgentService(_support.ServerTestBase):
    """Promise: with no agent service configured, every existing C2 feature
    works as it did. ServerTestBase clears AGENT_URL, so this holds whatever
    the surrounding environment says.
    """

    def test_index_renders(self):
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_agent_list_works(self):
        self.assertIsInstance(self._operator_get("/api/agents"), list)

    def test_full_task_roundtrip_works(self):
        self._register_agent()
        task = self._operator_post(f"/api/agents/{self.aid}/task", {"cmd": "whoami"})
        self.assertEqual(self._checkin()["cmd"], "whoami")
        self._beacon_post("/result", {
            "action": "result", "agent_id": self.aid, "task_id": task["id"],
            "status": "ok", "output": "root",
        })
        stored = self._operator_get(f"/api/tasks/{task['id']}")
        self.assertEqual(stored["output"], "root")
        self.assertEqual(stored["status"], "ok")

    def test_ai_routes_return_503_not_500(self):
        # An unconfigured proxy must degrade, not error.
        for path in ("/api/ai/status", "/api/ai/beacons"):
            self.assertEqual(self._operator_get_raw(path).status_code, 503, path)

    def test_server_log_and_loot_endpoints_work(self):
        self.assertIsInstance(self._operator_get("/api/logs/server"), list)
        self.assertIsInstance(self._operator_get("/api/loot"), list)


class TestBeaconCompatibilityBothWays(_support.ServerTestBase):
    """Promise: old beacons work against the new server and new beacons work
    against the old one. Neither side may require the capability field.
    """

    def setUp(self):
        super().setUp()
        for cm in (_caps._fake_sysfs(None), _caps._fake_route_table(None),
                   _caps._fake_raccoon_config(False)):
            cm.__enter__()
            self.addCleanup(cm.__exit__, None, None, None)

    def _beacon(self):
        b = Beacon(_caps._make_config())
        b._running = True
        return b

    def test_register_payload_without_caps_registers(self):
        resp = self._beacon_post("/r", {
            "action": "register", "id": "abc", "hostname": "h",
            "os": "Linux 6.1", "arch": "x86_64", "pid": 1, "user": "u",
            "interval": 300,
        })
        self.assertTrue(resp["success"])

    def test_current_beacon_payload_registers_once_caps_are_stripped(self):
        info = self._beacon()._system_info()
        self.assertIn("caps", info)
        stripped = {k: v for k, v in info.items() if k != "caps"}
        stripped["action"] = "register"
        self.assertTrue(self._beacon_post("/r", stripped)["success"])

    def test_current_beacon_payload_registers_unmodified(self):
        info = self._beacon()._system_info()
        info["action"] = "register"
        self.assertTrue(self._beacon_post("/r", info)["success"])

    def test_unknown_command_still_returns_the_existing_error(self):
        # Not "wire": the plan defers a wire command, and the day it lands
        # this test must not turn red for the wrong reason.
        b = self._beacon()
        with mock.patch.object(b, "_send_result_https") as send:
            b._process_tasking({"cmd": "no-such-command", "args": "", "id": "t1"})
        send.assert_called_once_with("t1", "error", "Unknown command: no-such-command", None)


class TestDropBoxDefaults(unittest.TestCase):
    """Promise: the shipped configuration still prefers Sliver and ships the
    agent switched off. Read as plain YAML, without the agent package.
    """

    @classmethod
    def setUpClass(cls):
        import yaml
        cls.cfg = yaml.safe_load(SHIPPED_CONFIG.read_text())

    def test_shipped_config_still_prefers_sliver(self):
        self.assertIs(self.cfg["c2"]["sliver"]["enabled"], True)

    def test_shipped_config_has_the_agent_block_disabled(self):
        self.assertIs(self.cfg["agent"]["enabled"], False)


@unittest.skipUnless(AGENT_DIR.is_dir(), "software/agent/ is absent")
class TestAgentPackageContracts(unittest.TestCase):
    """Promises about the agent package itself. The only class in this file
    that looks at software/agent/.

    Importing it must not load an HTTP library, because the C2's dependency
    guarantee rests on the transports importing `requests` lazily. That is
    what the import test below checks, and it checks it for every module
    except the two process entry points, `service` and `__main__`, which
    import aiohttp at module level because serving HTTP is their whole job.
    The exemption is deliberately that narrow: it is not "the agent may use
    aiohttp", only "the module that is the server may".

    It is also narrower than the promise it serves. That the C2 pulls in
    nothing new is proven by TestC2WithoutAgentPackage (the C2's source has
    no agent import, and the C2 imports with software.agent made
    unimportable) and by TestRequirementsHaveNotGrown; the agent's own
    dependency, aiohttp, lives in software/agent/requirements.txt and not in
    the C2's. What this test adds is that the *transports* (llm/provider.py,
    c2client.py, tools/vuln.py) stay lazy, so the package is cheap to import.
    A server library in the entry point is not a violation of that. And a
    stock configuration reports the agent unavailable, on purpose: Sliver and
    agent operation are mutually exclusive, and the shipped raccoon.yaml
    enables Sliver. Someone who sees the agent unavailable out of the box
    should find that documented here, not take it for a bug.
    """

    HTTP_LIBRARIES = ("requests", "urllib3", "httpx", "aiohttp")

    def test_every_agent_module_imports_without_an_http_library(self):
        script = textwrap.dedent("""
            import importlib, json, pkgutil, sys
            import software.agent as pkg

            def fail(name):
                raise ImportError("cannot import " + name)

            # The two process entry points, by full name: a module called
            # `service` anywhere else in the package is not exempt.
            exempt = {pkg.__name__ + ".__main__", pkg.__name__ + ".service"}
            names = [pkg.__name__]
            for m in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + ".",
                                           onerror=fail):
                if m.name not in exempt:
                    names.append(m.name)
            for name in names:
                importlib.import_module(name)
            loaded = [lib for lib in %r if lib in sys.modules]
            print(json.dumps({"modules": len(names), "loaded": loaded}))
        """ % (self.HTTP_LIBRARIES,))
        r = _run("-c", script)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        out = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertGreater(out["modules"], 1)
        self.assertEqual(out["loaded"], [],
                         "importing software.agent loaded an HTTP library")

    def test_stock_configuration_reports_the_agent_unavailable(self):
        from software.agent import config

        # env={} keeps the machine's own settings out of it.
        cfg = config.load(argv=[], yaml_path=str(SHIPPED_CONFIG), env={})
        ok, reason = cfg.available()
        self.assertFalse(ok)
        self.assertIn("Sliver", reason)


class TestTheSuiteCannotSilentlyShrink(unittest.TestCase):
    """No test class may sit after a module's `__main__` guard.

    `unittest.main()` exits at module level, so a class defined below it is
    never defined when the file is run directly -- and the file still
    reports OK, with a smaller number nobody reads. Eleven files here had
    grown that way, because appending a class to the end of a file is the
    natural thing to do and the guard was in the middle.

    `python -m unittest` imports the module instead of executing it as
    __main__, so it saw every test and the reported totals were right. The
    two invocations disagreed by 23 tests in one file. A silent disagreement
    between two obvious ways to run the suite is worth one test to prevent.
    """

    def test_no_test_class_is_defined_after_the_main_guard(self):
        import re
        offenders = {}
        for path in sorted(Path(__file__).parent.glob("test_*.py")):
            text = path.read_text()
            match = re.search(r'^if __name__ == ["\']__main__["\']:',
                              text, re.M)
            if not match:
                continue
            below = text[match.end():]
            classes = re.findall(r"^class\s+(\w+)", below, re.M)
            if classes:
                offenders[path.name] = classes
        self.assertEqual(offenders, {},
                         "test classes below the __main__ guard are skipped "
                         "when the file is run directly")


if __name__ == "__main__":
    unittest.main()
