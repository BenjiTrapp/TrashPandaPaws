#!/usr/bin/env python3
"""`/api/server/rdp` launches a viewer without a shell between.

The route built a command line out of request fields and gave the string
to `subprocess.Popen(..., shell=True)`. The VNC branch went further and
piped the password through `bash -c "echo '{password}' | vncpasswd -f"`
inside single quotes, so a password containing `'` was a command-injection
primitive. Three costs, all of them real with only the operator token:

  * the shell, which turns `;`, `$(...)` and backticks in any field into
    commands;
  * the password in the process table in clear text, where every user on
    the C2 host can read it with `ps`;
  * `/tmp/.vnc_pass_*` left behind for ever, holding an obfuscated VNC
    password that `vncpasswd` can turn back into the real one.

All three are closed here. The viewer is launched from the argument list
the route already built, the password goes to `vncpasswd` on standard
input, and the file it produces is `0600` in a private directory that is
removed when the viewer exits.

The route still needs the operator token, so the input was never
anonymous. That is why this sat in *Known limits* rather than being
treated as remote code execution -- and also why it is not nothing: the
token is what a cross-site request or a borrowed browser session holds.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.c2.server import ServerCrypto, create_app

KEY = b"k" * 32
TOKEN = "test-operator-token"


class RdpCase(unittest.TestCase):
    def setUp(self):
        self.data_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.data_dir, ignore_errors=True)
        app = create_app(ServerCrypto(KEY), TOKEN, self.data_dir)
        app.config["TESTING"] = True
        self.client = app.test_client()
        self.auth = {"Authorization": "Bearer " + TOKEN}
        self.launched = []
        self.ran = []
        # A hook that runs inside the patched Popen, for the tests that have
        # to look at the password file *before* the launcher removes it. It
        # cannot replace `_popen`: the recording is what `post` waits on,
        # and a replacement that forgot it would make every test here sit
        # out its ten-second deadline instead.
        self.on_popen = None

    def _popen(self, *args, **kwargs):
        # The hook first, the recording second. `post` waits on the
        # recording, so recording first let it return while the hook was
        # still running and the assertions then read an empty dict -- which
        # happened only when another class had run before this one, i.e. in
        # the suite and not in a single-class run.
        if self.on_popen is not None:
            self.on_popen(*args, **kwargs)
        handle = mock.MagicMock(pid=4242)
        handle.wait.return_value = 0
        self.launched.append((args, kwargs))
        return handle

    def _run(self, *args, **kwargs):
        self.ran.append((args, kwargs))
        completed = mock.MagicMock()
        completed.returncode = 0
        completed.stdout = b"\x00\x01obfuscated"
        return completed

    def post(self, **body):
        # `which` answers for every viewer name so both branches are
        # reachable on a machine that has none of them installed.
        with mock.patch("software.c2.server.shutil.which",
                        side_effect=lambda name: "/usr/bin/" + name), \
                mock.patch("software.c2.server.subprocess.Popen",
                           side_effect=self._popen), \
                mock.patch("software.c2.server.subprocess.run",
                           side_effect=self._run):
            reply = self.client.post("/api/server/rdp", json=body,
                                     headers=self.auth)
        # The launch happens on a thread; wait for it rather than sleeping.
        deadline = time.monotonic() + 10
        while not self.launched and time.monotonic() < deadline:
            time.sleep(0.01)
        return reply

    def argv(self):
        self.assertTrue(self.launched, "nothing was launched")
        args, kwargs = self.launched[0]
        return args[0], kwargs


class TestNoShellIsInvolved(RdpCase):
    def test_the_viewer_is_launched_from_an_argument_list(self):
        self.post(target="10.0.0.5", mode="xfreerdp", username="alice",
                  password="hunter2")
        argv, kwargs = self.argv()
        self.assertIsInstance(argv, list,
                              "the command is still handed over as a string")
        self.assertFalse(kwargs.get("shell"),
                         "Popen was called with shell=True")
        # The name, not the resolved path: `shutil.which` is asked which of
        # `xfreerdp` and `xfreerdp3` exists, and Popen resolves the winner
        # on PATH as it always has.
        self.assertEqual(argv[0], "xfreerdp")

    def test_shell_metacharacters_in_a_field_stay_one_argument(self):
        # The whole point. Before the fix each of these would have been
        # parsed by a shell; now they are one argv element, and the viewer
        # can refuse them as a bad host name all it likes.
        for hostile in ("10.0.0.5; touch /tmp/pwned",
                        "10.0.0.5 && id", "$(id)", "`id`",
                        "10.0.0.5\nid", "a|b", "a>out"):
            with self.subTest(target=hostile):
                self.launched = []
                self.post(target=hostile, mode="xfreerdp")
                argv, _kwargs = self.argv()
                self.assertIn("/v:" + hostile, argv)

    def test_a_vnc_password_with_a_quote_stays_one_argument(self):
        # The injection primitive the finding names: the password went into
        # `bash -c "echo '<it>' | vncpasswd -f"` inside single quotes.
        self.post(target="10.0.0.5", mode="vnc", password="it's; id")
        self.assertTrue(self.ran, "vncpasswd was never run")
        args, kwargs = self.ran[0]
        self.assertIsInstance(args[0], list)
        self.assertNotIn("bash", args[0])
        self.assertFalse(kwargs.get("shell"))

    def test_the_reported_command_is_quoted_for_a_human_not_for_a_shell(self):
        reply = self.post(target="10.0.0.5; id", mode="xfreerdp")
        shown = reply.get_json()["cmd"]
        # It is shown in the operator page, so it has to be readable -- and
        # it must not read as something safe to paste.
        self.assertIn("10.0.0.5; id", shown.replace("'", ""))


class TestThePasswordStaysOffTheProcessTable(RdpCase):
    def test_the_vnc_password_is_not_an_argument_to_anything(self):
        self.post(target="10.0.0.5", mode="vnc", password="s3cret-vnc")
        for args, kwargs in self.ran + self.launched:
            flat = " ".join(str(part) for part in
                            (args[0] if args and isinstance(args[0], list)
                             else args))
            with self.subTest(call=flat[:60]):
                self.assertNotIn("s3cret-vnc", flat)

    def test_the_vnc_password_is_written_to_stdin(self):
        self.post(target="10.0.0.5", mode="vnc", password="s3cret-vnc")
        _args, kwargs = self.ran[0]
        self.assertEqual(kwargs.get("input"), b"s3cret-vnc")

    def test_the_rdp_password_is_still_an_argument_and_says_why(self):
        # Not closed, and not closeable here: xfreerdp takes /p: on its
        # command line and offers no stdin for it. The route says so in a
        # comment; this test is what keeps that honest rather than letting
        # the above read as "no password is ever on a command line".
        self.post(target="10.0.0.5", mode="xfreerdp", password="rdp-pass")
        argv, _kwargs = self.argv()
        self.assertIn("/p:rdp-pass", argv)
        source = (REPO_ROOT / "software" / "c2" / "server.py").read_text()
        route = source[source.find("def api_server_rdp"):]
        route = route[:route.find("\n    @app.route")]
        self.assertIn("process table", route,
                      "the route does not say that /p: is visible in ps")


class TestTheGeneratedPasswordFileIsContained(RdpCase):
    def test_it_is_owner_only_and_in_an_owner_only_directory(self):
        seen = {}

        def capture(*args, **kwargs):
            # Read the file the route just wrote, before the cleanup.
            path = Path(args[0][args[0].index("-passwd") + 1])
            seen["file"] = path.stat().st_mode & 0o777
            seen["dir"] = path.parent.stat().st_mode & 0o777
            seen["path"] = path

        self.on_popen = capture
        self.post(target="10.0.0.5", mode="vnc", password="s3cret-vnc")
        self.assertEqual(seen.get("file"), 0o600, seen)
        self.assertEqual(seen.get("dir"), 0o700, seen)

    def test_it_does_not_land_in_the_shared_temp_directory(self):
        seen = {}

        def capture(*args, **kwargs):
            seen["path"] = Path(args[0][args[0].index("-passwd") + 1])

        self.on_popen = capture
        self.post(target="10.0.0.5", mode="vnc", password="s3cret-vnc")
        self.assertNotEqual(seen["path"].parent,
                            Path(tempfile.gettempdir()),
                            "the password file sits directly in the shared "
                            "temp directory, as /tmp/.vnc_pass_* did")

    def test_it_is_removed_when_the_viewer_exits(self):
        seen = {}

        def capture(*args, **kwargs):
            seen["path"] = Path(args[0][args[0].index("-passwd") + 1])

        self.on_popen = capture
        self.post(target="10.0.0.5", mode="vnc", password="s3cret-vnc")
        deadline = time.monotonic() + 10
        while seen["path"].exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertFalse(seen["path"].exists(),
                         "the generated password file outlived the viewer")
        self.assertFalse(seen["path"].parent.exists(),
                         "its directory outlived the viewer")

    def test_no_password_file_is_made_when_there_is_no_password(self):
        self.post(target="10.0.0.5", mode="vnc")
        argv, _kwargs = self.argv()
        self.assertNotIn("-passwd", argv)
        self.assertEqual(self.ran, [])


class TestTheRouteStillBehaves(RdpCase):
    def test_a_missing_target_is_refused(self):
        reply = self.client.post("/api/server/rdp", json={},
                                 headers=self.auth)
        self.assertEqual(reply.status_code, 400)

    def test_an_unknown_mode_is_refused(self):
        reply = self.client.post("/api/server/rdp",
                                 json={"target": "h", "mode": "telepathy"},
                                 headers=self.auth)
        self.assertEqual(reply.status_code, 400)

    def test_the_rdp_branch_answers_at_all(self):
        # Found while fixing the shell: `shutil` was used by the xfreerdp
        # viewer lookup and never imported, so this route answered 500 to
        # every RDP request -- the operator GUI's RDP button had been dead
        # since that lookup landed. Measured before the fix: 500 for
        # mode=xfreerdp on a machine with and without freerdp installed.
        # Unpatched on purpose: whatever this host has, the answer must be
        # a decision and not a traceback.
        reply = self.client.post("/api/server/rdp",
                                 json={"target": "10.0.0.5",
                                       "mode": "xfreerdp"},
                                 headers=self.auth)
        self.assertIn(reply.status_code, (200, 400), reply.data[:200])

    def test_the_route_still_needs_the_operator_token(self):
        reply = self.client.post("/api/server/rdp", json={"target": "h"})
        self.assertEqual(reply.status_code, 401)

    def test_the_flags_the_form_asks_for_still_arrive(self):
        self.post(target="10.0.0.5", mode="xfreerdp", username="alice",
                  domain="CORP", password="abc", use_hash=True, port="3390",
                  fullscreen=True, ignore_cert=True)
        argv, _kwargs = self.argv()
        for expected in ("/v:10.0.0.5", "/port:3390", "/d:CORP", "/u:alice",
                         "/pth:abc", "/f", "/cert-ignore", "/sec:nla",
                         "+clipboard"):
            self.assertIn(expected, argv)


if __name__ == "__main__":
    unittest.main()
