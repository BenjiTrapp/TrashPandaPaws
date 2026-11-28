#!/usr/bin/env python3
"""`start_server.sh` installing NetExec, and what it does on aarch64.

The shipped image learned this the hard way and `software/c2/Dockerfile`
carries the measurement: `aardwolf` is a hard dependency of NetExec
(`aardwolf>=0.2.17`, not an extra) and publishes a macOS arm64 wheel, a
manylinux x86_64 wheel and a Windows wheel -- and **no Linux aarch64
one**. Re-measured for this change in a native aarch64 container:

    pip download --no-deps --only-binary :all: aardwolf==0.2.17
    ERROR: No matching distribution found for aardwolf==0.2.17

So on an aarch64 Linux host, pip falls back to the sdist, which builds two
PyO3 extensions through setuptools-rust. The image solves it with a build
stage that ships only the wheel. The launcher has no stage: it runs on the
operator's own host and has no business installing a Rust toolchain there.

What it can do, and is held to here:

  * use an interpreter NetExec accepts -- it requires >= 3.11, and the
    interpreter `pipx` picks by default is whatever `#!/usr/bin/python3`
    is, which on a Debian 12 host is 3.11 and on an older one is not. The
    image's own defect was this exact one in reverse: pipx built the venv
    with Debian's 3.11 while the wheel was cp312, and the `|| echo`
    swallowed it;
  * stop hiding the reason. `2>/dev/null` on the install meant every
    failure read `install failed (skipped)`, which is the same line for a
    network hiccup, a missing compiler and an unsupported interpreter;
  * say what is actually wrong when the architecture has no wheel, and
    name the two things that work: a Rust toolchain, or the shipped image
    that already carries the built wheel;
  * keep the `||`. One tool that will not install must not stop the team
    server from starting -- the same bargain the Dockerfile's install
    makes, for the same reason.
"""

import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

LAUNCHER = REPO_ROOT / "software" / "c2" / "start_server.sh"


def _netexec_block(text):
    """The launcher's NetExec section, by its own heading."""
    start = text.index("# ── NetExec")
    end = text.index("\n# ──", start + 10)
    return text[start:end]


def _code(block):
    """The section's commands, with its prose dropped and lines joined.

    This section argues at length about what it does *not* do -- no
    toolchain installed, no error hidden -- and it quotes the very
    `pip download --only-binary` command it runs. A check that read the
    whole text would pass on the comment while the command was gone:
    three of four mutations survived the first version of these tests for
    exactly that reason, and `_directive_lines` in `test_docs.py` carries
    the same lesson about unit files. Continuations are joined too,
    because the `pipx install` runs across two lines and a per-line check
    sees neither half whole.
    """
    out, pending = [], ""
    for raw in block.splitlines():
        line = raw.split("#", 1)[0].rstrip() if not raw.lstrip().startswith("#") \
            else ""
        if not line.strip():
            continue
        line = pending + line.strip()
        if line.endswith("\\"):
            pending = line[:-1].rstrip() + " "
            continue
        pending = ""
        out.append(line)
    if pending:
        out.append(pending)
    return out


class TestTheLauncherIsAValidScript(unittest.TestCase):
    def test_it_parses(self):
        # `bash -n` rather than running it: the script starts a server.
        done = subprocess.run(["bash", "-n", str(LAUNCHER)],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)


class TestTheNetExecInstall(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = LAUNCHER.read_text()
        cls.block = _netexec_block(cls.text)
        cls.code = _code(cls.block)
        cls.install = [line for line in cls.code if "pipx install" in line]

    def test_the_install_names_the_interpreter_it_wants(self):
        self.assertTrue(self.install, "nothing installs NetExec at all")
        for line in self.install:
            self.assertIn(
                "--python", line,
                "the NetExec install does not pass --python, so pipx builds "
                "its venv with whatever /usr/bin/python3 happens to be -- "
                "the image's own measured defect")

    def test_the_interpreter_floor_is_netexecs_own(self):
        # NetExec's pyproject says requires-python = ">=3.11,<4.0". An
        # interpreter this script picked below that fails at the resolve
        # with a message about Python and nothing about Rust, which sends
        # the reader after the wrong thing.
        #
        # Every version named in the *code* is checked, not just that
        # "3.11" appears somewhere: the first version of this test passed
        # with the candidate list cut down to python3.9, because the
        # `(3, 11)` in the fallback was still there.
        found = []
        for line in self.code:
            found.extend(re.findall(r"python3\.(\d+)", line))
        self.assertTrue(found, "the code names no interpreter at all")
        for minor in found:
            self.assertGreaterEqual(
                int(minor), 11,
                "the code offers python3.%s to pipx, and NetExec requires "
                ">= 3.11" % minor)
        tuples = [m for line in self.code
                  for m in re.findall(r"\(3,\s*(\d+)\)", line)]
        for minor in tuples:
            self.assertGreaterEqual(int(minor), 11, minor)

    def test_the_failure_is_not_hidden(self):
        for line in self.install:
            self.assertNotIn(
                "2>/dev/null", line,
                "the install still sends its error to /dev/null, so every "
                "failure reads the same")
            self.assertNotIn("&>/dev/null", line)

    def test_the_block_survives_a_failed_install(self):
        # The Dockerfile's bargain, and for the same reason: one tool that
        # will not install must not stop the team server from starting.
        # Checked on the install line itself -- a `||` anywhere in the
        # section is not the one that matters, and the first version of
        # this test passed with the install's own `||` removed.
        for line in self.install:
            self.assertIn("||", line,
                          "the install no longer tolerates failure, so a "
                          "network hiccup would stop the launcher")
        self.assertNotIn("set -e\n", self.block)

    def test_the_architecture_without_a_wheel_is_named_with_its_reason(self):
        for needle in ("aarch64", "aardwolf"):
            self.assertIn(needle, self.block,
                          "the block does not mention %s, so an operator on "
                          "that architecture is told only that the install "
                          "failed" % needle)

    def test_both_working_remedies_are_named(self):
        flat = " ".join(self.block.split())
        self.assertRegex(flat, r"(?i)rust",
                         "the block does not name a Rust toolchain, which "
                         "is one of the two things that make this work")
        self.assertRegex(flat, r"(?i)docker",
                         "the block does not name the shipped image, which "
                         "already carries the built wheel")

    def test_a_present_nxc_is_left_alone(self):
        self.assertRegex(self.block, r"command -v nxc",
                         "the block reinstalls NetExec even when it is "
                         "already there")

    def test_the_wheel_question_is_asked_before_the_install_is_attempted(self):
        # Asking pip whether a wheel fits costs one index lookup; finding
        # out by watching a source build fail costs minutes, and on a host
        # with a toolchain it is not even the right answer.
        probes = [n for n, line in enumerate(self.code)
                  if "--only-binary" in line]
        installs = [n for n, line in enumerate(self.code)
                    if "pipx install" in line]
        self.assertTrue(probes,
                        "nothing asks whether a published wheel fits this "
                        "interpreter and architecture (the comment that "
                        "quotes the command is not the command)")
        self.assertTrue(installs)
        self.assertLess(min(probes), min(installs),
                        "the wheel probe runs after the install attempt")

    def test_a_toolchain_is_not_installed_by_the_launcher(self):
        # The line this project does not cross: the image builds its wheel
        # in a stage that is thrown away, and the launcher runs on the
        # operator's own host.
        for forbidden in ("sh.rustup.rs", "rustup-init", "apt-get install -y rustc",
                          "apt install -y rustc"):
            self.assertNotIn(forbidden, self.text,
                             "the launcher installs a Rust toolchain on the "
                             "operator's host")


class TestTheImplantProvisioningIsHonestAboutNxc(unittest.TestCase):
    """Neither provisioning path claims NetExec, and one of them says why.

    The implant cannot have `nxc` on the terms this repository keeps: the
    install needs a Rust compiler on the device (no aarch64 wheel exists)
    or a grown `software/requirements.txt` (NetExec pulls 27 runtime
    dependencies, including `impacket` and `pynfsclient` from git). Both
    are refused elsewhere in this repository by decisions it has already
    made, so the honest state is that the implant does not carry it -- and
    the thing a test can hold is that nothing pretends otherwise.
    """

    PATHS = ("software/setup/bootstrap.sh", "software/setup/build_image.sh")

    def test_neither_provisioning_path_installs_netexec(self):
        for name in self.PATHS:
            text = (REPO_ROOT / name).read_text()
            with self.subTest(path=name):
                for needle in ("pipx install", "netexec", "NetExec"):
                    self.assertNotIn(
                        needle, text,
                        "%s installs NetExec; on aarch64 that needs a Rust "
                        "compiler on the device" % name)

    def test_the_implant_requirements_do_not_grow_netexec(self):
        text = (REPO_ROOT / "software" / "requirements.txt").read_text()
        for line in text.splitlines():
            name = line.split("#", 1)[0].strip()
            with self.subTest(line=line):
                self.assertNotIn(name.lower()[:7], ("netexec", "aardwol"))
        self.assertEqual(
            len([ln for ln in text.splitlines()
                 if ln.split("#", 1)[0].strip()]), 9,
            "software/requirements.txt changed size; it is the implant's "
            "whole dependency surface and the one file that must not grow")


if __name__ == "__main__":
    unittest.main()
