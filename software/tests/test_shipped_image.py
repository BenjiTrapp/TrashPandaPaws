#!/usr/bin/env python3
"""The shipped team-server image: that it can be built, and can then run.

Six defects were found in `software/c2/Dockerfile` the first time anyone
tried to build it on this project's own development machine. Four of them
broke the build on *every* architecture, and one of those four had been
hidden by a `2>/dev/null`. A fifth let the image build and then crash at
import. None of it was caught, because nothing in this repository ever
built the image.

These tests need no Docker: they read the Dockerfile, the compose file and
the entrypoint, and they assert the properties whose absence produced each
defect. The build itself is CI's job -- see .github/workflows/ci.yml --
because only a build proves a build.
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
C2 = REPO / "software" / "c2"
DOCKERFILE = C2 / "Dockerfile"
COMPOSE = C2 / "docker-compose.yml"
ENTRYPOINT = C2 / "docker-entrypoint.sh"
SERVER = C2 / "server.py"


def _text(path):
    return path.read_text()


def _instructions(path):
    """The file without its comments: what Docker actually runs."""
    return "\n".join(line for line in _text(path).splitlines()
                     if not line.lstrip().startswith("#"))


class TheBaseIsPinned(unittest.TestCase):
    def test_the_base_image_names_a_debian_release(self):
        # Measured: `python:3.12-slim` moved from Debian 12 to Debian 13,
        # where freerdp2-x11 no longer exists, and the build died at step 3
        # of 20 for everyone. An unpinned base means the image's contents
        # change under it without a commit.
        base = re.search(r"^FROM\s+(\S+)", _instructions(DOCKERFILE), re.M)
        self.assertIsNotNone(base, "no FROM line")
        self.assertRegex(
            base.group(1), r":.+-(bookworm|trixie|bullseye)\b",
            "the base image does not name a Debian release, so apt can "
            "stop carrying a package without anything here changing")


class TheBuildHasWhatItCompilesWith(unittest.TestCase):
    def test_python_headers_are_installed(self):
        # arc4, a NetExec dependency, publishes no Linux aarch64 wheel, so
        # pip compiles it from source there and needs Python.h. Measured:
        # without python3-dev the build dies on arm64 and succeeds on
        # amd64, which is why nobody saw it.
        self.assertTrue(re.search(r"\bpython3-dev\b", _instructions(DOCKERFILE)),
                        "python3-dev is not installed, so a dependency "
                        "without a wheel cannot compile")

    def test_a_tool_without_a_wheel_cannot_fail_the_whole_build(self):
        # aardwolf, NetExec's RDP library, has no aarch64 wheel either and
        # needs a Rust toolchain. Adding Rust to a slim image for one
        # optional tool is the wrong trade, so the install is allowed to
        # fail -- and the entrypoint then reports the tool as missing
        # rather than claiming it (see TheBannerDoesNotLie).
        netexec = [line for line in _instructions(DOCKERFILE).splitlines()
                   if "NetExec" in line]
        self.assertTrue(netexec, "the NetExec install vanished entirely")
        self.assertTrue(
            any("||" in line for line in netexec),
            "a tool that cannot build on one architecture must not fail "
            "the image for every architecture")


class LinksDoNotFightWhatPipInstalled(unittest.TestCase):
    def test_every_console_script_link_is_forced(self):
        # `pip install -e .` installs its own console script at the same
        # path, so a plain `ln -s` fails with "File exists" -- meaning the
        # step could only succeed when pip FAILED. The `2>/dev/null` on the
        # pip call hid which of the two had happened.
        plain = re.findall(r"&&\s*ln -s\s+(?!-)", _instructions(DOCKERFILE))
        self.assertEqual(
            plain, [],
            "a bare `ln -s` into /usr/local/bin breaks as soon as pip "
            "installs its own entry point at that path")


class TheImageCanActuallyRunTheServer(unittest.TestCase):
    def test_server_py_imports_from_the_package(self):
        # The premise of the next test. If this stops being true the next
        # one is no longer proving anything.
        self.assertTrue(re.search(r"^from software\.c2\.", _text(SERVER), re.M),
                        "server.py no longer imports from the package, so "
                        "the next test proves nothing")

    def test_the_build_context_can_see_the_package(self):
        # The image copied three flat files into /opt/raccoon-c2 while
        # server.py imports `software.c2.listeners` and
        # `software.c2.stagers`. So the server died at import with
        # ModuleNotFoundError: No module named 'software' -- the image
        # built and could not start. The listener service already builds
        # from the repository root; the team server now does too.
        import yaml

        with open(COMPOSE) as handle:
            doc = yaml.safe_load(handle)
        build = doc["services"]["raccoon-c2"]["build"]
        context = build["context"] if isinstance(build, dict) else build
        self.assertNotEqual(
            context, ".",
            "a context of software/c2 cannot COPY the software/ package, "
            "and server.py imports from it")

    def test_the_package_is_copied_into_the_image(self):
        copied = re.findall(r"^COPY\s+(\S+)", _instructions(DOCKERFILE), re.M)
        self.assertTrue(
            any(part.startswith("software/") for part in copied),
            "nothing copies the software/ package, so every `from "
            "software.c2...` import in server.py fails at start-up")


    def test_every_copy_source_exists_in_the_build_context(self):
        # Moving the context to the repository root broke `COPY
        # docker-entrypoint.sh`, which had been written against the old
        # one: the build died at step 17 of 19. A COPY path is only
        # meaningful together with the context, and nothing checked the
        # two against each other.
        missing = []
        for line in _instructions(DOCKERFILE).splitlines():
            match = re.match(r"^COPY\s+(?!--)(.+)$", line)
            if not match:
                continue
            parts = match.group(1).split()
            for source in parts[:-1]:
                if not list(REPO.glob(source.rstrip("/"))):
                    missing.append(source)
        self.assertEqual(
            missing, [],
            "these COPY sources do not exist relative to the build "
            "context (the repository root), so the build cannot reach "
            "step 19")


    def test_the_entrypoint_launches_the_package_not_a_loose_file(self):
        # Defect 7, and I made this one myself: once the image copied the
        # package instead of three flat files, the entrypoint's
        # `python3 /opt/raccoon-c2/server.py` pointed at a path that no
        # longer existed. The banner printed perfectly and then the
        # container died with "can't open file". Running it as a module is
        # also what the CI step runs, so the two cannot drift apart.
        launch = [line for line in _instructions(ENTRYPOINT).splitlines()
                  if "CMD=(" in line or line.strip().startswith("exec ")]
        self.assertTrue(launch, "the entrypoint no longer launches anything")
        self.assertTrue(
            any("-m software.c2.server" in line for line in launch),
            "the entrypoint must launch the installed package; a path to "
            "a loose server.py breaks whenever the COPY layout changes")


class TheBannerDoesNotLie(unittest.TestCase):
    def test_no_tool_is_reported_as_installed_without_being_found(self):
        # `$(nxc --version 2>/dev/null || echo 'installed')` prints
        # "installed" for a tool that is absent, under a green [✓]. It told
        # me NetExec was installed in an image I had deliberately built
        # without it. Three tools did this.
        # Instructions, not comments. The first version of this read the
        # whole file and caught the comment above the fix, which quotes the
        # broken line on purpose -- a test that forbids describing a defect
        # is a test that makes the code harder to understand.
        self.assertNotIn(
            "echo 'installed'", _instructions(ENTRYPOINT),
            "a missing tool must not be reported as installed")

    def test_no_green_tick_is_printed_beside_a_value_it_cannot_vouch_for(self):
        # The first version of this fix routed NetExec, RelayKing and
        # Responder through a helper and left Flask, Impacket and Lsassy
        # printing a literal green tick beside a version lookup that could
        # return "not installed" -- so an absent package would have read
        # "[✓] Lsassy not installed". Same defect, three lines over.
        offenders = []
        for line in _instructions(ENTRYPOINT).splitlines():
            if "[✓]" not in line or "$(" not in line:
                continue
            if "python3 --version" in line:
                continue  # the interpreter running this script, always there
            offenders.append(line.strip()[:60])
        self.assertEqual(
            offenders, [],
            "these lines print a fixed green tick next to a value looked "
            "up at run time, so they claim a tool the image may not have")

    def test_the_tool_summary_is_not_a_hardcoded_list(self):
        # The summary line read `impacket nxc lsassy relayking responder
        # nmap` as fixed text, so it claimed every tool whatever the image
        # held.
        self.assertNotIn("impacket nxc lsassy relayking responder nmap",
                         _instructions(ENTRYPOINT))


class RdpDoesNotHardcodeOneBinaryName(unittest.TestCase):
    def test_the_rdp_client_is_looked_up_not_assumed(self):
        # freerdp2 ships `xfreerdp`, freerdp3 ships `xfreerdp3`. server.py
        # hardcoded `xfreerdp`, so the next base-image move would leave the
        # RDP button failing at runtime for an operator to discover. The
        # VNC path twenty lines below already probes several names; this
        # makes RDP match it.
        text = _text(SERVER)
        i = text.index('mode == "xfreerdp"')
        block = text[i:i + 900]
        self.assertIn(
            "xfreerdp3", block,
            "only the freerdp2 binary name is known, so the image cannot "
            "move to freerdp3 without breaking RDP silently")


class CiBuildsAndStartsTheImage(unittest.TestCase):
    """Some workflow must build this image. Which file is not the point.

    These tests read every workflow rather than naming one, because the
    repository's main CI file arrives in a different branch and a test
    that hardcoded its path would turn an ordinary merge order into a
    failure.
    """

    def setUp(self):
        workflows = REPO / ".github" / "workflows"
        self.files = sorted(workflows.glob("*.yml")) + \
            sorted(workflows.glob("*.yaml"))
        self.assertTrue(self.files, "no workflows at all")
        self.ci = "\n".join(_text(path) for path in self.files)

    def test_a_job_builds_the_shipped_image(self):
        self.assertTrue(
            re.search(r"software/c2/(Dockerfile|docker-compose\.yml)",
                      self.ci),
            "no workflow builds the shipped image, which is how it came to "
            "be broken on every architecture without anyone noticing")

    def test_the_build_job_also_starts_the_server(self):
        # Defect 5 built cleanly and crashed at import. A job that only
        # builds would have reported green over an image that cannot run,
        # so the job runs the server far enough to execute its imports.
        self.assertTrue(
            re.search(r"software\.c2\.server[^\n]*--help", self.ci),
            "the image is built but never started, so an import error "
            "would pass unnoticed -- which is defect 5 exactly")


if __name__ == "__main__":
    unittest.main()
