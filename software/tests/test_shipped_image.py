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


def _stages(path):
    """The Dockerfile split at each FROM, as (stage name, its instructions).

    Comments are already gone, so a stage's body is what Docker runs in it
    and nothing else. The name is whatever follows `AS`, or "" when a stage
    is unnamed -- the last stage is the shipped one either way.

    Backslash continuations are joined, so one instruction is one line.
    Without that, a test asking whether the NetExec install carries a flag
    had to hope the flag and the word "NetExec" landed on the same
    physical line -- and when the install grew a second line, the `||`
    test went on passing only because the word also appears in the echo
    message beside it. A line-based question about a multi-line
    instruction answers by accident.

    Two limits worth knowing, neither of which this Dockerfile reaches: a
    `#` inside a `RUN <<EOF` heredoc is stripped as if it were a Dockerfile
    comment, and `foo\` with no space before the backslash glues to the
    next word rather than keeping them apart.
    """
    stages = []
    for line in _logical_lines(_instructions(path)):
        head = re.match(r"^FROM\s+\S+(?:\s+AS\s+(\S+))?", line, re.I)
        if head:
            stages.append([head.group(1) or "", []])
        elif stages:
            stages[-1][1].append(line)
    return [(name, "\n".join(body)) for name, body in stages]


def _logical_lines(text):
    """One entry per instruction, with `\\`-continuations joined."""
    lines = []
    pending = ""
    for line in text.splitlines():
        pending += line
        if pending.rstrip().endswith("\\"):
            pending = pending.rstrip()[:-1]
            continue
        lines.append(pending)
        pending = ""
    if pending:
        lines.append(pending)
    return lines


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
        # The NetExec install ends in `|| echo`, and the reason has
        # changed since this test was written. It used to mean "aardwolf
        # needs Rust and this image will not carry it"; the wheels stage
        # settled that (see NetExecIsBuiltForThisArchitectureNotHopedFor).
        # It now guards the ordinary ways one install fails -- a network
        # hiccup, an upstream yank, a crate that stops building -- which
        # must not cost every architecture its image. The absence is no
        # longer allowed to pass unnoticed: a workflow asserts the tool
        # resolves (see CiBuildsAndStartsTheImage).
        netexec = [line for line in _logical_lines(_instructions(DOCKERFILE))
                   if "NetExec" in line]
        self.assertTrue(netexec, "the NetExec install vanished entirely")
        self.assertTrue(
            any("||" in line for line in netexec),
            "a tool that cannot build on one architecture must not fail "
            "the image for every architecture")


class NetExecIsBuiltForThisArchitectureNotHopedFor(unittest.TestCase):
    """That `nxc` is in the shipped image on arm64 too, and Rust is not.

    Measured, not assumed. `aardwolf` 0.2.17 publishes a macOS arm64
    wheel, a manylinux x86_64 wheel, a Windows wheel and an sdist -- and
    no Linux aarch64 wheel. It is a hard dependency of NetExec
    (`aardwolf>=0.2.17` in its pyproject, not an extra), so it cannot be
    dropped, and its own pyproject builds two PyO3 extensions through
    setuptools-rust, so the sdist needs cargo.

    The consequence was not cosmetic. `software/agent/executor/
    server_tool.py` runs an admitted command *on the C2 host*, which is
    this container, and the agent emits `nxc smb ...`. On arm64 the image
    built green and the agent then ran into "command not found".

    So the toolchain is present where the wheel is built and absent from
    what ships -- which is what the earlier judgement ("adding Rust to a
    slim image is the wrong trade") was protecting, and it still holds.

    Every test here couples two places rather than spotting a name in
    one, because a review measured what name-spotting lets through: with
    the wheel copied to a path `PIP_FIND_LINKS` did not name, with the
    `ENV` moved after the install, with a builder stage that built no
    wheel at all, and with the builder on 3.11 under a shipped 3.12 --
    four mutations that each cost arm64 its `nxc` -- the earlier versions
    of these tests stayed green on all four.
    """

    TOOLCHAIN = r"\b(rustup|cargo|rustc|rust-all)\b"

    def setUp(self):
        self.stages = _stages(DOCKERFILE)
        self.assertTrue(len(self.stages) > 1, "no builder stage at all")
        self.shipped = self.stages[-1][1]
        self.earlier = [body for _, body in self.stages[:-1]]
        self.netexec = [line for line in _logical_lines(self.shipped)
                        if "NetExec" in line and "pipx" in line]
        self.assertTrue(self.netexec, "the NetExec install vanished entirely")

    def _wheelhouse(self):
        """The one path the three places must agree on."""
        copied = re.search(r"COPY\s+--from=\S+\s+(\S+)\s+(\S+)", self.shipped)
        self.assertIsNotNone(
            copied,
            "the shipped stage takes nothing from the builder, so whatever "
            "was compiled there was compiled for nothing")
        return copied.group(2).rstrip("/")

    def test_a_builder_stage_builds_the_wheel_pypi_does_not_publish(self):
        # The earlier version asked only whether some earlier stage
        # mentioned a toolchain. A stage that installed rustup and built
        # nothing passed it, which is a stage that costs build time and
        # changes nothing.
        house = self._wheelhouse()
        builds = [line for body in self.earlier
                  for line in _logical_lines(body)
                  if "pip wheel" in line and "aardwolf" in line]
        self.assertTrue(
            builds,
            "no earlier stage runs `pip wheel` for aardwolf, so there is "
            "no wheel for the architecture PyPI publishes none for")
        self.assertTrue(
            any(house in line for line in builds),
            "the wheel is built somewhere other than %s, the path the "
            "shipped stage copies -- so the copy brings nothing" % house)
        self.assertTrue(
            any(re.search(self.TOOLCHAIN, body) for body in self.earlier),
            "nothing in the builder can compile Rust, and aardwolf's two "
            "PyO3 extensions cannot be built without it")

    def test_the_shipped_stage_carries_no_rust_toolchain(self):
        found = re.search(self.TOOLCHAIN, self.shipped)
        self.assertIsNone(
            found,
            "the shipped stage installs %s: a compiler toolchain in the "
            "image an operator runs is the trade this file already "
            "refused" % (found.group(0) if found else ""))
        # A review got cargo into the image past the check above with
        # `COPY --from=wheels /usr/local/ /usr/local/`, which names no
        # toolchain at all. So what may cross the stage boundary is the
        # wheelhouse, and nothing else.
        house = self._wheelhouse()
        crossing = re.findall(r"COPY\s+--from=\S+\s+(\S+)\s+(\S+)",
                              self.shipped)
        self.assertEqual(
            [dest.rstrip("/") for _, dest in crossing], [house],
            "more than the wheelhouse is copied out of the builder, and "
            "the builder is where the Rust toolchain lives")

    def test_the_netexec_install_can_see_the_built_wheel(self):
        house = self._wheelhouse()
        find_links = re.search(r"ENV\s+PIP_FIND_LINKS=(\S+)", self.shipped)
        self.assertIsNotNone(
            find_links,
            "nothing points pip at the wheelhouse, so it resolves aardwolf "
            "from PyPI again and needs the toolchain it has not got")
        self.assertEqual(
            find_links.group(1).rstrip("/"), house,
            "pip is pointed at a different directory than the wheel was "
            "copied to, so the wheel is in the image and invisible")
        # Order matters and is invisible at run time: an `ENV` after the
        # install leaves the install resolving from PyPI, and the image
        # still ends up with the variable set, so nothing downstream can
        # tell.
        body = self.shipped
        self.assertLess(
            body.index(find_links.group(0)), body.index(self.netexec[0][:40]),
            "PIP_FIND_LINKS is set after the NetExec install, so the "
            "install could not see the wheel")

    def test_every_stage_names_the_same_base_image(self):
        # The wheel is tagged for the interpreter that built it (cp312
        # here), and the venv it must fit is built by the shipped stage's
        # interpreter. Those are two FROM lines, and a drift between them
        # reproduces the exact defect this file already carries a fix for
        # -- with the `||` still there to swallow it.
        bases = re.findall(r"^FROM\s+(\S+)", _instructions(DOCKERFILE), re.M)
        self.assertEqual(
            len(set(bases)), 1,
            "the stages are built on different bases (%s), so the wheel's "
            "interpreter tag and the venv's interpreter can differ"
            % ", ".join(sorted(set(bases))))

    def test_the_netexec_venv_uses_the_interpreter_the_wheel_was_built_for(self):
        # This one cost a full build to find, and the wheelhouse alone did
        # not fix it. pipx comes from apt, so it runs under
        # `#!/usr/bin/python3`, and in this image that is Debian's 3.11.2
        # while `python3` is the image's own 3.12.16. pipx therefore built
        # the NetExec venv with 3.11, the cp312 wheel did not match it,
        # pip fell back to the sdist and died with "can't find Rust
        # compiler" -- and the `||` swallowed that, so the image shipped
        # green with no nxc in it, exactly as before the stage existed.
        #
        # Upstream's own wheels are cp311-abi3 and so fit both, which is
        # why this never bit the architecture PyPI serves.
        self.assertTrue(
            any("--python" in line for line in self.netexec),
            "the NetExec venv is built with whatever interpreter pipx "
            "defaults to, which is apt's and not the one the wheel in "
            "the wheelhouse was built for")

    def test_the_wheel_build_cannot_fail_the_whole_image(self):
        # The first version of this stage had no tolerance anywhere, so a
        # `sh.rustup.rs` outage, a PyPI hiccup or a crate that stopped
        # building failed the image on *every* architecture -- including
        # the one that never needed the stage. That is the inverse of what
        # TheBuildHasWhatItCompilesWith asks for, and the `||` on the
        # NetExec install could not reach any of it, because the build
        # died a stage earlier.
        building = [line for body in self.earlier
                    for line in _logical_lines(body)
                    if "pip wheel" in line]
        self.assertTrue(building, "no stage builds a wheel")
        self.assertTrue(
            all(re.search(r"\|\||^RUN\s+set\s|if\s", line)
                for line in building),
            "the wheel build is not tolerated, so one upstream outage "
            "costs every architecture its image")



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


class TheReadmeDescribesTheImageThatExists(unittest.TestCase):
    def test_the_readme_does_not_say_an_architecture_ships_without_nxc(self):
        # The README's Docker section said "on arm64 the install is
        # skipped and the image builds without it" and stayed saying it
        # after that stopped being true. By this file's own standard that
        # is a stale comment, in the most-read file in the repository, and
        # nothing read it -- so this does.
        readme = _text(REPO / "README.md")
        for claim in ("the install is skipped",
                      "NetExec on\nthe architectures PyPI serves it for",
                      "NetExec is the one tool that\nmay be missing"):
            self.assertNotIn(
                claim, readme,
                "the README still describes the image that existed before "
                "the wheels stage: %r" % claim)


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
        # Instructions, not comments. A review deleted the asserting step
        # outright and the nxc test below stayed green, because the word
        # it looked for also appears in the comment above the step. This
        # file has been bitten by that shape before -- test_docs.py says
        # `_nothing_is_pinned` "was defeated once by a continuation
        # backslash and reported an open finding as fixed".
        self.ci = "\n".join(_instructions(path) for path in self.files)
        self.commented = "\n".join(_text(path) for path in self.files)

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

    def test_the_build_job_proves_netexec_resolves(self):
        # The image's own NetExec install keeps its `||` so that one
        # unbuildable tool cannot cost every architecture its image. That
        # same resilience is a way to ship a quietly incomplete image:
        # the build goes green, and the agent later runs `nxc` on the C2
        # host and gets "command not found". So a job asserts it.
        #
        # Not on nxc's exit status. Measured in the built image: `nxc
        # --version` prints the version and then exits 1, because
        # upstream's cli.py calls sys.exit(1) there. A `run:` step is
        # bash -e, so gating on the status would have failed the job on
        # every run, including a perfect one -- and the first person to
        # see that would have appended `|| true` and reopened the hole.
        # docker-entrypoint.sh already knew this about relayking.
        self.assertTrue(
            re.search(r"command -v nxc", self.ci),
            "no workflow checks that NetExec resolves inside the built "
            "image, so the install's own `||` can hide its absence")

    def test_the_netexec_check_also_proves_the_library_is_there(self):
        # `nxc --version` passes without aardwolf: measured by moving the
        # package aside inside the venv, after which the version still
        # printed and `nxc rdp --help` still exited 0. aardwolf is the
        # whole reason the wheels stage exists, so a check that cannot
        # see it is not checking this change.
        self.assertTrue(
            re.search(r"import aardwolf", self.ci),
            "the check cannot tell a complete NetExec from one whose RDP "
            "library is missing, which is the thing the wheels stage is "
            "for")

    def test_the_image_is_built_on_the_architecture_that_was_broken(self):
        # The whole defect was arm64-only: on x86_64 aardwolf has a
        # published wheel, so the wheels stage compiles nothing there. A
        # single ubuntu-latest job therefore proves the fix on the one
        # architecture that never needed it, and would stay green with
        # the wheels stage deleted. `ubuntu-24.04-arm` is a standard
        # GitHub-hosted runner, free and unlimited on public repositories.
        self.assertTrue(
            re.search(r"ubuntu-\d+\.\d+-arm", self.ci),
            "nothing builds this image on arm64, so nothing ever builds "
            "the Rust wheel the change exists to build")
        self.assertNotIn(
            "ubuntu-24.04-arm", _text(REPO / ".github" / "workflows" /
                                      "shipped-image.yml").split("jobs:")[0],
            "the arm runner is named before any job, which cannot run "
            "anything")


if __name__ == "__main__":
    unittest.main()
