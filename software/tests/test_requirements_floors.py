#!/usr/bin/env python3
"""A package named in more than one requirements file carries one specifier.

The files are separate on purpose (the C2's must not grow), so a few
packages are listed in more than one so that each file stands alone:
aiohttp in the agent's and the tools', cryptography and scapy in the C2's
and the tests'. The comments in those files say the copies agree. This is
what makes that a fact instead of a sentence: it parses every file and
fails when one package is declared with two different specifiers, or with a
floor in one file and none in another.

It compares what the files *declare*, not what any of them was tested at.
Nothing here says a floor works; only that the files do not contradict each
other, which is the one thing that can be checked without installing every
floor.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# The files compared, named by hand on purpose: a list is readable, and a new
# requirements file deserves a deliberate decision about whether its floors
# are shared. What stops that decision being skipped is
# TestTheListIsComplete below, which discovers the files and fails on any this
# list neither names nor excuses.
FILES = (
    "software/requirements.txt",
    "software/agent/requirements.txt",
    "tools/requirements.txt",
    "software/tests/requirements.txt",
)

# A tracked requirements file that is deliberately not compared, with the
# reason. Empty today. It exists so "this one's floors are not shared" is a
# written decision with a reason and not an omission nobody can tell from a
# forgotten file.
NOT_COMPARED = {}

# Third-party material is not ours to keep in step: its specifiers are the
# upstream's, and a subtree update replaces them wholesale, so a vendored
# file disagreeing with ours is not drift in this repository. Other
# repo-wide checks here exclude vendor/ for the same reason. None is
# tracked today (the only .txt under vendor/ is llms.txt), so this guards
# the day one arrives.
_EXCLUDED_PREFIXES = ("vendor/",)

# A requirements file by name: requirements.txt, requirements-dev.txt,
# dev-requirements.in, constraints.txt. Not by content, so a file that
# merely mentions the word is not swept in.
_REQUIREMENTS_NAME = re.compile(
    r"(^|/)([^/]*requirements[^/]*\.(txt|in)|constraints[^/]*\.txt)$")

# Only for a tree that is not a git checkout (an exported copy). The walk
# must then skip what git would have ignored; this is the short list that
# matters, and it is the fallback, not the source of truth.
_WALK_SKIP_DIRS = frozenset({".git", ".venv", "venv", "node_modules",
                             "__pycache__", ".worktrees", "site-packages"})

_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?P<spec>[^;]*)")


def declared(text):
    """{normalised package name: specifier} for one requirements file.

    Comments, blank lines and `-r` includes are skipped: an include is the
    same declaration seen twice, not a second one.
    """
    found = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQUIREMENT.match(line)
        if m is None:
            continue
        name = re.sub(r"[-_.]+", "-", m.group("name")).lower()
        found[name] = re.sub(r"\s+", "", m.group("spec"))
    return found


def disagreements(files):
    """{package: {specifier: [files]}} for every package whose files differ.

    `files` maps a file name to its text. A package declared in only one file
    can never appear here.
    """
    by_package = {}
    for filename, text in files.items():
        for name, spec in declared(text).items():
            by_package.setdefault(name, {}).setdefault(spec, []).append(filename)
    return {name: specs for name, specs in by_package.items()
            if len(specs) > 1}


def _tracked(root):
    """Paths `git ls-files` reports under root, or None outside a checkout."""
    try:
        listed = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                                capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if listed.returncode != 0:
        return None
    return [n for n in listed.stdout.decode("utf-8", "replace").split("\0")
            if n] or None


def _walked(root):
    names = []
    for dirpath, dirnames, filenames in os.walk(str(root)):
        dirnames[:] = [d for d in dirnames if d not in _WALK_SKIP_DIRS]
        for filename in filenames:
            full = os.path.join(dirpath, filename)
            names.append(os.path.relpath(full, str(root)).replace(os.sep, "/"))
    return names


def requirements_files(root=REPO):
    """Every requirements file the repository ships, relative to root.

    From `git ls-files`, so only tracked files count: the virtual
    environments (software/.venv and software/c2/.venv hold hundreds of
    vendored packages' files), a scratch copy, and the sibling checkouts
    under .worktrees/ -- each of which carries its own copy of these files --
    are not seen, because git does not list another worktree's files from this
    one and .gitignore names the rest. A walk would have to guess all of that.

    The cost of "tracked only": a new file is invisible until `git add`, so
    the completeness check fires when it is staged, not when it is created. It
    cannot slip past a commit, which is where it has to be caught.
    """
    names = _tracked(root)
    if names is None:
        names = _walked(root)
    return sorted(n for n in names
                  if _REQUIREMENTS_NAME.search(n)
                  and not n.startswith(_EXCLUDED_PREFIXES))


class TestDeclaredParser(unittest.TestCase):
    """The checker has to be able to see a disagreement, or it proves nothing."""

    def test_parses_name_and_specifier_ignoring_comments_and_includes(self):
        text = ("# a comment\n-r ../other.txt\n\n"
                "Pillow\naiohttp >= 3.9.0  # trailing\nPyYAML>=6.0\n")
        self.assertEqual(declared(text),
                         {"pillow": "", "aiohttp": ">=3.9.0", "pyyaml": ">=6.0"})

    def test_names_are_normalised_so_case_and_underscores_do_not_hide_a_match(self):
        self.assertEqual(declared("Typing_Extensions>=4\n"),
                         {"typing-extensions": ">=4"})

    def test_two_different_floors_for_one_package_are_reported(self):
        found = disagreements({"a.txt": "aiohttp>=3.9.0\n",
                               "b.txt": "aiohttp>=3.8.0\n"})
        self.assertEqual(set(found), {"aiohttp"})
        self.assertEqual(found["aiohttp"], {">=3.9.0": ["a.txt"],
                                            ">=3.8.0": ["b.txt"]})

    def test_a_floor_in_one_file_and_none_in_another_is_reported(self):
        found = disagreements({"a.txt": "cryptography>=41.0.0\n",
                               "b.txt": "cryptography\n"})
        self.assertEqual(set(found), {"cryptography"})

    def test_agreement_and_single_declarations_are_not_reported(self):
        self.assertEqual(
            disagreements({"a.txt": "aiohttp>=3.9.0\nflask\n",
                           "b.txt": "aiohttp>=3.9.0\nPillow\n"}), {})


class TestDiscovery(unittest.TestCase):
    """requirements_files() against a tree this test owns."""

    def _git(self, root, *args):
        subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
             "-C", str(root)] + list(args),
            check=True, capture_output=True)

    def _tree(self, root):
        root = Path(root)
        for rel, text in {
            ".gitignore": ".venv/\n.worktrees/\nscratch/\n",
            "requirements.txt": "flask\n",
            "sub/requirements-dev.txt": "pytest\n",
            "sub/constraints.txt": "flask<4\n",
            "notes.txt": "mentions requirements in prose\n",
            ".venv/lib/site-packages/pkg/requirements.txt": "x\n",
            "scratch/requirements.txt": "x\n",
            "vendor/upstream/requirements.txt": "x\n",
        }.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        self._git(root, "init", "-q")
        self._git(root, "add", "-A")
        return root

    def test_finds_tracked_requirements_files_by_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(tmp)
            self.assertEqual(requirements_files(root),
                             ["requirements.txt", "sub/constraints.txt",
                              "sub/requirements-dev.txt"])

    def test_does_not_see_ignored_copies_or_vendor(self):
        # The .venv copy and the scratch copy are ignored, so git never lists
        # them; vendor/ is tracked and is excluded by name.
        with tempfile.TemporaryDirectory() as tmp:
            found = requirements_files(self._tree(tmp))
        for path in found:
            self.assertFalse(path.startswith((".venv", "scratch", "vendor")),
                             path)

    def test_does_not_see_another_worktrees_copy(self):
        # Confirmed against a real linked worktree rather than assumed: it
        # holds its own tracked copy, and the main checkout does not list it.
        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(tmp)
            self._git(root, "commit", "-q", "-m", "x")
            self._git(root, "worktree", "add", "-q", ".worktrees/w", "-b", "w")
            self.assertTrue(
                (root / ".worktrees/w/requirements.txt").is_file())
            self.assertFalse(any(p.startswith(".worktrees")
                                 for p in requirements_files(root)))

    def test_outside_a_checkout_it_walks_and_skips_environments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in ("requirements.txt", ".venv/x/requirements.txt",
                        ".worktrees/w/requirements.txt",
                        "vendor/u/requirements.txt"):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text("x\n", encoding="utf-8")
            self.assertEqual(requirements_files(root), ["requirements.txt"])


class TestTheListIsComplete(unittest.TestCase):
    """A fifth requirements file must be a decision, not a silent escape."""

    def test_every_discovered_file_is_compared_or_excused_with_a_reason(self):
        unlisted = [path for path in requirements_files()
                    if path not in FILES and path not in NOT_COMPARED]
        self.assertEqual(
            unlisted, [],
            "requirements file(s) not covered by the floor check: add each to "
            "FILES in test_requirements_floors.py if its packages' specifiers "
            "should agree with the others', or to NOT_COMPARED with the reason "
            "they should not")

    def test_the_list_names_only_files_that_are_tracked(self):
        # The other direction: a renamed or deleted file must not linger.
        tracked = set(requirements_files())
        self.assertEqual([p for p in FILES if p not in tracked], [])

    def test_an_excuse_is_not_also_in_the_list_and_has_a_reason(self):
        for path, reason in NOT_COMPARED.items():
            self.assertNotIn(path, FILES, path)
            self.assertTrue(reason.strip(), "no reason given for %s" % path)

    def test_discovery_finds_the_files_it_is_meant_to(self):
        # Without this, a discovery that returned nothing would make the
        # completeness test pass for the wrong reason.
        self.assertTrue(set(FILES) <= set(requirements_files()))


class TestTheRepositoryFiles(unittest.TestCase):
    def setUp(self):
        self.files = {name: (REPO / name).read_text() for name in FILES}

    def test_every_file_declares_something(self):
        # A parser that silently reads nothing would make the next test pass
        # for the wrong reason.
        for name, text in self.files.items():
            self.assertTrue(declared(text), "parsed no requirements from %s" % name)

    def test_a_package_in_more_than_one_file_has_one_specifier(self):
        self.assertEqual(disagreements(self.files), {})


if __name__ == "__main__":
    unittest.main()
