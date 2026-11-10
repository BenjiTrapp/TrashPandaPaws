#!/usr/bin/env python3
"""A package named in more than one requirements file carries one specifier.

The four files are separate on purpose (the C2's must not grow), so a few
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

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

FILES = (
    "software/requirements.txt",
    "software/agent/requirements.txt",
    "tools/requirements.txt",
    "software/tests/requirements.txt",
)

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
