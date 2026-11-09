#!/usr/bin/env python3
"""
Make tool output machine-independent: rewrite the absolute path of this
repository to the repository-relative form, in place.

The kicad-happy analyzers (vendor/kicad-happy, not ours to edit) record the
absolute path of the file they were given in `inputs.source_files` and as the
keys of `inputs.source_hashes`, however the path was spelled on the command
line. Committed, that puts the operator's home directory in the repository and
makes the same board analysed on two machines yield two different files.
check_netlist.py echoes its argument the same way. Run this over every such
output before it is committed; hardware/tools/run_kicad_happy.sh does.

Only the repository-root prefix is removed (`<root>/hardware/kicad/x` becomes
`hardware/kicad/x`): no number, finding or hash is touched. The script exits 1
if, after rewriting, a file still contains an absolute home-directory path
(a macOS, Linux or Windows user directory), because that is a path to somewhere
other than this repository and has to be looked at, not guessed at. The one
exemption (FIXTURE_HOME_NAMES) applies to files under software/tests/ only.

Usage: relativize_paths.py [--check] FILE...
  --check   change nothing; exit 1 if a file would change or still has a leak
"""

import argparse
import posixpath
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

_NAME = r"[A-Za-z0-9_][^/\\\s\"']*"
_MAC = "/" + "Users"      # split so that this file does not itself match a grep for the prefix

HOME_PATH = re.compile(rf"{_MAC}/{_NAME}|/home/{_NAME}|[A-Za-z]:\\+Users\\+{_NAME}")

# The one exemption (ruling CL). A path is a leak when it names a person or a machine
# (a username in the repository, and a different file on every machine). Two strings in
# the test fixtures of software/tests/ look like home directories and are not paths
# anyone inhabits; they are text inside a string that describes a command:
#   home/{u}  "shell tee -a <that>/.ssh/authorized_keys" and similar (test_agent_safety.py):
#             command strings that the agent's safety layer is tested to classify, with a
#             one-letter placeholder for the user.
#   home/{pi} 'chown -R "$ACTUAL_USER" <that>/.ssh' (test_c2_hardening.py): installer text
#             used as the negative case "a chown of something else", fed to a parser.
# (Written with braces and without the leading slash so that this file does not match its
# own scan; under /home/ they are the names pi and u.)
# That, and nothing about the platform, is the whole basis for both. In particular
# the name pi is NOT exempt for being a standard Raspberry Pi account. Raspberry Pi OS stopped
# having a default "pi" user in April 2022: "the default 'pi' user is being removed, and
# instead you will create a user the first time you boot a newly-flashed Raspberry Pi OS
# image" (https://www.raspberrypi.com/news/raspberry-pi-bullseye-update-april-2022/,
# fetched 2026-11-09), so on a current install the home directory may carry the operator's
# own name. And this repository's software does not assume "pi" either:
# software/setup/bootstrap.sh takes the account from ACTUAL_USER="${SUDO_USER:-$USER}".
# So the same strings anywhere else (hardware/fab/, a README, a committed analyzer output)
# stay leaks, and so does every other name under software/tests/.
# Residual risk, accepted: an operator who really is named "pi" or "u" and whose path is
# committed into software/tests/ would not be caught. Names are exempt only as whole path
# segments (pierre, pi2 and ubuntu are leaks) and only under /home/;
# /Users/ and the Windows form are never exempt. Adding a name needs an argument here
# and a change to the test that pins the list.
FIXTURE_DIR = "software/tests/"
FIXTURE_HOME_NAMES = ("pi", "u")


def in_fixture_dir(repo_path):
    """True if `repo_path`, a path relative to the repository root, is under
    software/tests/ once `..` and `.` are resolved."""
    return posixpath.normpath(Path(repo_path).as_posix()).startswith(FIXTURE_DIR)


def prefixes():
    """The spellings of the repository root a tool may have recorded: with and
    without symlinks resolved (/var -> /private/var on macOS)."""
    found = {str(ROOT), str(ROOT.resolve())}
    return sorted(found, key=len, reverse=True)


def relativize(text):
    for prefix in prefixes():
        text = text.replace(prefix + "/", "")
    return text


def leaks(text, repo_path=None):
    """The home-directory paths in `text`. `repo_path` is where the text lives,
    relative to the repository root; for a file under software/tests/ the fixture
    exemption applies (see FIXTURE_HOME_NAMES), anywhere else, or with no path, it
    does not."""
    found = set(HOME_PATH.findall(text))
    if repo_path is not None and in_fixture_dir(repo_path):
        found -= {"/home/" + name for name in FIXTURE_HOME_NAMES}
    return sorted(found)


def repo_relative(path):
    """`path` relative to the repository root, or None if it is outside it."""
    try:
        return Path(path).resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("files", nargs="+")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    status = 0
    for name in args.files:
        path = Path(name)
        original = path.read_bytes().decode("utf-8")
        text = relativize(original)
        if text != original:
            if args.check:
                print(f"{path}: contains the absolute repository path")
                status = 1
            else:
                path.write_bytes(text.encode("utf-8"))
                print(f"{path}: made repository-relative")
        left = leaks(text, repo_relative(path))
        if left:
            print(f"{path}: still contains absolute home paths: {', '.join(left)}")
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
