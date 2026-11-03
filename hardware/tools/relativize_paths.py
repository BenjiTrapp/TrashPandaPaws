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
other than this repository and has to be looked at, not guessed at.

Usage: relativize_paths.py [--check] FILE...
  --check   change nothing; exit 1 if a file would change or still has a leak
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

_NAME = r"[A-Za-z0-9_][^/\\\s\"']*"
_MAC = "/" + "Users"      # split so that this file does not itself match a grep for the prefix
HOME_PATH = re.compile(rf"{_MAC}/{_NAME}|/home/{_NAME}|[A-Za-z]:\\+Users\\+{_NAME}")


def prefixes():
    """The spellings of the repository root a tool may have recorded: with and
    without symlinks resolved (/var -> /private/var on macOS)."""
    found = {str(ROOT), str(ROOT.resolve())}
    return sorted(found, key=len, reverse=True)


def relativize(text):
    for prefix in prefixes():
        text = text.replace(prefix + "/", "")
    return text


def leaks(text):
    return sorted(set(HOME_PATH.findall(text)))


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
        left = leaks(text)
        if left:
            print(f"{path}: still contains absolute home paths: {', '.join(left)}")
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
