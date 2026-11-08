#!/usr/bin/env python3
"""Apply one-line mutations to a file and report which tests notice.

A substitute for review, not an equal of it. The rules it enforces are
the ones this project learned the hard way:

  * The baseline is checked **before** and **after**. A run that leaves
    the file mutated poisons every measurement that follows it, and
    comparing the file against an `orig` that was already mutated reports
    "unchanged" while being wrong. That happened: a run killed by a
    timeout left a `+ 1` in a length field, and the eleven "caught"
    mutations that followed were all measuring a listener that could not
    answer at all.
  * The original is written to a sidecar before anything is touched, and
    restored from it on the way out -- including on SIGTERM and SIGINT,
    which is how a harness gets killed in practice.
  * A pattern that does not match is reported, not skipped quietly. It
    usually means the file already differs from what the author thought.

    python3 tools/mutation_check.py software/c2/listeners/smb.py \\
        software.tests.test_listeners.TestTheSmbListener mutations.json
"""

import json
import pathlib
import signal
import subprocess
import sys


def run(target: pathlib.Path, tests: str, mutations, timeout=600):
    sidecar = target.with_suffix(target.suffix + ".mutation-backup")
    original = target.read_text()
    sidecar.write_text(original)

    def restore(*_args):
        target.write_text(original)
        sidecar.unlink(missing_ok=True)

    def bail(signum, _frame):
        restore()
        print("  restored after signal %d" % signum, flush=True)
        sys.exit(1)

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, bail)

    try:
        if _failed(tests, timeout):
            print("  BASELINE IS NOT GREEN -- nothing measured", flush=True)
            return 1
        print("  baseline green", flush=True)

        caught = survived = missing = 0
        for name, find, replace in mutations:
            if find not in original:
                print("  %-44s PATTERN NOT FOUND" % name, flush=True)
                missing += 1
                continue
            target.write_text(original.replace(find, replace, 1))
            try:
                verdict = "caught" if _failed(tests, timeout) else "SURVIVED"
            finally:
                target.write_text(original)
            caught += verdict == "caught"
            survived += verdict == "SURVIVED"
            print("  %-44s %s" % (name, verdict), flush=True)

        if _failed(tests, timeout):
            print("  BASELINE BROKE DURING THE RUN -- results are void",
                  flush=True)
            return 1
        print("  baseline still green", flush=True)
        print("  %d caught, %d survived, %d patterns missing"
              % (caught, survived, missing), flush=True)
        return 0
    finally:
        restore()


def _failed(tests: str, timeout: int) -> bool:
    """True if the test selection fails. A hang counts as failure."""
    try:
        done = subprocess.run([sys.executable, "-m", "unittest", tests],
                              capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return True
    return done.returncode != 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 3:
        print(__doc__)
        return 2
    target, tests, spec = argv
    mutations = json.loads(pathlib.Path(spec).read_text())
    return run(pathlib.Path(target), tests,
               [(m["name"], m["find"], m["replace"]) for m in mutations])


if __name__ == "__main__":
    sys.exit(main())
