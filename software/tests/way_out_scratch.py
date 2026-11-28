#!/usr/bin/env python3
"""One scratch directory that the way out's own config reader accepts.

Not a test module -- `unittest discover`'s pattern is `test*.py`, so this
name keeps it out of the collection and in the import graph.

**Why it has to exist.** `read_way_out_policy` refuses a `state_dir`
under `/tmp` by name, with its reason: both `raccoon-beacon.service` and
`raccoon-implant.service` set `PrivateTmp=true`, so each process would
get its own private `/tmp` and the beacon and the scout would never see
each other's files. The handoff would silently never happen.

`tempfile.gettempdir()` **is** `/tmp` on Linux. So every test that built
its state directory with a bare `mkdtemp` ran the whole feature
*disabled* on Linux -- and a disabled way out has no arithmetic, no
handoff and no state file, so the assertions that were left were about
the ungated path. 77 of them failed in CI and the rest passed for the
wrong reason, on the one platform the implant ships on.

This is the second time that rule has caught a harness rather than a
bug: `tools/way_out_bench.py` measured a disabled feature on its first
container run and reported the ungated numbers as if they were results.
The bench's `_scratch` is the same function as this one, and the design's
`## Measurements` records that finding. This file is the test suite
finally learning it.

The other half of the lesson is `assert_live` below: a helper that hands
back a beacon or a scout **asserts that the feature is on**, so a
harness that disables it again fails loudly instead of quietly checking
nothing.
"""

import os
import tempfile


def scratch(case, prefix="raccoon-way-out-"):
    """A state directory the reader accepts, removed when `case` ends.

    `/var/tmp` when the default is under `/tmp`, because it is writable
    on every Linux this runs on and is not private per unit; the home
    directory after that; and the platform default when it is already
    acceptable, which is `/var/folders/...` on macOS.
    """
    import shutil

    directory = _scratch_dir(prefix)
    case.addCleanup(shutil.rmtree, directory, ignore_errors=True)
    return directory


def _scratch_dir(prefix):
    default = tempfile.gettempdir()
    if default == "/tmp" or default.startswith("/tmp/"):
        for candidate in ("/var/tmp", os.path.expanduser("~")):
            if os.path.isdir(candidate) and os.access(candidate, os.W_OK):
                return tempfile.mkdtemp(prefix=prefix, dir=candidate)
        raise AssertionError(
            "every writable scratch directory here is under /tmp, which the "
            "way-out reader refuses by name -- so these tests would run the "
            "feature disabled and assert nothing. Point TMPDIR somewhere "
            "else.")
    return tempfile.mkdtemp(prefix=prefix)


def assert_live(case, beacon):
    """Fail now if this beacon's way out is off. Returns the beacon.

    Called by every helper that hands back a beacon with `c2.way_out`
    enabled. The reader refuses a policy for several reasons and says so
    in a log line nobody reads in a test, so without this the refusal
    arrives as a surprising assertion thirty lines later -- or, worse, as
    a test that passes.
    """
    case.assertTrue(
        beacon._way_out_state_dir,
        "this beacon's way out is off, so the test below is not testing it: "
        "`read_way_out_policy` refused the block it was given (a state_dir "
        "under /tmp is the usual reason -- see this module's docstring)")
    return beacon
