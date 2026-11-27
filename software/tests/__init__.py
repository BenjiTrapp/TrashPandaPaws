#!/usr/bin/env python3
"""Shared support for the suite. One helper, and it exists for one defect.

`software/tests/` is otherwise all test modules, and they share by importing
each other (`from software.tests import test_egress_decider`). This file
holds what no single module owns.
"""

import os
import tempfile

# `/tmp` and anything under it. `read_way_out_policy` refuses a
# `c2.way_out.state_dir` there, and that refusal is right: both
# `raccoon-beacon.service` and `raccoon-implant.service` set
# `PrivateTmp=true`, so each process would get its own private `/tmp` and
# the beacon and the scout would never see each other's files.
_TMP = ("/tmp",)


def _is_under_tmp(path: str) -> bool:
    return path == "/tmp" or path.startswith("/tmp/")


def way_out_scratch(prefix: str) -> str:
    """A directory the way-out reader will accept, on Linux too.

    The default temp directory **is** `/tmp` on Linux and is not on macOS,
    where it is under `/var/folders`. So five test modules that minted their
    state directory with a plain `tempfile.mkdtemp()` passed on the machine
    they were written on and failed on every Linux runner: measured, 71
    failures and 24 errors in CI, and the same 71 and 24 reproduced here by
    setting `TMPDIR=/tmp`. Every one of them was `read_way_out_policy`
    refusing the path and the fixture raising, not a product defect -- the
    rule doing its job against the one scratch directory the tests could not
    use.

    `tools/way_out_bench.py` met this first and solved it for itself, in its
    own `_scratch()`; the two stay separate because a tool that imports the
    test package is the wrong dependency, and each says so. The choice here
    is the same: `/var/tmp` when it is writable, then the home directory.

    Raises rather than falling back to `/tmp`, because a fixture that quietly
    hands over a refused path is how this was missed in the first place.
    """
    default = tempfile.gettempdir()
    if not _is_under_tmp(default):
        return tempfile.mkdtemp(prefix=prefix)
    for candidate in ("/var/tmp", os.path.expanduser("~")):
        if os.path.isdir(candidate) and os.access(candidate, os.W_OK):
            return tempfile.mkdtemp(prefix=prefix, dir=candidate)
    raise RuntimeError(
        "every writable scratch directory here is under /tmp, which the "
        "way-out reader refuses, so these tests would measure a disabled "
        "feature: give the runner a writable /var/tmp or home directory")
