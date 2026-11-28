#!/usr/bin/env python3
"""The harness that the rest of the way out's tests are built on.

`software/tests/way_out_scratch.py` exists because of a failure that was
invisible on the machine this feature was written on and total on the
platform it ships to. `read_way_out_policy` refuses a `state_dir` under
`/tmp` -- both implant units set `PrivateTmp=true`, so the two processes
would get separate private `/tmp`s and the handoff would silently never
happen -- and `tempfile.gettempdir()` **is** `/tmp` on Linux. So every
test that built its state directory with a bare `mkdtemp` ran the whole
feature *disabled* there: 77 assertions failed in CI and the rest passed
for the wrong reason.

It was the second time that rule caught a harness instead of a bug. The
first was `tools/way_out_bench.py`, whose first container run measured a
disabled feature and reported the ungated path's numbers as results --
recorded in the design's `## Measurements` as the measurement's own first
finding, with `test_way_out_bench.py` holding the fix. The two tests
below are deliberately the same pair as that file's, for the same reason
on the other side.

So this file asks two questions of the harness itself:

  * does a scratch directory land somewhere the **reader accepts**, even
    when the platform's temp directory is `/tmp`;
  * does a helper that hands back a beacon **notice** when the feature it
    is about is off.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.c2.beacon import read_way_out_policy
from software.tests import way_out_scratch as _scratch


class TestTheScratchDirectory(unittest.TestCase):
    def test_it_is_not_under_tmp_even_when_the_platform_says_it_should_be(self):
        # `gettempdir` is patched rather than `TMPDIR` set: `tempfile`
        # caches its answer in a module global on first use, so a test
        # that set the environment variable would be testing nothing in a
        # process that had already made one temporary file.
        with mock.patch.object(tempfile, "gettempdir", lambda: "/tmp"):
            directory = _scratch.scratch(self, "raccoon-harness-")
        self.assertFalse(directory == "/tmp"
                         or directory.startswith("/tmp/"), directory)
        self.assertTrue(os.path.isdir(directory))

    def test_it_is_somewhere_the_way_out_reader_accepts(self):
        with mock.patch.object(tempfile, "gettempdir", lambda: "/tmp"):
            directory = _scratch.scratch(self, "raccoon-harness-")
        policy = read_way_out_policy({"enabled": True,
                                      "state_dir": directory})
        self.assertTrue(policy["enabled"],
                        "the suite scratches in %r, which the way-out "
                        "reader refuses -- so every test built on it runs "
                        "the feature disabled" % directory)
        self.assertEqual(policy["state_dir"], directory)

    def test_the_platforms_own_directory_is_used_when_it_is_acceptable(self):
        # The helper must not drag every test onto `/var/tmp` on a machine
        # where there is nothing wrong with the default -- macOS, where
        # this feature was written, has `/var/folders/...`. Driven through
        # a directory this test owns rather than through the real default,
        # so it asks the same question on a platform whose default *is*
        # the refused one.
        acceptable = _scratch.scratch(self, "raccoon-harness-outer-")
        with mock.patch.object(tempfile, "gettempdir", lambda: acceptable):
            directory = _scratch.scratch(self, "raccoon-harness-")
        self.assertTrue(directory.startswith(acceptable), directory)

    def test_it_is_removed_when_the_test_ends(self):
        outer = []

        class Inner(unittest.TestCase):
            def runTest(self):
                outer.append(_scratch.scratch(self, "raccoon-harness-"))

        Inner().run(unittest.TestResult())
        self.assertEqual(len(outer), 1)
        self.assertFalse(os.path.exists(outer[0]), outer[0])


class TestAHelperNoticesADisabledFeature(unittest.TestCase):
    """`assert_live`, which is the other half of the same lesson."""

    def beacon(self, state_dir):
        import base64

        from software.c2.beacon import Beacon
        beacon = Beacon({"c2": {
            "beacon_interval_seconds": 300, "jitter_percent": 0,
            "encryption_key": base64.b64encode(b"\x24" * 32).decode(),
            "proxy": {"mode": "auto"}, "https": {"enabled": False},
            "dns": {"enabled": False}, "smb": {"enabled": False},
            "quic": {"enabled": False},
            "way_out": read_way_out_policy({"enabled": True,
                                            "state_dir": state_dir}),
        }})
        beacon._running = False
        self.addCleanup(setattr, beacon, "_running", False)
        return beacon

    def test_it_passes_a_beacon_whose_way_out_is_on(self):
        beacon = self.beacon(_scratch.scratch(self, "raccoon-harness-"))
        self.assertIs(_scratch.assert_live(self, beacon), beacon)

    def test_it_fails_a_beacon_whose_way_out_the_reader_refused(self):
        # The exact shape of the CI failure: a `/tmp` state directory, so
        # the reader refuses the block, so `_way_out_state_dir` is empty
        # and the feature is not there to be tested.
        refused = self.beacon("/tmp/raccoon-harness")
        self.assertFalse(refused._way_out_enabled)
        with self.assertRaises(AssertionError) as caught:
            _scratch.assert_live(self, refused)
        self.assertIn("not testing it", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
