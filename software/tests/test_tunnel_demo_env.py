#!/usr/bin/env python3
"""The tunnel demo environment, judged without starting a process.

`tools/tunnel_demo_env.py` stands up a real tunnel-server child, a real
`TunnelEndpoint` and the shipped Flask app, so the tunnel panel can be
photographed. None of that can be exercised in a unit test, and it is not
the part that could break quietly: the part that could is the one block of
configuration the whole environment is built on. So this file asks the
one question a test can answer honestly -- does the config the script
ships pass the real validator and come back unchanged, and does its shell
range clear the SOCKS range `TunnelServer.__init__` refuses an overlap
with -- and leaves the looking to the capture step the task ends on.

**It validates `default_demo_config`, not `demo_config` with literals.**
`demo_config` is parametric, so a test that passed it its own numbers
would never read the module's shipped `_SOCKS_*/_SHELL_*` constants and
would stay green if someone edited them to overlap -- which is exactly the
mistake "the defaults it ships cannot trip the overlap refusal" is meant
to catch. `default_demo_config` reads those constants, so the assertions
below are about what `main` actually runs.

The import test is the standing rule for every module a test imports: the
module does its work in `main`. It is checked for real, in a fresh
subprocess that imports the module and then reports whether importing it
created a temporary directory -- the one side effect `main` has that a
careless move to module scope would leak.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from software.c2.tunnel.supervisor import tunnel_server_config

from tools import tunnel_demo_env

_REPO = Path(__file__).resolve().parent.parent.parent


class DemoConfigTests(unittest.TestCase):
    def test_the_demo_config_is_one_tunnel_server_validated_by_the_real_validator(self):
        # default_demo_config, so the shipped ranges are the ones under
        # test. bind_port is a demo input, not a shipped constant, so it is
        # passed; the ranges and the transcript directory are the module's.
        block = tunnel_demo_env.default_demo_config(
            bind_port=18446, transcript_dir="/tmp/demo-transcripts")
        validated = tunnel_server_config(block)
        self.assertIsNotNone(validated)
        self.assertEqual(validated["bind_port"], 18446)
        self.assertEqual(validated["socks_port_first"],
                         tunnel_demo_env._SOCKS_FIRST)
        self.assertEqual(validated["socks_port_last"],
                         tunnel_demo_env._SOCKS_LAST)
        self.assertEqual(validated["shell_port_first"],
                         tunnel_demo_env._SHELL_FIRST)
        self.assertEqual(validated["shell_port_last"],
                         tunnel_demo_env._SHELL_LAST)
        self.assertEqual(validated["shell_transcript_dir"],
                         "/tmp/demo-transcripts")

    def test_the_shell_range_does_not_overlap_the_socks_range(self):
        # The real validator makes the same refusal TunnelServer.__init__
        # does; that default_demo_config passes through it at all is the
        # proof the shipped ranges are disjoint. Editing a constant into an
        # overlap would raise here rather than leave the test green.
        block = tunnel_demo_env.default_demo_config(
            bind_port=18446, transcript_dir="/tmp/demo-transcripts")
        validated = tunnel_server_config(block)
        first, last = validated["shell_port_first"], validated["shell_port_last"]
        sfirst, slast = (validated["socks_port_first"],
                         validated["socks_port_last"])
        self.assertFalse(first <= slast and sfirst <= last)

    def test_it_starts_nothing_on_import(self):
        """Importing the module creates no temporary directory.

        `main` is the only thing that calls `mkdtemp`, binds a socket or
        spawns a child. Rather than assert the names exist -- which holds
        for any importable module and proves nothing -- a fresh Python
        imports the module and reports, through a sentinel this harness
        reads back, how many `tunnel-demo-*` directories exist before and
        after the import. A move of `main`'s body to module scope would
        make the count rise and fail this.
        """
        probe = (
            "import glob, tempfile;"
            "pat = tempfile.gettempdir() + '/tunnel-demo-*';"
            "before = len(glob.glob(pat));"
            "import tools.tunnel_demo_env;"
            "after = len(glob.glob(pat));"
            "print(after - before)"
        )
        result = subprocess.run(
            [sys.executable, "-c", probe],
            cwd=str(_REPO), capture_output=True, text=True,
            env=dict(os.environ, PYTHONPATH=str(_REPO)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "0",
                         "importing the module created a temporary directory, "
                         "so something runs on import: %r" % result.stdout)


if __name__ == "__main__":
    unittest.main()
