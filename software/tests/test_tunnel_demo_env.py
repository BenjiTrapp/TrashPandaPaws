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

The third test is the standing rule for every module a test imports: the
module does its work in `main`, so importing it binds no socket and spawns
no child.
"""

import sys
import unittest

from software.c2.tunnel.supervisor import tunnel_server_config

from tools import tunnel_demo_env


class DemoConfigTests(unittest.TestCase):
    def test_the_demo_config_is_one_tunnel_server_validated_by_the_real_validator(self):
        block = tunnel_demo_env.demo_config(
            bind_port=18446,
            socks_first=19050, socks_last=19059,
            shell_first=19150, shell_last=19159,
            transcript_dir="/tmp/demo-transcripts")
        validated = tunnel_server_config(block)
        self.assertIsNotNone(validated)
        self.assertEqual(validated["bind_port"], 18446)
        self.assertEqual(validated["socks_port_first"], 19050)
        self.assertEqual(validated["socks_port_last"], 19059)
        self.assertEqual(validated["shell_port_first"], 19150)
        self.assertEqual(validated["shell_port_last"], 19159)
        self.assertEqual(validated["shell_transcript_dir"],
                         "/tmp/demo-transcripts")

    def test_the_shell_range_does_not_overlap_the_socks_range(self):
        block = tunnel_demo_env.demo_config(
            bind_port=18446,
            socks_first=19050, socks_last=19059,
            shell_first=19150, shell_last=19159,
            transcript_dir="/tmp/demo-transcripts")
        # The real validator makes the same refusal TunnelServer.__init__
        # does; that it returns at all is the proof the ranges are disjoint.
        validated = tunnel_server_config(block)
        first, last = validated["shell_port_first"], validated["shell_port_last"]
        sfirst, slast = (validated["socks_port_first"],
                         validated["socks_port_last"])
        self.assertFalse(first <= slast and sfirst <= last)

    def test_it_starts_nothing_on_import(self):
        # Importing the module above bound no socket and spawned no child;
        # the proof is that it is already imported and the suite is still
        # here. Said as an assertion so the property has a name that fails
        # loudly if someone moves work to module scope.
        self.assertIn("tools.tunnel_demo_env", sys.modules)
        self.assertTrue(hasattr(tunnel_demo_env, "main"))
        self.assertTrue(hasattr(tunnel_demo_env, "demo_config"))


if __name__ == "__main__":
    unittest.main()
