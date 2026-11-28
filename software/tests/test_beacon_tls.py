#!/usr/bin/env python3
"""`c2.fallback.https.verify_ssl` is a switch, not a comment.

`_HttpSession._build_opener` set `check_hostname = False` and
`verify_mode = ssl.CERT_NONE` unconditionally, and `ProxyDiscovery`'s
probe did the same, while `Beacon.verify_ssl` was assigned from the
configuration and read nowhere. So the key in `configs/raccoon.yaml` could
not be turned on: over the internet the payload encryption was the only
control left, whatever the file said.

What this fixes is the wiring, and only that. The shipped default stays
`false`, because changing it would turn every existing deployment with a
self-signed team-server certificate off at the next beacon interval -- and
that *is* a trust decision rather than a defect. What is still missing
after this, and is recorded as such, is pinning: an operator with a
self-signed certificate has no way to say "this one", only "any" or
"none".

Two places deliberately keep `CERT_NONE` and say why here as well as in
the code:

* the loopback forward in `_https_post`, which talks to `127.0.0.1` on
  this host through the gsocket leg's child -- no certificate names a
  loopback forward, and `docs/LISTENERS.md` states that this leg's `https`
  scheme means TLS without verification;
* `NetworkScanner._probe_ssl`, which exists to *report a target's*
  certificate. Verifying there would refuse exactly the hosts it is for.
"""

import ast
import base64
import os
import ssl
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.c2 import beacon as beacon_mod
from software.c2.beacon import Beacon, _HttpSession


def _a_beacon(**https):
    block = {"enabled": True,
             "callback_url": "https://c2.example.com/api/v1/beacon"}
    block.update(https)
    return Beacon({"c2": {
        "beacon_interval_seconds": 300,
        "jitter_percent": 0,
        "encryption_key": base64.b64encode(os.urandom(32)).decode(),
        "proxy": {"mode": "none"},
        "https": block,
        "dns": {"enabled": False, "domain": "", "resolver": "1.1.1.1"},
    }})


def _context_of(session):
    """The SSL context the session's opener would use for HTTPS."""
    opener = session._build_opener()
    for handler in opener.handlers:
        context = getattr(handler, "_context", None)
        if context is not None:
            return context
    raise AssertionError("no HTTPS handler carries a context")


class TestTheSessionHonoursTheFlag(unittest.TestCase):
    def test_the_default_is_unverified_and_unchanged(self):
        session = _HttpSession()
        self.assertFalse(session.verify)
        context = _context_of(session)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        self.assertFalse(context.check_hostname)

    def test_verify_true_turns_both_halves_on(self):
        # Both, because either alone is a hole: CERT_REQUIRED with
        # check_hostname off accepts a valid certificate for another name.
        session = _HttpSession()
        session.verify = True
        context = _context_of(session)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_a_bound_session_keeps_the_flag(self):
        # The source-bound handler is a different class, and it is the one
        # the way out's radio rung uses, so the flag has to reach it too.
        session = _HttpSession()
        session.verify = True
        session.source_address = ("10.0.0.9", 0)
        context = _context_of(session)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)


class TestTheBeaconPassesItsConfiguredValue(unittest.TestCase):
    def test_the_flag_reaches_the_session_the_beacon_posts_with(self):
        for configured in (True, False):
            with self.subTest(verify_ssl=configured):
                beacon = _a_beacon(verify_ssl=configured)
                self.assertEqual(beacon.verify_ssl, configured)
                self.assertEqual(beacon._bound_session().verify, configured)

    def test_an_absent_key_is_unverified(self):
        beacon = _a_beacon()
        self.assertFalse(beacon.verify_ssl)
        self.assertFalse(beacon._bound_session().verify)

    def test_a_quoted_boolean_is_not_read_as_true(self):
        # `bool("false")` is True, and this setting is the difference
        # between a verified channel and one that only says it is. The
        # project refuses quoted booleans elsewhere for the same reason.
        beacon = _a_beacon(verify_ssl="false")
        self.assertFalse(beacon.verify_ssl,
                         "the string 'false' was read as true")
        self.assertFalse(beacon._bound_session().verify)

    def test_the_proxy_probe_carries_it_too(self):
        # The finding names the probe as well as the opener: it is a real
        # HTTPS request to the operator's own callback URL, made before any
        # beacon traffic.
        from software.c2.beacon import ProxyDiscovery

        self.assertFalse(ProxyDiscovery().verify)
        self.assertTrue(ProxyDiscovery(verify=True).verify)
        beacon = _a_beacon(verify_ssl=True)
        self.assertTrue(beacon._proxy.verify,
                        "the beacon's own ProxyDiscovery was built without "
                        "the configured value")
        self.assertFalse(_a_beacon()._proxy.verify)


class TestTheTwoDeliberateExceptionsStay(unittest.TestCase):
    def test_the_loopback_forward_is_not_verified(self):
        # No certificate names a loopback forward, and docs/LISTENERS.md
        # states that this leg's `https` scheme means TLS without
        # verification. A beacon with verify_ssl on must still reach its
        # own forward.
        #
        # Behavioural, through `_https_post`, not a search of its source:
        # the first version of this test read the function's text for the
        # word "verify", and a mutation that *did* hand the flag to the
        # loopback session passed it -- the comment explaining the
        # exception was the match.
        beacon = _a_beacon(verify_ssl=True)
        built = []
        real = beacon_mod._HttpSession

        def recording(*args, **kwargs):
            session = real(*args, **kwargs)
            built.append(session)
            return session

        with mock.patch.object(beacon_mod, "_HttpSession",
                               side_effect=recording):
            beacon._https_post("beacon", {"action": "beacon"},
                               base="http://127.0.0.1:16443")
        self.assertTrue(built, "no session was built")
        self.assertFalse(
            built[-1].verify,
            "the loopback forward's session verifies, so the gsocket leg "
            "cannot reach its own forward on a beacon with verify_ssl on")

    def test_a_non_loopback_base_does_verify(self):
        # The other side of the same branch, so the exception above is an
        # exception and not the rule.
        beacon = _a_beacon(verify_ssl=True)
        built = []
        real = beacon_mod._HttpSession

        def recording(*args, **kwargs):
            session = real(*args, **kwargs)
            built.append(session)
            return session

        with mock.patch.object(beacon_mod, "_HttpSession",
                               side_effect=recording):
            beacon._https_post("beacon", {"action": "beacon"},
                               base="https://c2.example.com/api/v1/beacon")
        self.assertTrue(built, "no session was built")
        self.assertTrue(built[-1].verify,
                        "a request to the callback URL did not verify")

    def test_the_target_probe_still_reports_any_certificate(self):
        source = (REPO_ROOT / "software" / "c2" / "beacon.py").read_text()
        start = source.index("def _probe_ssl")
        body = source[start:start + 1200]
        self.assertIn("ssl.CERT_NONE", body)
        self.assertRegex(body, r"(?s)verif",
                         "_probe_ssl does not say why it does not verify")


class TestWhatIsStillOpenIsStatedNarrowly(unittest.TestCase):
    def test_the_shipped_default_is_still_off(self):
        import yaml

        config = yaml.safe_load(
            (REPO_ROOT / "configs" / "raccoon.yaml").read_text())
        self.assertIs(config["c2"]["fallback"]["https"]["verify_ssl"], False,
                      "the shipped default changed, which is a trust "
                      "decision and not this change's to make")

    def test_there_is_still_no_pinning(self):
        # What the Known-limits entry is cut down to. A fingerprint or a CA
        # bundle would close it; neither exists, and an operator with a
        # self-signed certificate can still only choose "any" or "none".
        source = (REPO_ROOT / "software" / "c2" / "beacon.py").read_text()
        for absent in ("load_verify_locations", "get_server_certificate",
                       "pinned_sha256", "ca_bundle"):
            self.assertNotIn(absent, source)

    def test_the_listeners_guide_no_longer_calls_the_key_dead(self):
        guide = (REPO_ROOT / "docs" / "LISTENERS.md").read_text()
        self.assertNotIn("has had no reader for a long time", guide,
                         "docs/LISTENERS.md still says c2.https.verify_ssl "
                         "has no reader")

    def test_known_limits_no_longer_says_it_cannot_verify_at_all(self):
        limits = (REPO_ROOT / "docs" / "AGENT.md").read_text()
        self.assertNotIn("cannot verify TLS at all", limits)


class TestNothingElseLostItsContext(unittest.TestCase):
    """Every `CERT_NONE` left in beacon.py is one of the three named here.

    A fourth would be a channel nobody decided about, which is how the
    first one got there.
    """

    def test_there_are_exactly_three_unverified_contexts(self):
        source = (REPO_ROOT / "software" / "c2" / "beacon.py").read_text()
        tree = ast.parse(source)
        functions = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if "attr='CERT_NONE'" in ast.dump(node):
                    functions.append(node.name)
        self.assertEqual(sorted(functions),
                         ["_build_opener", "_probe_ssl", "select_working"],
                         "a function gained or lost an unverified TLS "
                         "context; each one is a decision")


if __name__ == "__main__":
    unittest.main()
