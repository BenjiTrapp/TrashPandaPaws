#!/usr/bin/env python3
"""Stage 4: the model answers one question, and ships off.

The scout asks a local model which rung to take, validates the answer
against the verbs the implant actually has, and publishes it. The beacon
never calls the model and never waits for it: it reads a file and ignores
a stale one. That property was chosen to keep `beacon.py` stdlib-only, and
it happens to absorb the unmeasured latency as well -- a model too slow
for this hardware degrades to the policy rather than blocking the rescue.

**It ships off, and that is not timidity.** What inference costs on a Pi
powered over PoE -- watts, seconds, thermal headroom -- is not measured
anywhere in this repository and cannot be: there is no device. So the
first operator to switch it on is the first measurement.

**Loopback only.** The model exists for this implant's own decision; a
listener reachable from the target segment would hand it to anyone on the
network the implant is hiding in. The config reader refuses a non-loopback
endpoint by name and this module refuses one again -- the reader runs in
the beacon's process, and this one runs in the scout's.

**A bad answer is a refusal, logged, not a crash.** The same stance
`read_egress_policy` takes toward a rule naming a flag nothing sets: the
weakest model in the system would otherwise own the decision with the
least room for error.
"""

import json
import os
import socket
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.c2.beacon import EGRESS_VERBS
from software.scout import model as model_mod

A_MODEL = {"enabled": True, "endpoint": "http://127.0.0.1:11434",
           "name": "qwen2.5:0.5b", "timeout_seconds": 30}
A_STATE = {"version": 1, "stuck_cycles": 12, "hours_dark": 1.0,
           "evidence": {"legs": {"https": "timed_out"}, "flags": []}}
A_TAP = {"flags": ["portal_answered"], "proxies": ["10.0.0.1:3128"],
         "resolvers": {"10.0.0.2": 4}, "credentials": 1,
         "tls_destinations": ["updates.example.com"], "ssids": []}


# Every form a loopback check has to answer, and the answer. Two
# implementations read it -- `beacon.py`'s `_way_out_is_loopback` in the
# beacon's process and `software/scout/model.py`'s `_is_loopback` in the
# scout's -- and a review found two mutations that survived the whole
# suite: accepting `0.0.0.0`, which this design's anti-goal names in so
# many words, and stripping userinfo the wrong way so that
# `http://127.0.0.1@evil.com/` dialled `evil.com`.
LOOPBACK_ENDPOINTS = (
    ("http://127.0.0.1:11434", True),
    ("http://127.0.0.1", True),
    ("http://localhost:11434", True),
    ("HTTP://LOCALHOST:11434", True),
    ("http://[::1]:11434", True),
    ("https://127.0.0.1:11434", True),
    ("http://evil.com@127.0.0.1/", True),
    ("http://127.0.0.1:11434/api/generate", True),
    # 0.0.0.0 is "every interface", which is the one address the design's
    # anti-goal names: a listener there is handed to anyone on the network
    # the implant is hiding in.
    ("http://0.0.0.0:11434", False),
    ("http://[::]:11434", False),
    # Userinfo. The host is what follows the last `@`, not what precedes
    # the first.
    ("http://127.0.0.1@evil.com/", False),
    ("http://127.0.0.1:11434@evil.com/", False),
    # Hosts that merely mention loopback.
    ("http://127.0.0.1.evil.lan:11434", False),
    ("http://model.lan/?at=127.0.0.1", False),
    ("http://localhost.evil.lan", False),
    # Forms this check deliberately does not resolve into loopback: a
    # conservative "no" on something unusual is the safe answer here.
    ("http://127.1:11434", False),
    ("http://2130706433:11434", False),
    ("http://[::ffff:127.0.0.1]:11434", False),
    ("http://localhost.:11434", False),
    # Not a URL this may dial at all.
    ("ws://127.0.0.1:11434", False),
    ("127.0.0.1:11434", False),
    ("", False),
    (None, False),
)


class TestOnlyLoopback(unittest.TestCase):
    """The one address the model may live at, and every near miss."""

    def test_each_form_is_answered_the_same_way_by_both_checkers(self):
        from software.c2.beacon import _way_out_is_loopback
        for endpoint, allowed in LOOPBACK_ENDPOINTS:
            with self.subTest(endpoint=endpoint):
                self.assertEqual(bool(model_mod._is_loopback(endpoint)),
                                 allowed, "the scout's checker")
                self.assertEqual(bool(_way_out_is_loopback(endpoint)),
                                 allowed, "the beacon's checker")

    def test_a_refused_endpoint_is_never_dialled(self):
        asked = []
        with mock.patch.object(model_mod, "_open",
                               lambda *a, **k: asked.append(1)):
            for endpoint, allowed in LOOPBACK_ENDPOINTS:
                if allowed:
                    continue
                self.assertIsNone(model_mod.ask(
                    dict(A_MODEL, endpoint=endpoint), A_STATE, A_TAP))
        self.assertEqual(asked, [])


class ValidationCase(unittest.TestCase):
    def validated(self, answer):
        return model_mod.validate(answer, EGRESS_VERBS)


class TestWhatCountsAsAnAnswer(ValidationCase):
    def test_a_verb_the_implant_has_is_taken(self):
        got = self.validated({"verb": "gsocket", "why": "nothing answered"})
        self.assertEqual(got["verb"], "gsocket")
        self.assertEqual(got["chose"], "model")
        self.assertEqual(got["why"], "nothing answered")

    def test_an_argument_and_an_estimate_come_through(self):
        got = self.validated({"verb": "proxy", "argument": "10.0.0.1:3128",
                              "p_success": 0.6})
        self.assertEqual(got["argument"], "10.0.0.1:3128")
        self.assertEqual(got["p_success"], 0.6)

    def test_a_verb_outside_the_allowed_set_is_a_refusal(self):
        # `sleep` is the one that matters: a verb the beacon really
        # dispatches, and the one an implant deciding for itself must not
        # have -- it could talk itself into silence.
        for verb in ("sleep", "persist", "tunnel", "kill", ""):
            with self.subTest(verb=verb):
                self.assertIsNone(self.validated({"verb": verb}))

    def test_an_answer_that_is_not_an_object_is_a_refusal(self):
        for answer in (None, [], "gsocket", 17, {"rung": 2}):
            with self.subTest(answer=answer):
                self.assertIsNone(self.validated(answer))

    def test_an_estimate_that_is_not_a_probability_is_dropped(self):
        # Dropped and not refused: the verb is still usable, and the
        # beacon's own clamp is what makes an estimate advisory. A number
        # outside (0, 1) is not an estimate at all.
        for proposed in ("high", None, 2.0, -1, True, float("nan")):
            with self.subTest(proposed=proposed):
                got = self.validated({"verb": "gsocket",
                                      "p_success": proposed})
                self.assertIsNotNone(got)
                self.assertIsNone(got["p_success"])

    def test_an_argument_that_is_not_a_string_is_dropped(self):
        got = self.validated({"verb": "proxy", "argument": {"url": 1}})
        self.assertEqual(got["argument"], "")

    def test_a_reason_is_kept_short(self):
        got = self.validated({"verb": "gsocket", "why": "x" * 5000})
        self.assertLessEqual(len(got["why"]), 500)

    def test_the_allowed_set_is_the_beacons_own(self):
        # One vocabulary and not two: the scout may import the beacon, and
        # the beacon may not import the scout -- so this is the direction
        # the dependency runs, and `EGRESS_VERBS` needs no copy.
        self.assertEqual(model_mod.ALLOWED, EGRESS_VERBS)


class TestAskingTheModel(unittest.TestCase):
    def reply(self, payload, status=200):
        """Stand in for the one HTTP call, recording what went out.

        `model._open` and **not** `urllib.request.urlopen`, which is
        where this stood before: patching `urlopen` was patching the
        defect. `urlopen` builds its opener from `getproxies()`, so the
        prompt honoured `http_proxy` from the implant's environment and
        was POSTed to a corporate proxy -- and no test could see it,
        because every one of them replaced the call. `_open` is the seam
        that owns "never through a proxy", and
        `TestTheQuestionDoesNotLeaveThisHost` below is the only honest
        pin on that: a real listener.
        """
        sent = {}

        def opened(request, timeout=None):
            sent["url"] = request.full_url
            sent["body"] = json.loads(request.data.decode("utf-8"))
            sent["timeout"] = timeout
            if isinstance(payload, Exception):
                raise payload
            return json.dumps(payload).encode("utf-8")

        patcher = mock.patch.object(model_mod, "_open", opened)
        patcher.start()
        self.addCleanup(patcher.stop)
        return sent

    def test_it_asks_the_configured_model_on_loopback(self):
        sent = self.reply({"response": json.dumps({"verb": "gsocket"})})
        got = model_mod.ask(A_MODEL, A_STATE, A_TAP)

        self.assertEqual(got["verb"], "gsocket")
        self.assertEqual(sent["url"], "http://127.0.0.1:11434/api/generate")
        self.assertEqual(sent["body"]["model"], "qwen2.5:0.5b")
        self.assertFalse(sent["body"]["stream"])
        self.assertEqual(sent["body"]["format"], "json")
        self.assertEqual(sent["timeout"], 30)

    def test_the_prompt_carries_the_evidence_and_the_allowed_verbs(self):
        sent = self.reply({"response": json.dumps({"verb": "gsocket"})})
        model_mod.ask(A_MODEL, A_STATE, A_TAP)
        prompt = sent["body"]["prompt"]
        for needle in ("timed_out", "portal_answered", "10.0.0.1:3128",
                       "1.0"):
            self.assertIn(needle, prompt, needle)
        for verb in EGRESS_VERBS:
            self.assertIn(verb, prompt, verb)

    def test_the_prompt_names_no_address_of_the_team_server(self):
        # The evidence is classes and flags, not endpoints. A prompt that
        # carried the callback URL would put the operator's infrastructure
        # into a third-party model's context on a device built to look
        # like an IP phone.
        sent = self.reply({"response": json.dumps({"verb": "gsocket"})})
        model_mod.ask(A_MODEL, A_STATE, A_TAP)
        self.assertNotIn("c2.example.com", sent["body"]["prompt"])

    def test_a_non_loopback_endpoint_is_refused_here_too(self):
        # Defence in depth: `read_way_out_policy` refuses one in the
        # beacon's process, and this runs in the scout's.
        # The last two are the trap: a host that merely *mentions*
        # loopback is not loopback, and a check by substring would dial
        # whatever the file named.
        for endpoint in ("http://10.0.0.5:11434", "http://model.lan:11434",
                         "https://api.example.com", "", None,
                         "http://model.lan/?from=127.0.0.1",
                         "http://127.0.0.1.evil.lan:11434"):
            with self.subTest(endpoint=endpoint):
                self.reply({"response": json.dumps({"verb": "gsocket"})})
                self.assertIsNone(model_mod.ask(
                    dict(A_MODEL, endpoint=endpoint), A_STATE, A_TAP))

    def test_a_model_with_no_name_is_not_asked(self):
        sent = self.reply({"response": json.dumps({"verb": "gsocket"})})
        self.assertIsNone(model_mod.ask(dict(A_MODEL, name=""), A_STATE,
                                        A_TAP))
        self.assertEqual(sent, {})

    def test_an_answer_that_is_not_json_is_a_refusal(self):
        for response in ("the proxy, obviously", "", "{", "[]", "null"):
            with self.subTest(response=response):
                self.reply({"response": response})
                self.assertIsNone(model_mod.ask(A_MODEL, A_STATE, A_TAP))

    def test_a_reply_with_no_response_field_is_a_refusal(self):
        for payload in ({}, {"error": "model not found"}, {"response": 17}):
            with self.subTest(payload=payload):
                self.reply(payload)
                self.assertIsNone(model_mod.ask(A_MODEL, A_STATE, A_TAP))

    def test_a_reply_that_is_not_json_at_all_is_a_refusal(self):
        with mock.patch.object(model_mod, "_open",
                               lambda request, timeout=None:
                               b"<html>no model here</html>"):
            self.assertIsNone(model_mod.ask(A_MODEL, A_STATE, A_TAP))

    def test_a_timeout_or_a_refused_connection_is_a_refusal(self):
        import socket
        import urllib.error
        for failure in (socket.timeout("too slow"),
                        urllib.error.URLError("connection refused"),
                        OSError("no such host"),
                        urllib.error.HTTPError("http://127.0.0.1:11434", 404,
                                               "no", {}, None)):
            with self.subTest(failure=type(failure).__name__):
                self.reply(failure)
                self.assertIsNone(model_mod.ask(A_MODEL, A_STATE, A_TAP))

    def test_a_refusal_says_what_came_back(self):
        self.reply({"response": json.dumps({"verb": "sleep"})})
        with self.assertLogs("raccoon.scout.model", level="WARNING") as got:
            self.assertIsNone(model_mod.ask(A_MODEL, A_STATE, A_TAP))
        self.assertIn("sleep", "\n".join(got.output))


class TestTheQuestionDoesNotLeaveThisHost(unittest.TestCase):
    """The claim this module makes in bold, read off a socket.

    "Loopback only, checked twice" was two checks on the endpoint's
    *text*, and the request went out through `urllib.request.urlopen`,
    which builds its opener from `getproxies()`. With `http_proxy` in the
    implant's environment and no `no_proxy`, the whole prompt was POSTed
    in cleartext to that proxy -- a body that says there is an implant,
    that it bridges a switch port and a host, how long it has been dark,
    the host's MAC, IP, proxy and resolver, and the menu of moves
    including taking the host's identity. A corporate proxy is the one
    device on the network most certain to log it.

    No test could see that, because every test of `ask` replaced the
    call. So this one does not: it points `http_proxy` at a listener it
    owns and requires that the listener sees **nothing**. The project's
    own recorded lesson, applied to itself -- a reachable peer cannot be
    proved by asserting a URL's text.
    """

    def listener(self):
        """A socket standing in for the proxy, and what it saw."""
        seen = []
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(2)
        server.settimeout(0.2)
        done = threading.Event()

        def accept():
            while not done.is_set():
                try:
                    connection, _peer = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                try:
                    seen.append(connection.recv(4096))
                finally:
                    connection.close()

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()

        def stop():
            done.set()
            thread.join(timeout=5)
            server.close()

        self.addCleanup(stop)
        return seen, server.getsockname()[1]

    def test_the_prompt_is_not_sent_to_the_proxy_in_the_environment(self):
        seen, port = self.listener()
        # `no_proxy` cleared as well: this machine happens to carry one
        # that bypasses loopback, which is exactly why the defect was
        # invisible where it was written.
        environment = dict(os.environ)
        for name in ("no_proxy", "NO_PROXY", "https_proxy", "HTTPS_PROXY"):
            environment.pop(name, None)
        environment["http_proxy"] = "http://127.0.0.1:%d" % port
        environment["HTTP_PROXY"] = environment["http_proxy"]

        with mock.patch.dict(os.environ, environment, clear=True):
            self.assertIsNone(model_mod.ask(
                dict(A_MODEL, endpoint="http://127.0.0.1:1/",
                     timeout_seconds=3),
                A_STATE, A_TAP))

        deadline = time.time() + 1.0
        while not seen and time.time() < deadline:
            time.sleep(0.02)
        self.assertEqual(seen, [],
                         "the prompt was sent to the proxy named in the "
                         "implant's environment: %r"
                         % (seen[0][:400] if seen else b"",))

    def test_the_question_still_reaches_a_model_on_loopback(self):
        # The other half, so the fix cannot be "send nothing at all": a
        # real listener on loopback gets the real request.
        seen, port = self.listener()
        with mock.patch.dict(os.environ, {}, clear=False):
            model_mod.ask(dict(A_MODEL,
                               endpoint="http://127.0.0.1:%d/" % port,
                               timeout_seconds=3),
                          A_STATE, A_TAP)
        deadline = time.time() + 5
        while not seen and time.time() < deadline:
            time.sleep(0.02)
        self.assertTrue(seen, "nothing reached the loopback listener")
        self.assertIn(b"/api/generate", seen[0])


class TestItIsOffUnlessSwitchedOn(unittest.TestCase):
    def test_a_block_that_is_not_enabled_is_never_asked(self):
        asked = []
        with mock.patch.object(model_mod, "_open",
                               lambda *a, **k: asked.append(1)):
            self.assertIsNone(model_mod.ask(dict(A_MODEL, enabled=False),
                                            A_STATE, A_TAP))
        self.assertEqual(asked, [])

    def test_the_shipped_config_has_it_off(self):
        import yaml
        config = yaml.safe_load(
            (REPO_ROOT / "configs" / "raccoon.yaml").read_text())
        self.assertFalse(
            config["c2"]["way_out"]["model"]["enabled"],
            "stage 4 must ship off: without a device nobody can say what "
            "inference costs on PoE")
        self.assertEqual(config["c2"]["way_out"]["model"]["endpoint"],
                         "http://127.0.0.1:11434")


if __name__ == "__main__":
    unittest.main()
