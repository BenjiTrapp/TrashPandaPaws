#!/usr/bin/env python3
"""A body the server will not read, and a token it stops answering.

Two halves of one finding, and they are not the same threat.

`MAX_CONTENT_LENGTH` was never set, so one **unauthenticated** POST with a
multi-gigabyte body was read into memory and parsed as JSON before
anything asked whether it was a valid message. Writing a loot file needs a
message that decrypts and names a registered agent, so that part applies
to a sender with the key -- but the read and the parse do not.

And there was no lockout on the operator token: sixty wrong-token requests
in a row all answered 401, as fast as they could be sent. A first audit
reported rate limiting as present because its pattern matched the
`X-RateLimit-Limit` and `X-RateLimit-Remaining` strings in a C2 profile
example in `server.py`. Those are example response headers in a malleable
profile, not a limiter, and this file is partly here so that nobody has to
take that question on trust again.

The cap's number is derived rather than chosen: the beacon refuses to send
a single file over 10 MiB and a loot zip over 50 MiB (`_exec_download`,
`_exec_loot`). 50 MiB of zip is 66.7 MiB of base64 inside the JSON, and
the JSON is then encrypted and base64'd again, so the largest body a
beacon can legitimately produce is about 89 MiB.
"""

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.c2 import server as server_mod

KEY = b"k" * 32
TOKEN = "test-operator-token"


class ServerCase(unittest.TestCase):
    def setUp(self):
        for store in (server_mod.agents, server_mod.task_queues,
                      server_mod.history, server_mod.results,
                      server_mod.auth_failures):
            store.clear()
            self.addCleanup(store.clear)
        self.data_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.data_dir, ignore_errors=True)
        self.crypto = server_mod.ServerCrypto(KEY)
        self.app = server_mod.create_app(self.crypto, TOKEN, self.data_dir)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.auth = {"Authorization": "Bearer " + TOKEN}
        self.wrong = {"Authorization": "Bearer not-the-token"}


class TestTheRequestSizeCap(ServerCase):
    def test_a_cap_is_configured(self):
        self.assertIsNotNone(self.app.config.get("MAX_CONTENT_LENGTH"),
                             "MAX_CONTENT_LENGTH is unset, so a body of any "
                             "size is read into memory and parsed")

    def test_the_cap_is_above_the_largest_body_a_beacon_can_send(self):
        # Derived from the beacon's own ceilings rather than picked: a cap
        # below them would refuse legitimate loot, which is worse than no
        # cap because it fails only on the engagement that collected
        # something big.
        cap = self.app.config["MAX_CONTENT_LENGTH"]
        loot_zip = 50 * 1024 * 1024
        encrypted = loot_zip * 4 // 3 * 4 // 3        # two base64 layers
        self.assertGreater(cap, encrypted,
                           "the cap is below the 50 MiB loot zip the beacon "
                           "will send, twice base64-encoded")

    def test_an_oversized_body_on_the_beacon_route_is_never_parsed(self):
        # The agent socket answers every caller the same cover response,
        # including this one -- a prober must not be able to tell a refused
        # body from a wrong key. So the evidence is not the status: it is
        # that the body did not become a registration.
        huge = "A" * (self.app.config["MAX_CONTENT_LENGTH"] + 1024)
        body = json.dumps(self.crypto.wrap(
            {"action": "register", "id": "big", "hostname": huge,
             "user": "u"})).encode()
        self.assertGreater(len(body), self.app.config["MAX_CONTENT_LENGTH"])
        reply = self.client.post("/api/v1/beacon", data=body,
                                 content_type="application/json")
        self.assertEqual(reply.get_json(),
                         {"status": "ok", "version": "2.1.0"})
        self.assertEqual(server_mod.agents, {},
                         "the oversized body was read, decrypted and acted "
                         "on")

    def test_an_oversized_body_is_refused_on_an_operator_route(self):
        # On a route whose own checks pass, so the refusal is the cap's and
        # not a 404 arriving first.
        agent_id = self.crypto.unwrap(self.client.post(
            "/api/v1/beacon", data=json.dumps(self.crypto.wrap(
                {"action": "register", "id": "i1", "hostname": "h",
                 "user": "u"})),
            content_type="application/json").get_json())["agent_id"]
        body = json.dumps({"cmd": "upload", "args": "/tmp/x",
                           "data": "A" * self.app.config[
                               "MAX_CONTENT_LENGTH"]}).encode()
        reply = self.client.post("/api/agents/%s/task" % agent_id, data=body,
                                 content_type="application/json",
                                 headers=self.auth)
        self.assertEqual(reply.status_code, 413)
        self.assertEqual(server_mod.task_queues.get(agent_id, []), [])

    def test_an_ordinary_check_in_is_unaffected(self):
        reply = self.client.post("/api/v1/beacon", data=json.dumps(
            self.crypto.wrap({"action": "register", "id": "i1",
                              "hostname": "h", "user": "u"})),
            content_type="application/json")
        self.assertEqual(reply.status_code, 200)
        self.assertIn("agent_id", self.crypto.unwrap(reply.get_json()))


class TestTheOperatorTokenLockout(ServerCase):
    def test_sixty_wrong_tokens_do_not_all_answer_401(self):
        codes = [self.client.get("/api/loot", headers=self.wrong).status_code
                 for _ in range(60)]
        self.assertIn(429, codes,
                      "sixty wrong-token requests in a row all answered "
                      "401, as fast as they could be sent")

    def test_the_refusal_says_how_long_to_wait(self):
        for _ in range(server_mod.AUTH_FAILURE_LIMIT + 1):
            reply = self.client.get("/api/loot", headers=self.wrong)
        self.assertEqual(reply.status_code, 429)
        self.assertTrue(reply.headers.get("Retry-After"),
                        "a 429 with no Retry-After tells a client nothing")

    def test_the_limit_is_not_reached_by_ordinary_use(self):
        # The cost of getting this wrong is locking the operator out of
        # their own C2, so the threshold has to be above a few fat-fingered
        # attempts.
        self.assertGreaterEqual(server_mod.AUTH_FAILURE_LIMIT, 5)
        codes = {self.client.get("/api/loot", headers=self.wrong).status_code
                 for _ in range(server_mod.AUTH_FAILURE_LIMIT)}
        self.assertEqual(codes, {401})

    def test_the_right_token_clears_the_count(self):
        for _ in range(server_mod.AUTH_FAILURE_LIMIT - 1):
            self.client.get("/api/loot", headers=self.wrong)
        self.assertEqual(
            self.client.get("/api/loot", headers=self.auth).status_code, 200)
        # Back to a full budget: an operator who mistypes, succeeds, and
        # mistypes again is not one attempt from a lockout.
        codes = {self.client.get("/api/loot", headers=self.wrong).status_code
                 for _ in range(server_mod.AUTH_FAILURE_LIMIT)}
        self.assertEqual(codes, {401})

    def test_a_locked_out_address_cannot_use_the_right_token_either(self):
        # Deliberate: a lockout that the right token walks through is not a
        # lockout, because the attacker's next guess might be right.
        for _ in range(server_mod.AUTH_FAILURE_LIMIT + 1):
            self.client.get("/api/loot", headers=self.wrong)
        self.assertEqual(
            self.client.get("/api/loot", headers=self.auth).status_code, 429)

    def test_the_window_expires(self):
        for _ in range(server_mod.AUTH_FAILURE_LIMIT + 1):
            self.client.get("/api/loot", headers=self.wrong)
        self.assertEqual(
            self.client.get("/api/loot", headers=self.auth).status_code, 429)
        # Rewind every recorded failure past the window rather than
        # sleeping through it: the window is a minute and this suite has
        # four thousand tests.
        for address, stamps in server_mod.auth_failures.items():
            server_mod.auth_failures[address] = [
                stamp - server_mod.AUTH_FAILURE_WINDOW - 1
                for stamp in stamps]
        self.assertEqual(
            self.client.get("/api/loot", headers=self.auth).status_code, 200)

    def test_the_count_is_kept_per_address(self):
        for _ in range(server_mod.AUTH_FAILURE_LIMIT + 1):
            self.client.get("/api/loot", headers=self.wrong)
        self.assertEqual(
            self.client.get("/api/loot", headers=self.auth).status_code, 429)
        other = self.client.get("/api/loot", headers=self.auth,
                                environ_overrides={"REMOTE_ADDR": "10.0.0.9"})
        self.assertEqual(other.status_code, 200,
                         "one address's wrong guesses locked out every "
                         "other address, which is a way to lock the "
                         "operator out of their own C2")

    def test_the_record_does_not_grow_without_bound(self):
        for n in range(server_mod.AUTH_FAILURE_ADDRESSES + 50):
            self.client.get("/api/loot", headers=self.wrong,
                            environ_overrides={
                                "REMOTE_ADDR": "10.1.%d.%d" % (n // 256,
                                                               n % 256)})
        self.assertLessEqual(len(server_mod.auth_failures),
                             server_mod.AUTH_FAILURE_ADDRESSES)

    def test_the_beacon_route_is_not_rate_limited(self):
        # The agent socket has no operator token and answers every caller
        # the same cover response; counting failures there would let one
        # prober deny the channel to every beacon behind the same NAT.
        for _ in range(server_mod.AUTH_FAILURE_LIMIT + 5):
            reply = self.client.post("/api/v1/beacon", data="{}",
                                     content_type="application/json")
            self.assertEqual(reply.status_code, 200)


class TestTheRateLimitClaimIsAboutCode(unittest.TestCase):
    def test_the_profile_example_headers_are_not_mistaken_for_a_limiter(self):
        # The audit's own false positive, kept as a test: these two strings
        # are in a malleable C2 profile example and are not a limiter.
        source = (REPO_ROOT / "software" / "c2" / "server.py").read_text()
        self.assertIn("X-RateLimit-Limit", source)
        self.assertIn("auth_failures", source,
                      "the only rate limiting in this file would again be "
                      "the profile example's response headers")


if __name__ == "__main__":
    unittest.main()
