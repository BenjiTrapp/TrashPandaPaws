#!/usr/bin/env python3
"""A message the server has already seen does not get to happen twice.

Two consequences were named in the finding, and they need different
answers:

* **Resubmitting a captured result** overwrote the recorded output for
  that task and wrote its loot file again. A key holder can re-encrypt
  the same payload, so a nonce cache cannot see that one -- what stops it
  is that a task's result is written once.
* **Replaying a captured check-in** took the queued task off the queue,
  so the real beacon never saw it. That needs no key at all: the captured
  bytes are enough. What stops it is the envelope's own nonce, which is
  twelve random bytes per message and already unique -- a repeat is
  either a replay or an AES-GCM nonce reuse, and both deserve the same
  refusal.

Neither half changes the wire, asks a beacon for anything, or needs a
clock. That matters here: the implant is a Pi with no RTC, so a freshness
window is not a thing this project can lean on, and a per-agent counter
would need somewhere on the implant to persist it -- which a build that is
a single pasted file does not have.

What remains after both, and is recorded rather than hidden: the nonce
cache is bounded, so a byte-identical check-in replayed after enough other
traffic is accepted again.
"""

import base64
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.c2 import server as server_mod

KEY = b"k" * 32
TOKEN = "test-operator-token"
COVER = {"status": "ok", "version": "2.1.0"}


class ReplayCase(unittest.TestCase):
    def setUp(self):
        for store in (server_mod.agents, server_mod.task_queues,
                      server_mod.history, server_mod.results,
                      server_mod.dispatches):
            store.clear()
            self.addCleanup(store.clear)
        server_mod._name_counter = 0
        self.data_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.data_dir, ignore_errors=True)
        self.crypto = server_mod.ServerCrypto(KEY)
        self.addCleanup(self.crypto.seen_envelopes.clear)
        app = server_mod.create_app(self.crypto, TOKEN, self.data_dir)
        app.config["TESTING"] = True
        self.client = app.test_client()
        self.auth = {"Authorization": "Bearer " + TOKEN}

    def wrapped(self, payload):
        """One envelope, so a test can send the very same bytes twice."""
        return json.dumps(self.crypto.wrap(payload))

    def send(self, body):
        return self.client.post("/api/v1/beacon", data=body,
                                content_type="application/json")

    def post(self, payload):
        return self.send(self.wrapped(payload))

    def register(self, implant_id="implant-1"):
        reply = self.post({"action": "register", "id": implant_id,
                           "hostname": "h", "user": "u"})
        return self.crypto.unwrap(reply.get_json())["agent_id"]

    def queue(self, agent_id, args="id"):
        return self.client.post("/api/agents/%s/task" % agent_id,
                                json={"cmd": "shell", "args": args},
                                headers=self.auth).get_json()["id"]


class TestAResultIsWrittenOnce(ReplayCase):
    def test_a_resubmitted_result_does_not_overwrite_the_first(self):
        agent_id = self.register()
        captured = {"action": "result", "agent_id": agent_id,
                    "task_id": "t1", "status": "ok", "output": "first"}
        self.post(captured)
        self.assertEqual(server_mod.results["t1"]["output"], "first")
        # Re-encrypted, which is what a key holder can do and what a nonce
        # cache cannot see.
        self.post(captured)
        self.assertEqual(server_mod.results["t1"]["output"], "first")

    def test_a_second_result_cannot_change_the_status_either(self):
        agent_id = self.register()
        self.post({"action": "result", "agent_id": agent_id,
                   "task_id": "t1", "status": "ok", "output": "uid=0"})
        self.post({"action": "result", "agent_id": agent_id,
                   "task_id": "t1", "status": "error", "output": ""})
        self.assertEqual(server_mod.results["t1"]["status"], "ok")
        self.assertEqual(server_mod.results["t1"]["output"], "uid=0")

    def test_the_second_submission_writes_no_second_loot_file(self):
        agent_id = self.register()
        payload = {"action": "result", "agent_id": agent_id,
                   "task_id": "t1", "status": "ok", "output": "",
                   "data": {"data": base64.b64encode(b"spoils").decode(),
                            "filename": "creds.txt", "loot": True}}
        self.post(payload)
        loot = self.data_dir / "loot" / agent_id
        self.assertEqual(len(list(loot.iterdir())), 1)
        self.post(payload)
        self.assertEqual(len(list(loot.iterdir())), 1,
                         "the resubmission wrote the loot file again")

    def test_the_refusal_is_indistinguishable_from_an_acceptance(self):
        # This route's whole contract: a prober must not be able to tell
        # what happened. Both answers are the ack, and neither is the
        # unkeyed cover response.
        agent_id = self.register()
        payload = {"action": "result", "agent_id": agent_id,
                   "task_id": "t1", "status": "ok", "output": "x"}
        first = self.post(payload)
        second = self.post(payload)
        for reply in (first, second):
            self.assertEqual(reply.status_code, 200)
            self.assertEqual(self.crypto.unwrap(reply.get_json()),
                             {"ack": True})
            self.assertNotEqual(reply.get_json(), COVER)

    def test_history_is_not_rewritten_by_the_second_submission(self):
        agent_id = self.register()
        task_id = self.queue(agent_id)
        self.post({"action": "result", "agent_id": agent_id,
                   "task_id": task_id, "status": "ok", "output": "real"})
        self.post({"action": "result", "agent_id": agent_id,
                   "task_id": task_id, "status": "ok", "output": "forged"})
        entries = [e for e in server_mod.history[agent_id]
                   if e.get("task_id") == task_id]
        self.assertEqual([e["output"] for e in entries], ["real"])

    def test_a_different_task_is_still_accepted(self):
        agent_id = self.register()
        self.post({"action": "result", "agent_id": agent_id,
                   "task_id": "t1", "status": "ok", "output": "one"})
        self.post({"action": "result", "agent_id": agent_id,
                   "task_id": "t2", "status": "ok", "output": "two"})
        self.assertEqual(server_mod.results["t2"]["output"], "two")


class TestACapturedEnvelopeIsRefused(ReplayCase):
    def test_the_same_bytes_twice_do_not_dequeue_two_tasks(self):
        # The consequence that needs no key. Two tasks are queued and one
        # check-in is captured and sent twice; before the fix the second
        # copy took the second task, which the real beacon then never saw.
        agent_id = self.register()
        first_task = self.queue(agent_id, args="one")
        second_task = self.queue(agent_id, args="two")
        body = self.wrapped({"action": "beacon", "agent_id": agent_id,
                             "id": "implant-1"})
        answer = self.crypto.unwrap(self.send(body).get_json())
        self.assertEqual(answer["id"], first_task)
        replay = self.send(body)
        self.assertEqual(replay.get_json(), COVER,
                         "the replayed envelope was processed")
        self.assertEqual([t["id"] for t in server_mod.task_queues[agent_id]],
                         [second_task],
                         "the replay took a task off the queue")

    def test_a_replayed_registration_is_refused(self):
        body = self.wrapped({"action": "register", "id": "implant-1",
                             "hostname": "h", "user": "u"})
        first = self.crypto.unwrap(self.send(body).get_json())
        self.assertIn("agent_id", first)
        self.assertEqual(self.send(body).get_json(), COVER)

    def test_a_fresh_envelope_of_the_same_payload_is_accepted(self):
        # The cache is about the bytes, not about the content: a beacon
        # that checks in twice with the same fields is the normal case.
        agent_id = self.register()
        for _ in range(3):
            reply = self.post({"action": "beacon", "agent_id": agent_id,
                               "id": "implant-1"})
            self.assertNotEqual(reply.get_json(), COVER)

    def test_the_record_does_not_grow_without_bound(self):
        agent_id = self.register()
        for _ in range(server_mod.SEEN_ENVELOPES_MAX + 50):
            self.post({"action": "beacon", "agent_id": agent_id,
                       "id": "implant-1"})
        self.assertLessEqual(len(self.crypto.seen_envelopes),
                             server_mod.SEEN_ENVELOPES_MAX)

    def test_the_bound_is_what_the_known_limits_entry_says(self):
        # The residual this leaves, stated in one place and read here: a
        # byte-identical envelope replayed after enough other traffic is
        # accepted again, because nothing here has a clock to bound the
        # cache by time instead of by count.
        limits = (REPO_ROOT / "docs" / "AGENT.md").read_text()
        self.assertIn(str(server_mod.SEEN_ENVELOPES_MAX), limits,
                      "Known limits does not state the cache's size, so the "
                      "residual cannot be read off it")

    def test_an_envelope_the_server_sent_is_not_in_the_cache(self):
        # Only what was decrypted is remembered. Caching what the server
        # *encrypts* would refuse its own next reply with a repeated
        # nonce, and the two directions do not share a cache.
        before = len(self.crypto.seen_envelopes)
        self.crypto.wrap({"ack": True})
        self.crypto.wrap({"ack": True})
        self.assertEqual(len(self.crypto.seen_envelopes), before)


class TestTheOldBehaviourIsGone(ReplayCase):
    def test_the_known_limits_entry_no_longer_claims_there_is_no_cache(self):
        limits = (REPO_ROOT / "docs" / "AGENT.md").read_text()
        self.assertNotIn("no seen-message cache", limits)
        self.assertNotIn("A captured message is enough; the key is not "
                         "needed.", limits)


if __name__ == "__main__":
    unittest.main()
