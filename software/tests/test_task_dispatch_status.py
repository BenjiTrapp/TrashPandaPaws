#!/usr/bin/env python3
"""`GET /api/tasks/<id>` tells "not delivered yet" from "you will never hear".

`/api/tasks/<task_id>` answered from `results` alone, and nothing on the
DNS channel ever produces a result -- it is tasking only, by construction.
So a task sitting in the queue and a task delivered over DNS gave the same
answer, `pending`, for ever. The interface flags the agent (`VIA DNS`) and
the panel states the limit, but the task's own status did not.

The fix is `dispatched`, and it is reported for every transport rather
than only for DNS: the server cannot tell an HTTPS check-in from an SMB or
QUIC one -- all three arrive as an HTTP POST on the agent socket -- so
"delivered" is the honest word for all of them, and over HTTPS it is
simply followed by a result.

The lifetime is `results`' lifetime, deliberately: neither survives a
restart (`_save_state` persists agents, history, the scan store and the
name counter). A record that outlived the results it is read beside would
answer `dispatched` for a task whose result had been forgotten.
"""

import base64
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.c2 import server as server_mod


class DispatchCase(unittest.TestCase):
    TOKEN = "test-operator-token"
    LISTENER_TOKEN = "test-listener-token"

    def setUp(self):
        for store in (server_mod.agents, server_mod.task_queues,
                      server_mod.history, server_mod.results,
                      server_mod.dispatches):
            store.clear()
            self.addCleanup(store.clear)
        server_mod._name_counter = 0
        self.data_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.data_dir, ignore_errors=True)
        self.crypto = server_mod.ServerCrypto(b"k" * 32)
        app = server_mod.create_app(self.crypto, self.TOKEN, self.data_dir,
                                    listener_token=self.LISTENER_TOKEN)
        app.config["TESTING"] = True
        self.client = app.test_client()
        self.auth = {"Authorization": "Bearer " + self.TOKEN}

    def register(self, implant_id="implant-1"):
        reply = self.client.post("/api/v1/beacon", data=json.dumps(
            self.crypto.wrap({"action": "register", "id": implant_id,
                              "hostname": "h", "user": "u"})),
            content_type="application/json")
        return self.crypto.unwrap(reply.get_json())["agent_id"]

    def queue(self, agent_id, cmd="shell", args="id"):
        reply = self.client.post("/api/agents/%s/task" % agent_id,
                                 json={"cmd": cmd, "args": args},
                                 headers=self.auth)
        return reply.get_json()["id"]

    def status_of(self, task_id):
        reply = self.client.get("/api/tasks/%s" % task_id, headers=self.auth)
        self.assertEqual(reply.status_code, 200)
        return reply.get_json()

    def check_in(self, agent_id):
        reply = self.client.post("/api/v1/beacon", data=json.dumps(
            self.crypto.wrap({"action": "beacon", "agent_id": agent_id,
                              "id": "implant-1"})),
            content_type="application/json")
        return self.crypto.unwrap(reply.get_json())


class TestAQueuedTaskIsStillPending(DispatchCase):
    def test_a_task_nobody_has_collected_reads_pending(self):
        agent_id = self.register()
        task_id = self.queue(agent_id)
        self.assertEqual(self.status_of(task_id)["status"], "pending")

    def test_a_task_id_nobody_ever_queued_reads_pending(self):
        # The endpoint has never distinguished an unknown id from a queued
        # one and this change does not make it: the id is not a secret and
        # answering 404 would turn it into an oracle for which ids exist.
        self.assertEqual(self.status_of("no-such-task")["status"], "pending")


class TestADeliveredTaskReadsDispatched(DispatchCase):
    def test_a_task_taken_by_a_check_in_reads_dispatched(self):
        agent_id = self.register()
        task_id = self.queue(agent_id)
        self.assertEqual(self.check_in(agent_id)["id"], task_id)
        answer = self.status_of(task_id)
        self.assertEqual(answer["status"], "dispatched")
        self.assertEqual(answer["task_id"], task_id)
        self.assertTrue(answer.get("dispatched"),
                        "the answer does not say when it went out")

    def test_a_task_taken_over_dns_reads_dispatched(self):
        # The channel the finding is about: nothing ever comes back, so
        # this is the only status the task will ever have.
        agent_id = self.register()
        task_id = self.queue(agent_id)
        reply = self.client.get(
            "/api/v1/dns/implant-1",
            headers={"X-Listener-Token": self.LISTENER_TOKEN})
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(self.crypto.unwrap(reply.get_json())["id"], task_id)
        self.assertEqual(self.status_of(task_id)["status"], "dispatched")

    def test_a_result_still_wins_over_the_dispatch_record(self):
        agent_id = self.register()
        task_id = self.queue(agent_id)
        self.check_in(agent_id)
        self.client.post("/api/v1/beacon", data=json.dumps(
            self.crypto.wrap({"action": "result", "agent_id": agent_id,
                              "task_id": task_id, "status": "ok",
                              "output": "uid=0"})),
            content_type="application/json")
        answer = self.status_of(task_id)
        self.assertEqual(answer["status"], "ok")
        self.assertEqual(answer["output"], "uid=0")

    def test_every_task_of_a_batch_is_recorded(self):
        agent_id = self.register()
        server_mod.agents[agent_id]["caps"] = ["batch"]
        ids = [self.queue(agent_id, args="id%d" % n) for n in range(3)]
        answer = self.check_in(agent_id)
        self.assertEqual([t["id"] for t in answer["tasks"]], ids)
        for task_id in ids:
            with self.subTest(task_id=task_id):
                self.assertEqual(self.status_of(task_id)["status"],
                                 "dispatched")


class TestTheRecordIsBounded(DispatchCase):
    def test_the_record_does_not_grow_without_bound(self):
        # One dict per delivered task, on a route a beacon reaches as often
        # as it likes. `results` has the same shape and the same exposure,
        # and the missing cap on it is a separate recorded finding; this
        # one is not going to add a second instance of it.
        agent_id = self.register()
        limit = server_mod.DISPATCHES_MAX
        for n in range(limit + 25):
            task_id = self.queue(agent_id, args="n%d" % n)
            self.check_in(agent_id)
            del task_id
        self.assertLessEqual(len(server_mod.dispatches), limit)

    def test_the_newest_dispatches_are_the_ones_kept(self):
        agent_id = self.register()
        ids = []
        for n in range(server_mod.DISPATCHES_MAX + 5):
            ids.append(self.queue(agent_id, args="n%d" % n))
            self.check_in(agent_id)
        self.assertEqual(self.status_of(ids[-1])["status"], "dispatched")
        self.assertEqual(self.status_of(ids[0])["status"], "pending")


class TestTheAgentClientStillWaits(unittest.TestCase):
    """`dispatched` must not read as "finished" to the agent.

    `get_task_result` returns None while a status is in flight and a result
    otherwise, and `await_task` polls on that. A new in-flight status the
    client did not know would have made every dispatched task look like a
    finished one with no output -- which is how a status change to an API
    somebody polls goes wrong.
    """

    def test_dispatched_counts_as_in_flight(self):
        from software.agent import c2client

        self.assertIn("pending", c2client._TASK_IN_FLIGHT)
        self.assertIn("dispatched", c2client._TASK_IN_FLIGHT)

    def test_a_dispatched_answer_is_not_a_result(self):
        import asyncio
        from unittest import mock

        from software.agent import c2client

        client = c2client.C2Client("http://127.0.0.1:1", "t")
        with mock.patch.object(
                client, "_request",
                side_effect=mock.AsyncMock(return_value={
                    "task_id": "t1", "status": "dispatched",
                    "dispatched": "2026-11-28 00:00:00"})):
            self.assertIsNone(
                asyncio.run(client.get_task_result("t1")),
                "a dispatched task was read as a finished one")


class TestTheOperatorPageIsUnaffected(unittest.TestCase):
    """The history entry's status stays `pending` until a result arrives.

    Seven places in the operator page read `status === "pending"` on a
    history entry to mean "still in flight", and three more do it
    server-side. Marking history `dispatched` would have made all ten read
    a delivered task as finished with no output. The dispatch record is
    kept beside `results` instead, which is what `/api/tasks/<id>` reads
    and what nothing in the page does.
    """

    def test_the_history_entry_is_not_marked_dispatched(self):
        source = (REPO_ROOT / "software" / "c2" / "server.py").read_text()
        start = source.find("def _dispatch_for")
        body = source[start:source.find("\ndef ", start + 1)]
        self.assertIn("dispatched", body)
        self.assertNotIn("history", body,
                         "_dispatch_for touches history, and ten readers "
                         "take a history status of pending to mean in "
                         "flight")


class TestWhatTheDocumentsSay(unittest.TestCase):
    def test_known_limits_no_longer_says_a_dns_task_stays_pending(self):
        text = (REPO_ROOT / "docs" / "AGENT.md").read_text()
        self.assertNotIn("stays `pending` for ever", text)

    def test_the_panel_tag_still_warns_that_no_result_comes_back(self):
        # The status change does not make the limit go away: the task is
        # delivered and its outcome is still never reported. The tag that
        # says so has to stay.
        source = (REPO_ROOT / "software" / "c2" / "server.py").read_text()
        tag = source[source.find("VIA DNS") - 900:source.find("VIA DNS")]
        self.assertIn("result is never reported", tag)


if __name__ == "__main__":
    unittest.main()
