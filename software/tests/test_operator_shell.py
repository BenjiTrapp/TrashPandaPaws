#!/usr/bin/env python3
"""Tests for the operator shell's server-side logic.

The feature's anti-goal is a channel left open on the target device while
the operator believes it closed. The claim tests below are about exactly
that: every way the bookkeeping could forget a stop it owes.
"""

import ast
import base64
import hashlib
import json
import os
import selectors
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.c2 import beacon, opshell


class _ClaimsCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "opshell-owned.json"


class TestTheClaimCounts(_ClaimsCase):
    def test_the_last_session_out_is_the_one_that_closes(self):
        c = opshell.Claims(self.path)
        a, b = c.open("raccoon-bandit"), c.open("raccoon-bandit")
        self.assertFalse(c.close("raccoon-bandit", a))
        self.assertTrue(c.close("raccoon-bandit", b))

    def test_a_second_browser_does_not_lose_the_first_ones_channel(self):
        # Review Focus 3. One bearer token, two views: the refcount is the
        # only thing standing between `exit` in one tab and a dead session
        # in the other.
        c = opshell.Claims(self.path)
        first = c.open("raccoon-bandit")
        c.open("raccoon-bandit")
        c.close("raccoon-bandit", first)
        self.assertEqual(c.sessions("raccoon-bandit"), 1)

    def test_a_silent_browser_lapses_and_a_beating_one_does_not(self):
        # The beat is made part-way through the grace, with the clock
        # pinned: a beat made "now" and a check made "now + 11" would
        # leave both sessions equally stale.
        c = opshell.Claims(self.path, grace=10.0)
        with unittest.mock.patch.object(opshell.time, "time", return_value=1000.0):
            c.open("quiet-one")
            alive = c.open("alive-one")
        with unittest.mock.patch.object(opshell.time, "time", return_value=1008.0):
            c.beat("alive-one", alive)
        self.assertEqual(c.lapsed(now=1011.0), ["quiet-one"])
        self.assertEqual(c.sessions("alive-one"), 1)

    def test_a_session_exactly_at_the_grace_has_not_lapsed(self):
        c = opshell.Claims(self.path, grace=10.0)
        with unittest.mock.patch.object(opshell.time, "time", return_value=1000.0):
            c.open("raccoon-bandit")
        self.assertEqual(c.lapsed(now=1010.0), [])
        self.assertEqual(c.lapsed(now=1010.5), ["raccoon-bandit"])

    def test_a_stale_session_beside_a_live_one_is_not_left_in_the_count(self):
        # A browser that died while another tab stays open. If the ghost
        # stayed in the count, the live tab's `exit` would answer "not the
        # last", no stop would be queued, and the channel would stand.
        c = opshell.Claims(self.path, grace=10.0)
        with unittest.mock.patch.object(opshell.time, "time", return_value=1000.0):
            c.open("raccoon-bandit")
            live = c.open("raccoon-bandit")
        with unittest.mock.patch.object(opshell.time, "time", return_value=1008.0):
            c.beat("raccoon-bandit", live)
        self.assertEqual(c.lapsed(now=1012.0), [])
        self.assertEqual(c.sessions("raccoon-bandit"), 1)
        self.assertTrue(c.close("raccoon-bandit", live))

    def test_a_lapsed_claim_is_reported_once_and_not_revived_by_a_late_beat(self):
        c = opshell.Claims(self.path, grace=10.0)
        with unittest.mock.patch.object(opshell.time, "time", return_value=1000.0):
            sid = c.open("raccoon-bandit")
        self.assertEqual(c.lapsed(now=1020.0), ["raccoon-bandit"])
        self.assertEqual(c.lapsed(now=1021.0), [])
        c.beat("raccoon-bandit", sid)
        self.assertEqual(c.sessions("raccoon-bandit"), 0)
        self.assertFalse(c.close("raccoon-bandit", sid))

    def test_closing_a_session_that_is_not_held_is_not_a_last_close(self):
        c = opshell.Claims(self.path)
        c.open("raccoon-bandit")
        self.assertFalse(c.close("raccoon-bandit", "not-a-session"))
        self.assertFalse(c.close("never-opened", "x"))
        self.assertEqual(c.sessions("raccoon-bandit"), 1)


class TestOwnershipIsPersisted(_ClaimsCase):
    def test_ownership_survives_a_restart_and_reconciles(self):
        # The anti-goal: a restart between start and stop must not leave a
        # channel with nobody to close it.
        opshell.Claims(self.path).open("raccoon-bandit")
        fresh = opshell.Claims(self.path)          # a new process
        self.assertEqual(fresh.owned(), ["raccoon-bandit"])
        self.assertEqual(opshell.reconcile(fresh, ["raccoon-bandit"]),
                         ["raccoon-bandit"])

    def test_an_agent_that_vanished_is_forgotten_not_reported_closed(self):
        # Review Focus 1. No agent, no task, no honest claim of closure.
        c = opshell.Claims(self.path)
        c.open("gone-raccoon")
        self.assertEqual(opshell.reconcile(c, []), [])
        self.assertEqual(c.owned(), [])
        self.assertEqual(opshell.Claims(self.path).owned(), [])

    def test_closing_the_last_session_keeps_ownership_until_the_stop_is_seen(self):
        # Closing only queues the stop. If ownership went with the last
        # session, a restart before the beacon's next check-in would find
        # nothing owed and the stop would never be re-queued.
        c = opshell.Claims(self.path)
        sid = c.open("raccoon-bandit")
        self.assertTrue(c.close("raccoon-bandit", sid))
        fresh = opshell.Claims(self.path)
        self.assertEqual(opshell.reconcile(fresh, ["raccoon-bandit"]),
                         ["raccoon-bandit"])
        self.assertTrue(fresh.release("raccoon-bandit"))
        self.assertEqual(opshell.Claims(self.path).owned(), [])

    def test_release_after_the_stop_is_seen_drops_ownership(self):
        c = opshell.Claims(self.path)
        sid = c.open("raccoon-bandit")
        c.close("raccoon-bandit", sid)
        self.assertTrue(c.release("raccoon-bandit"))
        self.assertEqual(c.owned(), [])
        self.assertEqual(opshell.Claims(self.path).owned(), [])

    def test_a_view_opened_after_the_stop_keeps_its_claim_through_the_release(self):
        # The start-after-stop race. The last view closes (stop queued),
        # another opens (start queued after it), then the stop is
        # acknowledged. Releasing ownership there would leave a channel
        # open with no owner and no pending stop: the live view's `exit`
        # would answer "not the last" and a restart would reconcile to
        # nothing.
        c = opshell.Claims(self.path)
        old = c.open("raccoon-bandit")
        self.assertTrue(c.close("raccoon-bandit", old))
        new = c.open("raccoon-bandit")
        self.assertFalse(c.release("raccoon-bandit"))
        self.assertEqual(c.sessions("raccoon-bandit"), 1)
        self.assertEqual(c.owned(), ["raccoon-bandit"])
        self.assertEqual(opshell.Claims(self.path).owned(), ["raccoon-bandit"])
        self.assertTrue(c.close("raccoon-bandit", new))

    def test_releasing_a_channel_that_is_not_owned_is_not_a_release(self):
        c = opshell.Claims(self.path)
        self.assertFalse(c.release("never-opened"))

    def test_forget_is_for_an_agent_that_is_gone_and_takes_its_claims_with_it(self):
        c = opshell.Claims(self.path)
        c.open("gone-raccoon")
        c.forget("gone-raccoon")
        self.assertEqual(c.sessions("gone-raccoon"), 0)
        self.assertEqual(c.owned(), [])

    def test_a_live_claim_is_not_owed_a_stop(self):
        c = opshell.Claims(self.path)
        c.open("raccoon-bandit")
        self.assertEqual(opshell.reconcile(c, ["raccoon-bandit"]), [])
        self.assertEqual(c.owned(), ["raccoon-bandit"])

    def test_a_channel_this_view_did_not_start_is_not_owned(self):
        c = opshell.Claims(self.path)
        c.open("raccoon-bandit")
        self.assertEqual(opshell.reconcile(c, ["raccoon-bandit", "other-one"]), [])
        self.assertEqual(c.owned(), ["raccoon-bandit"])

    def test_the_record_is_private_and_says_only_whose_channel_it_is(self):
        opshell.Claims(self.path).open("raccoon-bandit")
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        record = json.loads(self.path.read_text())
        self.assertEqual(list(record), ["raccoon-bandit"])
        self.assertEqual(list(record["raccoon-bandit"]), ["since"])

    def test_the_record_stays_private_when_rewritten_under_a_loose_umask(self):
        c = opshell.Claims(self.path)
        c.open("one")
        old = os.umask(0)
        try:
            c.open("two")
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_opening_again_does_not_move_the_ownership_date(self):
        c = opshell.Claims(self.path)
        c.open("raccoon-bandit")
        first = json.loads(self.path.read_text())["raccoon-bandit"]["since"]
        with unittest.mock.patch.object(opshell, "_now_iso", return_value="2999-01-01T00:00:00+00:00"):
            c.open("raccoon-bandit")
        self.assertEqual(json.loads(self.path.read_text())["raccoon-bandit"]["since"], first)

    def test_a_claim_is_not_taken_when_the_record_cannot_be_written(self):
        # Starting a channel on the strength of a record that was never
        # saved is the anti-goal with a delay.
        c = opshell.Claims(self.path)
        with unittest.mock.patch.object(opshell.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                c.open("raccoon-bandit")
        self.assertEqual(c.sessions("raccoon-bandit"), 0)
        self.assertEqual(c.owned(), [])
        self.assertEqual([p.name for p in self.path.parent.iterdir()], [])

    def test_a_damaged_record_is_an_error_not_an_empty_fleet(self):
        # Treating a damaged file as "owns nothing" would drop every stop
        # that was owed without anyone being told.
        self.path.write_text("{not json")
        with self.assertRaises(opshell.OwnershipRecordError) as raised:
            opshell.Claims(self.path)
        self.assertIn(str(self.path), str(raised.exception))
        self.assertEqual(raised.exception.path, self.path)

    def test_a_record_that_is_not_an_object_is_the_same_error(self):
        self.path.write_text("[]")
        with self.assertRaises(opshell.OwnershipRecordError) as raised:
            opshell.Claims(self.path)
        self.assertIn(str(self.path), str(raised.exception))

    def test_a_record_that_cannot_be_read_is_the_same_error(self):
        # One `except` for the caller: damaged and unreadable both mean
        # "do not guess what was owned".
        self.path.write_text("{}")
        with unittest.mock.patch.object(Path, "read_text", side_effect=PermissionError("denied")):
            with self.assertRaises(opshell.OwnershipRecordError) as raised:
                opshell.Claims(self.path)
        self.assertIn(str(self.path), str(raised.exception))

    def test_the_record_error_is_a_value_error(self):
        self.assertTrue(issubclass(opshell.OwnershipRecordError, ValueError))


def _route_dict_keys():
    """Key sets of the dict literals `api_create_task` builds in server.py.

    Returns (task_keys, history_keys) read from the source, so a test can
    hold `queue_tunnel` to the route's shape without importing the server.
    """
    source = (Path(__file__).parent.parent / "c2" / "server.py").read_text()
    route = next(n for n in ast.walk(ast.parse(source))
                 if isinstance(n, ast.FunctionDef) and n.name == "api_create_task")
    task_keys = history_keys = None
    for node in ast.walk(route):
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict)
                and [t.id for t in node.targets if isinstance(t, ast.Name)] == ["task"]):
            task_keys = [k.value for k in node.value.keys]
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "append" and node.args
                and isinstance(node.args[0], ast.Dict)):
            history_keys = [k.value for k in node.args[0].keys]
    return task_keys, history_keys


class TestRaisingAndDroppingTheChannel(unittest.TestCase):
    def test_start_is_queued_as_an_operator_lane_tunnel_task(self):
        queues, hist = {}, {}
        task = opshell.queue_tunnel("raccoon-bandit", "start", queues, hist, "now")
        self.assertEqual((task["cmd"], task["args"], task["lane"]),
                         ("tunnel", "start", "operator"))
        self.assertEqual(queues["raccoon-bandit"], [task])

    def test_a_live_socks_session_forbids_the_stop(self):
        ok, why = opshell.may_stop({"socks": {"sessions": 1}}, owned=True)
        self.assertFalse(ok)
        self.assertIn("socks", why.lower())

    def test_a_channel_this_view_did_not_start_is_left_alone(self):
        ok, why = opshell.may_stop({"socks": {"sessions": 0}}, owned=False)
        self.assertFalse(ok)

    def test_an_owned_idle_channel_may_be_stopped(self):
        ok, _ = opshell.may_stop({"socks": {"sessions": 0}}, owned=True)
        self.assertTrue(ok)

    def test_the_expected_checkin_counts_down_from_the_last_one(self):
        agent = {"_last_seen_ts": 1000.0, "interval": 300}
        self.assertEqual(opshell.expected_checkin(agent, now=1100.0), 200.0)
        self.assertIsNone(opshell.expected_checkin({}, now=1100.0))

    # -- beyond the brief's five ------------------------------------------

    def test_the_task_has_exactly_the_keys_the_route_gives_its_tasks(self):
        # A task missing a key the dispatcher reads is a task the implant
        # never runs, and a channel that never rises. The route's own source
        # is the reference, so the two cannot drift apart unnoticed.
        task_keys, _ = _route_dict_keys()
        task = opshell.queue_tunnel("raccoon-bandit", "start", {}, {}, "now")
        self.assertEqual(sorted(task), sorted(task_keys))
        self.assertEqual((task["data"], task["timeout"], task["status"], task["queued"]),
                         ("", 300, "pending", "now"))
        self.assertTrue(task["id"])

    def test_the_task_is_recorded_in_the_agents_history_as_the_route_records_it(self):
        # The operator must be able to see in the history that this
        # feature queued a task, in the shape the history view reads.
        _, history_keys = _route_dict_keys()
        queues, hist = {}, {}
        task = opshell.queue_tunnel("raccoon-bandit", "stop", queues, hist, "now")
        entry, = hist["raccoon-bandit"]
        self.assertEqual(sorted(entry), sorted(history_keys))
        self.assertEqual(entry, {"task_id": task["id"], "cmd": "tunnel",
                                 "args": "stop", "lane": "operator",
                                 "timestamp": "now", "status": "pending",
                                 "output": None})

    def test_a_queued_task_goes_behind_what_is_already_waiting(self):
        # Replacing the agent's queue would silently drop another task.
        waiting = {"id": "old", "cmd": "ls"}
        queues, hist = {"raccoon-bandit": [waiting]}, {"raccoon-bandit": [{"task_id": "old"}]}
        task = opshell.queue_tunnel("raccoon-bandit", "start", queues, hist, "now")
        self.assertEqual(queues["raccoon-bandit"], [waiting, task])
        self.assertEqual(len(hist["raccoon-bandit"]), 2)

    def test_only_start_and_stop_can_be_queued(self):
        # The feature's tasks are `tunnel start` and `tunnel stop`. Anything
        # else, `sleep` above all, is not this module's to queue.
        queues, hist = {}, {}
        for action in ("sleep", "restart", "", "START"):
            with self.assertRaises(ValueError):
                opshell.queue_tunnel("raccoon-bandit", action, queues, hist, "now")
        self.assertEqual((queues, hist), ({}, {}))

    def test_two_queued_tasks_do_not_share_an_id(self):
        queues = {}
        a = opshell.queue_tunnel("raccoon-bandit", "start", queues, {}, "now")
        b = opshell.queue_tunnel("raccoon-bandit", "stop", queues, {}, "now")
        self.assertNotEqual(a["id"], b["id"])

    def test_an_endpoint_that_is_not_connected_cannot_be_checked_so_no_stop(self):
        # No row means no report of SOCKS sessions, and the stop rule asks
        # for that report. The reason says why, so the view can show it.
        ok, why = opshell.may_stop(None, owned=True)
        self.assertFalse(ok)
        self.assertIn("connected", why)

    def test_a_row_that_does_not_say_how_many_socks_sessions_is_not_idle(self):
        # Absence of a number is not a zero.
        for row in ({}, {"socks": {}}, {"socks": {"sessions": None}},
                    {"socks": {"sessions": "0"}}, {"socks": {"sessions": True}},
                    {"socks": "up"}):
            ok, why = opshell.may_stop(row, owned=True)
            self.assertFalse(ok, row)
            self.assertIn("socks", why.lower())

    def test_an_endpoint_with_no_socks_port_open_has_no_session_to_protect(self):
        # The tunnel server's row says `socks: None` when no SOCKS port is
        # open. A shell-only channel must still be closable.
        ok, _ = opshell.may_stop({"socks": None}, owned=True)
        self.assertTrue(ok)

    def test_being_unowned_wins_over_an_idle_socks_port(self):
        ok, why = opshell.may_stop({"socks": None}, owned=False)
        self.assertFalse(ok)
        self.assertNotIn("socks", why.lower())

    def test_an_overdue_beacon_is_a_negative_number_not_an_error(self):
        agent = {"_last_seen_ts": 1000.0, "interval": 300}
        self.assertEqual(opshell.expected_checkin(agent, now=1400.0), -100.0)

    def test_an_agent_that_never_reported_an_interval_is_taken_at_the_default(self):
        # The server's own default, 300 s, applies where `interval` is absent.
        self.assertEqual(opshell.expected_checkin({"_last_seen_ts": 1000.0}, now=1100.0), 200.0)
        for junk in (None, "soon", True, [5]):
            agent = {"_last_seen_ts": 1000.0, "interval": junk}
            self.assertEqual(opshell.expected_checkin(agent, now=1100.0), 200.0, junk)

    def test_an_agent_with_a_timestamp_that_is_not_a_number_has_not_been_seen(self):
        self.assertIsNone(opshell.expected_checkin({"_last_seen_ts": None, "interval": 60}, now=5.0))
        self.assertIsNone(opshell.expected_checkin({"_last_seen_ts": "x", "interval": 60}, now=5.0))

    def test_reading_the_expected_checkin_never_writes_the_agent(self):
        # Nothing here may change a beacon's interval.
        agent = {"_last_seen_ts": 1000.0, "interval": 300}
        opshell.expected_checkin(agent, now=1100.0)
        self.assertEqual(agent, {"_last_seen_ts": 1000.0, "interval": 300})
        # The default is a reading, not something written back: an agent
        # that reported no interval must not be handed one.
        bare = {"_last_seen_ts": 1000.0}
        opshell.expected_checkin(bare, now=1100.0)
        self.assertEqual(bare, {"_last_seen_ts": 1000.0})


class _FakeShellPort:
    """A loopback listener that plays the shell port, once.

    It writes `prompt` (nothing at all when `prompt` is None), reads the
    one auth line, then writes `then` and either hangs up (`die_after_auth`)
    or holds the connection until `stop`. A prompt that is not the real one
    is a refusal in its place, as the accept loop writes them, and is
    followed by a half-close so the bridge sees the stream end. What the
    peer sent is `received()`; `first_line()` waits for the line itself.
    `hold`, an Event, keeps the prompt back until it is set, and
    `connected` says the bridge has dialled in. `drain=False` never reads
    past the line, so a large write to it ends up blocked.
    """

    PROMPT = b"password: "

    def __init__(self, prompt=PROMPT, then=b"", die_after_auth=False,
                 drip=False, hold=None, drain=True, quiet=0.0, late=b""):
        # `quiet` and `late`: stay silent for that many seconds after the
        # auth line, then write `late` and hang up. The only way to prove
        # that the route's pump treats a read timeout as "still open"
        # rather than as the end of the stream.
        self._prompt, self._then, self._die = prompt, then, die_after_auth
        self._quiet, self._late = quiet, late
        self._drip = drip
        self._hold = hold
        self._drain = drain
        self.connected = threading.Event()
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._listener.settimeout(0.05)
        self.port = self._listener.getsockname()[1]
        self._got_line = threading.Event()
        self._stop = threading.Event()
        self._chunks = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        conn = None
        try:
            while conn is None:
                if self._stop.is_set():
                    return
                try:
                    conn, _ = self._listener.accept()
                except socket.timeout:
                    pass
            self.connected.set()
            if self._hold is not None:
                self._hold.wait(10.0)
            if self._prompt is None:
                self._stop.wait(10.0)
                return
            if self._drip:
                for i in range(len(self._prompt)):
                    conn.sendall(self._prompt[i:i + 1])
                    time.sleep(0.02)
            else:
                conn.sendall(self._prompt)
            if self._prompt != self.PROMPT:
                conn.shutdown(socket.SHUT_WR)
            conn.settimeout(5.0)
            while b"\n" not in b"".join(self._chunks):
                chunk = conn.recv(4096)
                if not chunk:
                    break
                self._chunks.append(chunk)
            self._got_line.set()
            if self._then:
                conn.sendall(self._then)
            if self._quiet:
                if self._stop.wait(self._quiet):
                    return
                if self._late:
                    conn.sendall(self._late)
                conn.shutdown(socket.SHUT_WR)
                return
            conn.settimeout(0.05)
            if not self._drain:
                self._stop.wait(10.0)
            while self._drain and not self._die and not self._stop.is_set():
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                self._chunks.append(chunk)
        except OSError:
            pass
        finally:
            self._got_line.set()
            if conn is not None:
                conn.close()

    def first_line(self):
        self._got_line.wait(5.0)
        return b"".join(self._chunks).split(b"\n", 1)[0] + b"\n"

    def received(self):
        self._thread.join(5.0)
        return b"".join(self._chunks)

    def stop(self):
        self._stop.set()
        self._thread.join(5.0)
        self._listener.close()


class TestTheBridge(unittest.TestCase):
    def _fake(self, **kwargs):
        port = _FakeShellPort(**kwargs)
        self.addCleanup(port.stop)
        return port

    def _bridge(self, port, password="secret", cols=80, rows=24):
        b = opshell.Bridge(port.port, password, cols, rows)
        self.addCleanup(b.close)
        return b

    def test_the_auth_line_carries_the_password_then_the_geometry(self):
        self.assertEqual(opshell.auth_line("pw with space", 100, 30),
                         b"pw with space 100x30\n")

    def test_geometry_is_clamped_and_reported_as_sent(self):
        # Review Focus 5. The pty cannot be renegotiated, so what was sent
        # is the only truth the strip may state.
        b = opshell.Bridge(port=1, password="x", cols=0, rows=9000)
        self.assertEqual(b.geometry, (1, beacon.SHELL_GEOMETRY_MAX))

    def test_it_waits_for_the_prompt_before_sending(self):
        port = self._fake(prompt=b"password: ")
        b = self._bridge(port)
        b.connect()
        self.assertEqual(port.first_line(), b"secret 80x24\n")

    def test_a_refusal_arrives_as_bytes_on_the_stream(self):
        # Review Focus 2. ShellFront writes its refusal onto the stream;
        # the bridge must pass it through, not turn it into an exception.
        port = self._fake(prompt=b"password: ", then=b"too many sessions\n")
        b = self._bridge(port)
        b.connect()
        self.assertIn(b"too many sessions", b.read(timeout=2))

    def test_a_port_that_dies_ends_the_read_within_the_timeout(self):
        # Review Focus 4. A hang here is a view that lies about being live.
        port = self._fake(prompt=b"password: ", die_after_auth=True)
        b = self._bridge(port)
        b.connect()
        self.assertEqual(b.read(timeout=2), b"")

    def test_a_port_that_never_prompts_raises_inside_the_timeout(self):
        port = self._fake(prompt=None)
        started = time.monotonic()
        with self.assertRaises(OSError):
            self._bridge(port).connect(timeout=1.0)
        self.assertLess(time.monotonic() - started, 3.0)

    def test_a_refusal_in_place_of_the_prompt_is_shown_and_no_password_is_sent(self):
        # The accept loop refuses without ever prompting. That text is the
        # reason the operator is owed, and the password has no business
        # going to a peer that did not ask for it.
        refusal = b"raccoon: too many attach attempts\r\n"
        port = self._fake(prompt=refusal)
        b = self._bridge(port)
        b.connect()
        seen, chunk = b"", b.read(timeout=2)
        while chunk:
            seen, chunk = seen + chunk, b.read(timeout=2)
        self.assertEqual(seen, refusal)
        b.close()
        self.assertEqual(port.received(), b"")

    def test_a_peer_that_says_nothing_is_a_timeout_not_the_end(self):
        # `b""` means the stream ended. An idle shell is the normal state
        # of one, so silence must be told apart from it.
        port = self._fake(prompt=b"password: ")
        b = self._bridge(port)
        b.connect()
        with self.assertRaises(socket.timeout):
            b.read(timeout=0.2)
        self.assertTrue(b.is_open)

    def test_a_prompt_that_arrives_in_pieces_is_still_the_prompt(self):
        port = self._fake(prompt=b"password: ", drip=True)
        b = self._bridge(port)
        b.connect()
        self.assertEqual(port.first_line(), b"secret 80x24\n")

    def test_bytes_written_reach_the_port_whole(self):
        # Larger than a socket buffer's worth in one call: `sendall`, not
        # `send`, or the tail would go missing.
        port = self._fake(prompt=b"password: ")
        b = self._bridge(port)
        b.connect()
        payload = b"x" * 4000000 + b"\n"
        b.write(payload)
        b.close()
        got = port.received()
        self.assertEqual(got, b"secret 80x24\n" + payload)

    def test_closing_wakes_a_read_that_is_waiting(self):
        port = self._fake(prompt=b"password: ")
        b = self._bridge(port)
        b.connect()
        out = []
        reader = threading.Thread(target=lambda: out.append(b.read(timeout=5)))
        reader.start()
        time.sleep(0.2)
        b.close()
        reader.join(3.0)
        self.assertFalse(reader.is_alive())
        self.assertEqual(out, [b""])

    def test_a_password_with_a_line_ending_is_refused_not_truncated(self):
        for bad in ("a\nb", "a\rb"):
            with self.assertRaises(ValueError):
                opshell.auth_line(bad, 80, 24)

    def test_a_dimension_that_is_not_a_number_takes_the_default(self):
        for junk in (None, "wide", True, 80.5):
            b = opshell.Bridge(1, "x", junk, junk)
            self.assertEqual(b.geometry,
                             (beacon.SHELL_DEFAULT_COLS, beacon.SHELL_DEFAULT_ROWS), junk)

    def test_the_password_is_not_in_the_bridge_s_repr(self):
        b = opshell.Bridge(1, "hunter2", 80, 24)
        self.assertNotIn("hunter2", repr(b))

    def test_a_close_during_connect_leaves_no_session_behind(self):
        # The feature's anti-goal through a normal operator action: the
        # view is closed while the prompt is still awaited. The password
        # must not leave, and no live bridge may come back.
        hold = threading.Event()
        port = self._fake(prompt=b"password: ", hold=hold)
        b = opshell.Bridge(port.port, "secret", 80, 24)
        outcome = []

        def dial():
            try:
                b.connect(timeout=10.0)
                outcome.append("connected")
            except OSError as exc:
                outcome.append(exc)

        t = threading.Thread(target=dial, daemon=True)
        t.start()
        self.assertTrue(port.connected.wait(5.0))
        b.close()
        t.join(3.0)
        self.assertFalse(t.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], ConnectionError)
        self.assertFalse(b.is_open)
        hold.set()
        self.assertEqual(port.received(), b"")

    def test_a_close_before_connect_returns_is_not_undone_by_it(self):
        b = opshell.Bridge(1, "secret", 80, 24)
        b.close()
        with self.assertRaises(RuntimeError):
            b.connect()
        self.assertFalse(b.is_open)

    def test_closing_wakes_a_read_without_the_shutdown_s_help(self):
        # The socketpair is what makes the wake deterministic; with the
        # shutdown made a no-op, nothing else is left to do it.
        port = self._fake(prompt=b"password: ")
        b = self._bridge(port)
        b.connect()
        out = []
        reader = threading.Thread(target=lambda: out.append(b.read(timeout=5)),
                                  daemon=True)
        with unittest.mock.patch.object(socket.socket, "shutdown",
                                        lambda self, how: None):
            reader.start()
            time.sleep(0.2)
            started = time.monotonic()
            b.close()
            reader.join(3.0)
        self.assertFalse(reader.is_alive())
        self.assertEqual(out, [b""])
        self.assertLess(time.monotonic() - started, 1.0)

    def test_no_descriptor_outlives_the_bridge_on_any_path(self):
        # Every socket and selector the bridge makes is caught as it is
        # made and must be closed once the bridge is. Counting the
        # process's descriptors would be thrown off by whatever else a
        # 3500-test process has running.
        made = []

        def keep(real):
            def make(*args, **kwargs):
                out = real(*args, **kwargs)
                made.extend(out if isinstance(out, tuple) else [out])
                return out
            return make

        def closed(obj):
            if isinstance(obj, socket.socket):
                return obj.fileno() == -1
            return obj.get_map() is None

        cases = {
            "never connected": None,
            "connected and closed": dict(prompt=b"password: "),
            "refused in place of the prompt": dict(prompt=b"raccoon: no\r\n"),
            "hung up before a byte": dict(prompt=b""),
            "never prompted": dict(prompt=None),
        }
        for name, kwargs in cases.items():
            del made[:]
            port = self._fake(**kwargs) if kwargs is not None else None
            with unittest.mock.patch.object(
                    opshell.socket, "socketpair", keep(socket.socketpair)), \
                    unittest.mock.patch.object(
                        opshell.socket, "create_connection",
                        keep(socket.create_connection)), \
                    unittest.mock.patch.object(
                        opshell.selectors, "DefaultSelector",
                        keep(selectors.DefaultSelector)):
                b = opshell.Bridge(port.port if port else 1, "secret", 80, 24)
                if port is not None:
                    try:
                        b.connect(timeout=0.5)
                    except OSError:
                        pass
                b.close()
            # Two ends of the wake-up pair, the connection, the selector.
            self.assertEqual(len(made), 0 if port is None else 4, name)
            for obj in made:
                self.assertTrue(closed(obj), (name, obj))

    def test_closing_ends_a_write_that_is_blocked_on_a_peer_that_does_not_read(self):
        # The wake byte cannot reach a thread inside `sendall`; the
        # shutdown does.
        port = self._fake(prompt=b"password: ", drain=False)
        b = self._bridge(port)
        b.connect()
        out = []

        def push():
            try:
                b.write(b"x" * 64000000)
                out.append("sent")
            except OSError as exc:
                out.append(exc)

        writer = threading.Thread(target=push, daemon=True)
        writer.start()
        time.sleep(0.3)
        b.close()
        writer.join(3.0)
        self.assertFalse(writer.is_alive())
        self.assertEqual(len(out), 1)
        self.assertIsInstance(out[0], OSError)
        with self.assertRaises(BrokenPipeError):
            b.write(b"after")

    def test_a_port_that_hangs_up_without_a_byte_is_not_a_live_session(self):
        port = self._fake(prompt=b"")
        b = opshell.Bridge(port.port, "secret", 80, 24)
        self.addCleanup(b.close)
        with self.assertRaises(ConnectionError):
            b.connect(timeout=2.0)
        self.assertFalse(b.is_open)
        self.assertEqual(port.received(), b"")

    def test_the_bridge_says_whether_the_port_accepted_the_session(self):
        accepted = self._bridge(self._fake(prompt=b"password: "))
        accepted.connect()
        self.assertTrue(accepted.accepted)
        refused = self._bridge(self._fake(prompt=b"raccoon: too many\r\n"))
        refused.connect()
        self.assertFalse(refused.accepted)
        with self.assertRaises(OSError):
            refused.write(b"ls\n")

    def test_the_password_is_dropped_once_it_has_been_sent(self):
        port = self._fake(prompt=b"password: ")
        b = self._bridge(port, password="hunter2")
        self.assertEqual(b._password, "hunter2")
        b.connect()
        self.assertIsNone(b._password)

    def test_the_geometry_clamp_is_the_beacons(self):
        # `_dimension` mirrors `beacon._shell_geometry`, which is private
        # to that module; this is what notices the two drifting.
        for value in (0, 1, 80, 999, 1000, 1001, 9000, -5, None, "x",
                      True, 80.5):
            self.assertEqual(opshell._dimension(value, 77),
                             beacon._shell_geometry(value, 77), value)


class _RouteCase(unittest.TestCase):
    """A real app with the operator socket's own policy installed.

    `operator_port` is passed so the socket split exists: without it
    `create_app` allows everything on one socket, and the agent-socket test
    below would prove nothing.
    """

    OPERATOR_PORT = 18999
    TOKEN = "route-token"
    AGENT = "clumsy-raccoon"
    IMPLANT = "implant-1"
    SHELL_PASSWORD = "C06d-ScunJ-TGDoFbKx5EQ"

    ROUTES = (("/api/opshell/state", "GET"),
              ("/api/opshell/open", "POST"),
              ("/api/opshell/close", "POST"),
              ("/api/opshell/stream", "GET"),
              ("/api/opshell/keys", "POST"))

    def setUp(self):
        from software.c2 import server as server_mod

        self.sm = server_mod
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.data_dir = Path(tmp.name)
        self.crypto = server_mod.ServerCrypto(b"\x11" * 32)
        self.auth = {"Authorization": "Bearer " + self.TOKEN}

        server_mod.agents.clear()
        server_mod.task_queues.clear()
        server_mod.history.clear()
        del server_mod.event_log[:]
        self.addCleanup(server_mod.agents.clear)
        self.addCleanup(server_mod.task_queues.clear)
        self.addCleanup(server_mod.history.clear)
        self.addCleanup(lambda: server_mod.event_log.clear())
        server_mod.agents[self.AGENT] = {
            "id": self.IMPLANT, "agent_id": self.AGENT, "hostname": "parrot",
            "interval": 300, "_last_seen_ts": time.time(), "caps": ["batch"],
        }

    def app(self, supervisor="default"):
        if supervisor == "default":
            supervisor = self.connected()
        return self.sm.create_app(
            self.crypto, self.TOKEN, self.data_dir,
            operator_port=self.OPERATOR_PORT,
            tunnel_supervisor=supervisor)

    def client(self, **kw):
        """One app per test, cached.

        A new `create_app` per request is a server restart per request:
        the claim store is rebuilt empty while ownership sits on disk, so
        the start-up reconcile correctly swept every channel between two
        calls of the same test. That is right behaviour and a wrong
        fixture. Tests that want a restart build a second app on purpose.
        """
        key = tuple(sorted((k, id(v)) for k, v in kw.items()))
        cached = getattr(self, "_client_cache", None)
        if cached is None:
            cached = self._client_cache = {}
        if key not in cached:
            cached[key] = self.operator_client(self.app(**kw))
        return cached[key]

    OPERATOR_URL = "http://localhost:18999"

    def operator_client(self, app):
        """A client whose requests look as if they arrived on the operator
        socket.

        `create_app` judges a request by `SERVER_PORT`, and the test client
        goes through no socket at all -- so without this every request here
        would get the beacon catch-all's cover answer and every assertion
        would be about that instead of about the routes. Measured: setting
        `SERVER_PORT` in `environ_base` does **not** work, because werkzeug
        recomputes it from the URL; the port has to be in the URL itself.
        """
        client = app.test_client()
        client.operator_url = self.OPERATOR_URL
        return client

    def url(self, path):
        # Idempotent: the wrappers below prefix, and so do some call sites.
        if path.startswith("http"):
            return path
        return self.OPERATOR_URL + path

    # ── supervisors, in the states the routes must tell apart ──

    def _supervisor(self, status):
        class _Fake(object):
            def __init__(self):
                self.started = False

            def status(self):
                return status

            def start(self):
                self.started = True
                status["state"] = "running"
                return status

        return _Fake()

    def dead_port(self):
        """A port nothing listens on, for certain.

        Not a guessed number: 19630 is the first of the shipped shell range
        and it was live on the machine this was written on, so a guessed
        port made the stream route attach to a real service and the test
        hung. Bind one, read its number, close it.
        """
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        return port

    def connected(self, sessions=0, socks_sessions=0, user="root"):
        return self._supervisor({
            "state": "running", "can_control": True, "pid": 4242,
            "shell_port_first": 19630, "shell_port_last": 19640,
            "shell_transcript_dir": "/tmp/transcripts",
            "endpoints": [{
                "identity": "parrot-box", "implant_id": self.IMPLANT,
                "state": "connected", "user": user,
                "shell_port": self.dead_port(),
                "shell_password": self.SHELL_PASSWORD,
                "shell_recording": True,
                "shell": {"sessions": sessions, "max_sessions": 4},
                "socks": {"sessions": socks_sessions, "max_sessions": 256},
            }],
        })

    def configured_but_stopped(self):
        return self._supervisor({
            "state": "stopped", "can_control": True, "pid": None,
            "shell_port_first": 19630, "shell_port_last": 19640,
            "endpoints": [],
        })

    def running_without_shell_ports(self):
        return self._supervisor({
            "state": "running", "can_control": True, "pid": 4242,
            "shell_port_first": None, "shell_port_last": None,
            "endpoints": [],
        })

    def get(self, path, **kw):
        return self.client(**kw).get(self.url(path), headers=self.auth)

    def post(self, path, payload=None, **kw):
        return self.client(**kw).post(self.url(path), json=payload or {},
                                      headers=self.auth)


class TestTheRoutesAreOperatorOnly(_RouteCase):
    def test_every_route_needs_the_operator_token(self):
        client = self.client()
        for path, method in self.ROUTES:
            answer = client.open(self.url(path), method=method)
            self.assertEqual(answer.status_code, 401, path)

    def test_no_route_answers_on_the_agent_socket(self):
        # Exercised through the app, not compared against
        # _AGENT_SOCKET_ENDPOINTS: a frozenset of two is trivially true
        # today and would stay true if a route were added to it.
        #
        # The policy answers with the beacon catch-all's cover response
        # rather than a refusal, on purpose -- "a 403 or a 404 would tell a
        # prober what is listening" (server.py). So the assertion is that
        # the cover answer came back and the route's own body did not.
        client = self.client()
        on_operator = client.get(self.url("/api/opshell/state"), headers=self.auth)
        self.assertIn("channel", on_operator.get_json() or {},
                      "the state route must answer on the operator socket, "
                      "or this test cannot tell a hidden route from a "
                      "missing one")
        for path, method in self.ROUTES:
            answer = client.open("http://localhost:9999" + path,
                                 method=method, headers=self.auth)
            body = answer.get_json() or {}
            self.assertEqual(body.get("status"), "ok", path)
            self.assertNotIn("channel", body, path)
            self.assertNotIn("target", body, path)


class TestTheStateTellsTheTruth(_RouteCase):
    def test_no_response_body_carries_the_shell_password(self):
        self.post(self.url("/api/opshell/open"), {"agent": self.AGENT})
        state = self.get(self.url("/api/opshell/state"))
        self.assertIn("channel", state.get_json() or {},
                      "an empty body trivially contains no password; the "
                      "state route has to answer for this test to mean "
                      "anything")
        for path, method in self.ROUTES:
            answer = self.client().open(self.url(path), method=method,
                                        json={}, headers=self.auth)
            self.assertNotIn(self.SHELL_PASSWORD,
                             answer.get_data(as_text=True), path)

    def test_a_missing_tunnel_server_is_a_named_reason_not_a_500(self):
        state = self.get(self.url("/api/opshell/state"), supervisor=None).get_json()
        self.assertEqual(state["state"], "idle")
        self.assertTrue(state["reason"])

    def test_a_missing_shell_port_range_names_itself(self):
        state = self.get(self.url("/api/opshell/state"),
                         supervisor=self.running_without_shell_ports()
                         ).get_json()
        self.assertIn("shell port", state["reason"].lower())

    def test_the_candidates_are_the_fleet_not_a_guess_at_their_builds(self):
        # The design decided against pre-filtering: nothing at rest knows
        # which build carries a tunnel, and a refusal arrives with the
        # beacon's own answer instead.
        state = self.get(self.url("/api/opshell/state")).get_json()
        self.assertEqual(state["candidates"], [self.AGENT])

    def test_a_beacons_refusal_reaches_the_reason(self):
        self.sm.history[self.AGENT] = [{
            "task_id": "aa", "cmd": "tunnel", "args": "start",
            "status": "done",
            "output": "[error] Not starting a tunnel child: no tunnel block",
        }]
        self.post(self.url("/api/opshell/open"), {"agent": self.AGENT})
        state = self.get(self.url("/api/opshell/state")).get_json()
        self.assertIn("no tunnel block", state["reason"])


class TestOpeningTheChannel(_RouteCase):
    def test_open_queues_one_tunnel_start_and_nothing_else(self):
        self.post(self.url("/api/opshell/open"), {"agent": self.AGENT},
                  supervisor=self.configured_but_stopped())
        queued = [(t["cmd"], t["args"])
                  for t in self.sm.task_queues[self.AGENT]]
        self.assertEqual(queued, [("tunnel", "start")])

    def test_open_writes_the_audit_line(self):
        # queue_tunnel deliberately does not log -- _log_event lives in
        # server.py and calling it from opshell would close an import
        # cycle. The route is where the operator's action becomes findable.
        self.post(self.url("/api/opshell/open"), {"agent": self.AGENT},
                  supervisor=self.configured_but_stopped())
        kinds = [e.get("cat") for e in self.sm.event_log]
        self.assertIn("TASK", kinds)

    def test_a_second_open_does_not_queue_a_second_start(self):
        client = self.client(supervisor=self.configured_but_stopped())
        client.post(self.url("/api/opshell/open"), json={"agent": self.AGENT},
                    headers=self.auth)
        # No injected history: the entry the first call wrote is what
        # `_tunnel_pending` has to recognise, and replacing it would prove
        # only that the test's own dict is readable.
        client.post(self.url("/api/opshell/open"), json={"agent": self.AGENT},
                    headers=self.auth)
        starts = [t for t in self.sm.task_queues[self.AGENT]
                  if t["args"] == "start"]
        self.assertEqual(len(starts), 1)

    def test_open_starts_the_tunnel_server_when_it_is_configured_and_down(self):
        # The operator's rule: the server runs on this host, so starting it
        # costs the implant nothing and the glyph stays one click.
        supervisor = self.configured_but_stopped()
        app = self.sm.create_app(self.crypto, self.TOKEN, self.data_dir,
                                 operator_port=self.OPERATOR_PORT,
                                 tunnel_supervisor=supervisor)
        self.operator_client(app).post(self.url("/api/opshell/open"),
                                       json={"agent": self.AGENT},
                                       headers=self.auth)
        self.assertTrue(supervisor.started)

    def test_the_designated_target_is_remembered_across_app_restarts(self):
        self.post(self.url("/api/opshell/open"), {"agent": self.AGENT})
        fresh = self.sm.create_app(self.crypto, self.TOKEN, self.data_dir,
                                   operator_port=self.OPERATOR_PORT,
                                   tunnel_supervisor=self.connected())
        state = self.operator_client(fresh).get(
            self.url("/api/opshell/state"), headers=self.auth).get_json()
        self.assertEqual(state["target"], self.AGENT)

    def test_an_unknown_agent_is_refused_by_name(self):
        answer = self.post(self.url("/api/opshell/open"), {"agent": "no-such-raccoon"})
        self.assertEqual(answer.status_code, 404)
        self.assertEqual(self.sm.task_queues, {})


class TestClosingTheChannel(_RouteCase):
    def test_close_reports_closing_and_never_closed(self):
        client = self.client()
        opened = client.post(self.url("/api/opshell/open"),
                             json={"agent": self.AGENT},
                             headers=self.auth).get_json()
        state = client.post(self.url("/api/opshell/close"),
                            json={"session": opened["session"]},
                            headers=self.auth).get_json()
        self.assertEqual(state["state"], "closing")

    def test_close_queues_the_stop_and_logs_it(self):
        client = self.client()
        opened = client.post(self.url("/api/opshell/open"),
                             json={"agent": self.AGENT},
                             headers=self.auth).get_json()
        client.post(self.url("/api/opshell/close"),
                    json={"session": opened["session"]}, headers=self.auth)
        queued = [(t["cmd"], t["args"])
                  for t in self.sm.task_queues[self.AGENT]]
        self.assertIn(("tunnel", "stop"), queued)

    def test_a_live_socks_session_leaves_the_stop_owed_and_says_so(self):
        # The operator's rule: one child serves both ports, so closing the
        # terminal must not drop a pivot. The claim stays on file.
        client = self.client(supervisor=self.connected(socks_sessions=2))
        opened = client.post(self.url("/api/opshell/open"),
                             json={"agent": self.AGENT},
                             headers=self.auth).get_json()
        state = client.post(self.url("/api/opshell/close"),
                            json={"session": opened["session"]},
                            headers=self.auth).get_json()
        queued = [t["args"] for t in self.sm.task_queues.get(self.AGENT, [])]
        self.assertNotIn("stop", queued)
        self.assertEqual(state["channel"], "open")
        self.assertIn("socks", state["reason"].lower())

    def test_a_channel_the_agent_reports_is_stoppable_without_a_relay_row(self):
        # may_stop(None, owned=True) refuses by contract, because a None
        # row carries no SOCKS report. The beacon reports its own tunnel
        # state in its check-in, so the server can know without the relay
        # -- otherwise a relay outage leaves a channel open for ever.
        client = self.client(supervisor=self.configured_but_stopped())
        opened = client.post(self.url("/api/opshell/open"),
                             json={"agent": self.AGENT},
                             headers=self.auth).get_json()
        self.sm.agents[self.AGENT]["tunnel"] = {"running": True, "pid": 991}
        client.post(self.url("/api/opshell/close"),
                    json={"session": opened["session"]}, headers=self.auth)
        queued = [t["args"] for t in self.sm.task_queues.get(self.AGENT, [])]
        self.assertIn("stop", queued)


class TestNothingTouchesTheInterval(_RouteCase):
    def test_no_route_ever_queues_sleep(self):
        # A stopped tunnel server, so that `open` really does queue
        # something: with a channel already up it correctly queues nothing,
        # and then this test would be asserting against an empty queue.
        client = self.client(supervisor=self.configured_but_stopped())
        for path, payload in (("/api/opshell/open", {"agent": self.AGENT}),
                              ("/api/opshell/close", {}),
                              ("/api/opshell/keys", {"session": "x",
                                                     "data": ""})):
            client.post(self.url(path), json=payload, headers=self.auth)
        every = [t["cmd"] for q in self.sm.task_queues.values() for t in q]
        self.assertIn("tunnel", every,
                      "nothing was queued at all, so this test would pass "
                      "against routes that do not exist")
        self.assertNotIn("sleep", every)
        self.assertEqual(self.sm.agents[self.AGENT]["interval"], 300)


class TestADamagedOwnershipRecord(_RouteCase):
    def test_the_server_still_starts_and_the_view_says_what_it_cannot_know(self):
        # The module raises deliberately: reading a damaged record as "owns
        # nothing" would silently drop every owed stop. A C2 server that
        # refuses to boot because of a scratch file is the wrong trade, so
        # the route reports it instead.
        (self.data_dir / "opshell-owned.json").write_text("{not json")
        # The route logs the damaged record at error level, which is right
        # -- and noise in a test run is a finding of its own, so the log is
        # captured rather than left to print.
        with self.assertLogs("raccoon.c2.server", level="ERROR") as logged:
            state = self.get(self.url("/api/opshell/state")).get_json()
        self.assertTrue(any("ownership record" in line
                            for line in logged.output))
        self.assertEqual(state["channel"], "unknown")
        self.assertTrue(state["reason"])


class TestADeadTunnelChildIsNotALiveChannel(_RouteCase):
    """The beacon reports a child that has exited, on purpose.

    `beacon.py:7067-7074` reports `{"pid", "running": code is None,
    "source"}` plus `exit_code` once it is gone, and the comment at
    `:5306` says that report "is what confirms a stop they asked for". So
    a `pid` proves nothing about whether anything is running.
    """

    DEAD = {"pid": 991, "running": False, "exit_code": 0, "source": "task"}

    def test_an_exited_child_does_not_count_as_an_open_channel(self):
        self.sm.agents[self.AGENT]["tunnel"] = dict(self.DEAD)
        self.post(self.url("/api/opshell/open"), {"agent": self.AGENT},
                  supervisor=self.configured_but_stopped())
        state = self.get("/api/opshell/state",
                         supervisor=self.configured_but_stopped()).get_json()
        self.assertEqual(state["channel"], "closed")

    def test_the_glyph_still_opens_a_channel_after_the_last_one_died(self):
        # The defect this protects against stopped the feature working at
        # all: an acknowledged stop leaves `running: False` behind, and a
        # pid read as "open" meant no start was ever queued again.
        self.sm.agents[self.AGENT]["tunnel"] = dict(self.DEAD)
        self.post(self.url("/api/opshell/open"), {"agent": self.AGENT},
                  supervisor=self.configured_but_stopped())
        queued = [(t["cmd"], t["args"])
                  for t in self.sm.task_queues.get(self.AGENT, [])]
        self.assertEqual(queued, [("tunnel", "start")])

    def test_a_running_child_still_counts(self):
        client = self.client(supervisor=self.configured_but_stopped())
        client.post(self.url("/api/opshell/open"), json={"agent": self.AGENT},
                    headers=self.auth)
        self.sm.agents[self.AGENT]["tunnel"] = {"pid": 991, "running": True}
        state = client.get(self.url("/api/opshell/state"),
                           headers=self.auth).get_json()
        self.assertEqual(state["channel"], "open")


class TestTheSessionTheOperatorHolds(_RouteCase):
    """Whoever opened a session must be able to close it.

    `/open` used to create a claim and throw its id away, so no browser
    could ever close it: the refcount then said "not the last session" for
    sixty seconds and no stop was queued, and a close without an id
    bypassed the count altogether.
    """

    def test_open_hands_back_the_session_it_created(self):
        answer = self.post(self.url("/api/opshell/open"),
                           {"agent": self.AGENT})
        self.assertTrue((answer.get_json() or {}).get("session"))

    def test_the_session_it_handed_back_closes_the_channel(self):
        client = self.client(supervisor=self.connected())
        opened = client.post(self.url("/api/opshell/open"),
                             json={"agent": self.AGENT},
                             headers=self.auth).get_json()
        state = client.post(self.url("/api/opshell/close"),
                            json={"session": opened["session"]},
                            headers=self.auth).get_json()
        queued = [t["args"] for t in self.sm.task_queues.get(self.AGENT, [])]
        self.assertIn("stop", queued)
        self.assertEqual(state["state"], "closing")

    def test_a_close_without_a_session_is_refused_not_treated_as_the_last(self):
        client = self.client(supervisor=self.connected())
        client.post(self.url("/api/opshell/open"), json={"agent": self.AGENT},
                    headers=self.auth)
        answer = client.post(self.url("/api/opshell/close"), json={},
                             headers=self.auth)
        self.assertEqual(answer.status_code, 400)
        queued = [t["args"] for t in self.sm.task_queues.get(self.AGENT, [])]
        self.assertNotIn("stop", queued)

    def test_two_sessions_need_two_closes_in_either_order(self):
        for order in (0, 1):
            with self.subTest(order=order):
                self._two_closes(order)

    def _two_closes(self, order):
            self.sm.task_queues.clear()
            client = self.client(supervisor=self.connected())
            first = client.post(self.url("/api/opshell/open"),
                                json={"agent": self.AGENT},
                                headers=self.auth).get_json()["session"]
            second = client.post(self.url("/api/opshell/open"),
                                 json={"agent": self.AGENT},
                                 headers=self.auth).get_json()["session"]
            pair = [first, second] if order == 0 else [second, first]
            client.post(self.url("/api/opshell/close"),
                        json={"session": pair[0]}, headers=self.auth)
            queued = [t["args"]
                      for t in self.sm.task_queues.get(self.AGENT, [])]
            self.assertNotIn("stop", queued, "order %d" % order)
            client.post(self.url("/api/opshell/close"),
                        json={"session": pair[1]}, headers=self.auth)
            queued = [t["args"]
                      for t in self.sm.task_queues.get(self.AGENT, [])]
            self.assertIn("stop", queued, "order %d" % order)

    def test_a_refused_close_leaves_the_channel_owned(self):
        # Requirement 2 exists to stop a refusal being read as "done". A
        # release in that branch would leave the old test green, so this
        # one asserts the ownership that makes the stop still owed.
        client = self.client(supervisor=self.connected(socks_sessions=2))
        opened = client.post(self.url("/api/opshell/open"),
                             json={"agent": self.AGENT},
                             headers=self.auth).get_json()
        client.post(self.url("/api/opshell/close"),
                    json={"session": opened["session"]}, headers=self.auth)
        claims = opshell.Claims(self.data_dir / "opshell-owned.json")
        self.assertIn(self.AGENT, claims.owned())


class TestTheStreamAndTheKeystrokes(_RouteCase):
    """The pump, against a real loopback port that speaks the real wire.

    Nothing exercised `/stream`, `pump` or `/keys` before: every stream in
    the suite hit a dead port and answered 502, so four of the carried
    requirements were claimed and untested. `_FakeShellPort` already
    speaks the shell port's exchange, so the route can be driven end to
    end.
    """

    def _open(self, client):
        return client.post(self.url("/api/opshell/open"),
                           json={"agent": self.AGENT},
                           headers=self.auth).get_json()["session"]

    def _with_port(self, **kw):
        port = _FakeShellPort(**kw)
        self.addCleanup(port.stop)
        supervisor = self.connected()
        row = supervisor.status()["endpoints"][0]
        row["shell_port"] = port.port
        return port, self.client(supervisor=supervisor)

    def test_the_stream_carries_what_the_port_writes(self):
        # `die_after_auth` so that the stream ends: a port that stays open
        # and quiet keeps the stream open on purpose -- that is what a
        # terminal is -- and the test client reads a body to its end.
        port, client = self._with_port(then=b"root@parrot:~# ",
                                       die_after_auth=True)
        session = self._open(client)
        answer = client.get(
            self.url("/api/opshell/stream?session=" + session),
            headers=self.auth)
        self.assertEqual(answer.status_code, 200)
        self.assertIn(b"root@parrot", answer.get_data())

    def test_the_password_goes_on_the_wire_and_not_into_the_body(self):
        port, client = self._with_port(then=b"x", die_after_auth=True)
        session = self._open(client)
        answer = client.get(
            self.url("/api/opshell/stream?session=" + session),
            headers=self.auth)
        self.assertNotIn(self.SHELL_PASSWORD.encode(), answer.get_data())
        self.assertIn(self.SHELL_PASSWORD.encode(), port.first_line())

    def test_the_stream_reuses_the_session_the_operator_already_holds(self):
        # A second claim per stream was how `/open`'s session became an
        # orphan nobody could close.
        port, client = self._with_port(then=b"hi", die_after_auth=True)
        opened = client.post(self.url("/api/opshell/open"),
                             json={"agent": self.AGENT},
                             headers=self.auth).get_json()
        answer = client.get(
            self.url("/api/opshell/stream?session=" + opened["session"]),
            headers=self.auth)
        self.assertEqual(answer.headers["X-Opshell-Session"],
                         opened["session"])

    def test_a_finished_stream_leaves_the_browsers_claim_alone(self):
        # This test used to assert the opposite and was wrong: releasing
        # the browser's claim when the stream ended answered "that was the
        # last" inside cleanup, nothing queued a stop, and the browser's
        # later /close got False for a session that no longer existed. The
        # channel stayed up while the view said it had closed.
        port, client = self._with_port(then=b"bye", die_after_auth=True)
        opened = client.post(self.url("/api/opshell/open"),
                             json={"agent": self.AGENT},
                             headers=self.auth).get_json()
        answer = client.get(
            self.url("/api/opshell/stream?session=" + opened["session"]),
            headers=self.auth)
        answer.get_data()
        # Through the app, not through a fresh `Claims`: only ownership is
        # persisted, the sessions live in the app's own store, so a new
        # instance would report none of them and the assertion would pass
        # for the wrong reason.
        state = client.get(self.url("/api/opshell/state"),
                           headers=self.auth).get_json()
        self.assertEqual(state["sessions"], 1)

    def test_open_then_stream_then_close_queues_the_stop(self):
        # The path the review asked for by name, and the one the lost-stop
        # defect lived on.
        port, client = self._with_port(then=b"bye", die_after_auth=True)
        opened = client.post(self.url("/api/opshell/open"),
                             json={"agent": self.AGENT},
                             headers=self.auth).get_json()
        client.get(self.url("/api/opshell/stream?session=" + opened["session"]),
                   headers=self.auth).get_data()
        client.post(self.url("/api/opshell/close"),
                    json={"session": opened["session"]}, headers=self.auth)
        queued = [t["args"] for t in self.sm.task_queues.get(self.AGENT, [])]
        self.assertIn("stop", queued)

    def test_a_made_up_session_is_not_adopted(self):
        # `sessions(target) == 0` asked whether anybody was live, so a
        # stale or invented id was adopted whenever another tab was -- and
        # that stream then ran uncounted under the other tab's close.
        port, client = self._with_port(then=b"x", die_after_auth=True)
        self._open(client)
        answer = client.get(self.url("/api/opshell/stream?session=invented"),
                            headers=self.auth)
        self.assertEqual(answer.status_code, 400)

    def test_the_geometry_header_is_the_pair_that_was_sent(self):
        port, client = self._with_port(then=b"x", die_after_auth=True)
        session = self._open(client)
        answer = client.get(
            self.url("/api/opshell/stream?session=%s&cols=0&rows=9000"
                     % session), headers=self.auth)
        self.assertEqual(answer.headers["X-Opshell-Geometry"],
                         "1x%d" % beacon.SHELL_GEOMETRY_MAX)

    def test_keys_reach_the_port(self):
        # Without a stream: the route's contract is "write to the bridge
        # registered under this session", and a live stream cannot be held
        # open here because the test client reads a body to its end.
        port = _FakeShellPort(then=b"$ ")
        self.addCleanup(port.stop)
        bridge = opshell.Bridge(port.port, self.SHELL_PASSWORD, 80, 24)
        bridge.connect()
        self.addCleanup(bridge.close)
        self.sm.opshell_bridges["held"] = bridge
        self.addCleanup(lambda: self.sm.opshell_bridges.pop("held", None))
        wrote = self.client().post(
            self.url("/api/opshell/keys"),
            json={"session": "held",
                  "data": base64.b64encode(b"id\n").decode()},
            headers=self.auth)
        self.assertEqual(wrote.get_json()["written"], 3)
        for _ in range(40):
            if b"id" in port.received():
                break
            time.sleep(0.05)
        self.assertIn(b"id", port.received())

    def test_keys_for_an_unknown_session_are_refused(self):
        _, client = self._with_port()
        answer = client.post(self.url("/api/opshell/keys"),
                             json={"session": "nope", "data": ""},
                             headers=self.auth)
        self.assertEqual(answer.status_code, 404)

    def test_a_port_that_refuses_before_the_prompt_says_so_on_the_stream(self):
        # Two of the far end's refusals are written from its accept loop,
        # before any prompt. The operator must read the sentence, not a
        # broken pipe.
        port, client = self._with_port(prompt=b"raccoon: too many sessions\r\n",
                                       die_after_auth=True)
        session = self._open(client)
        answer = client.get(
            self.url("/api/opshell/stream?session=" + session),
            headers=self.auth)
        self.assertIn(b"too many sessions", answer.get_data())


class TestWhatOpenRefusesInsteadOfQueueing(_RouteCase):
    """A start queued into a setup that cannot carry it is worse than a no.

    The first version queued one anyway and then reported `idle`, so the
    operator saw nothing happening while a child was starting on the
    target.
    """

    def test_no_shell_port_range_is_a_refusal_and_queues_nothing(self):
        answer = self.post(self.url("/api/opshell/open"),
                           {"agent": self.AGENT},
                           supervisor=self.running_without_shell_ports())
        self.assertEqual(answer.status_code, 409)
        self.assertEqual(self.sm.task_queues, {})

    def test_no_tunnel_server_is_a_refusal_and_queues_nothing(self):
        answer = self.post(self.url("/api/opshell/open"),
                           {"agent": self.AGENT}, supervisor=None)
        self.assertEqual(answer.status_code, 409)
        self.assertEqual(self.sm.task_queues, {})

    def test_a_damaged_record_refuses_on_the_first_request_after_a_restart(self):
        # The guard used to read a flag that is only filled in lazily, so
        # the very first request after a restart sailed past it and queued a
        # start with nothing owning it.
        (self.data_dir / "opshell-owned.json").write_text("{not json")
        with self.assertLogs("raccoon.c2.server", level="ERROR"):
            answer = self.post(self.url("/api/opshell/open"),
                               {"agent": self.AGENT})
        self.assertEqual(answer.status_code, 409)
        self.assertEqual(self.sm.task_queues, {})


class TestTheStateDoesNotGoBlindOrStick(_RouteCase):
    def _target(self):
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": self.AGENT}))

    def test_a_channel_the_agent_reports_is_shown_with_no_supervisor(self):
        self._target()
        self.sm.agents[self.AGENT]["tunnel"] = {"pid": 9, "running": True}
        state = self.get("/api/opshell/state", supervisor=None).get_json()
        self.assertEqual((state["channel"], state["state"]), ("open", "live"))
        self.assertTrue(state["reason"])

    def test_a_channel_the_agent_reports_is_shown_without_shell_ports(self):
        self._target()
        self.sm.agents[self.AGENT]["tunnel"] = {"pid": 9, "running": True}
        state = self.get("/api/opshell/state",
                         supervisor=self.running_without_shell_ports()
                         ).get_json()
        self.assertEqual(state["channel"], "open")

    def test_an_answered_stop_stops_saying_closing_once_the_child_is_gone(self):
        self._target()
        self.sm.history[self.AGENT] = [{"task_id": "a", "cmd": "tunnel",
                                        "args": "stop", "status": "done",
                                        "output": "Tunnel stopped"}]
        self.sm.agents[self.AGENT]["tunnel"] = {"pid": 9, "running": False,
                                                "exit_code": 0}
        state = self.get("/api/opshell/state",
                         supervisor=self.configured_but_stopped()).get_json()
        self.assertEqual(state["state"], "idle")

    def test_an_answered_start_whose_child_died_does_not_say_waiting(self):
        self._target()
        self.sm.history[self.AGENT] = [{"task_id": "a", "cmd": "tunnel",
                                        "args": "start", "status": "done",
                                        "output": "Tunnel started pid 9"}]
        self.sm.agents[self.AGENT]["tunnel"] = {"pid": 9, "running": False,
                                                "exit_code": 1}
        state = self.get("/api/opshell/state",
                         supervisor=self.configured_but_stopped()).get_json()
        self.assertEqual(state["state"], "idle")

    def test_a_refused_start_reads_idle_with_the_reason_not_closing(self):
        self._target()
        self.sm.history[self.AGENT] = [{
            "task_id": "a", "cmd": "tunnel", "args": "start",
            "status": "done",
            "output": "[error] Not starting a tunnel child: no tunnel block"}]
        state = self.get("/api/opshell/state",
                         supervisor=self.configured_but_stopped()).get_json()
        self.assertEqual(state["state"], "idle")
        self.assertIn("no tunnel block", state["reason"])


class TestThePumpWaitsOutAQuietShell(_RouteCase):
    def test_a_silence_longer_than_the_read_timeout_does_not_end_the_stream(self):
        # Requirement 9, which was claimed and untested: `read` answers a
        # quiet peer with a timeout and only b"" ends the stream. The route
        # reads with a 5 s timeout, so the port stays silent for longer
        # than that before it speaks. Slow on purpose -- it is the only way
        # to prove the `continue`.
        port = _FakeShellPort(quiet=6.5, late=b"late output\n")
        self.addCleanup(port.stop)
        supervisor = self.connected()
        supervisor.status()["endpoints"][0]["shell_port"] = port.port
        client = self.client(supervisor=supervisor)
        session = client.post(self.url("/api/opshell/open"),
                              json={"agent": self.AGENT},
                              headers=self.auth).get_json()["session"]
        answer = client.get(
            self.url("/api/opshell/stream?session=" + session),
            headers=self.auth)
        self.assertIn(b"late output", answer.get_data())


class TestARefusedBridgeTellsKeysWhy(_RouteCase):
    def test_keys_answer_409_and_point_at_the_stream(self):
        # Requirement 8's other half. The far end writes two refusals from
        # its accept loop, before any prompt, so a bridge can be connected
        # and never accepted -- and a keystroke must not come back as a
        # broken pipe.
        port = _FakeShellPort(prompt=b"raccoon: too many sessions\r\n",
                              die_after_auth=True)
        self.addCleanup(port.stop)
        bridge = opshell.Bridge(port.port, self.SHELL_PASSWORD, 80, 24)
        bridge.connect()
        self.addCleanup(bridge.close)
        self.assertFalse(bridge.accepted)
        self.sm.opshell_bridges["refused"] = bridge
        self.addCleanup(lambda: self.sm.opshell_bridges.pop("refused", None))
        answer = self.client().post(
            self.url("/api/opshell/keys"),
            json={"session": "refused",
                  "data": base64.b64encode(b"id\n").decode()},
            headers=self.auth)
        self.assertEqual(answer.status_code, 409)
        self.assertTrue(answer.get_json()["refused"])


class TestTheOneDecisionPlace(_ClaimsCase):
    """`end_session`: close one session and owe or queue the stop.

    Four callers used to decide this with different knowledge, and two
    rounds of fixes each closed one hole and opened another. These tests
    are about the decision, not about a route.
    """

    def _args(self, claims, row, reports=False, queues=None, hist=None):
        return (claims, "raccoon-bandit", "s1", row, reports,
                queues if queues is not None else {},
                hist if hist is not None else {}, "now")

    def test_not_the_last_session_decides_nothing(self):
        claims = opshell.Claims(self.path)
        first = claims.open("raccoon-bandit")
        second = claims.open("raccoon-bandit")
        queues = {}
        queued, last, _ = opshell.end_session(
            claims, "raccoon-bandit", first, {"socks": {"sessions": 0}},
            False, queues, {}, "now")
        self.assertEqual((queued, last, queues), (False, False, {}))
        self.assertTrue(claims.holds("raccoon-bandit", second))

    def test_the_last_session_queues_the_stop(self):
        claims = opshell.Claims(self.path)
        only = claims.open("raccoon-bandit")
        queues = {}
        queued, last, _ = opshell.end_session(
            claims, "raccoon-bandit", only, {"socks": {"sessions": 0}},
            False, queues, {}, "now")
        self.assertTrue(queued and last)
        self.assertEqual([t["args"] for t in queues["raccoon-bandit"]],
                         ["stop"])

    def test_a_live_pivot_leaves_it_owed_with_a_reason(self):
        claims = opshell.Claims(self.path)
        only = claims.open("raccoon-bandit")
        queues = {}
        queued, last, why = opshell.end_session(
            claims, "raccoon-bandit", only, {"socks": {"sessions": 3}},
            False, queues, {}, "now")
        self.assertEqual((queued, last), (False, True))
        self.assertIn("socks", why.lower())
        self.assertEqual(queues, {})
        self.assertIn("raccoon-bandit", claims.owned())

    def test_a_channel_only_the_agent_reports_is_still_stoppable(self):
        claims = opshell.Claims(self.path)
        only = claims.open("raccoon-bandit")
        queues = {}
        queued, _last, _why = opshell.end_session(
            claims, "raccoon-bandit", only, None, True, queues, {}, "now")
        self.assertTrue(queued)


class TestTheSweepClosesWhatNobodyWatches(_ClaimsCase):
    def test_a_lapsed_claim_gets_its_stop_queued(self):
        claims = opshell.Claims(self.path, grace=10.0)
        claims.open("raccoon-bandit")
        queues = {}
        done = opshell.sweep(claims, ["raccoon-bandit"],
                             {"raccoon-bandit": {"socks": {"sessions": 0}}},
                             {"raccoon-bandit": False}, queues, {}, "now",
                             time.time() + 11)
        self.assertEqual(done, ["raccoon-bandit"])
        self.assertEqual([t["args"] for t in queues["raccoon-bandit"]],
                         ["stop"])

    def test_a_live_claim_is_left_alone(self):
        claims = opshell.Claims(self.path, grace=10.0)
        claims.open("raccoon-bandit")
        queues = {}
        done = opshell.sweep(claims, ["raccoon-bandit"],
                             {"raccoon-bandit": {"socks": {"sessions": 0}}},
                             {"raccoon-bandit": False}, queues, {}, "now",
                             time.time())
        self.assertEqual((done, queues), ([], {}))

    def test_a_lapsed_claim_over_a_live_pivot_is_not_dropped(self):
        claims = opshell.Claims(self.path, grace=10.0)
        claims.open("raccoon-bandit")
        queues = {}
        done = opshell.sweep(claims, ["raccoon-bandit"],
                             {"raccoon-bandit": {"socks": {"sessions": 2}}},
                             {"raccoon-bandit": False}, queues, {}, "now",
                             time.time() + 11)
        self.assertEqual((done, queues), ([], {}))
        self.assertIn("raccoon-bandit", claims.owned())

    def test_an_agent_that_left_the_fleet_is_forgotten_not_tasked(self):
        claims = opshell.Claims(self.path, grace=10.0)
        claims.open("gone-raccoon")
        queues = {}
        done = opshell.sweep(claims, [], {}, {}, queues, {}, "now",
                             time.time() + 11)
        self.assertEqual((done, queues), ([], {}))
        self.assertEqual(claims.owned(), [])

    def test_ownership_left_by_a_dead_process_is_swept_at_once(self):
        # `reconcile`'s half: no live claim at all, which is what a restart
        # leaves behind.
        opshell.Claims(self.path).open("raccoon-bandit")
        fresh = opshell.Claims(self.path, grace=10.0)
        queues = {}
        done = opshell.sweep(fresh, ["raccoon-bandit"],
                             {"raccoon-bandit": {"socks": {"sessions": 0}}},
                             {"raccoon-bandit": False}, queues, {}, "now",
                             time.time())
        self.assertEqual(done, ["raccoon-bandit"])


class TestTheHeartbeatIsPerSession(_RouteCase):
    def test_state_beats_only_the_session_it_was_given(self):
        # Beating every registered session let any open tab keep a dead
        # tab's claim alive for ever, and the lapse is what turns an
        # abandoned view into a queued stop.
        client = self.client()
        first = client.post(self.url("/api/opshell/open"),
                            json={"agent": self.AGENT},
                            headers=self.auth).get_json()["session"]
        second = client.post(self.url("/api/opshell/open"),
                             json={"agent": self.AGENT},
                             headers=self.auth).get_json()["session"]
        with unittest.mock.patch.object(opshell.Claims, "beat",
                                        autospec=True) as beat:
            client.get(self.url("/api/opshell/state?session=" + first),
                       headers=self.auth)
        beaten = [call.args[2] for call in beat.call_args_list]
        self.assertEqual(beaten, [first])
        self.assertNotIn(second, beaten)

    def test_state_without_a_session_beats_nothing(self):
        client = self.client()
        client.post(self.url("/api/opshell/open"), json={"agent": self.AGENT},
                    headers=self.auth)
        with unittest.mock.patch.object(opshell.Claims, "beat",
                                        autospec=True) as beat:
            client.get(self.url("/api/opshell/state"), headers=self.auth)
        self.assertEqual(beat.call_args_list, [])


class TestAStaleTunnelReportIsNotADeadChild(_RouteCase):
    def _target(self):
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": self.AGENT}))

    def test_a_report_about_an_older_child_does_not_read_as_idle(self):
        # The beacon builds its check-in, `tunnel` included, before it runs
        # the tasks that check-in carries -- so the report arriving with a
        # start's answer still describes the previous child. Read at face
        # value it said `idle` over a channel coming up, for a whole
        # interval.
        self._target()
        self.sm.history[self.AGENT] = [{
            "task_id": "a", "cmd": "tunnel", "args": "start",
            "status": "done", "output": "Tunnel started: pid 4242, task"}]
        self.sm.agents[self.AGENT]["tunnel"] = {"pid": 991, "running": False,
                                                "exit_code": 0}
        state = self.get("/api/opshell/state",
                         supervisor=self.configured_but_stopped()).get_json()
        self.assertEqual(state["state"], "waiting")

    def test_a_report_about_this_child_does_read_as_idle(self):
        self._target()
        self.sm.history[self.AGENT] = [{
            "task_id": "a", "cmd": "tunnel", "args": "start",
            "status": "done", "output": "Tunnel started: pid 4242, task"}]
        self.sm.agents[self.AGENT]["tunnel"] = {"pid": 4242, "running": False,
                                                "exit_code": 1}
        state = self.get("/api/opshell/state",
                         supervisor=self.configured_but_stopped()).get_json()
        self.assertEqual(state["state"], "idle")


class TestTheSweepDoesNotRunAway(_ClaimsCase):
    """The sweep made two latent gaps active, and both were Critical.

    `reconcile` reports an owned agent with no sessions every time it is
    asked -- which is exactly what an owed stop looks like -- so without a
    brake the sweep queued a fresh `tunnel stop` on every poll. And
    nothing released ownership, so once a channel had been stopped the
    agent stayed owned for ever and the sweep went on stopping *later*
    channels the view had never raised.
    """

    def _rows(self, socks=0):
        return {"raccoon-bandit": {"socks": {"sessions": socks}}}

    def test_a_pending_stop_stops_the_sweep_queueing_another(self):
        claims = opshell.Claims(self.path, grace=10.0)
        claims.open("raccoon-bandit")
        queues = {}
        clock = time.time() + 11
        for _ in range(4):
            opshell.sweep(claims, ["raccoon-bandit"], self._rows(),
                          {"raccoon-bandit": False}, queues, {}, "now", clock,
                          {"raccoon-bandit": bool(queues)}, {})
        self.assertEqual([t["args"] for t in queues["raccoon-bandit"]],
                         ["stop"])

    def test_decide_stop_refuses_while_a_tunnel_task_is_outstanding(self):
        claims = opshell.Claims(self.path)
        claims.open("raccoon-bandit")
        queues = {}
        queued, why = opshell.decide_stop(
            claims, "raccoon-bandit", {"socks": {"sessions": 0}}, False,
            queues, {}, "now", already_pending=True)
        self.assertFalse(queued)
        self.assertIn("already queued", why)
        self.assertEqual(queues, {})

    def test_a_settled_stop_releases_the_ownership_that_owed_it(self):
        claims = opshell.Claims(self.path, grace=10.0)
        claims.open("raccoon-bandit")
        claims.lapsed(time.time() + 11)
        queues = {}
        opshell.sweep(claims, ["raccoon-bandit"], self._rows(),
                      {"raccoon-bandit": False}, queues, {}, "now",
                      time.time(), {}, {"raccoon-bandit": True})
        self.assertEqual(claims.owned(), [])
        self.assertEqual(queues, {})

    def test_a_later_channel_is_not_stopped_once_ownership_is_released(self):
        # The second Critical in one test: stale ownership plus a sweep
        # stopped a pivot somebody else had raised from the tunnel panel.
        claims = opshell.Claims(self.path, grace=10.0)
        claims.open("raccoon-bandit")
        claims.lapsed(time.time() + 11)
        queues = {}
        opshell.sweep(claims, ["raccoon-bandit"], self._rows(),
                      {"raccoon-bandit": False}, queues, {}, "now",
                      time.time(), {}, {"raccoon-bandit": True})
        # A later channel: a row with no SOCKS session, which is what the
        # sweep used to read as "mine to stop".
        opshell.sweep(claims, ["raccoon-bandit"], self._rows(),
                      {"raccoon-bandit": False}, queues, {}, "now",
                      time.time(), {}, {})
        self.assertEqual(queues, {})


class TestTheBeatComesBeforeTheSweep(_RouteCase):
    def test_a_tab_polling_later_than_the_grace_keeps_its_claim(self):
        # Sweeping first made a tab lapse itself on the very request that
        # proved it was watching. A hidden browser tab is throttled to
        # about one poll a minute, which is exactly that edge.
        client = self.client(supervisor=self.connected())
        session = client.post(self.url("/api/opshell/open"),
                              json={"agent": self.AGENT},
                              headers=self.auth).get_json()["session"]
        with unittest.mock.patch.object(opshell.Claims, "lapsed",
                                        autospec=True) as lapsed:
            # The sweep is asked about a clock far past the grace; the beat
            # that ran first is what has to save the claim.
            lapsed.side_effect = lambda self_, now: []
            client.get(self.url("/api/opshell/state?session=" + session),
                       headers=self.auth)
            order = [c for c in lapsed.mock_calls]
        state = client.get(self.url("/api/opshell/state?session=" + session),
                           headers=self.auth).get_json()
        self.assertEqual(state["sessions"], 1)
        self.assertTrue(order, "the sweep did not run at all")


class TestADamagedRecordIsNotAFreeForAll(_RouteCase):
    def test_the_stream_is_refused_rather_than_inventing_a_session(self):
        (self.data_dir / "opshell-owned.json").write_text("{not json")
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": self.AGENT}))
        with self.assertLogs("raccoon.c2.server", level="ERROR"):
            answer = self.get("/api/opshell/stream")
        self.assertEqual(answer.status_code, 400)

    def test_a_close_queues_no_stop_when_nothing_can_be_recorded(self):
        (self.data_dir / "opshell-owned.json").write_text("{not json")
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": self.AGENT}))
        with self.assertLogs("raccoon.c2.server", level="ERROR"):
            self.post(self.url("/api/opshell/close"), {"session": "anything"})
        self.assertEqual(self.sm.task_queues, {})


class TestTheStreamDoesNotDialBeforeItChecks(_RouteCase):
    def test_a_request_with_no_session_never_reaches_the_port(self):
        # A refused request must not have sent the password, taken one of
        # the port's four slots and possibly opened a transcript first.
        port = _FakeShellPort(then=b"x", die_after_auth=True)
        self.addCleanup(port.stop)
        supervisor = self.connected()
        supervisor.status()["endpoints"][0]["shell_port"] = port.port
        client = self.client(supervisor=supervisor)
        client.post(self.url("/api/opshell/open"), json={"agent": self.AGENT},
                    headers=self.auth)
        answer = client.get(self.url("/api/opshell/stream"),
                            headers=self.auth)
        self.assertEqual(answer.status_code, 400)
        self.assertFalse(port.connected.is_set())


class TestTheAgentsOwnReportArrivesThroughACheckIn(_RouteCase):
    """End to end, because every other test set the field by hand.

    The beacon has been sending `info["tunnel"]` since the tunnel feature
    shipped and `_handle_beacon` never stored it. The operator shell's
    whole second source for "is this channel still up" reads that field,
    so the fallback meant to cover a relay outage was never true in
    production -- and it was invisible because the tests wrote the field
    themselves. This one makes the beacon's own path produce it.
    """

    def _check_in(self, tunnel):
        crypto = self.crypto
        app = self.app(supervisor=self.configured_but_stopped())
        client = app.test_client()
        payload = {"action": "beacon", "agent_id": self.AGENT,
                   "tunnel": tunnel}
        client.post("http://localhost:1/api/v1/beacon",
                    json=crypto.wrap(payload))
        return app

    def test_a_check_in_stores_what_the_beacon_reported(self):
        self._check_in({"pid": 991, "running": True, "source": "task"})
        self.assertEqual(
            (self.sm.agents[self.AGENT].get("tunnel") or {}).get("pid"), 991)

    def test_the_view_then_reports_the_channel_without_a_relay_row(self):
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": self.AGENT}))
        app = self._check_in({"pid": 991, "running": True, "source": "task"})
        state = self.operator_client(app).get(
            self.url("/api/opshell/state"), headers=self.auth).get_json()
        self.assertEqual(state["channel"], "open")

    def test_a_report_of_a_dead_child_does_not_read_as_a_channel(self):
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": self.AGENT}))
        app = self._check_in({"pid": 991, "running": False, "exit_code": 0})
        state = self.operator_client(app).get(
            self.url("/api/opshell/state"), headers=self.auth).get_json()
        self.assertEqual(state["channel"], "closed")


class TestTheBrakeCanLetGo(_RouteCase):
    """A brake that cannot release is worse than one stop too many.

    A history entry leaves `pending` only when a result comes back, and
    nothing expires it. `task_queues` is not persisted, so a restart loses
    the task and keeps the entry -- and the first version of the brake then
    answered "already queued" for ever: no stop would ever be sent again,
    the channel would stay up and the view would say `closing` for good.
    """

    def _entry(self, queued_iso, in_queue):
        self.sm.history[self.AGENT] = [{
            "task_id": "t1", "cmd": "tunnel", "args": "stop",
            "status": "pending", "timestamp": queued_iso}]
        if in_queue:
            self.sm.task_queues[self.AGENT] = [{"id": "t1", "cmd": "tunnel",
                                                "args": "stop"}]

    def test_a_task_still_in_the_queue_brakes(self):
        self._entry("2026-11-18T00:00:00Z", True)
        self.assertTrue(self.sm._opshell_stop_in_flight(self.AGENT))

    def test_a_recent_answerless_task_still_brakes(self):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._entry(now.replace("+00:00", "Z"), False)
        self.assertTrue(self.sm._opshell_stop_in_flight(self.AGENT))

    def test_a_task_older_than_two_intervals_lets_go(self):
        self._entry("2020-01-01T00:00:00Z", False)
        self.assertFalse(self.sm._opshell_stop_in_flight(self.AGENT))

    def test_an_entry_with_no_timestamp_lets_go(self):
        self.sm.history[self.AGENT] = [{"task_id": "t1", "cmd": "tunnel",
                                        "args": "stop", "status": "pending"}]
        self.assertFalse(self.sm._opshell_stop_in_flight(self.AGENT))


class TestWhatReleasesOwnership(_RouteCase):
    def test_a_relay_row_keeps_the_stop_owed(self):
        # The first version promised this check in its docstring and did
        # not make it, so a failed stop released the ownership that owed a
        # retry.
        self.sm.history[self.AGENT] = [{"task_id": "t1", "cmd": "tunnel",
                                        "args": "stop", "status": "done",
                                        "output": "could not stop"}]
        row = {"identity": "x", "implant_id": self.IMPLANT}
        self.assertFalse(self.sm._opshell_stop_settled(self.AGENT, row))
        self.assertTrue(self.sm._opshell_stop_settled(self.AGENT, None))

    def test_a_pending_stop_is_not_settled(self):
        self.sm.history[self.AGENT] = [{"task_id": "t1", "cmd": "tunnel",
                                        "args": "stop", "status": "pending"}]
        self.assertFalse(self.sm._opshell_stop_settled(self.AGENT, None))

    def test_a_child_the_agent_still_reports_is_not_settled(self):
        self.sm.history[self.AGENT] = [{"task_id": "t1", "cmd": "tunnel",
                                        "args": "stop", "status": "done",
                                        "output": "stopped"}]
        self.sm.agents[self.AGENT]["tunnel"] = {"pid": 9, "running": True}
        self.assertFalse(self.sm._opshell_stop_settled(self.AGENT, None))


class TestACheckInDoesNotRetireAWatchingTab(_ClaimsCase):
    def test_lapsed_false_leaves_a_slow_tab_alone(self):
        # A check-in carries no browser heartbeat, so it must not judge
        # whether a browser is still watching. A tab polling slower than
        # the grace would otherwise be retired by somebody else's agent.
        claims = opshell.Claims(self.path, grace=10.0)
        claims.open("raccoon-bandit")
        queues = {}
        opshell.sweep(claims, ["raccoon-bandit"],
                      {"raccoon-bandit": {"socks": {"sessions": 0}}},
                      {"raccoon-bandit": False}, queues, {}, "now",
                      time.time() + 11, {}, {}, lapsed=False)
        self.assertEqual(queues, {})
        self.assertEqual(claims.sessions("raccoon-bandit"), 1)

    def test_lapsed_true_does_retire_it(self):
        claims = opshell.Claims(self.path, grace=10.0)
        claims.open("raccoon-bandit")
        queues = {}
        opshell.sweep(claims, ["raccoon-bandit"],
                      {"raccoon-bandit": {"socks": {"sessions": 0}}},
                      {"raccoon-bandit": False}, queues, {}, "now",
                      time.time() + 11, {}, {}, lapsed=True)
        self.assertEqual([t["args"] for t in queues["raccoon-bandit"]],
                         ["stop"])


class TestAStaleReportDoesNotOutliveItsBeacon(_RouteCase):
    """An absent `tunnel` key is a statement, not a gap.

    The beacon leaves it out when *this process* has never started a
    child, so keeping the previous report meant a target reboot left a
    dead `running: True` behind for ever: the view showed the channel
    open, `/open` never queued another start for that agent, and the close
    never settled -- which is how stale ownership could later stop a
    teammate's pivot.
    """

    def _beacon(self, app, payload):
        app.test_client().post("http://localhost:1/api/v1/beacon",
                               json=self.crypto.wrap(payload))

    def test_a_check_in_without_the_key_clears_the_last_report(self):
        app = self.app(supervisor=self.configured_but_stopped())
        self._beacon(app, {"action": "beacon", "agent_id": self.AGENT,
                           "tunnel": {"pid": 9, "running": True}})
        self._beacon(app, {"action": "beacon", "agent_id": self.AGENT})
        self.assertNotIn("tunnel", self.sm.agents[self.AGENT])

    def test_the_glyph_opens_again_after_the_target_rebooted(self):
        app = self.app(supervisor=self.configured_but_stopped())
        client = self.operator_client(app)
        self._beacon(app, {"action": "beacon", "agent_id": self.AGENT,
                           "tunnel": {"pid": 9, "running": True}})
        self._beacon(app, {"action": "beacon", "agent_id": self.AGENT})
        self.sm.task_queues.pop(self.AGENT, None)
        client.post(self.url("/api/opshell/open"),
                    json={"agent": self.AGENT}, headers=self.auth)
        queued = [t["args"] for t in self.sm.task_queues.get(self.AGENT, [])]
        self.assertEqual(queued, ["start"])

    def test_a_re_registration_drops_the_old_processes_report(self):
        app = self.app(supervisor=self.configured_but_stopped())
        self._beacon(app, {"action": "beacon", "agent_id": self.AGENT,
                           "tunnel": {"pid": 9, "running": True}})
        self._beacon(app, {"action": "register", "id": self.IMPLANT,
                           "hostname": "parrot", "interval": 300})
        self.assertNotIn("tunnel", self.sm.agents[self.AGENT])


class TestTheSweepIsWiredToTheCheckIn(_RouteCase):
    def test_a_check_in_queues_the_stop_a_dead_process_owed(self):
        # The wiring, not the helper: every other sweep test calls
        # `opshell.sweep` directly, so four mutations of the call site
        # survived -- including reverting `lapsed=False` and putting the
        # whole-fleet walk back. This drives it through the beacon route.
        (self.data_dir / "opshell-owned.json").write_text(
            json.dumps({self.AGENT: {"since": "2026-11-18T00:00:00Z"}}))
        # A connected endpoint with no SOCKS session: the one state in
        # which the rules allow the stop. With no row and no agent report
        # the stop stays correctly *owed* rather than queued, which is
        # what the first version of this test asserted against.
        app = self.app(supervisor=self.connected())
        app.test_client().post(
            "http://localhost:1/api/v1/beacon",
            json=self.crypto.wrap({"action": "beacon",
                                   "agent_id": self.AGENT}))
        # The history, not the queue: the same check-in that noticed the
        # stop was owed also dispatched it, so `task_queues` is empty
        # again by the time the response is written. That is the property
        # worth having -- the stop rides the check-in that found it -- and
        # asserting on the queue was asserting on its absence.
        tunnel = [e for e in self.sm.history.get(self.AGENT, [])
                  if e.get("cmd") == "tunnel"]
        self.assertEqual([e.get("args") for e in tunnel], ["stop"])

    def test_a_check_in_does_not_retire_a_session_that_is_watching(self):
        # `lapsed=False` at the call site: a check-in carries no heartbeat,
        # so it must not judge a browser's liveness. Reverting the keyword
        # turns this red.
        app = self.app(supervisor=self.configured_but_stopped())
        client = self.operator_client(app)
        session = client.post(self.url("/api/opshell/open"),
                              json={"agent": self.AGENT},
                              headers=self.auth).get_json()["session"]
        self.sm.task_queues.pop(self.AGENT, None)
        with unittest.mock.patch.object(opshell.Claims, "lapsed",
                                        autospec=True,
                                        return_value=[self.AGENT]) as lapsed:
            app.test_client().post(
                "http://localhost:1/api/v1/beacon",
                json=self.crypto.wrap({"action": "beacon",
                                       "agent_id": self.AGENT}))
        self.assertEqual(lapsed.call_args_list, [])
        state = client.get(self.url("/api/opshell/state?session=" + session),
                           headers=self.auth).get_json()
        self.assertEqual(state["sessions"], 1)


STATIC = Path(__file__).resolve().parents[1] / "c2" / "static"
VENDOR_MD = STATIC / "VENDOR.md"


class TestTheVendoredTerminal(unittest.TestCase):
    """The one third-party file in this project, and its pin.

    "Nothing is pinned" is an open finding in `AGENT.md`: four
    requirements files use lower bounds, the image installs six packages
    with no constraint, and three tools are built from moving git
    branches. A vendored file with no recorded hash would be a new
    instance of that finding, so the hash is the point of this task and
    not bookkeeping around it.
    """

    def _parse_vendor_md(self):
        """Every row of VENDOR.md's table, by filename.

        A table rather than a sentence, because a test has to read it: a
        record only a human can parse is a record that drifts.
        """
        out = {}
        for line in VENDOR_MD.read_text().splitlines():
            if not line.startswith("|"):
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) < 3 or cells[0] in ("file", "") or set(cells[0]) <= set("-: "):
                continue
            out[cells[0].strip("`")] = {"version": cells[1],
                                        "sha256": cells[2]}
        return out

    def test_vendor_md_records_a_version_and_a_sha256_for_every_file(self):
        recorded = self._parse_vendor_md()
        self.assertEqual(set(recorded), {"xterm.js", "xterm.css"})
        for name, entry in recorded.items():
            self.assertRegex(entry["version"], r"^\d+\.\d+\.\d+$", name)
            self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$", name)

    def test_each_file_matches_its_recorded_hash(self):
        for name, entry in self._parse_vendor_md().items():
            digest = hashlib.sha256((STATIC / name).read_bytes()).hexdigest()
            self.assertEqual(digest, entry["sha256"], name)

    def test_the_record_says_where_each_file_came_from_and_when(self):
        # A hash proves the file has not changed. It does not say what the
        # file is, who may use it, or which release to compare against --
        # so the row carries the upstream URL, the licence and the date.
        text = VENDOR_MD.read_text()
        self.assertIn("https://", text)
        self.assertRegex(text, r"MIT")
        self.assertRegex(text, r"20\d\d-\d\d-\d\d")

    def test_the_version_agrees_with_the_url_it_was_fetched_from(self):
        # Without this the version column is decoration: changing 6.0.0 to
        # 6.0.1 in the table left every other test green, because nothing
        # cross-checked it against anything. The upstream URL carries the
        # version, so the two have to agree.
        for line in VENDOR_MD.read_text().splitlines():
            if not line.startswith("| `"):
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            name, version, url = cells[0].strip("`"), cells[1], cells[3]
            self.assertIn(version, url,
                          "%s: the row says %s and was fetched from %s"
                          % (name, version, url))

    def test_the_files_are_served_and_not_empty(self):
        for name in ("xterm.js", "xterm.css"):
            self.assertGreater((STATIC / name).stat().st_size, 1000, name)


SERVER_SRC = (Path(__file__).resolve().parents[1] / "c2" / "server.py").read_text()


class _GuiCase(unittest.TestCase):
    """The interface is inline in `server.py`, so the tests read it.

    The pattern this repository already uses (`test_tunnel_gui.py`, and
    `TestTheTwoGuisDoNotShareHelpers` in `test_dns_rescue.py`). Two small
    readers are all it needs.
    """

    def header_block(self):
        start = SERVER_SRC.index("topbar-ico-btn\" onclick=")
        return SERVER_SRC[start - 200:start + 1200]

    def js_function(self, name):
        for opener in ("async function %s(" % name, "function %s(" % name):
            at = SERVER_SRC.find(opener)
            if at >= 0:
                break
        self.assertGreaterEqual(at, 0, "no function %s in server.py" % name)
        depth, i, started = 0, SERVER_SRC.index("{", at), False
        for j in range(i, len(SERVER_SRC)):
            if SERVER_SRC[j] == "{":
                depth, started = depth + 1, True
            elif SERVER_SRC[j] == "}":
                depth -= 1
                if started and depth == 0:
                    return SERVER_SRC[at:j + 1]
        self.fail("unbalanced braces reading %s" % name)


class TestTheGlyphAndTheView(_GuiCase):
    def test_the_header_carries_a_terminal_glyph_that_opens_the_view(self):
        self.assertIn("showOperatorShell()", self.header_block())

    def test_the_view_dials_nothing_until_the_operator_asks(self):
        # The goal: nothing happens on open, on hover, or on page load. The
        # channel is raised only when the operator presses the button in
        # the view that says it will.
        opened = self.js_function("showOperatorShell")
        self.assertNotIn("/api/opshell/open", opened)

    def test_the_page_loads_the_vendored_terminal(self):
        self.assertIn('/static/xterm.js', SERVER_SRC)
        self.assertIn('/static/xterm.css', SERVER_SRC)

    def test_the_stream_is_read_with_fetch_and_not_eventsource(self):
        # EventSource cannot send the Authorization header this socket
        # requires, and a token in a URL is forbidden by test_docs.
        attach = self.js_function("opshellAttach")
        self.assertIn("getReader", attach)
        # Not used, rather than not mentioned. The first version of this
        # forbade the word and caught the comment that explains why the
        # thing is unusable here -- the same mistake as a Dockerfile test
        # earlier in this branch, which forbade a string and hit the
        # comment quoting the defect it described.
        self.assertNotRegex(SERVER_SRC, r"new\s+EventSource\s*\(")

    def test_keystrokes_are_posted_not_put_in_the_url(self):
        attach = self.js_function("opshellAttach")
        self.assertIn("/api/opshell/keys", attach)


class TestTheViewDoesNotOverclaim(_GuiCase):
    def test_the_word_closed_is_never_rendered_from_the_closing_state(self):
        # "Closing" and "closed" are different facts: a stop is queued and
        # takes effect at the next check-in. The first mockup of this said
        # "stop acknowledged" at the moment of exit, which was a lie.
        render = self.js_function("opshellRender")
        self.assertIn('"closing"', render)
        for line in render.splitlines():
            if '"closing"' in line:
                self.assertNotIn("Channel closed", line)

    def test_the_strip_states_the_user_and_does_not_assume_root(self):
        # The tunnel panel carries this scar already: it "used to state
        # root for every row", and the user is a reported field now.
        render = self.js_function("opshellRender")
        self.assertIn("state.user", render)
        self.assertIn("state.root", render)

    def test_the_first_terminal_line_claims_only_what_the_code_does(self):
        # `unset HISTFILE` and `set +o history` run after the rc files
        # (beacon.py:3228). That is exactly what this says, and no more.
        self.assertIn("history is off in this session", SERVER_SRC)

    def test_there_is_no_cancel_button_for_a_queued_task(self):
        # This server has no task withdrawal, so a button that said it
        # could take one back would be worse than its absence.
        render = self.js_function("opshellRender")
        self.assertNotRegex(render, r"(?i)>\s*cancel")

    def test_the_view_states_the_geometry_it_actually_sent(self):
        # The pty cannot be renegotiated, so the pair on screen is the one
        # that was sent or nothing.
        render = self.js_function("opshellRender")
        self.assertIn("state.geometry", render)

    def test_the_wait_shows_the_expected_check_in_not_a_spinner(self):
        # A spinner invites the operator to help it along; the number says
        # that waiting is the price of staying quiet.
        render = self.js_function("opshellRender")
        self.assertIn("expected_checkin", render)

    def test_the_reason_is_shown_whenever_the_server_sends_one(self):
        render = self.js_function("opshellRender")
        self.assertIn("state.reason", render)


if __name__ == "__main__":
    unittest.main()
