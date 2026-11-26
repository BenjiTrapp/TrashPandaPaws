#!/usr/bin/env python3
"""Tests for the operator shell's server-side logic.

The feature's anti-goal is a channel left open on the target device while
the operator believes it closed. The claim tests below are about exactly
that: every way the bookkeeping could forget a stop it owes.
"""

import ast
import base64
import hashlib
import re
import shutil
import subprocess
import json
import os
import selectors
import socket
import struct
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
from software.tests.test_c2_server import NOT_AN_OBJECT, logged_tracebacks


class _ClaimsCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "opshell-owned.json"


class TestTheClaimCounts(_ClaimsCase):
    def test_the_last_session_out_is_the_one_that_closes(self):
        c = opshell.Claims(self.path)
        a, b = c.open("raccoon-bandit", raised=True), c.open("raccoon-bandit", raised=True)
        self.assertFalse(c.close("raccoon-bandit", a))
        self.assertTrue(c.close("raccoon-bandit", b))

    def test_a_second_browser_does_not_lose_the_first_ones_channel(self):
        # Review Focus 3. One bearer token, two views: the refcount is the
        # only thing standing between `exit` in one tab and a dead session
        # in the other.
        c = opshell.Claims(self.path)
        first = c.open("raccoon-bandit", raised=True)
        c.open("raccoon-bandit", raised=True)
        c.close("raccoon-bandit", first)
        self.assertEqual(c.sessions("raccoon-bandit"), 1)

    def test_a_silent_browser_lapses_and_a_beating_one_does_not(self):
        # The beat is made part-way through the grace, with the clock
        # pinned: a beat made "now" and a check made "now + 11" would
        # leave both sessions equally stale.
        c = opshell.Claims(self.path, grace=10.0)
        with unittest.mock.patch.object(opshell.time, "time", return_value=1000.0):
            c.open("quiet-one", raised=True)
            alive = c.open("alive-one", raised=True)
        with unittest.mock.patch.object(opshell.time, "time", return_value=1008.0):
            c.beat("alive-one", alive)
        self.assertEqual(c.lapsed(now=1011.0), ["quiet-one"])
        self.assertEqual(c.sessions("alive-one"), 1)

    def test_a_session_exactly_at_the_grace_has_not_lapsed(self):
        c = opshell.Claims(self.path, grace=10.0)
        with unittest.mock.patch.object(opshell.time, "time", return_value=1000.0):
            c.open("raccoon-bandit", raised=True)
        self.assertEqual(c.lapsed(now=1010.0), [])
        self.assertEqual(c.lapsed(now=1010.5), ["raccoon-bandit"])

    def test_a_stale_session_beside_a_live_one_is_not_left_in_the_count(self):
        # A browser that died while another tab stays open. If the ghost
        # stayed in the count, the live tab's `exit` would answer "not the
        # last", no stop would be queued, and the channel would stand.
        c = opshell.Claims(self.path, grace=10.0)
        with unittest.mock.patch.object(opshell.time, "time", return_value=1000.0):
            c.open("raccoon-bandit", raised=True)
            live = c.open("raccoon-bandit", raised=True)
        with unittest.mock.patch.object(opshell.time, "time", return_value=1008.0):
            c.beat("raccoon-bandit", live)
        self.assertEqual(c.lapsed(now=1012.0), [])
        self.assertEqual(c.sessions("raccoon-bandit"), 1)
        self.assertTrue(c.close("raccoon-bandit", live))

    def test_a_lapsed_claim_is_reported_once_and_not_revived_by_a_late_beat(self):
        c = opshell.Claims(self.path, grace=10.0)
        with unittest.mock.patch.object(opshell.time, "time", return_value=1000.0):
            sid = c.open("raccoon-bandit", raised=True)
        self.assertEqual(c.lapsed(now=1020.0), ["raccoon-bandit"])
        self.assertEqual(c.lapsed(now=1021.0), [])
        c.beat("raccoon-bandit", sid)
        self.assertEqual(c.sessions("raccoon-bandit"), 0)
        self.assertFalse(c.close("raccoon-bandit", sid))

    def test_closing_a_session_that_is_not_held_is_not_a_last_close(self):
        c = opshell.Claims(self.path)
        c.open("raccoon-bandit", raised=True)
        self.assertFalse(c.close("raccoon-bandit", "not-a-session"))
        self.assertFalse(c.close("never-opened", "x"))
        self.assertEqual(c.sessions("raccoon-bandit"), 1)


class TestOwnershipIsPersisted(_ClaimsCase):
    def test_ownership_survives_a_restart_and_reconciles(self):
        # The anti-goal: a restart between start and stop must not leave a
        # channel with nobody to close it.
        opshell.Claims(self.path).open("raccoon-bandit", raised=True)
        fresh = opshell.Claims(self.path)          # a new process
        self.assertEqual(fresh.owned(), ["raccoon-bandit"])
        self.assertEqual(opshell.reconcile(fresh, ["raccoon-bandit"]),
                         ["raccoon-bandit"])

    def test_an_agent_that_vanished_is_forgotten_not_reported_closed(self):
        # Review Focus 1. No agent, no task, no honest claim of closure.
        c = opshell.Claims(self.path)
        c.open("gone-raccoon", raised=True)
        self.assertEqual(opshell.reconcile(c, []), [])
        self.assertEqual(c.owned(), [])
        self.assertEqual(opshell.Claims(self.path).owned(), [])

    def test_closing_the_last_session_keeps_ownership_until_the_stop_is_seen(self):
        # Closing only queues the stop. If ownership went with the last
        # session, a restart before the beacon's next check-in would find
        # nothing owed and the stop would never be re-queued.
        c = opshell.Claims(self.path)
        sid = c.open("raccoon-bandit", raised=True)
        self.assertTrue(c.close("raccoon-bandit", sid))
        fresh = opshell.Claims(self.path)
        self.assertEqual(opshell.reconcile(fresh, ["raccoon-bandit"]),
                         ["raccoon-bandit"])
        self.assertTrue(fresh.release("raccoon-bandit"))
        self.assertEqual(opshell.Claims(self.path).owned(), [])

    def test_release_after_the_stop_is_seen_drops_ownership(self):
        c = opshell.Claims(self.path)
        sid = c.open("raccoon-bandit", raised=True)
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
        old = c.open("raccoon-bandit", raised=True)
        self.assertTrue(c.close("raccoon-bandit", old))
        new = c.open("raccoon-bandit", raised=True)
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
        c.open("gone-raccoon", raised=True)
        c.forget("gone-raccoon")
        self.assertEqual(c.sessions("gone-raccoon"), 0)
        self.assertEqual(c.owned(), [])

    def test_a_live_claim_is_not_owed_a_stop(self):
        c = opshell.Claims(self.path)
        c.open("raccoon-bandit", raised=True)
        self.assertEqual(opshell.reconcile(c, ["raccoon-bandit"]), [])
        self.assertEqual(c.owned(), ["raccoon-bandit"])

    def test_a_channel_this_view_did_not_start_is_not_owned(self):
        c = opshell.Claims(self.path)
        c.open("raccoon-bandit", raised=True)
        self.assertEqual(opshell.reconcile(c, ["raccoon-bandit", "other-one"]), [])
        self.assertEqual(c.owned(), ["raccoon-bandit"])

    def test_the_record_is_private_and_says_only_whose_channel_it_is(self):
        opshell.Claims(self.path).open("raccoon-bandit", raised=True)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        record = json.loads(self.path.read_text())
        self.assertEqual(list(record), ["raccoon-bandit"])
        # `raised` as well as `since`: which of the two kinds of claim
        # this is decides whether its stop may ever be queued, so it has
        # to survive a restart. Still nothing about the host, the port or
        # the password.
        self.assertEqual(sorted(record["raccoon-bandit"]),
                         ["raised", "since"])

    def test_the_record_stays_private_when_rewritten_under_a_loose_umask(self):
        c = opshell.Claims(self.path)
        c.open("one", raised=True)
        old = os.umask(0)
        try:
            c.open("two", raised=True)
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_opening_again_does_not_move_the_ownership_date(self):
        c = opshell.Claims(self.path)
        c.open("raccoon-bandit", raised=True)
        first = json.loads(self.path.read_text())["raccoon-bandit"]["since"]
        with unittest.mock.patch.object(opshell, "_now_iso", return_value="2999-01-01T00:00:00+00:00"):
            c.open("raccoon-bandit", raised=True)
        self.assertEqual(json.loads(self.path.read_text())["raccoon-bandit"]["since"], first)

    def test_a_claim_is_not_taken_when_the_record_cannot_be_written(self):
        # Starting a channel on the strength of a record that was never
        # saved is the anti-goal with a delay.
        c = opshell.Claims(self.path)
        with unittest.mock.patch.object(opshell.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                c.open("raccoon-bandit", raised=True)
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

    def test_every_shape_of_damage_is_the_same_error(self):
        """Promoted from a deferred minor by the final review.

        `read_text()` raises `UnicodeDecodeError`, which is not an
        `OSError`, so it escaped `_load`, escaped `opshell_claims()`'s
        `except OwnershipRecordError`, and reached Flask: measured, every
        route of this feature answered 500 for a record with one stray
        byte in it. The deferred note said "does not catch
        UnicodeDecodeError" and I had read that as tidiness.
        """
        for damage in (b"{not json", b"[]", b"\xff\xfe nonsense",
                       b"\x00", b'{"a": 1}\xff'):
            self.path.write_bytes(damage)
            with self.assertRaises(opshell.OwnershipRecordError, msg=damage):
                opshell.Claims(self.path)

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
                 drip=False, hold=None, drain=True, quiet=0.0, late=b"",
                 reset=False, connections=1):
        # `reset`: hang up with SO_LINGER 0 after the auth line, so the peer
        # sees ECONNRESET rather than a clean end. A tunnel server that is
        # killed looks like this, and every other fake port in this file
        # closes politely -- which is why the pump's missing `OSError` arm
        # survived the whole branch.
        self._reset = reset
        self._connections = connections
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
        """Accept up to `connections` callers, each on its own thread.

        One connection was enough until a test needed two live sessions
        with different geometries -- and with one, the second stream got a
        502 and the test silently measured the first session again. The
        real port serves four at once.
        """
        served = 0
        while served < self._connections and not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            served += 1
            if served == self._connections:
                self._handle(conn)
            else:
                t = threading.Thread(target=self._handle, args=(conn,),
                                     daemon=True)
                t.start()

    def _handle(self, conn):
        try:
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
            if self._reset:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                struct.pack("ii", 1, 0))
                conn.close()
                return
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
            "shell_transcripts": "/tmp/transcripts",
            "endpoints": [{
                "identity": "parrot-box", "implant_id": self.IMPLANT,
                "hostname": "parrot",
                "state": "connected", "user": user,
                "shell_port": self.dead_port(),
                "shell_password": self.SHELL_PASSWORD,
                "shell_recording": True,
                # What a session on that endpoint does about command
                # history, as its HELLO reported it. The relay never
                # leaves the pair unset for a connected endpoint: an
                # unknown word, and an endpoint too old to send one, both
                # read as "weak" there.
                "history": "off",
                "history_detail": "",
                "shell": {"sessions": sessions, "max_sessions": 4},
                "socks": {"sessions": socks_sessions, "max_sessions": 256},
            }],
        })

    def raised_and_up(self, socks_sessions=0):
        """A view that raised the channel itself, on an endpoint now up.

        The honest sequence, and several tests needed it once a stop became
        allowed only for a channel *this view raised*: they had been
        opening onto an endpoint that was already connected, which is
        adoption, and then asserting a stop. `status()` returns the same
        dict every call, so the endpoint can appear between the two
        requests exactly as it does when the agent's start lands.

        Returns `(client, session, status)`.
        """
        supervisor = self.configured_but_stopped()
        status = supervisor.status()
        client = self.operator_client(self.app(supervisor=supervisor))
        session = client.post(self.url("/api/opshell/open"),
                              json={"agent": self.AGENT},
                              headers=self.auth).get_json()["session"]
        status["state"] = "running"
        status["shell_transcripts"] = "/tmp/transcripts"
        status["endpoints"] = [{
            "identity": "parrot-box", "implant_id": self.IMPLANT,
                "hostname": "parrot",
            "state": "connected", "user": "root",
            "shell_port": self.dead_port(),
            "shell_password": self.SHELL_PASSWORD,
            "shell_recording": True,
            "history": "off",
            "history_detail": "",
            "shell": {"sessions": 0, "max_sessions": 4},
            "socks": {"sessions": socks_sessions, "max_sessions": 256},
        }]
        self.sm.task_queues.pop(self.AGENT, None)
        self.sm.history.pop(self.AGENT, None)
        return client, session, status

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

    # ── state answers, for the fields that are read off the row ──

    def _state_for(self, supervisor):
        """The state answer for that supervisor, with a target designated.

        The target matters: `/state` answers early for a view that has
        been pointed at nothing, so without one this would measure that
        early answer instead of the field it was asked about -- the
        mistake `test_the_strip_gets_a_host_to_show` records.
        """
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": self.AGENT}))
        return self.get("/api/opshell/state", supervisor=supervisor).get_json()

    def _state_with_row(self, **fields):
        """The state answer over `connected()`, whose row carries `fields`.

        The fixture's own row, updated, rather than a second row written
        here: a row invented in a test is the typo-against-a-typo shape
        that `TestTheFixturesDoNotInventFieldNames` exists to stop.
        """
        supervisor = self.connected()
        supervisor.status()["endpoints"][0].update(fields)
        return self._state_for(supervisor)

    def _state_without_row(self):
        """The state answer for a configured relay that has no row yet.

        `configured_but_stopped()` reports a shell port range and no
        endpoints, which is every moment between the operator's click and
        the endpoint's HELLO.
        """
        return self._state_for(self.configured_but_stopped())

    def _blind_state(self):
        """The early answer, with no tunnel supervisor to ask at all."""
        return self._state_for(None)



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

    def test_the_state_answer_carries_the_history_guard_the_row_has(self):
        state = self._state_with_row(
            history="weak", history_detail="/bin/zsh takes no --rcfile")
        self.assertEqual(state["history"], "weak")
        self.assertIn("zsh", state["history_detail"])

    def test_a_guard_that_holds_history_off_reaches_the_answer_too(self):
        state = self._state_with_row(history="off", history_detail="")
        self.assertEqual(state["history"], "off")
        self.assertEqual(state["history_detail"], "")

    def test_a_channel_with_no_row_is_told_nothing_about_history(self):
        """`user` and `root` are populated only inside `if row is not
        None`, and so is this. An empty guard is the view's signal to
        claim neither: nothing here has measured the host, and "weak"
        would be a statement about a session that does not exist.
        """
        self.assertEqual(self._state_without_row()["history"], "")
        self.assertEqual(self._state_without_row()["history_detail"], "")
        self.assertEqual(self._blind_state()["history"], "")
        self.assertEqual(self._blind_state()["history_detail"], "")

    def test_a_relay_too_old_to_report_a_guard_is_told_nothing_either(self):
        """A row from a tunnel server built before this field: the
        endpoint's own answer cannot have reached it, and "" is the only
        reading of that. The relay is where an unknown word becomes
        `weak`, and that is a different question from a relay that says
        nothing at all."""
        supervisor = self.connected()
        row = supervisor.status()["endpoints"][0]
        row.pop("history", None)
        row.pop("history_detail", None)
        state = self._state_for(supervisor)
        self.assertEqual(state["history"], "")
        self.assertEqual(state["history_detail"], "")



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
        self.assertEqual(answer.get_json()["refused"], "no-such-raccoon")
        self.assertEqual(self.sm.task_queues, {})

    def test_naming_nothing_is_not_reported_as_an_unknown_device(self):
        answer = self.post(self.url("/api/opshell/open"), {})
        self.assertEqual(answer.status_code, 400)
        self.assertEqual(answer.get_json()["error"], "choose a device first")
        self.assertEqual(self.sm.task_queues, {})

    def test_a_remembered_designation_opens_for_a_body_that_names_nothing(self):
        # What makes the picker's placeholder safe: it posts no `agent` key,
        # and the fallback must survive the split. The designation is written
        # rather than earned by opening first -- a second open would be on
        # the adoption path and would prove this only incidentally. Writing
        # it is this suite's own pattern, from
        # `test_a_damaged_record_refuses_on_the_first_request_after_a_restart`.
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": self.AGENT}))
        answer = self.post(self.url("/api/opshell/open"), {})
        self.assertEqual(answer.status_code, 200)

    def test_a_designation_that_left_the_fleet_is_refused_by_its_name(self):
        # The API's half of the dead-designation row: a body naming nothing
        # falls back to the file, and a name the fleet does not hold is a
        # `404` that says which name, not the `400` for naming nothing.
        # The page's own guard does not reach this; any other client does.
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": "no-such-raccoon"}))
        answer = self.post(self.url("/api/opshell/open"), {})
        self.assertEqual(answer.status_code, 404)
        self.assertEqual(answer.get_json()["refused"], "no-such-raccoon")
        self.assertEqual(self.sm.task_queues, {})

    def test_a_designation_file_that_names_no_string_names_nothing(self):
        # The file is hand-editable, and a number in it reached `[:64]`.
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": 123}))
        answer = self.post(self.url("/api/opshell/open"), {})
        self.assertEqual(answer.status_code, 400)
        self.assertEqual(answer.get_json()["error"], "choose a device first")
        self.assertEqual(self.sm.task_queues, {})

    def test_a_designation_naming_no_string_reaches_no_route_as_a_name(self):
        # One step past the reader: it stopped raising on a non-object, but
        # handed `{"agent": ["x"]}`'s list on, and `/stream`'s
        # `target not in agents` raised `TypeError: unhashable type`. Every
        # route that reads the designation is asked, with and without a
        # session, since `/state` only beats a claim when given one.
        for bad in (["x"], {"a": 1}, 123, True):
            (self.data_dir / "opshell-target.json").write_text(
                json.dumps({"agent": bad}))
            with logged_tracebacks() as tracebacks:
                answers = {
                    "state": self.get("/api/opshell/state"),
                    "state?session": self.get("/api/opshell/state?session=s"),
                    "stream": self.get("/api/opshell/stream"),
                    "stream?session": self.get(
                        "/api/opshell/stream?session=s"),
                    "open": self.post(self.url("/api/opshell/open"), {}),
                    "close": self.post(self.url("/api/opshell/close"),
                                       {"session": "s"}),
                }
            for path, answer in answers.items():
                self.assertLess(answer.status_code, 500, (bad, path))
            for path in ("state", "state?session"):
                self.assertIsNone(answers[path].get_json()["target"],
                                  (bad, path))
            self.assertEqual(answers["stream"].status_code, 404, repr(bad))
            self.assertEqual(tracebacks, [], repr(bad))
            self.assertEqual(self.sm.task_queues, {}, repr(bad))

    def test_an_agent_field_that_is_not_a_string_is_refused_not_a_crash(self):
        # `.strip()` on an int answered 500. The same shape as the
        # `c2.fallback: true` crash on the beacon.
        for bad in (123, True, ["badger"], {"agent": "badger"}):
            answer = self.post(self.url("/api/opshell/open"), {"agent": bad})
            self.assertEqual(answer.status_code, 400, repr(bad))
            self.assertEqual(self.sm.task_queues, {}, repr(bad))

    def test_a_whitespace_name_names_nothing(self):
        answer = self.post(self.url("/api/opshell/open"), {"agent": "   "})
        self.assertEqual(answer.status_code, 400)

    def test_a_body_that_is_not_an_object_is_refused_not_a_crash(self):
        # `get_json(silent=True) or {}` only catches JSON that does not
        # parse; `[1]` parses, is truthy, and met `.get`. A designation is
        # on file, so a body quietly coerced to `{}` would have opened onto
        # it: refused is the claim, not merely "not a 500".
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": self.AGENT}))
        for body in NOT_AN_OBJECT:
            with logged_tracebacks() as tracebacks:
                answer = self.post(self.url("/api/opshell/open"), body)
            self.assertEqual(answer.status_code, 400, repr(body))
            self.assertIn("error", answer.get_json(), repr(body))
            self.assertEqual(tracebacks, [], repr(body))
            self.assertEqual(self.sm.task_queues, {}, repr(body))

    def test_a_designation_file_that_is_not_an_object_names_nothing(self):
        # The file is hand-editable, and `(json.load(f) or {}).get` met a
        # `[1]` with `.get`: the reader raised instead of answering None.
        for content in NOT_AN_OBJECT:
            (self.data_dir / "opshell-target.json").write_text(
                json.dumps(content))
            with logged_tracebacks() as tracebacks:
                opened = self.post(self.url("/api/opshell/open"), {})
                state = self.get("/api/opshell/state")
            self.assertEqual(opened.status_code, 400, repr(content))
            self.assertEqual(opened.get_json()["error"],
                             "choose a device first", repr(content))
            self.assertEqual(state.status_code, 200, repr(content))
            self.assertIsNone(state.get_json()["target"], repr(content))
            self.assertEqual(tracebacks, [], repr(content))
            self.assertEqual(self.sm.task_queues, {}, repr(content))


class TestADesignationFollowsTheDevice(_RouteCase):
    """The designation names a device, not a slot in the list.

    Fleet names are reused: the name counter is rewound by a restart that no
    save recorded, and the next device to register is handed a name that is
    already on disk as somebody's designation. The implant id is what
    identifies the host, so the file carries it and `opshell_target()`
    resolves through it -- and still answers with a name, so nothing that
    reads the designation changes.
    """

    OTHER = "implant-2"

    def designate(self, **fields):
        (self.data_dir / "opshell-target.json").write_text(json.dumps(fields))

    def designation(self):
        return json.loads((self.data_dir / "opshell-target.json").read_text())

    def target(self):
        answer = self.get("/api/opshell/state")
        self.assertEqual(answer.status_code, 200)
        return answer.get_json()["target"]

    def rebuild_fleet(self, **devices):
        """The fleet as a restarted server would have it: name -> id."""
        self.sm.agents.clear()
        for name, implant in devices.items():
            self.sm.agents[name] = {
                "id": implant, "agent_id": name, "hostname": name,
                "interval": 300, "_last_seen_ts": time.time(),
                "caps": ["batch"],
            }

    # ── what is written ──

    def test_a_successful_open_writes_the_implant_id_with_the_name(self):
        self.post(self.url("/api/opshell/open"), {"agent": self.AGENT})
        self.assertEqual(self.designation(),
                         {"agent": self.AGENT, "id": self.IMPLANT})

    def test_an_agent_that_has_no_id_is_written_by_name_alone(self):
        # The agent vanished between the open and the write, or never had
        # one: today's behaviour, not a crash and not an invented id.
        del self.sm.agents[self.AGENT]["id"]
        answer = self.post(self.url("/api/opshell/open"),
                           {"agent": self.AGENT})
        self.assertEqual(answer.status_code, 200)
        self.assertEqual(self.designation(), {"agent": self.AGENT})

    def test_the_designation_is_still_0600_with_an_id_in_it(self):
        self.post(self.url("/api/opshell/open"), {"agent": self.AGENT})
        target = self.data_dir / "opshell-target.json"
        self.assertEqual(oct(target.stat().st_mode & 0o777), "0o600")
        self.assertFalse(target.with_suffix(".tmp").exists())

    # ── what is resolved ──

    def test_the_device_returning_under_a_new_name_is_found_by_its_id(self):
        self.designate(agent="the-old-name", id=self.IMPLANT)
        self.assertEqual(self.target(), self.AGENT)

    def test_an_id_that_matches_beats_a_name_that_differs(self):
        # The case the change exists for: the file holds an id *and* a
        # name, the id matches one entry, and that entry's name is not the
        # file's. The device wins, whatever the name says.
        self.rebuild_fleet(**{"new-name": self.IMPLANT,
                              "the-old-name": self.OTHER})
        self.designate(agent="the-old-name", id=self.IMPLANT)
        self.assertEqual(self.target(), "new-name")

    def test_a_device_that_is_absent_resolves_to_nothing(self):
        self.rebuild_fleet(**{"someone-else": self.OTHER})
        self.designate(agent=self.AGENT, id=self.IMPLANT)
        self.assertIsNone(self.target())

    def test_the_name_handed_to_a_different_device_is_not_that_device(self):
        # The whole point. Device A was designated as `AGENT`; the counter
        # rewound and the name now belongs to a device with another id.
        self.designate(agent=self.AGENT, id=self.IMPLANT)
        self.rebuild_fleet(**{self.AGENT: self.OTHER})
        self.assertIsNone(self.target())

    def test_a_reused_name_is_not_opened_onto_either(self):
        # What the operator would have met: the picker marking the reused
        # name `selected`, and `Open` taking a shell on that host.
        self.designate(agent=self.AGENT, id=self.IMPLANT)
        self.rebuild_fleet(**{self.AGENT: self.OTHER})
        answer = self.post(self.url("/api/opshell/open"), {})
        self.assertEqual(answer.status_code, 400)
        self.assertEqual(answer.get_json()["error"], "choose a device first")
        self.assertEqual(self.sm.task_queues, {})

    def test_the_same_story_end_to_end_through_a_real_open(self):
        # Written by the route rather than by hand, so the writer and the
        # reader are held to each other.
        self.post(self.url("/api/opshell/open"), {"agent": self.AGENT})
        self.rebuild_fleet(**{self.AGENT: self.OTHER})
        self.assertIsNone(self.target())
        self.rebuild_fleet(**{"renamed": self.IMPLANT, self.AGENT: self.OTHER})
        self.assertEqual(self.target(), "renamed")

    def test_an_entry_with_no_id_is_never_the_device(self):
        self.designate(agent=self.AGENT, id=self.IMPLANT)
        del self.sm.agents[self.AGENT]["id"]
        self.assertIsNone(self.target())

    def test_an_id_that_is_not_a_string_names_nothing(self):
        # Hand-editable. Falling back to the name here would be the very
        # thing the id exists to stop.
        for bad in (None, 123, ["x"], {"a": 1}, True, ""):
            self.designate(agent=self.AGENT, id=bad)
            self.assertIsNone(self.target(), repr(bad))

    # ── a file written before this change ──

    def test_a_file_with_only_a_name_resolves_as_it_always_did(self):
        self.designate(agent=self.AGENT)
        self.assertEqual(self.target(), self.AGENT)

    def test_a_file_with_only_a_name_the_fleet_lacks_still_reports_it(self):
        # As before: the name comes back, and `open` refuses it by name
        # (`test_a_designation_that_left_the_fleet_is_refused_by_its_name`).
        self.designate(agent="no-such-raccoon")
        self.assertEqual(self.target(), "no-such-raccoon")

    # ── a read does not write ──

    def test_reading_never_writes_the_designation(self):
        # `/state` is a GET, polled every two seconds. A pre-change file is
        # upgraded by the next open and not before, and that includes the
        # shapes the resolver answers differently for.
        target = self.data_dir / "opshell-target.json"
        shapes = ({"agent": self.AGENT},
                  {"agent": "the-old-name", "id": self.IMPLANT},
                  {"agent": self.AGENT, "id": self.OTHER},
                  {"agent": "no-such-raccoon"})
        for shape in shapes:
            self.designate(**shape)
            before = (target.read_bytes(), target.stat().st_mtime_ns)
            self.get("/api/opshell/state")
            self.get("/api/opshell/state?session=s")
            self.get("/api/opshell/stream")
            self.post(self.url("/api/opshell/close"), {"session": "s"})
            self.assertEqual(
                (target.read_bytes(), target.stat().st_mtime_ns), before,
                repr(shape))
            self.assertFalse(target.with_suffix(".tmp").exists(), repr(shape))
        # And the next open is what upgrades a pre-change file.
        self.designate(agent=self.AGENT)
        self.post(self.url("/api/opshell/open"), {})
        self.assertEqual(self.designation(),
                         {"agent": self.AGENT, "id": self.IMPLANT})


class TestClosingTheChannel(_RouteCase):
    def test_close_reports_closing_and_never_closed(self):
        client, session, _ = self.raised_and_up()
        state = client.post(self.url("/api/opshell/close"),
                            json={"session": session},
                            headers=self.auth).get_json()
        self.assertEqual(state["state"], "closing")

    def test_close_queues_the_stop_and_logs_it(self):
        # `raised_and_up`, not `client()`: a stop is allowed only for a
        # channel this view raised, and opening onto an endpoint that is
        # already connected is adoption. This test used to assert a stop
        # for an adopted channel, which is the behaviour the plan's
        # constraint forbids.
        client, session, _ = self.raised_and_up()
        client.post(self.url("/api/opshell/close"),
                    json={"session": session}, headers=self.auth)
        queued = [(t["cmd"], t["args"])
                  for t in self.sm.task_queues[self.AGENT]]
        self.assertIn(("tunnel", "stop"), queued)

    def test_a_live_socks_session_leaves_the_stop_owed_and_says_so(self):
        # The operator's rule: one child serves both ports, so closing the
        # terminal must not drop a pivot. The claim stays on file.
        client, session, _ = self.raised_and_up(socks_sessions=2)
        state = client.post(self.url("/api/opshell/close"),
                            json={"session": session},
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

    def test_a_body_that_is_not_an_object_is_refused_not_a_crash(self):
        # The designation is on file so that a body coerced to `{}` would
        # have gone on to the session check: the 400 must be the body's.
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": self.AGENT}))
        for body in NOT_AN_OBJECT:
            with logged_tracebacks() as tracebacks:
                answer = self.post(self.url("/api/opshell/close"), body)
            self.assertEqual(answer.status_code, 400, repr(body))
            self.assertNotIn("session", answer.get_json()["error"],
                             repr(body))
            self.assertEqual(tracebacks, [], repr(body))
            self.assertEqual(self.sm.task_queues, {}, repr(body))

    def test_an_agent_field_that_is_not_a_string_names_nothing(self):
        # Its sibling `open` was fixed for this and `close` kept the line:
        # `.strip()` on an int answered 500. Now a non-string names nothing,
        # exactly as a body without `agent` does -- `open`'s rule.
        named_nothing = self.post(self.url("/api/opshell/close"),
                                  {"session": "s"})
        self.assertEqual(named_nothing.status_code, 404)
        self.assertEqual(named_nothing.get_json()["error"], "nothing is open")
        for bad in (123, True, ["badger"], {"agent": "badger"}):
            with logged_tracebacks() as tracebacks:
                answer = self.post(self.url("/api/opshell/close"),
                                   {"agent": bad, "session": "s"})
            self.assertEqual(answer.status_code, 404, repr(bad))
            self.assertEqual(answer.get_json(), named_nothing.get_json(),
                             repr(bad))
            self.assertEqual(tracebacks, [], repr(bad))
            self.assertEqual(self.sm.task_queues, {}, repr(bad))

    def test_a_whitespace_agent_falls_back_to_the_designation(self):
        # Deliberate, and `open`'s rule: with `_named` on both sources, a
        # name of only spaces names nothing, so the designated device is
        # closed. It answered 404 "nothing is open" while `close` kept the
        # `(... or "").strip()` line. The session id still guards the stop.
        client, session, _ = self.raised_and_up()
        answer = client.post(self.url("/api/opshell/close"),
                             json={"agent": "   ", "session": session},
                             headers=self.auth)
        self.assertEqual(answer.status_code, 200)
        self.assertEqual(answer.get_json()["target"], self.AGENT)
        self.assertEqual(answer.get_json()["state"], "closing")
        queued = [(t["cmd"], t["args"])
                  for t in self.sm.task_queues[self.AGENT]]
        self.assertIn(("tunnel", "stop"), queued)

    def test_a_designation_file_that_names_no_string_names_nothing(self):
        # The other source `open` guards: the hand-editable file. A number
        # there reached `.strip()` through the `or` chain just the same.
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": 123}))
        with logged_tracebacks() as tracebacks:
            answer = self.post(self.url("/api/opshell/close"), {"session": "s"})
        self.assertEqual(answer.status_code, 404)
        self.assertEqual(answer.get_json()["error"], "nothing is open")
        self.assertEqual(tracebacks, [])


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
        client, session, _ = self.raised_and_up()
        state = client.post(self.url("/api/opshell/close"),
                            json={"session": session},
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
            # The first open raises the channel, the second adopts it --
            # and the record must keep saying "raised", or the refcount
            # would be right and the stop still refused.
            client, first, _ = self.raised_and_up()
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
        # `raised_and_up`, because an adopted channel now leaves nothing on
        # file at all -- there is no owed stop to keep. The requirement is
        # about a channel this view *raised* and could not stop yet.
        client, session, _ = self.raised_and_up(socks_sessions=2)
        client.post(self.url("/api/opshell/close"),
                    json={"session": session}, headers=self.auth)
        claims = opshell.Claims(self.data_dir / "opshell-owned.json")
        self.assertIn(self.AGENT, claims.owned())
        self.assertTrue(claims.raised(self.AGENT))


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
        # Raised by this view, then up: a stop is allowed only for a
        # channel this view brought up, so a port that was already
        # connected at open time is adoption and correctly refuses.
        port = _FakeShellPort(then=b"bye", die_after_auth=True)
        self.addCleanup(port.stop)
        client, session, status = self.raised_and_up()
        status["endpoints"][0]["shell_port"] = port.port
        client.get(self.url("/api/opshell/stream?session=" + session),
                   headers=self.auth).get_data()
        client.post(self.url("/api/opshell/close"),
                    json={"session": session}, headers=self.auth)
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

    def test_the_geometry_reported_is_a_live_sessions_own(self):
        # The field used to be the constant default, every time, reported
        # even when no session existed. It read as honest because the view
        # sent back the same numbers it had been handed -- so the strip's
        # "120x40" was a restatement of the view's own guess, not a fact
        # about the pty.
        port, client = self._with_port(then=b"hello", drain=False,
                                       connections=2)
        session = self._open(client)
        # Held open, not just requested: the bridge is gone by the time a
        # buffered response has been read to its end, so a test that asked
        # afterwards measured the idle answer and would have passed against
        # the constant.
        stream = client.get(
            self.url("/api/opshell/stream?session=%s&cols=81&rows=25"
                     % session), headers=self.auth, buffered=False)
        self.addCleanup(stream.close)
        self.assertEqual(next(iter(stream.response))[:5], b"hello")
        state = client.get(self.url("/api/opshell/state?session=" + session),
                           headers=self.auth).get_json()
        self.assertEqual(state["geometry"], [81, 25])
        # A second session with a different pty, so the answer cannot be
        # "the first bridge in the dict" and still look right. Taking
        # `live[0]` returned another tab's geometry to a caller that had
        # named its own.
        other = self._open(client)
        second = client.get(
            self.url("/api/opshell/stream?session=%s&cols=100&rows=30"
                     % other), headers=self.auth, buffered=False)
        self.addCleanup(second.close)
        next(iter(second.response))
        for sid, expected in ((session, [81, 25]), (other, [100, 30])):
            answer = client.get(self.url("/api/opshell/state?session=" + sid),
                                headers=self.auth).get_json()
            self.assertEqual(answer["geometry"], expected, sid)

    def test_with_no_session_live_there_is_no_geometry_to_report(self):
        # Nothing has a geometry when nothing is open. The constant that
        # used to be reported here is what the *next* session would be
        # given, which is not a fact about this device.
        port, client = self._with_port(then=b"x", die_after_auth=True)
        state = client.get(self.url("/api/opshell/state"),
                           headers=self.auth).get_json()
        self.assertIsNone(state["geometry"])

    def test_a_tunnel_that_is_reset_ends_the_stream_with_a_reason(self):
        """I4 of the final review, and it escaped the response.

        `Bridge.read`'s docstring makes the distinction deliberately ("a
        shell that exited and a tunnel that was lost are not the same
        news") and the pump then caught only `socket.timeout`, so a reset
        raised `ConnectionResetError` out of the generator and aborted the
        chunked response mid-flight with a traceback. It survived the whole
        branch because every other fake port here closes politely.
        """
        port, client = self._with_port(then=b"root@parrot:~# ", reset=True)
        session = self._open(client)
        answer = client.get(self.url("/api/opshell/stream?session=" + session),
                            headers=self.auth)
        self.assertEqual(answer.status_code, 200)
        body = answer.get_data()
        self.assertIn(b"root@parrot", body)
        # A named reason, and one the operator can tell apart from `exit`:
        # a clean end prints "session ended" in the browser, and this must
        # not look like that.
        self.assertRegex(body, rb"(?i)tunnel.*(lost|reset)")

    def test_a_port_that_hangs_up_cleanly_says_so_differently(self):
        # The other half of the same distinction: without this, naming the
        # reset could be done by naming everything the same way.
        port, client = self._with_port(then=b"bye", die_after_auth=True)
        session = self._open(client)
        body = client.get(self.url("/api/opshell/stream?session=" + session),
                          headers=self.auth).get_data()
        self.assertNotRegex(body, rb"(?i)tunnel.*(lost|reset)")

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
        first = claims.open("raccoon-bandit", raised=True)
        second = claims.open("raccoon-bandit", raised=True)
        queues = {}
        queued, last, _ = opshell.end_session(
            claims, "raccoon-bandit", first, {"socks": {"sessions": 0}},
            False, queues, {}, "now")
        self.assertEqual((queued, last, queues), (False, False, {}))
        self.assertTrue(claims.holds("raccoon-bandit", second))

    def test_the_last_session_queues_the_stop(self):
        claims = opshell.Claims(self.path)
        only = claims.open("raccoon-bandit", raised=True)
        queues = {}
        queued, last, _ = opshell.end_session(
            claims, "raccoon-bandit", only, {"socks": {"sessions": 0}},
            False, queues, {}, "now")
        self.assertTrue(queued and last)
        self.assertEqual([t["args"] for t in queues["raccoon-bandit"]],
                         ["stop"])

    def test_a_live_pivot_leaves_it_owed_with_a_reason(self):
        claims = opshell.Claims(self.path)
        only = claims.open("raccoon-bandit", raised=True)
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
        only = claims.open("raccoon-bandit", raised=True)
        queues = {}
        queued, _last, _why = opshell.end_session(
            claims, "raccoon-bandit", only, None, True, queues, {}, "now")
        self.assertTrue(queued)


class TestTheSweepClosesWhatNobodyWatches(_ClaimsCase):
    def test_a_lapsed_claim_gets_its_stop_queued(self):
        claims = opshell.Claims(self.path, grace=10.0)
        claims.open("raccoon-bandit", raised=True)
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
        claims.open("raccoon-bandit", raised=True)
        queues = {}
        done = opshell.sweep(claims, ["raccoon-bandit"],
                             {"raccoon-bandit": {"socks": {"sessions": 0}}},
                             {"raccoon-bandit": False}, queues, {}, "now",
                             time.time())
        self.assertEqual((done, queues), ([], {}))

    def test_a_lapsed_claim_over_a_live_pivot_is_not_dropped(self):
        claims = opshell.Claims(self.path, grace=10.0)
        claims.open("raccoon-bandit", raised=True)
        queues = {}
        done = opshell.sweep(claims, ["raccoon-bandit"],
                             {"raccoon-bandit": {"socks": {"sessions": 2}}},
                             {"raccoon-bandit": False}, queues, {}, "now",
                             time.time() + 11)
        self.assertEqual((done, queues), ([], {}))
        self.assertIn("raccoon-bandit", claims.owned())

    def test_an_agent_that_left_the_fleet_is_forgotten_not_tasked(self):
        claims = opshell.Claims(self.path, grace=10.0)
        claims.open("gone-raccoon", raised=True)
        queues = {}
        done = opshell.sweep(claims, [], {}, {}, queues, {}, "now",
                             time.time() + 11)
        self.assertEqual((done, queues), ([], {}))
        self.assertEqual(claims.owned(), [])

    def test_ownership_left_by_a_dead_process_is_swept_at_once(self):
        # `reconcile`'s half: no live claim at all, which is what a restart
        # leaves behind.
        opshell.Claims(self.path).open("raccoon-bandit", raised=True)
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
        claims.open("raccoon-bandit", raised=True)
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
        claims.open("raccoon-bandit", raised=True)
        queues = {}
        queued, why = opshell.decide_stop(
            claims, "raccoon-bandit", {"socks": {"sessions": 0}}, False,
            queues, {}, "now", already_pending=True)
        self.assertFalse(queued)
        self.assertIn("already queued", why)
        self.assertEqual(queues, {})

    def test_a_settled_stop_releases_the_ownership_that_owed_it(self):
        claims = opshell.Claims(self.path, grace=10.0)
        claims.open("raccoon-bandit", raised=True)
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
        claims.open("raccoon-bandit", raised=True)
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


class TestAChannelThisViewNeverRaisedIsNotItsToStop(_RouteCase):
    """The plan's Global Constraint, which I broke with a fix.

    The rule: stop only a channel this view raised, and only with no live
    SOCKS session. `/open` writes ownership unconditionally, so "owned"
    meant "this view has a session here" -- and the Attach button I added
    for the third review's I6, plus the End button, made that one click.
    Measured before the fix: a connected endpoint the view had never
    raised, 0 SOCKS sessions, one open and one close -> `stop` queued.

    The second half of the rule always held: with a live SOCKS session the
    stop is refused. So this is about an idle pivot somebody else brought
    up and still wants.
    """

    def _adopt_and_close(self, socks=0):
        app = self.app(supervisor=self.connected(socks_sessions=socks))
        client = self.operator_client(app)
        opened = client.post(self.url("/api/opshell/open"),
                             json={"agent": self.AGENT},
                             headers=self.auth).get_json()
        answer = client.post(self.url("/api/opshell/close"),
                             json={"session": opened["session"]},
                             headers=self.auth).get_json()
        queued = [q["args"] for q in self.sm.task_queues.get(self.AGENT, [])]
        done = [e.get("args") for e in self.sm.history.get(self.AGENT, [])
                if e.get("cmd") == "tunnel"]
        return answer, queued + done

    def test_an_adopted_channel_is_not_stopped(self):
        answer, tasks = self._adopt_and_close()
        self.assertNotIn("stop", tasks,
                         "a channel this view never raised was stopped")
        self.assertRegex(answer.get("reason") or "", r"(?i)did not raise|"
                         r"was not (started|raised) (by|from) ")

    def test_a_channel_this_view_did_raise_is_stopped(self):
        # The other half, or the fix would be "never stop anything".
        client, session, _ = self.raised_and_up()
        client.post(self.url("/api/opshell/close"),
                    json={"session": session}, headers=self.auth)
        tasks = [q["args"] for q in self.sm.task_queues.get(self.AGENT, [])]
        tasks += [e.get("args") for e in self.sm.history.get(self.AGENT, [])
                  if e.get("cmd") == "tunnel"]
        self.assertIn("stop", tasks)

    def test_raising_it_later_makes_it_this_views_to_stop(self):
        # Adopted first, then raised: ownership of the stop is sticky, so
        # the record cannot be downgraded by a second adopting open.
        claims = opshell.Claims(self.data_dir / "r.json")
        claims.open("clumsy-raccoon", raised=False)
        claims.open("clumsy-raccoon", raised=True)
        self.assertTrue(claims.raised("clumsy-raccoon"))
        claims.open("clumsy-raccoon", raised=False)
        self.assertTrue(claims.raised("clumsy-raccoon"),
                        "a later adopting open forgot that we raised it")

    def test_the_record_survives_a_restart_with_the_distinction(self):
        path = self.data_dir / "r2.json"
        opshell.Claims(path).open("clumsy-raccoon", raised=True)
        self.assertTrue(opshell.Claims(path).raised("clumsy-raccoon"))
        other = self.data_dir / "r3.json"
        opshell.Claims(other).open("clumsy-raccoon", raised=False)
        self.assertFalse(opshell.Claims(other).raised("clumsy-raccoon"))

    def test_an_older_record_without_the_field_is_treated_as_raised(self):
        # Records written before this field existed describe channels the
        # view did raise -- that was the only way to get one. Reading them
        # as "adopted" would orphan their stops for ever.
        path = self.data_dir / "r4.json"
        path.write_text(json.dumps({"clumsy-raccoon":
                                    {"since": "2026-11-18T00:00:00Z"}}))
        self.assertTrue(opshell.Claims(path).raised("clumsy-raccoon"))


class TestAnAdoptedClaimIsNotSweptForEver(_ClaimsCase):
    def test_adopting_a_channel_leaves_nothing_behind_to_sweep(self):
        """I5 of the fourth review.

        An adopting `open` wrote an ownership record, `reconcile` reported
        it owed on every sweep, `decide_stop` refused it every time, and
        nothing could ever release it: `settled` cannot be true for a stop
        that was never queued. Measured: five sweeps, no tasks, still
        owned -- and each leaked record costs one relay round trip per
        `/state` poll and per check-in, which is the cost the sweep was
        narrowed to avoid.
        """
        claims = opshell.Claims(self.path)
        session = claims.open("raccoon-bandit", raised=False)
        self.assertEqual(claims.owned(), [],
                         "an adopting claim left ownership on file")
        # The session is still counted -- the refcount is what stops
        # another tab's close queueing a stop under this one.
        self.assertEqual(claims.sessions("raccoon-bandit"), 1)
        queues = {}
        # Inside the lapse margin, so the session is still watching: the
        # point is that a sweep finds nothing to owe, not that a lapsed
        # session cannot be closed.
        for _ in range(5):
            opshell.sweep(claims, ["raccoon-bandit"],
                          {"raccoon-bandit": {"socks": {"sessions": 0}}},
                          {"raccoon-bandit": False}, queues, {}, "now",
                          time.time(), {}, {})
        self.assertEqual(queues, {}, "an adopted channel was swept")
        self.assertTrue(claims.close("raccoon-bandit", session))
        # And after it lapses: still nothing owed, because nothing is owned.
        claims2 = opshell.Claims(self.path)
        claims2.open("raccoon-bandit", raised=False)
        opshell.sweep(claims2, ["raccoon-bandit"],
                      {"raccoon-bandit": {"socks": {"sessions": 0}}},
                      {"raccoon-bandit": False}, queues, {}, "now",
                      time.time() + 10000, {}, {})
        self.assertEqual(queues, {})

    def test_raising_one_later_still_records_it(self):
        # The upgrade path has to work from nothing on file, since an
        # adopting open now leaves nothing.
        claims = opshell.Claims(self.path)
        claims.open("raccoon-bandit", raised=False)
        claims.open("raccoon-bandit", raised=True)
        self.assertEqual(claims.owned(), ["raccoon-bandit"])
        self.assertTrue(claims.raised("raccoon-bandit"))


class TestANotTheLastCloseSaysWhy(_RouteCase):
    def test_a_second_tabs_close_comes_back_with_a_reason(self):
        # `end_session` returned `(False, False, "")` for a close that was
        # not the last, so the route sent no reason and the view had
        # nothing to show. Correct behaviour with no explanation is still a
        # button that looks broken.
        app = self.app(supervisor=self.connected())
        first = self.operator_client(app)
        second = self.operator_client(app)
        a = first.post(self.url("/api/opshell/open"),
                       json={"agent": self.AGENT},
                       headers=self.auth).get_json()["session"]
        second.post(self.url("/api/opshell/open"), json={"agent": self.AGENT},
                    headers=self.auth)
        answer = first.post(self.url("/api/opshell/close"),
                            json={"session": a}, headers=self.auth).get_json()
        self.assertRegex(answer.get("reason") or "",
                         r"(?i)another view|still (open|holding)")


class TestTheFixturesDoNotInventFieldNames(_RouteCase):
    """The third field-name error of this branch, and its last.

    Twice before, a fixture invented a key and the test then compared a
    typo against a typo. The third time it was `shell_transcript_dir`,
    which is the *config* key; `TunnelSupervisor.status()` reports the
    directory as `shell_transcripts`. So the Closed state's transcript
    path was permanently `null` in production while 194 tests passed.

    Reading the field names out of a real supervisor is the only version
    of this that cannot drift.
    """

    def real_status_keys(self):
        from software.c2.tunnel import supervisor as sup
        real = sup.TunnelSupervisor({"shell_transcript_dir": "/tmp/x"},
                                    self.data_dir)
        return set(real.status())

    def test_every_key_this_fixture_reports_is_one_the_real_one_reports(self):
        real = self.real_status_keys()
        for name in ("connected", "configured_but_stopped"):
            fixture = getattr(self, name)().status()
            unknown = set(fixture) - real
            self.assertEqual(unknown, set(),
                             "%s() invents %s" % (name, sorted(unknown)))

    def test_every_fixture_in_this_file_is_checked_not_two_by_name(self):
        # The first version named two fixtures by hand, so a third --
        # `running_without_shell_ports` -- was checked against nothing. The
        # list is discovered now.
        import inspect
        real = self.real_status_keys()
        found = 0
        for name, method in inspect.getmembers(self, inspect.ismethod):
            if name.startswith(("test_", "_")) or name in (
                    "real_status_keys", "setUp", "tearDown", "run",
                    "debug", "countTestCases", "defaultTestResult",
                    "shortDescription", "id", "subTest", "addCleanup",
                    "doCleanups", "addTypeEqualityFunc", "skipTest",
                    "client", "operator_client", "app", "get", "post",
                    "url", "dead_port", "raised_and_up"):
                continue
            try:
                value = method()
            except Exception:
                continue
            status = getattr(value, "status", None)
            if not callable(status):
                continue
            fixture = status()
            if not isinstance(fixture, dict) or "endpoints" not in fixture:
                continue
            found += 1
            unknown = set(fixture) - real
            self.assertEqual(unknown, set(),
                             "%s() invents %s" % (name, sorted(unknown)))
        self.assertGreaterEqual(found, 3,
                                "only %d supervisor fixtures were found" % found)

    def test_an_endpoint_row_reports_the_fields_the_server_reads(self):
        """Most of the fixture's surface is the endpoint row.

        A row is built in two places and the C2 only ever sees the second:
        `tunnel/server.py` makes it and `tunnel/__main__.py` augments it
        with the SOCKS and shell halves. So the names are checked against
        both sources rather than against a list in this file -- a list here
        is the typo-against-a-typo shape again.
        """
        repo = Path(__file__).resolve().parents[1] / "c2" / "tunnel"
        upstream = ((repo / "server.py").read_text()
                    + (repo / "__main__.py").read_text())
        row = self.connected().status()["endpoints"][0]
        for field in ("implant_id", "state", "user", "hostname",
                      "shell_port", "shell_password", "shell_recording",
                      "history", "history_detail",
                      "shell", "socks"):
            self.assertIn(field, row, "the fixture omits %r" % field)
            self.assertIn('"%s"' % field, upstream,
                          "nothing upstream writes %r" % field)
        for inner in ("sessions", "max_sessions"):
            self.assertIn(inner, row["shell"], inner)
            self.assertIn(inner, row["socks"], inner)

    def test_the_strip_gets_a_host_to_show(self):
        # `connected()` omitted `hostname`, so `out["host"]` was "" in
        # every route test and the strip's host was never exercised end to
        # end. A target, because `/state` answers before the row without
        # one -- which is how the first version of this test measured the
        # early answer instead of the field it names.
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": self.AGENT}))
        state = self.client().get(self.url("/api/opshell/state"),
                                  headers=self.auth).get_json()
        self.assertEqual(state["host"], "parrot")

    def test_the_server_reads_the_key_the_supervisor_writes(self):
        real = self.real_status_keys()
        self.assertIn("shell_transcripts", real)
        src = (Path(__file__).resolve().parents[1] / "c2" / "server.py").read_text()
        at = src.index('out["transcript_dir"]')
        self.assertIn("shell_transcripts", src[at:at + 200])

    def test_the_transcript_directory_reaches_the_view(self):
        # The property itself, through the route: the strip badges
        # "recording" from a field that is real, so an operator was told a
        # transcript existed and given nowhere to look for it.
        client = self.client()
        state = client.get(self.url("/api/opshell/state"),
                           headers=self.auth).get_json()
        self.assertEqual(state["transcript_dir"], "/tmp/transcripts")


class TestADeviceThatStoppedCallingHomeIsNotReportedLive(_RouteCase):
    def test_an_agent_hours_overdue_is_not_reported_open(self):
        """Review Focus 1's second form: "never checks in again".

        Measured by the reviewer: an agent still in the fleet, last seen
        two hours ago, reporting a running child, came back as
        `state: live, channel: open, expected_checkin: -6900` -- a positive
        claim about a device nothing had heard from, with the overdue
        number computed and rendered only in the waiting state. The
        operator's close then queues a stop that can never be delivered.
        """
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": self.AGENT}))
        self.sm.agents[self.AGENT]["_last_seen_ts"] = time.time() - 7200
        self.sm.agents[self.AGENT]["tunnel"] = {"pid": 9, "running": True}
        client = self.client()
        state = client.get(self.url("/api/opshell/state"),
                           headers=self.auth).get_json()
        self.assertEqual(state["channel"], "unknown")
        self.assertRegex(state["reason"] or "", r"(?i)overdue|has not checked")

    def test_the_overdue_reason_states_the_silence_not_the_lateness(self):
        # I3. It printed `-expected_checkin`, which is seconds *past due*,
        # under the words "has not checked in for" -- so 7200 s of silence
        # on a 300 s interval was reported as 6900. One whole interval out,
        # and `docs/TUNNEL.md` describes it as the silence.
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": self.AGENT}))
        self.sm.agents[self.AGENT]["_last_seen_ts"] = time.time() - 7200
        state = self.client().get(self.url("/api/opshell/state"),
                                  headers=self.auth).get_json()
        self.assertRegex(state["reason"], r"7\d\d\d seconds")

    def test_a_queued_start_on_an_overdue_device_still_shows_as_waiting(self):
        # I4. The overdue branch returned before the state machine, so a
        # queued start showed no `waiting` and no countdown: the operator
        # saw nothing happen and clicked again, taking a fresh claim each
        # time.
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": self.AGENT}))
        client = self.operator_client(self.app(
            supervisor=self.configured_but_stopped()))
        client.post(self.url("/api/opshell/open"), json={"agent": self.AGENT},
                    headers=self.auth)
        self.sm.agents[self.AGENT]["_last_seen_ts"] = time.time() - 7200
        state = client.get(self.url("/api/opshell/state"),
                           headers=self.auth).get_json()
        self.assertEqual(state["state"], "waiting")
        self.assertEqual(state["channel"], "unknown")
        self.assertRegex(state["reason"], r"(?i)has not checked in")

    def test_the_threshold_is_bounded_from_both_sides(self):
        # The pair below bounds the constant only to 2..24: raising it to
        # 24 left both green. These two sit either side of the boundary.
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": self.AGENT}))
        for age, expected in ((750, "unknown"), (450, "open")):
            self.sm.agents[self.AGENT]["_last_seen_ts"] = time.time() - age
            self.sm.agents[self.AGENT]["tunnel"] = {"pid": 9, "running": True}
            client = self.operator_client(self.app(
                supervisor=self.connected()))
            state = client.get(self.url("/api/opshell/state"),
                               headers=self.auth).get_json()
            self.assertEqual(state["channel"], expected, age)

    def test_a_jittered_beacon_is_not_called_overdue_for_being_jittered(self):
        # The beacon draws its sleep from [interval*(1-j), interval*(1+j)],
        # and jitter is operator-settable up to 100%. At that setting a
        # perfectly healthy agent crosses a flat two-interval line with no
        # missed check-in, and the view would flap to `unknown`.
        # The record shape production writes: `server.py` stores the
        # beacon's reported profile at `agents[id]["c2_profile"]` and
        # `beacon.py` puts `jitter` inside it. The first version of this
        # test invented a top-level `jitter` key -- the fourth time on this
        # branch that a fixture named a field production does not write,
        # and the hazard stayed live behind a green test.
        agent = {"_last_seen_ts": 1000.0, "interval": 300,
                 "c2_profile": {"jitter": 100}}
        self.assertFalse(opshell.report_is_overdue(agent, 1000.0 + 650))
        # A beacon with no jitter keeps the tight line.
        steady = {"_last_seen_ts": 1000.0, "interval": 300,
                  "c2_profile": {"jitter": 0}}
        self.assertTrue(opshell.report_is_overdue(steady, 1000.0 + 650))
        # And an agent that has reported no profile is given the
        # generator's own default rather than zero, because its beacon
        # still jitters.
        silent = {"_last_seen_ts": 1000.0, "interval": 300}
        self.assertFalse(opshell.report_is_overdue(silent, 1000.0 + 650))
        self.assertTrue(opshell.report_is_overdue(silent, 1000.0 + 1200))

    def test_every_agent_field_this_module_reads_is_one_the_server_writes(self):
        """The class fix for four instances of the same mistake.

        Twice a supervisor key, once a status key, once an agent-record
        key: a fixture invented the name, the code read the same invented
        name, and the test compared a typo against a typo. The guard added
        for the supervisor's keys did not cover the agent record, so the
        fourth one went through it.
        """
        import re as _re
        src = (Path(__file__).resolve().parents[1] / "c2" / "opshell.py").read_text()
        server = (Path(__file__).resolve().parents[1] / "c2" / "server.py").read_text()
        reads = set(_re.findall(r'agent\.get\("(\w+)"\)', src))
        reads |= set(_re.findall(r'agent\[\"(\w+)\"\]', src))
        # Nested reads too. The guard's first version saw only direct
        # accesses, so `c2_profile["jitter"]` -- the field the fix beside
        # it had just added -- was invisible to it.
        nested = set(_re.findall(r'\(profile or \{\}\)\.get\(\"(\w+)\"\)',
                                 src))
        self.assertTrue(reads, "no agent fields are read any more")
        # Only the agent-record writers, not any dict key anywhere in a
        # 426 KB file. The looser alternative matched `"host":` and
        # `"state":` in the embedded JavaScript, so it would have passed
        # names the server never puts on an agent record.
        writers = "\n".join(
            line for line in server.splitlines()
            if _re.search(r'agents\[[^\]]+\]\[|payload\[|payload\.get',
                          line))
        for field in sorted(reads):
            self.assertRegex(
                writers, r'\"%s\"' % field,
                "opshell.py reads agent[%r] and no agent-record writer in "
                "server.py mentions it" % field)
        for field in sorted(nested):
            self.assertRegex(
                server, r'\"%s\"' % field,
                "opshell.py reads a nested %r that nothing writes" % field)

    def test_an_agent_that_is_merely_late_is_still_reported_as_it_is(self):
        # One missed interval is normal: jitter, a slow link, a host that
        # was busy. Calling that "unknown" would make the word useless.
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": self.AGENT}))
        self.sm.agents[self.AGENT]["_last_seen_ts"] = time.time() - 310
        self.sm.agents[self.AGENT]["tunnel"] = {"pid": 9, "running": True}
        client = self.client()
        state = client.get(self.url("/api/opshell/state"),
                           headers=self.auth).get_json()
        self.assertEqual(state["channel"], "open")


class TestTheCheapGuardsOnTheRoutes(_RouteCase):
    def test_a_huge_paste_is_refused_rather_than_holding_a_worker(self):
        # `/keys` had no ceiling, so one paste could hold a worker thread
        # for the whole 15 s write timeout.
        answer = self.post(self.url("/api/opshell/keys"),
                           {"session": "x",
                            "data": base64.b64encode(b"A" * 400000).decode()})
        self.assertEqual(answer.status_code, 413)

    def test_data_that_is_not_a_string_is_a_bad_request_not_a_crash(self):
        # The ceiling I added introduced its own defect: `len()` on a
        # number raises TypeError, so `{"data": 5}` became HTTP 500 where
        # the old `except Exception` had answered 400. An earlier round of
        # this work had two fixes that each introduced a fault; this is the
        # third.
        for junk in (5, True, {"a": 1}, [1, 2], None):
            answer = self.post(self.url("/api/opshell/keys"),
                               {"session": "x", "data": junk})
            self.assertLess(answer.status_code, 500, repr(junk))

    def test_a_body_that_is_not_an_object_is_a_bad_request_not_a_crash(self):
        for body in NOT_AN_OBJECT:
            with logged_tracebacks() as tracebacks:
                answer = self.post(self.url("/api/opshell/keys"), body)
            self.assertEqual(answer.status_code, 400, repr(body))
            self.assertEqual(tracebacks, [], repr(body))

    def test_a_paste_a_person_could_make_is_not_refused(self):
        # The ceiling has to be above anything an operator would actually
        # paste, or it is a new defect rather than a guard. A 64 KB script
        # pasted into a shell is a real thing to do.
        answer = self.post(self.url("/api/opshell/keys"),
                           {"session": "x",
                            "data": base64.b64encode(b"A" * 65536).decode()})
        self.assertNotEqual(answer.status_code, 413)

    def test_the_designation_is_no_more_readable_than_the_ownership_record(self):
        # Its sibling is written 0600 deliberately. A hostname is not a
        # secret, but "which host is the operator working on" is exactly
        # the sort of thing that should not be world-readable in a data
        # directory, and the inconsistency invites someone to relax the
        # other one to match.
        client = self.client()
        client.post(self.url("/api/opshell/open"), json={"agent": self.AGENT},
                    headers=self.auth)
        target = self.data_dir / "opshell-target.json"
        self.assertTrue(target.exists())
        self.assertEqual(oct(target.stat().st_mode & 0o777), "0o600")


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


    def test_no_route_answers_500_for_any_shape_of_damage(self):
        """The property the class name claims, over every shape.

        This class tested `"{not json"` only, and the final review found
        that one stray byte took a different path: `read_text()` raises
        `UnicodeDecodeError`, which is not an `OSError`, so it escaped the
        guard and every route answered 500.

        A fresh app per shape, which is a restart per shape. The first
        version of this reused the cached client and so answered all three
        times out of the app built for the *first* damage -- measured:
        shapes two and three logged nothing at all, because nothing had
        read them. Three assertions about one file.
        """
        (self.data_dir / "opshell-target.json").write_text(
            json.dumps({"agent": self.AGENT}))
        for damage in (b"{not json", b"\xff\xfe not utf-8", b"[]",
                       b'{"a": 1}\xff'):
            (self.data_dir / "opshell-owned.json").write_bytes(damage)
            client = self.operator_client(self.app(supervisor=self.connected()))
            with self.assertLogs("raccoon.c2.server", level="ERROR"):
                answers = [
                    client.get(self.url("/api/opshell/state"),
                               headers=self.auth),
                    client.get(self.url("/api/opshell/stream"),
                               headers=self.auth),
                    client.post(self.url("/api/opshell/open"), json={},
                                headers=self.auth),
                    client.post(self.url("/api/opshell/close"),
                                json={"session": "x"}, headers=self.auth),
                    client.post(self.url("/api/opshell/keys"),
                                json={"session": "x", "data": ""},
                                headers=self.auth),
                ]
            for answer in answers:
                self.assertLess(answer.status_code, 500,
                                "%r: HTTP %d" % (damage, answer.status_code))
            # And it names the record rather than going quiet. Not
            # `channel: unknown`: a damaged record does not stop the server
            # seeing a channel that is up, and calling that one "unknown"
            # would be the lie this view exists to avoid.
            body = answers[0].get_json() or {}
            self.assertIn("ownership record", body.get("reason") or "",
                          repr(damage))


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


class TestTheViewNeverReportsAStateItHasNotGot(_RouteCase):
    def test_an_agent_that_left_the_fleet_leaves_the_channel_unknown(self):
        """Review Focus condition 1, which asked for exactly this word.

        The claim's half was right and tested; the view's half reported
        `channel: "closed"` from the default, so the strip said "channel
        closed" about a device nothing had heard from. Nothing in the
        feature had seen that channel go down.
        """
        app = self.app(supervisor=self.connected())
        client = self.operator_client(app)
        session = client.post(self.url("/api/opshell/open"),
                              json={"agent": self.AGENT},
                              headers=self.auth).get_json()["session"]
        self.sm.agents.pop(self.AGENT, None)
        state = client.get(self.url("/api/opshell/state?session=" + session),
                           headers=self.auth).get_json()
        self.assertEqual(state["channel"], "unknown")
        self.assertIn("no longer in the fleet", state["reason"])


class TestTheSweepRunsOnCheckInsAndNotOnEverything(_RouteCase):
    def test_a_result_post_does_not_pay_for_a_relay_round_trip(self):
        # The sweep ran on every beacon request, including `register` and
        # `result`, each costing one `tunnel_supervisor.status()` per owned
        # agent. A busy agent posts many results per check-in.
        (self.data_dir / "opshell-owned.json").write_text(
            json.dumps({self.AGENT: {"since": "2026-11-18T00:00:00Z"}}))
        supervisor = self.connected()
        calls = []
        real = supervisor.status
        supervisor.status = lambda *a, **k: (calls.append(1), real(*a, **k))[1]
        app = self.app(supervisor=supervisor)
        client = app.test_client()
        client.post("http://localhost:1/api/v1/beacon",
                    json=self.crypto.wrap({"action": "beacon",
                                           "agent_id": self.AGENT}))
        after_checkin = len(calls)
        self.assertGreater(after_checkin, 0, "the check-in did not sweep")
        client.post("http://localhost:1/api/v1/beacon",
                    json=self.crypto.wrap({"action": "result",
                                           "agent_id": self.AGENT,
                                           "task_id": "t", "output": "x"}))
        self.assertEqual(len(calls), after_checkin,
                         "a result post swept as well")


class TestOneGraceForEveryDriver(_RouteCase):
    def test_a_second_tab_cannot_retire_a_hidden_tabs_session(self):
        """The same defect as C1, from the other side.

        `/state` swept with the claim record's own 60 s grace -- which the
        check-in's new comment itself identifies as a hidden browser tab's
        exact poll period. So a second panel polling every two seconds
        retired the hidden tab's session, and the operator came back to a
        channel somebody else's page had stopped. Fixed by having one
        number instead of two: nothing is gained by being tighter than the
        slowest live poll, because the stop waits for a check-in anyway.
        """
        app = self.app(supervisor=self.connected())
        hidden = self.operator_client(app)
        with unittest.mock.patch.object(opshell.time, "time",
                                        return_value=time.time() - 90):
            session = hidden.post(self.url("/api/opshell/open"),
                                  json={"agent": self.AGENT},
                                  headers=self.auth).get_json()["session"]
        self.sm.task_queues.pop(self.AGENT, None)
        self.sm.history.pop(self.AGENT, None)
        # A second panel on the same server, polling now.
        self.operator_client(app).get(self.url("/api/opshell/state"),
                                      headers=self.auth)
        tunnel = [e.get("args") for e in self.sm.history.get(self.AGENT, [])
                  if e.get("cmd") == "tunnel"]
        self.assertEqual(tunnel, [],
                         "another tab's poll stopped a hidden tab's channel")
        state = hidden.get(self.url("/api/opshell/state?session=" + session),
                           headers=self.auth).get_json()
        self.assertEqual(state["sessions"], 1)

    def test_there_is_only_one_grace_to_get_wrong(self):
        # Two numbers meant two places to reason about, and the second one
        # was missed. The claim record's default *is* the lapse margin.
        self.assertEqual(
            opshell.Claims(self.data_dir / "g.json").grace,
            opshell.LAPSE_GRACE)
        import inspect
        self.assertNotIn("lapse_grace",
                         inspect.signature(opshell.sweep).parameters)


class TestTheLapseIsTheSameForEverySweep(_ClaimsCase):
    """One margin, and no caller can choose another.

    These tests have been rewritten twice, which is the point of the
    docstring. First they pinned `lapsed=False` / `lapsed=True` -- and that
    boolean's only False caller, the check-in, was the one that had to
    lapse. Then they pinned a per-driver grace, and the driver that kept
    the narrow one retired hidden tabs. Now there is one number.
    """

    def test_silence_inside_the_margin_keeps_the_claim(self):
        claims = opshell.Claims(self.path, grace=40.0)
        claims.open("raccoon-bandit", raised=True)
        queues = {}
        opshell.sweep(claims, ["raccoon-bandit"],
                      {"raccoon-bandit": {"socks": {"sessions": 0}}},
                      {"raccoon-bandit": False}, queues, {}, "now",
                      time.time() + 11, {}, {})
        self.assertEqual(queues, {})
        self.assertEqual(claims.sessions("raccoon-bandit"), 1)

    def test_silence_past_the_margin_queues_the_stop(self):
        claims = opshell.Claims(self.path, grace=40.0)
        claims.open("raccoon-bandit", raised=True)
        queues = {}
        opshell.sweep(claims, ["raccoon-bandit"],
                      {"raccoon-bandit": {"socks": {"sessions": 0}}},
                      {"raccoon-bandit": False}, queues, {}, "now",
                      time.time() + 41, {}, {})
        self.assertEqual([t["args"] for t in queues["raccoon-bandit"]],
                         ["stop"])

    def test_no_caller_can_ask_for_a_different_judgement(self):
        # Neither an abstention nor a margin of its own. Both existed, and
        # both became a defect in the same place.
        import inspect
        taken = inspect.signature(opshell.sweep).parameters
        self.assertNotIn("lapsed", taken)
        self.assertNotIn("lapse_grace", taken)

    def test_the_margin_clears_the_slowest_poll_a_live_browser_makes(self):
        # A hidden tab is throttled to about one poll a minute. The margin
        # has to clear that by enough that jitter cannot reach it, and
        # halving it should fail here rather than in the field, where the
        # symptom is a channel retired under a live tab.
        self.assertGreaterEqual(opshell.LAPSE_GRACE, 4 * 60.0)


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

    def test_a_check_in_retires_a_claim_no_browser_is_behind(self):
        """The anti-goal, reached by closing a browser.

        Found by the final review, and it was my own parked ruling: the
        lapse ran only from `/state`, so the one driver that arrives when
        no browser exists -- and the only moment a stop can be delivered --
        passed `lapsed=False` and never retired the stale session.
        `reconcile` then saw a session count of 1 and owed nothing. Measured
        over ten check-ins and 100000 simulated seconds: no stop. Worse,
        Task 8 then documented the opposite in `docs/TUNNEL.md`.

        The session's last beat is put in the past rather than the clock
        moved forward, so the check-in runs in real time like every other
        request.
        """
        supervisor = self.configured_but_stopped()
        status = supervisor.status()
        app = self.app(supervisor=supervisor)
        client = self.operator_client(app)
        with unittest.mock.patch.object(opshell.time, "time",
                                        return_value=time.time() - 1000):
            client.post(self.url("/api/opshell/open"),
                        json={"agent": self.AGENT}, headers=self.auth)
        # The endpoint appears between the two requests, as it does when
        # the agent's start lands. Opening onto one that was already there
        # is adoption, and an adopted channel is not this view's to stop.
        status["state"] = "running"
        status["endpoints"] = [{
            "identity": "parrot-box", "implant_id": self.IMPLANT,
                "hostname": "parrot",
            "state": "connected", "user": "root",
            "shell_port": self.dead_port(),
            "shell_password": self.SHELL_PASSWORD,
            "shell_recording": True,
            "history": "off",
            "history_detail": "",
            "shell": {"sessions": 0, "max_sessions": 4},
            "socks": {"sessions": 0, "max_sessions": 256},
        }]
        self.sm.task_queues.pop(self.AGENT, None)
        self.sm.history.pop(self.AGENT, None)
        app.test_client().post(
            "http://localhost:1/api/v1/beacon",
            json=self.crypto.wrap({"action": "beacon",
                                   "agent_id": self.AGENT}))
        tunnel = [e.get("args") for e in self.sm.history.get(self.AGENT, [])
                  if e.get("cmd") == "tunnel"]
        self.assertEqual(tunnel, ["stop"],
                         "a check-in with no browser behind the claim left "
                         "the channel up")

    def test_a_check_in_does_not_retire_a_tab_that_is_merely_throttled(self):
        """The reason the lapse was switched off here, and it is real.

        A hidden browser tab is throttled to about one poll a minute, and
        the view's own grace is 60 s -- exactly that edge. So this driver
        gets a wider margin instead of no judgement at all: 60 s of silence
        is a throttled tab, 1000 s is a tab that is gone.

        Measured by outcome. The version this replaces asserted that
        `Claims.lapsed` was never *called*, which pinned the implementation
        detail that turned out to be the defect.
        """
        app = self.app(supervisor=self.connected())
        client = self.operator_client(app)
        # 120 s, not 60: the margin against a 60 s grace used to be the
        # milliseconds between `/open` and the beacon POST, so the test
        # passed on a float tick. A hidden tab polls about once a minute,
        # so two missed polls is the case worth asserting.
        with unittest.mock.patch.object(opshell.time, "time",
                                        return_value=time.time() - 120):
            session = client.post(self.url("/api/opshell/open"),
                                  json={"agent": self.AGENT},
                                  headers=self.auth).get_json()["session"]
        self.sm.task_queues.pop(self.AGENT, None)
        self.sm.history.pop(self.AGENT, None)
        app.test_client().post(
            "http://localhost:1/api/v1/beacon",
            json=self.crypto.wrap({"action": "beacon",
                                   "agent_id": self.AGENT}))
        tunnel = [e.get("args") for e in self.sm.history.get(self.AGENT, [])
                  if e.get("cmd") == "tunnel"]
        self.assertEqual(tunnel, [], "a throttled tab lost its channel")
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
#: The page's one stylesheet. Read on its own, because the regex that used
#: to run over the whole file also matched every `if(x){...}` in the
#: JavaScript below it.
STYLE_BLOCK = SERVER_SRC[SERVER_SRC.index("<style>")
                         + len("<style>"):SERVER_SRC.index("</style>")]


def _css_blocks(css):
    """`(selector, body)` for every rule, descending into at-rules.

    A real parse and not one regex, because a regex that stops at the
    first `}` reads `@media (min-width:1px){.opshell-card{position:
    absolute}}` as one rule whose selector is the `@media` -- so the rule
    inside it is never examined, and a layout a test forbids goes green
    by being nested. `@keyframes` is descended into as well, which costs
    a `50%` "selector" nobody asks about.
    """
    out, i = [], 0
    while True:
        at = css.find("{", i)
        if at < 0:
            return out
        selector, depth, j = css[i:at].strip(), 0, at
        while j < len(css):
            if css[j] == "{":
                depth += 1
            elif css[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        body = css[at + 1:j]
        if selector.startswith("@") and "{" in body:
            out.extend(_css_blocks(body))
        else:
            out.append((selector, body))
        i = j + 1


def _css_rules(css, name, selector=None):
    """The body of every rule whose own selector is this class or id.

    Its own: `.name`, `#name`, and either of them in a state such as
    `:hover`, but never a descendant of them -- `.agent-card .dot` styles
    the dot and not the card. `selector` narrows it to one exact spelling.
    """
    out = []
    for sel, body in _css_blocks(re.sub(r"/\*.*?\*/", "", css, flags=re.S)):
        for part in (p.strip() for p in sel.split(",")):
            if selector is not None:
                hit = part == selector
            else:
                hit = bool(re.match(r"[.#]%s(?![\w-])(?![ >+~])"
                                    % re.escape(name), part)) \
                    and " " not in part
            if hit:
                out.append(body)
                break
    return out


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

    def css_rules(self, name, selector=None):
        """Every stylesheet rule whose own selector is this class or id.

        One reader, used by the card's test and the parked card's, rather
        than a slice from the name to the first `}`: both names also appear
        in the markup the JavaScript emits, and a rule nested inside an
        `@media` block was swallowed whole by the parse this replaces.
        """
        return _css_rules(STYLE_BLOCK, name, selector)

    def one_rule(self, name, selector):
        """The body of the one rule spelled `selector`; fails on 0 or 2."""
        rules = self.css_rules(name, selector)
        self.assertEqual(len(rules), 1,
                         "expected exactly one %s rule, got %d"
                         % (selector, len(rules)))
        return rules[0]


class TestTheGlyphAndTheView(_GuiCase):
    def test_the_card_is_framed_and_therefore_inset(self):
        body = self.one_rule("opshell-card", ".opshell-card")
        for prop in ("border-radius", "box-shadow", "margin"):
            self.assertIn(prop, body,
                          "a framed card needs %s; measured, the frame and "
                          "the shadow are invisible without the margin"
                          % prop)

    def test_the_card_is_translucent_like_every_sibling_surface(self):
        body = self.one_rule("opshell-card", ".opshell-card")
        self.assertIn("var(--surface)", body)
        self.assertNotIn("background:var(--bg)", body)

    def test_no_css_newer_than_the_browser_floor_is_used_unprefixed(self):
        # A regression fence for the Safari 14.1 floor: it passes today by
        # design, and fails the day someone reaches for a newer feature.
        for forbidden in (":has(", "@container", "aspect-ratio:"):
            self.assertNotIn(forbidden, STYLE_BLOCK)
        # Scoped to this view's rules: `.toolbar button` elsewhere in the
        # page already uses the unprefixed property and is not this view's.
        # Comments stripped first, as `_css_rules` does: one that mentions
        # `opshell` or holds a brace would otherwise distort the parse.
        bare = re.sub(r"/\*.*?\*/", "", STYLE_BLOCK, flags=re.S)
        for sel, body in _css_blocks(bare):
            if "opshell" in sel and "backdrop-filter" in body:
                self.assertIn("-webkit-backdrop-filter", body, sel)

    def test_the_header_carries_a_terminal_glyph_that_opens_the_view(self):
        self.assertIn("showOperatorShell()", self.header_block())

    def test_the_stylesheet_comment_does_not_claim_a_defer_it_has_not(self):
        # Only the script carries `defer`; the comment said both were
        # deferred. Case-insensitive and over the whole comment block: the
        # first version read 400 bytes and matched a capital D, so writing
        # "both are deferred" would have passed.
        at = SERVER_SRC.index('href="/static/xterm.css"')
        start = SERVER_SRC.rindex("<!--", 0, at)
        comment = SERVER_SRC[start:SERVER_SRC.index("-->", start)].lower()
        self.assertIn("stylesheet is not", comment)

    def test_no_page_transition_ends_the_session(self):
        """A reload is not a decision to stop working.

        `pagehide` fires on a reload and on any navigation, not only on a
        closed tab, and no browser signal tells them apart. Measured
        before this change: attach, reload, and the log shows
        `POST /api/opshell/close` with `sessions: 0` -- the session died
        because the page was replaced by itself.

        The closed tab is covered by the lapse instead:
        `opshell.LAPSE_GRACE` seconds of silence and the next check-in
        retires the claim.
        """
        # Both quote styles, and whitespace after the paren: this file
        # mixes `"` and `'` freely, so a pattern that names one of them
        # bans the spelling I happened to write and permits the other.
        self.assertNotRegex(
            SERVER_SRC,
            r"""addEventListener\(\s*['"](pagehide|beforeunload|unload)['"]""",
            "a page-transition handler is back; it cannot tell a reload "
            "from a closed tab")
        # And the property form, which `addEventListener` says nothing
        # about: `window.onpagehide = ...` is the same listener by another
        # door.
        self.assertNotRegex(
            SERVER_SRC, r"\bon(pagehide|beforeunload|unload)\s*=",
            "a page-transition handler is back as an `on...` property; it "
            "cannot tell a reload from a closed tab either")

    def test_the_close_survives_a_page_that_is_going_away(self):
        # `opshellEndSession` runs from the ✕, from the End button and from
        # `exit`. Nothing runs on page teardown any more, so what is left
        # for `keepalive` is the race: one of those closes already in
        # flight when the page goes away under it. That race has not been
        # measured -- the flag costs nothing, and a close cancelled with
        # the page leaves the claim held until the lapse.
        self.assertIn("keepalive:true", self.js_function("opshellEndSession"))

    def test_the_page_resumes_a_shell_at_startup(self):
        # Inside the `storedToken()` branch, so a page behind the token
        # gate asks nothing.
        at = SERVER_SRC.index("setInterval(refreshAgents, 3000)")
        gate = SERVER_SRC[at - 200:at + 400]
        self.assertIn("opshellResume()", gate)

    def test_a_resumed_session_draws_the_card_it_attaches_into(self):
        # Read rather than run: the harness's `document` cannot grow a
        # card, so every behavioural resume test supplies the terminal host
        # by hand and a resume that drew no card would pass all of them --
        # while the operator got an invisible session whose claim nothing
        # was heartbeating, stopped by the lapse four minutes later.
        self.assertIn("showOperatorShell()",
                      self.js_function("opshellResume"))

    def test_the_chrome_carries_both_window_controls(self):
        chrome = self.js_function("opshellChrome")
        self.assertIn("opshellMinimise(", chrome)
        self.assertIn("opshellClose(", chrome)
        # Not the inert handler, and not from the render: the render is
        # asserted elsewhere to be free of it.
        self.assertNotIn("opshellEndSession()", chrome)
        # `opshellRetitle` finds the title by this class.
        self.assertIn("opshell-title", chrome)

    def test_the_card_takes_the_content_column_and_not_the_whole_row(self):
        # Ruled during execution, against the markup rather than the plan:
        # `.main` is a flex row holding the 260px sidebar beside
        # `.content`, so a positioned layer over it would cover the agent
        # list this layout exists to keep visible. Every rule whose
        # selector is the card itself is read, by class or by id, and none
        # may position it, inset it or give it a z-index: a rule by id
        # beats the class rule, and `position:fixed` with four edges is the
        # same layer by another spelling.
        by_class = self.css_rules("opshell-card", ".opshell-card")
        self.assertEqual(len(by_class), 1,
                         "expected exactly one .opshell-card rule, got %d"
                         % len(by_class))
        self.assertIn("flex:1", by_class[0])
        for body in self.css_rules("opshell-card"):
            for prop in ("position", "inset", "z-index"):
                self.assertNotRegex(
                    body, r"(?<![\w-])%s\s*:" % prop,
                    "a rule on the card sets %s; it is a flex sibling in "
                    "the content column, not a layer over the page" % prop)

    def test_the_stylesheet_reader_sees_inside_a_media_block(self):
        """The bypass the test above was green through.

        Its first version ran one regex over the file -- selector, `{`,
        everything up to the first `}` -- so a rule nested in an at-rule
        was read as the at-rule's own body and its selector was the
        `@media`, which matches no class. The layout the test forbids
        shipped by being indented one level further in. Both spellings are
        checked here, so the reader cannot quietly lose the descent.
        """
        nested = ("@media (min-width:1px){.opshell-card{position:absolute;"
                  "inset:0;z-index:50}}")
        self.assertEqual(_css_rules(nested, "opshell-card"),
                         ["position:absolute;inset:0;z-index:50"])
        # What the old parse saw instead: one rule, selector `@media ...`,
        # which the card filter then rejected.
        self.assertEqual(
            [sel for sel, _ in re.findall(r"(?m)^\s*([^{}\n]+)\{([^}]*)\}",
                                          nested)],
            ["@media (min-width:1px)"])
        # And a plain rule is still found, at either spelling, while a
        # descendant of it is not.
        self.assertEqual(_css_rules(".x{a:1}#x{b:2}.x .y{c:3}", "x"),
                         ["a:1", "b:2"])

    def test_the_parked_card_is_not_mistakable_for_a_selected_agent(self):
        # Use the rule helper from Step 0, not a slice to the first `}`:
        # `.opshell-parked` also appears in the markup this function emits.
        rules = self.css_rules("opshell-parked")
        self.assertEqual(len(rules), 1)
        self.assertIn("--red-dim", rules[0])
        # `.agent-card.active` is the other thing with that border, and it
        # carries a status dot -- `<span class="dot ${a.status}">` at
        # `server.py:5431`, styled by `.agent-card .dot` at `:4298`. This
        # one does not.
        parked = self.js_function("opshellParked")
        self.assertNotIn('class="dot', parked)
        # And every distinguisher the rule's own comment leans on is
        # pinned, because `--red-dim` plus no dot let a pixel-for-pixel
        # copy of `.agent-card.active` through: inset by a margin, rounded,
        # and tinted with the selected card's own
        # `background:rgba(255,26,26,0.08)` was green.
        self.assertIn("width:100%", rules[0])
        self.assertNotIn("border-radius", rules[0])
        self.assertNotIn("rgba(255,26,26", rules[0])

    def test_the_parked_card_is_a_button(self):
        """`design:187`: a `<button>`, not a div with an `onclick`.
        The header glyph was already corrected from stray text to a button
        once, in the operator's own commit `ca65f70`.

        Named elements and not the word `<button`: once the remnant's ✕
        arrived, the bare string was satisfied by that button alone, so
        turning the restore control into a `<span>` was green -- and a
        `<span onclick>` is unreachable by keyboard, which is the whole
        reason `ca65f70` exists.
        """
        parked = self.js_function("opshellParked")
        self.assertIn("<button", parked)
        self.assertNotIn("<div onclick", parked)
        self.assertRegex(parked, r'<button[^>]*opshell-parked-restore')
        self.assertNotRegex(
            parked, r'<(?!button)\w+[^>]*onclick',
            "a handler sits on something that is not a button")

    def test_the_view_dials_nothing_until_the_operator_asks(self):
        # The goal: nothing happens on open, on hover, or on page load. The
        # channel is raised only when the operator presses the button in
        # the view that says it will.
        opened = self.js_function("showOperatorShell")
        self.assertNotIn("/api/opshell/open", opened)

    def test_no_browser_feature_newer_than_the_page_is_used_unguarded(self):
        """The baseline this interface already had, and I raised it once.

        Measured across the page: optional chaining and the Clipboard API
        in the JavaScript, and flexbox `gap` in the CSS, which is Safari
        14.1 and is what makes the baseline 14.1 rather than 13.1 -- and
        nothing newer than that, until `AbortSignal.timeout` (Safari 16)
        went in uncalled-for. It threw inside the poll on an older browser and
        killed the heartbeat.

        So each 2022-or-later name must sit behind a check. The list is
        short on purpose: it names what this feature introduced rather than
        trying to police the whole file.
        """
        # Call sites, not mentions. The first version of this searched for
        # the name and matched the comment explaining why the name needs a
        # guard -- the third time on this branch that a check of mine
        # forbade describing a thing rather than doing it. A call is the
        # name followed by `(`.
        for name in ("AbortSignal.timeout", "structuredClone",
                     "Array.fromAsync", "Promise.withResolvers"):
            call = name + "("
            at = SERVER_SRC.find(call)
            while at >= 0:
                window = SERVER_SRC[max(0, at - 260):at]
                self.assertRegex(
                    window, r'typeof\s+%s' % re.escape(name),
                    "%s is called without a feature check at offset %d; it "
                    "is newer than this page's own baseline of Safari 14.1"
                    % (name, at))
                at = SERVER_SRC.find(call, at + 1)

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
        # The POST moved out of `opshellAttach` when the keystrokes were
        # coalesced, and its own behaviour is covered by
        # `test_only_one_keystroke_post_is_ever_in_flight`. What is left
        # here is the naming contract: a keystroke never rides in a URL,
        # anywhere.
        flush = self.js_function("opshellFlushKeys")
        self.assertIn("/api/opshell/keys", flush)
        self.assertIn('method:"POST"', flush)
        self.assertNotRegex(SERVER_SRC, r"/api/opshell/keys\?")

    def test_the_picker_row_is_one_type_size_with_room_around_it(self):
        """Seen in the browser on 2026-11-24: 13px label, 11px picker.

        The label inherits `#opshell-body`'s 13px while `.opshell-pick` is
        11px, so "Device" sat larger than the control it names, with
        nothing separating that row from the sentence under it.
        """
        row = self.one_rule("opshell-row", ".opshell-row")
        self.assertIn("font-size:11px", row)
        self.assertRegex(row, r"gap|margin",
                         "the row has no spacing of its own")
        self.assertIn('class="opshell-row"',
                      self.js_function("opshellPicker"))

    def test_both_window_controls_sit_on_one_line(self):
        """Seen on 2026-11-24: the `_` sat lower than the `✕`.

        Two things, and the first one alone did nothing. A centred
        inline-flex box makes the two buttons one size, but centring aligns
        the *line box*: measured in the browser with a canvas at this 18px
        size, the underscore's ink centre sits 4.56px below the baseline
        and the cross's 5.27px above it. So the glyph is lifted by their
        difference, 9.83px = 0.546em, written as 0.55em.

        This pin is the mechanism, not the effect: the suite has no layout
        engine, so it cannot see whether the two glyphs line up. The effect
        was measured in a browser and the numbers are in the rule's own
        comment -- the first version of this test passed while the view was
        still visibly wrong.
        """
        ctl = self.one_rule("opshell-ctl", ".opshell-ctl")
        self.assertIn("display:inline-flex", ctl)
        self.assertIn("align-items:center", ctl)
        lift = self.one_rule("opshell-ctl-min", ".opshell-ctl-min")
        self.assertRegex(lift, r"translateY\(-0\.5\d*em\)",
                         "the minimise glyph is not lifted, so it sits "
                         "below the cross however the box is aligned")
        self.assertIn("opshell-ctl-min", self.js_function("opshellChrome"))

    def test_the_footnote_does_not_sit_on_the_terminals_border(self):
        """Seen on 2026-11-24 at 900x500: it touched the box's edge.

        The box is new in part three, so this is too: the paragraph after
        it had no margin because nothing above it had an edge before.
        """
        self.assertRegex(self.one_rule("opshell-screen", ".opshell-screen"),
                         r"margin-bottom|margin:",
                         "the terminal box leaves no room under itself")

    def test_no_custom_property_is_read_without_being_defined(self):
        """Page-wide, and it lives here beside the browser-floor fence
        because that one is page-wide too and uses the same machinery.

        A declaration that reads an undefined custom property without a
        fallback is **invalid at computed-value time**: the property
        silently takes its initial value, so `background:var(--bg2)` paints
        nothing and `font-family:var(--font)` inherits. Measured on
        2026-11-25, four were read that way -- `--bg2` (8 places), `--bg3`
        (2), `--blue` (4 in the stylesheet plus three inline styles in the
        script) and `--font` (1) -- which is why nine rules across six
        panels had no background at all.

        `var(--x, fallback)` is fine and is not counted: a fallback is the
        documented way to read a property that may be absent, and this page
        uses it deliberately for `--yellow` and `--blue-dim`.
        """
        root = re.search(r":root\{(.*?)\}", SERVER_SRC, re.S)
        self.assertIsNotNone(root, "the page has no :root block")
        defined = set(re.findall(r"(--[a-z0-9-]+)\s*:", root.group(1)))
        page = SERVER_SRC[SERVER_SRC.index("_OPERATOR_HTML"):]
        read_plain = re.findall(r"var\((--[a-z0-9-]+)\)", page)
        missing = {}
        for name in read_plain:
            if name not in defined:
                missing[name] = missing.get(name, 0) + 1
        self.assertEqual(
            missing, {},
            "read without a fallback and never defined: %s -- each such "
            "declaration is dropped, so the rule renders without it"
            % ", ".join("%s (%d places)" % (n, c)
                        for n, c in sorted(missing.items())))

    def test_the_font_fallback_is_the_stack_the_stylesheet_declares(self):
        """`opshellFont`'s literal and `:root{--mono}` are one stack.

        The fallback is for a stylesheet that did not load, so it has to
        be the same list of families the stylesheet would have given --
        otherwise a terminal that fell back would be measured and drawn in
        a font the rest of the page never uses. Nothing tied the two: the
        node test's third case (`cssVars = {}`) asserted only that the
        answer names *some* real family, so changing `--mono` in the
        stylesheet and leaving the literal alone kept all 310 tests green.

        Read from the source rather than run, so it holds where node is
        not installed, and the string concatenation the line wrap needs is
        folded away first.
        """
        mono = re.search(r"^\s*--mono:(.*?);\s*$", STYLE_BLOCK, re.M)
        self.assertIsNotNone(mono, "the page no longer defines --mono")
        source = re.sub(r'"\s*\+\s*"', "", self.js_function("opshellFont"))
        self.assertIn(mono.group(1).strip(), source,
                      "opshellFont's fallback stack is not the one "
                      "`:root{--mono}` declares, so a terminal that fell "
                      "back would use a font the page does not")


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

    def test_the_strip_is_a_class_and_not_an_inline_style(self):
        src = self.js_function("opshellRender")
        self.assertIn('class="opshell-strip"', src)
        self.assertNotIn('style="display:flex', src)

    def test_a_very_long_host_does_not_push_the_controls_away(self):
        self.assertIn("flex-wrap:wrap",
                      self.one_rule("opshell-strip", ".opshell-strip"))

    def test_the_strip_states_the_user_and_does_not_assume_root(self):
        # The tunnel panel carries this scar already: it "used to state
        # root for every row", and the user is a reported field now.
        render = self.js_function("opshellRender")
        self.assertIn("state.user", render)
        self.assertIn("state.root", render)

    def test_the_first_line_states_the_history_guard_it_was_given(self):
        # The line is written by `opshellAttach`, not by `opshellRender`
        # (which draws the strip), so that is the function that must read
        # the two fields the machine reported.
        attach = self.js_function("opshellAttach")
        self.assertIn("state.history", attach)
        self.assertIn("state.history_detail", attach)

    def test_the_first_terminal_line_claims_only_what_the_code_does(self):
        # The sentence used to be a constant, true only while the generated
        # startup file held history off. What it says now is decided by
        # the machine's word, and the behaviour is pinned in node by the
        # tests of the class that runs the view that drive the first line:
        # `test_the_first_line_claims_nothing_when_it_was_told_nothing`,
        # `test_a_weak_guard_says_why_and_an_off_guard_says_it_is_off`,
        # `test_a_weak_guard_with_no_reason_reads_whole_on_its_own` and the
        # ones that hand the reason, the host and the target a hostile text.
        # What is read here is only that the claim has one author: the
        # attach, once, beside the weaker sentence it must never replace.
        attach = self.js_function("opshellAttach")
        self.assertEqual(attach.count("history is off in this session"), 1)
        self.assertIn("history is not guaranteed off", attach)
        self.assertEqual(SERVER_SRC.count("history is off in this session"), 1,
                         "the constant claim is written somewhere else too")

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

    def test_the_cards_footer_names_the_control_that_closes(self):
        # The card has two buttons and only one of them closes anything,
        # but the line under the terminal still read "Closing it queues
        # the channel's shutdown" -- written when the panel was a modal
        # with one way out. `test_docs` forbids
        # `closing the (view|panel)...queues the shutdown`, which that
        # spelling does not match: its own comment records the pattern as
        # having been green over the very page it was written to forbid.
        # So the pin is here, on the sentence, in the file that reads it.
        render = self.js_function("opshellRender")
        self.assertNotRegex(
            render, r"(?i)closing it queues",
            "the card's footer says 'closing it' where `_` closes nothing")
        self.assertRegex(render, r"&#10005;[^<]*closes the card",
                         "the footer does not say which control closes")
        self.assertRegex(render, r"_ parks",
                         "the footer does not say what `_` does instead")


#: The browser the view is executed against.
#:
#: Written as one JavaScript document rather than a pile of concatenated
#: Python strings, because the first version's stubs were wrong in the same
#: direction as the code and six mutations survived because of it: `fetch`
#: could not reject, so every network-failure arm was unreachable;
#: `AbortController.abort()` only recorded, so no test could show a stream
#: ending; and `setTimeout` never fired, so nothing could see a poll loop
#: that stopped or ran twice.
_NODE_ENV = r"""
let posted = [], aborted = [], removed = [], said = [];
let inFlight = 0, maxInFlight = 0, holdFetch = 0;
let scheduled = [];
const timers = new Map();

const sessionStorage = {d: {}, getItem(k){ return this.d[k] ?? null; },
  setItem(k, v){ this.d[k] = String(v); },
  removeItem(k){ delete this.d[k]; }};
sessionStorage.setItem('raccoon_operator_token', 't');
function storedToken(){ return 't'; }
function tokenRejected(){ said.push('token-rejected'); }
function askForToken(){}
function H(){ return {'Authorization': 'Bearer t',
                      'Content-Type': 'application/json'}; }

// One reply, or a queue of them, so a test can say "the first call
// succeeds and the second is refused". `{throw: "..."}` rejects, which is
// what a dropped connection does and what the first harness could not
// express at all.
let nextReply = {ok: true, status: 200, body: {}};
let replies = null;
// A drained queue is an error, not a free 200. The first version fell
// back to a default success, so any mutation that made the code issue an
// *extra* request was absorbed silently -- which is a harness hiding the
// thing it was built to find.
function reply(){
  if(replies){
    if(!replies.length) throw new Error('unexpected extra request');
    return replies.shift();
  }
  return nextReply;
}

// What a browser does with a custom property: the page's stylesheet defines
// `--mono`, and `getComputedStyle(...).getPropertyValue` answers it, or an
// empty string when it is not defined. `_node` fills `cssVars` from the
// page's own `:root`, so no test restates the stack.
let cssVars = {};
function getComputedStyle(){
  return {getPropertyValue: name => cssVars[name] || ''};
}

class AbortError extends Error {
  constructor(){ super('The operation was aborted'); this.name = 'AbortError'; }
}

class AbortSignal2 {
  constructor(){ this.aborted = false; this._on = []; }
  addEventListener(_, fn){ this._on.push(fn); }
  set onabort(fn){ this._on.push(fn); }
  _fire(){ this.aborted = true; this._on.forEach(fn => fn()); }
}

// Timeout signals that can be made to fire, rather than a comment saying
// they fire. The previous version recorded the number and nothing else --
// the same sin as an `abort()` that only pushed a string, which is what
// made six mutations invisible.
let pendingTimeouts = [];
function fireTimeouts(){
  const due = pendingTimeouts.slice();
  pendingTimeouts.length = 0;
  due.forEach(s => s._fire());
}

class AbortController {
  constructor(){ this.signal = new AbortSignal2(); }
  abort(){ aborted.push('abort'); this.signal._fire(); }
}
// The real one: a timeout is a signal that fires itself.
AbortSignal.timeout = ms => {
  const s = new AbortSignal2();
  s._ms = ms;
  pendingTimeouts.push(s);
  return s;
};

async function fetch(url, opts){
  opts = opts || {};
  posted.push({url, method: opts.method || 'GET', body: opts.body,
               keepalive: !!opts.keepalive, timeout: opts.signal &&
               opts.signal._ms});
  if(opts.signal){
    if(opts.signal.aborted) throw new AbortError();
    opts.signal.addEventListener('abort', () => {});
  }
  inFlight += 1;
  maxInFlight = Math.max(maxInFlight, inFlight);
  for(let i = 0; i < holdFetch; i++) await Promise.resolve();
  inFlight -= 1;
  if(opts.signal && opts.signal.aborted) throw new AbortError();
  const r = reply();
  if(r.throw) throw new Error(r.throw);
  return {ok: r.ok, status: r.status, body: r.stream || null,
          json: async () => {
            if(r.badJson) throw new Error('Unexpected token < in JSON');
            return r.body;
          }};
}

// A node that does what a browser's does, so that a view which toggles a
// class, sets a style, appends a card or measures a probe is observable.
// Every method here acts, and the three `test_the_harness_dom_*` tests
// exercise each so that a stub returning undefined -- the shape of the two
// lies this harness has already told -- fails there and not in a later task.
let nextBox = null;
function fakeBox(w, h){ nextBox = {width: w, height: h}; }
// What the browser does with an id: a node in the page can be found by it,
// and one taken out of the page cannot. `els` is that index.
function adopt(n){ if(n.id) els[n.id] = n; }
function forget(n){ if(n.id && els[n.id] === n) delete els[n.id]; }
// A removed or emptied node takes its whole subtree out of the page, so a
// grandchild's id stops answering too, as `getElementById` does in Safari.
function forgetTree(n){ forget(n); n.children.forEach(forgetTree); }
function makeNode(id, box){
  const classes = new Set();
  let html = '', text = '';
  // What both content setters do: in a browser, assigning `innerHTML` or
  // `textContent` replaces everything inside the node, and the subtree
  // that leaves takes its ids out of the page with it.
  const empty = () => {
    node.children.forEach(c => { c.parentNode = null; forgetTree(c); });
    node.children = [];
  };
  const node = {
    id, value: '', style: {}, children: [], parentNode: null,
    // Not a browser property: a hook so a test can see every write.
    htmlWrites: [],
    box: box || {width: 0, height: 0},
    classList: {
      add(...names){ names.forEach(c => classes.add(c)); },
      remove(...names){ names.forEach(c => classes.delete(c)); },
      contains: c => classes.has(c),
      toggle(c, force){
        const on = force === undefined ? !classes.has(c) : !!force;
        if(on) classes.add(c); else classes.delete(c);
        return on;
      },
    },
    // A browser element has `parentNode` and `parentElement` and no
    // `parent`: a harness that offered `.parent` would pass page code that
    // is `undefined` in Safari. There is deliberately no such field here.
    get parentElement(){ return node.parentNode; },
    get innerHTML(){ return html; },
    // Assigning replaces the children, whatever the value: the page
    // rebuilds `#agent-list` this way every three seconds, and a card
    // inside the list goes with it while one beside it does not.
    set innerHTML(v){
      html = String(v);
      node.htmlWrites.push(html);
      // Markup is not parsed here, so the text a browser would find inside
      // it is not invented: the write leaves no text rather than the text
      // that happened to be there before it.
      text = '';
      empty();
    },
    // A real accessor and not an inert own property: `opshellRetitle`
    // writes the card's title this way on every poll tick, and what it
    // must not disturb -- the buttons beside the title -- can only be
    // shown to survive if a write here replaces the children, as a
    // browser's does.
    get textContent(){ return text; },
    set textContent(v){ text = String(v); html = text; empty(); },
    appendChild(child){
      if(child.parentNode) child.parentNode.children.splice(
        child.parentNode.children.indexOf(child), 1);
      child.parentNode = node;
      node.children.push(child);
      adopt(child);
      return child;
    },
    remove(){
      removed.push(node.id);
      forgetTree(node);
      if(node.parentNode){
        node.parentNode.children.splice(
          node.parentNode.children.indexOf(node), 1);
        node.parentNode = null;
      }
    },
    // A node that is not in the page, or is hidden by itself or by any
    // ancestor, measures nothing -- as in Safari. A registered node counts
    // as in the page: `els` nodes have no parent node, and `.content` is one.
    getBoundingClientRect(){
      let shown = !!node.parentNode || els[node.id] === node;
      for(let n = node; n; n = n.parentNode){
        if(n.style.display === 'none') shown = false;
      }
      const b = shown ? node.box : {width: 0, height: 0};
      return {width: b.width, height: b.height, top: 0, left: 0,
              right: b.width, bottom: b.height};
    },
  };
  return node;
}

// `els` stays the one registry of nodes, and `el(id)` the one way into it:
// the tests that set `els['opshell-body']` by hand and read `.innerHTML`
// back depend on both.
const els = {};
function el(id){
  return els[id] || (els[id] = makeNode(id));
}
// `.sidebar` resolves `els['sidebar']` even if that node does not carry the
// class, which a browser would not match. That looseness is deliberate: the
// registry is how a test names a node, and making each one also carry its
// class would only restate the name. A bare word takes the same two routes.
function queried(sel){
  if(sel[0] === '#') return els[sel.slice(1)] || null;
  const name = sel[0] === '.' ? sel.slice(1) : sel;
  if(els[name]) return els[name];
  return Object.values(els).find(n => n.classList.contains(name)) || null;
}
// `fakeBox` goes to the next `createElement`, which is how the page makes
// nodes; `el()` registrations are test set-up and must not take it, so a
// registered node is given its size through `.box`.
const document = {
  getElementById: id => els[id] || null,
  querySelector: queried,
  createElement: () => {
    const box = nextBox;
    nextBox = null;
    return makeNode(null, box);
  },
  body: makeNode('body'),
};
const window = {listeners: {}, addEventListener(name, fn){
  (this.listeners[name] = this.listeners[name] || []).push(fn); }};
const navigator = {};

// Timers that can actually fire, one turn at a time, so a test can watch a
// poll loop continue -- or stop.
// A map, not an array whose length is the id: the first version reset
// `timers.length = 0` on every round, so an id handed out before a round
// pointed at an unrelated slot afterwards and `clearTimeout` would have
// cancelled the wrong callback.
let timerSeq = 0;
function setTimeout(fn, ms){
  scheduled.push(ms);
  timerSeq += 1;
  timers.set(timerSeq, fn);
  return timerSeq;
}
function clearTimeout(id){ if(id) timers.delete(id); }
async function runTimers(rounds){
  for(let i = 0; i < (rounds || 1); i++){
    const due = Array.from(timers.entries());
    due.forEach(([id]) => timers.delete(id));
    for(const [, fn] of due) if(fn) await fn();
  }
}

class TextEncoder { encode(s){ return Buffer.from(s, 'utf8'); } }

// A readable stream, so the reader loop can actually run. Without one
// every successful reply had `body: null` and took the `!res.body` branch,
// which hid the whole loop: the terminal write path, the guard for a
// disposed terminal, the `done` exit and the close that follows it. Two
// Review Focus conditions were proven at the bridge and never through the
// view.
function fakeStream(chunks, failAfter){
  let i = 0;
  return {
    getReader(){
      return {
        async read(){
          if(failAfter !== undefined && i === failAfter){
            throw new Error('stream broke');
          }
          if(i >= chunks.length) return {done: true, value: undefined};
          return {done: false, value: chunks[i++]};
        },
      };
    },
  };
}

// A terminal that records, so `opshellSay` and the attach notes are
// observable rather than merely survivable.
function fakeTerm(){
  return {lines: [], writeln(s){ this.lines.push(s); },
          write(b){ this.lines.push(String(b)); },
          dispose(){ this.disposed = true; },
          open(){}, onData(fn){ this._data = fn; }};
}
"""



class TestTheViewSuiteIsNotSilentlyEmpty(unittest.TestCase):
    def test_node_is_present_or_this_fails_loudly(self):
        """A hundred and nineteen tests hide behind `skipUnless(node)`.

        They are the only defence the interface has -- the grep tests
        cannot see a swallowed error, a missing control or a close that
        never happens. A box without node loses all of them and reports
        success, which is the same shape as the five tests this branch
        once deleted while the suite went green.

        One loud failure instead of a hundred and nineteen quiet skips.
        """
        self.assertTrue(
            shutil.which("node"),
            "node is not installed, so every behavioural test of the "
            "operator shell's interface was skipped. Install node, or "
            "accept that this feature's view is untested on this machine.")

    def test_the_count_of_behavioural_tests_has_not_quietly_dropped(self):
        # The five deleted tests were invisible because the total still
        # looked plausible. A floor makes a silent loss loud.
        names = [n for n in dir(TestTheViewRunsAndIsNotJustRead)
                 if n.startswith("test_")]
        # A floor well under the real count permits a silent loss, and that
        # is what happened twice: five tests deleted at once while the
        # total still looked plausible, and later a single named safety
        # test deleted while the total *rose* from 231 to 246. So the floor
        # sits close to the real count -- 48 against 50 when it was set,
        # carried with the controller's nod, 52 against 54 once the
        # harness's DOM brought three tests of its own, and 57 against 59
        # once the card, its double-press guard and its missing-mount guard
        # brought five more, and 59 against 61 once the card's restore and
        # its title brought two, and 78 against 80 once minimise, the park,
        # the restore, the remnant's own cross and two reviews' six
        # bypasses brought nineteen -- one of which, a grep that ran no
        # node, left for the class that reads the source -- and 85 against
        # 87 once the measured geometry brought seven: its ratio, its floor,
        # its cap, the hidden card's fallback, the probe's removal, the
        # pair that is sent and the host's box -- and 87 against 89 once the
        # attach said when it had not fitted the card, and said nothing when
        # it had, and told a probe failure from a hidden card -- and 89
        # against 91 once the pair was pinned to the probe's own box by
        # division rounded down, and the probe to the terminal's own font --
        # and 90 against 92 once that font was resolved for both, because
        # the canvas strategy cannot read `var(--mono)` -- and 97 against 99
        # once the final review's five Important brought six (the terminal
        # disposed where its node is replaced and not inherited by the next
        # session, an answer that is not a state, a duration that cannot
        # outlive its device, a claim the resume may not overwrite, and the
        # sentence saying why a card did not come back) and a parked panel
        # with no session brought the seventh -- and 101 against 103 once the
        # merge blocker brought four: why a parked session ended surviving
        # the tick that ends it, an ordinary exit explaining nothing and
        # not being inherited, that sentence stated once, and a card that
        # came back not being told its shell is gone -- and 105 against
        # 107 once the first terminal line stated the history guard it was
        # given, which brought four: nothing said when it was told
        # nothing, "not guaranteed" with its reason beside "off", the same
        # sentence whole with no reason, and a reason that may not carry a
        # control sequence into the terminal -- and 115 against 117 once
        # every other writer of text from the machine or a server into that
        # terminal was locked one by one, which brought ten: the helper
        # itself, the host and the target, the stream's failure, the
        # shutdown that failed and the reason it was refused for, the poll
        # that failed and the state's own note, the key request that failed
        # and the one that was refused, and the shell's own bytes reaching
        # the terminal untouched -- and 117 against 119 once the review of
        # that brought two: where the helper cuts what is left, and that a
        # host or a reason of any length leaves the sentence it is written
        # into on the line -- and 138 against 138 once the window look
        # brought fourteen: four for the strip's pills, three for the
        # terminal's box and the short card that still scrolls, three for
        # the body's scrollbar, its loading class and its text size, and
        # four for the shell's own buttons and picker and the file
        # browser's button fenced off. The floor had already slid to 117
        # against 124 before that, five tests landing without it being
        # raised, which is the slack this floor exists to refuse --
        self.assertGreaterEqual(
            len(names), 138,
            "only %d behavioural view tests remain; a named safety test was "
            "once deleted while the total went up" % len(names))
        # -- and the properties that each cost this branch a Critical are
        # named one by one, because a count cannot defend a property.
        for must in ("test_what_is_typed_during_a_failing_batch_dies_with_it",
                     # A first line that says history is off when the page
                     # was told nothing is the claim that would mislead the
                     # person it is addressed to, and no other test keeps
                     # the default from being "off".
                     "test_the_first_line_claims_nothing_when_it_was_told_nothing",
                     # The same sentence without its reason: a relay too old
                     # to send one must still read whole, with no empty
                     # parenthesis and no cause the page was not told.
                     "test_a_weak_guard_with_no_reason_reads_whole_on_its_own",
                     # The filter's own definition. Every writer's test
                     # asserts that it *calls* the helper; only this one
                     # says what the helper removes, and that it keeps the
                     # rest, so a class that narrows or widens is caught
                     # here and nowhere else.
                     "test_the_helper_removes_what_a_terminal_acts_on_and_nothing_else",
                     # The other direction: filtering too much. The shell's
                     # own bytes carry its colour, and removing colour is
                     # what this whole feature exists to prevent. The
                     # numeric floor cannot stand in for these three:
                     # deleting any two leaves the total at its floor.
                     "test_what_the_shell_prints_still_reaches_the_terminal_untouched",
                     "test_the_same_holds_when_the_request_is_rejected_outright",
                     "test_a_write_that_may_have_landed_is_not_called_nothing",
                     "test_closing_the_view_closes_the_session",
                     "test_the_poll_keeps_beating_on_the_path_that_usually_runs",
                     "test_keystrokes_do_not_cross_from_one_session_into_the_next",
                     "test_the_end_button_actually_ends_something",
                     # A parked session whose heartbeat stops is a channel
                     # stopped under a working operator: `opshellPoll`
                     # returns when `#opshell-body` is missing, so a
                     # minimise that took the card apart would let the
                     # lapse fire four minutes later.
                     "test_minimising_keeps_the_body_so_the_heartbeat_keeps_beating",
                     # And the only pin tying the card's chrome to the card
                     # it is appended to: without it one deleted line ships
                     # a window-control card with no window controls, and
                     # the grep of `opshellChrome` cannot see that.
                     "test_the_card_sits_in_the_content_column_and_not_inside_content",
                     # The size is fixed for the life of the connection, so
                     # a measurement taken in a hidden card is wrong for the
                     # whole session and nothing can correct it.
                     "test_a_host_inside_a_hidden_card_falls_back_rather_than_guessing",
                     # Without the stylesheet's box the host is 0 tall when
                     # measured, and every session in every browser is
                     # floored at five rows while the rest stay green.
                     "test_the_terminal_host_has_a_box_to_be_measured_in"):
            self.assertIn(must, names,
                          "%s named a property that cost this branch a "
                          "Critical. It may not be removed without another "
                          "test that names the same property." % must)


class TestTheViewRunsAndIsNotJustRead(_GuiCase):
    """The view, executed, not grepped.

    Every other interface test on this branch reads `server.py` as text,
    and the final review found four defects they were all green through:
    closing the panel queued nothing, a server refusal was swallowed
    whole, a reloaded page offered no control at all, and the Closed state
    was never rendered. A grep for an identifier cannot see any of those.

    `test_c2_hardening.py` already runs this interface in node under
    `skipUnless`, so this is the house pattern rather than a new
    dependency.
    """

    # `candidates` is `sorted(agents)`, so this is the real order, and
    # `badger` is what the browser hands back for an unselected list.
    FLEET = ["badger", "clumsy-raccoon", "parrot"]

    def _node(self, script):
        env = _NODE_ENV
        # The module's own `let` declarations, lifted from the source
        # rather than restated here: a harness that declares its own
        # `opshellSession` is a harness that tests its own invention, which
        # is the exact failure this whole class exists to stop.
        decls = re.findall(r"^let opshell\w+ = .*$", SERVER_SRC, re.M)
        self.assertGreaterEqual(len(decls), 6, "the view's state is not "
                                "declared with `let opshell...` any more")
        src = "\n".join(decls + [self.js_function(n) for n in (
            "esc", "opshellEndSession", "opshellTeardown", "opshellPicker",
            "opshellRender", "opshellOpen", "opshellB64",
            "opshellClean", "opshellPlain", "opshellSay", "opshellDropRest",
            "opshellFlushKeys",
            "opshellEndAfterAttach", "opshellRemember", "opshellRecall",
            "opshellResume", "showOperatorShell", "opshellChrome",
            "opshellClose", "opshellMinimise", "opshellRestore",
            "opshellParked", "opshellRetitle", "opshellPoll",
            "opshellAttach", "opshellMeasure", "opshellFont")]) + "\n"
        # The one module constant the keystroke path reads.
        const = re.search(r"^const OPSHELL_KEYS_CEILING = .*$",
                          SERVER_SRC, re.M)
        self.assertIsNotNone(const, "the request ceiling is gone")
        src = const.group(0) + "\n" + src
        mono = re.search(r"^\s*--mono:(.*?);\s*$", STYLE_BLOCK, re.M)
        self.assertIsNotNone(mono, "the page no longer defines --mono")
        src = "cssVars['--mono'] = %s;\n" % json.dumps(mono.group(1)) + src
        out = subprocess.run(
            ["node", "--input-type=module", "-e", env + src + script],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0,
                         "node failed:\n" + out.stderr[-1500:])
        return json.loads(out.stdout.strip().splitlines()[-1])

    def render(self, session=None, **state):
        """`opshellRender(state)`'s markup, with `opshellSession` set.

        Beside `_node`, which it calls, and not on `_GuiCase`: no other
        subclass of `_GuiCase` defines `_node`, so none of them could use it.
        """
        return self._node(
            "opshellSession = %s;\n"
            "const html = opshellRender(%s);\n"
            "console.log(JSON.stringify({html}));"
            % (json.dumps(session), json.dumps(state)))["html"]

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_root_session_says_root_once(self):
        """Seen in the browser on 2026-11-24; no test caught it.

        The server sets `root` from `user == "root"` (`server.py:2004`), so
        on a root session the orange pill repeated the word the user text
        had just said, and the strip read `root root`. Dropping either one
        unconditionally would lose a claim, which the design names as an
        anti-goal, so the word is drawn once -- as the pill, because the
        pill is the one that also says *privileged*.
        """
        html = self.render(session="mine", state="live", host="pi",
                           user="root", root=True, channel="open")
        self.assertEqual(html.count(">root<"), 1,
                         "the strip says root %d times"
                         % html.count(">root<"))
        self.assertIn("opshell-pill-root", html)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_non_root_user_is_named_beside_the_root_pill(self):
        """The other half: suppressing the pill must not suppress a user.

        A session whose user is not `root` but which reports `root` -- the
        server cannot produce it today, but the view is told both fields
        separately -- must still show both.
        """
        html = self.render(session="mine", state="live", host="pi",
                           user="derbenji", root=True, channel="open")
        self.assertIn(">derbenji<", html)
        self.assertEqual(html.count(">root<"), 1)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_claim_with_no_value_renders_no_pill(self):
        # Geometry is null in every state before a bridge exists, and drew
        # an empty `<span>`: a hole in the row.
        html = self.render(state="waiting", geometry=None, host="pi",
                           channel="closed", expected_checkin=12)
        start = html.index('<div class="opshell-strip">')
        strip = html[start:html.index("</div>", start)]
        self.assertNotIn('class="opshell-pill"></span>', strip)
        self.assertNotIn("></span>", strip)
        self.assertEqual(html.count('<span class="opshell-pill'), 1,
                         "the channel alone is a pill here")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_every_claim_the_strip_made_is_still_made(self):
        html = self.render(session="mine", state="live", host="pi",
                           user="root", root=True, geometry=[118, 34],
                           recording=True, channel="open")
        for claim in ("pi", "root", "118x34", "recording", "channel open"):
            self.assertIn(claim, html)
        self.assertEqual(html.count("opshell-pill-root"), 1)
        self.assertEqual(html.count("opshell-pill-rec"), 1)
        self.assertEqual(html.count("opshell-pill-ok"), 1)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_user_is_not_called_root_when_it_is_not(self):
        html = self.render(session="mine", state="live", host="pi",
                           user="bob", root=False, channel="open")
        self.assertIn("bob", html)
        self.assertNotIn("opshell-pill-root", html)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_hostile_host_cannot_write_markup_into_a_pill(self):
        html = self.render(session="mine", state="live", channel="open",
                           host='<img src=x>"\'', user="<b>",
                           geometry=["<i>", 1])
        self.assertNotIn("<img", html)
        self.assertNotIn("<b>", html)
        self.assertNotIn("<i>", html)
        self.assertIn("&lt;img", html)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_harness_dom_answers_like_a_browser(self):
        """The harness has lied twice, in the same way both times.

        Its `fetch` could not reject and its `abort()` only recorded a
        string, and six mutations survived because of it. Every stub the
        harness's DOM has is therefore exercised, so that a stub which
        quietly does nothing fails here rather than in a later task. This
        test covers what a node does when it is built; the two that follow
        cover what it does when it is changed or taken apart, and what it
        reports about being in the page.

        The probe is appended to a host before it is measured, because a
        node that is not in the page measures nothing, as in Safari.
        """
        got = self._node(
            "const n = document.createElement('div');\n"
            "n.classList.add('a'); n.classList.toggle('b');\n"
            "n.style.display = 'none';\n"
            "n.innerHTML = '<p>x</p>';\n"
            "const host = el('host'); host.appendChild(n);\n"
            "fakeBox(820, 600);\n"
            "const probe = document.createElement('span');\n"
            "el('stage').appendChild(probe);\n"
            "const box = probe.getBoundingClientRect();\n"
            "console.log(JSON.stringify({cls: [n.classList.contains('a'),"
            " n.classList.contains('b'), n.classList.contains('c')],"
            " style: n.style.display, html: n.innerHTML,"
            " kids: host.children.length, box: [box.width, box.height],"
            " found: document.querySelector('#host') === host}));")
        self.assertEqual(got["cls"], [True, True, False])
        self.assertEqual(got["style"], "none")
        self.assertEqual(got["html"], "<p>x</p>")
        self.assertEqual(got["kids"], 1)
        self.assertEqual(got["box"], [820, 600])
        self.assertTrue(got["found"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_harness_dom_answers_when_a_node_is_changed_or_taken_apart(self):
        """What a node does when it is changed or taken apart.

        A class removed or toggled back, a style that belongs to one node, an
        `innerHTML` that stores, records and coerces, a `textContent` that
        reads back and clears the children, a node moved to another
        host or removed, and a selector that finds the right thing and
        answers exactly `null` when there is none. Each assertion names the
        stub it pins; a stub that returned undefined or did nothing fails.
        """
        got = self._node(
            "const a = el('a'), b = el('b');\n"
            "const n = document.createElement('div');\n"
            # classList.add / remove with two names at once
            "n.classList.add('p', 'q');\n"
            "const added = [n.classList.contains('p'),"
            " n.classList.contains('q')];\n"
            "n.classList.remove('p', 'q');\n"
            "const removedBoth = [n.classList.contains('p'),"
            " n.classList.contains('q')];\n"
            # classList.remove of one of two
            "n.classList.add('x'); n.classList.add('y');\n"
            "n.classList.remove('x');\n"
            # toggle, twice, with its return values; and with force
            "const t1 = n.classList.toggle('z');\n"
            "const afterOne = n.classList.contains('z');\n"
            "const t2 = n.classList.toggle('z');\n"
            "const afterTwo = n.classList.contains('z');\n"
            "const f1 = n.classList.toggle('f', true);\n"
            "const f2 = n.classList.toggle('f', true);\n"
            "const f3 = n.classList.toggle('f', false);\n"
            "const f4 = n.classList.toggle('never', false);\n"
            "const neverThere = n.classList.contains('never');\n"
            # style belongs to one node
            "const other = document.createElement('div');\n"
            "other.style.display = 'none';\n"
            "n.style.display = 'block';\n"
            # innerHTML stores and records, and coerces to a string
            "n.innerHTML = 'one'; n.innerHTML = 'two';\n"
            "const m = document.createElement('div'); m.innerHTML = 42;\n"
            # appendChild returns its child, and moving leaves the first host
            "const mover = document.createElement('i');\n"
            "const ret = a.appendChild(mover);\n"
            "b.appendChild(mover);\n"
            "const reparented = [a.children.length, b.children.length,"
            " mover.parentNode === b, mover.parentElement === b,"
            " ret === mover, 'parent' in mover];\n"
            # remove() takes a node out of its parent and records it
            "const gone = el('gone'); a.appendChild(gone);\n"
            "const before = a.children.length; gone.remove();\n"
            "const afterRemove = [before, a.children.length,"
            " gone.parentNode === null, gone.parentElement === null,"
            " removed.includes('gone')];\n"
            "document.body.appendChild(other);\n"
            "const registered = Object.keys(els).sort();\n"
            # a subtree leaves the page whole: remove() and an innerHTML
            # write each unregister a grandchild, not just the child
            "const outer = document.createElement('div'); outer.id = 'outer';\n"
            "const inner = document.createElement('div'); inner.id = 'inner';\n"
            "outer.appendChild(inner); a.appendChild(outer);\n"
            "const treeIn = [document.getElementById('outer') === outer,"
            " document.getElementById('inner') === inner];\n"
            "outer.remove();\n"
            "const afterTree = [document.getElementById('outer'),"
            " document.getElementById('inner')];\n"
            "const kid = document.createElement('div'); kid.id = 'kid';\n"
            "const grand = document.createElement('div'); grand.id = 'grand';\n"
            "kid.appendChild(grand); b.appendChild(kid);\n"
            "const kidsIn = [document.getElementById('kid') === kid,"
            " document.getElementById('grand') === grand];\n"
            "b.innerHTML = '';\n"
            "const afterEmpty = [document.getElementById('kid'),"
            " document.getElementById('grand')];\n"
            # node identity
            "const v = el('v');\n"
            "const ids = [v.id, v.value, document.createElement('p').id];\n"
            # querySelector, every route
            "const sidebar = el('sidebar');\n"
            "const carrier = el('carrier'); carrier.classList.add('content');\n"
            "const phantom = el('holder'); phantom.classList.add('phantom');\n"
            # textContent: it reads back, it replaces the children, and an
            # innerHTML write leaves no text behind
            "const t = el('t');\n"
            "const inTitle = document.createElement('b'); t.appendChild(inTitle);\n"
            "t.textContent = 'parrot';\n"
            "const titled = [t.textContent, t.innerHTML, t.children.length,"
            " inTitle.parentNode === null];\n"
            "t.innerHTML = '<b>x</b>';\n"
            "const afterHtml = [t.textContent, t.innerHTML];\n"
            "console.log(JSON.stringify({\n"
            " added, removedBoth,\n"
            " cls: [n.classList.contains('x'), n.classList.contains('y')],\n"
            " toggled: [t1, afterOne, t2, afterTwo, f1, f2, f3,"
            " n.classList.contains('f'), f4, neverThere],\n"
            " styles: [n.style.display, other.style.display],\n"
            " writes: n.htmlWrites, html: n.innerHTML,\n"
            " coerced: [m.innerHTML, typeof m.innerHTML],\n"
            " titled, afterHtml,\n"
            " reparented, afterRemove, registered, ids,"
            " treeIn, afterTree, kidsIn, afterEmpty,\n"
            " body: document.body.children.length,\n"
            " byId: document.querySelector('#a') === a,\n"
            " byName: document.querySelector('.sidebar') === sidebar,\n"
            " bare: document.querySelector('sidebar') === sidebar,\n"
            " byClass: document.querySelector('.content') === carrier,\n"
            " bareClass: document.querySelector('phantom') === phantom,\n"
            " missing: [document.querySelector('.nothing') === null,"
            " document.querySelector('#nothing') === null,"
            " document.querySelector('#phantom') === null,"
            " document.querySelector('#content') === null]}));")
        self.assertEqual(got["added"], [True, True])
        self.assertEqual(got["removedBoth"], [False, False])
        self.assertEqual(got["cls"], [False, True])
        self.assertEqual(got["toggled"],
                         [True, True, False, False, True, True, False, False,
                          False, False])
        self.assertEqual(got["styles"], ["block", "none"])
        self.assertEqual(got["writes"], ["one", "two"])
        self.assertEqual(got["html"], "two")
        self.assertEqual(got["coerced"], ["42", "string"])
        # `textContent` reads back what was written and replaces the
        # children, as the `innerHTML` setter does: the card's header is
        # retitled this way on every poll tick, so "the buttons beside the
        # title survive it" has to be drivable rather than argued. And an
        # `innerHTML` write leaves no text behind, because this harness
        # does not parse the markup it is given.
        self.assertEqual(got["titled"], ["parrot", "parrot", 0, True])
        self.assertEqual(got["afterHtml"], ["", "<b>x</b>"])
        # A browser node has `parentNode` and `parentElement`, never `parent`.
        self.assertEqual(got["reparented"], [0, 1, True, True, True, False])
        self.assertEqual(got["afterRemove"], [1, 0, True, True, True])
        # createElement makes nodes that belong to nobody's registry, and a
        # removed node has left it.
        self.assertEqual(got["registered"], ["a", "b"])
        # And the whole subtree goes with it: a grandchild's id must not
        # answer once its ancestor has been removed or emptied.
        self.assertEqual(got["treeIn"], [True, True])
        self.assertEqual(got["afterTree"], [None, None])
        self.assertEqual(got["kidsIn"], [True, True])
        self.assertEqual(got["afterEmpty"], [None, None])
        self.assertEqual(got["ids"], ["v", "", None])
        self.assertEqual(got["body"], 1)
        self.assertTrue(got["byId"])
        self.assertTrue(got["byName"])
        self.assertTrue(got["bare"])
        self.assertTrue(got["byClass"])
        self.assertTrue(got["bareClass"])
        # A miss is exactly `null`, and `#x` is an id, never a class.
        self.assertEqual(got["missing"], [True, True, True, True])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_harness_dom_knows_whether_a_node_is_in_the_page(self):
        """What a node reports about being in the page.

        Task 5 minimises a card by hiding it and Task 6 measures: a hidden
        probe that answered its box here and nothing in Safari would size
        the terminal to nothing on restore. So a node measures nothing
        unless it is in the page (it has a parent node, or it is a registered
        node) and neither it nor any ancestor is `display: none`. Also here:
        `fakeBox` is spent by the next `createElement` and by nothing else,
        an id appended into the page can be found and one removed cannot,
        and assigning `innerHTML` empties the node, so a card inside the
        agent list is told from one parked beside it.
        """
        got = self._node(
            "const host = el('host');\n"
            "const rect = n => { const r = n.getBoundingClientRect();\n"
            "  return [r.width, r.height, r.top, r.left, r.right, r.bottom]; };\n"
            "const wh = n => rect(n).slice(0, 2);\n"
            # fakeBox goes to the next createElement, not to a registration
            "fakeBox(820, 600);\n"
            "const reg = el('some-new-id');\n"
            "const made = document.createElement('div');\n"
            "host.appendChild(made);\n"
            "const next = document.createElement('div'); host.appendChild(next);\n"
            "const spent = [wh(made), wh(reg), wh(next)];\n"
            "reg.box = {width: 3, height: 4};\n"
            "const viaBox = wh(reg);\n"
            "el('content').box = {width: 900, height: 700};\n"
            "const registeredRoot = wh(el('content'));\n"
            # the rect's five fields
            "fakeBox(10, 20);\n"
            "const sized = document.createElement('div'); host.appendChild(sized);\n"
            "const fields = rect(sized);\n"
            # in the page, out of it, and taken out again
            "fakeBox(7, 8);\n"
            "const loose = document.createElement('div');\n"
            "const unattached = wh(loose);\n"
            "host.appendChild(loose);\n"
            "const attached = wh(loose);\n"
            "loose.style.display = 'none';\n"
            "const hiddenSelf = wh(loose);\n"
            "loose.style.display = 'block';\n"
            "const shown = wh(loose);\n"
            "loose.style.display = '';\n"
            "loose.remove();\n"
            "const afterRemove = wh(loose);\n"
            # hidden by an ancestor, at either level
            "const top = el('card'), mid = document.createElement('div');\n"
            "fakeBox(820, 600);\n"
            "const probe = document.createElement('div');\n"
            "top.appendChild(mid); mid.appendChild(probe);\n"
            "const visible = wh(probe);\n"
            "top.style.display = 'none';\n"
            "const topHidden = wh(probe);\n"
            "top.style.display = ''; mid.style.display = 'none';\n"
            "const midHidden = wh(probe);\n"
            "mid.style.display = 'block';\n"
            "const restored = wh(probe);\n"
            # an id appended into the page is found; removed, it is not
            "const card = document.createElement('div');\n"
            "const beforeAppend = document.getElementById('opshell-card');\n"
            "card.id = 'opshell-card'; host.appendChild(card);\n"
            "const found = document.getElementById('opshell-card') === card;\n"
            "card.remove();\n"
            "const afterCardRemove = document.getElementById('opshell-card');\n"
            "const t1 = document.createElement('div'); t1.id = 'twin';\n"
            "const t2 = document.createElement('div'); t2.id = 'twin';\n"
            "host.appendChild(t1); host.appendChild(t2); t1.remove();\n"
            "const twinKept = document.getElementById('twin') === t2;\n"
            # innerHTML empties: a card in the list goes, one beside it stays
            "const list = el('list'), side = el('side');\n"
            "const inner = document.createElement('div'); inner.id = 'inner';\n"
            "const parked = document.createElement('div'); parked.id = 'parked';\n"
            "list.appendChild(inner); side.appendChild(list);\n"
            "side.appendChild(parked);\n"
            "list.innerHTML = '';\n"
            "const emptied = [list.children.length, inner.parentNode === null,"
            " inner.parentElement === null,"
            " document.getElementById('inner') === null,"
            " parked.parentNode === side, parked.parentElement === side,"
            " side.children.length,"
            " document.getElementById('parked') === parked];\n"
            "const again = document.createElement('div'); list.appendChild(again);\n"
            "list.innerHTML = '<p>x</p>';\n"
            "const refilled = [list.children.length, again.parentNode === null];\n"
            "console.log(JSON.stringify({spent, viaBox, registeredRoot, fields,"
            " unattached, attached, hiddenSelf, shown, afterRemove,"
            " visible, topHidden, midHidden, restored,"
            " beforeAppend, found, afterCardRemove, twinKept,"
            " emptied, refilled, removed}));")
        self.assertEqual(got["spent"], [[820, 600], [0, 0], [0, 0]])
        self.assertEqual(got["viaBox"], [3, 4])
        self.assertEqual(got["registeredRoot"], [900, 700])
        # width, height, top, left, right, bottom
        self.assertEqual(got["fields"], [10, 20, 0, 0, 10, 20])
        self.assertEqual(got["unattached"], [0, 0])
        self.assertEqual(got["attached"], [7, 8])
        self.assertEqual(got["hiddenSelf"], [0, 0])
        self.assertEqual(got["shown"], [7, 8])
        self.assertEqual(got["afterRemove"], [0, 0])
        self.assertEqual(got["visible"], [820, 600])
        self.assertEqual(got["topHidden"], [0, 0])
        self.assertEqual(got["midHidden"], [0, 0])
        self.assertEqual(got["restored"], [820, 600])
        self.assertIsNone(got["beforeAppend"])
        self.assertTrue(got["found"])
        self.assertIsNone(got["afterCardRemove"])
        self.assertTrue(got["twinKept"])
        self.assertEqual(got["emptied"],
                         [0, True, True, True, True, True, 2, True])
        self.assertEqual(got["refilled"], [0, True])
        self.assertIn("opshell-card", got["removed"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_closing_the_view_closes_the_session(self):
        # C2 of the final review. Teardown cleared a timer and returned, so
        # the channel stayed up on the device -- while the panel's own text
        # promised "closing it queues the channel's shutdown" and
        # teardown's own comment claimed the lapse would handle it.
        got = self._node(
            "opshellSession = 'sid-1'; opshellAbort = new AbortController();\n"
            "els['x'] = el('x');\n"
            "await opshellTeardown(els['x']);\n"
            "console.log(JSON.stringify({posted: posted.map(p => p.url),"
            " methods: posted.map(p => p.method), bodies: posted.map(p => p.body),"
            " session: opshellSession, removed}));")
        self.assertEqual(got["posted"], ["/api/opshell/close"])
        self.assertEqual(got["methods"], ["POST"])
        self.assertIn("sid-1", got["bodies"][0])
        self.assertIsNone(got["session"])
        self.assertEqual(got["removed"], ["x"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_ending_the_session_aborts_the_stream_it_left_running(self):
        # The stream outlived the view: the bridge, the pty, one of the
        # port's four slots, the transcript and a Flask worker all survived
        # a closed panel, because the pump exits only on handover, lapse or
        # EOF.
        # The abort has to make an in-flight request reject, not merely
        # be recorded. The first harness's `abort()` only pushed a string,
        # so no test could show a stream ending -- and `opshellAttach`'s
        # own reader loop was outside the harness entirely.
        got = self._node(
            "opshellSession = 'sid-2'; opshellAbort = new AbortController();\n"
            "holdFetch = 4;\n"
            "const inflight = fetch('/api/opshell/stream',"
            " {signal: opshellAbort.signal}).then(() => 'resolved',"
            " e => e.name);\n"
            "await opshellEndSession();\n"
            "console.log(JSON.stringify({aborted, abort: opshellAbort,"
            " outcome: await inflight}));")
        self.assertEqual(got["aborted"], ["abort"])
        self.assertIsNone(got["abort"])
        self.assertEqual(got["outcome"], "AbortError",
                         "the stream request was not actually aborted")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_closing_a_view_that_never_opened_a_session_posts_nothing(self):
        got = self._node(
            "opshellSession = null; els['y'] = el('y');\n"
            "await opshellTeardown(els['y']);\n"
            "console.log(JSON.stringify({posted, removed}));")
        self.assertEqual(got["posted"], [])
        self.assertEqual(got["removed"], ["y"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_remembered_session_is_resumed_on_load(self):
        got = self._node(
            "els['main'] = el('main'); els['content'] = el('content');\n"
            "els['main'].appendChild(els['content']);\n"
            "sessionStorage.setItem(opshellStore, 'kept-1');\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot', sessions:1}}];\n"
            "await opshellResume();\n"
            "console.log(JSON.stringify({session: opshellSession,"
            " urls: posted.map(p => p.url)}));")
        self.assertEqual(got["session"], "kept-1")
        # The id rides in the query string, and `startswith` could not see
        # that: `encodeURIComponent("")` left `?session=` and passed. The
        # server reads that arg to beat *this* claim and to report the
        # geometry of *this* bridge, so without it the claim is not
        # heartbeat by the request that resumed it and the card reports
        # another tab's pty size.
        self.assertIn("/api/opshell/state?session=kept-1", got["urls"][0],
                      got["urls"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_session_that_is_gone_is_forgotten_rather_than_drawn(self):
        """Review Focus 2.

        The tab was shut for longer than the lapse, so the claim was
        retired and the channel stopped. A card drawn from the remembered
        id would look live over nothing.
        """
        got = self._node(
            "sessionStorage.setItem(opshellStore, 'stale-1');\n"
            "replies = [{ok:true, status:200, body:{state:'idle',"
            " channel:'closed', sessions:0}}];\n"
            "await opshellResume();\n"
            "console.log(JSON.stringify({session: opshellSession,"
            " remembered: sessionStorage.getItem(opshellStore),"
            " bodies: Object.keys(els)}));")
        self.assertIsNone(got["session"])
        self.assertIsNone(got["remembered"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_channel_that_is_not_up_yet_is_not_resumed_either(self):
        # The other half of the same guard, and it was unpinned: cut to
        # `if(!(state.sessions > 0))` the suite stayed green, and then a
        # `waiting` or `closing` answer that happens to carry another tab's
        # session count adopts the id and draws a terminal for a channel
        # that is not up -- `/stream` would refuse it, which is the card
        # looking live over nothing that Review Focus 2 is about.
        for state in ("waiting", "closing"):
            got = self._node(
                "sessionStorage.setItem(opshellStore, 'early-1');\n"
                "replies = [{ok:true, status:200, body:{state:'%s',"
                " channel:'closed', sessions:1}}];\n"
                "await opshellResume();\n"
                "console.log(JSON.stringify({session: opshellSession,"
                " remembered: sessionStorage.getItem(opshellStore)}));"
                % state)
            self.assertIsNone(got["session"], state)
            self.assertIsNone(got["remembered"], state)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_session_this_server_does_not_know_is_not_adopted(self):
        """Review Focus 5.

        Two team servers on one origin -- a port change on localhost is
        the common case -- leave each other's ids in the same
        `sessionStorage`. An id the server answers `sessions: 0` for is
        not this server's.
        """
        got = self._node(
            "sessionStorage.setItem(opshellStore, 'other-servers-id');\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot', sessions:0}}];\n"
            "await opshellResume();\n"
            "console.log(JSON.stringify({session: opshellSession,"
            " remembered: sessionStorage.getItem(opshellStore)}));")
        self.assertIsNone(got["session"])
        self.assertIsNone(got["remembered"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_resumed_session_says_it_is_a_new_shell(self):
        got = self._node(
            "sessionStorage.setItem(opshellStore, 'kept');\n"
            "els['main'] = el('main'); els['content'] = el('content');\n"
            "els['main'].appendChild(els['content']);\n"
            "els['opshell-term'] = el('opshell-term');\n"
            "const term = fakeTerm();\n"
            "globalThis.Terminal = function(){ return term; };\n"
            # The card is drawn for real now, so its poll runs and takes a
            # reply of its own, as it does in the two-terminals test below.
            "const live = {state:'live', channel:'open', host:'parrot',"
            " sessions:1, geometry:[80,24]};\n"
            "replies = [{ok:true, status:200, body:live},"
            " {ok:true, status:200, body:live},"
            " {ok:true, status:200, stream: fakeStream(['x'])},"
            " {ok:true, status:200, body:{}}];\n"
            "await opshellResume();\n"
            "console.log(JSON.stringify({said: term.lines.join(' ')}));")
        self.assertRegex(got["said"], r"(?i)new shell")
        self.assertRegex(got["said"], r"(?i)previous|earlier|gone")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_resume_does_not_put_two_terminals_on_one_session(self):
        # The card's own poll attaches when it finds the terminal host, and
        # the resume attaches the session it just verified, so both can
        # reach for the same one. Two streams on one session is a handover
        # on the server: the first bridge is dropped, and the terminal the
        # operator is typing into goes quiet with no line to say why.
        got = self._node(
            "sessionStorage.setItem(opshellStore, 'kept-3');\n"
            "els['main'] = el('main'); els['content'] = el('content');\n"
            "els['main'].appendChild(els['content']);\n"
            "els['opshell-term'] = el('opshell-term');\n"
            "globalThis.Terminal = function(){ return fakeTerm(); };\n"
            "const live = {state:'live', channel:'open', host:'parrot',"
            " sessions:1, geometry:[80,24]};\n"
            "replies = [{ok:true, status:200, body:live},"
            " {ok:true, status:200, body:live},"
            " {ok:true, status:200, stream: fakeStream(['x'])},"
            " {ok:true, status:200, body:{}}];\n"
            "await opshellResume();\n"
            "console.log(JSON.stringify({streams: posted.filter(p =>"
            " p.url.indexOf('/api/opshell/stream') === 0).length}));")
        self.assertEqual(got["streams"], 1,
                         "%d streams were opened on one session; the second "
                         "takes the bridge over from the first"
                         % got["streams"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_session_is_remembered_when_it_opens_and_forgotten_when_it_ends(self):
        # Nothing above writes the id: every resume test puts it in
        # `sessionStorage` by hand, so a page that remembers nothing passes
        # all of them while a reload restores nothing at all. Both ends in
        # one test, because remembering without forgetting is the worse
        # half -- a card drawn on the next load over a session that was
        # handed back.
        got = self._node(
            "els['opshell-body'] = el('opshell-body');\n"
            "replies = [{ok:true, status:200, body:{session:'s9'}},"
            " {ok:true, status:200, body:{}}];\n"
            "await opshellOpen();\n"
            "const afterOpen = sessionStorage.getItem(opshellStore);\n"
            "await opshellEndSession();\n"
            "console.log(JSON.stringify({afterOpen,"
            " afterEnd: sessionStorage.getItem(opshellStore)}));")
        self.assertEqual(got["afterOpen"], "s9")
        self.assertIsNone(got["afterEnd"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_session_is_not_given_up_on_a_server_that_did_not_answer(self):
        # An id is surrendered on the server's word about the session, and
        # on nothing else. Both halves, because the first version of this
        # test drove only the throw: `if(!r.ok || !state){ opshellRemember(
        # ""); return false; }` was green across the whole suite, and that
        # is the 401 -- the case this narrowing was argued from. The token
        # gate prompts, the operator types the token, and the id has
        # already been thrown away by a resume that ran before either.
        #
        # A request that never arrived is the other half: it says nothing
        # about the session, and forgetting there turns one unlucky reload
        # into a channel this page can no longer put back by itself.
        #
        # The throw case also shows that the resume's fetch path cannot
        # reject -- startup calls it bare, so a rejection is an unhandled
        # one and node exits non-zero, which `_node` reads as a failure.
        # Only that path: `showOperatorShell` and `opshellAttach` are
        # reached on the live path and are not covered here.
        for reply, why in (("{throw:'Failed to fetch'}", "a dropped request"),
                           ("{ok:false, status:401, body:{}}", "a 401"),
                           ("{ok:false, status:502, body:{}}", "a 502")):
            got = self._node(
                "sessionStorage.setItem(opshellStore, 'kept-2');\n"
                "replies = [%s];\n"
                "await opshellResume();\n"
                "console.log(JSON.stringify({session: opshellSession,"
                " remembered: sessionStorage.getItem(opshellStore),"
                " urls: posted.map(p => p.url)}));" % reply)
            self.assertIsNone(got["session"], why)
            self.assertEqual(got["remembered"], "kept-2",
                             "%s cost the operator the remembered session"
                             % why)
            # One request, not a retry loop inside startup.
            self.assertEqual(len(got["urls"]), 1, why)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_refusal_from_open_is_shown_and_not_swallowed(self):
        # I3. `api()` throws only on 401, so a 409 resolved normally, the
        # body had no `session`, and the catch never ran: the button did
        # nothing and the server's carefully worded reason was discarded.
        got = self._node(
            "els['opshell-body'] = el('opshell-body');\n"
            # By hand, so not end to end: the real card is `_refusal_card`'s.
            "els['opshell-refused'] = el('opshell-refused');\n"
            "nextReply = {ok:false, status:409, body:"
            "{error:'the tunnel server would not start: port in use'}};\n"
            "await opshellOpen();\n"
            "console.log(JSON.stringify({shown: els['opshell-refused'].innerHTML,"
            " session: opshellSession}));")
        self.assertIn("would not start", got["shown"])
        self.assertIn("port in use", got["shown"])
        self.assertIsNone(got["session"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_live_channel_with_no_local_session_offers_both_controls(self):
        # I6. After F5, in a second tab, or when the channel was raised
        # from the tunnel panel, the view drew the live strip with an empty
        # terminal box and no control at all: the operator could neither
        # join the session they could see nor drop it, and about a minute
        # later it was stopped without anyone asking.
        got = self._node(
            "opshellSession = null;\n"
            "const html = opshellRender({state:'live', channel:'open',"
            " host:'parrot', geometry:[120,40]});\n"
            "console.log(JSON.stringify({html}));")
        html = got["html"]
        self.assertIn("opshellOpen(", html,
                      "no way to attach to a channel the view can see")
        # Not `opshellEndSession` -- that is the inert one in this state,
        # and asserting its *name* here is what let the Critical through.
        # What it actually does is
        # `test_the_end_button_actually_ends_something`.
        self.assertIn("opshellEndAfterAttach(", html,
                      "no way to drop a channel the view can see")
        self.assertNotIn("opshellEndSession()", html,
                         "the inert handler is back on the button")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_live_channel_this_page_holds_draws_the_terminal_instead(self):
        got = self._node(
            "opshellSession = 'mine';\n"
            "const html = opshellRender({state:'live', channel:'open',"
            " host:'parrot', geometry:[120,40]});\n"
            "console.log(JSON.stringify({html}));")
        self.assertIn('id="opshell-term"', got["html"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_end_button_actually_ends_something(self):
        """The re-review's Critical, and it was in my own fix.

        The branch is drawn only when `!opshellSession`, and
        `opshellEndSession` returns false before it aborts or posts
        anything when there is no session -- so the button promised "ending
        it queues the channel's shutdown" and provably did nothing. The
        same class as the two Criticals this wave was written to fix, and
        the test that was supposed to cover it asserted that the markup
        *mentions* the call.

        So this calls the handler the markup names, rather than looking for
        its name.
        """
        got = self._node(
            "opshellSession = null;\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "const html = opshellRender({state:'live', channel:'open',"
            " host:'parrot', candidates:['clumsy-raccoon'],"
            " target:'clumsy-raccoon', geometry:[120,40]});\n"
            "const m = html.match(/onclick=\"([a-zA-Z]+)\\(([^\"]*)\\)\"/g);\n"
            "const ender = (m||[]).find(x => !x.includes('opshellOpen'));\n"
            "nextReply = {ok:true, status:200, body:{session:'adopted'}};\n"
            "await opshellEndAfterAttach();\n"
            "console.log(JSON.stringify({ender,"
            " urls: posted.map(p => p.url)}));")
        self.assertIsNotNone(got["ender"], "no control to end the session")
        self.assertIn("opshellEndAfterAttach", got["ender"])
        # It takes the claim, then releases it: the stop then goes through
        # the one path that decides stops, and a channel this view did not
        # raise comes back with the server's own refusal rather than a
        # silent nothing.
        self.assertEqual(got["urls"],
                         ["/api/opshell/open", "/api/opshell/close"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_end_button_reports_a_close_that_was_refused(self):
        # Two requests, two answers: one global reply could not express
        # "the claim was taken and then the shutdown was refused", which is
        # the case the button exists for -- a channel somebody else raised.
        # It also puts the harness's reply queue to work, which nothing was
        # using, so its "throw on an unexpected request" protection was
        # dead weight.
        got = self._node(
            "opshellSession = null; opshellTerm = fakeTerm();\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "replies = [{ok:true, status:200, body:{session:'adopted'}},"
            " {ok:true, status:200, body:{reason:'this channel was not "
            "started by the operator shell'}}];\n"
            "await opshellEndAfterAttach();\n"
            "console.log(JSON.stringify({urls: posted.map(p => p.url),"
            " said: opshellTerm.lines.join(' '),"
            " shown: els['opshell-body'].innerHTML,"
            " session: opshellSession}));")
        self.assertEqual(got["urls"],
                         ["/api/opshell/open", "/api/opshell/close"])
        self.assertRegex(got["said"] + " " + got["shown"],
                         r"(?i)not started by the operator shell")
        self.assertIsNone(got["session"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_an_unexpected_extra_request_is_an_error_not_a_free_success(self):
        # The harness's own guard, exercised. Without a test the queue's
        # throw was dead: reverting it to a default 200 left every test
        # green, so any mutation that added a request was absorbed.
        out = subprocess.run(
            ["node", "--input-type=module", "-e",
             _NODE_ENV + "\nreplies = [{ok:true, status:200, body:{}}];\n"
             "await fetch('/one');\n"
             "let threw = false;\n"
             "try { await fetch('/two'); } catch(e) { threw = true; }\n"
             "console.log(JSON.stringify({threw}));"],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr[-800:])
        self.assertTrue(json.loads(out.stdout.strip())["threw"],
                        "a request beyond the queue was handed a free 200")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_double_click_on_open_takes_only_one_claim(self):
        # The first version grepped `opshellOpen` for the word "disabled",
        # which survives in `if(button.disabled) return;` -- so deleting
        # the line that arms the guard left it green and the double-click
        # took two claims again. The orphaned one then made the operator's
        # close answer "not the last", and no stop was queued until it
        # lapsed.
        got = self._node(
            "const button = {disabled:false};\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "nextReply = {ok:true, status:200, body:{session:'s1'}};\n"
            "const ev = {currentTarget: button};\n"
            "await Promise.all([opshellOpen(ev), opshellOpen(ev)]);\n"
            "console.log(JSON.stringify({opens: posted.filter("
            "p => p.url.endsWith('open')).length}));")
        self.assertEqual(got["opens"], 1)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_batch_is_sent_whole_or_not_at_all(self):
        """Atomic, after three repairs that each added a failure mode.

        Generation one posted per keystroke and could reorder. Generation
        two coalesced and lost whole batches in silence. Generation three
        put a failed batch back and made an unbounded buffer that lied.
        Generation four split oversized batches -- and a split that fails
        part way delivers a prefix into a root shell: measured, 262144
        bytes of a pasted script executed while the view said nothing had
        been delivered and told the operator to type it again.

        A terminal cannot express partial delivery, so this does not try.
        One batch, one request, no splitting, no retry: it arrives whole or
        it is refused whole and named.
        """
        got = self._node(
            "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
            # Under the client's ceiling, so the server's refusal is the
            # path under test rather than the up-front check.
            "opshellKeys = 'rm -rf /important' + 'A'.repeat(100000) + '\\r';\n"
            "nextReply = {ok:false, status:413, body:{}};\n"
            "await opshellFlushKeys();\n"
            "console.log(JSON.stringify({posts: posted.filter("
            "p => p.url.endsWith('keys')).length,"
            " leftover: opshellKeys.length,"
            " said: opshellTerm.lines.join(' ')}));")
        # Nothing was sent, so nothing can have partly landed.
        self.assertEqual(got["posts"], 1)
        self.assertEqual(got["leftover"], 0)
        self.assertRegex(got["said"], r"(?i)nothing .*(sent|delivered)|"
                                      r"not .*(sent|delivered)")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_what_is_typed_during_a_failing_batch_dies_with_it(self):
        """The worst finding of this branch, and I caused it.

        The previous shape cleared the buffer on a failed batch, under its
        own comment: "delivering later keystrokes without the ones before
        them is how a truncated command reaches a root shell". The atomic
        rewrite deleted that line **and the test that named it** -- and the
        test count went up, so the count check I had added could not see
        it.

        The window is not microseconds: a 502 comes from a `sendall` with a
        fifteen-second timeout, so fifteen seconds of typing accumulates
        and is then delivered without the batch that was dropped.
        Reproduced by the reviewer as `rm -rf /` followed by an Enter typed
        mid-flight.

        `holdFetch` is what makes this measurable; the test it replaces had
        it at zero, so nothing could arrive mid-flight at all.
        """
        got = self._node(
            "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
            "holdFetch = 6;\n"
            "opshellKeys = 'var/tmp/junk';\n"
            "nextReply = {ok:false, status:502, body:{}};\n"
            "const flushing = opshellFlushKeys();\n"
            # Typed while the batch is in the air.
            "opshellKeys += '\\r';\n"
            "await flushing;\n"
            "nextReply = {ok:true, status:200, body:{}};\n"
            "await opshellFlushKeys();\n"
            "const sent = posted.filter(p => p.url.endsWith('keys')).map("
            "p => Buffer.from(JSON.parse(p.body).data,'base64').toString());\n"
            "console.log(JSON.stringify({leftover: opshellKeys,"
            " sent, said: opshellTerm.lines.join(' ')}));")
        self.assertEqual(got["leftover"], "",
                         "keystrokes typed during a failed batch survived it")
        # Exactly one request: the failed one. The Enter must never go out
        # on its own.
        self.assertEqual(got["sent"], ["var/tmp/junk"])
        self.assertRegex(got["said"], r"(?i)since|anything else|typed after")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_same_holds_when_the_request_is_rejected_outright(self):
        # Two arms, and the first version of the fix covered one. A
        # rejected request is the commoner of the two -- a dropped
        # connection rather than a status -- and it had the same hole.
        got = self._node(
            "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
            "holdFetch = 6;\n"
            "opshellKeys = 'var/tmp/junk';\n"
            "nextReply = {throw:'socket hang up'};\n"
            "const flushing = opshellFlushKeys();\n"
            "opshellKeys += '\\r';\n"
            "await flushing;\n"
            "nextReply = {ok:true, status:200, body:{}};\n"
            "await opshellFlushKeys();\n"
            "const sent = posted.filter(p => p.url.endsWith('keys')).map("
            "p => Buffer.from(JSON.parse(p.body).data,'base64').toString());\n"
            "console.log(JSON.stringify({leftover: opshellKeys, sent,"
            " said: opshellTerm.lines.join(' ')}));")
        self.assertEqual(got["leftover"], "")
        self.assertEqual(got["sent"], ["var/tmp/junk"])
        self.assertRegex(got["said"], r"(?i)since|anything else|typed after")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_write_that_may_have_landed_is_not_called_nothing(self):
        """B2: 502 is the one status that means a write was attempted.

        The route answers 502 only when the bridge was accepted and
        `sendall` raised -- and a `sendall` that times out mid-write has
        already put bytes on the wire and cannot say how many. Saying
        "nothing reached the shell" there is the same false assurance this
        round was written to remove, one door along.
        """
        maybe = self._node(
            "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
            "nextReply = {ok:false, status:502, body:{}};\n"
            "opshellKeys = 'ls';\n"
            "await opshellFlushKeys();\n"
            "console.log(JSON.stringify({said: opshellTerm.lines.join(' ')}));")
        # Uncertainty, however it is worded, and never the denial.
        self.assertRegex(maybe["said"],
                         r"(?i)may (or may not|already)? ?have")
        self.assertNotRegex(maybe["said"], r"(?i)nothing reached")
        # And the statuses that truly wrote nothing still say so, or the
        # distinction is worthless.
        for status in (413, 404, 409, 400):
            got = self._node(
                "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
                "nextReply = {ok:false, status:%d, body:{}};\n"
                "opshellKeys = 'ls';\n"
                "await opshellFlushKeys();\n"
                "console.log(JSON.stringify({said: opshellTerm.lines"
                ".join(' ')}));" % status)
            self.assertRegex(got["said"], r"(?i)nothing reached", str(status))

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_paste_too_large_to_send_whole_is_refused_before_it_is_sent(self):
        # Refused up front, with its size, rather than split: splitting is
        # what created the partial-delivery defect. The ceiling is measured
        # in the units the server measures, so a non-ASCII paste cannot
        # slip past the client's check and be refused by the server.
        got = self._node(
            "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
            "opshellKeys = '\\u00e9'.repeat(200000);\n"
            "await opshellFlushKeys();\n"
            "console.log(JSON.stringify({posts: posted.filter("
            "p => p.url.endsWith('keys')).length,"
            " leftover: opshellKeys.length,"
            " said: opshellTerm.lines.join(' ')}));")
        self.assertEqual(got["posts"], 0,
                         "an oversized paste was sent anyway")
        self.assertEqual(got["leftover"], 0)
        self.assertRegex(got["said"], r"(?i)too large|too much")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_paste_the_server_accepts_is_not_refused_by_the_client(self):
        # The two ceilings have to agree, or the client refuses what the
        # server would have taken -- or worse, the reverse. Measured in
        # base64 of UTF-8, which is what the route counts.
        got = self._node(
            "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
            "opshellKeys = '\\u00e9'.repeat(60000);\n"
            "await opshellFlushKeys();\n"
            "const sent = posted.filter(p => p.url.endsWith('keys'));\n"
            "console.log(JSON.stringify({posts: sent.length,"
            " encoded: sent.length ? JSON.parse(sent[0].body).data.length : 0,"
            " said: opshellTerm.lines.join(' ')}));")
        self.assertEqual(got["posts"], 1)
        self.assertLessEqual(got["encoded"], 256 * 1024)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_an_emoji_survives_the_encoding_whole(self):
        # Atomic sending removed the slicing that could cut a surrogate
        # pair, but the encoder still has to handle one: a pair arriving as
        # two U+FFFD is a different character reaching a root shell.
        got = self._node(
            "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
            "opshellKeys = 'echo \\ud83d\\udc3e';\n"
            "await opshellFlushKeys();\n"
            "const body = posted.filter(p => p.url.endsWith('keys'))[0];\n"
            "console.log(JSON.stringify({text: Buffer.from("
            "JSON.parse(body.body).data, 'base64').toString('utf8')}));")
        self.assertEqual(got["text"], "echo \U0001f43e")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_refusal_shows_the_detail_the_route_sent(self):
        # The route answers 409 for a bridge that was never accepted with
        # `detail: "its reason is on the stream"`. The client printed
        # `HTTP 409` and discarded the sentence that tells the operator
        # where to look.
        got = self._node(
            "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
            "nextReply = {ok:false, status:409, body:{error:'the shell port "
            "refused this session', detail:'its reason is on the stream'}};\n"
            "opshellKeys = 'ls';\n"
            "await opshellFlushKeys();\n"
            "console.log(JSON.stringify({said: opshellTerm.lines.join(' ')}));")
        self.assertIn("refused this session", got["said"])
        self.assertIn("on the stream", got["said"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_nothing_is_ever_sent_twice(self):
        """The retry duplicated input, and its test pinned the duplicate.

        A rejected `fetch` does not mean the request was not delivered: a
        reset after the body was written, or a lost response, both reject.
        The retry then re-sent the same bytes into a root shell, and
        `/api/opshell/keys` has no idempotency of any kind. A named drop
        beats a silent duplicate.
        """
        got = self._node(
            "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
            "nextReply = {throw:'socket hang up'};\n"
            "opshellKeys = 'reboot\\r';\n"
            "await opshellFlushKeys();\n"
            "console.log(JSON.stringify({posts: posted.filter("
            "p => p.url.endsWith('keys')).length,"
            " leftover: opshellKeys.length,"
            " said: opshellTerm.lines.join(' ')}));")
        self.assertEqual(got["posts"], 1, "the batch was sent twice")
        self.assertEqual(got["leftover"], 0)
        # The one thing nobody on this side can know: a rejected request
        # may already have been delivered.
        self.assertRegex(got["said"], r"(?i)may or may not|may have")
        self.assertRegex(got["said"], r"(?i)not .*again|check the session")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_refusal_that_cannot_succeed_drops_the_batch_and_says_so(self):
        """C1 of the third review: my own fix was worse than the defect.

        Putting the batch back with no bound and no discard rule made an
        unbounded, permanently undeliverable buffer -- and every keypress
        re-drove the flush, so the operator was told "still waiting" for
        ever while nothing was delivered. If the cause then cleared, the
        whole accumulated and never-echoed buffer would replay into a root
        shell as one batch.

        413, 404, 409 and 400 cannot come good by waiting, so they are
        dropped and named as dropped.
        """
        for status in (413, 404, 409, 400):
            got = self._node(
                "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
                "nextReply = {ok:false, status:%d, body:{}};\n"
                "opshellKeys = 'rm -rf /tmp/x';\n"
                "await opshellFlushKeys();\n"
                "opshellKeys += 'more';\n"
                "await opshellFlushKeys();\n"
                "console.log(JSON.stringify({leftover: opshellKeys,"
                " posts: posted.filter(p => p.url.endsWith('keys')).length,"
                " said: opshellTerm.lines.join(' ')}));" % status)
            self.assertEqual(got["leftover"], "", status)
            self.assertRegex(got["said"], r"(?i)dropped|not delivered",
                             str(status))
            self.assertEqual(got["posts"], 2, status)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_what_the_port_writes_reaches_the_terminal(self):
        """Review Focus 2's browser half, unproven until now.

        The cap's refusal arrives as bytes on the stream rather than as an
        HTTP error, which the bridge tests pin -- but no test ever gave the
        harness a stream, so every successful reply took the `!res.body`
        branch and the reader loop never ran once.
        """
        got = self._node(
            "els['opshell-term'] = el('opshell-term');\n"
            "globalThis.Terminal = function(){ return fakeTerm(); };\n"
            "opshellSession = 'sid';\n"
            "nextReply = {ok:true, status:200,"
            " stream: fakeStream(['no free session slots', 'root@parrot:~# '])};\n"
            "await opshellAttach({state:'live', geometry:[80,24],"
            " host:'parrot'});\n"
            "console.log(JSON.stringify({lines: opshellTerm"
            " ? opshellTerm.lines : null, session: opshellSession,"
            " closed: posted.filter(p => p.url.endsWith('close')).length}));")
        self.assertIn("no free session slots", " ".join(got["lines"]))
        self.assertIn("root@parrot", " ".join(got["lines"]))

    def _first_line(self, state_fields):
        """What the page wrote first into the terminal for this state."""
        got = self._node(
            "els['opshell-term'] = el('opshell-term');\n"
            "const term = fakeTerm();\n"
            "globalThis.Terminal = function(){ return term; };\n"
            "opshellSession = 'sid';\n"
            "nextReply = {ok:true, status:200, stream: fakeStream(['x'])};\n"
            "await opshellAttach(Object.assign({state:'live',"
            " geometry:[80,24], host:'parrot'}, %s));\n"
            "console.log(JSON.stringify({first: term.lines[0],"
            " all: term.lines.join(' ')}));" % json.dumps(state_fields))
        return got["first"], got["all"]

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_first_line_claims_nothing_when_it_was_told_nothing(self):
        """Review Focus 3. A page that defaults to "history is off" would
        claim it for a channel the relay has no row for."""
        for fields in ({"history": "", "history_detail": ""},
                       {},
                       {"history": None, "history_detail": None},
                       {"history": "banana", "history_detail": "x"},
                       {"history": "", "history_detail": "stray reason"}):
            first, _ = self._first_line(fields)
            self.assertNotRegex(first, r"(?i)history",
                                "said something about history for %r" % fields)
            self.assertNotIn("stray reason", first)
            self.assertIn("live on parrot", first)
            self.assertRegex(first, r"[0-9]+x[0-9]+, fixed for this session")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_weak_guard_says_why_and_an_off_guard_says_it_is_off(self):
        lines = {}
        for guard, detail in (("off", ""),
                              ("weak", "/bin/zsh takes no --rcfile")):
            lines[guard], _ = self._first_line(
                {"history": guard, "history_detail": detail})
        self.assertRegex(lines["off"], r"(?i)history is off in this session")
        self.assertNotRegex(lines["weak"], r"(?i)history is off")
        self.assertRegex(lines["weak"], r"(?i)not guaranteed off")
        self.assertIn("/bin/zsh takes no --rcfile", lines["weak"])
        # How the reason is attached, and what the sentence after it says:
        # the reason in parentheses straight after the guard, a colon, then
        # the page's explanation, which names what runs after what.
        self.assertIn("not guaranteed off in this session "
                      "(/bin/zsh takes no --rcfile): " + self._RECORDED,
                      lines["weak"])
        self.assertNotEqual(lines["off"], lines["weak"])

    # What the weak guard costs, as measured on the Mac this was built for:
    # `/etc/zshrc` sets `HISTFILE` unconditionally, after the environment,
    # so there it is not "maybe" -- every command is written to the file.
    _RECORDED = ("it may well be recorded: the host's startup files run "
                 "after our HISTFILE, and on macOS /etc/zshrc sets its own")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_weak_guard_says_history_may_well_be_recorded_and_why(self):
        """A direction, not a set of words: the line may not say history is
        held off by anything, nor that undoing it is the user's doing and a
        possibility, and it has to name the system file that does it."""
        first, _ = self._first_line(
            {"history": "weak", "history_detail": "/bin/zsh cannot be given "
                                                  "a startup file of ours"})
        explained = first.split("): ", 1)[1].split(" \u00b7 ", 1)[0]
        self.assertEqual(explained, self._RECORDED)
        self.assertRegex(explained, r"(?i)\bmay well be recorded\b")
        self.assertRegex(explained, r"run after our HISTFILE")
        self.assertRegex(explained, r"macOS /etc/zshrc sets its own")
        self.assertNotRegex(explained, r"(?i)held off|may undo|your own|"
                                       r"not recorded|is off")
        # Short enough to read on one line of a card at 120 columns, the
        # size a card falls back to, and not much wider than 80.
        self.assertLessEqual(len(explained), 110, len(explained))

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_weak_guard_with_no_reason_reads_whole_on_its_own(self):
        """A relay too old to send the field arrives as "weak" and nothing
        else. The sentence then stands without a reason clause: no empty
        parenthesis, no colon or "because" left hanging."""
        for detail in ("", None, "   ", "\x1b\x07"):
            first, _ = self._first_line(
                {"history": "weak", "history_detail": detail})
            self.assertIn("history is not guaranteed off in this session",
                          first, repr(detail))
            self.assertNotRegex(first, r"\(\s*\)", repr(detail))
            self.assertNotRegex(first, r"(?i)because|\bwhy\b|:\s*(\u00b7|\x1b|$)",
                                repr(detail))
            self.assertNotRegex(first, r"(?i)history is off")
            self.assertNotRegex(first, r"(?i)startup file",
                                "explained a cause the page was not told")
            self.assertNotIn("undefined", first)
            self.assertNotIn("null", first)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_reason_is_text_from_the_machine_and_cannot_drive_the_terminal(self):
        """`history_detail` is written by the machine, so it may not carry a
        control sequence into the operator's terminal: an escape that
        cleared the line would hide the one sentence that says history is
        not held off."""
        first, everything = self._first_line(
            {"history": "weak", "history_detail": self._HOSTILE})
        # The only escapes in the line are the page's own dim and reset.
        self.assertEqual(re.findall(r"\x1b\[[0-9;]*[A-Za-z]", first),
                         ["\x1b[2m", "\x1b[0m"])
        self.assertNotRegex(first, r"[\x00-\x08\x0a-\x1a\x1c-\x1f\x7f-\x9f"
                                   r"\u200b-\u200f\u202a-\u202e\u2060-\u2069"
                                   r"\ufeff]")
        self.assertNotIn("\r", first)
        self.assertIn("not guaranteed off", first)
        self.assertIn("end", first)

    # --- Every door into the terminal, locked one at a time ---------------
    #
    # `history_detail` was the first writer of machine-derived text into the
    # terminal to be made plain, and the first line, the notes and the
    # stream-failure lines carry text from the same places. Each is driven
    # here with a hostile string and what reached the terminal is read back:
    # the helper's own test cannot say that a writer calls it.
    #
    # One sample for all of them, so it carries a character from every part
    # of what the helper removes: the C0 range's top (\x1f), DEL, the C1
    # range's bottom, the two that open a string in xterm.js (\x90 device
    # control, \x9d operating system command), the string terminator and
    # the top (\x9c, \x9f), a run, and the invisible and direction-marking
    # characters (zero-width space, right-to-left override, word joiner,
    # byte-order mark).
    _HOSTILE = ("ok\x1b[2J\x1b[H\rfake\x07\x9b31m\x7f\x80\x90\x9c\x9d\x9f"
                "\x1f\u200b\u202e\u2060\ufeff & <end>")

    def _assert_nothing_drives_the_terminal(self, lines, where):
        """Every note the hostile string reached carries no control byte of
        its own, only the page's dim and reset, and is still readable: not
        blanked, and not HTML-escaped -- this is a terminal, not markup."""
        hit = [l for l in lines if "ok" in l and "end" in l]
        self.assertTrue(hit, "%s: the text never reached the terminal: %r"
                        % (where, lines))
        for line in hit:
            bare = re.sub(r"^\r\n", "", line)
            bare = bare.replace("\x1b[2m", "").replace("\x1b[0m", "")
            self.assertNotRegex(
                bare,
                "[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2069"
                "\ufeff]",
                "%s wrote a control or invisible character: %r"
                % (where, line))
            self.assertIn("ok", bare)
            self.assertIn("& <end>", bare, "%s changed the text: %r"
                          % (where, line))
            self.assertNotIn("&amp;", bare)
            self.assertEqual(
                re.findall(r"\x1b", line),
                ["\x1b"] * (line.count("\x1b[2m") + line.count("\x1b[0m")),
                "%s let an escape sequence through: %r" % (where, line))

    def _lines(self, script):
        got = self._node(script + "\nconsole.log(JSON.stringify("
                         "{lines: opshellTerm ? opshellTerm.lines : []}));")
        return got["lines"]

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_helper_removes_what_a_terminal_acts_on_and_nothing_else(self):
        # Every character is its own case, so narrowing either end of a
        # range, or dropping the `+`, fails a case and not just a hunch.
        removed = ["\x1b[2J", "\r", "\n", "\x07", "\x7f", "\x9b", "\x00",
                   "\x1c", "\x1f", "\x80", "\x90", "\x98", "\x9c", "\x9d",
                   "\x9f", "\u200b", "\u200f", "\u202a", "\u202e", "\u2060",
                   "\u2069", "\ufeff"]
        runs = ["a\x1b\x07b", "a\x1b\x07\x9d\u202e\ufeffb", "a\x1f\x80b"]
        edges = "a\u00a0b\u200ac\u202fd\u205fe\u206af"
        got = self._node(
            "const cases = %s;\n"
            "console.log(JSON.stringify({\n"
            " out: cases.map(opshellPlain),\n"
            " kept: opshellPlain('caf\\u00e9 \\u65e5\\u672c \\u2713 & <b>'),\n"
            " edges: opshellPlain(%s),\n"
            " nothing: [opshellPlain(null), opshellPlain(undefined),"
            " opshellPlain(''), opshellPlain(7)]}));"
            % (json.dumps(["a" + c + "b" for c in removed] + runs
                          + ["  x  "]), json.dumps(edges)))
        self.assertEqual(
            got["out"],
            ["a [2Jb"] + ["a b"] * (len(removed) - 1 + len(runs)) + ["x"])
        self.assertEqual(got["kept"], "caf\u00e9 \u65e5\u672c \u2713 & <b>")
        # Just outside the removed ranges -- a no-break space, a hair space,
        # a narrow no-break space, a medium mathematical space and the code
        # point after the word joiner's block -- all stay.
        self.assertEqual(got["edges"], edges)
        self.assertEqual(got["nothing"], ["", "", "", "7"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_helper_cuts_what_is_left_at_two_hundred_characters(self):
        got = self._node(
            "const sur = 'x'.repeat(198) + '\\ud83d\\ude00' + 'y'.repeat(9);\n"
            "console.log(JSON.stringify({\n"
            " exact: opshellPlain('x'.repeat(200)),\n"
            " over: opshellPlain('x'.repeat(201)),\n"
            " far: opshellPlain('x'.repeat(5000)),\n"
            " pair: opshellPlain(sur),\n"
            " spaced: opshellPlain('x'.repeat(198) + ' \\x1b y'.repeat(9)),\n"
            " measuredAfter: opshellPlain('\\x1b'.repeat(300) + 'x'.repeat(10))"
            "}));")
        self.assertEqual(got["exact"], "x" * 200)
        self.assertEqual(got["over"], "x" * 199 + "\u2026")
        self.assertEqual(got["far"], "x" * 199 + "\u2026")
        # The cut may not leave half of a surrogate pair, nor a space
        # before the ellipsis.
        self.assertEqual(got["pair"], "x" * 198 + "\u2026")
        self.assertEqual(got["spaced"], "x" * 198 + "\u2026")
        # What is cut is what is left after the removal, not the raw text.
        self.assertEqual(got["measuredAfter"], "x" * 10)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_host_and_the_target_cannot_drive_the_terminal(self):
        for field, extra in (("host", {}), ("target", {"host": ""})):
            fields = dict(extra)
            fields[field] = self._HOSTILE
            first, _ = self._first_line(fields)
            self._assert_nothing_drives_the_terminal(
                [first], "the first line's %s" % field)
            self.assertIn("live on ok", first)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_stream_failure_cannot_drive_the_terminal(self):
        lines = self._lines(
            "els['opshell-term'] = el('opshell-term');\n"
            "globalThis.Terminal = function(){ return fakeTerm(); };\n"
            "opshellSession = 'sid';\n"
            "nextReply = {throw:%s};\n"
            "await opshellAttach({state:'live', geometry:[80,24],"
            " host:'parrot'});" % json.dumps(self._HOSTILE))
        self.assertTrue([l for l in lines if "the stream failed" in l])
        self._assert_nothing_drives_the_terminal(lines, "the stream failure")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_long_host_or_reason_cannot_push_the_sentence_off_the_line(self):
        """Nothing upstream caps either, and the part of the line that says
        what the history guard is, and how big the terminal is, comes last."""
        first, _ = self._first_line(
            {"host": "h" * 5000, "history": "weak",
             "history_detail": "r" * 5000})
        self.assertLess(len(first), 800, len(first))
        self.assertIn("\u2026", first)
        self.assertIn("may well be recorded", first)
        self.assertRegex(first, r"[0-9]+x[0-9]+, fixed for this session")

    # The cap belongs to what a note carries, not to the note: the page's
    # own sentences are longer than 200 characters, and the last of them is
    # the one that matters. Measured before this: the 502 note, 271
    # characters, ended "Anything typed since has been...".
    _DROPPED = ("Anything typed since has been dropped too, so no part of a "
                "command can arrive without the rest of it. --\x1b[0m")

    def _note_after(self, reply, keys="ls"):
        """The last note a failed batch wrote, with one more key typed while
        it was in flight."""
        return self._node(
            "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
            "holdFetch = 6;\n"
            "opshellKeys = %s;\n"
            "nextReply = %s;\n"
            "const flushing = opshellFlushKeys();\n"
            "opshellKeys += '\\r';\n"
            "await flushing;\n"
            "console.log(JSON.stringify({last: opshellTerm.lines"
            "[opshellTerm.lines.length - 1]}));"
            % (json.dumps(keys), reply))["last"]

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_502_note_arrives_whole_with_its_last_sentence(self):
        last = self._note_after(
            "{ok:false, status:502, body:{error:'the bridge could not write "
            "to the shell', detail:'sendall timed out'}}")
        self.assertGreater(len(last), 200, "the case under test is a note "
                           "longer than the old cap")
        self.assertTrue(last.endswith(self._DROPPED), last)
        self.assertNotIn("\u2026", last)
        self.assertIn("the bridge could not write to the shell -- sendall "
                      "timed out", last)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_what_a_note_carries_is_still_cut_and_the_note_is_not(self):
        """The server's reason and the exception text are the untrusted
        parts, and a long one is cut where it is interpolated -- so it
        cannot push the sentence after it off the line either."""
        for reply in ("{ok:false, status:502, body:{error:%s}}"
                      % json.dumps("e" * 5000),
                      "{throw:%s}" % json.dumps("e" * 5000)):
            last = self._note_after(reply)
            self.assertTrue(last.endswith(self._DROPPED), (reply[:30], last))
            self.assertIn("e" * 199 + "\u2026", last)
            self.assertNotIn("e" * 200, last)
            self.assertLess(len(last), 600, len(last))

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_fetch_failure_and_the_paste_notes_arrive_whole(self):
        failed = self._note_after("{throw:'socket hang up'}")
        self.assertIn("(socket hang up). Nothing was sent again -- check the "
                      "session before retyping. " + self._DROPPED, failed)
        self.assertNotIn("\u2026", failed)
        got = self._node(
            "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
            "opshellKeys = 'x'.repeat(%d);\n"
            "await opshellFlushKeys();\n"
            "console.log(JSON.stringify({last: opshellTerm.lines"
            "[opshellTerm.lines.length - 1]}));" % (256 * 1024))
        self.assertTrue(got["last"].endswith(
            "Nothing was sent. Send it in smaller pieces, or put the file on "
            "the host another way. --\x1b[0m"), got["last"])
        self.assertNotIn("\u2026", got["last"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_every_note_is_still_made_plain_without_the_cap(self):
        got = self._node(
            "opshellTerm = fakeTerm();\n"
            "opshellSay(%s + 'z'.repeat(400));\n"
            "console.log(JSON.stringify({last: opshellTerm.lines[0],"
            " clean: opshellClean('a\\x1b\\x07b ' + 'y'.repeat(300))}));"
            % json.dumps(self._HOSTILE))
        self._assert_nothing_drives_the_terminal([got["last"]], "a long note")
        self.assertIn("z" * 400, got["last"])
        self.assertEqual(got["clean"], "a b " + "y" * 300)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_what_the_shell_prints_still_reaches_the_terminal_untouched(self):
        """The one writer that is not made plain: the shell's own bytes. A
        terminal exists to act on them, and stripping them would be a shell
        that cannot show colour or move its cursor."""
        got = self._node(
            "els['opshell-term'] = el('opshell-term');\n"
            "const term = fakeTerm();\n"
            "globalThis.Terminal = function(){ return term; };\n"
            "opshellSession = 'sid';\n"
            "nextReply = {ok:true, status:200, stream:"
            " fakeStream(['\\x1b[31mred\\x1b[0m\\r\\n'])};\n"
            "await opshellAttach({state:'live', geometry:[80,24],"
            " host:'parrot'});\n"
            "console.log(JSON.stringify({lines: term.lines}));")
        self.assertIn("\x1b[31mred\x1b[0m\r\n", got["lines"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_refused_shutdown_cannot_drive_the_terminal(self):
        # The request itself fails: the message is the exception's.
        lines = self._lines(
            "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
            "nextReply = {throw:%s};\n"
            "await opshellEndSession();" % json.dumps(self._HOSTILE))
        self._assert_nothing_drives_the_terminal(lines, "the failed shutdown")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_servers_reason_for_a_refused_shutdown_cannot_drive_the_terminal(self):
        for key in ("reason", "error"):
            lines = self._lines(
                "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
                "nextReply = {ok:true, status:200, body:{%s:%s}};\n"
                "await opshellEndSession();"
                % (key, json.dumps(self._HOSTILE)))
            self._assert_nothing_drives_the_terminal(
                lines, "the server's %s" % key)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_poll_failure_cannot_drive_the_terminal(self):
        # An HTML error page from a proxy makes the JSON parse fail with
        # text from the far side in it, so this message is not the page's.
        lines = self._lines(
            "opshellAttached = true; opshellSession = 'sid';\n"
            "opshellTerm = fakeTerm();\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "nextReply = {throw:%s};\n"
            "await opshellPoll();" % json.dumps(self._HOSTILE))
        self.assertTrue([l for l in lines if "lost contact" in l])
        self._assert_nothing_drives_the_terminal(lines, "the poll failure")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_what_the_state_says_cannot_drive_the_terminal(self):
        for body in ("state:'live', channel:'unknown', reason:%s",
                     "state:'closing', channel:%s"):
            lines = self._lines(
                "opshellAttached = true; opshellSession = 'sid';\n"
                "opshellTerm = fakeTerm();\n"
                "els['opshell-body'] = el('opshell-body');\n"
                "nextReply = {ok:true, status:200, body:{host:'parrot',"
                " %s}};\n"
                "await opshellPoll();" % (body % json.dumps(self._HOSTILE)))
            self._assert_nothing_drives_the_terminal(
                lines, "the state's note (%s)" % body.split(",")[1].strip())

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_failed_key_request_cannot_drive_the_terminal(self):
        lines = self._lines(
            "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
            "opshellKeys = 'ls\\r';\n"
            "nextReply = {throw:%s};\n"
            "await opshellFlushKeys();" % json.dumps(self._HOSTILE))
        self.assertTrue([l for l in lines if "may or may not" in l])
        self._assert_nothing_drives_the_terminal(lines, "the key failure")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_refused_key_request_cannot_drive_the_terminal(self):
        # Every field the route sends, because the page joins all three.
        lines = self._lines(
            "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
            "opshellKeys = 'ls\\r';\n"
            "nextReply = {ok:false, status:409, body:{error:%(h)s,"
            " refused:%(h)s, detail:%(h)s}};\n"
            "await opshellFlushKeys();" % {"h": json.dumps(self._HOSTILE)})
        self.assertTrue([l for l in lines if "not delivered" in l])
        self._assert_nothing_drives_the_terminal(lines, "the key refusal")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_far_end_that_hangs_up_ends_the_session(self):
        # Review Focus 4's browser half: the loop's `done` exit, the
        # closing note, and the close that queues the shutdown.
        got = self._node(
            "els['opshell-term'] = el('opshell-term');\n"
            "globalThis.Terminal = function(){ return fakeTerm(); };\n"
            "opshellSession = 'sid';\n"
            "const term = fakeTerm();\n"
            "globalThis.Terminal = function(){ return term; };\n"
            "nextReply = {ok:true, status:200, stream: fakeStream(['bye'])};\n"
            "await opshellAttach({state:'live', geometry:[80,24],"
            " host:'parrot'});\n"
            "console.log(JSON.stringify({said: term.lines.join(' '),"
            " session: opshellSession,"
            " closed: posted.filter(p => p.url.endsWith('close')).length}));")
        self.assertRegex(got["said"], r"session ended")
        # And this session, which nothing resumed, is not told it replaced
        # one. `if(opshellFresh)` reduced to `if(true)` was green across
        # the whole suite: every freshly opened shell then announced "the
        # previous session ended with the page that held it", which in a
        # fresh tab is false. An invented predecessor is the same class of
        # defect as silence about a real one -- this is the direction of
        # the lie that no other test was watching.
        self.assertNotRegex(got["said"], r"(?i)new shell")
        self.assertIsNone(got["session"])
        self.assertEqual(got["closed"], 1,
                         "a finished stream did not end the session")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_stream_that_breaks_mid_session_ends_it_too(self):
        got = self._node(
            "els['opshell-term'] = el('opshell-term');\n"
            "const term = fakeTerm();\n"
            "globalThis.Terminal = function(){ return term; };\n"
            "opshellSession = 'sid';\n"
            "nextReply = {ok:true, status:200,"
            " stream: fakeStream(['hello'], 1)};\n"
            "await opshellAttach({state:'live', geometry:[80,24],"
            " host:'parrot'});\n"
            "console.log(JSON.stringify({said: term.lines.join(' '),"
            " session: opshellSession,"
            " closed: posted.filter(p => p.url.endsWith('close')).length}));")
        self.assertIn("hello", got["said"])
        self.assertIsNone(got["session"])
        self.assertEqual(got["closed"], 1)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_torn_down_view_does_not_write_into_a_disposed_terminal(self):
        # The guard inside the loop. Without it the first chunk after a
        # teardown threw a TypeError outside the try, the promise rejected
        # unhandled, and the close never ran.
        got = self._node(
            "els['opshell-term'] = el('opshell-term');\n"
            "const term = fakeTerm();\n"
            "globalThis.Terminal = function(){ return term; };\n"
            "opshellSession = 'sid';\n"
            "let reads = 0;\n"
            "nextReply = {ok:true, status:200, stream: {getReader(){"
            " return {async read(){ reads += 1;"
            " if(reads === 1){ opshellTerm = null;"
            " return {done:false, value:'x'}; }"
            " return {done:true}; }}; }}};\n"
            "await opshellAttach({state:'live', geometry:[80,24],"
            " host:'parrot'});\n"
            "console.log(JSON.stringify({reads, wrote: term.lines.length}));")
        # It stops at the first chunk after the terminal went, rather than
        # throwing or writing into a detached element.
        self.assertEqual(got["reads"], 1)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_stream_that_cannot_be_reached_ends_the_session(self):
        # Found by mutation: the `catch` arm of the stream fetch had no
        # test, so removing its `opshellEndSession` left everything green
        # -- and that is the arm a dropped connection takes, which is
        # commoner than a 409.
        got = self._node(
            "els['opshell-term'] = el('opshell-term');\n"
            "globalThis.Terminal = function(){ return fakeTerm(); };\n"
            "opshellSession = 'sid';\n"
            "nextReply = {throw:'ECONNREFUSED'};\n"
            "await opshellAttach({state:'live', geometry:[80,24],"
            " host:'parrot'});\n"
            "console.log(JSON.stringify({session: opshellSession,"
            " attached: opshellAttached,"
            " closed: posted.filter(p => p.url.endsWith('close')).length}));")
        self.assertIsNone(got["session"])
        self.assertFalse(got["attached"])
        self.assertEqual(got["closed"], 1)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_stream_the_port_refuses_ends_the_session(self):
        """The root of C1's "for ever".

        `opshellAttach` wrote "[the shell port refused this session]" and
        returned with `opshellAttached` and `opshellSession` still set and
        no reader loop to clear them. Every keystroke after that got 404,
        and the claim was held until the lapse four minutes later.
        """
        got = self._node(
            "els['opshell-term'] = el('opshell-term');\n"
            "globalThis.Terminal = function(){ return fakeTerm(); };\n"
            "opshellSession = 'sid';\n"
            "nextReply = {ok:false, status:409, body:{}};\n"
            "await opshellAttach({state:'live', geometry:[80,24],"
            " host:'parrot'});\n"
            "console.log(JSON.stringify({session: opshellSession,"
            " attached: opshellAttached,"
            " closed: posted.filter(p => p.url.endsWith('close')).length}));")
        self.assertIsNone(got["session"])
        self.assertFalse(got["attached"])
        self.assertEqual(got["closed"], 1,
                         "a refused stream left the claim held")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_every_way_a_stop_can_be_refused_reaches_the_operator(self):
        """C2 of the third review, and the same class a third time.

        `opshellEndSession` awaited the close and never looked at the
        answer, so all three refusals were silent: a rejected request, a
        `reason` from `may_stop`, and another view holding the session --
        while the paragraph beside the button promised the reason would
        come back.
        """
        cases = (
            ("{throw:'socket hang up'}", r"(?i)hang up"),
            ("{ok:true, status:200, body:{reason:'3 live socks sessions "
             "ride this channel'}}", r"(?i)socks session"),
            ("{ok:true, status:200, body:{reason:'another view is holding "
             "this channel'}}", r"(?i)another view"),
            ("{ok:false, status:409, body:{error:'the ownership record "
             "could not be read'}}", r"(?i)ownership record"),
        )
        for reply, expected in cases:
            got = self._node(
                "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
                "els['opshell-body'] = el('opshell-body');\n"
                "nextReply = " + reply + ";\n"
                "await opshellEndSession();\n"
                "console.log(JSON.stringify({said: opshellTerm.lines.join(' '),"
                " shown: els['opshell-body'].innerHTML}));")
            self.assertRegex(got["said"] + " " + got["shown"], expected,
                             reply)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_stop_that_was_queued_is_confirmed_rather_than_silent(self):
        # Success has to be distinguishable from the silence that used to
        # mean failure.
        got = self._node(
            "opshellSession = 'sid'; opshellTerm = fakeTerm();\n"
            "nextReply = {ok:true, status:200, body:{state:'closing'}};\n"
            "await opshellEndSession();\n"
            "console.log(JSON.stringify({said: opshellTerm.lines.join(' ')}));")
        self.assertRegex(got["said"], r"(?i)queued|next check-in")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_keystrokes_do_not_cross_from_one_session_into_the_next(self):
        # Measured by the reviewer: "more" typed into a session that died,
        # then "ls" in the next one, posted as "morels". Injected input
        # into a root shell on the operator's own device.
        got = self._node(
            "opshellSession = 'first'; opshellKeys = 'more';\n"
            "await opshellEndSession();\n"
            "opshellSession = 'second'; opshellKeys += 'ls';\n"
            "posted.length = 0;\n"
            "await opshellFlushKeys();\n"
            "const sent = posted.filter(p => p.url.endsWith('keys'))"
            ".map(p => Buffer.from(JSON.parse(p.body).data,'base64')"
            ".toString());\n"
            "console.log(JSON.stringify({sent}));")
        self.assertEqual(got["sent"], ["ls"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_poll_keeps_beating_on_the_path_that_usually_runs(self):
        """Critical 2 of the fourth review: the line nothing defended.

        `claims.beat` has one caller, reached only by this poll, and the
        poll re-enters itself from two places: the failure arm, which had a
        test, and the success arm, which had none. Deleting the success
        arm's `setTimeout` left all 231 tests green -- and then the claim
        goes silent, the 240 second margin retires it, and the sweep stops
        a channel with an operator sitting in the shell. The whole lapse
        argument rests on this one line.

        `runTimers` existed and nothing called it, which is why the
        multi-poll properties were all unproven.
        """
        got = self._node(
            "els['opshell-body'] = el('opshell-body');\n"
            "opshellSession = 'sid';\n"
            "nextReply = {ok:true, status:200, body:{state:'waiting',"
            " channel:'closed', host:'parrot', expected_checkin:12}};\n"
            "await opshellPoll();\n"
            "const first = posted.length;\n"
            "await runTimers(1);\n"
            "await runTimers(1);\n"
            "const urls = posted.filter(p => p.url.includes('/state'))"
            ".map(p => p.url);\n"
            "console.log(JSON.stringify({first, polls: urls.length,"
            " carriesSession: urls.every(u => u.includes('session=')),"
            " scheduledEach: scheduled}));")
        self.assertEqual(got["first"], 1)
        self.assertEqual(got["polls"], 3,
                         "the poll did not keep beating: %d requests"
                         % got["polls"])
        self.assertTrue(got["carriesSession"],
                        "a poll without the session id is not a heartbeat")
        # One timer per poll, not two: a second schedule per turn doubles
        # the loop every time round.
        self.assertEqual(got["scheduledEach"], [2000, 2000, 2000])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_stalled_poll_becomes_a_failure_and_the_beat_goes_on(self):
        """What the deadline actually does, not that it is present.

        The previous test asserted the number was recorded and under 30
        seconds -- `AbortSignal.timeout(29999)` would have passed it. The
        harness now fires the signal, so the stall can be driven: a proxy
        that accepts and never answers, which is the case this deadline
        exists for and the one that produces no rejection on its own.
        """
        got = self._node(
            "els['opshell-body'] = el('opshell-body');\n"
            "opshellSession = 'sid';\n"
            "holdFetch = 8;\n"
            "const polling = opshellPoll();\n"
            "fireTimeouts();\n"
            "await polling;\n"
            "console.log(JSON.stringify({shown: els['opshell-body'].innerHTML,"
            " scheduled, deadline: posted[0] && posted[0].timeout}));")
        self.assertRegex(got["shown"], r"(?i)abort")
        self.assertEqual(got["scheduled"], [2000],
                         "a stalled poll did not reschedule itself")
        self.assertEqual(got["deadline"], 8000)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_an_older_browser_loses_the_deadline_and_not_the_heartbeat(self):
        """`AbortSignal.timeout` is Safari 16; this interface is Safari 14.1.

        Measured against the rest of the page: 164 uses of optional
        chaining and the Clipboard API in its JavaScript, flexbox `gap`
        in its CSS -- which is the 14.1 -- and nothing newer than that,
        until I added a 2022 feature and called it unconditionally. On an older browser that throws a TypeError inside
        the poll, which kills the heartbeat: the exact failure the deadline
        was added to prevent, arriving by a different door.

        So it is used when it exists and skipped when it does not. A poll
        with no deadline is what the view had last week; a poll that throws
        is worse than both.
        """
        got = self._node(
            "delete AbortSignal.timeout;\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "opshellSession = 'sid';\n"
            "nextReply = {ok:true, status:200, body:{state:'waiting',"
            " channel:'closed', host:'parrot', expected_checkin:9}};\n"
            "await opshellPoll();\n"
            "await runTimers(1);\n"
            "console.log(JSON.stringify({polls: posted.filter("
            "p => p.url.includes('/state')).length, scheduled,"
            " deadlines: posted.map(p => p.timeout),"
            " shown: els['opshell-body'].innerHTML.slice(0, 40)}));")
        self.assertEqual(got["polls"], 2,
                         "the heartbeat stopped without AbortSignal.timeout")
        self.assertEqual(got["scheduled"], [2000, 2000])
        self.assertEqual(got["deadlines"], [None, None])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_one_failed_poll_does_not_end_the_heartbeat(self):
        """The grace argument rests on the poll being reliable.

        The catch returned without rescheduling, so one network blip -- or
        a proxy's HTML 502, which makes `api()` reject on the JSON parse --
        stopped the heartbeat for good. The claim then lapsed and a session
        the operator was sitting in was stopped on the device.
        """
        got = self._node(
            "els['opshell-body'] = el('opshell-body');\n"
            "nextReply = {throw:'network'};\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({scheduled,"
            " shown: els['opshell-body'].innerHTML}));")
        self.assertEqual(got["scheduled"], [2000],
                         "the poll did not reschedule itself after a failure")
        self.assertIn("network", got["shown"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_poll_has_a_deadline_so_a_stall_becomes_a_failure(self):
        # I1 of the third review. The 240 s margin rests on the poll
        # running, and nothing bounded a single poll: a proxy that accepts
        # and never answers produces no rejection at all, so the heartbeat
        # stopped silently and the claim lapsed under a live root shell.
        got = self._node(
            "els['opshell-body'] = el('opshell-body');\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({timeouts: posted.map("
            "p => p.timeout)}));")
        self.assertTrue(any(got["timeouts"]),
                        "the state poll has no deadline")
        for t in got["timeouts"]:
            if t:
                self.assertLessEqual(t, 30000)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_what_the_state_says_reaches_an_operator_in_the_terminal(self):
        # I2. While attached the body is never re-rendered, so `unknown`,
        # `closing` and the overdue reason were invisible to exactly the
        # person who needed them.
        got = self._node(
            "opshellAttached = true; opshellSession = 'sid';\n"
            "opshellTerm = fakeTerm();\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "nextReply = {ok:true, status:200, body:{state:'live',"
            " channel:'unknown', host:'parrot', reason:'clumsy-raccoon has"
            " not checked in for 7200 seconds'}};\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({said: opshellTerm.lines.join(' ')}));")
        self.assertRegex(got["said"], r"(?i)has not checked in|unknown")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_same_trouble_is_not_announced_every_two_seconds(self):
        # I5. A sustained outage wrote a line every poll: 30 polls, 30
        # lines, scrolling the operator's own work off the screen exactly
        # when they needed to read it.
        got = self._node(
            "opshellAttached = true; opshellSession = 'sid';\n"
            "opshellTerm = fakeTerm();\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "nextReply = {throw:'network down'};\n"
            "for(let i = 0; i < 6; i++) await opshellPoll();\n"
            "const before = opshellTerm.lines.length;\n"
            "nextReply = {ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot'}};\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({during: before,"
            " after: opshellTerm.lines.length,"
            " said: opshellTerm.lines.join(' ')}));")
        self.assertEqual(got["during"], 1,
                         "the outage was announced %d times" % got["during"])
        # And recovery is worth one line, or the operator is left reading
        # the last complaint.
        self.assertEqual(got["after"], 2)
        self.assertRegex(got["said"], r"(?i)again|restored|back")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_claim_that_lands_after_the_view_is_gone_is_given_back(self):
        # I6. Teardown ran first, found no session, posted nothing -- and
        # the reply then set `opshellSession` on a view that no longer
        # existed, so the channel came down only via the lapse.
        got = self._node(
            "els['opshell-body'] = el('opshell-body');\n"
            "holdFetch = 4;\n"
            "nextReply = {ok:true, status:200, body:{session:'late'}};\n"
            "const opening = opshellOpen();\n"
            "await opshellTeardown(els['opshell-body']);\n"
            "delete els['opshell-body'];\n"
            "await opening;\n"
            "console.log(JSON.stringify({session: opshellSession,"
            " urls: posted.map(p => p.url)}));")
        self.assertIsNone(got["session"])
        self.assertEqual(got["urls"],
                         ["/api/opshell/open", "/api/opshell/close"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_second_session_is_warned_about_the_same_outage(self):
        """I4 of the fourth review: two variables that outlive a session.

        `opshellKeys` is cleared when a session ends, for exactly this
        reason -- state leaking into the next one -- and the two variables
        added for "say it once per transition" were left behind. Measured:
        session A warns once, teardown, session B hits the identical
        outage and is warned **zero** times, while the claim lapses under
        an operator sitting in a root shell. And the mirror: a fresh panel
        announcing "the team server is answering again" for trouble it
        never saw.
        """
        got = self._node(
            "els['opshell-body'] = el('opshell-body');\n"
            "opshellAttached = true; opshellSession = 'a';\n"
            "opshellTerm = fakeTerm();\n"
            "nextReply = {throw:'Failed to fetch'};\n"
            "await opshellPoll();\n"
            "const inA = opshellTerm.lines.length;\n"
            "await opshellTeardown(els['opshell-body']);\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "opshellAttached = true; opshellSession = 'b';\n"
            "opshellTerm = fakeTerm();\n"
            "await opshellPoll();\n"
            "const inB = opshellTerm.lines.length;\n"
            "opshellTerm = fakeTerm();\n"
            "nextReply = {ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot'}};\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({inA, inB,"
            " recovered: opshellTerm.lines.join(' ')}));")
        self.assertEqual(got["inA"], 1)
        self.assertEqual(got["inB"], 1,
                         "the second session was warned %d times"
                         % got["inB"])
        self.assertRegex(got["recovered"], r"(?i)answering again")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_fresh_panel_does_not_announce_a_recovery_it_never_missed(self):
        got = self._node(
            "els['opshell-body'] = el('opshell-body');\n"
            "opshellAttached = true; opshellSession = 'a';\n"
            "opshellTerm = fakeTerm();\n"
            "nextReply = {throw:'down'};\n"
            "await opshellPoll();\n"
            "await opshellTeardown(els['opshell-body']);\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "opshellAttached = true; opshellSession = 'b';\n"
            "opshellTerm = fakeTerm();\n"
            "nextReply = {ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot'}};\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({said: opshellTerm.lines.join(' ')}));")
        self.assertNotRegex(got["said"], r"(?i)answering again")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_failed_poll_does_not_destroy_a_live_terminal(self):
        # The same line replaced `innerHTML` while the terminal was
        # attached, so a blip during a session took the terminal's DOM node
        # with it -- and the stream then wrote into a detached element.
        got = self._node(
            "opshellAttached = true;\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "els['opshell-body'].innerHTML = '<div id=\"opshell-term\"></div>';\n"
            "globalThis.setTimeout = () => 7;\n"
            "opshellTerm = fakeTerm();\n"
            "nextReply = {throw:'blip'};\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({still: els['opshell-body'].innerHTML}));")
        self.assertIn("opshell-term", got["still"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_closed_state_says_where_the_transcript_is(self):
        # I2. The design: Closed "says what remains: the session's
        # duration, and the transcript's path when recording was on".
        # `transcript_dir` was computed, shipped in every state body, and
        # read by nothing -- so after a recorded session the operator was
        # given no way to find the one artifact it left.
        got = self._node(
            "const on = opshellRender({state:'closed', channel:'closed',"
            " host:'parrot', recording:true, geometry:[120,40],"
            " transcript_dir:'/opt/raccoon/transcripts', duration:92});\n"
            "const off = opshellRender({state:'closed', channel:'closed',"
            " host:'parrot', recording:false, geometry:[120,40],"
            " transcript_dir:'/opt/raccoon/transcripts'});\n"
            "console.log(JSON.stringify({on, off}));")
        self.assertIn("/opt/raccoon/transcripts", got["on"])
        self.assertIn("92", got["on"])
        # Not when nothing was recorded: a path with no file at the end of
        # it is worse than no path.
        self.assertNotIn("/opt/raccoon/transcripts", got["off"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_only_one_keystroke_post_is_ever_in_flight(self):
        """I5, and the property the first version of this test missed.

        One POST per keystroke over up to six parallel connections can
        complete out of order, and in a terminal that means transposed
        characters -- which the operator blames on the link rather than on
        this. So the guarantee is "never two at once", and it has to be
        measured while requests are slow: with a stub that resolves
        immediately, order holds whatever the code does, and removing the
        serialisation left the first version of this test green. Measured
        by mutation, not assumed.
        """
        got = self._node(
            "holdFetch = 6; opshellSession = 'sid'; opshellKeys = '';\n"
            "opshellKeys += 'a'; const a = opshellFlushKeys();\n"
            "opshellKeys += 'b'; const b = opshellFlushKeys();\n"
            "opshellKeys += 'c'; const c = opshellFlushKeys();\n"
            "await Promise.all([a, b, c]);\n"
            "await opshellFlushKeys();\n"
            "const bodies = posted.map(p => JSON.parse(p.body).data);\n"
            "console.log(JSON.stringify({urls: posted.map(p => p.url),"
            " max: maxInFlight,"
            " text: bodies.map(x => Buffer.from(x,'base64').toString())}));")
        self.assertTrue(all(u == "/api/opshell/keys" for u in got["urls"]))
        self.assertEqual(got["max"], 1,
                         "%d keystroke posts were in flight at once; two can "
                         "complete out of order" % got["max"])
        # Every keystroke arrives, in order, and in fewer posts than
        # keystrokes: the point of coalescing.
        self.assertEqual("".join(got["text"]), "abc")
        self.assertLess(len(got["text"]), 3)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_card_sits_in_the_content_column_and_not_inside_content(self):
        # `renderAgentView` writes `#content.innerHTML` on every agent
        # click, and this design wants the agent list clickable. A card
        # that lived inside `.content` would lose its terminal to a click.
        got = self._node(
            "els['main'] = el('main'); els['content'] = el('content');\n"
            "els['main'].appendChild(els['content']);\n"
            "els['content'].innerHTML = '<div class=\"empty\"></div>';\n"
            "await showOperatorShell();\n"
            "const card = els['main'].children[els['main'].children.length-1];\n"
            "console.log(JSON.stringify({content: els['content'].innerHTML,"
            " bodyExists: !!document.getElementById('opshell-body'),"
            " hidden: els['content'].style.display,"
            " inMain: els['main'].children.length,"
            " isCard: card.classList.contains('opshell-card'),"
            " bodyInCard: !!document.getElementById('opshell-body') &&"
            " document.getElementById('opshell-body').parentNode !== null,"
            " chrome: card.children[0] && card.children[0].innerHTML}));")
        # The controls are in the card, not just in the function that
        # makes them: a card with its chrome unwritten or unappended has
        # no way to close or minimise, and the grep of `opshellChrome`
        # cannot see that.
        self.assertIn("opshellClose(", got["chrome"] or "")
        self.assertIn("opshellMinimise(", got["chrome"] or "")
        self.assertIn("empty", got["content"])
        self.assertTrue(got["bodyExists"])
        self.assertEqual(got["hidden"], "none",
                         "two flex:1 siblings would split the column")
        self.assertEqual(got["inMain"], 2)
        self.assertTrue(got["isCard"])
        self.assertTrue(got["bodyInCard"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_cross_ends_the_session_and_takes_the_card_down(self):
        got = self._node(
            "opshellSession = 'sid'; els['opshell-card'] = el('opshell-card');\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "els['content'] = el('content');\n"
            "els['content'].style.display = 'none';\n"
            "nextReply = {ok:true, status:200, body:{state:'closing'}};\n"
            "await opshellClose();\n"
            "console.log(JSON.stringify({urls: posted.map(p => p.url),"
            " session: opshellSession, removed,"
            " shown: els['content'].style.display}));")
        self.assertEqual(got["urls"], ["/api/opshell/close"])
        self.assertIsNone(got["session"])
        self.assertIn("opshell-card", got["removed"])
        self.assertEqual(got["shown"], "",
                         "the content column stayed hidden with no card "
                         "over it")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_an_agent_click_does_not_detach_a_live_terminal(self):
        # The condition the layer exists for, driven rather than reasoned
        # about: `renderAgentView` writes `#content.innerHTML`, and the
        # card is a sibling, so the terminal's host must survive.
        got = self._node(
            "els['main'] = el('main'); els['content'] = el('content');\n"
            "els['main'].appendChild(els['content']);\n"
            "await showOperatorShell();\n"
            "opshellTerm = fakeTerm();\n"
            "els['content'].innerHTML = '<div class=\"pcard\">agent</div>';\n"
            "console.log(JSON.stringify({"
            " host: !!document.getElementById('opshell-term') ||"
            " !!document.getElementById('opshell-body'),"
            " content: els['content'].innerHTML}));")
        self.assertTrue(got["host"],
                        "an agent click took the card's body with it")
        self.assertIn("pcard", got["content"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_button_pressed_twice_does_not_draw_a_second_terminal(self):
        # Not modal any more: the header button stays reachable while the
        # card is up, and two cards would be two `#opshell-body`, the second
        # unreachable by id and both polling the one session.
        got = self._node(
            "els['main'] = el('main'); els['content'] = el('content');\n"
            "els['main'].appendChild(els['content']);\n"
            "await showOperatorShell();\n"
            "await showOperatorShell();\n"
            "console.log(JSON.stringify({inMain: els['main'].children.length,"
            " cards: els['main'].children.filter(c =>"
            " c.classList.contains('opshell-card')).length}));")
        self.assertEqual(got["cards"], 1)
        self.assertEqual(got["inMain"], 2)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_taking_the_card_down_gives_the_column_back_wherever_it_is_called_from(self):
        # The invariant is "no card, so a visible column", and it lives where
        # the card comes down. Driven through `opshellTeardown` itself and
        # not through the cross, so a restore that sits only in the caller
        # does not pass.
        got = self._node(
            "els['content'] = el('content');\n"
            "els['main'] = el('main'); els['main'].appendChild(els['content']);\n"
            "await showOperatorShell();\n"
            "const hidden = els['content'].style.display;\n"
            "await opshellTeardown(document.getElementById('opshell-card'));\n"
            "console.log(JSON.stringify({hidden,"
            " shown: els['content'].style.display,"
            " card: document.getElementById('opshell-card')}));")
        self.assertEqual(got["hidden"], "none")
        self.assertEqual(got["shown"], "")
        self.assertIsNone(got["card"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_taking_the_card_down_takes_the_park_with_it(self):
        # The other half of the invariant the test above pins: no card
        # without a visible column, and no park without a card. Nothing
        # reaches teardown while parked today -- the ✕ is inside the card
        # and a hidden card has no clickable buttons -- so this is here to
        # keep it true for the next caller, which is how the parked flag
        # would otherwise come to say "parked" over the next card drawn.
        got = self._node(
            "opshellSession = 'sid';\n"
            "els['content'] = el('content');\n"
            "els['main'] = el('main'); els['main'].appendChild(els['content']);\n"
            "els['sidebar'] = el('sidebar');\n"
            "await showOperatorShell();\n"
            "opshellMinimise();\n"
            "const parked = els['sidebar'].children.length;\n"
            "await opshellTeardown(document.getElementById('opshell-card'));\n"
            "console.log(JSON.stringify({parked,"
            " minimised: opshellMinimised,"
            " left: els['sidebar'].children.length,"
            " shown: els['content'].style.display,"
            " card: document.getElementById('opshell-card')}));")
        self.assertEqual(got["parked"], 1)
        self.assertFalse(got["minimised"])
        self.assertEqual(got["left"], 0, "a parked card outlived its card")
        self.assertEqual(got["shown"], "")
        self.assertIsNone(got["card"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_card_names_the_device_once_the_state_does(self):
        # The header row's job is to say which device this is. Until the
        # state names one it says what the card is; the buttons beside the
        # title are not touched. The harness does not parse markup, so the
        # title is registered by hand, as `#opshell-body` could not be.
        #
        # And a tick that changes nothing writes nothing: assigning
        # `textContent` replaces the node's text even when the string is
        # identical, which in a browser drops a selection the operator made
        # in the header -- every two seconds. What the harness can show is
        # the write itself, through what a write destroys.
        got = self._node(
            "els['opshell-body'] = el('opshell-body');\n"
            "els['opshell-title'] = el('opshell-title');\n"
            "els['opshell-title'].classList.add('opshell-title');\n"
            "els['opshell-title'].textContent = 'Operator Shell';\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot', sessions:0}},"
            " {ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot', sessions:0}},"
            " {ok:true, status:200, body:{state:'idle', channel:'closed'}}];\n"
            "await opshellPoll();\n"
            "const named = els['opshell-title'].textContent;\n"
            "const mark = document.createElement('b');\n"
            "els['opshell-title'].appendChild(mark);\n"
            "await opshellPoll();\n"
            "const unchanged = [els['opshell-title'].textContent,"
            " mark.parentNode !== null];\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({named, unchanged,"
            " after: els['opshell-title'].textContent}));")
        self.assertEqual(got["named"], "parrot")
        self.assertEqual(got["unchanged"], ["parrot", True],
                         "the title was rewritten with the string it "
                         "already had")
        self.assertEqual(got["after"], "Operator Shell")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_page_without_its_mount_point_gets_no_card_and_no_throw(self):
        # `opshellResume` runs in the startup branch beside the agent
        # refresh timer, so a throw here is a dead page -- no device list,
        # no refresh -- and not merely a shell that failed to open. It can
        # only happen if the page's own markup changed, which is why the
        # console is told rather than the operator left with nothing.
        for setup, why in (
                ("", "no .main"),
                ("els['main'] = el('main');\n", "no #content")):
            got = self._node(
                "const warned = []; console.warn = m => warned.push(String(m));\n"
                + setup +
                "let threw = null;\n"
                "try { await showOperatorShell(); } catch(e) { threw = String(e); }\n"
                "console.log(JSON.stringify({threw, warned,"
                " card: !!document.getElementById('opshell-card'),"
                " body: !!document.getElementById('opshell-body'),"
                " polled: posted.length}));")
            self.assertIsNone(got["threw"], why)
            self.assertFalse(got["card"], why)
            self.assertFalse(got["body"], why)
            self.assertEqual(got["polled"], 0, why)
            self.assertEqual(len(got["warned"]), 1, why)
            self.assertIn("Operator Shell", got["warned"][0])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_minimising_keeps_the_body_so_the_heartbeat_keeps_beating(self):
        """`opshellPoll` returns when `#opshell-body` is missing, and that
        poll is the claim's heartbeat. Taking the card apart would let the
        240-second lapse fire under a parked session."""
        got = self._node(
            "opshellSession = 'sid';\n"
            "els['opshell-card'] = el('opshell-card');\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "els['sidebar'] = el('sidebar'); els['content'] = el('content');\n"
            "els['content'].style.display = 'none';\n"
            "opshellMinimise();\n"
            "nextReply = {ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot'}};\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({minimised: opshellMinimised,"
            " hidden: els['opshell-card'].style.display,"
            " column: els['content'].style.display,"
            " remembered: sessionStorage.getItem(opshellStore + '_min'),"
            " docked: els['sidebar'].children[0].classList"
            ".contains('opshell-dock'),"
            " polls: posted.filter(p => p.url.includes('/state')).length,"
            " carries: posted[0] && posted[0].url.includes('session=')}));")
        self.assertTrue(got["minimised"])
        self.assertEqual(got["hidden"], "none")
        self.assertEqual(got["column"], "",
                         "a parked shell left the content column blank")
        self.assertEqual(got["polls"], 1)
        self.assertTrue(got["carries"])
        # The park's half of the reload memory: `_min` is written here and
        # only read in `opshellResume`, so the resume's test -- which
        # plants the key by hand -- cannot see this line go.
        self.assertEqual(got["remembered"], "1")
        # And the tray carries its class, or `.opshell-dock{flex:none}`
        # never applies and `.agent-list`'s `flex:1` squeezes it.
        self.assertTrue(got["docked"], "the dock has no class to style it")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_reload_comes_back_parked_and_as_one_card(self):
        """Review Focus 1."""
        got = self._node(
            "sessionStorage.setItem(opshellStore, 'kept');\n"
            "sessionStorage.setItem(opshellStore + '_min', '1');\n"
            "els['main'] = el('main');\n"
            "els['sidebar'] = el('sidebar'); els['content'] = el('content');\n"
            "els['main'].appendChild(els['content']);\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot', sessions:1}}];\n"
            "await opshellResume();\n"
            "console.log(JSON.stringify({minimised: opshellMinimised,"
            " parked: els['sidebar'].children.length,"
            " cards: els['main'].children.filter(c =>"
            " c.classList.contains('opshell-card')).length}));")
        self.assertTrue(got["minimised"])
        self.assertEqual(got["parked"], 1)
        self.assertEqual(got["cards"], 1, "a reload drew two cards")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_session_that_ended_while_parked_says_so(self):
        got = self._node(
            "opshellLast = {duration: 92};\n"
            "const html = opshellParked({state:'closed', channel:'closed',"
            " host:'parrot'});\n"
            "console.log(JSON.stringify({html}));")
        self.assertRegex(got["html"], r"(?i)session ended")
        self.assertIn("92", got["html"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_parked_card_does_not_claim_an_end_another_tab_refused(self):
        """Review Focus 4.

        Two tabs are two claims. The other tab's close answers "not the
        last", the channel stays up, and this parked card must keep saying
        the channel is open rather than announcing an end that did not
        happen.
        """
        got = self._node(
            "opshellLast = null;\n"
            "const html = opshellParked({state:'live', channel:'open',"
            " host:'parrot', reason:'another view is holding this channel'});\n"
            "console.log(JSON.stringify({html}));")
        self.assertNotRegex(got["html"], r"(?i)session ended")
        self.assertRegex(got["html"], r"(?i)open")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_header_glyph_restores_a_parked_card(self):
        """[added] `showOperatorShell` returns when `#opshell-card` exists,
        and a parked card exists. Without this the operator presses the
        glyph and nothing happens."""
        got = self._node(
            "opshellSession = 'sid';\n"
            "els['main'] = el('main'); els['content'] = el('content');\n"
            "els['sidebar'] = el('sidebar');\n"
            "els['main'].appendChild(els['content']);\n"
            "await showOperatorShell();\n"
            "opshellMinimise();\n"
            "const parkedAfterMin = els['sidebar'].children.length;\n"
            "await showOperatorShell();\n"
            "console.log(JSON.stringify({parkedAfterMin,"
            " minimised: opshellMinimised,"
            " remembered: sessionStorage.getItem(opshellStore + '_min'),"
            " card: document.getElementById('opshell-card').style.display,"
            " column: els['content'].style.display,"
            " parked: els['sidebar'].children.length,"
            " cards: els['main'].children.filter(c =>"
            " c.classList.contains('opshell-card')).length}));")
        self.assertEqual(got["parkedAfterMin"], 1)
        self.assertFalse(got["minimised"], "the glyph did not restore")
        self.assertEqual(got["card"], "")
        self.assertEqual(got["column"], "none")
        self.assertEqual(got["parked"], 0, "the parked card stayed behind")
        self.assertEqual(got["cards"], 1)
        # The restore's half of the reload memory. Without it a reload
        # after a restore comes back parked over the operator's work.
        self.assertIsNone(got["remembered"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_parked_card_survives_the_agent_list_being_rebuilt(self):
        """[added] `refreshAgents` assigns `#agent-list.innerHTML` every
        three seconds. That is the reason the parked card goes after the
        list rather than inside it, and the harness can now drive it
        instead of leaving it to be argued about."""
        got = self._node(
            "opshellSession = 'sid';\n"
            "els['opshell-card'] = el('opshell-card');\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "els['sidebar'] = el('sidebar');\n"
            "els['agent-list'] = el('agent-list');\n"
            "els['sidebar'].appendChild(els['agent-list']);\n"
            "els['content'] = el('content');\n"
            "opshellMinimise();\n"
            "const before = els['sidebar'].children.length;\n"
            "els['agent-list'].innerHTML = '<div class=\"agent-card\">a</div>';\n"
            "console.log(JSON.stringify({before,"
            " after: els['sidebar'].children.length,"
            " inList: els['agent-list'].children.length}));")
        self.assertEqual(got["before"], 2, "list plus parked card")
        self.assertEqual(got["after"], 2,
                         "the agent list's rebuild took the parked card")
        self.assertEqual(got["inList"], 0)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_parked_card_keeps_telling_the_truth_about_the_channel(self):
        """[added] The parked label is the only thing on screen while the
        card is hidden. A label written once and never refreshed would go
        on saying `open` after the channel dropped -- the lying interface
        this whole feature exists to avoid."""
        got = self._node(
            "opshellSession = 'sid';\n"
            "els['opshell-card'] = el('opshell-card');\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "els['sidebar'] = el('sidebar'); els['content'] = el('content');\n"
            "opshellMinimise();\n"
            "const parked = els['sidebar'].children[0];\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot'}},"
            " {ok:true, status:200, body:{state:'live',"
            " channel:'closed', host:'parrot'}}];\n"
            "await opshellPoll();\n"
            "const first = parked.innerHTML;\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({first, second: parked.innerHTML}));")
        self.assertRegex(got["first"], r"(?i)open")
        self.assertNotEqual(got["first"], got["second"],
                            "the parked label never refreshed")
        self.assertNotRegex(got["second"], r"(?i)\bopen\b")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_session_that_ended_before_the_server_caught_up_says_so_too(self):
        # The other half of Review Focus 4, and the one a mutation walked
        # through: keying the parked label off the *state* instead of off
        # `opshellLast` survives both tests above, because the poll only
        # ever merges `closed` when `opshellLast` is set. It is wrong the
        # moment `exit` ends a parked session -- the stop is queued and the
        # server goes on reporting the channel open until the next
        # check-in, which is minutes away -- and the parked card would
        # spend those minutes saying the shell is there.
        got = self._node(
            "opshellLast = {duration: 7};\n"
            "const html = opshellParked({state:'live', channel:'open',"
            " host:'parrot'});\n"
            "console.log(JSON.stringify({html}));")
        self.assertRegex(got["html"], r"(?i)session ended")
        self.assertIn("7", got["html"])
        self.assertNotRegex(got["html"], r"(?i)channel open")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_card_the_operator_left_open_does_not_come_back_parked(self):
        # The minimised flag is remembered beside the session id, so it
        # dies with it. A session that ended while parked leaves the flag
        # behind: `opshellResume` then finds no id, draws nothing and never
        # reaches it, so the only thing that can clear it is the next
        # session that starts -- and without that, the next reload parks a
        # card the operator was working in.
        got = self._node(
            "sessionStorage.setItem(opshellStore + '_min', '1');\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "els['opshell-agent'] = el('opshell-agent');\n"
            "els['opshell-agent'].value = 'parrot';\n"
            "nextReply = {ok:true, status:200, body:{session:'new-one'}};\n"
            "await opshellOpen();\n"
            "const stale = sessionStorage.getItem(opshellStore + '_min');\n"
            "els['main'] = el('main'); els['content'] = el('content');\n"
            "els['sidebar'] = el('sidebar');\n"
            "els['main'].appendChild(els['content']);\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot', sessions:1}}];\n"
            "await opshellResume();\n"
            "console.log(JSON.stringify({stale, session: opshellSession,"
            " minimised: opshellMinimised,"
            " parked: els['sidebar'].children.length}));")
        self.assertIsNone(got["stale"])
        self.assertEqual(got["session"], "new-one")
        self.assertFalse(got["minimised"],
                         "a reload parked a card the operator left open")
        self.assertEqual(got["parked"], 0)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_session_that_ends_while_parked_says_so_without_waiting(self):
        # The parked label is the only thing on screen while the card is
        # hidden, and `exit` lands between two ticks: waiting for the next
        # poll leaves "channel open" standing over a shell that is gone,
        # for up to two seconds, and the ✕ that dismisses the remnant
        # arrives that late too. No timer is run here, so every request is
        # one this test asked for.
        #
        # The tick after that end is driven as well, because this write
        # has to leave the poll's memory of the label in step: a remnant
        # the poll believes it has not written yet is a remnant rewritten
        # on the next tick, with the two buttons in it destroyed -- the
        # defect the poll's guard exists to prevent, by another door.
        got = self._node(
            "opshellSession = 'sid';\n"
            "opshellStarted = Date.now() - 92000;\n"
            "els['main'] = el('main'); els['content'] = el('content');\n"
            "els['sidebar'] = el('sidebar');\n"
            "els['main'].appendChild(els['content']);\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot'}},"
            " {ok:true, status:200, body:{}},"
            " {ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot'}}];\n"
            "await showOperatorShell();\n"
            "opshellMinimise();\n"
            "const parked = els['sidebar'].children[0];\n"
            "const before = parked.innerHTML;\n"
            "await opshellEndSession();\n"
            "const after = parked.innerHTML;\n"
            "const mark = document.createElement('b');\n"
            "parked.appendChild(mark);\n"
            "const writes = parked.htmlWrites.length;\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({before, after,"
            " writes, later: parked.htmlWrites.length,"
            " kept: mark.parentNode !== null,"
            " urls: posted.map(p => p.url.split('?')[0])}));")
        self.assertRegex(got["before"], r"(?i)channel open")
        self.assertRegex(got["after"], r"(?i)session ended")
        self.assertIn("92", got["after"])
        # The remnant still names the device its session ran on.
        self.assertIn("parrot", got["after"])
        # And the ✕ arrives with the end, never over a live session: a
        # dismiss beside a running shell would end it in one press from
        # the sidebar, with none of the card's sentence about what that
        # queues.
        self.assertNotIn("opshellClose(", got["before"])
        self.assertIn("opshellClose(", got["after"])
        # The tick after the end says the same thing, so it writes
        # nothing and the remnant's buttons stay where they were.
        self.assertEqual(got["later"], got["writes"],
                         "the tick after the end rewrote the remnant")
        self.assertTrue(got["kept"])
        self.assertEqual(got["urls"], ["/api/opshell/state",
                                       "/api/opshell/close",
                                       "/api/opshell/state"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_parked_cross_dismisses_what_the_session_left(self):
        """`design:196`: the remnant carries the ✕ that dismisses it.

        Without it a session that ended while parked leaves an entry
        nothing can remove -- the design's second anti-goal -- and
        restoring the card only to close it is not an answer. The design's
        own condition comes with it: the dismiss path must not clear
        `opshellLast` before the duration has been shown, and
        `opshellTeardown` is what clears it.
        """
        got = self._node(
            "opshellSession = 'sid';\n"
            "opshellStarted = Date.now() - 92000;\n"
            "els['main'] = el('main'); els['content'] = el('content');\n"
            "els['sidebar'] = el('sidebar');\n"
            "els['main'].appendChild(els['content']);\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot'}},"
            " {ok:true, status:200, body:{}}];\n"
            "await showOperatorShell();\n"
            "opshellMinimise();\n"
            "await opshellEndSession();\n"
            "const shown = els['sidebar'].children[0].innerHTML;\n"
            "const heldWhenShown = opshellLast && opshellLast.duration;\n"
            "await opshellClose();\n"
            "console.log(JSON.stringify({shown, heldWhenShown,"
            " minimised: opshellMinimised,"
            " left: els['sidebar'].children.length,"
            " card: document.getElementById('opshell-card'),"
            " column: els['content'].style.display,"
            " last: opshellLast,"
            " urls: posted.map(p => p.url.split('?')[0])}));")
        # The duration was on screen, in the entry the operator presses,
        # while `opshellLast` still held it.
        self.assertRegex(got["shown"], r"(?i)session ended")
        self.assertIn("92", got["shown"])
        self.assertEqual(got["heldWhenShown"], 92)
        # The ✕ is in the markup and not only in the handler this test
        # calls, and it is on a button: the harness does not parse markup,
        # so the control is pinned the way the chrome's two are, and a
        # `<span onclick=...>` -- unreachable by keyboard -- does not pass.
        self.assertRegex(got["shown"],
                         r'<button[^>]*onclick="opshellClose\(')
        # And then the remnant goes, with the hidden card behind it, and
        # the column stays the operator's.
        self.assertEqual(got["left"], 0, "the remnant could not be dismissed")
        self.assertIsNone(got["card"])
        self.assertFalse(got["minimised"])
        self.assertEqual(got["column"], "")
        self.assertIsNone(got["last"])
        # Nothing is posted for a session that has already ended: the
        # close above is `opshellEndSession`'s, not the dismiss's.
        self.assertEqual(got["urls"],
                         ["/api/opshell/state", "/api/opshell/close"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_reopened_panel_does_not_park_with_the_last_sessions_label(self):
        # `showOperatorShell` appends the card and its live `_` before it
        # awaits the poll, so the glyph can be pressed before this panel
        # knows anything -- and for the whole of an outage, since the
        # poll's catch rides one out without touching what it was told.
        # What the dock may not do then is name the device of the session
        # that is over: that is a claim a shell is live on a named machine,
        # in the only element on screen, from a panel holding no session.
        # Measured before this: `>_ parrot / channel open`.
        got = self._node(
            "els['main'] = el('main'); els['content'] = el('content');\n"
            "els['sidebar'] = el('sidebar');\n"
            "els['main'].appendChild(els['content']);\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot'}}, {throw:'offline'}];\n"
            "await showOperatorShell();\n"
            "opshellMinimise();\n"
            "const named = els['sidebar'].children[0].innerHTML;\n"
            "await opshellTeardown(document.getElementById('opshell-card'));\n"
            "await showOperatorShell();\n"
            "opshellMinimise();\n"
            "console.log(JSON.stringify({named,"
            " again: els['sidebar'].children[0].innerHTML,"
            " last: opshellLast}));")
        self.assertIn("parrot", got["named"])
        self.assertNotIn("parrot", got["again"],
                         "a reopened panel parked with the device of the "
                         "session that ended")
        self.assertNotRegex(got["again"], r"(?i)channel open")
        # And not through the other door either: `opshellTeardown` clears
        # `opshellLast`, so a remnant label here would be the cross's
        # doing, dismissing a card the operator had just opened.
        self.assertIsNone(got["last"])
        self.assertNotRegex(got["again"], r"(?i)session ended")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_parking_while_an_open_is_in_flight_is_still_remembered(self):
        # The await straddles the park: the picker's buttons are inside the
        # card and unreachable once it is hidden, but the request they sent
        # is not, and it lands in `opshellRemember(answer.session)` after
        # the operator has pressed `_`. The page stays correctly parked, so
        # the only thing that goes wrong is the reload memory -- which is
        # the one thing nothing on screen would show. Measured without the
        # guard: `'1'` after the park, `null` once the open landed, and a
        # reload then came back open over the operator's work.
        got = self._node(
            "els['opshell-card'] = el('opshell-card');\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "els['sidebar'] = el('sidebar'); els['content'] = el('content');\n"
            "nextReply = {ok:true, status:200, body:{session:'new-one'}};\n"
            "const opening = opshellOpen();\n"
            "opshellMinimise();\n"
            "const duringFlight = sessionStorage.getItem(opshellStore + '_min');\n"
            "await opening;\n"
            "console.log(JSON.stringify({duringFlight,"
            " after: sessionStorage.getItem(opshellStore + '_min'),"
            " session: opshellSession, minimised: opshellMinimised,"
            " remembered: sessionStorage.getItem(opshellStore)}));")
        self.assertEqual(got["duringFlight"], "1")
        self.assertEqual(got["session"], "new-one")
        self.assertEqual(got["remembered"], "new-one")
        self.assertTrue(got["minimised"])
        self.assertEqual(got["after"], "1",
                         "an open that landed under a parked card forgot "
                         "that the card was parked")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_parked_label_is_not_rewritten_when_nothing_changed(self):
        # The defect Step 6 fixed in `opshellRetitle`, on a node that is
        # worse: this one holds the restore button and, on a remnant, the
        # ✕. Assigning `innerHTML` destroys and recreates them, so focus
        # returns to `<body>` every two seconds and a keyboard-only
        # operator cannot reliably Tab to Restore and press Enter. What
        # the harness can show is the write itself, through what a write
        # destroys and through the count of writes.
        #
        # The park here follows a poll, so the tick after it says exactly
        # what the park said: that pins the park's own write into the
        # poll's memory of the label as well as the guard that reads it,
        # because a park the poll believes it has not seen is a dock
        # rewritten on the very next tick.
        got = self._node(
            "opshellSession = 'sid';\n"
            "els['opshell-card'] = el('opshell-card');\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "els['sidebar'] = el('sidebar'); els['content'] = el('content');\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot'}},"
            " {ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot'}},"
            " {ok:true, status:200, body:{state:'live',"
            " channel:'closed', host:'parrot'}}];\n"
            "await opshellPoll();\n"
            "opshellMinimise();\n"
            "const dock = els['sidebar'].children[0];\n"
            "const parkWrites = dock.htmlWrites.length;\n"
            "const mark = document.createElement('b');\n"
            "dock.appendChild(mark);\n"
            "await opshellPoll();\n"
            "const quiet = [dock.htmlWrites.length, mark.parentNode !== null];\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({parkWrites, quiet,"
            " writes: dock.htmlWrites.length,"
            " kept: mark.parentNode !== null, html: dock.innerHTML}));")
        # The park writes the tray once, whatever was remembered before.
        self.assertEqual(got["parkWrites"], 1)
        # The tick after it says the same thing, so it writes nothing and
        # leaves what is in the tray alone.
        self.assertEqual(got["quiet"], [1, True],
                         "a tick that changed nothing rewrote the dock, "
                         "and took the buttons in it with it")
        # And the tick that does change it writes, or the label would be
        # the lie the refresh exists to prevent.
        self.assertEqual(got["writes"], 2)
        self.assertFalse(got["kept"])
        self.assertRegex(got["html"], r"(?i)channel closed")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_parked_label_is_compared_with_the_markup_it_wrote(self):
        """A browser's `innerHTML` getter re-serializes the DOM.

        A remnant's `&#10005;` reads back as `✕`, and an `&#39;` from a
        hostname reads back as `'` because `esc()`'s output lands in a
        text node -- measured in a browser at offsets 474 and 293. So a
        guard that compares the node's `innerHTML` with the markup it is
        about to write finds them different on every tick, and rewrites
        the dock every two seconds: the defect the guard exists to
        prevent, on the one path that has two focusable controls rather
        than one. `opshellRetitle`'s sibling guard is safe because
        `textContent` has no serializer.

        This harness cannot show that -- its getter returns the string
        that was written, verbatim -- but it can show the semantics that
        replaces it. The dock is judged by what this page last wrote into
        it, and nothing else in the page writes the dock, so something
        else appearing in the node is not a change this label has to
        answer for.
        """
        got = self._node(
            "opshellSession = 'sid';\n"
            "els['opshell-card'] = el('opshell-card');\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "els['sidebar'] = el('sidebar'); els['content'] = el('content');\n"
            "opshellMinimise();\n"
            "const dock = els['sidebar'].children[0];\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot'}},"
            " {ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot'}}];\n"
            "await opshellPoll();\n"
            "const mine = dock.htmlWrites.length;\n"
            "dock.innerHTML = 'what a browser reads back';\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({mine,"
            " writes: dock.htmlWrites.length, html: dock.innerHTML}));")
        # The park's own write, and the first poll's label.
        self.assertEqual(got["mine"], 2)
        # The write below is the third, and the tick after it adds none:
        # what changed is the node, not the markup this page wrote.
        self.assertEqual(got["writes"], 3,
                         "the poll judged the dock by what the node reads "
                         "back, so a remnant is rewritten on every tick")
        self.assertEqual(got["html"], "what a browser reads back")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_hostname_cannot_write_markup_into_the_parked_card(self):
        # `opshellParked` is a new sink for a string a remote machine
        # reported: `state.host` comes off the agent's own check-in. The
        # convention is to prove the escaper is on the value and not
        # merely available -- `test_agent_reported_pid_is_escaped` and
        # `test_every_value_a_listener_influences_is_escaped` -- and this
        # file had no such test at all.
        got = self._node(
            "opshellLast = null;\n"
            "console.log(JSON.stringify({html: opshellParked({state:'live',"
            " channel:'open',"
            " host:'<img src=x>\\\" onmouseover=1 \\''})}));")
        self.assertNotIn("<img", got["html"])
        self.assertIn("&lt;img", got["html"])
        # `<` is the one that matters in the position the host lands in --
        # text, inside a span; the `title` beside it is a literal string
        # and the host never reaches an attribute. The two quotes are
        # checked because they are what tells `esc()` apart from a
        # hand-rolled `<`-only replacement. What the assertions bear out is
        # `<`, `"` and `'` -- the payload has no `&` and `>` is not
        # asserted -- so a hole through either of those two is not covered
        # here.
        self.assertIn("&quot;", got["html"])
        self.assertIn("&#39;", got["html"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_geometry_is_measured_from_the_card(self):
        # Twice the room is twice the terminal. Pinning the ratio rather
        # than two literals keeps this test honest whatever the probe is
        # made of -- a test written against the probe's own constants
        # would only restate the implementation.
        got = self._node(
            "const small = el('opshell-term');\n"
            "small.box = {width: 800, height: 400};\n"
            "fakeBox(256, 16);\n"
            "const a = opshellMeasure(small);\n"
            "small.box = {width: 1600, height: 800};\n"
            "fakeBox(256, 16);\n"
            "const b = opshellMeasure(small);\n"
            "console.log(JSON.stringify({a, b}));")
        (ac, ar), (bc, br) = got["a"], got["b"]
        self.assertGreater(ac, 20)
        self.assertGreater(ar, 5)
        self.assertAlmostEqual(bc, ac * 2, delta=1,
                               msg="twice the width was not twice the columns")
        self.assertAlmostEqual(br, ar * 2, delta=1,
                               msg="twice the height was not twice the rows")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_window_too_narrow_still_gets_a_terminal(self):
        """Review Focus 3.

        A 0 or a negative would be clamped server-side by
        `opshell._dimension` to 1, so the operator would get a one-column
        terminal and no explanation. The floor is on this side.

        (0, 0) returns through the fallback, not through the floor, so only
        (1, 1) and (120, 40) exercise what this docstring is about.
        """
        for w, h in ((120, 40), (1, 1), (0, 0)):
            got = self._node(
                "const host = el('opshell-term');\n"
                "host.box = {width: %d, height: %d};\n"
                "fakeBox(256, 16);\n"
                "console.log(JSON.stringify({pair: opshellMeasure(host)}));"
                % (w, h))
            cols, rows = got["pair"]
            self.assertGreaterEqual(cols, 20, (w, h))
            self.assertGreaterEqual(rows, 5, (w, h))
            self.assertLessEqual(cols, 1000, (w, h))
            self.assertLessEqual(rows, 1000, (w, h))

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_window_too_wide_is_capped_where_the_server_caps_it(self):
        # The brief's floor test only reaches the cap from below: no box it
        # uses is large enough to cross 1000, so deleting the cap went
        # unseen. The server clamps to 1000 too, but a pair that arrives as
        # a different number than the page printed is a strip that lies.
        got = self._node(
            "const host = el('opshell-term');\n"
            "host.box = {width: 400000, height: 400000};\n"
            "fakeBox(256, 16);\n"
            "console.log(JSON.stringify({pair: opshellMeasure(host)}));")
        self.assertEqual(got["pair"], [1000, 1000])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_host_inside_a_hidden_card_falls_back_rather_than_guessing(self):
        """Fact 3: a reload whose first poll fails attaches into a card
        that is still `display:none`, and the size is fixed for the life of
        the connection, so a wrong measurement here is wrong for the whole
        session."""
        got = self._node(
            "els['opshell-card'] = el('opshell-card');\n"
            "const host = el('opshell-term');\n"
            "els['opshell-card'].appendChild(host);\n"
            "host.box = {width: 1600, height: 800};\n"
            "els['opshell-card'].style.display = 'none';\n"
            "fakeBox(256, 16);\n"
            "console.log(JSON.stringify({pair: opshellMeasure(host)}));")
        self.assertEqual(got["pair"], [120, 40],
                         "a hidden card was measured instead of falling back")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_probe_does_not_stay_behind(self):
        """The probe is a span in the page for the length of one
        measurement. One left behind on every attach is a leak the operator
        never sees."""
        got = self._node(
            "const host = el('opshell-term');\n"
            "host.box = {width: 800, height: 400};\n"
            "fakeBox(256, 16);\n"
            "const before = document.body.children.length;\n"
            "opshellMeasure(host); opshellMeasure(host);\n"
            "console.log(JSON.stringify({before,"
            " after: document.body.children.length,"
            " removedAny: removed.length > 0}));")
        self.assertEqual(got["after"], got["before"],
                         "a probe was left in the page")
        self.assertTrue(got["removedAny"], "the probe was never removed")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_pair_that_is_measured_is_the_pair_that_is_sent(self):
        got = self._node(
            "els['opshell-term'] = el('opshell-term');\n"
            "els['opshell-term'].box = {width: 1000, height: 500};\n"
            "globalThis.Terminal = function(o){ globalThis.made = o;"
            " return fakeTerm(); };\n"
            "opshellSession = 'sid';\n"
            "fakeBox(256, 16);\n"
            "nextReply = {ok:true, status:200, stream: fakeStream(['x'])};\n"
            "await opshellAttach({state:'live', host:'parrot'});\n"
            "const url = posted.find(p => p.url.includes('/stream')).url;\n"
            "console.log(JSON.stringify({made: [made.cols, made.rows],"
            " url}));")
        cols, rows = got["made"]
        self.assertIn("cols=%d&rows=%d" % (cols, rows), got["url"])
        self.assertNotEqual([cols, rows], [120, 40],
                            "the measurement never replaced the old default")

    def _attach_lines(self, card_display, probe_box):
        """What `opshellAttach` writes into the terminal, driven for real:
        the host sits in a card with this `display`, and the probe the page
        creates gets this box (None leaves it 0x0)."""
        return self._node(
            "const card = el('opshell-card');\n"
            "const host = el('opshell-term');\n"
            "card.appendChild(host);\n"
            "host.box = {width: 1600, height: 800};\n"
            "card.style.display = '%s';\n"
            "globalThis.Terminal = function(o){ globalThis.t = fakeTerm();"
            " return t; };\n"
            "opshellSession = 'sid';\n"
            "%s\n"
            "nextReply = {ok:true, status:200, stream: fakeStream(['x'])};\n"
            "await opshellAttach({state:'live', host:'parrot'});\n"
            "console.log(JSON.stringify({lines: t.lines}));"
            % (card_display, "fakeBox(%d, %d);" % probe_box
               if probe_box else ""))["lines"]

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_terminal_that_was_not_fitted_says_so_once_and_a_fitted_one_does_not(self):
        """The size is fixed for the life of the connection, so an operator
        who restores a card that was hidden at the attach sees a small
        terminal in a wide box with no way to resize it and no way to know
        why. Driven through `opshellAttach`, both ways: a note that always
        fires is the same defect as one that never does."""
        hidden = self._attach_lines("none", (256, 16))
        notes = [l for l in hidden if "not fitted" in l]
        self.assertEqual(len(notes), 1, hidden)
        self.assertIn("keeps that size", notes[0])
        # "that size" refers to the strip line above, so the strip is where
        # the size is pinned: the note does not carry it any more.
        strip = [l for l in hidden if "live on" in l]
        self.assertEqual(len(strip), 1, hidden)
        self.assertIn("120x40", strip[0])
        shown = self._attach_lines("", (256, 16))
        self.assertEqual([l for l in shown if "not fitted" in l], [], shown)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_notice_names_a_cause_it_has_established_and_the_two_differ(self):
        """A host with no box is a hidden card *or* a card on screen in a
        window too short to give it room, so the note may not say the card
        was not visible; and a probe that measured nothing is not the
        card's doing at all. The property is that the two reasons differ
        and neither claims the other's cause -- not a literal."""
        nobox = [l for l in self._attach_lines("none", (256, 16))
                 if "not fitted" in l]
        noprobe = [l for l in self._attach_lines("", None)
                   if "not fitted" in l]
        self.assertEqual((len(nobox), len(noprobe)), (1, 1))
        self.assertNotEqual(nobox[0], noprobe[0])
        self.assertIn("no room", nobox[0])
        self.assertNotIn("not visible", nobox[0],
                         "a host with no room is not necessarily hidden")
        self.assertNotIn("no room", noprobe[0],
                         "a probe failure was blamed on the card")
        self.assertNotIn("normal window", noprobe[0],
                         "a probe failure was promised a cure it does not get")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_pair_comes_from_the_probe_by_division_rounded_down(self):
        """Each of these is a one-token change that kept the suite green:
        the axes swapped, the probe's box replaced by the harness's own
        numbers, and `floor` made `ceil` -- which puts the last column and
        the bottom row outside an `overflow:hidden` host. The probe is the
        32-character run xterm measures, so a 256-wide box is an 8px cell."""
        cases = (((800, 400), (256, 16), [100, 25]),
                 # 101.25 columns and 25.6 rows: down, never up.
                 ((810, 410), (256, 16), [101, 25]),
                 # Another probe box is another pair: not the harness's 8x16.
                 ((800, 400), (128, 16), [200, 25]))
        for host, probe, want in cases:
            got = self._node(
                "const host = el('opshell-term');\n"
                "host.box = {width: %d, height: %d};\n"
                "fakeBox(%d, %d);\n"
                "console.log(JSON.stringify({pair: opshellMeasure(host)}));"
                % (host + probe))
            self.assertEqual(got["pair"], want, (host, probe))

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_probe_is_made_the_way_the_terminal_is(self):
        """Nothing else ties the two: a `fontSize: 13` in the `Terminal`
        options, or a probe that lost its font, would measure the wrong cell
        for every session and every test above would stay green. Read off
        the nodes the real attach creates, not off the source text."""
        got = self._node(
            "const made_nodes = [];\n"
            "const _ce = document.createElement;\n"
            "document.createElement = () => {"
            " const n = _ce(); made_nodes.push(n); return n; };\n"
            "els['opshell-term'] = el('opshell-term');\n"
            "els['opshell-term'].box = {width: 1000, height: 500};\n"
            "globalThis.Terminal = function(o){ globalThis.made = o;"
            " return fakeTerm(); };\n"
            "opshellSession = 'sid';\n"
            "fakeBox(256, 16);\n"
            "nextReply = {ok:true, status:200, stream: fakeStream(['x'])};\n"
            "await opshellAttach({state:'live', host:'parrot'});\n"
            "console.log(JSON.stringify({style: made_nodes[0].style,"
            " text: made_nodes[0].textContent, term: made}));")
        style, term = got["style"], got["term"]
        self.assertEqual(style.get("fontFamily"), term["fontFamily"])
        self.assertEqual(style.get("fontSize"), "%dpx" % term["fontSize"])
        # What xterm's own measurement element is: a run, in a box that
        # keeps its spaces and takes the font's own line height.
        self.assertEqual(style.get("display"), "inline-block")
        self.assertEqual(style.get("whiteSpace"), "pre")
        self.assertEqual(style.get("lineHeight"), "normal")
        self.assertEqual(got["text"], "W" * 32)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_terminal_is_given_a_resolved_font_and_the_probe_the_same_one(self):
        """The vendored xterm prefers an OffscreenCanvas strategy and sets
        `ctx.font = "12px " + fontFamily`; a canvas cannot resolve
        `var(--mono)`, so the assignment is ignored and the terminal's own
        cell is measured in a default sans-serif while the probe measures
        the right one. Both get the resolved list, and an empty answer from
        the stylesheet is the literal stack and not an empty name."""
        script = (
            "%s\n"
            "const made_nodes = [];\n"
            "const _ce = document.createElement;\n"
            "document.createElement = () => {"
            " const n = _ce(); made_nodes.push(n); return n; };\n"
            "els['opshell-term'] = el('opshell-term');\n"
            "els['opshell-term'].box = {width: 1000, height: 500};\n"
            "globalThis.Terminal = function(o){ globalThis.made = o;"
            " return fakeTerm(); };\n"
            "opshellSession = 'sid';\n"
            "fakeBox(256, 16);\n"
            "nextReply = {ok:true, status:200, stream: fakeStream(['x'])};\n"
            "await opshellAttach({state:'live', host:'parrot'});\n"
            "console.log(JSON.stringify({probe: made_nodes[0].style"
            ".fontFamily, term: made.fontFamily}));")
        stack = re.search(r"^\s*--mono:(.*?);\s*$", STYLE_BLOCK, re.M).group(1)
        for setup, want in (
                ("", stack),
                ("cssVars['--mono'] = '  \\'Test Mono\\', monospace  ';",
                 "'Test Mono', monospace"),
                ("cssVars = {};", None)):
            got = self._node(script % setup)
            self.assertEqual(got["probe"], got["term"],
                             "the probe and the terminal measure different fonts")
            self.assertNotIn("var(", got["term"],
                             "a canvas cannot resolve a custom property")
            self.assertIn("monospace", got["term"], "no real family named")
            if want is not None:
                self.assertEqual(got["term"], want)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_terminal_host_has_a_box_to_be_measured_in(self):
        """Not in the brief, found by reading the markup: `#opshell-term` is
        an empty block when the page measures it, so as a plain `div` it is
        as tall as nothing and `opshellMeasure` would answer the five-row
        floor for every session, in every browser, while every test above
        stayed green on a host the harness had given a box by hand. The
        host has to be given its room by the stylesheet.

        The declarations are one mechanism and are asserted as one:
        `display:flex` on the wrapper and `flex:1` on the body are what the
        `min-height:100%` and the host's `flex:1` hang on, and deleting
        either zeroes the host in a browser while the two that remain read
        as a complete answer. `min-height` and not `height` on the wrapper,
        and a floor on the host, so a short card scrolls the body instead of
        clipping the terminal away."""
        got = self._node(
            "opshellSession = 'mine';\n"
            "console.log(JSON.stringify({html: opshellRender({state:'live',"
            " channel:'open', host:'parrot'})}));")
        html = got["html"]
        wrapper = html.index('class="opshell-live"')
        self.assertLess(wrapper, html.index('id="opshell-term"'),
                        "the host is outside the box that gives it a height")
        flat = lambda name: ";".join(
            self.css_rules(name)).replace(" ", "").replace("\n", "")
        live, host, body = (flat("opshell-live"), flat("opshell-term"),
                            flat("opshell-body"))
        for need in ("display:flex", "flex-direction:column",
                     "min-height:100%"):
            self.assertIn(need, live)
        self.assertNotIn(";height:", ";" + live,
                         "a fixed height clips the terminal on a short card")
        for need in ("flex:1", "min-height:72px", "overflow:hidden"):
            self.assertIn(need, host)
        self.assertIn("flex:1", body,
                      "the body is what min-height:100% resolves against")
        self.assertIn("overflow:auto", body,
                      "a short card has nothing to scroll")

    def test_the_frame_is_not_on_the_measured_host(self):
        body = self.one_rule("opshell-term", "#opshell-term")
        self.assertNotRegex(body, r"padding|border",
                            "opshellMeasure reads this element's rect for the "
                            "cols it sends to /stream")
        # The rule above is only the host's own. A rule that reaches it from
        # an ancestor -- `.opshell-screen > div`, `#opshell-body *`, or
        # `.opshell-live #opshell-term` -- puts the frame back on it just as
        # well, and the bare markup the next test pins cannot see a rule.
        css = re.sub(r"/\*.*?\*/", "", STYLE_BLOCK, flags=re.S)
        above = r"(\.opshell-card|#opshell-body|\.opshell-live|\.opshell-screen)"
        for sel, rule in _css_blocks(css):
            for part in (p.strip() for p in sel.split(",")):
                last = re.split(r"\s*[ >+~]\s*", part)[-1]
                if "#opshell-term" in last:
                    self.assertNotRegex(rule, r"padding|border",
                                        "%s reaches the measured host" % part)
                if re.search(above + r".*[ >+~]", part):
                    self.assertNotRegex(
                        last, r"^(\*|div)(:[\w-]+(\([^)]*\))?)*$",
                        "%s reaches the measured host from above" % part)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_frame_is_on_a_wrapper_inside_the_live_box(self):
        html = self.render(session="mine", state="live", channel="open",
                           host="pi", geometry=[120, 40])
        self.assertLess(html.index('class="opshell-live"'),
                        html.index('class="opshell-screen"'))
        self.assertLess(html.index('class="opshell-screen"'),
                        html.index('id="opshell-term"'))
        self.assertIn('<div class="opshell-screen"><div id="opshell-term">'
                      '</div></div>', html,
                      "the measured host carries no class or style of its own")
        screen = self.one_rule("opshell-screen", ".opshell-screen")
        for prop in ("flex:1", "min-height:0", "display:flex", "padding",
                     "border-radius"):
            self.assertIn(prop, screen)

    def test_a_card_too_short_still_scrolls_instead_of_clipping(self):
        self.assertIn("min-height:72px",
                      self.one_rule("opshell-term", "#opshell-term"))
        self.assertIn("overflow:auto",
                      self.one_rule("opshell-body", "#opshell-body"))

    def test_the_bodys_scrollbar_is_the_houses_and_the_terminals_is_not_touched(self):
        self.assertIn("#opshell-body::-webkit-scrollbar", STYLE_BLOCK)
        thumb = self.one_rule("opshell-body",
                              "#opshell-body::-webkit-scrollbar-thumb")
        self.assertIn("var(--red-dim)", thumb)
        self.assertNotIn(".xterm", STYLE_BLOCK)

    def test_the_body_is_not_permanently_a_loading_message(self):
        src = self.js_function("showOperatorShell")
        inner = '<div class="loot-loading">Loading...</div>'
        self.assertIn(inner, src)
        # Every other way of putting the class on the body itself --
        # `classList.add`, `body.className = ...`, `setAttribute("class")`,
        # `classList.toggle` -- names it outside that one child, so the
        # class may appear nowhere else in the function.
        self.assertNotIn("loot-loading", src.replace(inner, ""))

    def test_the_body_states_its_own_text_size(self):
        body = self.one_rule("opshell-body", "#opshell-body")
        self.assertIn("font-size:13px", body)
        self.assertIn("color:var(--text)", body)
        for kept in ("flex:1", "min-height:0", "overflow:auto",
                     "padding:12px 16px"):
            self.assertIn(kept, body)

    def test_the_shells_buttons_sit_in_a_row(self):
        body = self.one_rule("opshell-btn", ".opshell-btn")
        self.assertIn("display:inline-flex", body)
        self.assertNotIn("display:flex;", body)

    def test_the_shell_no_longer_borrows_the_file_download_button(self):
        for name in ("opshellPicker", "opshellRender"):
            self.assertNotIn("fd-btn", self.js_function(name))

    def test_the_file_browsers_button_is_kept_untouched(self):
        # A fence and not an endorsement. `.fd-btn` is worn only by the file
        # browser's detail actions, which `fbShowDetail` draws: `fbLootDir`,
        # `fbLoadDir`, `fbDownloadFile`, the `View` button and `fbUploadTo`.
        # Named by function, because line numbers rot. Its `var(--bg2)` and
        # `var(--bg3)` are defined nowhere, which is a real defect there.
        # Fixing it is separate work that needs that panel's own
        # verification; this pins it so it cannot ship inside the Operator
        # Shell's branch without that.
        self.assertEqual(len(_css_rules(STYLE_BLOCK, "fd-btn", ".fd-btn")), 1)
        self.assertIn("var(--bg2)", self.one_rule("fd-btn", ".fd-btn"))

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_picker_is_themed_and_still_readable_by_its_id(self):
        html = self.render(state="idle", channel="closed", candidates=["pi"])
        tags = re.findall(r"<select\b[^>]*>", html)
        self.assertEqual(len(tags), 1, html)
        self.assertIn('id="opshell-agent"', tags[0])
        self.assertIn("opshell-pick", tags[0])
        self.assertIn("var(--border)", self.one_rule("opshell-pick",
                                                    ".opshell-pick"))

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_fleet_with_no_designation_offers_nothing_to_open(self):
        html = self.render(state="idle", channel="closed", candidates=self.FLEET)
        self.assertIn('<option value="">choose a device</option>', html)
        self.assertNotIn(" selected>", html)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_designation_that_left_the_fleet_offers_nothing_to_open(self):
        # The half no note carried: the strip names `raccoon-bandit` while the
        # browser would hand back `badger`, so Open took a shell on a device
        # the view had just named a different one.
        html = self.render(state="idle", channel="closed",
                           candidates=self.FLEET, target="raccoon-bandit")
        self.assertIn('<option value="">', html)
        self.assertNotIn(" selected>", html)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_designation_in_the_fleet_is_selected_and_gets_no_placeholder(self):
        html = self.render(state="idle", channel="closed",
                           candidates=self.FLEET, target="parrot")
        self.assertIn('<option value="parrot" selected>', html)
        self.assertNotIn('<option value="">', html)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_an_empty_fleet_offers_only_the_placeholder(self):
        html = self.render(state="idle", channel="closed", candidates=[])
        self.assertEqual(html.count("<option"), 1, html)
        self.assertIn('<option value="">', html)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_placeholder_is_told_by_its_empty_value_not_its_label(self):
        # Names are the server's own `raccoon-<word>` (`_assign_name`), not
        # hostnames, so only a hand-edited `state.json` holds this one --
        # which is why the placeholder is told by its value, not its label.
        html = self.render(state="idle", channel="closed",
                           candidates=["choose a device"])
        self.assertEqual(html.count('<option value="">'), 1, html)
        self.assertIn('<option value="choose a device">', html)

    # What a browser does with a `<select>` drawn into `#opshell-body`: the
    # write destroys the old one, and the new one holds the value the markup
    # selects -- the `selected` option, else the first. The harness does not
    # parse markup, so without this the list would outlive the redraw that
    # destroys it, and a pick could not be lost however the poll was written.
    _REDRAWN_PICKER = (
        "const body = el('opshell-body');\n"
        "body.appendChild(el('opshell-agent'));\n"
        "const write = Object.getOwnPropertyDescriptor(body, 'innerHTML');\n"
        "Object.defineProperty(body, 'innerHTML', {get: write.get,\n"
        "  set(v){\n"
        "    write.set.call(body, v);\n"
        "    const list = /<select id=\"opshell-agent\"[^>]*>(.*?)<\\/select>/"
        ".exec(v);\n"
        "    if(!list) return;\n"
        "    const on = /<option value=\"([^\"]*)\" selected>/.exec(list[1])\n"
        "      || /<option value=\"([^\"]*)\"/.exec(list[1]);\n"
        "    const node = makeNode('opshell-agent');\n"
        "    node.value = on ? on[1] : '';\n"
        "    body.appendChild(node);\n"
        "  }});\n")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_poll_does_not_take_back_the_operators_pick(self):
        # The final review's Critical. The poll redraws the idle body every
        # two seconds, and the markup selects the designation: the operator
        # picked `badger`, the tick put `parrot` back, and Open took a shell
        # on `parrot`. The markup is checked too, because the fix must not
        # reach it -- the ordinary path renders as it did.
        idle = {"state": "idle", "channel": "closed",
                "candidates": self.FLEET, "target": "parrot"}
        got = self._node(
            self._REDRAWN_PICKER
            + "body.innerHTML = opshellRender(%s);\n"
            "els['opshell-agent'].value = 'badger';\n"
            "replies = [{ok:true, status:200, body:%s}];\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({value: els['opshell-agent'].value,"
            " html: body.innerHTML, drawn: opshellRender(%s)}));"
            % (json.dumps(idle), json.dumps(idle), json.dumps(idle)))
        self.assertEqual(got["value"], "badger",
                         "the poll put the designation back over the pick")
        self.assertEqual(got["html"], got["drawn"])
        self.assertIn('<option value="parrot" selected>', got["html"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_pick_that_left_the_fleet_is_not_put_back(self):
        # The other half: a value that is no longer an option is one a
        # browser would refuse anyway, and keeping it would leave the list
        # showing nothing selected. The markup's own selection stands.
        before = {"state": "idle", "channel": "closed",
                  "candidates": self.FLEET, "target": "parrot"}
        after = dict(before, candidates=["clumsy-raccoon", "parrot"])
        got = self._node(
            self._REDRAWN_PICKER
            + "body.innerHTML = opshellRender(%s);\n"
            "els['opshell-agent'].value = 'badger';\n"
            "replies = [{ok:true, status:200, body:%s}];\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({value: els['opshell-agent'].value}));"
            % (json.dumps(before), json.dumps(after)))
        self.assertEqual(got["value"], "parrot")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_list_showing_its_placeholder_opens_nothing(self):
        # Posting `{}` from the placeholder let the server fall back to
        # whatever designation existed by then -- one another tab could
        # have written after this view was drawn, and so a device the
        # operator was never shown. Nothing is posted; the reason is said.
        got = self._node(
            "els['opshell-body'] = el('opshell-body');\n"
            "els['opshell-agent'] = el('opshell-agent');\n"
            # By hand, so not end to end: the real card is `_refusal_card`'s.
            "els['opshell-refused'] = el('opshell-refused');\n"
            "replies = [];\n"
            "const opened = await opshellOpen();\n"
            "console.log(JSON.stringify({opened, posted,"
            " shown: els['opshell-refused'].innerHTML}));")
        self.assertFalse(got["opened"])
        self.assertEqual(got["posted"], [])
        self.assertIn("choose a device first", got["shown"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_attach_which_has_no_list_still_names_nothing_and_opens(self):
        # The guard's boundary. Attach is drawn with no picker and relies
        # on the server's fallback to the designation, so a view with no
        # list at all must still post `{}`.
        got = self._node(
            "els['opshell-body'] = el('opshell-body');\n"
            "replies = [{ok:true, status:200, body:{session:'adopted'}}];\n"
            "const opened = await opshellOpen();\n"
            "console.log(JSON.stringify({opened, posted,"
            " session: opshellSession}));")
        self.assertTrue(got["opened"])
        self.assertEqual([p["body"] for p in got["posted"]], ["{}"])
        self.assertEqual(got["session"], "adopted")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_refused_name_is_shown_with_the_refusal(self):
        # The route answers `no such agent` with the name in `refused`, and
        # the page drew only the first half -- so a designation that had
        # left the fleet was refused without saying which one.
        got = self._node(
            "els['opshell-body'] = el('opshell-body');\n"
            # By hand, so not end to end: the real card is `_refusal_card`'s.
            "els['opshell-refused'] = el('opshell-refused');\n"
            "replies = [{ok:false, status:404, body:{error:'no such agent',"
            " refused:'no-such-raccoon'}}];\n"
            "const opened = await opshellOpen();\n"
            "console.log(JSON.stringify({opened,"
            " shown: els['opshell-refused'].innerHTML}));")
        self.assertFalse(got["opened"])
        self.assertIn("no such agent: no-such-raccoon", got["shown"])

    # What the poll answers while nothing is attached: the card's ordinary
    # resting state, and the one that redraws `#opshell-body` every tick.
    IDLE = {"state": "idle", "channel": "closed", "candidates": ["badger"]}

    def _refusal_card(self, script):
        """A real card, `script` run in it, and what the card then says.

        Drawn by `showOperatorShell` rather than assembled here, so where the
        page puts a refusal is the page's answer and not this harness's.
        `notes` is every `.opshell-note` among the card's own children;
        `said` is every child's markup together, so a refusal left anywhere
        in the card -- the body included -- is found.
        """
        return self._node(
            "els['main'] = el('main'); els['content'] = el('content');\n"
            "els['main'].appendChild(els['content']);\n"
            "replies = [{ok:true, status:200, body:%s}];\n"
            "await showOperatorShell();\n"
            "els['opshell-agent'] = el('opshell-agent');\n"
            "%s\n"
            "const card = els['opshell-card'];\n"
            "console.log(JSON.stringify({\n"
            " body: els['opshell-body'].innerHTML,\n"
            " notes: card.children.filter(c =>"
            " c.classList.contains('opshell-note')).map(c => c.innerHTML),\n"
            " said: card.children.map(c => c.innerHTML).join('\\n'),\n"
            " rejected: said.includes('token-rejected')}));"
            % (json.dumps(self.IDLE), script))

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_refusal_is_still_there_after_the_poll_redraws_the_body(self):
        """Reported by the operator: the message went too fast to read.

        It was written into `#opshell-body`, and the next poll -- two
        seconds later, while nothing is attached -- rebuilt that node from
        the state, which does not carry it. Measured: both refusals this
        branch added were gone one tick after they were shown.
        """
        got = self._refusal_card(
            "els['opshell-agent'].value = 'badger';\n"
            "replies = [{ok:false, status:404, body:{error:'no such agent',"
            " refused:'badger'}}, {ok:true, status:200, body:%s}];\n"
            "await opshellOpen();\n"
            "await opshellPoll();" % json.dumps(self.IDLE))
        self.assertEqual(len(got["notes"]), 1, got["said"])
        self.assertIn("no such agent: badger", got["notes"][0],
                      "the poll took the refusal off the page")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_refusal_is_not_written_into_the_body_the_poll_owns(self):
        # The property that makes the one above hold for every tick and not
        # just the first: the poll can only erase what is inside its node.
        got = self._refusal_card(
            "els['opshell-agent'].value = '';\n"
            "replies = [];\n"
            "await opshellOpen();")
        self.assertNotIn("choose a device first", got["body"])
        self.assertEqual(len(got["notes"]), 1, got["said"])
        self.assertIn("choose a device first", got["notes"][0])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_second_attempt_takes_back_what_the_first_one_said(self):
        # A refusal is about the press that earned it. Left standing over an
        # Open that went through, it says that press failed.
        got = self._refusal_card(
            "els['opshell-agent'].value = '';\n"
            "replies = [];\n"
            "await opshellOpen();\n"
            "els['opshell-agent'].value = 'badger';\n"
            "replies = [{ok:true, status:200, body:{state:'waiting'}}];\n"
            "await opshellOpen();")
        self.assertNotIn("choose a device first", got["said"])
        self.assertEqual(got["notes"], [],
                         "an empty note is still drawn, padding and all")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_two_refusals_leave_one_note(self):
        got = self._refusal_card(
            "els['opshell-agent'].value = '';\n"
            "replies = [];\n"
            "await opshellOpen();\n"
            "els['opshell-agent'].value = 'badger';\n"
            "replies = [{ok:false, status:404, body:{error:'no such agent',"
            " refused:'badger'}}];\n"
            "await opshellOpen();")
        self.assertEqual(len(got["notes"]), 1, got["said"])
        self.assertIn("no such agent: badger", got["notes"][0])
        self.assertNotIn("choose a device first", got["said"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_an_attempt_the_token_stops_still_takes_back_the_last_refusal(self):
        # Why the clear is the first thing `opshellOpen` does and not beside
        # `opshellLast = null`: a 401 returns before that line, so the token
        # prompt came up under a refusal from a press that is no longer the
        # one being answered.
        got = self._refusal_card(
            "els['opshell-agent'].value = '';\n"
            "replies = [];\n"
            "await opshellOpen();\n"
            "els['opshell-agent'].value = 'badger';\n"
            "replies = [{ok:false, status:401, body:{}}];\n"
            "await opshellOpen();")
        self.assertTrue(got["rejected"], "the second attempt never reached "
                        "the 401 path, so this proves nothing")
        self.assertNotIn("choose a device first", got["said"],
                         "a refusal outlived the attempt that followed it")
        self.assertEqual(got["notes"], [])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_minimising_twice_parks_one_card(self):
        # The guard `showOperatorShell` holds itself to. Two docks share an
        # id, so a restore removes the one it finds and the other stays:
        # the operator gets the shell back with a button beside the device
        # list still offering to restore it. Measured without the guard:
        # two docks, one left behind.
        got = self._node(
            "opshellSession = 'sid';\n"
            "els['main'] = el('main'); els['content'] = el('content');\n"
            "els['sidebar'] = el('sidebar');\n"
            "els['main'].appendChild(els['content']);\n"
            "await showOperatorShell();\n"
            "opshellMinimise();\n"
            "opshellMinimise();\n"
            "const docks = els['sidebar'].children.length;\n"
            "opshellRestore();\n"
            "console.log(JSON.stringify({docks,"
            " leftBehind: els['sidebar'].children.length,"
            " card: document.getElementById('opshell-card').style.display}));")
        self.assertEqual(got["docks"], 1)
        self.assertEqual(got["leftBehind"], 0,
                         "a second park was left beside the restored shell")
        self.assertEqual(got["card"], "")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_page_with_nowhere_to_park_keeps_the_card(self):
        # Minimise is reached from the card's own header, so a throw here
        # would be a dead button and not the dead page the mount-point
        # guard above is about. What it must not do is hide the card with
        # no parked entry beside it: that is a root shell running with
        # nothing on screen and nothing to press, which is the state this
        # whole feature exists to make impossible.
        got = self._node(
            "const warned = []; console.warn = m => warned.push(String(m));\n"
            "opshellSession = 'sid';\n"
            "els['opshell-card'] = el('opshell-card');\n"
            "els['opshell-card'].style.display = '';\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "els['content'] = el('content');\n"
            "els['content'].style.display = 'none';\n"
            "let threw = null;\n"
            "try { opshellMinimise(); } catch(e) { threw = String(e); }\n"
            "console.log(JSON.stringify({threw, warned,"
            " minimised: opshellMinimised,"
            " card: els['opshell-card'].style.display,"
            " column: els['content'].style.display}));")
        self.assertIsNone(got["threw"])
        self.assertFalse(got["minimised"])
        self.assertEqual(got["card"], "", "the card was hidden with no "
                                          "parked entry to bring it back")
        self.assertEqual(got["column"], "none")
        self.assertEqual(len(got["warned"]), 1)
        self.assertIn("Operator Shell", got["warned"][0])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_refusal_reaches_the_operator_once_the_body_has_been_redrawn(self):
        """The final review's first Important.

        The poll replaces `#opshell-body`, and `#opshell-term` goes with
        it. `opshellTerm` stayed non-null over that dead node, and
        `dispose()` had one call site -- `opshellTeardown` -- which a card
        that survives between sessions no longer reaches. So
        `opshellEndSession`'s panel fallback, `!opshellTerm`, could never
        be true: pressing **End the session** on a channel another view
        holds wrote the server's refusal into a detached terminal and the
        operator saw nothing at all.
        """
        got = self._node(
            "opshellSession = null;\n"
            "const term = fakeTerm(); opshellTerm = term;\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot'}},"
            " {ok:true, status:200, body:{session:'adopted'}},"
            " {ok:true, status:200, body:{reason:'another view is holding "
            "this channel, so it stays up'}}];\n"
            "await opshellPoll();\n"
            "const gone = [term.disposed === true, opshellTerm === null];\n"
            "await opshellEndAfterAttach();\n"
            "console.log(JSON.stringify({gone,"
            " shown: els['opshell-body'].innerHTML,"
            " urls: posted.map(p => p.url.split('?')[0])}));")
        # The terminal goes with the node it lived in.
        self.assertEqual(got["gone"], [True, True],
                         "the poll replaced the terminal's node and left "
                         "the terminal undisposed")
        # And the reason the operator pressed a button for is on screen.
        self.assertRegex(got["shown"], r"(?i)another view is holding")
        self.assertEqual(got["urls"], ["/api/opshell/state",
                                       "/api/opshell/open",
                                       "/api/opshell/close"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_second_session_does_not_inherit_the_first_terminal(self):
        # The other half of the same Important: a card that outlives its
        # session used to keep the xterm instance and its observers for
        # every open-end-open cycle, and the next attach wrote into a
        # terminal whose node had been replaced. Driven through a real
        # attach, a real end -- the stream runs out -- a poll, and a second
        # attach.
        got = self._node(
            "els['opshell-term'] = el('opshell-term');\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "const built = [];\n"
            "globalThis.Terminal = function(o){ const t = fakeTerm();"
            " built.push(t); return t; };\n"
            "opshellSession = 'sid-1';\n"
            "nextReply = {ok:true, status:200, stream: fakeStream(['hi'])};\n"
            "await opshellAttach({state:'live', host:'parrot',"
            " geometry:[80,24]});\n"
            "const afterFirst = [built.length, built[0].disposed === true,"
            " opshellTerm === built[0]];\n"
            "nextReply = {ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot'}};\n"
            "await opshellPoll();\n"
            "const afterPoll = [built[0].disposed === true,"
            " opshellTerm === null];\n"
            "const wroteBefore = built[0].lines.length;\n"
            "opshellSession = 'sid-2';\n"
            "nextReply = {ok:true, status:200, stream: fakeStream(['ho'])};\n"
            "await opshellAttach({state:'live', host:'parrot',"
            " geometry:[80,24]});\n"
            "console.log(JSON.stringify({afterFirst, afterPoll,"
            " built: built.length,"
            " quiet: built[0].lines.length === wroteBefore,"
            " wrote: built[1].lines.length > 0,"
            " current: opshellTerm === built[1]}));")
        # The session ended with the stream and the terminal was still
        # there: that is the state the poll has to clean up.
        self.assertEqual(got["afterFirst"], [1, False, True])
        self.assertEqual(got["afterPoll"], [True, True])
        # A second attach builds its own, and writes into that one: the
        # count alone could not fail, because the harness's fake terminal
        # is a fresh object per call, so what is asserted is where the
        # output went.
        self.assertEqual(got["built"], 2)
        self.assertTrue(got["quiet"], "the second session wrote into the "
                                      "first session's disposed terminal")
        self.assertTrue(got["wrote"], "the second session's terminal got "
                                      "nothing")
        self.assertTrue(got["current"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_an_answer_that_is_not_a_state_does_not_kill_the_heartbeat(self):
        """The final review's second Important.

        Everything after the poll's `try` reads `state.state` and
        `state.geometry`, and that tail runs after the only `setTimeout`
        has been consumed. A `/state` answer of `null` -- valid JSON, and
        what a proxy or a route change can hand back -- threw there, the
        rejection was unhandled, and the heartbeat stopped for good: the
        claim then lapsed 240 seconds later under an operator sitting in
        the session. Measured before the check: `rescheduled: 0`.
        """
        for body in ("null", "'<html>maintenance</html>'", "[1,2]", "42"):
            got = self._node(
                "els['opshell-body'] = el('opshell-body');\n"
                "nextReply = {ok:true, status:200, body:%s};\n"
                "let threw = null;\n"
                "try { await opshellPoll(); } catch(e) { threw = String(e); }\n"
                "console.log(JSON.stringify({threw, scheduled,"
                " beating: opshellTimer !== null,"
                " shown: els['opshell-body'].innerHTML}));" % body)
            self.assertIsNone(got["threw"], body)
            self.assertEqual(got["scheduled"], [2000],
                             "the poll did not reschedule itself after %s"
                             % body)
            self.assertTrue(got["beating"], body)
            self.assertRegex(got["shown"], r"(?i)not an object", body)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_new_device_is_not_shown_the_last_ones_duration(self):
        """The final review's third Important.

        `opshellLast` was cleared inside `if(answer.session)`, so an open
        that came back without one -- the channel is down, the start is
        queued -- left the previous session's duration standing, and the
        poll folded it over the next idle answer: the card then said "The
        session lasted 92s" beside a device that never ran it.
        """
        got = self._node(
            "opshellLast = {duration: 92};\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "els['opshell-agent'] = el('opshell-agent');\n"
            "els['opshell-agent'].value = 'badger';\n"
            "replies = [{ok:true, status:200, body:{state:'waiting'}},"
            " {ok:true, status:200, body:{state:'idle', channel:'closed',"
            " host:'badger', candidates:['badger'], target:'badger'}}];\n"
            "await opshellOpen();\n"
            "const held = opshellLast;\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({held,"
            " shown: els['opshell-body'].innerHTML}));")
        self.assertIsNone(got["held"],
                          "the duration survived the device that ran it")
        self.assertNotIn("92", got["shown"])
        self.assertNotRegex(got["shown"], r"(?i)session lasted")
        self.assertIn("badger", got["shown"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_claim_taken_while_the_resume_is_in_flight_is_not_overwritten(self):
        """The final review's fourth Important.

        The resume's `/state` had no deadline, and while it is outstanding
        the view is usable: the operator presses `>_`, is told the channel
        is up and this page is not holding it, and presses Attach. A
        resume that then wrote its remembered id over the adopted one
        orphaned the new claim -- every close answers "not the last" and
        nothing is stopped until the lapse four minutes later. What the
        page did wins; what it remembered does not.
        """
        got = self._node(
            "sessionStorage.setItem(opshellStore, 'remembered');\n"
            "els['main'] = el('main'); els['content'] = el('content');\n"
            "els['main'].appendChild(els['content']);\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot', sessions:1}}];\n"
            "const resuming = opshellResume();\n"
            # What Attach leaves behind while that request is in flight:
            # `opshellOpen`'s own two lines, set here rather than awaited,
            # because which of two pending fetches resolves first is not
            # something a test should depend on.
            "opshellSession = 'adopted'; opshellRemember('adopted');\n"
            "const resumed = await resuming;\n"
            "console.log(JSON.stringify({resumed, session: opshellSession,"
            " remembered: sessionStorage.getItem(opshellStore),"
            " card: !!document.getElementById('opshell-card'),"
            " deadline: posted[0] && posted[0].timeout}));")
        self.assertFalse(got["resumed"])
        self.assertEqual(got["session"], "adopted",
                         "the resume overwrote a claim this page had "
                         "already taken")
        self.assertEqual(got["remembered"], "adopted")
        self.assertFalse(got["card"])
        # And the window is bounded, as the poll's is.
        self.assertEqual(got["deadline"], 8000)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_session_that_did_not_come_back_is_explained_at_the_next_open(self):
        """The final review's fifth Important, its ruling.

        A reload whose session has gone adopts nothing and clears both
        keys, which is the half that matters -- but nothing was said,
        while `docs/TUNNEL.md` promises the card comes back the way it was
        left. The operator was left wondering whether a shell was still
        running somewhere, which is the doubt this feature exists to
        remove, and the page knows the answer: the server said that
        session was not live.

        Said at the next open and not at load, because this feature opens
        only on an explicit action; and said once, because the fact is
        taken out of storage as it is read.
        """
        got = self._node(
            "sessionStorage.setItem(opshellStore, 'gone-1');\n"
            "els['main'] = el('main'); els['content'] = el('content');\n"
            "els['main'].appendChild(els['content']);\n"
            "replies = [{ok:true, status:200, body:{state:'idle',"
            " channel:'closed', sessions:0}},"
            " {ok:true, status:200, body:{state:'idle', channel:'closed'}},"
            " {ok:true, status:200, body:{state:'idle', channel:'closed'}}];\n"
            "const resumed = await opshellResume();\n"
            "const atLoad = !!document.getElementById('opshell-card');\n"
            "const kept = sessionStorage.getItem(opshellStore + '_gone');\n"
            "await showOperatorShell();\n"
            "const first = document.getElementById('opshell-card')"
            ".children.map(c => c.innerHTML).join(' ');\n"
            "const firstNotes = document.getElementById('opshell-card')"
            ".children.filter(c => c.classList.contains('opshell-note'))"
            ".map(c => c.innerHTML);\n"
            "const cleared = sessionStorage.getItem(opshellStore + '_gone');\n"
            "await opshellTeardown(document.getElementById('opshell-card'));\n"
            "await showOperatorShell();\n"
            "const card = document.getElementById('opshell-card');\n"
            "console.log(JSON.stringify({resumed, atLoad, kept: !!kept,"
            " first, firstNotes, cleared,"
            " second: card.children.map(c => c.innerHTML).join(' '),"
            " parts: card.children.length,"
            " notes: card.children.filter(c =>"
            " c.classList.contains('opshell-note')).length}));")
        self.assertFalse(got["resumed"])
        # Nothing opens itself at load: that is the feature's own rule.
        self.assertFalse(got["atLoad"], "a card opened itself at load")
        self.assertTrue(got["kept"], "the reason was not remembered")
        # The next open says it, and says what the page actually knows.
        self.assertRegex(got["first"], r"(?i)gone|no longer")
        self.assertRegex(got["first"], r"(?i)team server")
        # And as a note: the class is what places a node outside
        # `#opshell-body`, and the text alone would pass without it.
        self.assertEqual(len(got["firstNotes"]), 1,
                         "the reason is shown, but not as an .opshell-note")
        self.assertRegex(got["firstNotes"][0], r"(?i)gone|no longer")
        self.assertIsNone(got["cleared"])
        # The one after that does not.
        self.assertNotRegex(got["second"], r"(?i)gone|no longer")
        # Two properties, kept apart. The count is chrome, the empty
        # `#opshell-refused` and the body: anything more is a child nobody
        # drew on purpose, whatever its class.
        self.assertEqual(got["parts"], 3, "the card carries a child beyond "
                         "chrome, #opshell-refused and the body")
        self.assertEqual(got["notes"], 0, "the note outlived its one open")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_parked_panel_with_no_session_does_not_claim_a_shell(self):
        # The card can be parked over the picker: no session, nothing
        # running. The live border, a cursor whose own comment says it
        # blinks while the shell is alive, and "Restore the shell" each
        # claimed more than the view knew.
        got = self._node(
            "opshellSession = null; opshellLast = null;\n"
            "const idle = opshellParked({state:'idle', channel:'closed'});\n"
            "opshellSession = 'sid';\n"
            "const live = opshellParked({state:'live', channel:'open',"
            " host:'parrot'});\n"
            "opshellSession = null; opshellLast = {duration: 92};\n"
            "const ended = opshellParked({state:'idle', channel:'closed',"
            " host:'parrot'});\n"
            "console.log(JSON.stringify({idle, live, ended}));")
        # No session: it restores the panel, and nothing blinks.
        self.assertNotRegex(got["idle"], r"(?i)restore the shell")
        self.assertRegex(got["idle"], r"(?i)restore the panel")
        self.assertNotIn("opshell-cursor", got["idle"])
        # A session this page holds: both.
        self.assertRegex(got["live"], r"(?i)restore the shell")
        self.assertIn("opshell-cursor", got["live"])
        # And a remnant is neither.
        self.assertNotRegex(got["ended"], r"(?i)restore the")
        self.assertNotIn("opshell-cursor", got["ended"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_why_a_parked_session_ended_survives_the_tick_that_ends_it(self):
        """The merge blocker, and the ruling that fixed it.

        On a parked card `opshellEndSession` runs with `opshellTerm` still
        set -- the poll disposes on its *next* tick -- so `opshellSay` put
        the server's reason into the terminal and the panel fallback
        (`!opshellTerm`) was skipped. Two seconds later that tick disposed
        the terminal and replaced the body, and the reason was nowhere:
        measured, `body: ""`, then `disposed: true` with the live render in
        its place, while the dock said only `session ended`.

        So the reason rides on `opshellLast`, beside the duration, which
        is the one thing that crosses a tick.
        """
        got = self._node(
            "opshellSession = 'sid'; opshellStarted = Date.now() - 92000;\n"
            "els['main'] = el('main'); els['content'] = el('content');\n"
            "els['sidebar'] = el('sidebar');\n"
            "els['main'].appendChild(els['content']);\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot'}},"
            " {ok:true, status:200, body:{reason:'another view is holding "
            "this channel, so it stays up'}},"
            " {ok:true, status:200, body:{state:'idle', channel:'closed',"
            " host:'parrot'}}];\n"
            "await showOperatorShell();\n"
            "opshellMinimise();\n"
            "const term = fakeTerm(); opshellTerm = term;\n"
            "await opshellEndSession();\n"
            "const atEnd = [term.lines.join(' ').includes('another view'),"
            " els['opshell-body'].innerHTML.includes('another view'),"
            " term.disposed === true];\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({atEnd,"
            " last: opshellLast,"
            " disposed: term.disposed === true,"
            " body: els['opshell-body'].innerHTML,"
            " dock: els['sidebar'].children[0].innerHTML}));")
        # At the end itself: the terminal has it, the panel does not, and
        # the terminal is still alive -- the state the next tick destroys.
        self.assertEqual(got["atEnd"], [True, False, False])
        # It is in the page's own state, with the duration.
        self.assertEqual(got["last"]["duration"], 92)
        self.assertRegex(got["last"]["why"], r"(?i)another view is holding")
        # And the tick that disposes the terminal draws it into the card,
        # so the restore has both.
        self.assertTrue(got["disposed"])
        self.assertRegex(got["body"], r"(?i)another view is holding")
        self.assertIn("92", got["body"])
        # The dock is unchanged: one line in a 260px column says the
        # session ended, and the sentence is read on the restore.
        self.assertRegex(got["dock"], r"(?i)session ended")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_an_ordinary_exit_explains_nothing_and_is_not_inherited(self):
        # Two of the three conditions on that ruling, in the sequence that
        # breaks them: a session that ended with nothing to explain must
        # not have something said about it -- a render that always finds
        # something to say is the inversion this branch has shipped once
        # already -- and the next session's end must not inherit the last
        # one's sentence.
        got = self._node(
            "opshellSession = 'sid-1'; opshellStarted = Date.now() - 92000;\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "els['opshell-agent'] = el('opshell-agent');\n"
            "els['opshell-agent'].value = 'parrot';\n"
            "replies = [{ok:true, status:200, body:{reason:'another view is "
            "holding this channel'}},"
            " {ok:true, status:200, body:{session:'sid-2'}},"
            " {ok:true, status:200, body:{}},"
            " {ok:true, status:200, body:{state:'idle', channel:'closed'}}];\n"
            "await opshellEndSession();\n"
            "const first = opshellLast;\n"
            "await opshellOpen();\n"
            "const cleared = opshellLast;\n"
            "opshellStarted = Date.now() - 5000;\n"
            "await opshellEndSession();\n"
            "const second = opshellLast;\n"
            "await opshellPoll();\n"
            "const body = els['opshell-body'].innerHTML;\n"
            "console.log(JSON.stringify({first, cleared,"
            " keys: Object.keys(second), second,"
            " body, paras: (body.match(/loot-empty/g)||[]).length}));")
        self.assertRegex(got["first"]["why"], r"(?i)another view")
        # Whatever clears `opshellLast` clears the sentence with it,
        # because the sentence lives inside it.
        self.assertIsNone(got["cleared"])
        self.assertEqual(got["keys"], ["duration"],
                         "the next session's end inherited a sentence")
        self.assertEqual(got["second"]["duration"], 5)
        self.assertNotRegex(got["body"], r"(?i)another view")
        self.assertIn("5s", got["body"])
        # One dim paragraph in that render, the picker's own: an
        # unconditional sentence would be a second, empty one.
        self.assertEqual(got["paras"], 1,
                         "a session with nothing to explain got a "
                         "paragraph anyway")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_reason_a_session_ended_is_stated_once(self):
        # The third condition: the strip already prints `state.reason`
        # whenever the server sends one, and the server's reason for a
        # channel that would not stop is the same sentence the close came
        # back with. Said twice, two paragraphs apart, it reads as two
        # facts.
        got = self._node(
            "const same = opshellRender({state:'closed', duration:92,"
            " why:'another view is holding this channel',"
            " reason:'another view is holding this channel'});\n"
            "const differs = opshellRender({state:'closed', duration:92,"
            " why:'another view is holding this channel',"
            " reason:'the device has not called home for two hours'});\n"
            "console.log(JSON.stringify({"
            " sameCount: (same.match(/another view/g)||[]).length,"
            " differsCount: (differs.match(/another view/g)||[]).length,"
            " kept: differs.includes('called home')}));")
        self.assertEqual(got["sameCount"], 1,
                         "the same sentence was printed twice")
        # And a different one from the server is not swallowed by it.
        self.assertEqual(got["differsCount"], 1)
        self.assertTrue(got["kept"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_card_that_came_back_is_not_told_its_shell_is_gone(self):
        # `showOperatorShell` returns early when a card already exists, so
        # a `_gone` written while the panel was open is read by nobody and
        # stays. Then a session is started, parked, and the page reloaded:
        # the resume succeeds, and the note was appended above a live,
        # restored terminal. The resume clears it where it adopts: a page
        # putting a card back owes no explanation.
        got = self._node(
            "sessionStorage.setItem(opshellStore, 'kept');\n"
            "sessionStorage.setItem(opshellStore + '_gone',"
            " 'The shell this tab had open is gone: the team server does "
            "not report that session as live.');\n"
            "els['main'] = el('main'); els['content'] = el('content');\n"
            "els['sidebar'] = el('sidebar');\n"
            "els['main'].appendChild(els['content']);\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot', sessions:1}},"
            " {ok:true, status:200, body:{state:'live', channel:'open',"
            " host:'parrot'}}];\n"
            "const resumed = await opshellResume();\n"
            "const card = document.getElementById('opshell-card');\n"
            "console.log(JSON.stringify({resumed,"
            " parts: card.children.length,"
            " notes: card.children.filter(c =>"
            " c.classList.contains('opshell-note')).length,"
            " html: card.children.map(c => c.innerHTML).join(' '),"
            " gone: sessionStorage.getItem(opshellStore + '_gone')}));")
        self.assertTrue(got["resumed"])
        # Two properties, kept apart, as in the test above.
        self.assertEqual(got["parts"], 3, "the card carries a child beyond "
                         "chrome, #opshell-refused and the body")
        self.assertEqual(got["notes"], 0,
                         "the note was drawn over a card that came back")
        self.assertNotRegex(got["html"], r"(?i)is gone")
        self.assertIsNone(got["gone"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_non_ascii_keystrokes_survive_the_encoding(self):
        # The old encoder was `btoa(unescape(encodeURIComponent(d)))`,
        # which works but leans on a deprecated function.
        got = self._node(
            "console.log(JSON.stringify({b64: opshellB64('\\u00e4\\u20ac')}));")
        self.assertEqual(base64.b64decode(got["b64"]).decode("utf-8"), "\u00e4\u20ac")


if __name__ == "__main__":
    unittest.main()
