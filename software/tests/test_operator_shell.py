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


class TestTheGlyphAndTheView(_GuiCase):
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
        rules = self.css_rules("opshell-card")
        self.assertGreaterEqual(len(rules), 1)
        for body in rules:
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

        Measured across the page: optional chaining and the Clipboard API,
        both Safari 13.1, and nothing newer -- until `AbortSignal.timeout`
        (Safari 16) went in uncalled-for. It threw inside the poll on an
        older browser and killed the heartbeat.

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
                    "is newer than this page's own baseline of Safari 13.1"
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
        """Seventy-nine tests hide behind `skipUnless(node)`.

        They are the only defence the interface has -- the grep tests
        cannot see a swallowed error, a missing control or a close that
        never happens. A box without node loses all of them and reports
        success, which is the same shape as the five tests this branch
        once deleted while the suite went green.

        One loud failure instead of seventy-nine quiet skips.
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
        # its title brought two, and 77 against 79 once minimise, the park,
        # the restore, the remnant's own cross and a review's five
        # bypasses brought eighteen -- one of which, a grep that ran no
        # node, left for the class that reads the source --
        self.assertGreaterEqual(
            len(names), 77,
            "only %d behavioural view tests remain; a named safety test was "
            "once deleted while the total went up" % len(names))
        # -- and the properties that each cost this branch a Critical are
        # named one by one, because a count cannot defend a property.
        for must in ("test_what_is_typed_during_a_failing_batch_dies_with_it",
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
                     "test_the_card_sits_in_the_content_column_and_not_inside_content"):
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
            "opshellSay", "opshellDropRest", "opshellFlushKeys",
            "opshellEndAfterAttach", "opshellRemember", "opshellRecall",
            "opshellResume", "showOperatorShell", "opshellChrome",
            "opshellClose", "opshellMinimise", "opshellRestore",
            "opshellParked", "opshellRetitle", "opshellPoll",
            "opshellAttach")]) + "\n"
        # The one module constant the keystroke path reads.
        const = re.search(r"^const OPSHELL_KEYS_CEILING = .*$",
                          SERVER_SRC, re.M)
        self.assertIsNotNone(const, "the request ceiling is gone")
        src = const.group(0) + "\n" + src
        out = subprocess.run(
            ["node", "--input-type=module", "-e", env + src + script],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0,
                         "node failed:\n" + out.stderr[-1500:])
        return json.loads(out.stdout.strip().splitlines()[-1])

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
            "nextReply = {ok:false, status:409, body:"
            "{error:'the tunnel server would not start: port in use'}};\n"
            "await opshellOpen();\n"
            "console.log(JSON.stringify({shown: els['opshell-body'].innerHTML,"
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
        """`AbortSignal.timeout` is Safari 16; this interface is Safari 13.1.

        Measured against the rest of the page: 164 uses of optional
        chaining (2020) and the Clipboard API (Safari 13.1), and nothing
        newer than that -- until I added a 2022 feature and called it
        unconditionally. On an older browser that throws a TypeError inside
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
        # arrives that late too. No timer is run here, and the queue holds
        # exactly the poll and the close, so a poll sneaking in would be an
        # error rather than a free pass.
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
            "const parked = els['sidebar'].children[0];\n"
            "const before = parked.innerHTML;\n"
            "await opshellEndSession();\n"
            "console.log(JSON.stringify({before, after: parked.innerHTML,"
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
        self.assertEqual(got["urls"],
                         ["/api/opshell/state", "/api/opshell/close"])

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
            " channel:'open', host:'parrot'}},"
            " {ok:true, status:200, body:{state:'live',"
            " channel:'closed', host:'parrot'}}];\n"
            "await opshellPoll();\n"
            "const mark = document.createElement('b');\n"
            "dock.appendChild(mark);\n"
            "await opshellPoll();\n"
            "const quiet = [dock.htmlWrites.length, mark.parentNode !== null];\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({quiet,"
            " writes: dock.htmlWrites.length,"
            " kept: mark.parentNode !== null}));")
        # Two writes: the park's own, and the first poll's label. The
        # second poll said the same thing and wrote nothing.
        self.assertEqual(got["quiet"], [2, True],
                         "a tick that changed nothing rewrote the dock, "
                         "and took the buttons in it with it")
        # And the tick that does change it writes, or the label would be
        # the lie the refresh exists to prevent.
        self.assertEqual(got["writes"], 3)
        self.assertFalse(got["kept"])

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
        # The quote that would end the title attribute, and the one that
        # would end a single-quoted one.
        self.assertIn("&quot;", got["html"])
        self.assertIn("&#39;", got["html"])

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
    def test_non_ascii_keystrokes_survive_the_encoding(self):
        # The old encoder was `btoa(unescape(encodeURIComponent(d)))`,
        # which works but leans on a deprecated function.
        got = self._node(
            "console.log(JSON.stringify({b64: opshellB64('\\u00e4\\u20ac')}));")
        self.assertEqual(base64.b64decode(got["b64"]).decode("utf-8"), "\u00e4\u20ac")


if __name__ == "__main__":
    unittest.main()
