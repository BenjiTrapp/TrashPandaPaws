#!/usr/bin/env python3
"""
Regression tests for the security-audit remediation of the C2 beacon and
team server.
"""

import base64
import json
import os
import re
import shutil
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from software.c2 import beacon as beacon_mod
from software.c2 import server as server_mod
from software.c2.beacon import Beacon


PLAINTEXT_TASKING = {"tasks": [{"cmd": "shell", "args": "id"}]}


def _plaintext_b64() -> bytes:
    """The tasking a keyless party would send: b64(json), never encrypted."""
    return base64.b64encode(json.dumps(PLAINTEXT_TASKING).encode())


def _config(**transport):
    c2 = {
        "beacon_interval_seconds": 10,
        "jitter_percent": 20,
        "encryption_key": "",
        "proxy": {"mode": "none"},
        "https": {"enabled": False},
        "dns": {"enabled": False},
    }
    c2.update(transport)
    return {"c2": c2}


def _dns_beacon():
    return Beacon(_config(dns={"enabled": True, "domain": "c2.test",
                               "resolver": "8.8.8.8"}))


def _smb_beacon():
    return Beacon(_config(smb={"enabled": True, "server": "smb.test"}))


def _quic_beacon():
    return Beacon(_config(quic={"enabled": True, "server": "quic.test"}))


def _one_checkin(b):
    """Run exactly one pass of the real _beacon_loop and return every task
    that reached _process_tasking, i.e. everything that would have executed."""
    executed = []

    def stop(*_args, **_kwargs):
        b._running = False

    b._running = True
    with patch.object(b, "_process_tasking", side_effect=executed.append), \
            patch.object(b, "_jittered_sleep", side_effect=stop), \
            patch.object(b, "_backoff_sleep", side_effect=stop):
        b._beacon_loop()
    return executed


class _FakeUdp:
    """Stands in for the QUIC transport's UDP socket: swallows the request
    and answers with one datagram carrying the given payload."""

    def __init__(self, response_payload: bytes):
        frame = struct.pack(">I", len(response_payload)) + response_payload
        self._datagram = struct.pack(">IHH", 1, 0, 1) + frame
        self._sent = False

    def settimeout(self, _t):
        pass

    def sendto(self, _data, _addr):
        pass

    def recvfrom(self, _n):
        if self._sent:
            raise socket.timeout()
        self._sent = True
        return self._datagram, ("quic.test", 4433)

    def close(self):
        pass


class TestAeadIsNotOptional(unittest.TestCase):
    """Decryption failing is a failed exchange, never instructions."""

    # _encrypt takes a dict but the SMB and QUIC request legs hand it bytes,
    # so it raises before any response is read. Stubbing it lets these tests
    # reach the response leg, which is the one under test.
    def _smb_returning(self, b, response: bytes):
        return (patch.object(b, "_encrypt", return_value="req"),
                patch.object(b, "_smb_connect", return_value=MagicMock()),
                patch.object(b, "_smb_write_pipe", return_value=True),
                patch.object(b, "_smb_read_pipe", return_value=response))

    def _quic_returning(self, b, response: bytes):
        return (patch.object(b, "_encrypt", return_value="req"),
                patch.object(beacon_mod.socket, "socket",
                             side_effect=lambda *a, **k: _FakeUdp(response)))

    def _enter(self, patches):
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_dns_plaintext_tasking_is_refused(self):
        b = _dns_beacon()
        with patch.object(beacon_mod, "_dns_query",
                          return_value=[_plaintext_b64().decode()]):
            self.assertIsNone(b._beacon_dns())
            executed = _one_checkin(b)
        self.assertEqual(executed, [])

    # The SMB and QUIC fallbacks parsed the raw response bytes, the DNS one
    # parsed b64(json); a keyless party can use either shape.
    def _plaintext_shapes(self):
        return (("b64", _plaintext_b64()),
                ("raw", json.dumps(PLAINTEXT_TASKING).encode()))

    def test_smb_plaintext_tasking_is_refused(self):
        for shape, response in self._plaintext_shapes():
            with self.subTest(shape=shape):
                b = _smb_beacon()
                self._enter(self._smb_returning(b, response))
                self.assertIsNone(b._beacon_smb())
                self.assertEqual(_one_checkin(b), [])

    def test_quic_plaintext_tasking_is_refused(self):
        for shape, response in self._plaintext_shapes():
            with self.subTest(shape=shape):
                b = _quic_beacon()
                self._enter(self._quic_returning(b, response))
                self.assertIsNone(b._beacon_quic())
                self.assertEqual(_one_checkin(b), [])

    def test_undecryptable_response_is_a_failed_checkin_not_an_empty_one(self):
        # An empty-but-successful check-in resets the failure counter, so the
        # fifth consecutive failure would never trigger re-registration.
        b = _dns_beacon()
        b._registered = True
        b._consecutive_failures = 4
        with patch.object(beacon_mod, "_dns_query",
                          return_value=[_plaintext_b64().decode()]), \
                patch.object(b, "_register_https") as register:
            executed = _one_checkin(b)
        self.assertEqual(executed, [])
        self.assertEqual(b._consecutive_failures, 5)
        register.assert_called_once()
        self.assertFalse(b._registered)

    def test_dns_one_bad_record_does_not_abort_the_remaining_records(self):
        b = _dns_beacon()
        genuine = {"tasks": [{"cmd": "pwd", "id": "t1"}]}
        records = [_plaintext_b64().decode(), "not-base64-at-all!!",
                   b._encrypt(genuine)]
        with patch.object(beacon_mod, "_dns_query", return_value=records):
            self.assertEqual(b._beacon_dns(), genuine)
            executed = _one_checkin(b)
        self.assertEqual(executed, genuine["tasks"])

    def test_encrypted_responses_still_work_on_every_channel(self):
        genuine = {"tasks": [{"cmd": "pwd", "id": "t1"}]}

        dns = _dns_beacon()
        with patch.object(beacon_mod, "_dns_query",
                          return_value=[dns._encrypt(genuine)]):
            self.assertEqual(dns._beacon_dns(), genuine)

        smb = _smb_beacon()
        self._enter(self._smb_returning(smb, smb._encrypt(genuine).encode()))
        self.assertEqual(smb._beacon_smb(), genuine)

        quic = _quic_beacon()
        self._enter(self._quic_returning(quic, quic._encrypt(genuine).encode()))
        self.assertEqual(quic._beacon_quic(), genuine)


class TestGuiEscaping(unittest.TestCase):
    """Agent-reported values must be escaped before they reach the DOM.

    The operator interface is a Python string and the project has no
    JavaScript runner, so the DOM-side checks locate one specific construct
    in that string and assert on it. The coercion checks go through the real
    beacon route.
    """

    TOKEN = "test-operator-token"

    @staticmethod
    def _line_with(needle, source=None):
        source = server_mod._OPERATOR_HTML if source is None else source
        lines = [ln for ln in source.splitlines() if needle in ln]
        assert len(lines) == 1, "%r matched %d lines" % (needle, len(lines))
        return lines[0]

    def setUp(self):
        server_mod.agents.clear()
        server_mod.task_queues.clear()
        server_mod.history.clear()
        self.addCleanup(server_mod.agents.clear)
        self.addCleanup(server_mod.task_queues.clear)
        self.addCleanup(server_mod.history.clear)

    def test_esc_escapes_single_quote(self):
        html = server_mod._OPERATOR_HTML
        body = re.search(r"function esc\(s\)\{(.*?)\n\}", html, re.S).group(1)
        replacements = re.findall(r'\.replace\(/(.)/g,"([^"]*)"\)', body)
        self.assertEqual(replacements, [
            ("&", "&amp;"),
            ("<", "&lt;"),
            (">", "&gt;"),
            ('"', "&quot;"),
            ("'", "&#39;"),
        ])

    def test_agent_reported_pid_is_escaped(self):
        line = self._line_with("PID ${")
        self.assertIn("PID ${esc(info.pid", line)
        self.assertNotIn("${info.pid", line)

    def test_beacon_config_interval_is_escaped(self):
        line = self._line_with('id="cfg-interval"')
        self.assertIn('value="${esc(curInterval)}"', line)
        self.assertNotIn('value="${curInterval}"', line)

    def _tbl_definitions_after(self, marker):
        html = server_mod._OPERATOR_HTML
        tail = html[html.index(marker):]
        return [ln for ln in tail.splitlines()
                if ln.lstrip().startswith("const tbl = (label, val)")]

    def test_last_request_header_names_are_escaped(self):
        # The header name is the `k` of Object.entries(lr.headers), handed to
        # the tbl helper defined in the _last_request block as its label.
        tbl = self._tbl_definitions_after("const lr = info._last_request;")[0]
        self.assertIn("+esc(label)+", tbl)
        self.assertNotIn("+label+", tbl)
        self.assertIn("rhtml += tbl(k, v);", server_mod._OPERATOR_HTML)

    def test_beacon_profile_table_labels_are_escaped(self):
        tbl = self._tbl_definitions_after(
            'const prof = info.c2_profile;')[0]
        self.assertIn("+esc(label)+", tbl)
        self.assertNotIn("+label+", tbl)

    def test_process_id_regexp_only_accepts_an_integer(self):
        self._line_with('new RegExp("(^|\\\\s)"+pid')
        assign = self._line_with("const pid = info")
        self.assertIn("Number.isInteger(info.pid)", assign)

    def _post(self, client, crypto, payload):
        return client.post("/api/v1/beacon",
                           data=json.dumps(crypto.wrap(payload)),
                           content_type="application/json")

    def _app(self):
        crypto = server_mod.ServerCrypto(b"k" * 32)
        data_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, data_dir, True)
        app = server_mod.create_app(crypto, self.TOKEN, data_dir)
        app.config["TESTING"] = True
        return app.test_client(), crypto

    def _list_agents(self, client):
        return client.get("/api/agents",
                          headers={"Authorization": "Bearer " + self.TOKEN})

    def _register(self, client, crypto, **fields):
        payload = {"action": "register", "id": "implant-1",
                   "hostname": "h", "user": "u"}
        payload.update(fields)
        self._post(client, crypto, payload)
        self.assertEqual(len(server_mod.agents), 1)
        return next(iter(server_mod.agents.values()))

    def test_pid_from_a_beacon_is_coerced_to_int(self):
        client, crypto = self._app()
        hostile = "<img src=x onerror=alert(1)>"
        agent = self._register(client, crypto, pid=hostile)
        self.assertEqual(agent["pid"], 0)
        self.assertIsInstance(agent["pid"], int)

        self._post(client, crypto, {"action": "register", "id": "implant-1",
                                    "pid": hostile})
        self.assertEqual(agent["pid"], 0)

        self._post(client, crypto, {"action": "register", "id": "implant-1",
                                    "pid": "4242"})
        self.assertEqual(agent["pid"], 4242)

    def test_interval_from_a_beacon_is_coerced_to_int(self):
        client, crypto = self._app()
        agent = self._register(client, crypto, interval="soon")
        self.assertEqual(agent["interval"], 300)
        self.assertIsInstance(agent["interval"], int)
        self.assertEqual(self._list_agents(client).status_code, 200)

        agent["interval"] = 30
        self._post(client, crypto, {"action": "register", "id": "implant-1",
                                    "interval": "soon"})
        self.assertEqual(agent["interval"], 300)
        self.assertEqual(self._list_agents(client).status_code, 200)

    def test_uptime_from_a_beacon_is_coerced_to_int(self):
        client, crypto = self._app()
        hostile = "<img src=x onerror=alert(1)>"
        agent = self._register(client, crypto, uptime=hostile)
        self.assertEqual(agent["uptime"], 0)
        self.assertIsInstance(agent["uptime"], int)
        self.assertEqual(self._list_agents(client).status_code, 200)

        for hostile_uptime in (hostile, [5], {"a": 1}, " 5 x"):
            self._post(client, crypto, {"action": "beacon",
                                        "agent_id": agent["agent_id"],
                                        "uptime": hostile_uptime})
            self.assertEqual(agent["uptime"], 0)
            self.assertIsInstance(agent["uptime"], int)
        self.assertEqual(self._list_agents(client).status_code, 200)

        self._post(client, crypto, {"action": "beacon",
                                    "agent_id": agent["agent_id"],
                                    "uptime": 3600})
        self.assertEqual(agent["uptime"], 3600)

    def test_as_int_pins_how_agent_numbers_are_read(self):
        D = -1  # a default no input below can produce by accident
        cases = [
            # ints and numeric strings
            (7, 7), ("7", 7), (" 7 ", 7),
            # a float and its string form behave the same: truncated
            (5.7, 5), ("5.7", 5), (-5.7, -5), ("-5.7", -5), ("1e3", 1000),
            # range is deliberately not validated: zero and negatives are
            # stored as reported
            (0, 0), (-3, -3), ("-3", -3),
            # a bool is not a number an agent would report
            (True, D), (False, D),
            # not finite
            (float("nan"), D), (float("inf"), D), (float("-inf"), D),
            ("nan", D), ("inf", D), ("1e999", D),
            # not numbers
            (None, D), ("", D), ("soon", D), ("0x10", D),
            ("<img src=x onerror=alert(1)>", D),
            ([5], D), ({"a": 5}, D),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(server_mod._as_int(value, D), expected)
                self.assertIs(type(server_mod._as_int(value, D)), int)

        # the default is returned as given, not itself coerced
        self.assertEqual(server_mod._as_int(None, 300), 300)

    def test_interval_on_a_beacon_checkin_is_coerced_and_route_survives(self):
        client, crypto = self._app()
        agent = self._register(client, crypto, interval=30)
        self._post(client, crypto, {"action": "beacon",
                                    "agent_id": agent["agent_id"],
                                    "interval": "<b>x</b>"})
        self.assertEqual(agent["interval"], 30)
        self.assertIsInstance(agent["interval"], int)
        self.assertEqual(self._list_agents(client).status_code, 200)


class TestLootWriteIsContained(unittest.TestCase):
    """A file an agent sends lands inside the directory meant for it.

    Everything runs under one temporary root that holds the data directory and
    a sibling directory standing in for "anywhere else on the host". Escapes
    are detected by walking that root, never by trusting a return value.
    """

    TOKEN = "test-operator-token"
    SUBS = (("loot", True), ("downloads", False))

    def setUp(self):
        server_mod.agents.clear()
        server_mod.task_queues.clear()
        server_mod.history.clear()
        self.addCleanup(server_mod.agents.clear)
        self.addCleanup(server_mod.task_queues.clear)
        self.addCleanup(server_mod.history.clear)

        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.data_dir = self.root / "data"
        self.data_dir.mkdir()
        self.elsewhere = self.root / "elsewhere"
        self.elsewhere.mkdir()

        self.crypto = server_mod.ServerCrypto(b"k" * 32)
        app = server_mod.create_app(self.crypto, self.TOKEN, self.data_dir)
        app.config["TESTING"] = True
        self.client = app.test_client()

    def _post(self, payload):
        return self.client.post("/api/v1/beacon",
                                data=json.dumps(self.crypto.wrap(payload)),
                                content_type="application/json")

    def _register(self):
        resp = self._post({"action": "register", "id": "implant-1",
                           "hostname": "h", "user": "u"})
        return self.crypto.unwrap(resp.get_json())["agent_id"]

    def _send_file(self, agent_id, loot, filename="note.txt", body=b"payload"):
        return self._post({
            "action": "result", "task_id": "t1", "agent_id": agent_id,
            "status": "ok", "output": "",
            "data": {"data": base64.b64encode(body).decode(),
                     "filename": filename, "loot": loot},
        })

    def _written_files(self):
        """Every file under the temp root, except the server's own state."""
        found = []
        for dirpath, _dirs, files in os.walk(self.root):
            for name in files:
                path = Path(dirpath) / name
                if path != self.data_dir / "state.json":
                    found.append(path)
        return found

    def _assert_nothing_written(self):
        self.assertEqual(self._written_files(), [])

    def _assert_no_agent_directories(self):
        for sub, _loot in self.SUBS:
            base = self.data_dir / sub
            self.assertEqual(list(base.iterdir()) if base.exists() else [], [])

    def test_absolute_agent_id_cannot_escape_the_loot_dir(self):
        self._register()
        for _sub, loot in self.SUBS:
            self._send_file(str(self.elsewhere), loot)
        self.assertEqual(list(self.elsewhere.iterdir()), [])
        self._assert_nothing_written()

    def test_dotdot_agent_id_cannot_escape(self):
        self._register()
        for agent_id in ("../../elsewhere", "..", "../..",
                         "../downloads", "./../../elsewhere"):
            for _sub, loot in self.SUBS:
                with self.subTest(agent_id=agent_id, loot=loot):
                    self._send_file(agent_id, loot)
        self.assertEqual(list(self.elsewhere.iterdir()), [])
        self._assert_nothing_written()

    def test_empty_agent_id_writes_nothing(self):
        self._register()
        for agent_id in ("", None, ".", 0):
            for _sub, loot in self.SUBS:
                with self.subTest(agent_id=agent_id, loot=loot):
                    self._send_file(agent_id, loot)
        self._assert_nothing_written()

    def test_unregistered_agent_creates_no_directory(self):
        self._register()
        for _sub, loot in self.SUBS:
            self._send_file("raccoon-never-registered", loot)
        self._assert_nothing_written()
        self._assert_no_agent_directories()
        self.assertFalse(
            (self.data_dir / "loot" / "raccoon-never-registered").exists())
        self.assertFalse(
            (self.data_dir / "downloads" / "raccoon-never-registered").exists())

    def test_a_registry_entry_that_is_itself_hostile_is_still_contained(self):
        # Registered or not, the resolved directory must sit under the base:
        # state.json is loaded into `agents`, so the registry is not a
        # guarantee on its own.
        for hostile in ("../../elsewhere", str(self.elsewhere), ".."):
            server_mod.agents[hostile] = {"agent_id": hostile, "id": "x"}
            for _sub, loot in self.SUBS:
                with self.subTest(agent_id=hostile, loot=loot):
                    self._send_file(hostile, loot)
        self.assertEqual(list(self.elsewhere.iterdir()), [])
        self._assert_nothing_written()

    def test_an_agent_directory_that_is_a_symlink_out_is_not_followed(self):
        agent_id = self._register()
        for sub, loot in self.SUBS:
            (self.data_dir / sub).mkdir(exist_ok=True)
            os.symlink(self.elsewhere, self.data_dir / sub / agent_id)
            self._send_file(agent_id, loot)
        self.assertEqual(list(self.elsewhere.iterdir()), [])

    def test_filename_with_separators_is_flattened(self):
        agent_id = self._register()
        hostile = ["../../elsewhere/pwn", "/etc/passwd", "a/b/c.txt",
                   "..\\..\\elsewhere\\pwn", "../", "..", "", "x\x00y.txt",
                   "sp ace;`id`$(x).txt"]
        for filename in hostile:
            for _sub, loot in self.SUBS:
                with self.subTest(filename=filename, loot=loot):
                    self._send_file(agent_id, loot, filename=filename)
        self.assertEqual(list(self.elsewhere.iterdir()), [])
        files = self._written_files()
        self.assertTrue(files)
        for sub, _loot in self.SUBS:
            agent_dir = self.data_dir / sub / agent_id
            self.assertTrue(agent_dir.is_dir())
            # flat: only plain files directly in the agent directory
            self.assertEqual([p for p in agent_dir.iterdir()
                              if not p.is_file()], [])
        for path in files:
            self.assertIn(path.parent, (self.data_dir / "loot" / agent_id,
                                        self.data_dir / "downloads" / agent_id))
            self.assertRegex(path.name, r"^[A-Za-z0-9._-]+$")

    def test_a_registered_agent_still_receives_its_loot(self):
        agent_id = self._register()
        for sub, loot in self.SUBS:
            resp = self._send_file(agent_id, loot, filename="creds.txt",
                                   body=b"secret-" + sub.encode())
            self.assertEqual(resp.status_code, 200)
            written = list((self.data_dir / sub / agent_id).iterdir())
            self.assertEqual(len(written), 1)
            self.assertTrue(written[0].name.endswith("_creds.txt"))
            self.assertEqual(written[0].read_bytes(),
                             b"secret-" + sub.encode())
        self.assertEqual(len(self._written_files()), 2)

    def test_a_rejected_write_answers_exactly_like_an_accepted_one(self):
        agent_id = self._register()
        accepted = self._send_file(agent_id, True)
        rejected = self._send_file(str(self.elsewhere), True)
        unknown = self._send_file("raccoon-never-registered", True)
        for resp in (accepted, rejected, unknown):
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(self.crypto.unwrap(resp.get_json()),
                             {"ack": True})
        self.assertEqual(len(self._written_files()), 1)


# New test classes belong above this guard; never append below it.
if __name__ == "__main__":
    unittest.main()
