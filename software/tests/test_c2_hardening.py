#!/usr/bin/env python3
"""
Regression tests for the security-audit remediation of the C2 beacon and
team server.
"""

import ast
import base64
import contextlib
import io
import json
import os
import re
import shlex
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from collections import namedtuple
from pathlib import Path, PurePosixPath
from unittest.mock import MagicMock, patch

from cryptography.exceptions import InvalidTag
from werkzeug.serving import WSGIRequestHandler, make_server

from software.c2 import beacon as beacon_mod
from software.c2 import server as server_mod
from software.c2.beacon import Beacon
from tools.demo_env import key_b64, random_key


PLAINTEXT_TASKING = {"tasks": [{"cmd": "shell", "args": "id"}]}


def _plaintext_b64() -> bytes:
    """The tasking a keyless party would send: b64(json), never encrypted."""
    return base64.b64encode(json.dumps(PLAINTEXT_TASKING).encode())


def _config(**transport):
    c2 = {
        "beacon_interval_seconds": 10,
        "jitter_percent": 20,
        "encryption_key": key_b64(random_key()),
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
            resp = self._send_file(agent_id, loot)
            self.assertEqual(self.crypto.unwrap(resp.get_json()),
                             {"ack": True})
        # Both halves: nothing landed behind the link, and nothing landed
        # anywhere else either (a fallback directory, a flattened copy).
        self.assertEqual(list(self.elsewhere.iterdir()), [])
        self._assert_nothing_written()
        for sub, _loot in self.SUBS:
            link = self.data_dir / sub / agent_id
            self.assertTrue(link.is_symlink())
            self.assertEqual(os.listdir(link), [])
            self.assertEqual(os.listdir(self.data_dir / sub), [agent_id])
        self.assertEqual(sorted(os.listdir(self.data_dir)),
                         ["downloads", "loot", "state.json"])

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

    def test_undecodable_data_answers_the_same_for_known_and_unknown_agents(self):
        # A registered id must not be distinguishable from an unregistered
        # one by sending data that cannot be decoded.
        known = self._register()
        for garbage in ("A", "abcde", 12345, ["x"], {"k": "v"}):
            for _sub, loot in self.SUBS:
                responses = []
                for agent_id in (known, "raccoon-never-registered"):
                    resp = self._post({
                        "action": "result", "task_id": "t1",
                        "agent_id": agent_id, "status": "ok", "output": "",
                        "data": {"data": garbage, "filename": "f.txt",
                                 "loot": loot},
                    })
                    responses.append(resp)
                with self.subTest(garbage=garbage, loot=loot):
                    for resp in responses:
                        self.assertEqual(resp.status_code, 200)
                        self.assertEqual(self.crypto.unwrap(resp.get_json()),
                                         {"ack": True})
                        # the unkeyed catch-all body is the other shape
                        self.assertNotEqual(resp.get_json(),
                                            {"status": "ok",
                                             "version": "2.1.0"})
        self._assert_nothing_written()
        self._assert_no_agent_directories()

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


_REPO = Path(__file__).resolve().parents[2]
_BOOTSTRAP = _REPO / "software" / "setup" / "bootstrap.sh"
_UNIT_DIR = _REPO / "services"

_SHELL_SEPARATORS = {";", "&&", "||", "|", "&"}
_SHELL_PREFIXES = {"if", "elif", "then", "else", "do", "while", "until", "!",
                   "{", "sudo", "command", "exec", "time"}

_Chown = namedtuple("_Chown", "owner recursive contents path source")
_Reach = namedtuple("_Reach", "paths trees")


def _command_start(words):
    """Drop what precedes a command: keywords, sudo, a ``name()`` header."""
    while words:
        if words[0] in _SHELL_PREFIXES:
            words = words[1:]
        elif words[1:2] == ["()"] or words[1:3] == ["(", ")"]:
            words = words[2:] if words[1] == "()" else words[3:]
        else:
            break
    return words


def _shell_commands(text):
    """Each simple command in a shell script as a list of unquoted words.

    This recognises the spellings bootstrap.sh uses; it is not a general
    shell parser (``find -exec chown``, ``xargs chown``, ``/bin/chown``,
    ``C=chown; $C`` and ``install -o`` are invisible to it).
    """
    commands = []
    for line in re.sub(r"\\\n", " ", text).splitlines():
        lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        try:
            words = list(lexer)
        except ValueError:  # an unbalanced quote: prose in a heredoc
            continue
        command = []
        for word in words + [";"]:
            if word not in _SHELL_SEPARATORS:
                command.append(word)
                continue
            command = _command_start(command)
            if command:
                commands.append(command)
            command = []
    return commands


def _expand_variables(word, variables):
    return re.sub(r"\$\{(\w+)\}|\$(\w+)",
                  lambda m: variables.get(m.group(1) or m.group(2), m.group(0)),
                  word)


def _expand_braces(word):
    m = re.search(r"\{([^{}]*,[^{}]*)\}", word)
    if not m:
        return [word]
    return [out for alt in m.group(1).split(",")
            for out in _expand_braces(word[:m.start()] + alt + word[m.end():])]


def _installer_chowns(script):
    """(variables, [_Chown]) for every ownership change the script makes.

    ``owner`` is "root" or "user": anything that is not root is the
    unprivileged account, however it is spelled. A target the reader cannot
    resolve raises instead of being skipped, so a spelling it does not
    understand cannot pass the tests by being invisible to them.
    """
    variables = {}
    chowns = []
    for words in _shell_commands(script):
        assignment = re.fullmatch(r"([A-Za-z_]\w*)=(.*)", words[0])
        if len(words) == 1 and assignment:
            variables[assignment.group(1)] = _expand_variables(
                assignment.group(2), variables)
            continue
        if words[0] != "chown":
            continue
        recursive, operands, options_done = False, [], False
        for word in words[1:]:
            if not options_done and word == "--":
                options_done = True
            elif not options_done and word.startswith("--"):
                recursive = recursive or word == "--recursive"
            elif not options_done and re.fullmatch(r"-[A-Za-z]+", word):
                recursive = recursive or "R" in word
            else:
                operands.append(word)
        owner = re.split(r"[:.]", operands[0], maxsplit=1)[0]
        if owner == "":  # ":group" changes the group only
            continue
        kind = "root" if owner in ("root", "0") else "user"
        for operand in operands[1:]:
            for target in _expand_braces(_expand_variables(operand, variables)):
                contents = target.endswith("/*")
                if contents:
                    target = target[:-2]
                if re.search(r"[$*?\[`]", target) or not target.startswith("/"):
                    raise AssertionError(
                        "cannot resolve chown target %r in: %s"
                        % (target, " ".join(words)))
                chowns.append(_Chown(kind, recursive, contents,
                                     PurePosixPath(target), " ".join(words)))
    return variables, chowns


def _installer_chmods(script, variables):
    """{path: mode} for the last chmod that named each path."""
    modes = {}
    for words in _shell_commands(script):
        if words[0] != "chmod":
            continue
        operands = [w for w in words[1:] if not re.fullmatch(r"--?[A-Za-z-]*", w)]
        for operand in operands[1:]:
            for path in _expand_braces(_expand_variables(operand, variables)):
                modes[str(PurePosixPath(path))] = operands[0]
    return modes


def _owner_of(chowns, path):
    """Who owns ``path`` once the script has run; untouched means root."""
    path = PurePosixPath(path)
    owner = "root"
    for c in chowns:
        if c.contents:
            hit = (path != c.path and c.path in path.parents
                   and (c.recursive or path.parent == c.path))
        else:
            hit = path == c.path or (c.recursive and c.path in path.parents)
        if hit:
            owner = c.owner
    return owner


def _handed_away(chowns, path):
    """True when ``path`` or a directory above it belongs to the user.

    A user who owns the directory holding a file can replace that file, so
    owning an ancestor is as good as owning the file.
    """
    path = PurePosixPath(path)
    return any(_owner_of(chowns, p) == "user" for p in [path, *path.parents])


def _tree_handed_away(chowns, tree):
    """True when ``tree``, or anything inside it, ends up user-owned."""
    tree = PurePosixPath(tree)
    if _handed_away(chowns, tree):
        return True
    for c in chowns:
        affected = c.path / "*" if c.contents else c.path
        if (c.owner == "user" and tree in affected.parents
                and _owner_of(chowns, affected) == "user"):
            return True
    return False


def _unit_reach(text):
    """What root executes or reads for a systemd unit; None if not root.

    ``paths`` need only be unowned by the user themselves and their parent
    directories: the interpreter, its arguments, the working directory, the
    PYTHONPATH entries, and the module a ``-m`` line imports. ``trees`` are
    code root imports wholesale, so nothing inside them may be user-owned
    either: each ``-m`` package, and the virtualenv a ``bin/python`` is in.
    systemd runs a system unit as root unless it names another User=.
    """
    user, workdir, pythonpath, execs, section = "root", None, [], [], None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line
        elif section == "[Service]" and "=" in line:
            key, _, value = line.partition("=")
            value = value.strip()
            if key == "User":
                user = value
            elif key == "WorkingDirectory":
                workdir = value.lstrip("-")
            elif key == "Environment":
                for assignment in shlex.split(value):
                    name, _, entries = assignment.partition("=")
                    if name == "PYTHONPATH":
                        pythonpath += [e for e in entries.split(":") if e]
            elif key.startswith("Exec") and value:
                execs.append(shlex.split(value.lstrip("@-:+!")))
    if user not in ("root", "0"):
        return None
    roots = [r for r in [workdir] + pythonpath if r and r.startswith("/")]
    paths, trees = set(PurePosixPath(r) for r in roots), set()
    for words in execs:
        if not words:
            continue
        exe, args = PurePosixPath(words[0]), words[1:]
        paths.add(exe)
        if re.fullmatch(r"python[\d.]*", exe.name) and exe.parent.name == "bin":
            trees.add(exe.parent.parent)
        paths.update(PurePosixPath(a) for a in args if a.startswith("/"))
        for flag, module in zip(args, args[1:]):
            if flag == "-m":
                parts = module.split(".")
                for root in roots:
                    base = PurePosixPath(root)
                    trees.add(base / parts[0])
                    paths.add(base.joinpath(*parts))
                    paths.add(base.joinpath(*parts).with_suffix(".py"))
    return _Reach(sorted(str(p) for p in paths), sorted(str(t) for t in trees))


def _root_units(unit_dir):
    """{unit name: _Reach} for each unit under ``unit_dir`` that runs as root."""
    units = {}
    for unit in sorted(Path(unit_dir).glob("*.service")):
        reach = _unit_reach(unit.read_text())
        if reach is not None:
            units[unit.name] = reach
    return units


class TestInstallerOwnership(unittest.TestCase):
    """bootstrap.sh must not give root's code to the account that ran sudo.

    The services run /opt/raccoon/venv/bin/python as root with Restart=always,
    so whoever owns that tree can make root run what they like. The suite
    cannot run a root installer, so these read it as text.
    """

    def setUp(self):
        self.script = _BOOTSTRAP.read_text()
        self.variables, self.chowns = _installer_chowns(self.script)
        self.install_dir = self.variables.get("INSTALL_DIR")

    def _given_away_by(self):
        return "; ".join(c.source for c in self.chowns if c.owner == "user")

    def test_install_dir_is_not_handed_to_the_invoking_user(self):
        self.assertEqual(self.install_dir, "/opt/raccoon")
        self.assertFalse(
            _handed_away(self.chowns, self.install_dir),
            "bootstrap.sh gives the install directory to an unprivileged "
            "account: " + self._given_away_by())

    def test_the_two_data_dirs_are_still_user_owned(self):
        chmods = _installer_chmods(self.script, self.variables)
        for name in ("captures", "logs"):
            path = "%s/%s" % (self.install_dir, name)
            with self.subTest(directory=path):
                self.assertEqual(_owner_of(self.chowns, path), "user")
                self.assertIn(chmods.get(path), ("700", "0700", "u=rwx,go="))

    def test_every_unit_running_as_root_executes_a_root_owned_path(self):
        """Not just the interpreter: the package, working dir and config too."""
        units = _root_units(_UNIT_DIR)
        self.assertTrue(units, "no unit running as root found in %s"
                        % _UNIT_DIR)
        for name, reach in units.items():
            self.assertTrue(reach.paths, "%s reaches no path" % name)
            checks = ([(p, _handed_away) for p in reach.paths]
                      + [(t, _tree_handed_away) for t in reach.trees])
            for path, handed_away in checks:
                with self.subTest(unit=name, reaches=path):
                    self.assertTrue(path.startswith("/"))
                    self.assertFalse(
                        handed_away(self.chowns, path),
                        "%s makes root execute or read %s, but bootstrap.sh "
                        "gives it, a directory above it, or something in it "
                        "to an unprivileged account: %s"
                        % (name, path, self._given_away_by()))


_READER_HEADER = 'INSTALL_DIR="/opt/raccoon"\nACTUAL_USER="${SUDO_USER:-$USER}"\n'
_FIXED_PERMISSIONS = (
    'chown -R root:root "${INSTALL_DIR}"\n'
    'chown "${ACTUAL_USER}:${ACTUAL_USER}" "${INSTALL_DIR}/captures" '
    '"${INSTALL_DIR}/logs"\n')

# (label, installer text, "path" or "tree", target, handed to the user?)
_HAND_OVER_CASES = [
    ("the original line",
     'chown -R "${ACTUAL_USER}:${ACTUAL_USER}" "${INSTALL_DIR}"',
     "path", "/opt/raccoon", True),
    ("sudo prefix", 'sudo chown -R "$SUDO_USER" /opt/raccoon',
     "path", "/opt/raccoon", True),
    ("trailing slash", 'chown -R "$SUDO_USER" /opt/raccoon/',
     "path", "/opt/raccoon", True),
    ("trailing dot", 'chown -R "$SUDO_USER" /opt/raccoon/.',
     "path", "/opt/raccoon", True),
    ("--from option", 'chown -R --from=root "$SUDO_USER" /opt/raccoon',
     "path", "/opt/raccoon", True),
    ("flag after the operands", 'chown "$ACTUAL_USER:$ACTUAL_USER" $INSTALL_DIR -R',
     "path", "/opt/raccoon", True),
    ("long and bundled flags",
     'chown --recursive $SUDO_USER /opt/raccoon\nchown -hR pi /opt/raccoon',
     "path", "/opt/raccoon", True),
    ("not recursive", 'chown "${ACTUAL_USER}" "${INSTALL_DIR}"',
     "path", "/opt/raccoon", True),
    ("a parent directory", 'chown -R "$ACTUAL_USER" /opt',
     "path", "/opt/raccoon", True),
    ("default expansion", 'chown -R "${SUDO_USER:-$USER}" "$INSTALL_DIR"',
     "path", "/opt/raccoon", True),
    ("one-line function", 'fix() { chown -R "$ACTUAL_USER" "$INSTALL_DIR"; }',
     "path", "/opt/raccoon", True),
    ("multi-line function",
     'fix() {\n    chown -R "$ACTUAL_USER" "$INSTALL_DIR"\n}\nfix',
     "path", "/opt/raccoon", True),
    ("inside if/then/fi",
     'if true; then chown -R "$ACTUAL_USER" "$INSTALL_DIR"; fi',
     "path", "/opt/raccoon", True),
    ("after &&", '[ -d x ] && chown -R "$ACTUAL_USER" "$INSTALL_DIR"',
     "path", "/opt/raccoon", True),
    ("continued over lines",
     'chown -R \\\n    "$ACTUAL_USER" \\\n    "$INSTALL_DIR"',
     "path", "/opt/raccoon", True),
    ("after a root chown",
     'chown -R root:root /opt/raccoon\nchown -R "$ACTUAL_USER" /opt/raccoon',
     "path", "/opt/raccoon", True),
    ("the venv alone reaches the interpreter",
     'chown -R "$ACTUAL_USER" "${INSTALL_DIR}/venv"',
     "path", "/opt/raccoon/venv/bin/python", True),
    ("the venv alone is not the install dir",
     'chown -R "$ACTUAL_USER" "${INSTALL_DIR}/venv"',
     "path", "/opt/raccoon", False),
    ("the config dir reaches the config",
     'chown -R "$ACTUAL_USER" "${INSTALL_DIR}/configs"',
     "path", "/opt/raccoon/configs/raccoon.yaml", True),
    ("the software package",
     'chown -R "$ACTUAL_USER" "${INSTALL_DIR}/software"',
     "tree", "/opt/raccoon/software", True),
    ("the software package, spelled out",
     'chown -R "$ACTUAL_USER" /opt/raccoon/software',
     "tree", "/opt/raccoon/software", True),
    ("one subpackage",
     'chown -R "$ACTUAL_USER" "${INSTALL_DIR}/software/c2"',
     "tree", "/opt/raccoon/software", True),
    ("one module",
     'chown "$ACTUAL_USER" "${INSTALL_DIR}/software/main.py"',
     "tree", "/opt/raccoon/software", True),
    ("the contents of the install dir",
     'chown -R "$ACTUAL_USER" "${INSTALL_DIR}"/*',
     "tree", "/opt/raccoon/software", True),
    ("the contents of the install dir leave the dir itself",
     'chown -R "$ACTUAL_USER" "${INSTALL_DIR}"/*',
     "path", "/opt/raccoon", False),
    ("the virtualenv's libraries",
     'chown -R "$ACTUAL_USER" "${INSTALL_DIR}/venv/lib"',
     "tree", "/opt/raccoon/venv", True),
    ("the fix keeps the install dir", _FIXED_PERMISSIONS,
     "path", "/opt/raccoon", False),
    ("the fix keeps the interpreter", _FIXED_PERMISSIONS,
     "path", "/opt/raccoon/venv/bin/python", False),
    ("the fix keeps the config", _FIXED_PERMISSIONS,
     "path", "/opt/raccoon/configs/raccoon.yaml", False),
    ("the fix keeps the package", _FIXED_PERMISSIONS,
     "tree", "/opt/raccoon/software", False),
    ("the fix keeps the virtualenv", _FIXED_PERMISSIONS,
     "tree", "/opt/raccoon/venv", False),
    ("the data dirs alone", 'chown -R "$ACTUAL_USER" "${INSTALL_DIR}"/{captures,logs}',
     "path", "/opt/raccoon", False),
    ("a later root chown undoes it",
     'chown -R "$ACTUAL_USER" "$INSTALL_DIR"\nchown -R root:root "$INSTALL_DIR"',
     "tree", "/opt/raccoon/software", False),
    ("a group-only chown", 'chown -R :staff /opt/raccoon',
     "path", "/opt/raccoon", False),
    ("a comment", '# chown -R "$ACTUAL_USER" "$INSTALL_DIR"',
     "path", "/opt/raccoon", False),
    ("a word in an echo", 'echo chown -R "$ACTUAL_USER" "$INSTALL_DIR"',
     "path", "/opt/raccoon", False),
    ("a chown of something else", 'chown -R "$ACTUAL_USER" /home/pi/.ssh',
     "path", "/opt/raccoon", False),
]

# (label, installer text, path, who owns it afterwards)
_OWNER_CASES = [
    ("the fix hands over captures", _FIXED_PERMISSIONS,
     "/opt/raccoon/captures", "user"),
    ("the fix hands over logs", _FIXED_PERMISSIONS,
     "/opt/raccoon/logs", "user"),
    ("the fix leaves the install dir to root", _FIXED_PERMISSIONS,
     "/opt/raccoon", "root"),
    ("only the install dir is root's",
     'chown -R root:root "$INSTALL_DIR"', "/opt/raccoon/captures", "root"),
    ("the recursive form reaches the data dirs",
     'chown -R "$ACTUAL_USER" "$INSTALL_DIR"', "/opt/raccoon/logs", "user"),
]


class TestInstallerReader(unittest.TestCase):
    """The helpers behind TestInstallerOwnership, pinned against spellings.

    A reader that misses a spelling makes the ownership tests pass on a
    script that should fail them, so each case states what it must see.
    """

    def _chowns(self, snippet):
        return _installer_chowns(_READER_HEADER + snippet)[1]

    def test_a_chown_is_seen_in_every_spelling(self):
        for label, snippet, kind, target, expected in _HAND_OVER_CASES:
            with self.subTest(label):
                check = _tree_handed_away if kind == "tree" else _handed_away
                self.assertEqual(check(self._chowns(snippet), target), expected)

    def test_the_owner_after_the_script_follows_the_order_of_the_commands(self):
        for label, snippet, path, expected in _OWNER_CASES:
            with self.subTest(label):
                self.assertEqual(_owner_of(self._chowns(snippet), path), expected)

    def test_an_unresolvable_chown_target_is_an_error_not_a_pass(self):
        for target in ('"$SOMEWHERE"', '"$(mktemp -d)"', 'relative/dir'):
            with self.subTest(target):
                with self.assertRaises(AssertionError):
                    self._chowns('chown -R "$ACTUAL_USER" ' + target)

    def test_a_chmod_names_its_targets_and_not_its_options_or_mode(self):
        cases = [
            ('chmod 700 "${INSTALL_DIR}/captures"', {"/opt/raccoon/captures": "700"}),
            ('chmod -R 700 "${INSTALL_DIR}"/{captures,logs}',
             {"/opt/raccoon/captures": "700", "/opt/raccoon/logs": "700"}),
            ('chmod --recursive 0700 /opt/raccoon/logs/',
             {"/opt/raccoon/logs": "0700"}),
            ('chmod 700 "$INSTALL_DIR/a" "$INSTALL_DIR/b"\nchmod 755 "$INSTALL_DIR/b"',
             {"/opt/raccoon/a": "700", "/opt/raccoon/b": "755"}),
        ]
        for snippet, expected in cases:
            with self.subTest(snippet):
                script = _READER_HEADER + snippet
                variables, _ = _installer_chowns(script)
                self.assertEqual(_installer_chmods(script, variables), expected)

    def test_a_units_reach_covers_what_root_runs_and_reads(self):
        implant = (
            "[Service]\nUser=root\nWorkingDirectory=/opt/raccoon\n"
            "ExecStartPre=/bin/sleep 30\n"
            "ExecStart=/opt/raccoon/venv/bin/python -m software.main "
            "-c /opt/raccoon/configs/raccoon.yaml\n"
            'Environment="PYTHONPATH=/opt/raccoon"\n'
            'Environment="PATH=/opt/raccoon/venv/bin:/usr/bin"\n')
        reach = _unit_reach(implant)
        self.assertEqual(reach.trees,
                         ["/opt/raccoon/software", "/opt/raccoon/venv"])
        for path in ("/opt/raccoon", "/bin/sleep",
                     "/opt/raccoon/venv/bin/python",
                     "/opt/raccoon/configs/raccoon.yaml",
                     "/opt/raccoon/software/main",
                     "/opt/raccoon/software/main.py"):
            self.assertIn(path, reach.paths)
        self.assertNotIn("30", reach.paths)

    def test_a_dotted_module_reaches_its_top_level_package(self):
        reach = _unit_reach(
            "[Service]\nWorkingDirectory=/srv/app\n"
            'Environment="PYTHONPATH=/srv/lib:/srv/app"\n'
            "ExecStart=/usr/bin/python3 -m pkg.sub.tool\n")
        self.assertEqual(reach.trees, ["/srv/app/pkg", "/srv/lib/pkg",
                                       "/usr"])
        self.assertIn("/srv/lib/pkg/sub/tool.py", reach.paths)

    def test_a_unit_runs_as_root_unless_it_names_another_user(self):
        self.assertIsNotNone(_unit_reach("[Service]\nExecStart=/bin/true\n"))
        self.assertIsNotNone(
            _unit_reach("[Service]\nUser=0\nExecStart=/bin/true\n"))
        self.assertIsNone(
            _unit_reach("[Service]\nUser=nobody\nExecStart=/bin/true\n"))
        self.assertIsNone(_unit_reach("[Unit]\nUser=root\n[Service]\n"
                                      "User=pi\nExecStart=/bin/true\n"))


_GENERATOR = ('python3 -c "import os,base64; '
              'print(base64.b64encode(os.urandom(32)).decode())"')


class _ReachedCreateApp(Exception):
    """main() got past the key check and would have gone on to serve."""


def _server_main(*argv):
    """Run the server's main() as far as the key check; return
    (exit code, stderr). The code is "served" if main() got past the check,
    which is what a refusal must never do."""
    err = io.StringIO()
    code = None
    with tempfile.TemporaryDirectory() as data_dir, \
            patch.object(server_mod, "create_app",
                         side_effect=_ReachedCreateApp), \
            patch.object(server_mod, "_load_state"), \
            patch.object(server_mod, "_setup_file_logging"), \
            patch("sys.argv", ["server.py", "--data-dir", data_dir] + list(argv)), \
            contextlib.redirect_stderr(err):
        try:
            server_mod.main()
        except _ReachedCreateApp:
            code = "served"
        except SystemExit as exc:
            code = exc.code
    return code, err.getvalue()


class TestKeyMustBeSupplied(unittest.TestCase):
    """Findings C2 and C3: no key derived from public inputs, no fixed default.

    Review focus: every refusal names the problem and never the value -- not
    the key, not a prefix of it -- because these messages land in logs.
    """

    def _assert_not_echoed(self, value, text):
        # The whole value, then every 8-character window of it: a fixed prefix,
        # middle or tail slice leaves blind spots, and a leak of any part of
        # a key is a leak.
        self.assertNotIn(value, text, "the whole key was echoed")
        for i in range(len(value) - 7):
            self.assertNotIn(value[i:i + 8], text,
                             "characters %d-%d of the key were echoed"
                             % (i, i + 8))

    # ── Server ──

    def test_server_refuses_to_start_without_a_key(self):
        code, err = _server_main()
        self.assertIsInstance(code, int)
        self.assertNotEqual(code, 0)
        self.assertIn("--key", err)
        self.assertIn(_GENERATOR, err)

    def test_server_refuses_a_malformed_base64_key(self):
        code, err = _server_main("--key", "not*base64*at*all")
        self.assertIsInstance(code, int)
        self.assertNotEqual(code, 0)
        self.assertIn("not valid base64", err)
        self.assertNotIn("bytes", err.replace(_GENERATOR, ""))

    def test_server_refuses_a_key_of_the_wrong_length(self):
        # Both sides of the boundary: 31 and 33, not only the short side.
        for size in (16, 31, 33, 64):
            with self.subTest(size=size):
                code, err = _server_main("--key", key_b64(os.urandom(size)))
                self.assertIsInstance(code, int)
                self.assertNotEqual(code, 0)
                self.assertIn("%d bytes" % size, err)
                self.assertIn("exactly 32", err)
                self.assertNotIn("not valid base64", err)

    def test_server_accepts_a_32_byte_key(self):
        code, err = _server_main("--key", key_b64(random_key()))
        self.assertEqual(code, "served", err)

    def test_the_refusal_names_neither_the_key_nor_a_prefix_of_it(self):
        short = key_b64(os.urandom(24))
        long = key_b64(os.urandom(33))
        malformed = "Zq7Xw9Pk!" + key_b64(os.urandom(12))
        for value in (short, long, malformed):
            with self.subTest(side="server", value_kind=len(value)):
                code, err = _server_main("--key", value)
                self.assertIsInstance(code, int)
                self._assert_not_echoed(value, err)
            with self.subTest(side="beacon", value_kind=len(value)):
                with self.assertRaises(ValueError) as caught:
                    Beacon(_config(encryption_key=value))
                self._assert_not_echoed(value, str(caught.exception))
                # Not smuggled out through the exception chain either.
                self.assertIsNone(caught.exception.__context__)

    def _sha256_callers(self, path):
        tree = ast.parse(Path(path).read_text())
        callers = set()
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(fn):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "sha256"):
                    callers.add(fn.name)
        return callers

    def test_no_sha256_of_a_url_remains_in_the_server(self):
        source = Path(server_mod.__file__).read_text()
        self.assertEqual(self._sha256_callers(server_mod.__file__), set())
        self.assertNotIn("derive-key", source)
        self.assertNotIn("derive_key", source)

    def test_no_sha256_of_a_url_remains_in_the_beacon(self):
        # The one hash left names the implant; it never touches the key.
        self.assertEqual(self._sha256_callers(beacon_mod.__file__),
                         {"_generate_id"})

    # ── Beacon ──

    def test_beacon_refuses_an_empty_encryption_key(self):
        missing = _config()
        del missing["c2"]["encryption_key"]
        for config in (_config(encryption_key=""),
                       _config(encryption_key="   "), missing):
            with self.subTest(config=config["c2"].get("encryption_key")):
                with self.assertRaises(ValueError) as caught:
                    Beacon(config)
                self.assertIn("encryption_key", str(caught.exception))
                self.assertIn(_GENERATOR, str(caught.exception))

    def test_beacon_refuses_a_malformed_or_wrong_length_key(self):
        with self.assertRaisesRegex(ValueError, "not valid base64"):
            Beacon(_config(encryption_key="not*base64*at*all"))
        for size in (16, 31, 33, 64):
            with self.subTest(size=size):
                with self.assertRaisesRegex(
                        ValueError, "%d bytes.*exactly 32" % size):
                    Beacon(_config(encryption_key=key_b64(os.urandom(size))))

    def test_the_server_and_beacon_share_one_decoder(self):
        # Not a copy kept in step by a test: the same function, so whitespace,
        # strict base64 and the length rule cannot drift apart.
        self.assertIs(server_mod.decode_key, beacon_mod.decode_key)

    def test_decode_key_outcomes(self):
        good = os.urandom(32)
        cases = [
            ("empty", "", "required"),
            ("whitespace", "  \n\t ", "required"),
            ("none", None, "required"),
            ("not base64", "not*base64*at*all", "base64"),
            ("stray newline inside", key_b64(good)[:10] + "\n" + key_b64(good)[10:],
             "base64"),
            ("unpadded", key_b64(good).rstrip("="), "base64"),
            ("16 bytes", key_b64(os.urandom(16)), "length"),
            ("31 bytes", key_b64(os.urandom(31)), "length"),
            ("33 bytes", key_b64(os.urandom(33)), "length"),
            ("32 bytes", key_b64(good), good),
            ("32 bytes, newline-padded", "\n" + key_b64(good) + "\n", good),
        ]
        for name, value, expected in cases:
            with self.subTest(case=name):
                if isinstance(expected, bytes):
                    self.assertEqual(beacon_mod.decode_key(value), expected)
                    continue
                with self.assertRaises(ValueError) as caught:
                    beacon_mod.decode_key(value)
                message = str(caught.exception)
                if expected == "required":
                    self.assertIn("is required", message)
                elif expected == "base64":
                    self.assertIn("not valid base64", message)
                else:
                    self.assertIn("exactly 32", message)
                    self.assertNotIn("base64.", message.replace(_GENERATOR, ""))

    def test_beacon_uses_the_key_it_is_given(self):
        key = random_key()
        self.assertEqual(Beacon(_config(encryption_key=key_b64(key)))._key,
                         key)

    # ── Implant config: refused at load, only when a beacon will be built ──

    def _implant_config(self, key, fallback=True, sliver=False):
        return {"c2": {"enabled": True, "encryption_key": key,
                       "sliver": {"enabled": sliver},
                       "fallback": {"enabled": fallback}}}

    def _load_implant_config(self, config):
        import yaml
        from software import main as implant_main
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "raccoon.yaml"
            path.write_text(yaml.safe_dump(config))
            with contextlib.redirect_stderr(err):
                try:
                    return implant_main.load_config(str(path)), None, ""
                except SystemExit as exc:
                    return None, exc.code, err.getvalue()

    def test_implant_refuses_a_fallback_beacon_without_a_key(self):
        short = key_b64(os.urandom(8))
        for key in ("", "not*base64*at*all", short):
            with self.subTest(key=len(key)):
                loaded, code, err = self._load_implant_config(
                    self._implant_config(key))
                self.assertIsNone(loaded)
                self.assertNotIn(code, (None, 0))
                self.assertIn("c2.encryption_key", err)
                self.assertIn(_GENERATOR, err)
                if key:
                    self._assert_not_echoed(key, err)

    def test_a_config_that_builds_no_beacon_needs_no_key(self):
        # Sliver-only, or C2 off: nothing would ever use the key.
        sliver_only = self._implant_config("", fallback=False, sliver=True)
        c2_off = self._implant_config("")
        c2_off["c2"]["enabled"] = False
        for config in (sliver_only, c2_off):
            loaded, code, err = self._load_implant_config(config)
            self.assertEqual(loaded, config, err)

    def test_implant_loads_a_config_with_a_valid_key(self):
        config = self._implant_config(key_b64(random_key()), sliver=True)
        loaded, code, err = self._load_implant_config(config)
        self.assertEqual(loaded, config, err)

    def test_standalone_beacon_refuses_before_building_anything(self):
        import yaml
        from software.c2 import beacon_standalone
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "raccoon.yaml"
            path.write_text(yaml.safe_dump(self._implant_config("")))
            with patch.object(beacon_standalone, "CONFIG_PATHS", [str(path)]), \
                    patch.object(beacon_standalone, "already_running",
                                 return_value=False), \
                    patch.object(beacon_standalone, "setup_logging"), \
                    patch.object(beacon_standalone, "write_pid"), \
                    patch.object(beacon_standalone, "remove_pid") as removed, \
                    patch.object(beacon_mod, "Beacon",
                                 side_effect=AssertionError("beacon built")), \
                    contextlib.redirect_stderr(err):
                with self.assertRaises(SystemExit) as caught:
                    beacon_standalone.main()
        self.assertNotIn(caught.exception.code, (None, 0))
        self.assertIn("c2.encryption_key", err.getvalue())
        removed.assert_called_once_with()

    def test_smbloot_still_builds_its_local_beacon(self):
        # smbloot never talks to a C2; it must not trip over the key rule.
        # In a subprocess because smbloot puts software/c2 on sys.path and
        # imports its own copy of `beacon`, which this process must not see.
        script = (
            "import sys\n"
            "sys.argv = ['smbloot.py', '127.0.0.1', 'u', 'p', 'shares']\n"
            "sys.path.insert(0, 'software/c2')\n"
            "import smbloot\n"
            "smbloot.Beacon._exec_smbloot = lambda self, args: 'no shares'\n"
            "smbloot.main()\n")
        done = subprocess.run([sys.executable, "-c", script], cwd=str(_REPO),
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("no shares", done.stdout)

    # ── Nothing that ships still offers the removed shortcut ──

    def test_no_launcher_script_or_doc_offers_a_derived_or_default_key(self):
        shipped = [_REPO / "README.md", _REPO / "docs" / "AGENT.md",
                   _REPO / "configs" / "raccoon.yaml"]
        shipped += [p for p in (_REPO / "software" / "c2").iterdir()
                    if p.suffix in (".sh", ".ps1", ".py", ".yml")]
        banned = ("derive-key", "derive_key", "DeriveKey", "DERIVE_KEY",
                  'SHA256(":")', "SHA256(':')", "Derive from callback")
        for path in shipped:
            text = path.read_text(encoding="utf-8-sig")
            for phrase in banned:
                with self.subTest(path=path.name, phrase=phrase):
                    self.assertNotIn(phrase, text)

    # ── The installer says so before it enables anything ──

    _PREFLIGHT = _REPO / "services" / "check_beacon_key.sh"

    def _preflight(self, config_text=None, python=None, name="raccoon.yaml"):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / name
            if config_text is not None:
                path.write_text(config_text)
            env = dict(os.environ, RACCOON_ROOT=str(_REPO),
                       RACCOON_PYTHON=python or sys.executable,
                       RACCOON_CONFIG=str(path))
            done = subprocess.run(["bash", str(self._PREFLIGHT)], env=env,
                                  capture_output=True, text=True, timeout=60)
        return done.returncode, done.stdout + done.stderr

    def test_preflight_warns_when_the_beacon_would_be_refused(self):
        bad = "invalid-key-not-base64-" + key_b64(os.urandom(12))
        for key in ("", bad, key_b64(os.urandom(33))):
            with self.subTest(key=len(key)):
                code, out = self._preflight(
                    "c2:\n  enabled: true\n  encryption_key: \"%s\"\n"
                    "  fallback:\n    enabled: true\n" % key)
                self.assertEqual(code, 1, out)
                self.assertIn("c2.encryption_key", out)
                self.assertIn(_GENERATOR, out)
                self.assertIn("beacon.log", out)
                if key:
                    self._assert_not_echoed(key, out)

    def test_preflight_is_quiet_for_a_good_key_or_a_config_with_no_beacon(self):
        good = ("c2:\n  enabled: true\n  encryption_key: \"%s\"\n"
                "  fallback:\n    enabled: true\n" % key_b64(random_key()))
        no_beacon = ("c2:\n  enabled: true\n  encryption_key: \"\"\n"
                     "  fallback:\n    enabled: false\n")
        for text in (good, no_beacon):
            code, out = self._preflight(text)
            self.assertEqual((code, out), (0, ""))

    def test_preflight_says_when_it_could_not_check_and_never_quotes_the_file(self):
        secret = key_b64(os.urandom(32))
        code, out = self._preflight(
            "c2: [unclosed\n  encryption_key: %s\n" % secret)
        self.assertEqual(code, 2, out)
        self._assert_not_echoed(secret, out)
        code, out = self._preflight(None, name="absent.yaml")
        self.assertEqual(code, 2, out)
        self.assertIn("Could not check", out)

    def test_install_runs_the_preflight_first_and_warns_instead_of_stopping(self):
        text = (_REPO / "services" / "install.sh").read_text()
        check = text.index("check_beacon_key.sh")
        self.assertLess(check, text.index("systemctl enable"))
        self.assertLess(check, text.index("cp \"${SCRIPT_DIR}/raccoon-implant.service\""))
        # A failed check is recorded, not fatal: `set -e` must not end the install.
        self.assertRegex(text, r"check_beacon_key\.sh\" \|\| KEY_CHECK=\$\?")
        self.assertIn("encryption_key", text[text.index("\"$KEY_CHECK\" -ne 0"):])

    def test_the_quick_starts_say_to_set_a_key_before_the_first_run(self):
        readme = (_REPO / "README.md").read_text()
        lite = readme[readme.index("**Quick Start (Lite):**"):]
        lite = lite[:lite.index("sudo reboot")]
        self.assertLess(lite.index("c2.encryption_key"),
                        lite.index("services/install.sh"))
        manual = readme[readme.index("#### Option B: Manual setup"):]
        manual = manual[:manual.index("### Beacon Persistence")]
        self.assertIn("c2.encryption_key", manual)
        docker = readme[readme.index("#### Quick Start (Docker)"):]
        docker = docker[:docker.index("docker compose up -d")]
        self.assertIn("RACCOON_KEY", docker)

    # ── Shipped config ──

    def test_shipped_config_does_not_claim_a_derived_key(self):
        # raccoon.yaml's comment currently promises the derivation.
        lines = (_REPO / "configs" / "raccoon.yaml").read_text().splitlines()
        at = next(i for i, line in enumerate(lines)
                  if line.strip().startswith("encryption_key:"))
        comment = []
        for line in reversed(lines[:at]):
            if not line.strip().startswith("#"):
                break
            comment.append(line)
        block = "\n".join(comment)
        self.assertNotRegex(block.lower(), r"deriv|deterministic")
        self.assertIn(_GENERATOR, block)
        self.assertEqual(beacon_mod.KEY_GENERATOR, _GENERATOR)


def _http(method, port, path, body=None, headers=None):
    """One request over a real socket; (status, content type, body bytes).

    Not the test client: the policy under test keys on the socket a request
    arrived on, and the test client goes through no socket at all.
    """
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path),
                                 data=data, method=method,
                                 headers=dict(headers or {}))
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.headers.get("Content-Type"), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type"), exc.read()


class _QuietHandler(WSGIRequestHandler):
    def log_request(self, *args, **kwargs):
        pass


class _FakeListener:
    def __init__(self, calls, host, port, app, **kwargs):
        calls.append({"host": host, "port": port, "app": app, **kwargs})
        self.server_port = port

    def serve_forever(self):
        pass

    def shutdown(self):
        pass


def _main_listeners(*argv):
    """Run main() with make_server replaced; return (listeners, create_app
    keyword arguments). Nothing binds and nothing blocks."""
    calls = []
    made = {}
    real_create_app = server_mod.create_app

    def recording_create_app(*args, **kwargs):
        made.update(kwargs)
        return real_create_app(*args, **kwargs)

    with tempfile.TemporaryDirectory() as data_dir, \
            patch.object(server_mod, "make_server",
                         side_effect=lambda *a, **k: _FakeListener(calls, *a, **k)), \
            patch.object(server_mod, "create_app",
                         side_effect=recording_create_app), \
            patch.object(server_mod, "_load_state"), \
            patch.object(server_mod, "_setup_file_logging"), \
            patch.object(server_mod, "_log_event"), \
            patch.object(server_mod.logging, "basicConfig"), \
            patch("sys.argv", ["server.py", "--data-dir", data_dir,
                               "--key", key_b64(random_key())] + list(argv)), \
            contextlib.redirect_stdout(io.StringIO()):
        server_mod.main()
    return calls, made


class TestSocketPolicy(unittest.TestCase):
    """Finding C1, structural half: the operator interface and the agent
    endpoint no longer share a socket.

    Review focus: with no operator port configured the policy must allow
    everything -- every other test in this suite uses the test client, which
    has no socket to tell apart.
    """

    TOKEN = "socket-policy-operator-token"

    def setUp(self):
        self.saved_agents = dict(server_mod.agents)
        server_mod.agents.clear()
        self.addCleanup(self._restore_agents)
        self.data_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.data_dir, ignore_errors=True)
        self.crypto = server_mod.ServerCrypto(random_key())

    def _restore_agents(self):
        server_mod.agents.clear()
        server_mod.agents.update(self.saved_agents)

    def _split(self):
        """Two real listeners over one app, the operator port configured.

        Called by the tests that need sockets rather than from setUp, so the
        tests that need none run without them.
        """
        # Ephemeral ports, read back after binding: never a hardcoded number,
        # which once measured a foreign process and reported the opposite of
        # the truth. The app needs the operator port before it exists, so the
        # listeners are bound first and handed the app afterwards.
        self.operator = make_server("127.0.0.1", 0, None, threaded=True,
                                    request_handler=_QuietHandler)
        self.addCleanup(self.operator.server_close)
        self.agent = make_server("127.0.0.1", 0, None, threaded=True,
                                 request_handler=_QuietHandler)
        self.addCleanup(self.agent.server_close)
        self.op_port = self.operator.server_port
        self.agent_port = self.agent.server_port
        app = server_mod.create_app(self.crypto, self.TOKEN, self.data_dir,
                                    operator_port=self.op_port)
        for srv in (self.operator, self.agent):
            srv.app = app
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self.addCleanup(srv.shutdown)

    def _auth(self):
        return {"Authorization": "Bearer %s" % self.TOKEN}

    def _register(self, port):
        payload = {"action": "register", "id": "socket-policy-impl",
                   "hostname": "box", "os": "Linux", "arch": "aarch64",
                   "user": "pi", "pid": 7, "interval": 10, "uptime": 1}
        status, _, body = _http("POST", port, "/api/v1/register",
                                self.crypto.wrap(payload))
        return status, self.crypto.unwrap(json.loads(body))

    def _cover(self):
        # The catch-all's answer to a body it cannot read: the response any
        # prober already gets, and the one a refusal has to match.
        return _http("POST", self.agent_port, "/", {"not": "a beacon"})

    # ── The agent socket ──

    def test_agent_socket_refuses_the_operator_page(self):
        self._split()
        status, ctype, body = _http("GET", self.agent_port, "/")
        self.assertNotIn(b"<html", body.lower())
        self.assertNotIn(self.TOKEN.encode(), body)
        self.assertEqual((status, ctype, body), self._cover())

    def test_agent_socket_refuses_the_operator_api_even_with_a_valid_token(self):
        self._split()
        for method, path in (("GET", "/api/agents"),
                             ("GET", "/api/server/config"),
                             ("POST", "/api/server/exec"),
                             ("POST", "/api/server/token")):
            with self.subTest(method=method, path=path):
                body = {} if method == "POST" else None
                got = _http(method, self.agent_port, path, body, self._auth())
                self.assertEqual(got, self._cover())

    def test_agent_socket_serves_a_beacon_checkin(self):
        self._split()
        status, reply = self._register(self.agent_port)
        self.assertEqual(status, 200)
        self.assertIsNotNone(reply, "the registration was not answered")
        self.assertTrue(reply["success"])
        self.assertEqual(len(server_mod.agents), 1)

    # ── The operator socket ──

    def test_operator_socket_serves_the_page_and_the_api(self):
        self._split()
        status, _, body = _http("GET", self.op_port, "/")
        self.assertEqual(status, 200)
        self.assertIn(b"<html", body.lower())
        status, _, body = _http("GET", self.op_port, "/api/agents",
                                headers=self._auth())
        self.assertEqual(status, 200)
        self.assertIsInstance(json.loads(body), list)
        status, _, _ = _http("GET", self.op_port, "/api/agents")
        self.assertEqual(status, 401, "the token is still required")

    def test_operator_socket_still_serves_a_beacon_checkin(self):
        # Local beacons in the demo reach the operator socket; that stays.
        self._split()
        status, reply = self._register(self.op_port)
        self.assertEqual(status, 200)
        self.assertTrue(reply["success"])
        self.assertEqual(len(server_mod.agents), 1)

    # ── The inert default ──

    def test_the_split_is_inert_when_no_operator_port_is_configured(self):
        # app.test_client() does not go through a socket, so SERVER_PORT is
        # not meaningful. Assert a default-constructed app serves GET / and
        # the API -- otherwise this task breaks every existing test.
        app = server_mod.create_app(self.crypto, self.TOKEN, self.data_dir)
        client = app.test_client()
        page = client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"<html", page.data.lower())
        api = client.get("/api/agents", headers=self._auth())
        self.assertEqual(api.status_code, 200)
        # The catch-all takes POST on every path, so another method there is
        # a 405 today -- and stays one, not the cover a split app answers.
        self.assertEqual(client.get("/no/such/page").status_code, 405)

    def test_refusal_on_the_agent_socket_is_indistinguishable_from_the_cover(self):
        self._split()
        # Must reuse _fake_response(), not a 403 that fingerprints the C2:
        # an unrouted path and a wrong method included, which would
        # otherwise answer 404 and 405.
        cover = self._cover()
        self.assertEqual(cover[0], 200)
        for method, path in (("GET", "/"), ("GET", "/no/such/page"),
                             ("GET", "/api/v1/beacon"), ("GET", "/logo.png"),
                             ("GET", "/static/agent.js"),
                             ("OPTIONS", "/"), ("DELETE", "/api/agents")):
            with self.subTest(method=method, path=path):
                self.assertEqual(_http(method, self.agent_port, path), cover)

    # ── Where main() binds ──

    def test_operator_socket_binds_loopback_by_default(self):
        listeners, made = _main_listeners()
        bound = sorted((c["host"], c["port"]) for c in listeners)
        self.assertEqual(bound, [("0.0.0.0", 8443), ("127.0.0.1", 8444)])
        self.assertEqual(made.get("operator_port"), 8444)
        for c in listeners:
            self.assertTrue(c.get("threaded"))
            self.assertIs(c["app"], listeners[0]["app"], "one app, two sockets")

    def test_agent_socket_binds_the_configured_interface(self):
        listeners, made = _main_listeners("--host", "10.9.8.7", "--port", "9443",
                                          "--operator-host", "127.0.0.2",
                                          "--operator-port", "9444")
        bound = sorted((c["host"], c["port"]) for c in listeners)
        self.assertEqual(bound, [("10.9.8.7", 9443), ("127.0.0.2", 9444)])
        self.assertEqual(made.get("operator_port"), 9444)

    def test_one_socket_and_no_policy_when_the_ports_are_equal(self):
        listeners, made = _main_listeners("--host", "0.0.0.0", "--port", "8443",
                                          "--operator-port", "8443")
        self.assertEqual([(c["host"], c["port"]) for c in listeners],
                         [("0.0.0.0", 8443)])
        self.assertIsNone(made.get("operator_port"))

    def test_port_zero_is_refused_for_either_socket(self):
        # 0 would bind an ephemeral port the policy never matches, and the
        # GUI would be locked out with nothing said.
        for flag in ("--port", "--operator-port"):
            with self.subTest(flag=flag):
                code, err = _server_main("--key", key_b64(random_key()),
                                         flag, "0")
                self.assertEqual(code, 2)
                self.assertIn(flag, err)
                self.assertIn("1-65535", err)

    # ── The demo harness names its sockets as server.py does ──

    def test_demo_env_flags_mean_what_the_servers_flags_mean(self):
        from tools import demo_env
        args = demo_env.build_parser().parse_args(
            ["--port", "1111", "--operator-port", "2222"])
        env = demo_env.DemoEnv(args.operator_port, "t", beacon_port=args.port)
        self.assertEqual((env.operator_port, env.beacon_port), (2222, 1111))
        self.assertNotIn("--beacon-port",
                         demo_env.build_parser().format_help())

    def test_the_capture_script_opens_the_demo_on_its_operator_port(self):
        script = (_REPO / "tools" / "capture_figures.sh").read_text()
        launches = re.findall(r"tools/demo_env\.py[\s\\]+(--[\w-]+)", script)
        self.assertTrue(launches, "capture_figures.sh no longer runs demo_env")
        self.assertEqual(set(launches), {"--operator-port"})


class TestCallbackDefault(unittest.TestCase):
    """The Beacon Generator must never prefill a callback no beacon can reach.

    Through the documented SSH tunnel the GUI's own hostname is localhost,
    and a beacon given that address never registers -- silently. The helper
    is located by name in the interface string and its branches asserted on;
    where node is installed it is also executed.
    """

    @staticmethod
    def _helper():
        found = re.search(r"\nfunction bgDefaultCallbackUrl\(cfg, pageHost\)\{.*?\n\}\n",
                          server_mod._OPERATOR_HTML, re.S)
        assert found, "bgDefaultCallbackUrl is gone from the interface"
        return found.group(0)

    def _show_beacon_gen(self):
        html = server_mod._OPERATOR_HTML
        start = html.index("async function showBeaconGen(){")
        return html[start:html.index("\n}\n", start)]

    def test_the_generator_takes_its_default_from_the_helper(self):
        body = self._show_beacon_gen()
        self.assertTrue("bgDefaultCallbackUrl(cfg, location.hostname)" in body,
                        "showBeaconGen does not use the helper")
        self.assertIsNone(re.search(r'"://"\+location\.hostname', body),
                          "showBeaconGen still builds from the page host")

    def test_the_helper_refuses_a_loopback_page_host(self):
        helper = self._helper()
        self.assertRegex(helper, r"localhost")
        self.assertRegex(helper, r"127\\\.")
        self.assertIn('return ""', helper)

    def test_an_empty_default_is_explained_next_to_the_field(self):
        body = self._show_beacon_gen()
        self.assertTrue('id="bg-url-note"' in body, "no note beside the field")
        self.assertIsNotNone(
            re.search(r"(?s)\(defaultUrl \? '' : '<p id=\"bg-url-note\".{0,300}SSH tunnel", body),
            "the note is not shown exactly when the default is empty")

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_helper_behaves(self):
        cases = [
            # (cfg.host, cfg.port, cfg.ssl, page host, expected)
            ("0.0.0.0", 8443, False, "localhost", ""),
            ("0.0.0.0", 8443, False, "127.0.0.1", ""),
            ("0.0.0.0", 8443, False, "[::1]", ""),
            ("::", 8443, True, "localhost", ""),
            ("0.0.0.0", 8443, False, "c2.example.net",
             "http://c2.example.net:8443/api/v1/beacon"),
            ("0.0.0.0", 9443, True, "10.0.0.5",
             "https://10.0.0.5:9443/api/v1/beacon"),
            ("10.1.2.3", 8443, False, "localhost",
             "http://10.1.2.3:8443/api/v1/beacon"),
        ]
        script = self._helper() + "\nconst cases = %s;\n" % json.dumps(cases) + (
            "console.log(JSON.stringify(cases.map(c => bgDefaultCallbackUrl("
            "{host:c[0], port:c[1], ssl:c[2]}, c[3]))));\n")
        out = subprocess.run(["node", "-e", script], capture_output=True,
                             text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout), [c[4] for c in cases])


class TestTokenIsNotServed(unittest.TestCase):
    """Finding C1, credential half: `GET /` no longer carries the token.

    The page used to have the operator token substituted into it, on a
    route with no authentication, so anyone who could load the interface
    held the credential for every other route. The page now asks for the
    token once and keeps it in sessionStorage under `raccoon_token`.

    Review focus: the route walk enumerates the app's own rules, so a route
    added later that hands the token out is caught without editing a list.
    """

    TOKEN = "SECRET-OPERATOR-TOKEN-xyz123"
    KEY = "raccoon_token"

    def setUp(self):
        self.data_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.data_dir, ignore_errors=True)
        self.app = server_mod.create_app(server_mod.ServerCrypto(random_key()),
                                         self.TOKEN, self.data_dir)
        self.client = self.app.test_client()

    @staticmethod
    def _js_function(name):
        found = re.search(r"\n(?:async )?function %s\(.*?\n\}\n" % name,
                          server_mod._OPERATOR_HTML, re.S)
        assert found, "%s is gone from the interface" % name
        return found.group(0)

    def _run_node(self, stored, status):
        """Run the page's own api() against a stub fetch answering `status`."""
        key = re.search(r'\nconst TOKEN_KEY = "[^"]*";\n',
                        server_mod._OPERATOR_HTML)
        self.assertIsNotNone(key, "TOKEN_KEY is gone from the interface")
        harness = (
            "const store = %s;\n"
            "const sessionStorage = {getItem: k => k in store ? store[k] : null,"
            " setItem: (k, v) => { store[k] = String(v); },"
            " removeItem: k => { delete store[k]; }};\n"
            "const asked = []; function askForToken(r){ asked.push(r); }\n"
            "const sent = [];\n"
            "async function fetch(p, o){ sent.push(o.headers.Authorization);"
            " return {status: %d, ok: %s, json: async () => ({})}; }\n"
            % (json.dumps(stored), status, "true" if status < 400 else "false"))
        script = harness + key.group(0) + "".join(
            self._js_function(n) for n in ("storedToken", "H", "tokenRejected",
                                           "api")) + (
            "(async () => { const threw = [];\n"
            " for (let i = 0; i < 2; i++) {\n"
            "  try { await api('/api/agents'); threw.push(false); }"
            "  catch (e) { threw.push(true); } }\n"
            " console.log(JSON.stringify({stored: sessionStorage.getItem(%s),"
            " asked, sent, threw})); })();\n" % json.dumps(self.KEY))
        out = subprocess.run(["node", "-e", script], capture_output=True,
                             text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_get_root_does_not_contain_the_operator_token(self):
        # The regression test for the whole audit. Assert the token string
        # is absent from the body, not merely that {{TOKEN}} was replaced.
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertFalse(self.TOKEN in body, "GET / serves the operator token")
        # No substitution point at all: one edit away from the original
        # finding is one edit too few.
        self.assertFalse("{{TOKEN}}" in server_mod._OPERATOR_HTML,
                         "the page template has a token placeholder again")
        self.assertIsNone(re.search(r"\bconst TOKEN\b", server_mod._OPERATOR_HTML),
                          "the page declares a TOKEN constant again")

    def test_get_root_still_serves_the_application(self):
        body = self.client.get("/").get_data(as_text=True)
        self.assertIn('id="agent-list"', body)
        self.assertIn("async function api(path, opts){", body)
        self.assertIn('<script src="/static/agent.js" defer></script>', body)

    def test_no_route_returns_the_token_without_authentication(self):
        # Walk every rule, call it unauthenticated, assert the token is in
        # no response body. This catches a future re-introduction anywhere.
        adapter = self.app.url_map.bind("localhost")
        visited = set()
        for rule in self.app.url_map.iter_rules():
            for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
                path = adapter.build(rule.endpoint,
                                     {a: "1" for a in rule.arguments},
                                     method=method)
                resp = self.client.open(path, method=method)
                where = "%s %s (%s)" % (method, path, rule.endpoint)
                self.assertFalse(self.TOKEN.encode() in resp.get_data(),
                                 "token in the body of " + where)
                for name, value in resp.headers.items():
                    self.assertNotIn(self.TOKEN, value, where + " " + name)
                resp.close()
                visited.add(rule.endpoint)
        # Not vacuous: the page, the API and the beacon catch-all were walked.
        self.assertTrue({"index", "api_agents", "api_server_config",
                         "beacon_handler"} <= visited, visited)

    def test_the_page_prompts_when_no_token_is_stored(self):
        html = server_mod._OPERATOR_HTML
        self.assertTrue('const TOKEN_KEY = "%s";' % self.KEY in html,
                        "the page does not name its storage key")
        self.assertIn("sessionStorage.getItem(TOKEN_KEY)",
                      self._js_function("storedToken"))
        gate = re.search(r'<div id="token-gate"[\s\S]*?\n</div>\n', html)
        self.assertIsNotNone(gate, "no token prompt in the page")
        self.assertIn('type="password"', gate.group(0))
        # Startup polls only with a token; without one it asks instead.
        self.assertIsNotNone(re.search(
            r"\nif\(storedToken\(\)\)\{\n  setInterval\(refreshAgents, 3000\);"
            r"[\s\S]{0,400}?\n\} else \{\n  askForToken\(false\);\n\}\n", html),
            "startup does not branch on the stored token")
        self.assertEqual(html.count("setInterval(refreshAgents"), 1)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_with_nothing_stored_no_request_is_sent(self):
        result = self._run_node({}, 200)
        self.assertEqual(result["sent"], [])
        self.assertEqual(result["asked"], [False, False])
        self.assertEqual(result["threw"], [True, True])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_stored_token_is_read_at_call_time(self):
        result = self._run_node({self.KEY: "right"}, 200)
        self.assertEqual(result["sent"], ["Bearer right", "Bearer right"])
        self.assertEqual(result["stored"], "right")
        self.assertEqual(result["asked"], [])

    def test_a_wrong_token_is_reported_and_not_retained(self):
        # Source-level: assert the 401 path clears sessionStorage, so a bad
        # token does not survive a reload into a silent retry loop.
        rejected = self._js_function("tokenRejected")
        self.assertIn("sessionStorage.removeItem(TOKEN_KEY)", rejected)
        self.assertIn("askForToken(true)", rejected)
        for fn in ("api", "lootSave"):
            self.assertRegex(self._js_function(fn),
                             r"status === 401\)[^\n]*tokenRejected\(\)", fn)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_wrong_token_is_cleared_and_not_retried(self):
        result = self._run_node({self.KEY: "wrong"}, 401)
        self.assertIsNone(result["stored"])
        self.assertEqual(result["asked"], [True, False])
        # One request with the bad token, then none: no silent retry loop.
        self.assertEqual(result["sent"], ["Bearer wrong"])
        self.assertEqual(result["threw"], [True, True])

    def test_nothing_is_requested_without_a_stored_token(self):
        # The polls keep firing after a rejection, and agent.js reads its
        # status at load: each returns before building a request, rather
        # than sending a bare "Bearer " or throwing into the console.
        for fn in ("refreshAgents", "checkTaskResults", "lootSave"):
            body = self._js_function(fn)
            first = body.strip().split("\n")[1].strip()
            self.assertEqual(first, "if(!storedToken()) return;", fn)
        js = (_REPO / "software" / "c2" / "static" / "agent.js").read_text()
        call = re.search(r"\nasync function aiCall\(.*?\n\}\n", js, re.S).group(0)
        self.assertRegex(call, r"if\(!storedToken\(\)\) return \{ok: false, status: 401")
        self.assertLess(call.index("storedToken()"), call.index("fetch("))

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_rejected_notice_survives_the_next_poll(self):
        # Found by looking: a poll after the rejection asks again with
        # rejected=false, and once hid the notice it had just shown.
        script = (
            "const els = {'token-gate': {classList: {s: new Set(),"
            " add(c){ this.s.add(c); }, contains(c){ return this.s.has(c); }}},"
            " 'tg-error': {style: {display: ''}}, 'tg-input': {focus(){}}};\n"
            "const document = {getElementById: id => els[id]};\n"
            + self._js_function("askForToken") +
            "askForToken(true); askForToken(false);\n"
            "console.log(JSON.stringify([els['tg-error'].style.display,"
            " els['token-gate'].classList.contains('open')]));\n")
        out = subprocess.run(["node", "-e", script], capture_output=True,
                             text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout), ["block", True])

    def test_the_token_is_never_placed_in_a_url(self):
        # Option (b) was rejected; assert no location/search/?t= handling
        # crept in.
        sources = {
            "the page": server_mod._OPERATOR_HTML,
            "agent.js": (_REPO / "software" / "c2" / "static" / "agent.js").read_text(),
            "capture_figures.sh": (_REPO / "tools" / "capture_figures.sh").read_text(),
        }
        for board in ("c2_tour.json", "agent_run.json"):
            sources[board] = (_REPO / "tools" / "storyboards" / board).read_text()
        for where, text in sources.items():
            for needle in ("location.search", "location.hash", "location.href",
                           "URLSearchParams", "pushState", "replaceState",
                           "?t=", "&t=", "token=", "<form"):
                self.assertNotIn(needle, text, "%s in %s" % (needle, where))
        # The storyboards hand the token over the way the page keeps it, and
        # wait for proof it was accepted -- an agent row -- so a wrong token
        # fails the capture at the login step, not a timeout further on.
        for board in ("c2_tour.json", "agent_run.json"):
            first = json.loads(sources[board])[0]
            self.assertIn("sessionStorage.setItem('%s', '{{TOKEN}}')" % self.KEY,
                          first["js"], board)
            self.assertIn("#agent-list .agent-card", first["wait"], board)


class TestCaptureCleanup(unittest.TestCase):
    """capture_figures.sh must be able to stop the stack it started.

    `pkill -x -f` needs the pattern to equal the whole command line, and every
    launch carries arguments past the pattern, so cleanup matched nothing and
    a stale stack kept the ports: the next capture measured a foreign process.
    Nor may a pattern start at "python3": a framework Python on macOS lists
    itself by its full path, measured on the machine the figures are built on.
    """

    def test_every_cleanup_pattern_matches_its_launch(self):
        script = (_REPO / "tools" / "capture_figures.sh").read_text()
        self.assertFalse("pkill -x" in script, "cleanup still uses pkill -x")
        # Each launch as the shell would run it: continuations joined, quotes
        # dropped, the variables named rather than expanded.
        launches = [re.sub(r"\s+", " ", l).replace('"', "") for l in
                    re.sub(r"\\\n\s*", " ", script).splitlines()
                    if "nohup python3" in l]
        patterns = re.findall(r'pkill -f "([^"]+)"', script)
        self.assertEqual(len(patterns), 3, patterns)
        for pattern in patterns:
            # Anchored after the port, so 18099 cannot match 180990.
            self.assertTrue(pattern.endswith("_PORT "), pattern)
            self.assertFalse(pattern.startswith("python3 "),
                             "%r cannot match a macOS framework Python" % pattern)
            self.assertTrue(any(re.search(pattern.replace("$", r"\$"), l)
                                for l in launches),
                            "%r matches no launch" % pattern)


@contextlib.contextmanager
def _ran_main(env, *argv, data_dir=None, setup=None):
    """Run main() to completion with `env` as the only RACCOON_* variables.

    Yields the exit code ("served" if it ran through), what it printed, the
    data directory, the arguments create_app received and which of the two
    secret variables were still in the process environment afterwards. The
    directory is removed when the block ends, so look inside it there.
    """
    made = {}
    real_create_app = server_mod.create_app

    def recording_create_app(*args, **kwargs):
        made["operator_token"] = args[1]
        made["crypto"] = args[0]
        return real_create_app(*args, **kwargs)

    out, err = io.StringIO(), io.StringIO()
    result = {"code": "served", "out": out, "err": err, "made": made}
    own = data_dir is None
    data_dir = tempfile.mkdtemp() if own else data_dir
    result["data_dir"] = Path(data_dir)
    try:
        if setup:
            setup(Path(data_dir))
        with patch.dict(os.environ), \
                patch.object(server_mod, "make_server",
                             side_effect=lambda *a, **k: _FakeListener([], *a, **k)), \
                patch.object(server_mod, "create_app",
                             side_effect=recording_create_app), \
                patch.object(server_mod, "_load_state"), \
                patch.object(server_mod, "_setup_file_logging"), \
                patch.object(server_mod, "_log_event"), \
                patch.object(server_mod.logging, "basicConfig"), \
                patch("sys.argv", ["server.py", "--data-dir", data_dir] + list(argv)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            for name in ("RACCOON_KEY", "RACCOON_TOKEN"):
                os.environ.pop(name, None)
            os.environ.update(env)
            try:
                server_mod.main()
            except SystemExit as exc:
                result["code"] = exc.code
            result["left_in_environment"] = {
                n for n in ("RACCOON_KEY", "RACCOON_TOKEN") if n in os.environ}
        result["out"], result["err"] = out.getvalue(), err.getvalue()
        yield result
    finally:
        if own:
            shutil.rmtree(data_dir, ignore_errors=True)


_SECRET_FLAGS = r"(?:key|token|password|passwd|secret|api-key|apikey)"
# Whatever may sit between a flag and its value: blanks and line breaks, a
# shell backslash or a PowerShell backtick continuation.
_GAP = r"""(?:\s|\\|`)*"""
# A secret-bearing flag, then a variable: `--key "$K"`, `"--key" "$K"`,
# `--key=$K`, PowerShell's `"--key", $Key`, and any of those with the value
# on the next line. The flag must end where it ends -- `--certkey` and
# `--key-file` name paths, not secrets -- and what follows must be a `$`, so
# a usage line (`--key <b64>`), a case pattern (`--key) KEY=...`) and a
# comment do not match.
_SECRET_ARGUMENT = re.compile(
    r"""(?<![\w-])--""" + _SECRET_FLAGS + r"""(?![\w-])["']?""" + _GAP
    + r"""[=,]?""" + _GAP + r"""["']?\$""")


def _without_comments(text):
    """`text` with whole-line comments and PowerShell's `<# ... #>` block
    blanked, so the line numbers that remain are still the file's."""
    kept = []
    in_block = False
    for line in text.splitlines():
        stripped = line.strip().lstrip("\ufeff")
        if stripped.startswith("<#"):
            in_block = True
        if in_block:
            in_block = "#>" not in stripped
            kept.append("")
        elif stripped.startswith("#"):
            kept.append("")
        else:
            kept.append(line)
    return "\n".join(kept)


def _secret_arguments(text):
    """(line number, line) for each place that hands a secret over as an
    argument. The whole text is searched, not line by line, so a flag and its
    variable on separate lines are still one argument. Nothing but whole-line
    comments is skipped: an echo that ends on a flag with a variable on the
    next line would be reported -- and should be reworded."""
    clean = _without_comments(text)
    lines = clean.splitlines()
    return [(clean.count("\n", 0, m.start()) + 1,
             lines[clean.count("\n", 0, m.start())].strip())
            for m in _SECRET_ARGUMENT.finditer(clean)]


_C2_DIR = _REPO / "software" / "c2"
_SECRET_CARRIERS = (
    _C2_DIR / "start_server.sh",
    _C2_DIR / "start_server.ps1",
    _C2_DIR / "docker-entrypoint.sh",
    _C2_DIR / "test_add_agent.sh",
    _C2_DIR / "test_add_agent.ps1",
)


class TestSecretsStayOffTheCommandLine(unittest.TestCase):
    """Finding H8: `ps` and /proc/<pid>/cmdline are readable by every user.

    The server's token and key are read from the environment as well as the
    flags, and nothing that starts the server puts them in its argument list.
    Precedence is the one software/agent/config.py already uses: the flag
    wins, then the environment.
    """

    KEY = key_b64(random_key())
    OTHER_KEY = key_b64(random_key())
    TOKEN = "Qm7vX2kLp9RtHs4NwZb5"
    FLAG_TOKEN = "Bd3yC8zFg6JaUe1VxTq0"

    def _assert_not_echoed(self, value, text):
        self.assertNotIn(value, text)
        for i in range(len(value) - 7):
            self.assertNotIn(value[i:i + 8], text)

    def _roundtrips(self, crypto, key_b64_text):
        probe = {"probe": 1}
        other = server_mod.ServerCrypto(base64.b64decode(key_b64_text))
        try:
            return other.decrypt(crypto.encrypt(probe)) == probe
        except InvalidTag:
            return False

    # ── The server reads the environment ──

    def test_token_can_be_supplied_by_environment(self):
        with _ran_main({"RACCOON_KEY": self.KEY, "RACCOON_TOKEN": self.TOKEN}) as ran:
            self.assertEqual(ran["code"], "served", ran["err"])
            self.assertEqual(ran["made"]["operator_token"], self.TOKEN)

    def test_key_can_be_supplied_by_environment(self):
        with _ran_main({"RACCOON_KEY": self.KEY}) as ran:
            self.assertEqual(ran["code"], "served", ran["err"])
            self.assertTrue(self._roundtrips(ran["made"]["crypto"], self.KEY))

    def test_the_flag_beats_the_environment(self):
        env = {"RACCOON_KEY": self.OTHER_KEY, "RACCOON_TOKEN": self.TOKEN}
        with _ran_main(env, "--key", self.KEY, "--token", self.FLAG_TOKEN) as ran:
            self.assertEqual(ran["code"], "served", ran["err"])
            self.assertEqual(ran["made"]["operator_token"], self.FLAG_TOKEN)
            self.assertTrue(self._roundtrips(ran["made"]["crypto"], self.KEY))
            self.assertFalse(self._roundtrips(ran["made"]["crypto"], self.OTHER_KEY))

    def test_the_flag_wins_even_when_the_environment_key_is_bad(self):
        with _ran_main({"RACCOON_KEY": "not*base64*at*all"}, "--key", self.KEY) as ran:
            self.assertEqual(ran["code"], "served", ran["err"])

    def test_a_blank_variable_is_not_a_value(self):
        # Compose passes `RACCOON_TOKEN=${RACCOON_TOKEN:-}`: empty, not absent.
        with _ran_main({"RACCOON_KEY": "   "}) as ran:
            self.assertIsInstance(ran["code"], int)
            self.assertNotEqual(ran["code"], 0)
        with _ran_main({"RACCOON_KEY": self.KEY, "RACCOON_TOKEN": "  "}) as ran:
            self.assertEqual(ran["code"], "served", ran["err"])
            self.assertGreaterEqual(len(ran["made"]["operator_token"]), 16)

    def test_with_neither_the_refusal_names_both_ways_to_supply_a_key(self):
        with _ran_main({}) as ran:
            self.assertIsInstance(ran["code"], int)
            self.assertNotEqual(ran["code"], 0)
            self.assertIn("--key", ran["err"])
            self.assertIn("RACCOON_KEY", ran["err"])

    def test_a_bad_environment_key_is_refused_by_name_and_never_echoed(self):
        for value in (key_b64(os.urandom(24)), "Zq7Xw9Pk!" + key_b64(os.urandom(12))):
            with self.subTest(length=len(value)):
                with _ran_main({"RACCOON_KEY": value}) as ran:
                    self.assertIsInstance(ran["code"], int)
                    self.assertNotEqual(ran["code"], 0)
                    self.assertIn("RACCOON_KEY", ran["err"])
                    self._assert_not_echoed(value, ran["err"])

    def test_help_states_the_precedence_and_the_reason(self):
        out = io.StringIO()
        with patch("sys.argv", ["server.py", "--help"]), \
                contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit):
                server_mod.main()
        text = " ".join(out.getvalue().split())
        for variable in ("RACCOON_KEY", "RACCOON_TOKEN"):
            self.assertRegex(text, variable + r"[;,.][^.]*(wins|takes precedence)",
                             variable)
        self.assertIn("ps", text)

    def test_the_secrets_do_not_pass_on_to_the_tools_the_server_starts(self):
        # nxc, impacket and the rest inherit the server's environment.
        env = {"RACCOON_KEY": self.KEY, "RACCOON_TOKEN": self.TOKEN}
        with _ran_main(env) as ran:
            self.assertEqual(ran["code"], "served", ran["err"])
            self.assertEqual(ran["left_in_environment"], set())

    # ── The token stays discoverable: in a file, by path ──

    def _token_file(self, ran):
        return ran["data_dir"] / server_mod._TOKEN_FILE

    def test_the_token_is_kept_in_a_file_only_its_owner_can_read(self):
        old = os.umask(0)  # a permissive umask must not widen the file
        self.addCleanup(os.umask, old)
        with patch("os.chmod", side_effect=AssertionError("created, then chmod-ed")), \
                patch("os.fchmod", side_effect=AssertionError("created, then chmod-ed"),
                      create=True):
            with _ran_main({"RACCOON_KEY": self.KEY, "RACCOON_TOKEN": self.TOKEN}) as ran:
                path = self._token_file(ran)
                self.assertEqual(ran["code"], "served", ran["err"])
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(path.read_text().strip(), self.TOKEN)

    def test_a_generated_token_can_be_found_in_the_file(self):
        with _ran_main({"RACCOON_KEY": self.KEY}) as ran:
            self.assertEqual(self._token_file(ran).read_text().strip(),
                             ran["made"]["operator_token"])

    def test_the_banner_names_the_file_and_neither_secret(self):
        env = {"RACCOON_KEY": self.KEY}
        with _ran_main(env, "--token", self.FLAG_TOKEN) as ran:
            self.assertIn(str(self._token_file(ran)), ran["out"])
            self.assertIn("Token:", ran["out"])
            self._assert_not_echoed(self.FLAG_TOKEN, ran["out"] + ran["err"])
            self._assert_not_echoed(self.KEY, ran["out"] + ran["err"])
        with _ran_main(env) as ran:
            generated = ran["made"]["operator_token"]
            self._assert_not_echoed(generated, ran["out"] + ran["err"])

    def test_a_looser_file_left_by_an_earlier_run_is_replaced(self):
        def leave_one(data_dir):
            path = data_dir / server_mod._TOKEN_FILE
            path.write_text("stale-token")
            path.chmod(0o644)
        with _ran_main({"RACCOON_KEY": self.KEY, "RACCOON_TOKEN": self.TOKEN},
                       setup=leave_one) as ran:
            path = self._token_file(ran)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.read_text().strip(), self.TOKEN)

    def test_a_link_put_in_its_place_is_not_followed(self):
        victim = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, victim, ignore_errors=True)
        target = victim / "precious"
        target.write_text("untouched")

        def plant(data_dir):
            (data_dir / server_mod._TOKEN_FILE).symlink_to(target)
        with _ran_main({"RACCOON_KEY": self.KEY, "RACCOON_TOKEN": self.TOKEN},
                       setup=plant) as ran:
            self.assertEqual(target.read_text(), "untouched")
            path = self._token_file(ran)
            self.assertFalse(path.is_symlink())
            self.assertEqual(path.read_text().strip(), self.TOKEN)

    def test_a_file_that_cannot_be_written_stops_the_server_naming_only_the_path(self):
        def block(data_dir):
            (data_dir / server_mod._TOKEN_FILE).mkdir()
            (data_dir / server_mod._TOKEN_FILE / "occupied").write_text("x")
        with _ran_main({"RACCOON_KEY": self.KEY, "RACCOON_TOKEN": self.TOKEN},
                       setup=block) as ran:
            self.assertIsInstance(ran["code"], int)
            self.assertNotEqual(ran["code"], 0)
            self.assertIn(str(self._token_file(ran)), ran["err"])
            self._assert_not_echoed(self.TOKEN, ran["err"] + ran["out"])

    # ── Nothing that starts the server puts a secret in its arguments ──

    def test_no_launcher_passes_a_secret_as_an_argument(self):
        for path in _SECRET_CARRIERS:
            with self.subTest(file=path.name):
                self.assertTrue(path.is_file(), path)
                self.assertEqual(_secret_arguments(path.read_text(encoding="utf-8")), [])

    def test_the_scan_is_precise(self):
        # A scanner that cried wolf would be deleted, one that missed a form
        # would be worse: both directions are pinned.
        leaks = [
            'CMD+=("--key" "$KEY")',
            '[ -n "$RACCOON_KEY" ]   && CMD+=(--key "$RACCOON_KEY")',
            "[ -n \"$T\" ] && CMD+=(--token \"$T\")",
            '"--token" "$TOKEN")',
            "python3 server.py --token $TOKEN",
            "python3 server.py --token=${TOKEN}",
            '$PyArgs += "--key", $Key',
            '"--host", $Host_, "--key", $Key, "--interval", $Interval',
            "--password '$PW'",
        ]
        quiet = [
            '--key)        KEY="$2"; KEY_ORIGIN="passed with --key"; shift 2;;',
            'echo "Usage: $0 [--key <b64>] [--token <str>] [--certkey <file>]"',
            'echo -e "  ${D}Pass --key <base64>, or run interactively${N}"',
            "# CMD+=(--key \"$KEY\")  is what this used to be",
            "    # --token $TOKEN",
            '[[ -n "$CERTKEY" ]]    && CMD+=("--certkey" "$CERTKEY")',
            'CMD+=("--key-file" "$KEYFILE")',
            'CMD+=("--cert" "$CERT")',
            'parser.add_argument("--token", help="Fixed operator token")',
        ]
        for line in leaks:
            with self.subTest(leak=line):
                self.assertEqual(len(_secret_arguments(line)), 1)
        for line in quiet:
            with self.subTest(quiet=line):
                self.assertEqual(_secret_arguments(line), [])
        block = "<#\n.EXAMPLE\n    .\\x.ps1 --key $Key\n#>\nparam()\n"
        self.assertEqual(_secret_arguments(block), [])

    def test_the_scan_follows_a_flag_onto_the_next_line(self):
        split = [
            'CMD+=(--key\n    "$KEY")',
            'CMD+=("--token"\n     "$TOKEN")',
            'CMD=(python3 server.py \\\n    --token \\\n    "$TOKEN")',
            '$PyArgs = @($ServerPy,\n    "--key",\n    $Key)',
            '$PyArgs = @($ServerPy, "--key" `\n    , $Key)',
            'CMD+=(--key\n    # held back for later\n    "$KEY")',
        ]
        for text in split:
            with self.subTest(split=text):
                found = _secret_arguments(text)
                self.assertEqual(len(found), 1)
                self.assertIn("--", found[0][1], "reported on the flag's line")
        # The report names the flag's line, not the value's.
        self.assertEqual(_secret_arguments("a\nb\nCMD+=(--key\n\"$K\")")[0][0], 3)

    def test_the_wider_scan_still_ignores_what_is_not_a_secret_argument(self):
        quiet = [
            '--key)        KEY="$2"; KEY_ORIGIN="passed with --key"; shift 2;;',
            '--token)      TOKEN="$2"; shift 2;;',
            'echo "Usage: $0 [--key <b64>] [--token <str>] [--certkey <file>]"',
            'echo -e "  ${D}Pass --key <base64>, or run interactively${N}"',
            "# CMD+=(--key \"$KEY\")  is what this used to be",
            "    # --token $TOKEN",
            '[[ -n "$CERTKEY" ]]    && CMD+=("--certkey" "$CERTKEY")',
            'CMD+=("--key-file" "$KEYFILE")',
            'CMD+=("--cert" "$CERT")',
            'parser.add_argument("--token", help="Fixed operator token")',
            'echo "  --key wins over RACCOON_KEY"',
        ]
        for line in quiet:
            with self.subTest(quiet=line):
                self.assertEqual(_secret_arguments(line), [])
        # Joined, as the whole-text search sees a file: neighbouring lines
        # must not combine into a finding.
        self.assertEqual(_secret_arguments("\n".join(quiet)), [])
        self.assertEqual(_secret_arguments("\n".join(quiet * 2)), [])

    # ── Nothing prints a whole secret ──

    def _echo_lines(self, text):
        return [line for line in text.splitlines()
                if re.match(r"\s*(echo|Write-Host|print)\b", line)]

    def test_launchers_do_not_echo_a_full_key(self):
        shown = {"start_server.sh": (r"\$\{?ENC_KEY_B64\b", r":0:(\d+)"),
                 "start_server.ps1": (r"\$EncKeyB64\b", r"Substring\(0,\s*(\d+)\)")}
        for name, (full, sliced) in shown.items():
            text = (_C2_DIR / name).read_text(encoding="utf-8")
            with self.subTest(file=name):
                self.assertRegex(text, r"(?i)key_?preview")
                for line in self._echo_lines(text):
                    self.assertNotRegex(line, full + r"(?!\w)(?!\.Substring)(?!:0:)")
                lengths = [int(n) for n in re.findall(sliced, text)]
                self.assertTrue(lengths, "no truncation found")
                self.assertLessEqual(max(lengths), 8)

    def test_the_test_agent_launchers_show_no_more_of_the_key(self):
        sh = (_C2_DIR / "test_add_agent.sh").read_text(encoding="utf-8")
        ps = (_C2_DIR / "test_add_agent.ps1").read_text(encoding="utf-8")
        shown = [int(n) for n in re.findall(r"KEY:0:(\d+)", sh)]
        shown += [int(n) for n in re.findall(r"Substring\(0,\s*(\d+)\)", ps)]
        self.assertTrue(shown)
        self.assertLessEqual(max(shown), 8)

    def test_launchers_print_the_token_file_and_never_the_token(self):
        for name, token in (("start_server.sh", r"\$\{?TOKEN\b"),
                            ("start_server.ps1", r"\$Token\b")):
            text = (_C2_DIR / name).read_text(encoding="utf-8")
            with self.subTest(file=name):
                self.assertIn(server_mod._TOKEN_FILE, text)
                for line in self._echo_lines(text):
                    self.assertNotRegex(line, token, line)

    # ── Typing a secret does not show it ──

    @staticmethod
    def _prompts_before_reads(text, reader, shell=False):
        """(prompt text, reading line) for each line that reads input.

        The prompt is the line above it in a shell script; in PowerShell it
        is the run of Write-Host lines above, back to the last blank one.
        """
        lines = text.splitlines()
        found = []
        for i, line in enumerate(lines):
            if not re.search(reader, line):
                continue
            prompt = []
            for before in reversed(lines[:i]):
                if not before.strip():
                    continue
                if shell:
                    prompt.append(before)
                    break
                if before.strip() == 'Write-Host ""' or "Write-Host" not in before:
                    break
                prompt.append(before)
            found.append((" ".join(prompt), line.strip()))
        return found

    def test_a_typed_key_or_token_is_not_echoed_by_the_shell_launchers(self):
        for name in ("start_server.sh", "test_add_agent.sh"):
            text = (_C2_DIR / name).read_text(encoding="utf-8")
            reads = self._prompts_before_reads(text, r"^\s*read\b", shell=True)
            secret = [(p, r) for p, r in reads
                      if re.search(r"(?i)\bkey\b|operator token", p)]
            with self.subTest(file=name):
                self.assertTrue(secret, "found no key or token prompt")
                for prompt, read in secret:
                    self.assertRegex(read, r"read\s+-\w*s\w*\s",
                                     "reads a secret with the terminal echoing it")
                # Silent reading leaves the cursor on the prompt's line.
                for number, line in enumerate(text.splitlines()):
                    if any(line.strip() == r for _, r in secret):
                        self.assertIn("echo", text.splitlines()[number + 1], line)

    def test_a_typed_key_or_token_is_not_echoed_by_the_powershell_launchers(self):
        for name in ("start_server.ps1", "test_add_agent.ps1"):
            text = (_C2_DIR / name).read_text(encoding="utf-8")
            reads = self._prompts_before_reads(text, r"Read-(Host|Secret)")
            secret = [(p, r) for p, r in reads
                      if re.search(r"(?i)\bkey\b|operator token", p)]
            with self.subTest(file=name):
                self.assertTrue(secret, "found no key or token prompt")
                for prompt, read in secret:
                    self.assertIn("Read-Secret", read)
                self.assertRegex(text, r"function Read-Secret")
                self.assertIn("-AsSecureString", text)
                self.assertIn("ZeroFreeBSTR", text)

    # ── What replaces the arguments ──

    def test_the_container_entrypoint_does_not_convert_the_environment_to_argv(self):
        text = (_C2_DIR / "docker-entrypoint.sh").read_text(encoding="utf-8")
        self.assertNotIn("RACCOON_KEY", re.sub(r"(?m)^\s*#.*$", "", text))
        self.assertNotIn("RACCOON_TOKEN", re.sub(r"(?m)^\s*#.*$", "", text))
        self.assertIn("exec", text)

    def test_the_shell_launchers_hand_the_secrets_over_in_the_environment(self):
        text = (_C2_DIR / "start_server.sh").read_text(encoding="utf-8")
        self.assertRegex(text, r'RACCOON_KEY="\$KEY"\s+RACCOON_TOKEN="\$TOKEN"\s+exec ')
        # ...and read them back when the operator exported them instead.
        self.assertIn('${RACCOON_KEY:-}', text)
        self.assertIn('${RACCOON_TOKEN:-}', text)
        self.assertRegex(text, r'--data-dir"?\s+"?\$DATA_DIR')

    def test_the_powershell_launcher_hands_the_secrets_over_in_the_environment(self):
        text = (_C2_DIR / "start_server.ps1").read_text(encoding="utf-8")
        self.assertRegex(text, r"\$env:RACCOON_KEY\s*=\s*\$Key")
        self.assertRegex(text, r"\$env:RACCOON_TOKEN\s*=\s*\$Token")
        self.assertIn("--data-dir", text)
        self.assertLess(text.index("$env:RACCOON_KEY = $Key"),
                        text.index("& $Python @PyArgs"))

    def test_the_powershell_launchers_put_back_the_environment_they_found(self):
        # A script run as .\\x.ps1 shares the operator's session, so what it
        # sets would otherwise outlive the server and be reused, unannounced,
        # by the next run's RACCOON_KEY fallback.
        for name, names in (("start_server.ps1", ("RACCOON_KEY", "RACCOON_TOKEN")),
                            ("test_add_agent.ps1", ("RACCOON_KEY",))):
            text = (_C2_DIR / name).read_text(encoding="utf-8")
            launch = text.index("& $Python @PyArgs")
            tail = text[text.rindex("# -- Launch --"):]
            with self.subTest(file=name):
                self.assertIn("try {", tail)
                self.assertIn("finally {", tail)
                for var in names:
                    prior = "$Prior" + var[len("RACCOON_"):].capitalize()
                    saved = text.index("%s = $env:%s" % (prior, var))
                    set_ = text.index("$env:%s = " % var, saved)
                    self.assertLess(saved, set_)
                    self.assertLess(set_, launch)
                    restore = text[text.index("finally {", launch):]
                    self.assertIn("Remove-Item Env:" + var, restore)
                    self.assertIn("$env:%s = %s" % (var, prior), restore)

    def test_the_shell_launcher_does_not_claim_more_than_it_does(self):
        # The agent is started earlier from the same environment the
        # operator left, so "only the server gets the key" would be untrue
        # if they had exported RACCOON_KEY themselves.
        text = (_C2_DIR / "start_server.sh").read_text(encoding="utf-8")
        self.assertNotIn("Only the server gets the key", text)
        self.assertNotIn("the agent above never needed it", text)

    def test_a_write_failure_with_no_reason_does_not_print_none(self):
        with patch.object(server_mod, "_write_operator_token",
                          side_effect=OSError()):
            with _ran_main({"RACCOON_KEY": self.KEY,
                            "RACCOON_TOKEN": self.TOKEN}) as ran:
                self.assertIsInstance(ran["code"], int)
                self.assertNotEqual(ran["code"], 0)
                self.assertNotIn("None", ran["err"])
                self.assertIn(server_mod._TOKEN_FILE, ran["err"])

    def test_the_readme_says_the_token_file_stays_after_exit(self):
        text = " ".join((_REPO / "README.md").read_text(encoding="utf-8").split())
        signing_in = text[text.index("**Signing in:**"):]
        signing_in = signing_in[:signing_in.index("**GUI Features:**")]
        self.assertIn("operator-token", signing_in)
        self.assertIn("not removed on exit", signing_in)
        self.assertIn("whether the token was generated or supplied", signing_in)

    def test_the_launchers_and_the_server_agree_on_the_data_directory(self):
        sh = (_C2_DIR / "start_server.sh").read_text(encoding="utf-8")
        ps = (_C2_DIR / "start_server.ps1").read_text(encoding="utf-8")
        self.assertRegex(sh, r'DATA_DIR="\$HOME/\.raccoon-c2"')
        self.assertRegex(ps, r'\$DataDir\s*=\s*Join-Path \$env:USERPROFILE "\.raccoon-c2"')
        self.assertIn('Path.home() / ".raccoon-c2"',
                      (_C2_DIR / "server.py").read_text(encoding="utf-8"))

    def test_the_test_agent_reads_the_key_from_the_environment_too(self):
        script = str(_C2_DIR / "test_add_agent.py")
        env = {k: v for k, v in os.environ.items() if k != "RACCOON_KEY"}
        bad = subprocess.run([sys.executable, script], env=env, timeout=30,
                             capture_output=True, text=True)
        self.assertEqual(bad.returncode, 1)
        self.assertIn("RACCOON_KEY", bad.stdout)
        env["RACCOON_KEY"] = "not*base64*at*all"
        bad = subprocess.run([sys.executable, script], env=env, timeout=30,
                             capture_output=True, text=True)
        self.assertEqual(bad.returncode, 1)
        self.assertIn("RACCOON_KEY is not valid base64", bad.stdout)
        self.assertNotIn("not*base64", bad.stdout + bad.stderr)


# New test classes belong above this guard; never append below it.
if __name__ == "__main__":
    unittest.main()
