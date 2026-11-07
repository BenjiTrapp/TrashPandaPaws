#!/usr/bin/env python3
"""Tests for the beacon's alternative transports and their listeners.

The beacon is the specification for every listener in this package: its
request builders are the only description of the wire format that exists.
So the tests here exercise the real client against the real
`ServerCrypto`, not a mock of either -- a mock would agree with whatever
the code does and prove nothing about the two sides matching.
"""

import base64
import json
import logging
import os
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from software.c2 import beacon as beacon_mod
from software.c2.beacon import Beacon
from software.c2.listeners.relay import relay
from software.c2.server import ServerCrypto


def _read_source(*parts):
    """Read a file in the repository as text, for assertions about it."""
    return Path(__file__).resolve().parents[2].joinpath(*parts).read_text()


def _imports_and_names(*parts):
    """Every module a file imports, and every identifier it uses in code.

    Parsed with `ast` rather than grepped, so a module that explains in
    prose which packages it deliberately avoids does not fail a test about
    what it imports.
    """
    import ast
    tree = ast.parse(_read_source(*parts))
    imported, used = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name)
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            imported.add(base)
            if base:
                imported.add(base.split(".")[0])
            for alias in node.names:
                used.add(alias.name)
        elif isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            used.add(node.attr)
    return imported, used


_PAYLOAD_FIELD_FOR_TEST = beacon_mod._PAYLOAD_FIELDS[0]


def _key_pair():
    """One key, both ends -- the mismatch this repository has paid for twice."""
    raw = os.urandom(32)
    return raw, base64.b64encode(raw).decode()


def _beacon(key_b64, **protocols):
    cfg = {"c2": {"encryption_key": key_b64,
                  "https": {"enabled": False},
                  "dns": {"enabled": False}}}
    cfg["c2"].update(protocols)
    return Beacon(cfg)


class TestTheEncryptContract(unittest.TestCase):
    """`_encrypt(data: dict)` serialises its own argument.

    Given bytes it raised `TypeError` from inside `json.dumps` and the
    caller's `except` discarded it, so three transports never put a byte on
    the wire. Given a `str` it would have serialised a second time and
    produced JSON inside JSON -- no error, and a peer decrypting it would
    get a string where it expected a dict. The type hint said `dict` all
    along; these tests make it true.
    """

    def setUp(self):
        self.raw, self.b64 = _key_pair()
        self.crypto = ServerCrypto(self.raw)

    # ── the contract itself ──

    def test_encrypt_accepts_a_dict(self):
        b = _beacon(self.b64)
        out = b._encrypt({"action": "beacon"})
        self.assertIsInstance(out, str)
        self.assertEqual(self.crypto.decrypt(out), {"action": "beacon"})

    def test_encrypt_refuses_a_str(self):
        b = _beacon(self.b64)
        with self.assertRaises(TypeError) as caught:
            b._encrypt(json.dumps({"action": "beacon"}))
        message = str(caught.exception)
        self.assertIn("dict", message)
        # The type received must appear too, or the message tells a caller
        # what was wanted and not what it gave.
        self.assertIn("str", message)

    def test_encrypt_refuses_bytes(self):
        b = _beacon(self.b64)
        with self.assertRaises(TypeError) as caught:
            b._encrypt(json.dumps({"action": "beacon"}).encode())
        message = str(caught.exception)
        self.assertIn("dict", message)
        self.assertIn("bytes", message)

    def test_the_refusal_names_the_parameter(self):
        b = _beacon(self.b64)
        with self.assertRaises(TypeError) as caught:
            b._encrypt(b"x")
        self.assertIn("data", str(caught.exception))

    def test_encrypt_refuses_none_and_a_list(self):
        b = _beacon(self.b64)
        for bad in (None, [{"action": "beacon"}], 7):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    b._encrypt(bad)

    def test_the_refusal_never_contains_the_value(self):
        # The argument is plaintext about to be encrypted. The message may
        # name the parameter and the type; it may not quote the content.
        b = _beacon(self.b64)
        secret = "sensitive-marker-9f3a1c"
        for bad in (json.dumps({"k": secret}), json.dumps({"k": secret}).encode()):
            with self.subTest(kind=type(bad).__name__):
                with self.assertRaises(TypeError) as caught:
                    b._encrypt(bad)
                self.assertNotIn(secret, str(caught.exception))

    # ── the three call sites, through the real ServerCrypto ──

    def _smb_capture(self, b):
        """Run an SMB path with the socket layer stubbed; return what it wrote."""
        written = []
        return written, (
            patch.object(b, "_smb_connect", return_value=MagicMock()),
            patch.object(b, "_smb_write_pipe",
                         side_effect=lambda sock, data: written.append(data) or True),
            patch.object(b, "_smb_read_pipe", return_value=None),
        )

    def _enter(self, patches):
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_smb_checkin_payload_round_trips_through_server_crypto(self):
        b = _beacon(self.b64, smb={"enabled": True, "server": "10.0.0.1"})
        written, patches = self._smb_capture(b)
        self._enter(patches)

        b._beacon_smb()

        self.assertEqual(len(written), 1, "the check-in wrote nothing")
        payload = written[0]
        if isinstance(payload, bytes):
            payload = payload.decode()
        got = self.crypto.decrypt(payload)
        self.assertIsInstance(got, dict,
                              "the server decrypted a %s, not a dict"
                              % type(got).__name__)
        self.assertEqual(got["action"], "register")
        # On first contact the implant is identified by "id"; "agent_id" is
        # None until the server assigns one. _system_info() carries both,
        # and HTTPS does exactly the same -- so a listener must key off
        # "id" for a registration, not "agent_id".
        self.assertEqual(got["id"], b._implant_id)
        self.assertIsNone(got["agent_id"])

    def test_smb_result_payload_round_trips(self):
        b = _beacon(self.b64, smb={"enabled": True, "server": "10.0.0.1"})
        written, patches = self._smb_capture(b)
        self._enter(patches)

        b._send_result_smb("task-1", "ok", "uid=0(root)")

        self.assertEqual(len(written), 1, "the result wrote nothing")
        payload = written[0]
        if isinstance(payload, bytes):
            payload = payload.decode()
        got = self.crypto.decrypt(payload)
        self.assertIsInstance(got, dict)
        self.assertEqual(got["action"], "result")
        self.assertEqual(got["task_id"], "task-1")
        self.assertEqual(got["output"], "uid=0(root)")

    def test_quic_payload_round_trips(self):
        b = _beacon(self.b64, quic={"enabled": True, "server": "10.0.0.1:4433"})
        sent = []

        class _FakeUdp:
            def settimeout(self, _):
                pass

            def sendto(self, data, _addr):
                sent.append(data)

            def recvfrom(self, _n):
                raise OSError("no answer in this test")

            def close(self):
                pass

        self._enter((patch.object(beacon_mod.socket, "socket",
                                  side_effect=lambda *a, **k: _FakeUdp()),))

        b._quic_send({"action": "beacon", "agent_id": "probe"})

        self.assertTrue(sent, "the QUIC path sent nothing")
        # Each datagram is [stream_id(4)][frag_index(2)][total_frags(2)]
        # then the chunk -- struct ">IHH", eight bytes, not sixteen.
        frame = b"".join(d[8:] for d in sent)
        # The frame itself is [4-byte big-endian length][payload].
        length = int.from_bytes(frame[:4], "big")
        body = frame[4:4 + length]
        self.assertEqual(len(body), length, "the frame length header lies")
        got = self.crypto.decrypt(body.decode())
        self.assertIsInstance(got, dict)
        self.assertEqual(got["action"], "beacon")
        self.assertEqual(got["agent_id"], "probe")


class TestTheRelay(unittest.TestCase):
    """The relay moves an opaque string and never learns what is in it.

    It is the one piece all three listeners share, so it is also the one
    place where a key could leak into a container that has no business
    holding one. The tests therefore pin two things that are easy to lose
    later: that its signature takes no key, and that its module imports
    nothing from the crypto code.

    Everything else runs against a real HTTP server on an ephemeral port.
    A mock would agree with whatever the relay does; the point is that the
    far end finds the payload where the relay puts it.
    """

    def setUp(self):
        self.raw, self.b64 = _key_pair()
        self.crypto = ServerCrypto(self.raw)
        self._servers = []
        # werkzeug's development server logs every request at INFO, which
        # would put a line per test into the suite's output. This project
        # keeps that output pristine.
        quiet = logging.getLogger("werkzeug")
        previous = quiet.level
        quiet.setLevel(logging.ERROR)
        self.addCleanup(quiet.setLevel, previous)

    def _serve(self, handler):
        """Run `handler(body_dict) -> (status, dict|None)` on a free port."""
        from werkzeug.serving import make_server

        def app(environ, start_response):
            length = int(environ.get("CONTENT_LENGTH") or 0)
            body = json.loads(environ["wsgi.input"].read(length) or b"{}")
            status, answer = handler(body)
            payload = json.dumps(answer or {}).encode()
            start_response("%d WHATEVER" % status,
                           [("Content-Type", "application/json"),
                            ("Content-Length", str(len(payload)))])
            return [payload]

        srv = make_server("127.0.0.1", 0, app, threaded=True)
        self._servers.append(srv)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return "http://127.0.0.1:%d/" % srv.server_port

    # ── the happy path, both directions ──

    def test_a_payload_reaches_the_server_and_the_answer_comes_back(self):
        seen = []

        def handler(body):
            seen.append(body)
            return 200, self.crypto.wrap({"tasks": [{"cmd": "shell"}]})

        url = self._serve(handler)
        sent = self.crypto.encrypt({"action": "beacon"})
        got = relay(sent, url=url)

        self.assertIsNotNone(got, "the relay returned nothing")
        self.assertEqual(self.crypto.decrypt(got), {"tasks": [{"cmd": "shell"}]})
        self.assertEqual(len(seen), 1)

    def test_the_request_field_is_one_the_server_scans_for(self):
        # unwrap() checks 14 named fields and then falls back to any string
        # over 32 characters. The fallback is robustness, not an interface:
        # the relay must land in the named loop.
        seen = []
        url = self._serve(lambda body: (seen.append(body) or (200, {})))
        sent = self.crypto.encrypt({"action": "beacon"})
        relay(sent, url=url)

        self.assertEqual(len(seen), 1)
        field = next(k for k, v in seen[0].items() if v == sent)
        self.assertIn(field, beacon_mod._PAYLOAD_FIELDS,
                      "the relay used a field unwrap()'s named loop misses")
        self.assertEqual(self.crypto.unwrap(seen[0]), {"action": "beacon"})

    def test_the_answer_is_found_whichever_field_carries_it(self):
        # ServerCrypto.wrap picks the field at random, so the relay cannot
        # rely on a fixed one.
        answer = {"tasks": []}
        for field in beacon_mod._PAYLOAD_FIELDS:
            with self.subTest(field=field):
                body = {field: self.crypto.encrypt(answer), "seq": 7}
                url = self._serve(lambda _b, body=body: (200, body))
                got = relay(self.crypto.encrypt({"action": "beacon"}), url=url)
                self.assertIsNotNone(got, "field %s was not found" % field)
                self.assertEqual(self.crypto.decrypt(got), answer)

    # ── failure is None, never an exception ──

    def test_a_server_that_is_down_gives_None(self):
        import socket as _s
        probe = _s.socket()
        probe.bind(("127.0.0.1", 0))
        dead = probe.getsockname()[1]
        probe.close()
        self.assertIsNone(relay("x" * 40, url="http://127.0.0.1:%d/" % dead,
                                timeout=2.0))

    def test_a_server_that_hangs_gives_None_within_the_timeout(self):
        # A hang here would hold a listener's connection open. The timeout
        # is the whole reason it does not, so assert the clock too.
        def handler(_body):
            time.sleep(5)
            return 200, {}

        url = self._serve(handler)
        start = time.monotonic()
        got = relay("x" * 40, url=url, timeout=1.0)
        elapsed = time.monotonic() - start

        self.assertIsNone(got)
        self.assertLess(elapsed, 4.0,
                        "the relay waited %.1fs on a 1s timeout" % elapsed)

    def test_a_non_200_gives_None(self):
        for status in (401, 404, 500, 503):
            with self.subTest(status=status):
                url = self._serve(lambda _b, s=status: (s, {}))
                self.assertIsNone(relay("x" * 40, url=url, timeout=5.0))

    def test_a_200_with_no_usable_field_gives_None(self):
        for answer in ({}, {"seq": 1, "ok": True}, {"short": "abc"}):
            with self.subTest(answer=answer):
                url = self._serve(lambda _b, a=answer: (200, a))
                self.assertIsNone(relay("x" * 40, url=url, timeout=5.0))

    def test_an_answer_over_the_ceiling_gives_None(self):
        # Found by enumerating the failure modes rather than by reading:
        # without a ceiling, a 1 MB body with one long string came back as
        # a 1 MB payload, and the listener above would have fragmented that
        # into some 850 datagrams on a hostile server's behalf.
        from software.c2.listeners import relay as relay_mod
        from werkzeug.serving import make_server

        oversized = (b'{"x":"' + b"y" * (relay_mod._MAX_ANSWER_BYTES + 64)
                     + b'"}')

        def app(environ, start_response):
            start_response("200 OK",
                           [("Content-Type", "application/json"),
                            ("Content-Length", str(len(oversized)))])
            return [oversized]

        srv = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        url = "http://127.0.0.1:%d/" % srv.server_port
        self.assertIsNone(relay("x" * 40, url=url, timeout=30.0))

    def test_an_answer_just_under_the_ceiling_still_arrives(self):
        # The ceiling must not reject real work. A task may carry a file.
        from software.c2.listeners import relay as relay_mod
        payload = self.crypto.encrypt({"tasks": [{"cmd": "upload"}]})
        filler = "z" * 4096
        url = self._serve(lambda _b: (200, {_PAYLOAD_FIELD_FOR_TEST: payload,
                                            "pad": filler}))
        got = relay("x" * 40, url=url, timeout=30.0)
        self.assertIsNotNone(got)
        self.assertEqual(self.crypto.decrypt(got),
                         {"tasks": [{"cmd": "upload"}]})
        self.assertLess(len(filler), relay_mod._MAX_ANSWER_BYTES)

    def test_a_decoy_field_cannot_be_mistaken_for_the_payload(self):
        # ServerCrypto.wrap adds decoy fields beside the payload. Measured
        # over 200 draws: every decoy is an int or a float, never a string,
        # so the scan cannot return one. This test holds that property on
        # the server's side, where it is decided.
        from software.c2.server import _decoy_fields
        for _ in range(50):
            for value in _decoy_fields(8).values():
                self.assertNotIsInstance(
                    value, str,
                    "a decoy field became a string; the relay's scan takes "
                    "the first long string it finds")

    def test_a_200_with_a_body_that_is_not_json_gives_None(self):
        from werkzeug.serving import make_server

        def app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/html"),
                                      ("Content-Length", "5")])
            return [b"<html"]

        srv = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        url = "http://127.0.0.1:%d/" % srv.server_port
        self.assertIsNone(relay("x" * 40, url=url, timeout=5.0))

    # ── the relay cannot be handed a key ──

    def test_the_signature_takes_no_key(self):
        import inspect
        params = set(inspect.signature(relay).parameters)
        self.assertEqual(params, {"payload", "url", "timeout"})
        for name in params:
            self.assertNotIn("key", name.lower())

    def test_the_module_imports_nothing_from_the_crypto_code(self):
        # Parsed, not grepped: the module's own prose explains which
        # packages it avoids and why, so a substring scan fires on the
        # explanation. What matters is what it imports and what names it
        # uses in code.
        imported, used = _imports_and_names("software", "c2", "listeners",
                                            "relay.py")
        for banned in ("cryptography", "software.c2.server"):
            self.assertNotIn(banned, imported,
                             "relay.py imports %s; it must never be able "
                             "to hold or use a key" % banned)
        for banned in ("ServerCrypto", "AESGCM", "decode_key",
                       "_aes_gcm_encrypt", "_aes_gcm_decrypt"):
            self.assertNotIn(banned, used,
                             "relay.py uses %s in code" % banned)

    def test_the_module_needs_no_third_party_import(self):
        # A listener container must stay stdlib-only. server.py pulls in
        # flask, werkzeug, cryptography, jinja2 and click -- measured;
        # beacon.py pulls in none of them, which is why the field list
        # comes from there.
        imported, _ = _imports_and_names("software", "c2", "listeners",
                                         "relay.py")
        third_party = {"flask", "werkzeug", "cryptography", "jinja2", "click",
                       "requests"}
        self.assertEqual(third_party & imported, set(),
                         "relay.py imports %s" % (third_party & imported))
        for name in imported:
            self.assertFalse(name.endswith(".server") or name == "server",
                             "relay.py imports the team server module (%s)"
                             % name)


# New test classes belong above this guard; never append below it.
if __name__ == "__main__":
    unittest.main()
