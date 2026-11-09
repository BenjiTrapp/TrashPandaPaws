#!/usr/bin/env python3
"""
Unit tests for the tunnel's key store: one static X25519 keypair per
deployment and one pre-shared key per build.

Three things these tests are careful about.

**The permission tests do not depend on the ambient umask.** A restrictive
umask (077 is common in CI containers) turns a careless `open(path, "w")`
into a 0600 file, so a mode assertion that merely passes proves nothing.
Each one therefore runs under umask 000, restores it afterwards, and
creates a control file or directory *without* an explicit mode to show that
the same umask would have produced something readable by everyone. The
store's 0600 and 0700 are then demonstrably its own doing.

**The mode is read back with `stat`**, from the file on disk, not inferred
from the call that was supposed to set it.

**A malformed store is checked field by field.** Each case writes a file
that is wrong in exactly one way and asserts the error names both the file
and the field, because "something is wrong with your keys" is not a message
anybody can act on at the moment a tunnel fails to start.
"""

import base64
import json
import os
import stat
import tempfile
import unittest

from software.c2 import beacon as beacon_mod
from software.c2.tunnel.keys import KeyStore


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class KeyStoreTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = os.path.join(tmp.name, "keys")
        self.path = os.path.join(self.dir, "tunnel_keys.json")

    def open_permissive_umask(self):
        previous = os.umask(0)
        self.addCleanup(os.umask, previous)


class TestFirstUse(KeyStoreTestCase):
    def test_first_use_mints_a_keypair_and_persists_it(self):
        self.assertFalse(os.path.exists(self.path))
        store = KeyStore(self.path)
        self.assertTrue(os.path.isfile(self.path))
        private, public = store.static_private(), store.static_public()
        self.assertEqual(len(private), 32)
        self.assertEqual(len(public), 32)
        self.assertNotEqual(private, public)
        # The public half is the one the private half derives, not an
        # independent value that happens to be stored beside it.
        self.assertEqual(
            public,
            beacon_mod._x25519(private, beacon_mod._X25519_BASEPOINT),
        )
        with open(self.path) as handle:
            on_disk = json.load(handle)
        self.assertEqual(base64.b64decode(on_disk["static_private"]), private)

    def test_second_open_returns_the_same_public_key(self):
        first = KeyStore(self.path)
        second = KeyStore(self.path)
        self.assertEqual(first.static_public(), second.static_public())
        self.assertEqual(first.static_private(), second.static_private())

    def test_a_second_deployment_gets_its_own_keypair(self):
        other = os.path.join(self.dir, "other.json")
        self.assertNotEqual(
            KeyStore(self.path).static_public(), KeyStore(other).static_public()
        )


class TestPermissions(KeyStoreTestCase):
    def test_private_key_file_is_0600(self):
        self.open_permissive_umask()
        control_file = os.path.join(os.path.dirname(self.dir), "control.txt")
        with open(control_file, "w"):
            pass
        control_dir = os.path.join(os.path.dirname(self.dir), "control_dir")
        os.mkdir(control_dir)
        # Under this umask, doing nothing special yields world-accessible.
        self.assertEqual(_mode(control_file), 0o666)
        self.assertEqual(_mode(control_dir), 0o777)

        KeyStore(self.path)
        self.assertEqual(_mode(self.path), 0o600)
        self.assertEqual(_mode(self.dir), 0o700)

    def test_store_is_not_world_readable_after_a_registration(self):
        self.open_permissive_umask()
        store = KeyStore(self.path)
        store.register_build("build-a", os.urandom(32))
        self.assertEqual(_mode(self.path), 0o600)
        store.register_build("build-b", os.urandom(32))
        self.assertEqual(_mode(self.path), 0o600)
        store.retire_build("build-a")
        self.assertEqual(_mode(self.path), 0o600)
        self.assertEqual(_mode(self.dir), 0o700)

    def test_a_rewrite_leaves_no_other_file_beside_the_store(self):
        store = KeyStore(self.path)
        store.register_build("build-a", os.urandom(32))
        store.retire_build("build-a")
        self.assertEqual(os.listdir(self.dir), [os.path.basename(self.path)])

    def test_an_existing_directory_is_not_re_moded(self):
        os.makedirs(self.dir, mode=0o755)
        os.chmod(self.dir, 0o755)
        KeyStore(self.path)
        self.assertEqual(_mode(self.dir), 0o755)


class TestBuilds(KeyStoreTestCase):
    def test_register_two_builds_and_both_psks_are_offered(self):
        store = KeyStore(self.path)
        psk_a, psk_b = os.urandom(32), os.urandom(32)
        store.register_build("build-a", psk_a)
        store.register_build("build-b", psk_b)
        self.assertEqual(store.psks(), [psk_a, psk_b])
        self.assertEqual(store.identity_for(psk_a), "build-a")
        self.assertEqual(store.identity_for(psk_b), "build-b")
        # Registration survives reopening the store.
        reopened = KeyStore(self.path)
        self.assertEqual(reopened.psks(), [psk_a, psk_b])
        self.assertEqual(reopened.identity_for(psk_b), "build-b")

    def test_retire_one_build_leaves_the_other_working(self):
        store = KeyStore(self.path)
        psk_a, psk_b = os.urandom(32), os.urandom(32)
        store.register_build("build-a", psk_a)
        store.register_build("build-b", psk_b)
        self.assertTrue(store.retire_build("build-a"))
        self.assertEqual(store.psks(), [psk_b])
        self.assertIsNone(store.identity_for(psk_a))
        self.assertEqual(store.identity_for(psk_b), "build-b")
        # The deletion is on disk, not only in memory.
        reopened = KeyStore(self.path)
        self.assertEqual(reopened.psks(), [psk_b])
        self.assertIsNone(reopened.identity_for(psk_a))

    def test_retiring_an_unknown_build_returns_false(self):
        store = KeyStore(self.path)
        store.register_build("build-a", os.urandom(32))
        self.assertFalse(store.retire_build("never-registered"))
        self.assertEqual(len(store.psks()), 1)

    def test_identity_for_an_unknown_psk_is_none(self):
        store = KeyStore(self.path)
        store.register_build("build-a", os.urandom(32))
        self.assertIsNone(store.identity_for(os.urandom(32)))
        self.assertIsNone(store.identity_for(b""))
        self.assertIsNone(store.identity_for(None))

    def test_an_empty_store_offers_no_psks(self):
        self.assertEqual(KeyStore(self.path).psks(), [])

    def test_a_psk_that_is_not_32_bytes_is_refused_at_registration(self):
        store = KeyStore(self.path)
        for bad in (b"", b"\x01" * 31, b"\x01" * 33, b"\x01" * 64):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    store.register_build("build-a", bad)
        for bad in ("a" * 32, None, 12345):
            with self.subTest(kind=type(bad).__name__):
                with self.assertRaises(ValueError):
                    store.register_build("build-a", bad)
        # Nothing was kept, in memory or on disk, so the next handshake
        # does not inherit a key the Noise layer cannot use.
        self.assertEqual(store.psks(), [])
        self.assertEqual(KeyStore(self.path).psks(), [])

    def test_an_empty_identity_is_refused(self):
        store = KeyStore(self.path)
        for bad in ("", None, b"build-a"):
            with self.subTest(identity=bad):
                with self.assertRaises(ValueError):
                    store.register_build(bad, os.urandom(32))
        self.assertEqual(store.psks(), [])

    def test_registering_an_identity_twice_is_refused(self):
        store = KeyStore(self.path)
        psk = os.urandom(32)
        store.register_build("build-a", psk)
        with self.assertRaises(ValueError) as caught:
            store.register_build("build-a", os.urandom(32))
        self.assertIn("build-a", str(caught.exception))
        # The original credential is untouched.
        self.assertEqual(store.psks(), [psk])

    def test_one_psk_cannot_stand_for_two_builds(self):
        store = KeyStore(self.path)
        psk = os.urandom(32)
        store.register_build("build-a", psk)
        with self.assertRaises(ValueError) as caught:
            store.register_build("build-b", psk)
        self.assertIn("build-a", str(caught.exception))
        self.assertEqual(store.identity_for(psk), "build-a")

    def test_builds_lists_identities_without_the_secrets(self):
        store = KeyStore(self.path)
        psk = os.urandom(32)
        store.register_build("build-a", psk)
        listed = store.builds()
        self.assertEqual([entry["identity"] for entry in listed], ["build-a"])
        self.assertTrue(listed[0]["created"])
        self.assertNotIn("psk", listed[0])
        self.assertNotIn(psk, listed[0].values())
        # Editing what was returned does not edit the store.
        listed[0]["identity"] = "tampered"
        self.assertEqual(store.builds()[0]["identity"], "build-a")

    def test_a_returned_psk_list_is_a_copy(self):
        store = KeyStore(self.path)
        store.register_build("build-a", os.urandom(32))
        store.psks().clear()
        self.assertEqual(len(store.psks()), 1)


class TestMalformedStore(KeyStoreTestCase):
    def _good(self):
        return {
            "static_private": base64.b64encode(os.urandom(32)).decode(),
            "builds": [
                {
                    "identity": "build-a",
                    "psk": base64.b64encode(os.urandom(32)).decode(),
                    "created": "2026-11-09T00:00:00Z",
                }
            ],
        }

    def _write(self, text):
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        with open(self.path, "w") as handle:
            handle.write(text)

    def _expect_error(self, document, *needles):
        text = document if isinstance(document, str) else json.dumps(document)
        self._write(text)
        with self.assertRaises(ValueError) as caught:
            KeyStore(self.path)
        message = str(caught.exception)
        self.assertIn(self.path, message)
        for needle in needles:
            self.assertIn(needle, message)

    def test_the_good_document_loads(self):
        self._write(json.dumps(self._good()))
        store = KeyStore(self.path)
        self.assertEqual(len(store.psks()), 1)

    def test_not_json(self):
        self._expect_error("{ this is not json")

    def test_an_empty_file(self):
        self._expect_error("")

    def test_top_level_is_not_an_object(self):
        self._expect_error([1, 2, 3])

    def test_missing_static_private(self):
        doc = self._good()
        del doc["static_private"]
        self._expect_error(doc, "static_private")

    def test_static_private_not_base64(self):
        doc = self._good()
        doc["static_private"] = "!!! not base64 !!!"
        self._expect_error(doc, "static_private")

    def test_static_private_wrong_length(self):
        doc = self._good()
        doc["static_private"] = base64.b64encode(b"\x01" * 31).decode()
        self._expect_error(doc, "static_private")

    def test_static_private_not_a_string(self):
        doc = self._good()
        doc["static_private"] = 7
        self._expect_error(doc, "static_private")

    def test_builds_not_a_list(self):
        doc = self._good()
        doc["builds"] = {"identity": "build-a"}
        self._expect_error(doc, "builds")

    def test_build_missing_identity(self):
        doc = self._good()
        del doc["builds"][0]["identity"]
        self._expect_error(doc, "builds[0]", "identity")

    def test_build_with_empty_identity(self):
        doc = self._good()
        doc["builds"][0]["identity"] = ""
        self._expect_error(doc, "builds[0]", "identity")

    def test_build_psk_wrong_length(self):
        doc = self._good()
        doc["builds"][0]["psk"] = base64.b64encode(b"\x01" * 16).decode()
        self._expect_error(doc, "builds[0]", "psk")

    def test_build_psk_not_base64(self):
        doc = self._good()
        doc["builds"][0]["psk"] = "***"
        self._expect_error(doc, "builds[0]", "psk")

    def test_build_missing_created(self):
        doc = self._good()
        del doc["builds"][0]["created"]
        self._expect_error(doc, "builds[0]", "created")

    def test_the_second_bad_build_is_named_by_its_index(self):
        doc = self._good()
        doc["builds"].append(
            {"identity": "build-b", "psk": "AAAA", "created": "2026-11-09T00:00:00Z"}
        )
        self._expect_error(doc, "builds[1]", "psk")

    def test_duplicate_identity(self):
        doc = self._good()
        second = dict(doc["builds"][0])
        second["psk"] = base64.b64encode(os.urandom(32)).decode()
        doc["builds"].append(second)
        self._expect_error(doc, "builds[1]", "identity")

    def test_duplicate_psk(self):
        doc = self._good()
        second = dict(doc["builds"][0])
        second["identity"] = "build-b"
        doc["builds"].append(second)
        self._expect_error(doc, "builds[1]", "psk")

    def test_a_malformed_store_is_left_untouched(self):
        self._write("{ broken")
        with self.assertRaises(ValueError):
            KeyStore(self.path)
        with open(self.path) as handle:
            self.assertEqual(handle.read(), "{ broken")


if __name__ == "__main__":
    unittest.main()
