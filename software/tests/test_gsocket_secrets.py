#!/usr/bin/env python3
"""
Unit tests for the gsocket carrier's secret store: one Global Socket
Relay Network secret per implant, kept in one JSON file.

What these tests are careful about.

**The secret is the address.** Two hosts find each other on the relay
network by a shared secret and nothing else, so whoever holds an implant's
secret can dial the port that fronts the team server's beacon socket.
That is why a weak secret, a secret shared between two implants and a
store another user can read are each an error here rather than a warning.

**The permission tests do not depend on the ambient umask.** A restrictive
umask (077 is common in CI containers) turns a careless `open(path, "w")`
into a 0600 file, so a mode assertion that merely passes proves nothing.
Each one therefore runs under umask 000 and creates a control file or
directory *without* an explicit mode to show that the same umask would
have produced something readable by everyone. The store's 0600 and 0700
are then demonstrably its own doing, and the mode is read back with
`stat` from the file on disk rather than inferred from the call that was
supposed to set it.

**The store is the file, not a copy taken at start-up.** The build
generator registers an implant's secret in one process while the carrier
supervisor reads it in another, so these tests open two `SecretStore`
objects over one path and check that a registration made through one is
what the other answers with on its next call, with no reload for anybody
to remember.

**Nothing logs the secret.** The whole reason `secret_file_for` exists is
that `gs-netcat -s <secret>` would put the credential in a world-readable
`ps` line. A module that then wrote the same string into a log file would
have moved the leak rather than closed it, so one test exercises every
method with logging captured and asserts no secret appears.
"""

import ast
import json
import logging
import os
import stat
import string
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from software.c2.gsocket.secrets import (
    SECRET_MIN_LEN,
    SECRETSTORE_RELPATH,
    SecretStore,
    secretstore_path,
)


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class SecretStoreTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name
        self.dir = os.path.join(tmp.name, "gsocket")
        self.path = os.path.join(self.dir, "secrets.json")

    def open_permissive_umask(self):
        previous = os.umask(0)
        self.addCleanup(os.umask, previous)

    def document(self):
        with open(self.path) as handle:
            return json.load(handle)


class TestRegistration(SecretStoreTestCase):
    def test_a_registered_secret_comes_back(self):
        store = SecretStore(self.path)
        secret = store.generate()
        store.register_implant("gs-a", secret)
        self.assertEqual(store.secret_for("gs-a"), secret)
        self.assertEqual(store.identities(), ["gs-a"])
        # On disk, not only in memory: the generator and the supervisor
        # are different processes.
        self.assertEqual(SecretStore(self.path).secret_for("gs-a"), secret)

    def test_a_second_implant_gets_a_different_secret(self):
        store = SecretStore(self.path)
        first, second = store.generate(), store.generate()
        self.assertNotEqual(first, second)
        store.register_implant("gs-a", first)
        store.register_implant("gs-b", second)
        self.assertEqual(store.secret_for("gs-a"), first)
        self.assertEqual(store.secret_for("gs-b"), second)
        self.assertEqual(store.identities(), ["gs-a", "gs-b"])

    def test_a_duplicate_identity_is_refused_and_changes_nothing(self):
        store = SecretStore(self.path)
        secret = store.generate()
        store.register_implant("gs-a", secret)
        with self.assertRaises(ValueError) as caught:
            store.register_implant("gs-a", store.generate())
        self.assertIn("gs-a", str(caught.exception))
        # Overwriting would strand the implant already carrying the first
        # secret: it would keep dialling an address nothing answers on.
        self.assertEqual(store.secret_for("gs-a"), secret)
        self.assertEqual(SecretStore(self.path).secret_for("gs-a"), secret)
        self.assertEqual(store.identities(), ["gs-a"])

    def test_a_secret_already_registered_to_another_implant_is_refused(self):
        store = SecretStore(self.path)
        secret = store.generate()
        store.register_implant("gs-a", secret)
        with self.assertRaises(ValueError) as caught:
            store.register_implant("gs-b", secret)
        # Named, because the whole point of one secret per implant is
        # that a recovered image reaches only its own carrier.
        self.assertIn("gs-a", str(caught.exception))
        self.assertEqual(store.identities(), ["gs-a"])
        self.assertEqual(store.secret_for("gs-a"), secret)

    def test_an_unknown_identity_is_a_keyerror_naming_it(self):
        store = SecretStore(self.path)
        store.register_implant("gs-a", store.generate())
        for method in (store.secret_for, store.secret_file_for):
            with self.subTest(method=method.__name__):
                with self.assertRaises(KeyError) as caught:
                    method("gs-never-registered")
                self.assertIn("gs-never-registered", str(caught.exception))

    def test_an_empty_store_has_no_identities(self):
        self.assertEqual(SecretStore(self.path).identities(), [])

    def test_an_empty_identity_is_refused(self):
        store = SecretStore(self.path)
        for bad in ("", None, b"gs-a", 7):
            with self.subTest(identity=bad):
                with self.assertRaises(ValueError):
                    store.register_implant(bad, store.generate())
        self.assertEqual(store.identities(), [])

    def test_a_returned_identity_list_is_a_copy(self):
        store = SecretStore(self.path)
        store.register_implant("gs-a", store.generate())
        store.identities().clear()
        self.assertEqual(store.identities(), ["gs-a"])


class TestSecretStrength(SecretStoreTestCase):
    def test_a_short_secret_is_refused(self):
        # Anyone who guesses an implant's secret reaches a relay port
        # fronting the beacon socket, so the floor is enforced on
        # registration and not only in `generate`: a hand-written secret
        # cannot be weaker than a generated one.
        store = SecretStore(self.path)
        for length in (0, 1, 8, SECRET_MIN_LEN - 1):
            with self.subTest(length=length):
                with self.assertRaises(ValueError) as caught:
                    store.register_implant("gs-a", "a" * length)
                self.assertIn(str(SECRET_MIN_LEN), str(caught.exception))
        self.assertEqual(store.identities(), [])
        self.assertEqual(SecretStore(self.path).identities(), [])

    def test_the_floor_accepts_what_gs_netcat_g_mints(self):
        # The guide's only credential path is `gs-netcat -g`, and that
        # emits **21** characters: upstream `lib/gsocket-util.c:153-170`
        # base58-encodes its random bytes and then writes
        # `b58[22] = '\0';` -- "shorten secret to 21 characters". With a
        # floor of 24 the two commands the guide gives in order could not
        # both succeed, and the documented fallback was the one the guide
        # forbids ("do not type a secret you chose yourself").
        #
        # So the floor is pinned at 21 from both sides: a 21-character
        # base58 secret registers, and the constant is not allowed to
        # drift above the length of a minted one.
        self.assertLessEqual(
            SECRET_MIN_LEN, 21,
            "the floor is above the 21 characters `gs-netcat -g` emits "
            "(upstream lib/gsocket-util.c:153-170), so the only documented "
            "way to mint a secret produces one this store refuses")
        store = SecretStore(self.path)
        minted = "7Ps9kQxFbT2mNcVhR4dZa"  # 21 base58 characters
        self.assertEqual(len(minted), 21)
        store.register_implant("gs-a", minted)
        self.assertEqual(store.secret_for("gs-a"), minted)

    def test_a_secret_of_the_minimum_length_is_accepted(self):
        store = SecretStore(self.path)
        secret = "x" * SECRET_MIN_LEN
        store.register_implant("gs-a", secret)
        self.assertEqual(store.secret_for("gs-a"), secret)

    def test_a_secret_that_is_not_a_string_is_refused(self):
        store = SecretStore(self.path)
        for bad in (None, 12345, b"b" * SECRET_MIN_LEN):
            with self.subTest(kind=type(bad).__name__):
                with self.assertRaises(ValueError):
                    store.register_implant("gs-a", bad)
        self.assertEqual(store.identities(), [])

    def test_a_secret_with_whitespace_or_control_bytes_is_refused(self):
        # `secret_file_for` writes the secret and nothing else, and
        # `gs-netcat -k` reads that file back. A secret carrying a
        # newline, a tab or a leading space is a secret the two ends can
        # disagree about byte for byte, and the symptom is a carrier that
        # connects to the relay and never finds its peer.
        store = SecretStore(self.path)
        base = "k" * SECRET_MIN_LEN
        for bad in (base + "\n", " " + base, base[:10] + " " + base[10:],
                    base + "\t", base + "\x00", base + "\x7f"):
            with self.subTest(secret=repr(bad)):
                with self.assertRaises(ValueError):
                    store.register_implant("gs-a", bad)
        self.assertEqual(store.identities(), [])

    def test_generate_is_long_unambiguous_and_never_repeats(self):
        store = SecretStore(self.path)
        allowed = set(string.ascii_letters + string.digits) - set("0O1lI")
        seen = set()
        for _ in range(200):
            secret = store.generate()
            self.assertGreaterEqual(len(secret), SECRET_MIN_LEN)
            self.assertTrue(set(secret) <= allowed, repr(secret))
            seen.add(secret)
        # 200 draws from a space this size colliding would mean the
        # generator is not drawing at random.
        self.assertEqual(len(seen), 200)

    def test_every_generated_secret_is_accepted_by_the_floor(self):
        # A generator that produced something `register_implant` refuses
        # would make the whole build route fail on its last step.
        store = SecretStore(self.path)
        for index in range(25):
            store.register_implant("gs-%d" % index, store.generate())
        self.assertEqual(len(store.identities()), 25)


class TestPermissions(SecretStoreTestCase):
    def test_the_store_file_is_not_readable_by_others(self):
        self.open_permissive_umask()
        control_file = os.path.join(self.root, "control.txt")
        with open(control_file, "w"):
            pass
        control_dir = os.path.join(self.root, "control_dir")
        os.mkdir(control_dir)
        # Under this umask, doing nothing special yields world-accessible.
        self.assertEqual(_mode(control_file), 0o666)
        self.assertEqual(_mode(control_dir), 0o777)

        store = SecretStore(self.path)
        self.assertEqual(_mode(self.path), 0o600)
        self.assertEqual(_mode(self.dir), 0o700)
        store.register_implant("gs-a", store.generate())
        self.assertEqual(_mode(self.path), 0o600)
        self.assertEqual(_mode(self.dir), 0o700)

    def test_a_world_readable_store_is_refused_on_load(self):
        store = SecretStore(self.path)
        store.register_implant("gs-a", store.generate())
        os.chmod(self.path, 0o644)
        with self.assertRaises(ValueError) as caught:
            SecretStore(self.path)
        message = str(caught.exception)
        self.assertIn(self.path, message)
        # The mode itself, because "fix the permissions" without saying
        # what they are is not something an operator can act on.
        self.assertIn("644", message)
        # Refused, not quietly tightened: a store other users could read
        # has to be assumed read, and the answer is new secrets and new
        # builds, not a chmod that hides that it happened.
        self.assertEqual(_mode(self.path), 0o644)

    def test_a_store_made_world_readable_while_running_is_refused_too(self):
        store = SecretStore(self.path)
        store.register_implant("gs-a", store.generate())
        os.chmod(self.path, 0o604)
        with self.assertRaises(ValueError):
            store.secret_for("gs-a")
        with self.assertRaises(ValueError):
            store.identities()

    def test_an_existing_directory_is_not_re_moded(self):
        # It may be shared with things this module does not own.
        os.makedirs(self.dir, mode=0o755)
        os.chmod(self.dir, 0o755)
        SecretStore(self.path)
        self.assertEqual(_mode(self.dir), 0o755)

    def test_a_rewrite_leaves_no_other_file_beside_the_store(self):
        store = SecretStore(self.path)
        store.register_implant("gs-a", store.generate())
        store.register_implant("gs-b", store.generate())
        self.assertEqual(os.listdir(self.dir), [os.path.basename(self.path)])


class TestSecretFiles(SecretStoreTestCase):
    def test_secret_file_for_writes_0600_and_the_secret_alone(self):
        self.open_permissive_umask()
        store = SecretStore(self.path)
        secret = store.generate()
        store.register_implant("gs-a", secret)

        path = store.secret_file_for("gs-a")
        self.assertIsInstance(path, Path)
        self.assertTrue(path.is_file())
        self.assertEqual(_mode(path), 0o600)
        self.assertEqual(_mode(path.parent), 0o700)
        # Byte for byte the secret: no trailing newline, no JSON wrapper,
        # nothing `gs-netcat -k` would read as part of the credential.
        self.assertEqual(path.read_bytes(), secret.encode("ascii"))

    def test_two_implants_get_two_files(self):
        store = SecretStore(self.path)
        first, second = store.generate(), store.generate()
        store.register_implant("gs-a", first)
        store.register_implant("gs-b", second)
        path_a, path_b = store.secret_file_for("gs-a"), store.secret_file_for("gs-b")
        self.assertNotEqual(path_a, path_b)
        self.assertEqual(path_a.read_text(), first)
        self.assertEqual(path_b.read_text(), second)

    def test_identities_that_are_not_filename_safe_do_not_collide(self):
        # The identity reaches a path, so it cannot be used raw: a `/`
        # would write outside the store's directory and two identities
        # that differ only in punctuation would share one file, which is
        # the fleet-wide secret this store exists to avoid.
        store = SecretStore(self.path)
        awkward = ["gs/a", "gs:a", "../gs-a", "gs a", "gs-a"]
        secrets_by_identity = {}
        for identity in awkward:
            secret = store.generate()
            store.register_implant(identity, secret)
            secrets_by_identity[identity] = secret
        paths = {}
        for identity, secret in secrets_by_identity.items():
            path = store.secret_file_for(identity)
            self.assertEqual(path.parent.parent, Path(self.dir))
            self.assertEqual(path.read_text(), secret)
            paths[identity] = path
        self.assertEqual(len(set(paths.values())), len(awkward))

    def test_the_file_is_rewritten_so_a_stale_one_cannot_linger(self):
        # Written on every call rather than only when absent: the file is
        # a cache of the store, and a secret left from an earlier
        # registration is one the store no longer agrees with. The
        # symptom is a carrier that joins the relay network and waits
        # forever for a peer dialling a different address.
        store = SecretStore(self.path)
        secret = store.generate()
        store.register_implant("gs-a", secret)
        path = store.secret_file_for("gs-a")
        path.write_text("not the secret")

        again = store.secret_file_for("gs-a")
        self.assertEqual(again, path)
        self.assertEqual(path.read_text(), secret)
        self.assertEqual(_mode(path), 0o600)

    def test_a_world_readable_key_file_is_refused_not_repaired(self):
        # A key file holds one of the store's own secrets, and the store
        # refuses to load from a file other users can read on the grounds
        # that such a file has to be assumed read. Tightening this one
        # back to 0600 would repair the mode and destroy the only
        # evidence of the disclosure -- and with no logger in the module,
        # nothing anywhere would ever know it happened.
        store = SecretStore(self.path)
        secret = store.generate()
        store.register_implant("gs-a", secret)
        path = store.secret_file_for("gs-a")
        os.chmod(str(path), 0o644)

        with self.assertRaises(ValueError) as caught:
            store.secret_file_for("gs-a")
        message = str(caught.exception)
        self.assertIn(str(path), message)
        self.assertIn("644", message)
        # Left exactly as found: the operator has to see what was there.
        self.assertEqual(_mode(path), 0o644)
        self.assertEqual(path.read_text(), secret)

    def test_a_loose_store_and_a_loose_key_file_are_refused_alike(self):
        # The same credential refused two different ways is how the two
        # answers drift apart again, so this compares the words.
        store = SecretStore(self.path)
        store.register_implant("gs-a", store.generate())
        path = store.secret_file_for("gs-a")

        os.chmod(str(path), 0o644)
        with self.assertRaises(ValueError) as from_key_file:
            store.secret_file_for("gs-a")
        os.chmod(self.path, 0o644)
        with self.assertRaises(ValueError) as from_store:
            SecretStore(self.path)

        def anonymised(caught, named):
            return str(caught.exception).replace(str(named), "<path>")

        self.assertEqual(anonymised(from_key_file, path),
                         anonymised(from_store, self.path))

    def test_the_first_write_cannot_be_refused_for_a_mode(self):
        # Only an existing file can have been read by somebody, so a
        # fresh one must not inherit the refusal -- under a permissive
        # umask least of all, or an implant could never be given its
        # first key file at all.
        self.open_permissive_umask()
        store = SecretStore(self.path)
        secret = store.generate()
        store.register_implant("gs-a", secret)
        path = store.secret_file_for("gs-a")
        self.assertEqual(_mode(path), 0o600)

        # And again once the file is gone rather than loosened: deleting
        # it is not a disclosure.
        os.unlink(str(path))
        self.assertEqual(store.secret_file_for("gs-a").read_text(), secret)
        self.assertEqual(_mode(path), 0o600)

    def test_a_secret_registered_by_another_instance_can_be_written_out(self):
        running, generator = SecretStore(self.path), SecretStore(self.path)
        secret = generator.generate()
        generator.register_implant("gs-a", secret)
        self.assertEqual(running.secret_file_for("gs-a").read_text(), secret)

    def test_writing_a_secret_file_leaves_no_scratch_behind(self):
        store = SecretStore(self.path)
        store.register_implant("gs-a", store.generate())
        path = store.secret_file_for("gs-a")
        store.secret_file_for("gs-a")
        self.assertEqual(os.listdir(str(path.parent)), [path.name])


class TestTheFileIsTheTruth(SecretStoreTestCase):
    def test_a_registration_by_another_instance_is_answered(self):
        running, generator = SecretStore(self.path), SecretStore(self.path)
        self.assertEqual(running.identities(), [])
        secret = generator.generate()
        generator.register_implant("gs-a", secret)
        # No reload for anybody to remember: the supervisor is long-lived
        # and the build that was just generated has to be reachable.
        self.assertEqual(running.identities(), ["gs-a"])
        self.assertEqual(running.secret_for("gs-a"), secret)

    def test_interleaved_registrations_keep_each_others_work(self):
        first, second = SecretStore(self.path), SecretStore(self.path)
        secret_a, secret_b = first.generate(), second.generate()
        first.register_implant("gs-a", secret_a)
        # `second` has not been asked anything since; it must not write
        # back the empty list it opened with.
        second.register_implant("gs-b", secret_b)
        self.assertEqual(SecretStore(self.path).identities(), ["gs-a", "gs-b"])
        self.assertEqual(first.identities(), ["gs-a", "gs-b"])

    def test_a_duplicate_is_caught_against_another_instances_registration(self):
        first, second = SecretStore(self.path), SecretStore(self.path)
        secret = first.generate()
        first.register_implant("gs-a", secret)
        with self.assertRaises(ValueError):
            second.register_implant("gs-a", second.generate())
        with self.assertRaises(ValueError):
            second.register_implant("gs-b", secret)

    def test_an_unchanged_file_is_not_re_read(self):
        store = SecretStore(self.path)
        store.register_implant("gs-a", store.generate())
        with mock.patch.object(SecretStore, "_load", autospec=True) as load:
            for _ in range(3):
                store.identities()
                store.secret_for("gs-a")
        load.assert_not_called()

    def test_a_file_edited_in_place_is_noticed_by_its_mtime(self):
        store = SecretStore(self.path)
        inode = os.stat(self.path).st_ino
        document = self.document()
        secret = "z" * SECRET_MIN_LEN
        document["implants"].append({
            "identity": "hand-edited",
            "secret": secret,
            "created": "2026-11-19T00:00:00Z",
        })
        before = os.stat(self.path)
        with open(self.path, "r+") as handle:
            handle.seek(0)
            handle.truncate()
            json.dump(document, handle)
        os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns + 5_000_000_000))
        self.assertEqual(os.stat(self.path).st_ino, inode)
        self.assertEqual(store.secret_for("hand-edited"), secret)

    def test_a_file_replaced_with_the_same_mtime_is_noticed_by_its_inode(self):
        store = SecretStore(self.path)
        before = os.stat(self.path)
        document = self.document()
        secret = "y" * SECRET_MIN_LEN
        document["implants"].append({
            "identity": "swapped-in",
            "secret": secret,
            "created": "2026-11-19T00:00:00Z",
        })
        scratch = self.path + ".swap"
        with open(scratch, "w") as handle:
            json.dump(document, handle)
        os.chmod(scratch, 0o600)
        os.utime(scratch, ns=(before.st_atime_ns, before.st_mtime_ns))
        os.replace(scratch, self.path)
        after = os.stat(self.path)
        self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
        self.assertNotEqual(after.st_ino, before.st_ino)
        self.assertEqual(store.secret_for("swapped-in"), secret)

    def test_a_store_deleted_while_running_is_an_error_not_a_new_store(self):
        store = SecretStore(self.path)
        store.register_implant("gs-a", store.generate())
        os.unlink(self.path)
        with self.assertRaises(FileNotFoundError):
            store.identities()
        self.assertFalse(os.path.exists(self.path))


class TestWritesAreMovedIntoPlace(SecretStoreTestCase):
    def test_a_rewrite_is_a_complete_scratch_file_moved_over_the_target(self):
        self.open_permissive_umask()
        store = SecretStore(self.path)
        inode_before = os.stat(self.path).st_ino
        real_replace = os.replace
        seen = {}

        def spy(src, dst):
            seen["calls"] = seen.get("calls", 0) + 1
            seen["src"], seen["dst"] = src, dst
            # At the instant of the move the target is still the whole old
            # document, and the scratch is already the whole new one.
            with open(dst) as handle:
                seen["target_before"] = json.load(handle)
            with open(src) as handle:
                seen["scratch"] = json.load(handle)
            seen["scratch_mode"] = _mode(src)
            return real_replace(src, dst)

        with mock.patch("os.replace", side_effect=spy):
            store.register_implant("gs-a", store.generate())

        self.assertEqual(seen["calls"], 1)
        self.assertEqual(seen["dst"], self.path)
        self.assertEqual(os.path.dirname(seen["src"]), self.dir)
        self.assertNotEqual(seen["src"], self.path)
        self.assertEqual(seen["target_before"]["implants"], [])
        self.assertEqual(len(seen["scratch"]["implants"]), 1)
        self.assertEqual(seen["scratch_mode"], 0o600)
        self.assertFalse(os.path.exists(seen["src"]))
        self.assertNotEqual(os.stat(self.path).st_ino, inode_before)
        self.assertEqual(os.listdir(self.dir), [os.path.basename(self.path)])

    def test_a_failed_write_changes_nothing_and_leaves_no_scratch(self):
        store = SecretStore(self.path)
        keep = store.generate()
        store.register_implant("gs-a", keep)
        with mock.patch("os.replace", side_effect=OSError("disk went away")):
            with self.assertRaises(OSError):
                store.register_implant("gs-b", store.generate())
        self.assertEqual(store.identities(), ["gs-a"])
        self.assertEqual(SecretStore(self.path).secret_for("gs-a"), keep)
        self.assertEqual(os.listdir(self.dir), [os.path.basename(self.path)])


class TestMalformedStore(SecretStoreTestCase):
    def _good(self):
        return {
            "implants": [
                {
                    "identity": "gs-a",
                    "secret": "a" * SECRET_MIN_LEN,
                    "created": "2026-11-19T00:00:00Z",
                }
            ]
        }

    def _write(self, text):
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        with open(self.path, "w") as handle:
            handle.write(text)
        os.chmod(self.path, 0o600)

    def _expect_error(self, document, *needles):
        text = document if isinstance(document, str) else json.dumps(document)
        self._write(text)
        with self.assertRaises(ValueError) as caught:
            SecretStore(self.path)
        message = str(caught.exception)
        self.assertIn(self.path, message)
        for needle in needles:
            self.assertIn(needle, message)

    def test_the_good_document_loads(self):
        self._write(json.dumps(self._good()))
        self.assertEqual(SecretStore(self.path).identities(), ["gs-a"])

    def test_not_json(self):
        self._expect_error("{ this is not json")

    def test_an_empty_file(self):
        self._expect_error("")

    def test_top_level_is_not_an_object(self):
        self._expect_error([1, 2, 3])

    def test_implants_not_a_list(self):
        document = self._good()
        document["implants"] = {"identity": "gs-a"}
        self._expect_error(document, "implants")

    def test_implants_missing(self):
        self._expect_error({}, "implants")

    def test_implant_missing_identity(self):
        document = self._good()
        del document["implants"][0]["identity"]
        self._expect_error(document, "implants[0]", "identity")

    def test_implant_with_empty_identity(self):
        document = self._good()
        document["implants"][0]["identity"] = ""
        self._expect_error(document, "implants[0]", "identity")

    def test_implant_missing_secret(self):
        document = self._good()
        del document["implants"][0]["secret"]
        self._expect_error(document, "implants[0]", "secret")

    def test_implant_with_a_short_secret(self):
        # The floor applies to a hand-edited file too, or editing the
        # store is the way around it.
        document = self._good()
        document["implants"][0]["secret"] = "short"
        self._expect_error(document, "implants[0]", "secret")

    def test_implant_missing_created(self):
        document = self._good()
        del document["implants"][0]["created"]
        self._expect_error(document, "implants[0]", "created")

    def test_the_second_bad_implant_is_named_by_its_index(self):
        document = self._good()
        document["implants"].append({
            "identity": "gs-b",
            "secret": "tiny",
            "created": "2026-11-19T00:00:00Z",
        })
        self._expect_error(document, "implants[1]", "secret")

    def test_duplicate_identity(self):
        document = self._good()
        second = dict(document["implants"][0])
        second["secret"] = "b" * SECRET_MIN_LEN
        document["implants"].append(second)
        self._expect_error(document, "implants[1]", "identity")

    def test_duplicate_secret(self):
        document = self._good()
        second = dict(document["implants"][0])
        second["identity"] = "gs-b"
        document["implants"].append(second)
        self._expect_error(document, "implants[1]", "secret")

    def test_a_malformed_store_is_left_untouched(self):
        self._write("{ broken")
        with self.assertRaises(ValueError):
            SecretStore(self.path)
        with open(self.path) as handle:
            self.assertEqual(handle.read(), "{ broken")


class TestTheOnePathBothSidesUse(unittest.TestCase):
    """The store's location, as the one spelling of it.

    The build generator writes an implant's secret into this file and the
    carrier supervisor reads it out, and they are different processes. Two
    copies of the path that agree today are two copies, and the cost of
    drift is not obvious from either side: the generator registers a
    secret in a file the supervisor never reads, and the symptom is a
    carrier whose peer never appears on the relay network.
    """

    def test_the_relpath_is_the_agreed_one(self):
        self.assertEqual(SECRETSTORE_RELPATH, ("gsocket", "secrets.json"))

    def test_the_path_helper_joins_it_under_the_data_dir(self):
        with tempfile.TemporaryDirectory() as root:
            data_dir = os.path.join(root, "data")
            self.assertEqual(
                secretstore_path(data_dir),
                Path(data_dir) / "gsocket" / "secrets.json")
            # Accepts a Path as readily as a string: the callers differ.
            self.assertEqual(secretstore_path(Path(data_dir)),
                             secretstore_path(data_dir))


class TestNothingLeaksTheSecret(SecretStoreTestCase):
    def test_no_method_writes_a_secret_to_a_log_record(self):
        # `gs-netcat -s <secret>` is refused by this design because `ps`
        # is world-readable; a module that logged the same string would
        # have moved the leak into a file instead of closing it.
        records = []
        handler = logging.Handler(level=logging.DEBUG)
        handler.emit = records.append
        root = logging.getLogger()
        root.addHandler(handler)
        previous = root.level
        root.setLevel(logging.DEBUG)
        self.addCleanup(root.setLevel, previous)
        self.addCleanup(root.removeHandler, handler)

        store = SecretStore(self.path)
        secret = store.generate()
        store.register_implant("gs-a", secret)
        store.secret_for("gs-a")
        store.identities()
        store.secret_file_for("gs-a")
        with self.assertRaises(ValueError):
            store.register_implant("gs-b", secret)
        with self.assertRaises(ValueError):
            store.register_implant("gs-c", "short")

        said = "\n".join(record.getMessage() for record in records)
        self.assertNotIn(secret, said)

    def test_a_refusal_does_not_quote_the_secret_it_refused(self):
        # The message goes to an operator's screen and from there into a
        # bug report; the credential has no business in either.
        store = SecretStore(self.path)
        secret = store.generate()
        store.register_implant("gs-a", secret)
        with self.assertRaises(ValueError) as caught:
            store.register_implant("gs-b", secret)
        self.assertNotIn(secret, str(caught.exception))

        weak = "w" * (SECRET_MIN_LEN - 1)
        with self.assertRaises(ValueError) as caught:
            store.register_implant("gs-c", weak)
        self.assertNotIn(weak, str(caught.exception))

    def test_the_store_can_neither_log_nor_spawn(self):
        # The test above can only catch a leak through a path it thought
        # to exercise. This one removes the capability: a store with no
        # logger cannot write a secret to a log file, and one that cannot
        # spawn cannot pass `-s <secret>` to anything. Spawning
        # `gs-netcat` is the carrier's job, not the store's.
        import software.c2.gsocket.secrets as module

        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        self.assertNotIn("logging", imported)
        self.assertNotIn("subprocess", imported)
        self.assertEqual([name for name in vars(module)
                          if "log" in name.lower()], [])


if __name__ == "__main__":
    unittest.main()
