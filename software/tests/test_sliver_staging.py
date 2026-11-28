#!/usr/bin/env python3
"""The staged implant is not run until its hash was stated and matched.

`SliverManager._stage_implant` downloads a binary and a systemd unit then
runs it as root. It checked `c2.sliver.sha256` only `if self.expected_hash:`
and that key ships empty, so the shipped configuration had **no integrity
control on the download at all**: set `staging_url` and whatever answered
was executed. The Known-limits entry said "Set `sha256` whenever you set
`staging_url`" and left the enforcement to the reader.

It is enforced now: staging without a stated hash is refused before a
request is made. A binary already on disk is a different question and
keeps its old behaviour -- the shipped `implant_path` is put there by the
image, not by a download, and requiring a hash for it would stop every
deployment that never stages.

The transport still passes `verify=False`, and that is a separate
statement rather than an oversight: the staging host is usually the
operator's own with a self-signed certificate, and turning verification on
needs a trust decision (the same one the beacon's TLS entry is held open
for). What the hash gives is the part that does not need that decision --
the bytes that run are the bytes the operator named, whoever served them.
"""

import hashlib
import logging
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.c2.sliver import SliverManager


def _manager(tmp, **sliver):
    block = {"implant_path": str(Path(tmp) / "implant")}
    block.update(sliver)
    return SliverManager({"c2": {"sliver": block}})


class _Answer:
    """Just enough of a `requests` response to be downloaded from."""

    def __init__(self, body, status=200):
        self.status_code = status
        self._body = body

    def iter_content(self, chunk_size=8192):
        for start in range(0, len(self._body), chunk_size):
            yield self._body[start:start + chunk_size]


class StagingCase(unittest.TestCase):
    BODY = b"#!/bin/sh\necho implant\n"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.logged = self.assertLogs("raccoon.c2.sliver", level=logging.DEBUG)

    def digest(self, body=None):
        return hashlib.sha256(self.BODY if body is None else body).hexdigest()

    def stage(self, manager, body=None, status=200):
        """Run `_stage_implant` with the network replaced, and report calls."""
        calls = []

        def get(url, **kwargs):
            calls.append((url, kwargs))
            return _Answer(self.BODY if body is None else body, status)

        with mock.patch("software.c2.sliver.requests.get", side_effect=get):
            staged = manager._stage_implant()
        return staged, calls


class TestStagingWithoutAStatedHashIsRefused(StagingCase):
    def test_a_staging_url_with_no_sha256_downloads_nothing(self):
        manager = _manager(self.tmp, staging_url="https://drop.test/implant")
        with self.logged as caught:
            staged, calls = self.stage(manager)
        self.assertFalse(staged)
        self.assertEqual(calls, [], "a request was made without a hash to "
                                    "check the answer against")
        self.assertFalse(manager.implant_path.exists())
        self.assertRegex("\n".join(caught.output), r"sha256")

    def test_the_refusal_names_both_keys_so_it_can_be_acted_on(self):
        manager = _manager(self.tmp, staging_url="https://drop.test/implant")
        with self.logged as caught:
            self.stage(manager)
        message = "\n".join(caught.output)
        self.assertIn("staging_url", message)
        self.assertIn("sha256", message)

    def test_a_blank_hash_is_no_hash(self):
        for blank in ("", "   ", None):
            with self.subTest(sha256=blank):
                manager = _manager(self.tmp, sha256=blank,
                                   staging_url="https://drop.test/implant")
                with self.assertLogs("raccoon.c2.sliver", level="ERROR"):
                    staged, calls = self.stage(manager)
                self.assertFalse(staged)
                self.assertEqual(calls, [])

    def test_no_temporary_file_is_left_behind(self):
        manager = _manager(self.tmp, staging_url="https://drop.test/implant")
        with self.logged:
            self.stage(manager)
        self.assertEqual(list(Path(self.tmp).iterdir()), [])


class TestStagingWithAStatedHash(StagingCase):
    def test_the_matching_binary_is_staged_and_executable(self):
        manager = _manager(self.tmp, staging_url="https://drop.test/implant",
                           sha256=self.digest())
        with self.logged:
            staged, calls = self.stage(manager)
        self.assertTrue(staged)
        self.assertEqual(len(calls), 1)
        self.assertEqual(manager.implant_path.read_bytes(), self.BODY)
        self.assertEqual(manager.implant_path.stat().st_mode & 0o777, 0o700)

    def test_a_mismatching_binary_is_discarded_and_not_left_anywhere(self):
        manager = _manager(self.tmp, staging_url="https://drop.test/implant",
                           sha256=self.digest(b"something else"))
        with self.logged as caught:
            staged, _calls = self.stage(manager)
        self.assertFalse(staged)
        self.assertFalse(manager.implant_path.exists())
        self.assertEqual(list(Path(self.tmp).iterdir()), [],
                         "the .tmp download survived the mismatch")
        self.assertRegex("\n".join(caught.output), r"(?i)mismatch")

    def test_the_hash_is_compared_without_regard_to_case_or_padding(self):
        # An operator pasting a hash out of `sha256sum` output or a Windows
        # tool gets upper case and trailing whitespace; refusing those would
        # be a refusal the operator cannot tell from a real mismatch.
        for written in (self.digest().upper(), " " + self.digest() + "\n"):
            with self.subTest(sha256=written):
                manager = _manager(self.tmp, sha256=written,
                                   staging_url="https://drop.test/implant")
                with self.logged:
                    staged, _calls = self.stage(manager)
                self.assertTrue(staged)
                manager.implant_path.unlink()

    def test_a_non_200_answer_stages_nothing(self):
        manager = _manager(self.tmp, staging_url="https://drop.test/implant",
                           sha256=self.digest())
        with self.logged:
            staged, _calls = self.stage(manager, status=404)
        self.assertFalse(staged)
        self.assertFalse(manager.implant_path.exists())


class TestABinaryAlreadyOnDiskIsNotAffected(unittest.TestCase):
    """The deployment that never stages must keep working.

    `implant_path` is normally put there by the image or by hand, and it
    has no hash to be held to. Requiring one for a local binary would stop
    every such deployment, which is not what the finding was about.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)

    def test_a_local_binary_without_a_hash_still_verifies(self):
        manager = _manager(self.tmp)
        manager.implant_path.write_bytes(b"local")
        manager.implant_path.chmod(0o700)
        self.assertTrue(manager._verify_implant())

    def test_a_local_binary_with_a_wrong_hash_still_does_not(self):
        manager = _manager(self.tmp, sha256="0" * 64)
        manager.implant_path.write_bytes(b"local")
        manager.implant_path.chmod(0o700)
        with self.assertLogs("raccoon.c2.sliver", level="WARNING"):
            self.assertFalse(manager._verify_implant())

    def test_no_staging_url_is_still_not_an_error(self):
        manager = _manager(self.tmp)
        self.assertFalse(manager._stage_implant())


class TestTheShippedConfigurationSaysWhatItDoes(unittest.TestCase):
    def test_the_comment_no_longer_offers_to_skip_the_check(self):
        import yaml

        text = (REPO_ROOT / "configs" / "raccoon.yaml").read_text()
        block = text.split("  sliver:", 1)[1].split("\n  #", 1)[0]
        self.assertNotIn("leave empty to skip", block,
                         "the comment still says an empty sha256 skips the "
                         "check, which staging no longer allows")
        self.assertIn("staging_url", block)
        shipped = yaml.safe_load(text)["c2"]["sliver"]
        # Both still ship empty, which is what makes the refusal unreachable
        # until an operator sets the URL.
        self.assertEqual(shipped["staging_url"], "")
        self.assertEqual(shipped["sha256"], "")

    def test_the_gsocket_comment_no_longer_cites_sliver_for_skipping(self):
        text = (REPO_ROOT / "configs" / "raccoon.yaml").read_text()
        self.assertNotIn(
            'the meaning c2.sliver.sha256 has', text,
            "the gsocket block still says an empty value has the meaning "
            "c2.sliver.sha256 has, and that meaning changed")


if __name__ == "__main__":
    unittest.main()
