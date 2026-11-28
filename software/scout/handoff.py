#!/usr/bin/env python3
"""The two files the beacon and the scout meet over, from the scout's side.

`software/c2/beacon.py` is served to a target as source text and may
import only the standard library, so it cannot import this module and this
module cannot import it. The names and versions below are therefore
**copied** into `beacon.py` -- the arrangement the rescue record already
has (`beacon.py:1686-1692`) -- and `test_way_out_handoff.py` compares the
two and fails when they drift.

**Why files and not a socket.** `raccoon-beacon.service` runs
`beacon_standalone` and `raccoon-implant.service` runs `main.py`, so
`_stuck_cycles` and the scout's evidence are in-memory state of different
processes. A socket between them would be a listener on a device built to
look like an IP phone; a file is one line of JSON that says nothing about
the team server.

**Not under /tmp.** Both units set `PrivateTmp=true`, so each process
would get its own private `/tmp` and the handoff would silently never
happen. `c2.way_out.state_dir` names a real directory, and the beacon's
reader refuses a `/tmp` path by name with that reason.

Five files, and which side owns each:

    way_out_state.json      the beacon writes, the scout reads.  The stuck
                            window: how long, on what evidence, and how
                            much of its budget it has spent.
    way_out_scout.json      the scout writes, the beacon reads.  The
                            evidence from the tap, the rungs the scout
                            believes are available, and -- in the model
                            stage -- one recommendation.
    way_out_trail.jsonl     the beacon writes, nobody here reads.  One
                            line per attempt, kept after the state file is
                            gone, which is what makes a burned implant a
                            lesson.  It was this module's to write, and a
                            review moved it: see `trail_path` below.
    way_out_borrow.json     the scout writes, a borrow verb reads.  The
                            credentials themselves and the portal request
                            to replay: the half that can carry a secret,
                            which is why it is not in the document -- and
                            why the scout removes it when the window
                            closes rather than leaving a captured
                            password on the disk.
    way_out_identity.json   the beacon writes, main.py reads.  Rung 4's
                            cross-process trigger.

Every write is atomic and 0600: a scratch file in the same directory,
fsynced, moved over the target -- the shape `tunnel/shell.py` and
`tunnel/keys.py` already write their own small documents with, for the
same two reasons. Whoever reads one never sees half of one, and the file
is private from the instant it exists.
"""

import json
import logging
import os
import stat
import tempfile
import time
from typing import Optional

logger = logging.getLogger("raccoon.scout.handoff")

STATE_NAME = "way_out_state.json"
DOCUMENT_NAME = "way_out_scout.json"
TRAIL_NAME = "way_out_trail.jsonl"
BORROW_NAME = "way_out_borrow.json"
IDENTITY_NAME = "way_out_identity.json"

# Bumped when a reader would misread the older shape. A reader that finds
# another version treats the file as absent rather than guessing, because
# the two halves are upgraded by two different installs and a half-read
# document is a decision made on a misunderstanding.
STATE_VERSION = 1
DOCUMENT_VERSION = 1
BORROW_VERSION = 1

_PRIVATE_FILE = 0o600
_PRIVATE_DIR = 0o700


def state_path(state_dir: str) -> str:
    return os.path.join(state_dir, STATE_NAME)


def document_path(state_dir: str) -> str:
    return os.path.join(state_dir, DOCUMENT_NAME)


def trail_path(state_dir: str) -> str:
    """Where the trail is, which is all this module still owns of it.

    The writer was here -- `append_trail` -- and it is gone. The scout
    copied new lines out of the window's file on its publishing clock,
    which lost every attempt made in a window's last interval (a leg
    delivering removes that file, and on a recovered implant the lost
    line is the attempt that *worked*) and duplicated what it had already
    copied when its unit restarted. The beacon is the only process that
    knows an attempt happened, so it appends the line itself, in the same
    call that records the attempt: `Beacon._way_out_append_trail`.

    The name and the path stay here, because they are what the two sides
    have to agree on, and the tests hold the beacon's copy against them.
    """
    return os.path.join(state_dir, TRAIL_NAME)


def borrow_path(state_dir: str) -> str:
    return os.path.join(state_dir, BORROW_NAME)


def identity_path(state_dir: str) -> str:
    return os.path.join(state_dir, IDENTITY_NAME)


# ── reading ──


def read_state(state_dir: str) -> Optional[dict]:
    """The beacon's stuck-window file, or None.

    None for every reason there is not to have one: no file, no directory,
    no permission, half a file, a version this reader does not know. The
    scout publishes nothing while the answer is None, which is what keeps
    it quiet on a healthy implant.
    """
    return read_document_at(state_path(state_dir), STATE_VERSION)


def read_document(state_dir: str) -> Optional[dict]:
    """The scout's own document.

    Nothing in production calls this: the scout writes the document and
    the beacon reads it through its own copy of the reader, which is the
    whole point of the copies. It exists for this package's tests and for
    `tools/way_out_bench.py`, and that is said out loud because "a
    documented thing nothing calls" is exactly the shape of the worst
    defect this branch shipped.
    """
    return read_document_at(document_path(state_dir), DOCUMENT_VERSION)


def read_document_at(path: str, version: int) -> Optional[dict]:
    try:
        with open(path, "rb") as handle:
            loaded = json.loads(handle.read().decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(loaded, dict) or loaded.get("version") != version:
        return None
    return loaded


def read_borrow(state_dir: str) -> Optional[dict]:
    """The private half: the credentials and the portal request.

    Versioned like the other two, and for the sharpest form of the same
    reason: this is the file that selects a *credential*, and the two
    halves are upgraded by two different installs.

    The beacon reads this file through `Beacon._egress_borrow`, which
    carries its own copy of the reader; this one is for this package's
    tests, and the version it checks is the one that matters.
    """
    return read_document_at(borrow_path(state_dir), BORROW_VERSION)


# ── writing ──


def write_document(state_dir: str, document: dict) -> None:
    write_private_json(document_path(state_dir), document)


def write_borrow(state_dir: str, fields: dict) -> None:
    """The private half, stamped with when it was written.

    The stamp is what lets `Beacon._egress_borrow` tell a credential
    captured in *this* outage from one left behind by a previous one. The
    scout removes this file when a window closes, so the only way a stale
    one survives is a scout that died -- and then there is no fresh
    document either, and nothing else to notice with.
    """
    write_private_json(borrow_path(state_dir),
                       dict(fields, version=BORROW_VERSION,
                            written=time.time()))


def write_private_json(path: str, document: dict) -> None:
    """One small JSON file 0600: all of it, or none of it."""
    directory, name = os.path.split(path)
    _ensure_dir(directory)
    data = (json.dumps(document, sort_keys=True) + "\n").encode("utf-8")
    # Written to a scratch file and renamed, so a reader never sees half a
    # document -- and `mkstemp` creates it 0600 and refuses an existing
    # name, so a link planted at the *target* is replaced by the rename
    # rather than written through.
    descriptor, scratch = tempfile.mkstemp(prefix="." + name + ".",
                                           dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(scratch, _PRIVATE_FILE)
        os.replace(scratch, path)
    except Exception:
        try:
            os.unlink(scratch)
        except OSError:
            pass
        raise


def remove(path: str) -> None:
    """Delete a handoff file if it is there. Raises nothing.

    One production caller: the scout removes the borrow file when a
    window closes, because that is the one file here that carries a
    secret and nothing else would ever have removed it. The beacon
    removes its own window with `Beacon._way_out_clear_state`.
    """
    try:
        os.unlink(path)
    except OSError:
        pass


def _ensure_dir(directory: str) -> None:
    """The handoff's directory, 0700 and not a symlink. Raises if it cannot.

    **Tightened even when it already exists**, and that is the fix for a
    real hole: this used to return early on a pre-existing directory, so
    an operator who pointed `state_dir` at `/var/tmp/raccoon` -- or a
    local process that got there first -- left a world-writable directory
    holding 0600 files, and anybody who could write it could replace them.
    `/tmp` is refused by name in the config reader; every other path is
    refused here by mode.

    `lstat` and not `isdir`, because a symlink to a directory answers
    `isdir` with True: a link planted at this name would have the root
    scout writing the handoff wherever the link pointed.
    """
    if not directory:
        raise ValueError("a handoff file needs a directory to live in")
    try:
        found = os.lstat(directory)
    except OSError:
        os.makedirs(directory, mode=_PRIVATE_DIR, exist_ok=True)
        # `makedirs`'s mode applies to the leaf alone and is masked by the
        # umask, so the mode is set explicitly: a parent left at the
        # process umask would be a listable directory holding 0600 files.
        os.chmod(directory, _PRIVATE_DIR)
        return
    if stat.S_ISLNK(found.st_mode):
        raise ValueError(
            "the handoff directory %s is a symbolic link, and following it "
            "would write this implant's state wherever somebody else chose"
            % directory)
    if not stat.S_ISDIR(found.st_mode):
        raise ValueError("the handoff directory %s is not a directory"
                         % directory)
    if stat.S_IMODE(found.st_mode) != _PRIVATE_DIR:
        os.chmod(directory, _PRIVATE_DIR)


def is_private(path: str) -> bool:
    """Whether a handoff file is 0600. For this package's tests."""
    try:
        return stat.S_IMODE(os.stat(path).st_mode) == _PRIVATE_FILE
    except OSError:
        return False
