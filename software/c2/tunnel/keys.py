"""On-disk key material for the tunnel server: one static keypair, one PSK per build.

The tunnel authenticates implants with `Noise_NKpsk0_25519_AESGCM_SHA256`.
Under `NKpsk0` the initiator presents no static key of its own, so the
whole credential is two things: the server's static public key, which is
baked into every build, and a pre-shared key. This module holds both
halves of what the server needs to check that.

  * **One static X25519 keypair per deployment.** Minted the first time the
    store is opened and never replaced; replacing it would strand every
    build already out there. Only the private half is stored. The public
    half is derived from it when the store is read, so the two cannot
    disagree and a store whose private key is damaged is caught then.
  * **One PSK per build**, each paired with that build's identity string.
    The PSK is the credential, so it is per build on purpose: retiring a
    burned build is deleting its PSK, and nothing else has to be rotated.

The consumer calls `psks()` on every incoming connection and tries each
candidate until one authenticates, then `identity_for(psk)` to learn which
build connected.

Two properties are deliberate:

**The file is private from the instant it exists.** It is created with
`O_CREAT | O_EXCL` and mode 0600, never created loose and tightened
afterwards, and every rewrite goes through a fresh 0600 file that is moved
into place, so there is no window in which the private key is readable by
another user. The directory is created 0700. A directory that already
exists is left as it is: it may be shared with things this module does not
own.

**A malformed store is an error when it is read**, naming the file and
the field, following `listeners/registry.py`. And a PSK that is not 32
bytes is refused when it is *registered*, because the Noise responder
builds its whole candidate list before trying any of it: one bad key in
the store would abort the handshake for every build, not just its own.

**The file is the truth, not a copy taken at start-up.** A long-lived
server that cached its candidate list when it opened the store would make
"retire the build" mean "retire the build, and restart the server",
and an operator who had just burned a build would have no way to know the
deletion had not taken effect. So every accessor first `stat`s the file
and re-reads it if its inode or modification time differs from what was
recorded at the last read or write. That is one `stat` per call; the
callers are per-connection, not per-packet. Nothing is for the caller to
remember: there is no `reload()`.

For a reader to be able to do that, a rewrite has to be atomic. The new
document is written to a scratch file in the same directory, created 0600,
fsynced, and moved over the target with `os.replace`, so another process
sees the old store or the new one and never half of either. (First
creation uses `os.link` for the same reason: all-or-nothing, and it fails
if the file already exists.)

**Concurrent registration is last-writer-wins, and that is accepted.** One
team server owns this file. Each change re-reads the file first, so two
instances that interleave their registrations keep each other's work; only
two changes landing in the same instant can lose one. A `flock` on a side
file would close that, but at the price of a second file to create, secure
and clean up, a POSIX-only import, and a lock to hold across an fsync, to
guard against a race this deployment does not have. The limit is stated
here instead.
"""

import base64
import binascii
import hmac
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from software.c2.beacon import _X25519_BASEPOINT, _x25519, _x25519_keypair

_KEY_LEN = 32
_PSK_LEN = 32

_DIR_MODE = 0o700
_FILE_MODE = 0o600


class KeyStore:
    """The tunnel server's static keypair and per-build PSKs, kept in one JSON file."""

    def __init__(self, path):
        self._path = os.path.abspath(os.fspath(path))
        self._private = b""
        self._public = b""
        self._builds = []  # type: List[Dict[str, Any]]
        self._signature = None  # type: Optional[Tuple[int, int]]
        try:
            self._load()
        except FileNotFoundError:
            self._create()

    def static_public(self) -> bytes:
        """The server's static public key: what every build is given."""
        self._refresh()
        return self._public

    def static_private(self) -> bytes:
        """The server's static private key. Never leaves the server."""
        self._refresh()
        return self._private

    def register_build(self, identity: str, psk: bytes) -> None:
        """Add a build's PSK, or raise `ValueError` and change nothing.

        Refuses a PSK that is not exactly 32 bytes, an empty identity, an
        identity already registered, and a PSK already registered to
        another build. The last two are refused rather than overwritten:
        replacing a build's PSK silently would lock that build out, and
        two builds sharing one PSK would make `identity_for` ambiguous.
        Retire the old build first if replacing it is what was meant.
        """
        self._refresh()
        if not isinstance(identity, str) or not identity:
            raise ValueError("a build identity must be a non-empty string")
        if not isinstance(psk, bytes) or len(psk) != _PSK_LEN:
            got = "%d bytes" % len(psk) if isinstance(psk, bytes) else type(psk).__name__
            raise ValueError(
                "a PSK must be exactly %d bytes, got %s" % (_PSK_LEN, got)
            )
        for build in self._builds:
            if build["identity"] == identity:
                raise ValueError("build %r is already registered" % identity)
        owner = self.identity_for(psk)
        if owner is not None:
            raise ValueError("that PSK is already registered to build %r" % owner)

        record = {
            "identity": identity,
            "psk": bytes(psk),
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self._signature = self._write(self._builds + [record], exclusive=False)
        self._builds.append(record)

    def retire_build(self, identity: str) -> bool:
        """Delete a build's PSK. True if it was registered, False if not.

        Takes effect for every `KeyStore` over this file, running servers
        included, as soon as they next ask.
        """
        self._refresh()
        kept = [b for b in self._builds if b["identity"] != identity]
        if len(kept) == len(self._builds):
            return False
        self._signature = self._write(kept, exclusive=False)
        self._builds = kept
        return True

    def psks(self) -> List[bytes]:
        """Every registered PSK, in registration order, as a fresh list."""
        self._refresh()
        return [build["psk"] for build in self._builds]

    def identity_for(self, psk: bytes) -> Optional[str]:
        """The identity the PSK was registered under, or None.

        Compares against every entry without stopping at the first match,
        so the time taken does not say which build, or how many, matched.
        """
        self._refresh()
        if not isinstance(psk, bytes):
            return None
        found = None
        for build in self._builds:
            if hmac.compare_digest(build["psk"], psk) and found is None:
                found = build["identity"]
        return found

    def builds(self) -> List[dict]:
        """`{identity, created}` for each build.

        The PSKs are left out on purpose. This is what an operator panel
        lists, and a listing that returns the credential is how a secret
        ends up in a screenshot.
        """
        self._refresh()
        return [
            {"identity": b["identity"], "created": b["created"]}
            for b in self._builds
        ]

    def _fail(self, field: str, reason: str) -> ValueError:
        return ValueError("%s: %s: %s" % (self._path, field, reason))

    def _decode(self, field: str, value: Any, length: int) -> bytes:
        if not isinstance(value, str):
            raise self._fail(field, "expected a base64 string, got %s" % type(value).__name__)
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise self._fail(field, "is not valid base64")
        if len(raw) != length:
            raise self._fail(field, "must decode to %d bytes, got %d" % (length, len(raw)))
        return raw

    def _refresh(self) -> None:
        """Re-read the file if it is not the one last read or written."""
        status = os.stat(self._path)
        if (status.st_mtime_ns, status.st_ino) != self._signature:
            self._load()

    def _load(self) -> None:
        with open(self._path, "r", encoding="utf-8") as handle:
            # Taken from the descriptor we read, so the signature describes
            # the bytes we parse even if the file is replaced meanwhile.
            status = os.fstat(handle.fileno())
            text = handle.read()
        try:
            document = json.loads(text)
        except ValueError as exc:
            raise self._fail("(file)", "is not valid JSON: %s" % exc)
        if not isinstance(document, dict):
            raise self._fail("(file)", "expected a JSON object")
        if "static_private" not in document:
            raise self._fail("static_private", "is missing")
        private = self._decode("static_private", document["static_private"], _KEY_LEN)

        entries = document.get("builds", None)
        if not isinstance(entries, list):
            raise self._fail("builds", "expected a list")
        builds = []  # type: List[Dict[str, Any]]
        for index, entry in enumerate(entries):
            where = "builds[%d]" % index
            if not isinstance(entry, dict):
                raise self._fail(where, "expected an object")
            identity = entry.get("identity")
            if not isinstance(identity, str) or not identity:
                raise self._fail(where + ".identity", "must be a non-empty string")
            if "psk" not in entry:
                raise self._fail(where + ".psk", "is missing")
            psk = self._decode(where + ".psk", entry["psk"], _PSK_LEN)
            created = entry.get("created")
            if not isinstance(created, str) or not created:
                raise self._fail(where + ".created", "must be a non-empty string")
            for earlier in builds:
                if earlier["identity"] == identity:
                    raise self._fail(where + ".identity", "%r appears more than once" % identity)
                if hmac.compare_digest(earlier["psk"], psk):
                    raise self._fail(
                        where + ".psk",
                        "is the same key as build %r" % earlier["identity"],
                    )
            builds.append({"identity": identity, "psk": psk, "created": created})

        self._private = private
        self._public = _x25519(private, _X25519_BASEPOINT)
        self._builds = builds
        self._signature = (status.st_mtime_ns, status.st_ino)

    def _create(self) -> None:
        os.makedirs(os.path.dirname(self._path), mode=_DIR_MODE, exist_ok=True)
        private, public = _x25519_keypair()
        try:
            signature = self._write([], exclusive=True, private=private)
        except FileExistsError:
            # Another process minted the store between our look and our
            # write. Theirs is the deployment's keypair; use it.
            self._load()
            return
        self._private, self._public, self._builds = private, public, []
        self._signature = signature

    def _write(self, builds: List[Dict[str, Any]], exclusive: bool, private: Optional[bytes] = None) -> Tuple[int, int]:
        """Write the document atomically; return the (mtime_ns, inode) it has on disk."""
        document = {
            "static_private": base64.b64encode(private or self._private).decode("ascii"),
            "builds": [
                {
                    "identity": b["identity"],
                    "psk": base64.b64encode(b["psk"]).decode("ascii"),
                    "created": b["created"],
                }
                for b in builds
            ],
        }
        data = (json.dumps(document, indent=2) + "\n").encode("utf-8")
        directory, name = os.path.split(self._path)
        scratch = os.path.join(directory, ".%s.%s.tmp" % (name, os.urandom(6).hex()))
        descriptor = os.open(scratch, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _FILE_MODE)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
                status = os.fstat(handle.fileno())
            if exclusive:
                os.link(scratch, self._path)
            else:
                os.replace(scratch, self._path)
            return (status.st_mtime_ns, status.st_ino)
        finally:
            try:
                os.unlink(scratch)
            except FileNotFoundError:
                pass
