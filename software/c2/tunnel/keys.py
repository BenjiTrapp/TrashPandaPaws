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

State is loaded when the store is opened and written through on every
change. A change made by another process is seen on the next open, not
before.
"""

import base64
import binascii
import hmac
import json
import os
import time
from typing import Any, Dict, List, Optional

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
        try:
            self._load()
        except FileNotFoundError:
            self._create()

    def static_public(self) -> bytes:
        """The server's static public key: what every build is given."""
        return self._public

    def static_private(self) -> bytes:
        """The server's static private key. Never leaves the server."""
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
        self._write(self._builds + [record], exclusive=False)
        self._builds.append(record)

    def retire_build(self, identity: str) -> bool:
        """Delete a build's PSK. True if it was registered, False if not."""
        kept = [b for b in self._builds if b["identity"] != identity]
        if len(kept) == len(self._builds):
            return False
        self._write(kept, exclusive=False)
        self._builds = kept
        return True

    def psks(self) -> List[bytes]:
        """Every registered PSK, in registration order, as a fresh list."""
        return [build["psk"] for build in self._builds]

    def identity_for(self, psk: bytes) -> Optional[str]:
        """The identity the PSK was registered under, or None.

        Compares against every entry without stopping at the first match,
        so the time taken does not say which build, or how many, matched.
        """
        if not isinstance(psk, bytes):
            return None
        found = None
        for build in self._builds:
            if hmac.compare_digest(build["psk"], psk) and found is None:
                found = build["identity"]
        return found

    def builds(self) -> List[dict]:
        """`{identity, created}` for each build. The PSKs are not included."""
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

    def _load(self) -> None:
        with open(self._path, "r", encoding="utf-8") as handle:
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

    def _create(self) -> None:
        os.makedirs(os.path.dirname(self._path), mode=_DIR_MODE, exist_ok=True)
        private, public = _x25519_keypair()
        try:
            self._write([], exclusive=True, private=private)
        except FileExistsError:
            # Another process minted the store between our look and our
            # write. Theirs is the deployment's keypair; use it.
            self._load()
            return
        self._private, self._public, self._builds = private, public, []

    def _write(self, builds: List[Dict[str, Any]], exclusive: bool, private: Optional[bytes] = None) -> None:
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
            if exclusive:
                os.link(scratch, self._path)
            else:
                os.replace(scratch, self._path)
        finally:
            try:
                os.unlink(scratch)
            except FileNotFoundError:
                pass
