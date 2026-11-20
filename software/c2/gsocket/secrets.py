"""One Global Socket Relay Network secret per implant, kept in one JSON file.

The gsocket carrier is the only one of the beacon's legs that needs no
address. A `gs-netcat` process on the implant and another beside the team
server join the relay network and are introduced to each other by a
shared secret, so the secret *is* the address: whoever holds an implant's
secret can dial the port that fronts the team server's beacon socket.

**That is why there is one secret per implant and not one for the fleet.**
A fleet-wide secret is baked into every image, and these implants are
hardware left behind on someone else's site. The first one recovered
would hand its finder a dialable path to the beacon socket for *every*
other implant in the fleet. The damage is bounded either way -- what
travels over that path is still sealed in the AES-256-GCM envelope the
beacon payload already carries, so a dialer reaches exactly as far as a
compromised listener does and can neither read beacon traffic nor forge
it -- but fleet-wide the bound applies to the whole fleet rather than to
one device. Per-implant keeps a recovered image to itself: its secret
dials its own carrier and nothing else, and burning it is deleting one
entry here.

Five properties are deliberate.

**The secret never reaches a command line.** `gs-netcat` accepts
`-s <secret>` and its own documentation warns against it, because `ps` is
world-readable on every machine a carrier might run on. `secret_file_for`
exists so that the carrier can be handed `-k <path>` instead. For the
same reason nothing in this module writes a secret to a log record or
quotes one in an error message: a refusal names the implant, never the
credential it refused. There is no logger here and no `subprocess` import
-- spawning `gs-netcat` is the carrier's job, not the store's.

**The store is private from the instant it exists.** It is created with
`O_CREAT | O_EXCL` and mode 0600, never created loose and tightened
afterwards, and every rewrite goes through a fresh 0600 file that is moved
into place, so there is no window in which the secrets are readable by
another user. The directory is created 0700; a directory that already
exists is left as it is, because it may be shared with things this module
does not own. And a secret-bearing file that *is* readable by another
user -- the store, or one of the key files under it -- is refused rather
than quietly re-moded. Both hold the same credential, so both get the
same answer, from the same function and in the same words: a file other
users could read has to be assumed read, and the answer to that is a new
secret and a reflashed implant, not a `chmod` that repairs the mode and
erases the evidence.

**The minimum length is enforced on registration, not only in
`generate`.** The floor exists because a guessed secret is a dialable
path to the beacon socket, and a floor that only the generator respects
is no floor at all -- the one secret anybody hand-writes is the one that
matters. The same check runs when the file is read, so hand-editing the
store is not the way around it.

The number is 21, which is one below what `gs-netcat -g` actually emits.
Upstream `lib/gsocket-util.c:153-170` truncates its base58 encoding with
`b58[22] = '\0';` under the comment "shorten secret to 21 characters" --
but that terminator sits at index 22, so the string is indices 0..21 and
the generator emits **22**. Measured, not read: three runs of the v1.4.43
macOS build gave 22 characters each. The comment in upstream's own source
contradicts its own code, and this file deliberately trusts neither
number alone: the floor sits below both, so it keeps working whichever
one a future release honours. A floor above either would refuse the
secret minted the documented way, which is the failure this number
replaced. It is still a floor worth having: 21 base58 characters is about
123 bits, and every guess against it costs the guesser a fresh TCP
connection to the relay network, so the length is not the thing that will
fail -- a secret somebody chose by hand is, which is what the floor
catches.

Whitespace and control characters are
refused for a different reason: `secret_file_for` writes the secret and
nothing else, `gs-netcat -k` reads that file back, and a secret carrying
a newline or a stray space is one the two ends can disagree about byte
for byte. The symptom of that is a carrier that reaches the relay
network and never finds its peer, which looks nothing like a typo.

**The file is the truth, not a copy taken at start-up.** The build
generator registers an implant's secret in one process while the carrier
supervisor reads it in another, and the supervisor is long-lived. A
supervisor that cached the store when it opened it would answer "no such
implant" for a build generated a minute ago, and the operator's only clue
would be one carrier that never starts. So every accessor first `stat`s
the file and re-reads it if its inode, modification time or mode differs
from what was recorded at the last read or write. (The mode is part of
that signature because a `chmod` changes neither of the other two, and
the refusal above has to fire for a running store too.) That is one
`stat` per call; the callers are per-carrier-start, not per-packet.
Nothing is for the caller to remember: there is no `reload()`.

For a reader to be able to do that, a rewrite has to be atomic. The new
document is written to a scratch file in the same directory, created
0600, fsynced, and moved over the target with `os.replace`, so another
process sees the old store or the new one and never half of either.
(First creation uses `os.link` for the same reason: all-or-nothing, and
it fails if the file already exists.)

**Concurrent registration is last-writer-wins, and that is accepted.**
One team server owns this file. Each change re-reads it first, so two
instances that interleave their registrations keep each other's work;
only two changes landing in the same instant can lose one. This mirrors
`tunnel/keys.py`, which argues the point at length: a `flock` on a side
file would close the window at the price of a second file to create,
secure and clean up, to guard against a race this deployment does not
have.

One thing this module deliberately does *not* do, unlike
`tunnel/keys.py`: it does not announce a store it had to create. There,
a missing store means a freshly minted keypair that silently fails to
match every deployed build. Here, a missing store means an empty one, and
the next `secret_for` raises `KeyError` naming the implant -- already the
loudest thing it could say.

(This module is named `secrets` and imports the standard library's
`secrets` module. Python 3 resolves `import secrets` absolutely, against
`sys.path`, which does not contain this package's directory, so the two
do not collide.)
"""

import hashlib
import hmac
import json
import os
import secrets
import stat
import string
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# How short a secret is allowed to be. Public, unlike the rest of this
# module's constants: whoever mints an implant's secret has to agree with
# `register_implant`, which refuses anything shorter, and `generate`
# reads this rather than repeating the number.
#
# **21, which is one below what `gs-netcat -g` emits** -- the generator
# the operator guide tells an operator to use, and the only credential
# path this feature has. Upstream `lib/gsocket-util.c:153-170`
# base58-encodes its random bytes and then writes `b58[22] = '\0';` with
# the comment "shorten secret to 21 characters". That terminator is at
# index 22, so the string is indices 0..21: the code emits **22** and its
# own comment says 21. Measured on the v1.4.43 macOS build, three runs,
# 22 characters each (`tools/gsocket_rig.py --real` re-measures it).
#
# The floor sits below both numbers on purpose, so it survives whichever
# one a future release decides to honour. A floor of 24 refused every
# secret minted the documented way, which left the guide's two commands
# unable both to succeed and its fallback the one the guide forbids.
#
# The floor is still a real floor. 21 characters of base58 is about 123
# bits (21 * log2(58)), and this alphabet is 57 characters, so a
# generated one is about 122; against an attacker who needs a fresh TCP
# connection to the relay network for every guess, that is not a number
# anybody works through. What the floor is for is the hand-written
# secret, where the risk is a word somebody chose, not a few bits of
# length.
SECRET_MIN_LEN = 21

# Where the store lives under a team-server data directory, as the one
# spelling of it. `SecretStore.register_implant` writes an implant's
# secret into this file and the carrier supervisor reads it out, and they
# are different processes -- registration is an operator running a Python
# snippet on the team server (the GSRN section of `docs/LISTENERS.md`
# gives it), the read is the supervisor starting a carrier. Two copies of
# the path that agree today are two copies. The cost of drift is not
# obvious from either side -- a secret registered in a file the supervisor
# never reads, and the symptom is a carrier whose peer never appears on
# the relay network, which reads as a relay problem rather than as a
# wrong path.
#
# Nothing here writes the *implant's* copy of a secret, and nothing in
# this repository does: that file is created by hand on the implant, 0600.
SECRETSTORE_RELPATH = ("gsocket", "secrets.json")


def secretstore_path(data_dir) -> Path:
    """The store's path under `data_dir`: the one both sides ask for."""
    return Path(data_dir).joinpath(*SECRETSTORE_RELPATH)


_DIR_MODE = 0o700
_FILE_MODE = 0o600

# The alphabet `generate` draws from: letters and digits less `0O1lI`.
# A secret is occasionally read off a screen and typed into a build
# configuration by hand, and a transcription error here does not fail
# loudly -- it produces a carrier that joins the relay network and waits
# forever for a peer that is listening on a different address.
_ALPHABET = "".join(
    character for character in string.ascii_letters + string.digits
    if character not in "0O1lI"
)

# Characters a secret may contain: printable ASCII, no space. Anything
# outside this makes the secret something the two ends can disagree about
# once it has been through a file and `gs-netcat -k`.
_LOWEST_CHARACTER = 0x21
_HIGHEST_CHARACTER = 0x7E

# Where `secret_file_for` keeps the one-secret files, under the store's
# own directory so that one 0700 directory covers both.
_KEYFILE_DIRNAME = "keyfiles"

# What survives from an identity into its key file's name. The identity
# reaches a path, so it cannot be used raw: a `/` would write the file
# outside the store's directory. `.` is left out of the set as well, so
# that an identity of `..` cannot survive into a name that climbs out of
# it; everything else becomes a `-`.
_SLUG_CHARACTERS = frozenset(string.ascii_letters + string.digits + "-_")
_SLUG_MAX = 32


def _refuse_loose_mode(path, mode: int) -> None:
    """Raise if `mode` lets anyone but the owner read a secret-bearing file.

    One refusal, in one wording, for both files that hold secrets: the
    store and a key file. They hold the *same* credential, so an answer
    that differs between them is a hole -- and the cheaper answer is
    always the wrong one. A `chmod` back to 0600 looks like a repair but
    erases the only evidence that the secret was ever exposed, and this
    module has no logger to mention it in, so after the "repair" nothing
    anywhere knows it happened.

    Refusing is the answer because the disclosure is not undoable: a file
    other users could read has to be assumed read, and what that calls
    for is a new secret and a reflashed implant.
    """
    if mode & 0o077:
        raise ValueError(
            "%s: mode is 0o%03o, so users other than its owner can read the "
            "gsocket secrets in it. Every secret in this file is a dialable "
            "path to the beacon socket of the implant it belongs to, so "
            "treat it as disclosed: register a new secret and reflash that "
            "implant, rather than only tightening the file to 0o600"
            % (os.fspath(path), mode))


def _write_private(path, data: bytes, exclusive: bool) -> os.stat_result:
    """Put `data` at `path` atomically, 0600, and return its `stat`.

    The bytes go to a scratch file in the same directory, created 0600 so
    there is no instant at which a secret sits in a readable file, and
    that file is moved over the target. A reader therefore sees the whole
    old content or the whole new one. With `exclusive`, the move is an
    `os.link` that fails if the target already exists.
    """
    target = os.fspath(path)
    directory, name = os.path.split(target)
    scratch = os.path.join(directory, ".%s.%s.tmp" % (name, os.urandom(6).hex()))
    descriptor = os.open(scratch, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _FILE_MODE)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            status = os.fstat(handle.fileno())
        if exclusive:
            os.link(scratch, target)
        else:
            os.replace(scratch, target)
        return status
    finally:
        try:
            os.unlink(scratch)
        except FileNotFoundError:
            pass


class SecretStore:
    """Each implant's relay-network secret, kept in one JSON file."""

    def __init__(self, path):
        self._path = os.path.abspath(os.fspath(path))
        self._implants = []  # type: List[Dict[str, Any]]
        self._signature = None  # type: Optional[Tuple[int, int, int]]
        try:
            self._load()
        except FileNotFoundError:
            self._create()

    @staticmethod
    def generate() -> str:
        """A fresh secret: `SECRET_MIN_LEN` characters from `_ALPHABET`.

        The generated length *is* the enforced minimum on purpose. Two
        numbers here would invite the version of this module whose
        generator is weaker than the floor it enforces, and 21 characters
        over this 57-character alphabet is about 122 bits -- against an
        attacker who needs a fresh TCP connection to the relay network
        for every guess, far past anything that can be worked through.
        """
        return "".join(secrets.choice(_ALPHABET) for _ in range(SECRET_MIN_LEN))

    def register_implant(self, identity: str, secret: str) -> None:
        """Add an implant's secret, or raise `ValueError` and change nothing.

        Refuses an identity that is not a non-empty string, a secret that
        is not a string, is shorter than `SECRET_MIN_LEN` or carries
        whitespace or control characters, an identity already registered,
        and a secret already registered to another implant. The last two
        are refused rather than overwritten: replacing an implant's
        secret silently would leave the device already carrying the old
        one dialling an address nothing answers on, and two implants
        sharing one secret is the fleet-wide secret this store exists to
        avoid, reintroduced two devices at a time.
        """
        self._refresh()
        if not isinstance(identity, str) or not identity:
            raise ValueError("an implant identity must be a non-empty string")
        problem = _secret_problem(secret)
        if problem is not None:
            raise ValueError("the secret for implant %r %s" % (identity, problem))
        for implant in self._implants:
            if implant["identity"] == identity:
                raise ValueError("implant %r is already registered" % identity)
        owner = self._owner_of(secret)
        if owner is not None:
            raise ValueError(
                "that secret is already registered to implant %r" % owner)

        record = {
            "identity": identity,
            "secret": secret,
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self._signature = self._write(self._implants + [record], exclusive=False)
        self._implants.append(record)

    def secret_for(self, identity: str) -> str:
        """The implant's secret. `KeyError` naming it if it has none."""
        self._refresh()
        for implant in self._implants:
            if implant["identity"] == identity:
                return implant["secret"]
        raise KeyError(
            "no gsocket secret is registered for implant %r in %s"
            % (identity, self._path))

    def identities(self) -> List[str]:
        """Every registered identity, in registration order, as a fresh list.

        The secrets are left out on purpose. This is what an operator
        panel lists, and a listing that returns the credential is how a
        secret ends up in a screenshot.
        """
        self._refresh()
        return [implant["identity"] for implant in self._implants]

    def secret_file_for(self, identity: str) -> Path:
        """Write the implant's secret to a 0600 file and return its path.

        This is what `gs-netcat -k` is pointed at, so that the secret
        never appears in an argument vector.

        Rewritten on every call, because the file is a cache of the store
        and nothing else: a secret left from an earlier registration is
        one the store no longer agrees with, and the symptom of that is a
        carrier that joins the relay network and waits forever for a peer
        dialling a different address. Rewriting costs one small atomic
        write per carrier start, which is not a hot path.

        An existing file that other users can read is a different matter
        and is **refused**, exactly as the store itself is on load. That
        file holds one of the same secrets, so a `chmod` back to 0600
        here would be a repair of the mode and a loss of the only
        evidence that the secret was exposed -- the disclosure the store's
        own check insists must trigger a re-key, erased one directory
        down. Only an *existing* file can have been read: on the first
        write there is nothing to have been exposed, so the refusal
        cannot fire there.
        """
        secret = self.secret_for(identity)
        path = self._keyfile_path(identity)
        os.makedirs(str(path.parent), mode=_DIR_MODE, exist_ok=True)
        try:
            existing = os.stat(str(path))
        except FileNotFoundError:
            pass  # The first write for this implant; nothing to disclose.
        else:
            _refuse_loose_mode(path, stat.S_IMODE(existing.st_mode))
        _write_private(path, secret.encode("ascii"), exclusive=False)
        return path

    def _keyfile_path(self, identity: str) -> Path:
        """Where `identity`'s key file goes, from an identity of any shape.

        A slug of the identity so an operator can tell which file is
        which, and a digest of the whole identity so that two identities
        differing only in characters the slug drops cannot land on one
        file -- which would be two implants sharing a secret by accident
        of their names.
        """
        slug = "".join(
            character if character in _SLUG_CHARACTERS else "-"
            for character in identity
        )[:_SLUG_MAX].strip("-")
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
        name = "%s-%s.key" % (slug, digest) if slug else "%s.key" % digest
        return Path(os.path.dirname(self._path), _KEYFILE_DIRNAME, name)

    def _owner_of(self, secret: str) -> Optional[str]:
        """The identity this secret is registered to, or None.

        Only the duplicate guard in `register_implant` asks this -- what
        the carriers look a secret up by is the identity -- so the caller
        already holds the secret being searched for and there is no
        timing oracle here to protect. `compare_digest` rather than `==`
        all the same: a secret comparison that is constant-time in some
        places and not in others is the one that gets copied into the
        place where it matters.
        """
        for implant in self._implants:
            if hmac.compare_digest(implant["secret"], secret):
                return implant["identity"]
        return None

    def _fail(self, field: str, reason: str) -> ValueError:
        return ValueError("%s: %s: %s" % (self._path, field, reason))

    def _refresh(self) -> None:
        """Re-read the file if it is not the one last read or written."""
        status = os.stat(self._path)
        signature = (status.st_mtime_ns, status.st_ino, status.st_mode)
        if signature != self._signature:
            self._load()

    def _load(self) -> None:
        with open(self._path, "r", encoding="utf-8") as handle:
            # Taken from the descriptor we read, so the signature and the
            # mode describe the bytes we parse even if the file is
            # replaced meanwhile.
            status = os.fstat(handle.fileno())
            text = handle.read()
        mode = stat.S_IMODE(status.st_mode)
        _refuse_loose_mode(self._path, mode)
        try:
            document = json.loads(text)
        except ValueError as exc:
            raise self._fail("(file)", "is not valid JSON: %s" % exc)
        if not isinstance(document, dict):
            raise self._fail("(file)", "expected a JSON object")

        entries = document.get("implants", None)
        if not isinstance(entries, list):
            raise self._fail("implants", "expected a list")
        implants = []  # type: List[Dict[str, Any]]
        for index, entry in enumerate(entries):
            where = "implants[%d]" % index
            if not isinstance(entry, dict):
                raise self._fail(where, "expected an object")
            identity = entry.get("identity")
            if not isinstance(identity, str) or not identity:
                raise self._fail(where + ".identity", "must be a non-empty string")
            if "secret" not in entry:
                raise self._fail(where + ".secret", "is missing")
            # The same floor the registration applies, so hand-editing
            # this file is not the way around it.
            problem = _secret_problem(entry["secret"])
            if problem is not None:
                raise self._fail(where + ".secret", problem)
            created = entry.get("created")
            if not isinstance(created, str) or not created:
                raise self._fail(where + ".created", "must be a non-empty string")
            for earlier in implants:
                if earlier["identity"] == identity:
                    raise self._fail(
                        where + ".identity", "%r appears more than once" % identity)
                if hmac.compare_digest(earlier["secret"], entry["secret"]):
                    raise self._fail(
                        where + ".secret",
                        "is the same secret as implant %r" % earlier["identity"])
            implants.append({
                "identity": identity,
                "secret": entry["secret"],
                "created": created,
            })

        self._implants = implants
        self._signature = (status.st_mtime_ns, status.st_ino, status.st_mode)

    def _create(self) -> None:
        os.makedirs(os.path.dirname(self._path), mode=_DIR_MODE, exist_ok=True)
        try:
            signature = self._write([], exclusive=True)
        except FileExistsError:
            # Another process minted the store between our look and our
            # write. Theirs is the deployment's store; use it.
            self._load()
            return
        self._implants = []
        self._signature = signature

    def _write(self, implants: List[Dict[str, Any]], exclusive: bool) -> Tuple[int, int, int]:
        """Write the document atomically; return the signature it has on disk."""
        document = {
            "implants": [
                {
                    "identity": implant["identity"],
                    "secret": implant["secret"],
                    "created": implant["created"],
                }
                for implant in implants
            ]
        }
        data = (json.dumps(document, indent=2) + "\n").encode("utf-8")
        status = _write_private(self._path, data, exclusive=exclusive)
        return (status.st_mtime_ns, status.st_ino, status.st_mode)


def _secret_problem(secret) -> Optional[str]:
    """Why `secret` is unusable, phrased to follow "the secret ... ", or None.

    Returns a reason rather than raising so that the two callers can
    phrase it for their own context -- a registration names the implant,
    a load names the file and the field. Neither includes the secret
    itself: these messages reach an operator's screen and from there a
    bug report.
    """
    if not isinstance(secret, str):
        return "must be a string, got %s" % type(secret).__name__
    if len(secret) < SECRET_MIN_LEN:
        return (
            "must be at least %d characters, and is %d. A guessed secret is "
            "a dialable path to that implant's carrier"
            % (SECRET_MIN_LEN, len(secret)))
    for character in secret:
        if not _LOWEST_CHARACTER <= ord(character) <= _HIGHEST_CHARACTER:
            return (
                "must contain only printable ASCII with no spaces: it is "
                "written to a file and read back by `gs-netcat -k`, which "
                "leaves anything else to disagree about between the two ends")
    return None
