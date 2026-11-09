#!/usr/bin/env python3
"""
A holder for credential material, and the one reader of a credential file.

Two modules carry live secrets — the LLM API key and the C2 bearer token —
and both need the same guarantee: nothing that prints an object can print the
secret. It lives here rather than in either of them because a transport
client for the C2 has no business importing the LLM package to borrow a
string wrapper, and that dependency would make the LLM package impossible to
remove later.

A third caller now needs the same guarantee for a file: the Google token
source reads a key file, and so does the configuration loader. The loader
imports the LLM package, so the token source cannot import the loader to
borrow its reader without closing a cycle. The reader lives here for the same
reason the holder does, and the mode check that guards a credential is
written exactly once.
"""

import os
import stat
from typing import Optional


class SecretError(Exception):
    """A credential file that cannot be used, with a message safe to show.

    Every message names the path and, where relevant, the mode, and nothing of
    the content.
    """


class Secret:
    """Holds a credential so no repr, str or vars() dump can print it.

    A plain string attribute would show up in any dump of the owner's
    __dict__ and in any dataclass-style repr someone adds later.
    """

    __slots__ = ("_value",)

    def __init__(self, value: Optional[str]):
        self._value = value

    def reveal(self) -> Optional[str]:
        return self._value

    def __bool__(self) -> bool:
        return bool(self._value)

    def __repr__(self) -> str:
        return "<Secret>"

    __str__ = __repr__


def check_keyfile_mode(path: str, st_mode: int) -> None:
    """Refuse a credential file that is not a regular file only its owner can
    read.

    The one place this test is written. `read_keyfile` calls it on the
    descriptor it is about to read, and the token source's startup check
    calls it on a stat of the path, so tightening it here tightens both.
    """
    if not stat.S_ISREG(st_mode):
        raise SecretError("api_key_file %s is not a regular file" % path)
    # Any group or other bit, not only "not 0644": 0640 shares the key with a
    # group just as surely. 0400 passes; it is stricter than 0600.
    if st_mode & 0o077:
        raise SecretError(
            "api_key_file %s has mode %04o; it holds a secret and must be "
            "readable by its owner only (chmod 600)"
            % (path, stat.S_IMODE(st_mode)))


def read_keyfile(path: str) -> str:
    """The key in a file only its owner can read.

    The mode is checked on the descriptor that is then read, not on the path
    beforehand, so the file cannot be swapped between check and read. Every
    message names the path and the mode and nothing of the content.
    """
    path = os.path.expanduser(path)
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as exc:
        raise SecretError("api_key_file %s cannot be opened (%s)"
                          % (path, exc.strerror)) from None
    # fstat before fdopen: opening a directory as text raises at fdopen.
    try:
        check_keyfile_mode(path, os.fstat(fd).st_mode)
    except SecretError:
        os.close(fd)
        raise
    failure = None
    key = ""
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        try:
            key = handle.read().strip()
        except (OSError, UnicodeDecodeError):
            failure = "api_key_file %s cannot be read as text" % path
    # Raised once the except block has exited. A UnicodeDecodeError holds the
    # bytes it failed on in `.object`, which here are the key, and `from None`
    # hides __context__ without clearing it.
    if failure is not None:
        raise SecretError(failure)
    if not key:
        raise SecretError("api_key_file %s is empty" % path)
    return key
