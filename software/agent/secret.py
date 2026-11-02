#!/usr/bin/env python3
"""
A holder for credential material.

Two modules carry live secrets — the LLM API key and the C2 bearer token —
and both need the same guarantee: nothing that prints an object can print the
secret. It lives here rather than in either of them because a transport
client for the C2 has no business importing the LLM package to borrow a
string wrapper, and that dependency would make the LLM package impossible to
remove later.
"""

from typing import Optional


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
