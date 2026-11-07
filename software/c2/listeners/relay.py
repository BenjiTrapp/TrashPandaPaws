"""Carry an opaque payload to the team server's agent socket and back.

The one piece every listener shares. It takes a base64 string that is
already encrypted, POSTs it, and returns the base64 string that comes
back. It never decrypts, never validates and is never given a key -- two
tests pin that, because this is the module a listener container would
carry and the place a key could leak into one by accident.

Failure is `None`, never an exception. Each caller's correct response to a
failure is to tell its client the exchange failed and let the client's own
interval and jitter decide when to try again, so an exception would be
caught and discarded at every call site. For the same reason there is no
retry here: the beacon already has one, and a second would silently
double it.
"""

import json
import logging
import urllib.error
import urllib.request
from typing import Optional

# Where the far end looks for the payload. ServerCrypto.unwrap checks these
# fourteen names and only then falls back to scanning every string longer
# than 32 characters -- the fallback is robustness, not an interface, so the
# request must land in the named loop. ServerCrypto.wrap picks one of them
# at random for its answer, which is why finding it means scanning.
#
# Imported from the beacon rather than the server: both modules carry the
# identical list, and the beacon is stdlib-only while the server drags in
# five third-party packages. One source, no duplication, no flask in a
# listener container.
from ..beacon import _PAYLOAD_FIELDS

logger = logging.getLogger("raccoon.listeners.relay")

# Fixed, and first in the list so unwrap's loop matches immediately. The
# beacon randomises its field because its traffic crosses hostile ground;
# this hop is a listener talking to the team server over loopback or a
# container network, where there is nothing to evade and a fixed name is
# one less thing to explain.
_REQUEST_FIELD = _PAYLOAD_FIELDS[0]

_MIN_PAYLOAD_LEN = 32

# An explicit ceiling on what we will read back, because without one a
# hostile or broken server can make this function hold a string of any
# size -- and the listener above it would then dutifully fragment that
# into datagrams or push it down a pipe to the beacon, amplifying on the
# server's behalf. Measured before this was added: a 1 MB body with one
# long string came back as a 1 MB payload.
#
# 64 MiB is generous rather than tight on purpose. A check-in answer
# carries tasking, and a task may legitimately carry a file to drop on the
# target, so a small cap would break real work; the point here is that the
# number is bounded and stated rather than absent.
_MAX_ANSWER_BYTES = 64 * 1024 * 1024


def relay(payload: str, *, url: str, timeout: float = 30.0) -> Optional[str]:
    """POST `payload` to `url`; return the payload that comes back.

    `None` means the exchange failed, for any reason: the server was down,
    it answered something other than 200, the body was not JSON, or it
    carried no field that could hold a payload.
    """
    body = json.dumps({_REQUEST_FIELD: payload}).encode()
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json"})

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            # urlopen raises for 4xx and 5xx, so reaching here means 2xx;
            # anything other than 200 is still not an answer we trust.
            if response.status != 200:
                logger.debug("relay: status %s from %s", response.status, url)
                return None
            # One byte more than the ceiling, so a body that is exactly at
            # the limit still reads and one over it is detectable.
            raw = response.read(_MAX_ANSWER_BYTES + 1)
            if len(raw) > _MAX_ANSWER_BYTES:
                logger.debug("relay: answer from %s exceeded %d bytes",
                             url, _MAX_ANSWER_BYTES)
                return None
    except urllib.error.HTTPError as exc:
        logger.debug("relay: HTTP %s from %s", exc.code, url)
        return None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # URLError covers a refused connection and a DNS failure; OSError
        # covers a timeout, which surfaces as socket.timeout; ValueError
        # covers a malformed url reaching us from configuration.
        logger.debug("relay: %s talking to %s", exc, url)
        return None

    return _payload_of(raw, url)


def _payload_of(raw: bytes, url: str) -> Optional[str]:
    """Find the payload in a response body, or return None."""
    try:
        answer = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        logger.debug("relay: body from %s was not JSON", url)
        return None

    if not isinstance(answer, dict):
        return None

    for field in _PAYLOAD_FIELDS:
        value = answer.get(field)
        if isinstance(value, str) and len(value) > _MIN_PAYLOAD_LEN:
            return value

    # The same last resort unwrap() keeps on its side: a field name neither
    # end knows about should not strand a payload that is plainly there.
    for value in answer.values():
        if isinstance(value, str) and len(value) > _MIN_PAYLOAD_LEN:
            return value

    logger.debug("relay: no payload field in the answer from %s", url)
    return None
