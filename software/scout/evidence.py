#!/usr/bin/env python3
"""What the host on the other side of the bridge proves works.

The implant is an inline tap between a switch port and a host, so it can
see what gets out of that host -- evidence nobody in this repository
collects today, and the reason this project exists. `Evidence` is the
reading of that traffic and nothing else: it holds no socket, starts no
thread, and decides nothing. `software/scout/scout.py` feeds it packets
and publishes what it says.

**Why the bytes are parsed here rather than through scapy's layers.** HTTP
and TLS arrive as a TCP payload, and the question asked of them is narrow:
one request line, one header, one extension. scapy can parse both, through
layers whose availability depends on how it was built, and an exception
from one of them lands on the capture thread. So the payload is read as
bytes, every read is guarded, and a frame that does not parse is a frame
ignored. `Ether`, `IP`, `TCP`, `UDP` and `DNS` *are* taken from scapy:
those five are the layers the sniffer beside this file already relies on.

**Nothing `observe` is given may raise.** It runs on a capture thread on a
13 W device with no guard of its own, and a parse error that cost the
scout its thread would cost the implant the evidence this whole project is
about. `observe` therefore swallows everything and the tests pin it.

**Two shapes come out, and the split is deliberate.**
`as_document_fields` is the handoff the beacon reads: counts, names and
flags, no secret. `as_borrow_fields` is the private half -- the
credentials themselves and the portal request to replay -- which the
scout writes 0600 and only a borrow verb ever opens. A handoff carrying
passwords would be a second place they can be found on a device built to
look like an IP phone.
"""

import base64
import binascii
import logging
from typing import Dict, List, Optional

from scapy.all import DNS, IP, TCP, UDP, Ether

logger = logging.getLogger("raccoon.scout.evidence")

# ── The filter, which is the table in the design and no more ──
#
# This is a *second* promiscuous reader on a device whose whole power
# budget is about 13 W and which is already bridging and capturing, so the
# filter is the cost control: five protocols, each one a row of the design's
# evidence table.
#
#   ether proto 0x888e   EAPOL, which sets dot1x_seen
#   udp port 53          the host's resolver, and whether it answers
#   tcp port 80/8080/3128  CONNECT, PAC fetches, portal redirects
#   tcp port 443         TLS ClientHello/ServerHello: destinations that work
#
# Ports and not a payload match, because a BPF filter runs in the kernel
# and anything narrower would have to run here.
BPF_FILTER = ("ether proto 0x888e or udp port 53 or tcp port 80 "
              "or tcp port 8080 or tcp port 3128 or tcp port 443")

# EAPOL. The same ether type `nac_bypass.enable_eapol_forwarding` lets
# across the bridge so the downstream device stays authenticated.
_EAPOL_TYPE = 0x888E

# The flag names, in the rescue record's own bit order -- FLAG_DOT1X_SEEN
# is 0x02 and FLAG_PORTAL_ANSWERED is 0x04 -- because that is the order an
# operator reads them in `dns_rescue.py` and in the panel, and
# `_egress_check_flag`'s messages already make that promise about the two
# live flags.
_FLAG_ORDER = ("dot1x_seen", "portal_answered")

_REDIRECTS = (301, 302, 303, 307, 308)
_PORTAL_ACCEPTED = (200, 204, 302, 303)
_REQUEST_METHODS = ("GET", "POST", "CONNECT", "HEAD", "PUT")

# A ClientHello is handshake type 1 inside record type 22; a ServerHello is
# handshake type 2 in the same record type. The extension that carries the
# name is 0.
_TLS_HANDSHAKE = 0x16
_TLS_CLIENT_HELLO = 0x01
_TLS_SERVER_HELLO = 0x02
_TLS_EXT_SERVER_NAME = 0x0000

_NOT_A_SENDER = ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")


class Evidence(object):
    """One stuck window's reading of the tapped port."""

    def __init__(self):
        self.dot1x_seen = False
        self.portal_answered = False
        self.resolvers = {}             # type: Dict[str, int]
        self.tls_destinations = []      # type: List[str]
        self.proxies = []               # type: List[str]
        self.pac = []                   # type: List[str]
        self.wpad = []                  # type: List[str]
        self.credentials = []           # type: List[dict]
        self.portal = None              # type: Optional[dict]
        self.host_mac = None            # type: Optional[str]
        self.host_ip = None             # type: Optional[str]
        # Queries waiting for an answer, keyed by (resolver, id): a
        # resolver counts only once it has answered one, because "does this
        # resolver answer" is the question the rung needs settled.
        self._dns_pending = set()
        # ClientHellos waiting for a ServerHello, keyed by the reverse flow
        # tuple -- the key the server's packet will have.
        self._tls_pending = {}          # type: Dict[tuple, str]
        # The portal noticed, and the request to it that is waiting to be
        # called answered.
        self._portal_host = None        # type: Optional[str]
        self._portal_pending = {}       # type: Dict[tuple, dict]

    # ── the one entry point ──

    def observe(self, packet) -> None:
        """Read one captured frame. Raises nothing, whatever it is given."""
        try:
            self._observe(packet)
        except Exception as exc:
            # Debug and not a warning: a frame this does not understand is
            # the normal case on a tapped port, and one line per such frame
            # would be the loudest thing on the device.
            logger.debug("scout: a frame was not read: %s", exc)

    # ── what comes out ──

    def flags(self) -> List[str]:
        """The live flag names this evidence sets, in the record's bit order."""
        return [name for name in _FLAG_ORDER if getattr(self, name)]

    def as_document_fields(self) -> dict:
        """The handoff half: no secret, and JSON-safe."""
        return {
            "flags": self.flags(),
            "resolvers": dict(self.resolvers),
            "tls_destinations": list(self.tls_destinations),
            "proxies": list(self.proxies),
            "pac": list(self.pac),
            "wpad": list(self.wpad),
            # The count and not the credentials: see the module docstring.
            "credentials": len(self.credentials),
            "portal": {"url": self.portal["url"],
                       "content_type": self.portal["content_type"]}
            if self.portal else None,
            "host_mac": self.host_mac,
            "host_ip": self.host_ip,
        }

    def as_borrow_fields(self) -> dict:
        """The private half, for the file only a borrow verb opens."""
        return {
            "credentials": [dict(entry) for entry in self.credentials],
            "portal": dict(self.portal) if self.portal else None,
        }

    # ── the reading ──

    def _observe(self, packet) -> None:
        if not packet.haslayer(Ether):
            return
        if int(packet[Ether].type) == _EAPOL_TYPE:
            self.dot1x_seen = True
            return
        if not packet.haslayer(IP):
            return
        if packet.haslayer(UDP):
            self._udp(packet)
        elif packet.haslayer(TCP):
            self._tcp(packet)

    def _udp(self, packet) -> None:
        if not packet.haslayer(DNS):
            return
        dns = packet[DNS]
        resolver = (str(packet[IP].dst) if not int(dns.qr)
                    else str(packet[IP].src))
        key = (resolver, int(dns.id))
        if not int(dns.qr):
            self._note_identity(packet)
            self._dns_pending.add(key)
            self._note_wpad(dns)
            return
        # An answer, and only one with an answer section: a REFUSED or a
        # NXDOMAIN is a resolver that replied, not a resolver that resolves.
        #
        # The section itself and not `ancount`: that field is computed when
        # a packet is *built*, so it reads None on a `DNS()` constructed in
        # a test and 0 on the same bytes once they have been through the
        # wire. The answer section is the thing either way, and it is empty
        # -- `[]` -- on both a constructed and a parsed refusal.
        if key not in self._dns_pending or not dns.an:
            return
        self._dns_pending.discard(key)
        self.resolvers[resolver] = self.resolvers.get(resolver, 0) + 1

    def _note_wpad(self, dns) -> None:
        name = _qname(dns)
        if name and name.split(".", 1)[0] == "wpad" and name not in self.wpad:
            self.wpad.append(name)

    def _tcp(self, packet) -> None:
        payload = _payload(packet)
        if not payload:
            return
        if payload[0] == _TLS_HANDSHAKE:
            self._tls(packet, payload)
            return
        head = _http_head(payload)
        if head is None:
            return
        start, headers, body = head
        if start.startswith("HTTP/"):
            self._http_response(packet, start, headers)
        else:
            self._http_request(packet, start, headers, body)

    # ── HTTP ──

    def _http_request(self, packet, start, headers, body) -> None:
        parts = start.split()
        if len(parts) < 2 or parts[0] not in _REQUEST_METHODS:
            return
        method, target = parts[0], parts[1]
        self._note_identity(packet)
        where = "%s:%d" % (packet[IP].dst, int(packet[TCP].dport))
        if method == "CONNECT":
            if where not in self.proxies:
                self.proxies.append(where)
        self._note_credential(headers, where)
        host = headers.get("host", "")
        if method == "GET":
            self._note_pac(host, target)
        if method == "POST" and host and host == self._portal_host:
            self._portal_pending[_reverse_flow(packet)] = {
                "url": "http://%s%s" % (host, target),
                "body": body.decode("utf-8", "replace"),
                "content_type": headers.get("content-type", ""),
            }

    def _note_pac(self, host, target) -> None:
        path = target.split("?", 1)[0]
        last = path.rsplit("/", 1)[-1].lower()
        if not host or not (last.endswith(".pac") or last == "wpad.dat"):
            return
        url = "http://%s%s" % (host, target)
        if url not in self.pac:
            self.pac.append(url)

    def _http_response(self, packet, start, headers) -> None:
        status = _status(start)
        if status is None:
            return
        flow = _flow(packet)
        if status in _REDIRECTS:
            host = _netloc(headers.get("location", ""))
            if host:
                self._portal_host = host
            return
        pending = self._portal_pending.pop(flow, None)
        if pending is not None and status in _PORTAL_ACCEPTED:
            # The host got *past* a portal. That is what makes the answer
            # worth replaying; a redirect on its own is a login page.
            self.portal = pending
            self.portal_answered = True

    def _note_credential(self, headers, where) -> None:
        value = headers.get("proxy-authorization", "")
        parts = value.split(None, 1)
        if len(parts) != 2:
            return
        scheme, token = parts[0].lower(), parts[1].strip()
        if scheme == "ntlm" or scheme == "negotiate":
            # A challenge-response carries no password to borrow. Recorded
            # as what it is, so the rung declines with a reason instead of
            # selecting a credential with an empty secret.
            self._add_credential("proxy-%s" % scheme, "", "", where)
            return
        if scheme != "basic":
            return
        try:
            decoded = base64.b64decode(token, validate=True).decode(
                "utf-8", "replace")
        except (binascii.Error, ValueError):
            return
        if ":" not in decoded:
            return
        user, secret = decoded.split(":", 1)
        self._add_credential("proxy-basic", user, secret, where)

    def _add_credential(self, kind, user, secret, where) -> None:
        entry = {"kind": kind, "user": user, "secret": secret,
                 "where": where}
        if entry not in self.credentials:
            self.credentials.append(entry)

    # ── TLS ──

    def _tls(self, packet, payload) -> None:
        kind = _handshake_type(payload)
        if kind == _TLS_CLIENT_HELLO:
            name = _sni(payload)
            if name:
                self._note_identity(packet)
                self._tls_pending[_reverse_flow(packet)] = name
        elif kind == _TLS_SERVER_HELLO:
            name = self._tls_pending.pop(_flow(packet), None)
            if name and name not in self.tls_destinations:
                # Only now. "The host proves this works" is the whole value
                # of this line, and a ClientHello nobody answered proves
                # the opposite.
                self.tls_destinations.append(name)

    # ── identity ──

    def _note_identity(self, packet) -> None:
        """The first client-side sender, which is the host behind the tap.

        Taken from a parsed *request* -- an HTTP request line, a DNS query,
        a ClientHello -- and never from a bare frame. The tap sees both
        directions of the bridge and nothing in a frame says which side it
        came from, so "the one that asks" is the only honest reading
        available here.
        """
        if self.host_mac is not None:
            return
        mac = str(packet[Ether].src or "").lower()
        if not mac or mac in _NOT_A_SENDER or _is_multicast(mac):
            return
        self.host_mac = mac
        self.host_ip = str(packet[IP].src)


# ── the byte reading, all of it guarded by `observe` ──


def _payload(packet) -> bytes:
    layer = packet[TCP].payload
    data = bytes(layer) if layer else b""
    return data


def _http_head(payload: bytes):
    """`(start-line, headers, body)` or None when this is not a full head."""
    split = payload.split(b"\r\n\r\n", 1)
    if len(split) != 2:
        return None
    lines = split[0].split(b"\r\n")
    start = lines[0].decode("latin-1").strip()
    headers = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, _, value = line.partition(b":")
        headers[name.decode("latin-1").strip().lower()] = \
            value.decode("latin-1").strip()
    return start, headers, split[1]


def _status(start: str):
    parts = start.split()
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def _netloc(location: str) -> str:
    text = location.strip()
    for scheme in ("http://", "https://"):
        if text.lower().startswith(scheme):
            return text[len(scheme):].split("/", 1)[0]
    return ""


def _flow(packet) -> tuple:
    return (str(packet[IP].src), str(packet[IP].dst),
            int(packet[TCP].sport), int(packet[TCP].dport))


def _reverse_flow(packet) -> tuple:
    return (str(packet[IP].dst), str(packet[IP].src),
            int(packet[TCP].dport), int(packet[TCP].sport))


def _qname(dns) -> str:
    """The question's name, through the list scapy's `qd` now is.

    Indexed rather than read as an attribute: `qd` is a `PacketListField`
    in current scapy, and reaching `qname` on the list itself goes through
    a compatibility shim that warns -- so a suite run with warnings on
    would report the shim rather than anything about this code.
    """
    question = dns.qd
    if not question:
        return ""
    if isinstance(question, (list, tuple)):
        question = question[0]
    name = getattr(question, "qname", b"")
    if isinstance(name, bytes):
        name = name.decode("utf-8", "replace")
    return str(name).rstrip(".").lower()


def _handshake_type(payload: bytes):
    if len(payload) < 6:
        return None
    return payload[5]


def _sni(payload: bytes):
    """The one server_name a ClientHello carries, or None.

    Every length is checked against what is actually there, because a
    record cut short by the capture is the ordinary case on a tap -- and
    an `IndexError` here would be a frame that cost the scout its thread
    if `observe` ever stopped guarding.
    """
    # 5 bytes of record header, 4 of handshake header, 2 version, 32 random.
    at = 5 + 4 + 2 + 32
    if len(payload) < at + 1:
        return None
    at += 1 + payload[at]                        # session id
    if len(payload) < at + 2:
        return None
    at += 2 + int.from_bytes(payload[at:at + 2], "big")   # cipher suites
    if len(payload) < at + 1:
        return None
    at += 1 + payload[at]                        # compression methods
    if len(payload) < at + 2:
        return None
    end = at + 2 + int.from_bytes(payload[at:at + 2], "big")
    at += 2
    while at + 4 <= min(end, len(payload)):
        kind = int.from_bytes(payload[at:at + 2], "big")
        size = int.from_bytes(payload[at + 2:at + 4], "big")
        body = payload[at + 4:at + 4 + size]
        if len(body) < size:
            return None
        if kind == _TLS_EXT_SERVER_NAME:
            return _server_name(body)
        at += 4 + size
    return None


def _server_name(body: bytes):
    if len(body) < 5:
        return None
    # 2 bytes of list length, then entries of (type, 2-byte length, name).
    at = 2
    if body[at] != 0x00:
        return None
    size = int.from_bytes(body[at + 1:at + 3], "big")
    name = body[at + 3:at + 3 + size]
    if len(name) < size or not name:
        return None
    return name.decode("utf-8", "replace").rstrip(".").lower()


def _is_multicast(mac: str) -> bool:
    try:
        return bool(int(mac.split(":", 1)[0], 16) & 0x01)
    except ValueError:
        return False
