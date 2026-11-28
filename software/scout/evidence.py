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
import collections
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

# ── bounds, because this runs for as long as the implant is dark ──
#
# The design's own worst case for an outage is a week, on a 4 GB device
# that is bridging and running the sniffer's capture at the same time.
# Every container below used to grow without a ceiling, and a review
# measured 400 MB of resident memory from 40,000 frames of ordinary
# traffic -- most of it unanswered DNS queries and unanswered ClientHellos
# that nothing ever expired. The OOM killer would then have taken the
# scout, the sniffer or the beacon.
#
# `MAX_ENTRIES` caps what is published: the first N distinct things seen,
# because the *first* resolver and the *first* proxy a host used are the
# ones a rung wants, and a flood arriving later must not push them out.
# `MAX_PENDING` caps what is waiting for an answer, and that one evicts
# oldest-first: a query from ten minutes ago is not going to be answered.
MAX_ENTRIES = 256
MAX_PENDING = 2048

# A captive portal's form, as a body this will replay. Capped because a
# frame can carry 64 KB and the rung sends it verbatim.
MAX_PORTAL_BODY = 4096

# Where a captive portal can be. It is on the network the host is being
# held off, so a redirect to a public address is not a portal -- it is a
# frame pointing the implant at somebody's canary URL. Checked by prefix
# rather than with `ipaddress`, which `beacon.py` cannot have and this
# file keeps in step with by hand.
_PRIVATE_PREFIXES = ("10.", "192.168.", "169.254.", "127.")


class Evidence(object):
    """One stuck window's reading of the tapped port."""

    def __init__(self, own_mac=None, host_macs=None):
        # This implant's own address on the bridge, so its own traffic is
        # not mistaken for the host's. The scout sniffs `br0`, which
        # carries the beacon's own queries and its own TLS -- so without
        # this the document and the model's prompt could describe the
        # implant to itself, and the trail would name the implant as the
        # identity rung 4 would take. `None` on a host where it cannot be
        # read, which is the old behaviour and is still better than
        # refusing to collect anything.
        self.own_mac = (own_mac or "").strip().lower() or None
        # Which MACs the **bridge** has learned on the downstream port,
        # which is the side the host is on.
        #
        # This is the anchor for every piece of evidence a rung acts on,
        # and three reviews running it was something an adversary could
        # write: first anything on the wire, then "the first sender",
        # which a single DNS query ahead of the host's first request made
        # into the forger -- four frames bought a borrowable credential
        # and blinded the scout to the real host for the rest of a window
        # the design says can last a week. A port is not forgeable by a
        # peer on the segment, so the bridge is asked instead of the
        # frame.
        #
        # `None` is a host whose bridge could not be read, and then the
        # first sender is taken as before: a scout that refused to collect
        # because it could not find the forwarding table would be worse
        # than one that can be lied to. `docs/WAY_OUT.md` says which.
        self.host_macs = (frozenset(mac.strip().lower() for mac in host_macs
                                    if mac and mac.strip())
                          if host_macs is not None else None)
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
        # resolver answer" is the question the rung needs settled. Ordered
        # and bounded, so the oldest unanswered query is the one evicted.
        self._dns_pending = collections.OrderedDict()
        # The proxies that have answered a 407 on a CONNECT. A credential
        # is recorded only for one of these: a `Proxy-Authorization`
        # header is one frame anybody on the segment can send, and the
        # borrow rung answers a *refusal*, so the refusal has to have
        # happened. Keyed by `host:port`.
        self._refused_by = collections.OrderedDict()
        # CONNECTs waiting for their answer, so a 407 can be attributed to
        # the proxy the host was really talking to.
        self._connect_pending = collections.OrderedDict()
        # ClientHellos waiting for a ServerHello, keyed by the reverse flow
        # tuple -- the key the server's packet will have.
        self._tls_pending = collections.OrderedDict()
        # The portal noticed, and the request to it that is waiting to be
        # called answered.
        # The portal a redirect named, **per flow**: it was one global
        # name, so a 302 seen on any flow blessed a POST on any other --
        # which is not "the whole sequence on one flow", whatever the
        # commit that narrowed it said.
        self._portal_host = collections.OrderedDict()
        self._portal_pending = collections.OrderedDict()

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
        # Every row of the evidence table is gated on the sender, and the
        # gate is on the **request** side only -- see `_from_the_host`.
        # `dot1x_seen` is not evidence-only: it reaches the rescue record,
        # the operator's panel, a policy rule and rung 4's detection
        # probability, and one frame from anyone used to set it.
        if int(packet[Ether].type) == _EAPOL_TYPE:
            if self._from_the_host(packet):
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
            # A query is a request, so it has to be the host's. The answer
            # below is not gated: it can only settle something a query
            # already put in `_dns_pending`.
            if not self._from_the_host(packet):
                return
            self._note_identity(packet)
            _remember(self._dns_pending, key, True)
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
        self._dns_pending.pop(key, None)
        if (resolver not in self.resolvers
                and len(self.resolvers) >= MAX_ENTRIES):
            return
        self.resolvers[resolver] = self.resolvers.get(resolver, 0) + 1

    def _note_wpad(self, dns) -> None:
        name = _qname(dns)
        if name and name.split(".", 1)[0] == "wpad":
            _append(self.wpad, name)

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
            # A response is not gated on its sender: by construction it
            # can only settle something a *request* already recorded, and
            # a request's sender was checked. The 407 that makes a
            # credential borrowable is such a response -- it only counts
            # against a CONNECT in `_connect_pending`.
            self._http_response(packet, start, headers)
        elif self._from_the_host(packet):
            self._http_request(packet, start, headers, body)

    # ── HTTP ──

    def _http_request(self, packet, start, headers, body) -> None:
        parts = start.split()
        if len(parts) < 2 or parts[0] not in _REQUEST_METHODS:
            return
        method, target = parts[0], parts[1]
        self._note_identity(packet)
        where = "%s:%d" % (packet[IP].dst, int(packet[TCP].dport))
        if method == "CONNECT" and _is_local(str(packet[IP].dst)):
            # And on this network. A proxy at a public address is not this
            # network's proxy, whoever sent the frame.
            _append(self.proxies, where)
            _remember(self._connect_pending, _reverse_flow(packet), where)
            # Only against a CONNECT, and only to a proxy that has already
            # refused one: see `_refused_by`.
            self._note_credential(headers, where)
        host = headers.get("host", "")
        if method == "GET":
            self._note_pac(host, target)
        if (method == "POST" and host
                and host == self._portal_host.get(_flow(packet))):
            text = body.decode("utf-8", "replace")
            if len(text) <= MAX_PORTAL_BODY:
                _remember(self._portal_pending, _reverse_flow(packet), {
                    "url": "http://%s%s" % (host, target),
                    "body": text,
                    "content_type": headers.get("content-type", ""),
                })

    def _note_pac(self, host, target) -> None:
        path = target.split("?", 1)[0]
        last = path.rsplit("/", 1)[-1].lower()
        if not host or not (last.endswith(".pac") or last == "wpad.dat"):
            return
        _append(self.pac, "http://%s%s" % (host, target))

    def _http_response(self, packet, start, headers) -> None:
        status = _status(start)
        if status is None:
            return
        flow = _flow(packet)
        if status in _REDIRECTS:
            host = _netloc(headers.get("location", ""))
            # Only a portal on the network the host is being held off. A
            # redirect to a public address is one frame anybody on the
            # segment can send, and the rung would replay it -- which is a
            # request to somebody else's canary URL from the one host that
            # cannot afford to make one. Keyed by the flow the host would
            # answer it on, which is this response's reverse.
            if host and _is_local(host):
                _remember(self._portal_host, _reverse_flow(packet), host)
            return
        if status == 407:
            # The proxy demanded authentication. That is what makes a
            # credential on the next CONNECT worth borrowing.
            proxy = self._connect_pending.pop(flow, None)
            if proxy:
                _remember(self._refused_by, proxy, True, limit=MAX_ENTRIES)
            return
        pending = self._portal_pending.pop(flow, None)
        if pending is not None and status in _PORTAL_ACCEPTED:
            # The host got *past* a portal. That is what makes the answer
            # worth replaying; a redirect on its own is a login page.
            self.portal = pending
            self.portal_answered = True

    def _note_credential(self, headers, where) -> None:
        if where not in self._refused_by:
            # A header on a request to a host that never answered 407 is
            # not evidence of a credential this host needs -- it is a
            # frame. The borrow rung answers a refusal, so the refusal is
            # the precondition.
            return
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
        _append(self.credentials, {"kind": kind, "user": user,
                                   "secret": secret, "where": where})

    # ── TLS ──

    def _tls(self, packet, payload) -> None:
        kind = _handshake_type(payload)
        if kind == _TLS_CLIENT_HELLO:
            # The host's handshakes, and nobody else's: this row is the
            # target a louder rung aims at.
            if not self._from_the_host(packet):
                return
            name = _sni(payload)
            if name:
                self._note_identity(packet)
                _remember(self._tls_pending, _reverse_flow(packet), name)
        elif kind == _TLS_SERVER_HELLO:
            name = self._tls_pending.pop(_flow(packet), None)
            if name:
                # Only now. "The host proves this works" is the whole value
                # of this line, and a ClientHello nobody answered proves
                # the opposite.
                _append(self.tls_destinations, name)

    # ── identity ──

    def _from_the_host(self, packet) -> bool:
        """Whether this frame came from the host side of the bridge.

        The bridge's own forwarding table when there is one -- a MAC it
        learned on the downstream port, which a peer on the segment cannot
        forge -- and otherwise the first-sender latch this used to have,
        for a host where the table could not be read.

        The implant's own frames are never the host's, whichever way the
        question is answered: the scout sniffs `br0`, which carries the
        beacon's own traffic.

        **Asked of requests only.** A response comes from the other side
        of the conversation by definition, and it can only settle
        something a request already recorded -- a query in
        `_dns_pending`, a ClientHello in `_tls_pending`, a CONNECT in
        `_connect_pending`, a POST in `_portal_pending`. Gating responses
        as well would have thrown away every answer and left the evidence
        empty, which is how this was first written and what the tests
        caught.
        """
        try:
            mac = str(packet[Ether].src or "").lower()
        except Exception:
            return False
        if not mac or (self.own_mac and mac == self.own_mac):
            return False
        if self.host_macs is not None:
            return mac in self.host_macs
        if self.host_mac is None:
            return True
        return mac == self.host_mac

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
        if self.own_mac and mac == self.own_mac:
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


def _append(sequence: list, item) -> None:
    """Add `item` once, up to `MAX_ENTRIES`. See the bounds above.

    The *first* N and not the last: the first resolver and the first proxy
    a host used are the ones a rung wants, and a flood arriving later must
    not be able to push them out.
    """
    if item in sequence or len(sequence) >= MAX_ENTRIES:
        return
    sequence.append(item)


def _remember(pending, key, value, limit=None) -> None:
    """Record something waiting for an answer, oldest evicted first.

    The opposite policy from `_append`, and deliberately: a query from ten
    minutes ago is not going to be answered, so the newest are the ones
    worth keeping room for.

    `limit` is `MAX_PENDING` for the things that really are waiting, and
    `MAX_ENTRIES` for the one that is a *finding* -- the proxies that
    answered a 407. That one is small in reality and growable by anyone on
    the segment at two frames an entry, which is how it got missed by the
    bounding pass and then added, unbounded, by the pass that narrowed
    the credential arm.
    """
    pending[key] = value
    pending.move_to_end(key)
    ceiling = MAX_PENDING if limit is None else limit
    while len(pending) > ceiling:
        pending.popitem(last=False)


def _is_local(host: str) -> bool:
    """Whether a redirect's host could be a captive portal on this network.

    A portal is on the network the host is being held off. A name is
    allowed -- a portal usually has one, and this implant cannot resolve
    it to check -- but a public address is not: that is a frame pointing
    the implant at somebody else's URL.
    """
    name = host.split(":", 1)[0].strip().lower().rstrip(".")
    if not name:
        return False
    parts = name.split(".")
    if not all(part.isdigit() for part in parts) or len(parts) != 4:
        return True            # a name, not an address
    if name.startswith(_PRIVATE_PREFIXES):
        return True
    if parts[0] == "172":
        try:
            return 16 <= int(parts[1]) <= 31
        except ValueError:
            return False
    return False


def _is_multicast(mac: str) -> bool:
    try:
        return bool(int(mac.split(":", 1)[0], 16) & 0x01)
    except ValueError:
        return False
