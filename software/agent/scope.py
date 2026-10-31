#!/usr/bin/env python3
"""Fail-closed scope enforcement for the autonomous agent.

A command is permitted only if every target in it resolves with certainty to
an address inside the authorised ranges and outside the denied ones. An
argument whose target cannot be determined (a target file, a shell variable,
a shorthand the parser does not model) is a refusal, never a pass: a refused
command costs the agent one retry, a leaked one costs the engagement.

Nothing here resolves DNS. A hostname counts only if the caller's
`resolve_host` ties it to an address, normally from a prior finding.
`check` and `extract_targets` are total: hostile input yields a refusal
reason, never an exception.

Usage:
    from software.agent import scope

    s = scope.Scope(allow=["10.0.1.0/24"], deny=["10.0.1.254/32"])
    reason = s.check("nmap -sV 10.0.1.5", resolve_host=lambda h: None)
    if reason:
        refuse(reason)
"""

import ipaddress
import re
import shlex
import socket
from typing import Callable, List, Optional, Tuple
from urllib.parse import urlsplit

# ── Recognised shapes ──

_HOSTNAME = re.compile(r"[A-Za-z0-9._-]+", re.ASCII)
_RANGE_SHORT = re.compile(r"(\d+\.\d+\.\d+)\.(\d+)-(\d+)", re.ASCII)
_RANGE_FULL = re.compile(r"([\d.]+)-([\d.]+)", re.ASCII)
_PORT = re.compile(r"\d{1,5}", re.ASCII)
# What libc's inet_aton accepts: 1-4 parts, each decimal, octal or 0x-hex.
_INET_ATON = re.compile(
    r"(?:0[xX][0-9a-fA-F]+|\d+)(?:\.(?:0[xX][0-9a-fA-F]+|\d+)){0,3}", re.ASCII)
# Address-shaped but unparsed (octet lists like 10.0.1-3.5, host:port,
# host/path, IPv6 with port or zone) is unresolvable, never ignorable.
_ADDRESSY = re.compile(r"\d+(?:-\d+)?(?:\.\d+(?:-\d+)?){2}", re.ASCII)
_HOST_THEN_PORT_OR_PATH = re.compile(
    r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+(?=[:/])|[A-Za-z0-9_-]+:\d+", re.ASCII)

# ── Unresolvable by nature ──

_TARGET_FLAGS = ("--target-file", "--targets", "--target-list", "--input-file",
                 "--includefile")
_TARGET_FLAG_PREFIXES = ("-iL", "-iR")  # -iR: nmap picks random targets
_FILE_SUFFIXES = (".txt", ".lst", ".list")
_DYNAMIC_CHARS = frozenset("$`{}\\%")  # expansion, escapes, URL-encoding
_PUNCT = frozenset("();<>|&")
_ALWAYS_HOSTS = ("localhost",)

_NET, _UNKNOWN, _HOST, _BARE, _IGNORE = "net", "unknown", "host", "bare", "ignore"

_HINT = ("name each target individually as an IP address, CIDR block or "
         "range, without files, variables or shorthand")


# ── Parsing ──

def _as_network(addr):
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return ipaddress.ip_network((addr, addr.max_prefixlen))


def _parse_networks(piece: str, loose: bool = True) -> list:
    """Networks a target spelling denotes; ValueError if it is not one.

    `loose` admits the inet_aton spellings (0x0a000105, 167772421, 10.0.261,
    012.0.1.5), which the tools' resolvers turn into real addresses.
    """
    bare = piece.split("%", 1)[0] if ":" in piece else piece
    try:
        return [_as_network(ipaddress.ip_address(bare))]
    except ValueError:
        pass
    if "/" in piece:
        return [ipaddress.ip_network(piece, strict=False)]
    m = _RANGE_SHORT.fullmatch(piece)
    if m:
        first = ipaddress.ip_address("%s.%s" % (m.group(1), m.group(2)))
        last = ipaddress.ip_address("%s.%s" % (m.group(1), m.group(3)))
        return list(ipaddress.summarize_address_range(first, last))
    m = _RANGE_FULL.fullmatch(piece)
    if m:
        return list(ipaddress.summarize_address_range(
            ipaddress.ip_address(m.group(1)), ipaddress.ip_address(m.group(2))))
    if loose and _INET_ATON.fullmatch(piece):
        try:
            return [_as_network(ipaddress.IPv4Address(socket.inet_aton(piece)))]
        except (OSError, ValueError):
            pass
    raise ValueError(piece)


def _classify(piece: str, loose: bool, dotted: bool) -> str:
    if piece.lower().endswith(_FILE_SUFFIXES):
        return _UNKNOWN
    if not dotted and _PORT.fullmatch(piece) and 0 < int(piece) <= 65535:
        return _IGNORE
    try:
        _parse_networks(piece, loose)
        return _NET
    except ValueError:
        pass
    if (_INET_ATON.fullmatch(piece) or _ADDRESSY.search(piece)
            or piece.count(":") >= 2 or _HOST_THEN_PORT_OR_PATH.match(piece)):
        return _UNKNOWN
    if _HOSTNAME.fullmatch(piece):
        if "." in piece or piece.lower() in _ALWAYS_HOSTS:
            return _HOST
        return _BARE
    return _IGNORE


def _tokenise(command: str, depth: int = 0) -> List[str]:
    """Shell words; a quoted word holding whitespace is tokenised again."""
    lex = shlex.shlex(command.replace("\n", " ; ").replace("\r", " ; "),
                      posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    words = []
    for word in lex:
        if not any(c.isspace() for c in word):
            words.append(word)
        elif depth >= 8:
            raise ValueError("quoting nested too deeply")
        else:
            words.extend(_tokenise(word, depth + 1))
    return words


def _scan_value(value: str, found, unknown, bare) -> None:
    if "://" in value:
        try:
            host = urlsplit(value).hostname
        except ValueError:
            host = None
        if not host:
            unknown.append(value)
            return
        value = host
    elif "@" in value:
        value = value.rpartition("@")[2]
    pieces = value.split(",")
    for piece in pieces:
        if piece.startswith("[") and piece.endswith("]"):
            piece = piece[1:-1]
        if not piece:
            continue
        kind = _classify(piece, len(pieces) == 1, "." in value)
        if kind == _UNKNOWN:
            unknown.append(piece)
        elif kind in (_NET, _HOST):
            found.append(piece)
        elif kind == _BARE:
            bare.append(piece)


def _scan(command) -> Tuple[List[str], List[str], List[str]]:
    """(targets, unresolvable arguments, single-label words worth a lookup)."""
    found, unknown, bare = [], [], []
    if not isinstance(command, str):
        return found, ["<non-string command>"], bare
    try:
        words = _tokenise(command)
    except ValueError:
        return found, [command[:80]], bare
    at_start, skip_next = True, False
    for word in words:
        if not word:
            continue
        if set(word) <= _PUNCT:
            at_start, skip_next = True, ">" in word
            if "<" in word:
                unknown.append(word)
            continue
        if skip_next:
            skip_next = False
            continue
        is_program, at_start = at_start, False
        if not word.isascii() or _DYNAMIC_CHARS & set(word):
            unknown.append(word)
        elif word == "-":
            unknown.append(word)
        elif word.startswith("-"):
            flag, _, value = word.partition("=")
            if flag.lower() in _TARGET_FLAGS or flag.startswith(_TARGET_FLAG_PREFIXES):
                unknown.append(word)
            elif value:
                _scan_value(value, found, unknown, bare)
        elif is_program and _classify(word, True, True) not in (_NET, _UNKNOWN):
            continue  # the program name, e.g. secretsdump.py
        else:
            _scan_value(word, found, unknown, bare)
    return found, unknown, bare


def extract_targets(command: str) -> Tuple[List[str], List[str]]:
    """(recognised targets, arguments whose target cannot be determined)."""
    found, unknown, _ = _scan(command)
    return found, unknown


# ── Scope ──

def _contains(outer, net) -> bool:
    return outer.version == net.version and net.subnet_of(outer)


def _overlaps(a, b) -> bool:
    return a.version == b.version and a.overlaps(b)


class Scope:
    """Authorised (allow) and forbidden (deny) address ranges.

    A malformed entry raises ValueError here, not later: a silently dropped
    deny entry would be a fail-open. Allow entries must have no host bits set
    (a typo must not widen the authorisation); deny entries are widened to
    their network, which can only refuse more.
    """

    def __init__(self, allow: List[str], deny: List[str]):
        self._allow = [ipaddress.ip_network(c, strict=True) for c in allow]
        self._deny = [ipaddress.ip_network(c, strict=False) for c in deny]

    def check(self, command: str,
              resolve_host: Callable[[str], Optional[str]]) -> Optional[str]:
        """None if every target is in scope, else the reason for refusing."""
        try:
            return self._check(command, resolve_host)
        except Exception as exc:  # fail closed on any surprise
            return "scope check failed (%s); refusing" % type(exc).__name__

    def _check(self, command, resolve_host) -> Optional[str]:
        found, unknown, bare = _scan(command)
        if unknown:
            return "cannot verify %s against the authorised scope; %s" % (
                ", ".join("'%s'" % u for u in unknown), _HINT)
        for token in found:
            try:
                nets = _parse_networks(token)
            except ValueError:
                reason = self._check_host(token, resolve_host(token))
            else:
                reason = self._verdict(token, nets)
            if reason:
                return reason
        for word in bare:
            addr = resolve_host(word)
            if addr is not None:
                reason = self._check_host(word, addr)
                if reason:
                    return reason
        return None

    def _check_host(self, name: str, addr) -> Optional[str]:
        if addr is None:
            return ("hostname '%s' has no finding tying it to an address; "
                    "use its IP address" % name)
        try:
            if not isinstance(addr, str):
                raise ValueError(addr)
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return "hostname '%s' resolves to %r, which is not a single address" % (
                name, addr)
        return self._verdict("%s (%s)" % (name, addr), [_as_network(ip)])

    def _verdict(self, label: str, nets) -> Optional[str]:
        for net in nets:
            for denied in self._deny:
                if _overlaps(net, denied):
                    return "'%s' overlaps the denied range %s" % (label, denied)
            if not any(_contains(a, net) for a in self._allow):
                return "'%s' is not entirely inside the authorised ranges (%s)" % (
                    label, ", ".join(str(a) for a in self._allow) or "none")
        return None
