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
from typing import Any, Callable, List, Optional, Tuple
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
# Flags whose value is a filename to write, never a target. Without this,
# `nmap -oX out.xml 10.0.1.5` is refused because out.xml matches the hostname
# shape, and the refusal reads "use its IP address" — advice the caller
# cannot follow. Safe to ignore now that a scan must name a target anyway.
#
# Only unambiguous spellings are global. A bare `-o` is an output file for
# curl and wget but an *option* for ssh, and `-w` is a write target for some
# tools and a timeout for nc — so those are resolved per program below,
# the same way numeric flags are. Guessing globally cost two tests.
_OUTPUT_FLAGS = frozenset((
    "-oa", "-on", "-og", "-ox", "-oj", "-os", "-ow",
    "--output", "--output-file", "--outfile", "--log", "--logfile",
    "--log-file", "--stylesheet", "--append-output",
))
_PROGRAM_OUTPUT_FLAGS = {
    "curl": ("-o", "-O", "--remote-name", "--dump-header", "-D", "--trace",
             "--trace-ascii"),
    "wget": ("-o", "-O", "--output-document"),
    "masscan": ("-o",),
    "tee": ("-a",),
    "tcpdump": ("-w",),
    "tshark": ("-w",),
    "dumpcap": ("-w",),
}
# Flags naming a file the tool reads its *configuration* from. A config can
# carry ranges, so this is the same class as a target file, not an output
# file, and it is refused rather than ignored.
_CONFIG_FILE_FLAGS = {
    "masscan": ("-c", "--conf", "--readrange", "--resume"),
    "nmap": ("--script-args-file", "--servicedb", "--versiondb"),
    "hydra": ("-C",),
}
_FILE_SUFFIXES = (".txt", ".lst", ".list")
_DYNAMIC_CHARS = frozenset("$`{}\\%")  # expansion, escapes, URL-encoding
_GLOB_CHARS = frozenset("*?[]")
# The one legitimate use of brackets: an IPv6 literal, [fd00::1], at the start
# of a word or after @ / , = and before the end or : / ,
_BRACKETED_V6 = re.compile(r"(?:^|(?<=[@/,=]))\[([0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*)\](?=$|[:/,])")
_PUNCT = frozenset("();<>|&")
# A bare number is a port or count only as the value of a flag known to take
# one *for the program in command position*: `-c 4` is a count for ping, while
# `-n 22` is a boolean flag then an address for nmap. After any other flag it
# is a target (nmap reads 22 as 0.0.0.22), so an unlisted flag refuses the
# command and never passes it. A program missing from _PROGRAM_FLAGS gets only
# the shared scanner list below; do not widen that fallback.
_NUMERIC_FLAGS = (
    "-p", "--port", "--ports", "--top-ports", "--max-rate", "--min-rate",
    "--max-retries", "--host-timeout", "--max-rtt-timeout", "--min-rtt-timeout",
    "--initial-rtt-timeout", "--max-parallelism", "--min-parallelism",
    "--max-hostgroup", "--min-hostgroup", "--scan-delay", "--max-scan-delay",
    "--mtu", "--data-length", "--ttl", "--source-port", "-g", "-T", "--rate",
    "--retries", "--threads", "-t", "--timeout", "--wait", "--connect-timeout",
    "--delay", "--jitter")
_PRIVILEGE_VALUE_FLAGS = ("-u", "-U", "--user", "-g", "--group")
# Programs none of whose operands is a host. Their arguments are search
# terms, package names or versions, so reading them as targets refuses the
# command on its own input: a live run asked for `searchsploit dnsmasq 2.90`
# and `searchsploit vsftpd 2.3.4` and had the version refused as an
# address, which blocked the phase that looks CVEs up.
#
# Kept small and specific. This exempts a program from target scanning
# entirely, so a program that takes hosts *and* free text does not belong
# here -- it belongs in _PROGRAM_FLAGS with its value flags named.
_PROGRAMS_WITHOUT_TARGETS = frozenset((
    "searchsploit", "apropos", "whatis", "man", "which", "whereis",
    "apt", "apt-get", "apt-cache", "dpkg", "rpm", "yum", "dnf", "brew",
    "pip", "pip3", "gem", "npm",
))

_PROGRAM_FLAGS = {
    "nmap": _NUMERIC_FLAGS,
    "masscan": _NUMERIC_FLAGS,
    "ping": ("-c", "-i", "-W", "-t", "-s", "-w"),
    "curl": ("-m", "--max-time", "--connect-timeout", "--retry", "--retry-delay",
             "--retry-max-time", "--limit-rate"),
    "wget": ("-t", "-T", "--tries", "--timeout", "--wait"),
    "nc": ("-w", "-i", "-q", "-p"),
    "ncat": ("-w", "-i", "-q", "-p"),
    "ssh": ("-p",),
    "sleep": (),
    "searchsploit": (),
    "head": ("-n", "-c", "--lines", "--bytes"),
    "tail": ("-n", "-c", "--lines", "--bytes"),
    # Prefixes: their own flags that take a separate value. Guessing from the
    # word's shape fails (see safety._WRAPPER_VALUE_FLAGS).
    "timeout": ("-s", "--signal", "-k", "--kill-after"),
    "nice": ("-n", "--adjustment"),
    "ionice": ("-c", "-n", "--class", "--classdata"),
    "stdbuf": ("-i", "-o", "-e", "--input", "--output", "--error"),
    "env": ("-u", "--unset", "-C", "--chdir", "-S", "--split-string"),
    "xargs": ("-a", "--arg-file", "-d", "--delimiter", "-E", "-I", "-L",
              "-n", "--max-args", "-P", "--max-procs", "-s", "--max-chars"),
    "watch": ("-n", "--interval"),
    "time": ("-f", "-o", "--format", "--output"),
    "sudo": _PRIVILEGE_VALUE_FLAGS,
    "doas": _PRIVILEGE_VALUE_FLAGS,
    "runas": _PRIVILEGE_VALUE_FLAGS,
    "pkexec": _PRIVILEGE_VALUE_FLAGS,
    "nohup": (), "exec": (), "setsid": (), "command": (), "busybox": (),
}
# Programs in front of the real one; the program is the next positional word.
_PREFIXES = frozenset((
    "sudo", "doas", "runas", "pkexec", "env", "nohup", "exec", "setsid",
    "command", "busybox", "time", "stdbuf", "ionice", "xargs", "watch",
    "timeout", "nice"))
# Programs whose first positional argument is a duration or count, which is
# ignored; the exemption ends at the first other positional word, so
# `timeout 60 nmap -n 22` still refuses the 22.
_NUMBER_FIRST = frozenset(("timeout", "nice", "sleep", "head", "tail"))
# `nc host 80`: the second positional word is the port. The first stays a target,
# so `nc 80` is still refused.
_PORT_AFTER_HOST = frozenset(("nc", "ncat", "netcat", "telnet"))
_ASSIGNMENT = re.compile(r"\w+=", re.ASCII)
_DURATION = re.compile(r"\d+(?:\.\d+)?[smhd]?", re.ASCII)
# A file descriptor glued to a redirect (2>&1, 1>out) at the start of a word.
# `nmap 22 > out` has a space, so the 22 stays an argument and is refused.
_REDIRECT_FD = re.compile(r"(?<![^\s;|&(])\d(?=[<>])", re.ASCII)
_ALWAYS_HOSTS = ("localhost",)

_NET, _UNKNOWN, _HOST, _BARE, _PATH, _IGNORE = (
    "net", "unknown", "host", "bare", "path", "ignore")

_HINT = ("name each target individually as an IP address, CIDR block or "
         "range, without files, variables or shorthand")

_NUMBER_HINT = ("; a number that is a flag's value must be attached to it "
                "(-c4, -p22, --count=4), anywhere else it reads as an address")

_CLIP = 80  # what a refusal echoes of attacker-shaped text


def _clip(text: str) -> str:
    return text[:_CLIP] + ("..." if len(text) > _CLIP else "")


def _describe(command) -> str:
    if isinstance(command, str):
        return repr(_clip(command))
    return "<%s>" % type(command).__name__


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
    if "%" in piece:  # a zone id is not part of the address; never trim it off
        raise ValueError(piece)
    try:
        return [_as_network(ipaddress.ip_address(piece))]
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


def _classify(piece: str, loose: bool, dotted: bool, after_flag: bool = False) -> str:
    if piece.lower().endswith(_FILE_SUFFIXES):
        # A target-list suffix. Treated as a path rather than refused: this
        # branch used to refuse it, which also refused `cat notes.txt`. The
        # case it guards — `nxc smb hosts.txt`, a file of targets with
        # nothing checked — is caught by `require_target` instead.
        return _PATH
    if not dotted and _PORT.fullmatch(piece) and 0 < int(piece) <= 65535:
        # Only a flag's value is a port. Anywhere else the tools read the
        # number as an address: `nmap 22` scans 0.0.0.22.
        return _IGNORE if after_flag else _UNKNOWN
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
        # A single-label word with no finding is not refused here (nmap dc01):
        # `-u admin` looks identical. Deferred to the router's strict mode.
        return _BARE
    if "/" in piece or piece.startswith(("~", ".")):
        return _PATH
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


def _is_dynamic(word: str) -> bool:
    """True if the shell or the tool would expand the word to something else."""
    if _DYNAMIC_CHARS & set(word):
        return True
    head = word
    if "://" in word:  # a URL's path and query may legitimately hold ? * [ ]
        scheme, _, rest = word.partition("://")
        head = scheme + "://" + rest.split("/", 1)[0]
    head = _BRACKETED_V6.sub(_drop_valid_v6, head)
    return bool(_GLOB_CHARS & set(head))


def _drop_valid_v6(match) -> str:
    try:
        ipaddress.IPv6Address(match.group(1))
    except ValueError:
        return match.group(0)
    return ""


# `//host/share` and `\\host\share`. A share has no spelling that does not
# name its host, so refusing the whole word as unverifiable made every SMB
# invocation unreachable -- and told the model to "name each target
# individually as an IP address", which is advice it cannot follow. Both
# forms are split here the way the :// branch splits a URL.
_SHARE = re.compile(r"^//([^/]+)(?:/.*)?$")
_UNC = re.compile(r"(?<!\S)\\\\([^\\\s]+)\\")


def _scan_value(value: str, found, unknown, bare, after_flag: bool = False) -> None:
    value_in = value
    share = _SHARE.match(value)
    if share:
        value = share.group(1)
    elif "://" in value:
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
    named = False
    for piece in pieces:
        if piece.startswith("[") and piece.endswith("]"):
            piece = piece[1:-1]
        if not piece:
            continue
        named = True
        kind = _classify(piece, len(pieces) == 1, "." in value, after_flag)
        if kind == _UNKNOWN:
            unknown.append(piece)
        elif kind == _PATH:
            # A path is not a target, so it is not refused here. Refusing
            # every path — which this did — made the agent unable to read a
            # file at all: `cat /etc/shadow`, `ls /opt`, `grep pass
            # /var/log/auth.log` were all rejected, and that is most of what
            # there is to do on a host once you are on it.
            #
            # The hole it was closing was `nxc smb /tmp/hosts`, a file of
            # targets slipping through with nothing checked. That is caught
            # one layer up instead: a command the classifier calls a scan
            # must name at least one checkable target, which the router
            # enforces with `require_target`. A path after a known
            # target-file flag (-iL, -iR) is still refused, above this.
            continue
        elif kind in (_NET, _HOST):
            found.append(piece)
        elif kind == _BARE:
            bare.append(piece)
    if not named:  # `10.0.9.5@` and `10.0.9.5@,` name nothing to check
        unknown.append(value_in)


def _scan(command) -> Tuple[List[str], List[str], List[str]]:
    """(targets, unresolvable arguments, single-label words worth a lookup)."""
    found, unknown, bare = [], [], []
    if not isinstance(command, str):
        return found, ["<non-string command>"], bare
    try:
        # `\\host\share` -> `//host/share` before tokenising, which folds
        # backslashes away and would leave `\10.0.1.5share`. Anchored on
        # whitespace so `DOMAIN\user` is untouched.
        normalised = _UNC.sub(r"//\1/", _REDIRECT_FD.sub("", command))
        words = _tokenise(normalised)
    except ValueError:
        return found, [command[:_CLIP]], bare
    at_start, skip_next, after_flag = True, False, False
    # looking: the segment's program is not known yet; prefix: the last prefix
    # seen while looking; num_open: its leading number is still to come.
    looking, prog, prefix, num_open, options_ended = True, "", "", False, False
    positionals, output_pending = 0, False
    for word in words:
        if not word:
            continue
        if set(word) <= _PUNCT:
            at_start, skip_next, after_flag = True, ">" in word, False
            looking, prog, prefix, num_open, options_ended = True, "", "", False, False
            positionals, output_pending = 0, False
            if "<" in word:
                unknown.append(word)
            continue
        if skip_next:
            skip_next = after_flag = looking = False
            continue
        is_program, at_start = at_start, False
        follows_flag = after_flag
        is_flag = word.startswith("-") and word != "-" and not options_ended
        if word == "--" and not options_ended:
            options_ended = True
            after_flag = False
            continue
        if output_pending and not is_flag:
            # The filename an output flag writes to. Not a target, and
            # letting it through reads as a hostname: see _OUTPUT_FLAGS.
            output_pending = False
            after_flag = False
            continue
        output_pending = False
        if is_flag:
            bare_flag = word.partition("=")[0]
            lowered = bare_flag.lower()
            which = prefix if looking else prog
            config_flags = _CONFIG_FILE_FLAGS.get(which, ())
            if (bare_flag in config_flags or lowered in config_flags
                    or any(bare_flag.startswith(f) and len(bare_flag) > len(f)
                           and f.startswith("-") and not f.startswith("--")
                           for f in config_flags)):
                # A config file can list ranges, so it is a target file.
                # The startswith arm catches the attached form, `-c/tmp/conf`,
                # which partition("=") leaves whole.
                unknown.append(word)
                after_flag = False
                continue
            if (lowered in _OUTPUT_FLAGS
                    or bare_flag in _PROGRAM_OUTPUT_FLAGS.get(which, ())):
                # `-oX=out.xml` carries its value; `-oX out.xml` does not.
                output_pending = "=" not in word
                after_flag = False
                continue
            known = (_PROGRAM_FLAGS.get(prefix, ()) if looking
                     else _PROGRAM_FLAGS.get(prog, _NUMERIC_FLAGS))
            after_flag = word in known
        else:
            after_flag = False
            if word != "-" and not follows_flag:
                if num_open and _DURATION.fullmatch(word):
                    num_open = False
                    continue
                num_open = False
                if looking and not _ASSIGNMENT.match(word):
                    name = word.rsplit("/", 1)[-1].lower()
                    if name in _PREFIXES:
                        prefix, num_open = name, name in _NUMBER_FIRST
                    else:
                        looking, prog, num_open = False, name, name in _NUMBER_FIRST
                elif not looking and prog in _PORT_AFTER_HOST:
                    positionals += 1
                    if (positionals == 2 and _PORT.fullmatch(word)
                            and 0 < int(word) <= 65535):
                        continue
        if not looking and prog in _PROGRAMS_WITHOUT_TARGETS:
            # Its operands are search terms, not hosts.
            continue
        share = _SHARE.match(word)
        if share:
            # `//host/share` names its host and nothing else the scope can
            # judge. Read before the dynamic-text screen on purpose: a
            # share is routinely called ADMIN$ or C$, and the `$` was being
            # read as a variable reference, which refused every SMB
            # invocation on its share name.
            word = share.group(1)
        if not word.isascii() or _is_dynamic(word):
            unknown.append(word)
        elif word == "-":
            unknown.append(word)
        elif is_flag:
            flag, _, value = word.partition("=")
            if flag.lower() in _TARGET_FLAGS or flag.startswith(_TARGET_FLAG_PREFIXES):
                unknown.append(word)
            elif value:
                _scan_value(value, found, unknown, bare, after_flag=True)
        elif is_program and _classify(word, True, True) not in (_NET, _UNKNOWN):
            continue  # the program name, e.g. secretsdump.py
        else:
            _scan_value(word, found, unknown, bare, follows_flag)
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
              resolve_host: Callable[[str], Any],
              *, require_target: bool = False) -> Optional[str]:
        """None if every target is in scope, else the reason for refusing.

        `require_target` refuses a command that names nothing checkable at
        all. It is off by default and the router turns it on for commands
        classified as scanning, because that is where "no targets found"
        means "the targets are hidden in a file" rather than "this command
        has no targets". See the note above `_PATH`.
        """
        try:
            return self._check(command, resolve_host,
                               require_target=require_target)
        except Exception as exc:  # fail closed on any surprise
            return "scope check failed (%s) on %s; refusing" % (
                type(exc).__name__, _describe(command))

    def _check(self, command, resolve_host, require_target=False) -> Optional[str]:
        found, unknown, bare = _scan(command)
        if unknown:
            hint = _HINT
            if any(_PORT.fullmatch(u) for u in unknown):
                hint += _NUMBER_HINT
            return "cannot verify %s against the authorised scope; %s" % (
                ", ".join("'%s'" % _clip(u) for u in unknown), hint)
        if require_target and not found and not bare:
            return ("this command names no target the scope can check; %s"
                    % _HINT)
        verified = 0
        for token in found:
            try:
                nets = _parse_networks(token)
            except ValueError:
                reason = self._check_host(token, resolve_host(token))
            else:
                reason = self._verdict(token, nets)
            if reason:
                return reason
            verified += 1
        for word in bare:
            addr = resolve_host(word)
            if addr is not None:
                reason = self._check_host(word, addr)
                if reason:
                    return reason
                verified += 1
        if require_target and not verified:
            # Counting only what was actually checked. A single-label word
            # that resolved to nothing is not a target — `nxc smb
            # /tmp/hosts` leaves "smb", nxc's protocol argument, and that
            # must not satisfy the requirement.
            return ("this command names no target the scope can check; %s"
                    % _HINT)
        return None

    def _check_host(self, name: str, addr) -> Optional[str]:
        """Check one hostname against the scope.

        `addr` is whatever the caller's resolver returned: `None`, a single
        address, or several. Several is the normal case — any dual-stack name
        resolves to both an A and an AAAA record — so refusing a list would
        make hostname targets unusable, `localhost` included. Every address
        has to be inside the authorised ranges and outside the denied ones,
        which keeps this fail-closed: one address outside refuses the whole
        name, because the tool may well pick that one.
        """
        if addr is None:
            return ("hostname '%s' has no finding tying it to an address; "
                    "use its IP address" % _clip(name))
        # An explicit list of container types rather than "is it iterable":
        # a dict is iterable and yields its keys, so a resolver that returned
        # a mapping would be judged on whatever happened to be in key
        # position. A set is allowed because deduplicating is a reasonable
        # thing for a resolver to do.
        if isinstance(addr, str):
            addrs = [addr]
        elif isinstance(addr, (list, tuple, set, frozenset)):
            addrs = sorted(addr, key=repr)
        else:
            return "hostname '%s' resolved to %s, which is not an address" % (
                _clip(name), _clip(repr(addr)))
        if not addrs:
            # An empty result is "I looked and found nothing", which is the
            # same position as no finding at all, not a pass.
            return ("hostname '%s' has no finding tying it to an address; "
                    "use its IP address" % _clip(name))
        nets = []
        for one in addrs:
            try:
                if not isinstance(one, str):
                    raise ValueError(one)
                nets.append(_as_network(ipaddress.ip_address(one)))
            except ValueError:
                return ("hostname '%s' resolved to %s, which is not an "
                        "address" % (_clip(name), _clip(repr(one))))
        shown = addrs[0] if len(addrs) == 1 else ", ".join(str(a) for a in addrs)
        return self._verdict("%s (%s)" % (name, _clip(shown)), nets)

    def _verdict(self, label: str, nets) -> Optional[str]:
        for net in nets:
            for denied in self._deny:
                if _overlaps(net, denied):
                    return "'%s' overlaps the denied range %s" % (_clip(label), denied)
            if not any(_contains(a, net) for a in self._allow):
                return "'%s' is not entirely inside the authorised ranges (%s)" % (
                    _clip(label), ", ".join(str(a) for a in self._allow) or "none")
        return None
