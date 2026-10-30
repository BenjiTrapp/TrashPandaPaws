#!/usr/bin/env python3
"""Safety layer for the autonomous agent.

Classifies every command the agent proposes into one of three tiers —
forbidden (TIER_HARD), requires operator approval (TIER_KNOCK), permitted
(TIER_FREE) — screens for shell metacharacters, rewrites scanning commands
to enforce gentle timing, and validates stored scripts line by line.

Nothing here executes anything. Every function is total: hostile or
malformed input yields a verdict, never an exception.

Usage:
    from software.agent import safety

    cls = safety.classify(cmd, target_kind="beacon",
                          is_uplink_iface=lambda n: n == "eth0",
                          phase5_enabled=False)
    if cls.tier == safety.TIER_HARD:
        refuse(cls.reason)
"""

import math
import re
from collections import namedtuple

# ── Tiers ──

TIER_HARD = 1
TIER_KNOCK = 2
TIER_FREE = 3

Classification = namedtuple(
    "Classification",
    "tier action_key action_class points p_success p_detect phase reason",
)

# A tier-2 pattern with no RISK_TABLE row still never degrades to tier 3.
_UNKNOWN_KNOCK = (25, 0.3, 0.6)

_FREE = Classification(
    tier=TIER_FREE, action_key="", action_class="recon", points=0,
    p_success=0.0, p_detect=0.0, phase=0, reason="",
)

# ── Metacharacter screening ──

# Chaining, pipes, substitution, redirection, newlines and NUL. Screened on
# the raw string, before any normalisation, so nothing can be hidden by it.
_METACHARS = re.compile(r"[;&|`$()<>\n\r\x00]")


def has_shell_metachars(command):
    """True if the command contains shell syntax, or is not a string at all."""
    if not isinstance(command, str):
        return True
    return bool(_METACHARS.search(command))


# ── Normalisation ──
#
# Two normalised forms, produced once per command by _forms, and every
# pattern is matched against both. One deletes backslashes, which defeats
# escape tricks (r\eboot → reboot); the other turns them into slashes, which
# keeps Windows paths tokenised so that \bshutdown still has a word boundary
# in ...\System32\shutdown.exe. Deleting backslashes and keeping those paths
# tokenised are mutually exclusive on a single string, which is why there
# are two.

_CONTROL = re.compile(r"[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e]")
_QUOTES = re.compile(r"[\"'\\]")
_WHITESPACE = re.compile(r"\s+")

# `sudo -u alice cmd` and `doas -n cmd` both have to reduce to `cmd`, so the
# flag list has to know which flags take a value.
_PRIVILEGE = re.compile(
    r"^(?:sudo|doas|runas|pkexec|su)\b"
    r"(?:\s+(?:-u|-U|--user|-g|--group)\s+\S+|\s+-[^\s]+)*\s*")

# Wrappers that put a real program in argument position. Without these,
# `nohup sleep 7200` and `/usr/bin/sleep 7200` escape the first-token check.
_WRAPPERS = ("env", "nohup", "timeout", "exec", "setsid", "stdbuf", "nice",
             "ionice", "busybox", "command", "time")

# Commands that read rather than act. A verb appearing as their argument is
# a string, not an instruction: `grep reboot /var/log/syslog` must not be
# refused, or the agent cannot read its own logs.
#
# Deliberately excludes find, sed, awk and xxd. Each of those can execute or
# write — `find … -exec`, `sed -i`, `xxd -r` — so trusting their arguments as
# data would suppress the rules for the very lines that act.
_READERS = ("grep", "egrep", "fgrep", "rgrep", "man", "cat", "less", "more",
            "tail", "head", "ls", "echo", "file", "stat", "wc", "strings",
            "nl", "od", "dirname", "basename", "realpath")

# Wrappers that put a real program in argument position, and the shell-ish
# forms that introduce a nested command.
_COMMAND_INTRODUCERS = ("xargs", "watch", "su", "nohup", "timeout", "env",
                        "setsid", "stdbuf", "nice", "ionice", "busybox",
                        "command", "time", "exec", "sudo", "doas", "runas",
                        "pkexec", "sh", "bash", "zsh", "dash", "shell")


def _normalise(command):
    text = _CONTROL.sub("", command)
    text = _QUOTES.sub("", text)
    text = _WHITESPACE.sub(" ", text.lower()).strip()
    return text


def _strip_privilege(text):
    """Drop leading privilege-escalation wrappers and their flags."""
    previous = None
    while previous != text:
        previous = text
        text = _PRIVILEGE.sub("", text, count=1).strip()
    return text


# Which of each wrapper's own flags take a separately-given value. Guessing
# this from the token's shape does not work: a heuristic that treats an
# all-caps word as a value misses `timeout -s term …` once the line has been
# lowercased, and one that skips any token after any flag eats the real
# command in `env -i rm -rf /`, where -i takes nothing.
_WRAPPER_VALUE_FLAGS = {
    "timeout": ("-s", "--signal", "-k", "--kill-after"),
    "nice": ("-n", "--adjustment"),
    "ionice": ("-c", "-n", "--class", "--classdata"),
    "stdbuf": ("-i", "-o", "-e", "--input", "--output", "--error"),
    "env": ("-u", "--unset", "-s", "--split-string", "-c", "--chdir"),
    "xargs": ("-n", "-i", "-p", "-d", "-s", "-l", "--max-args",
              "--replace", "--max-procs", "--delimiter", "--max-lines"),
    "watch": ("-n", "--interval"),
    "time": ("-f", "-o", "--format", "--output"),
}


def _skip_wrapper_arguments(tokens, wrapper=""):
    """Drop a wrapper's own arguments, including values given separately.

    `timeout -s TERM 30 cmd` has to reduce to `cmd`. The first attempt at
    this skipped the flag but not its value, which left `term` in program
    position — hiding the real command and making a signal name look like one.
    """
    value_flags = _WRAPPER_VALUE_FLAGS.get(wrapper, ())
    rest = list(tokens)
    while rest:
        token = rest[0]
        if token.startswith("-"):
            rest = rest[1:]
            if rest and token in value_flags:
                rest = rest[1:]
            continue
        if re.match(r"^\d+(?:\.\d+)?[smhd]?$", token) or re.match(r"^\w+=", token):
            rest = rest[1:]
            continue
        break
    return rest


def _strip_wrappers(text):
    """Drop leading wrappers that put the real program in argument position."""
    previous = None
    while previous != text:
        previous = text
        tokens = text.split()
        if not tokens:
            break
        wrapper = _basename(tokens[0]).lower()
        if wrapper not in _WRAPPERS:
            break
        text = " ".join(_skip_wrapper_arguments(tokens[1:], wrapper)).strip()
    return text


def _effective(text):
    """The command with wrappers, privilege prefixes and `shell` removed."""
    text = _strip_privilege(text)
    if text.startswith("shell "):
        text = _strip_privilege(text[6:].strip())
    text = re.sub(r"^(?:sh|bash|zsh|dash|cmd(?:\.exe)?|powershell(?:\.exe)?)\b"
                  r"(?:\s+-\w+)*\s+", "", text).strip()
    text = _strip_privilege(_strip_wrappers(text))
    return text


def _program(text):
    """Basename of the effective command's program, lowercased."""
    tokens = text.split()
    if not tokens:
        return ""
    name = _basename(tokens[0]).lower()
    return name[:-4] if name.endswith(".exe") else name


def _basename(token):
    """Last path component of a token, for either separator."""
    return token.replace("\\", "/").rsplit("/", 1)[-1]


# ── LLM probability clamp ──

_CLAMP_SPAN = 0.2
_P_MIN = 0.01
_P_MAX = 0.99


def clamp_llm_adjustment(prior, proposed):
    """Bound an LLM-proposed probability to ±0.2 around the prior.

    The gate runs in the router, not as a tool, so the model cannot skip it —
    but it can still propose numbers. Clamping keeps a proposal advisory
    rather than authoritative. A proposal that is not a finite number is
    discarded in favour of the prior.
    """
    try:
        value = float(proposed)
    except (TypeError, ValueError):
        return prior
    if math.isnan(value):
        return prior
    low = prior - _CLAMP_SPAN
    high = prior + _CLAMP_SPAN
    value = max(low, min(high, value))
    return max(_P_MIN, min(_P_MAX, value))


# ── Risk table ──
#
# One row per action key. Tier-2 rows carry the priors the EV gate computes
# with; tier-1 rows carry zeroes because they are never weighed, only refused.


def _row(tier, key, cls_, reason, points=0, p_success=0.0, p_detect=0.0, phase=0):
    return Classification(tier=tier, action_key=key, action_class=cls_,
                          points=points, p_success=p_success,
                          p_detect=p_detect, phase=phase, reason=reason)


RISK_TABLE = {
    # ── Tier 1: irreversible, or fatal to the operation ──
    "beacon_control": _row(
        TIER_HARD, "beacon_control", "lifecycle",
        "beacon lifecycle control is irreversible without an operator"),
    "sleep_too_long": _row(
        TIER_HARD, "sleep_too_long", "lifecycle",
        "a sleep this long takes the beacon out of reach for hours"),
    "dropbox_lifeline": _row(
        TIER_HARD, "dropbox_lifeline", "lifecycle",
        "touches the drop-box bridge, NAC bypass, cover identity or tunnel"),
    "power_off": _row(
        TIER_HARD, "power_off", "lifecycle",
        "reboot or shutdown of the host carrying the beacon"),
    "network_service": _row(
        TIER_HARD, "network_service", "lifecycle",
        "restarting or disabling networking severs the C2 channel"),
    "firewall_change": _row(
        TIER_HARD, "firewall_change", "lifecycle",
        "firewall mutation can cut the C2 channel"),
    "disk_wipe": _row(
        TIER_HARD, "disk_wipe", "destructive",
        "destroys the filesystem of the host"),
    "airmon_check_kill": _row(
        TIER_HARD, "airmon_check_kill", "lifecycle",
        "airmon-ng check kill stops NetworkManager and severs C2"),

    # ── Tier 2: OpSec- or resilience-relevant, gated ──
    "iface_change": _row(
        TIER_KNOCK, "iface_change", "lifecycle",
        "changes the mode or state of a network interface",
        points=0, p_success=0.9, p_detect=0.2),
    "lsass_dump": _row(
        TIER_KNOCK, "lsass_dump", "credential_access",
        "credential material extraction — the single loudest EDR trigger",
        points=50, p_success=0.5, p_detect=0.7, phase=4),
    "responder": _row(
        TIER_KNOCK, "responder", "credential_access",
        "active name-resolution poisoning is broadcast and very visible",
        points=50, p_success=0.6, p_detect=0.55, phase=3),
    "ntlm_relay": _row(
        TIER_KNOCK, "ntlm_relay", "lateral",
        "relay and authentication coercion against third-party hosts",
        points=75, p_success=0.4, p_detect=0.5, phase=5),
    "log_clear": _row(
        TIER_KNOCK, "log_clear", "anti_forensics",
        "clearing logs is itself a high-signal detection event",
        points=0, p_success=0.8, p_detect=0.8, phase=5),
    "shadow_copy_delete": _row(
        TIER_KNOCK, "shadow_copy_delete", "anti_forensics",
        "shadow copy and recovery destruction reads as ransomware",
        points=0, p_success=0.8, p_detect=0.85, phase=5),
    "persist": _row(
        TIER_KNOCK, "persist", "persistence",
        "installing persistence leaves an artifact that outlives the test",
        points=25, p_success=0.9, p_detect=0.25, phase=4),
    "deauth": _row(
        TIER_KNOCK, "deauth", "wifi",
        "deauthentication is disruptive and attributable",
        points=30, p_success=0.7, p_detect=0.4, phase=6),
    "exploit_known_poc": _row(
        TIER_KNOCK, "exploit_known_poc", "exploitation",
        "exploitation against a confirmed service version",
        points=25, p_success=0.6, p_detect=0.3, phase=5),
}


# ── Classification rules ──
#
# Ordered, and the order is a correctness property rather than a style
# choice. Two reasons:
#
#   1. Tier-1 rules are listed before tier-2 rules, so a line that contains
#      both reaches the tier-1 verdict. "responder -I eth0 reboot" is a
#      reboot first and a poisoning attempt second.
#   2. Within a family the more specific rule comes first, so a removal verb
#      cannot be captured by an installation pattern that is a substring of
#      it — `unpersist` is handled as a beacon verb before `persist` is ever
#      consulted.
#
# Every pattern is matched against both normalised forms (see _forms): one
# with backslashes deleted, which defeats escape tricks like r\eboot, and one
# with backslashes turned into slashes, which keeps Windows paths tokenised.
# Teaching a rule one more program name is a single new alternation branch.

_RULES = [
    # ── Tier 1 ──
    (re.compile(r"\b(?:reboot|poweroff)\b(?!\.\w)"
                r"|\bshutdown(?:\.exe)?\b"
                r"|\bhalt\b(?!\.\w)"
                r"|\bkexec\b"
                r"|\b(?:restart|stop)-computer\b"
                r"|\b(?:tel)?init\s+[0-6]\b"
                r"|\bsystemctl\b[^/]*\b(?:poweroff|reboot|halt|kexec|emergency)\b"
                r"|\bsystemctl\b.*\bisolate\s+(?:rescue|emergency)"), "power_off"),

    (re.compile(r"\b(?:ip6?tables|ebtables|arptables)\b"
                r"(?=.*(?:\s-[fxz]\b|--flush|--delete-chain|--policy"
                r"|--insert|--append|--delete\b"
                r"|\s-p\s+\w+\s+(?:drop|reject)|\s-[aidr]\b))"
                r"|\bip6?tables-restore\b"
                r"|\bnft\b.*\b(?:flush|delete)\b"
                r"|\bufw\b[^|]*?\s(?:enable|disable|reset|default)\b"
                r"|\bfirewall-cmd\b.*(?:--reload|--add|--remove|--panic)"),
     "firewall_change"),

    (re.compile(r"\b(?:systemctl|service|rc-service)\b"
                r"(?=.*\b(?:stop|restart|disable|mask|reload)\b)"
                r"(?=.*\b(?:networkmanager|systemd-networkd|networking|network"
                r"|wpa_supplicant|dhcpcd|dhclient)\b)"
                r"|/etc/init\.d/network\w*\b.*\b(?:stop|restart)\b"
                r"|\bnetplan\s+apply\b"
                r"|\bnmcli\b.*\b(?:networking\s+(?:off|disable)"
                r"|radio\s+(?:\w+\s+)?(?:off|disable)"
                r"|r\s+all\s+(?:off|disable)|con(?:nection)?\s+down"
                r"|managed\s+no)\b"
                r"|\bip\b[^/]*\b(?:r|route)\s+(?:flush|del|delete)\b"
                r"|\bip\b[^/]*\b(?:a|addr|address)\s+(?:flush|del|delete)\b"
                r"|\broute\b\s+(?:del|delete|flush)\b"
                r"|\bdhclient\b\s+-r\b"), "network_service"),

    (re.compile(r"\bairmon-ng\b.*\bcheck\s+kill\b"), "airmon_check_kill"),

    # ── Tier 2 ──
    (re.compile(r"\blsassy\b|-m\s+lsassy\b|\blsass\b"
                r"|\bsecretsdump(?:\.py)?\b|impacket-secretsdump"
                r"|\bmimikatz\b|\bsekurlsa\b|\bpypykatz\b"
                r"|comsvcs\.dll|\bminidump\b|\bnanodump(?:\.exe)?\b"
                r"|\breg\s+save\b.*\b(?:sam|security|system)\b"
                r"|\bntdsutil\b|ntds\.dit\b"
                r"|--(?:lsa|ntds|sam)\b"), "lsass_dump"),

    (re.compile(r"\bresponder(?:\.py)?\b|\binveigh\b|\bmitm6\b"), "responder"),

    (re.compile(r"\bntlmrelayx(?:\.py)?\b|impacket-ntlmrelayx"
                r"|\bkrbrelayx(?:\.py)?\b|\bsmbrelayx(?:\.py)?\b"
                r"|\bprinterbug(?:\.py)?\b|\bdfscoerce(?:\.py)?\b"
                r"|\bcoercer\b|\bpetitpotam(?:\.py)?\b|-m\s+coerce"), "ntlm_relay"),

    (re.compile(r"\bwevtutil(?:\.exe)?\b.*\b(?:cl|clear-log)\b"
                r"|\bclear-eventlog\b"
                r"|\bjournalctl\b.*--vacuum"
                r"|\b(?:rm|shred|truncate|unlink)\b.*/var/log/"
                r"|\bhistory\b\s+-c\b"
                r"|\b(?:rm|shred)\b.*\.bash_history\b"), "log_clear"),

    (re.compile(r"\bvssadmin\b.*\b(?:delete|resize)\b"
                r"|\bwmic\b.*shadowcopy"
                r"|\bwbadmin\b.*\bdelete\b"
                r"|\bbcdedit\b.*recoveryenabled"
                r"|win32_shadowcopy"
                r"|\bdiskshadow\b"), "shadow_copy_delete"),

    (re.compile(r"^persist\b"
                r"|\bcrontab\b(?!\s+-l\b)"
                r"|\bsystemctl\b.*\benable\b"
                r"|\bschtasks\b.*/create\b"
                r"|\bat\b\s+(?:now\b|-|\d{1,2}:\d{2}\b|\d{1,2}(?:am|pm)\b"
                r"|midnight\b|noon\b|teatime\b)"
                r"|\bsystemd-run\b.*--on-"
                r"|\breg\s+add\b.*currentversion/?run"
                r"|\bsc\s+create\b"
                r"|\b(?:useradd|adduser)\b"
                r"|\bnet\s+user\b.*\s/add\b"
                r"|\blaunchctl\s+load\b"
                r"|authorized_keys\b"
                r"|/etc/rc\.local\b"
                r"|\.bashrc\b|\.zshrc\b|\.profile\b"), "persist"),

    (re.compile(r"\baireplay-ng\b.*(?:--deauth|\s-0\b)"
                r"|\bmdk[34]\b|\bbesside-ng\b|wifi\.deauth"), "deauth"),

    (re.compile(r"\bmsf(?:console|cli|venom)\b|\broutersploit\b"
                r"|\bnmap\b.*--script[= ]\S*(?:exploit|vuln|dos|brute)"
                r"|\bpython3?\b\s+\S*exploit\S*\.py\b"), "exploit_known_poc"),
]


# ── Drop-box lifelines ──
#
# Only consulted when the target is the drop-box itself (or when the caller
# did not say, which is treated as the drop-box). Mutating the bridge, the
# NAC bypass, the cover identity or the reverse tunnel strands the device;
# reading their state does not and is deliberately left alone.

_LIFELINE = re.compile(
    r"\bbrctl\s+(?:delif|delbr|addif|addbr|stp|setageing|hairpin)\b"
    r"|\bbridge\b.*\bfdb\s+flush\b"
    r"|\bip\s+link\s+(?:set|delete|del)\b.*\b(?:br0|eth1)\b"
    r"|\b(?:pkill|killall)\b.*\b(?:bridge_tap|nac_bypass|raccoon|python3?"
    r"|sshd|autossh|watchdog)\b"
    r"|\bkill\s+-\w+\s+-1\b"
    r"|\b(?:systemctl|service)\b(?=.*\braccoon\b)"
    r"(?=.*\b(?:stop|restart|disable|mask)\b)"
    r"|\b(?:systemctl|service)\b(?=.*\b(?:ssh|sshd|autossh)\b)"
    r"(?=.*\b(?:stop|restart|disable|mask)\b)"
    r"|/etc/init\.d/raccoon\S*\b.*\b(?:stop|restart)\b"
    r"|\b(?:rm|shred|mv|unlink)\b.*\b(?:raccoon|bridge_tap|nac_bypass)\b"
)


# ── Interface state and mode changes ──
#
# Context-dependent: harmless on an unrelated adapter, fatal on the one
# carrying the C2 channel. The interface name is handed to the caller's
# is_uplink_iface, and anything that callable cannot answer fails closed.

_IFACE_RULES = [
    re.compile(r"\biw\s+dev\s+(?P<if>\S+)\s+set\s+type\s+monitor\b"),
    re.compile(r"\biw\s+(?P<if>\S+)\s+set\s+monitor\b"),
    re.compile(r"\biwconfig\s+(?P<if>\S+)\s+mode\s+monitor\b"),
    re.compile(r"\bairmon-ng\s+(?:start|stop)\s+(?P<if>\S+)"),
    re.compile(r"\bip\s+(?:l|link)\s+set\s+(?:(?:-\S+|dev)\s+)*"
               r"(?P<if>[\w.:-]+)\s+(?:down|nomaster)\b"),
    re.compile(r"\bip\s+(?:l|link)\s+set\s+down\s+dev\s+(?P<if>[\w.:-]+)\b"),
    re.compile(r"\bip\s+(?:l|link)\s+(?:delete|del)\s+(?P<if>[\w.:-]+)\b"),
    re.compile(r"\bip\s+(?:a|addr|address)\s+(?:del|delete)\s+\S+\s+dev\s+"
               r"(?P<if>[\w.:-]+)\b"),
    re.compile(r"\bip\s+(?:a|addr|address)\s+flush\s+(?:dev\s+)?(?P<if>[\w.:-]+)\b"),
    re.compile(r"\bifconfig\s+(?:-\S+\s+)*(?P<if>[\w.:-]+)\s+(?:down|0\.0\.0\.0)\b"),
    re.compile(r"\bifdown\s+(?:-\S+\s+)*(?P<if>[\w.:-]+)\b"),
    re.compile(r"\bnmcli\s+dev(?:ice)?\s+disconnect\s+(?P<if>[\w.:-]+)\b"),
    re.compile(r"\bnmcli\s+dev(?:ice)?\s+set\s+(?P<if>[\w.:-]+)\s+managed\s+no\b"),
]

# ── Destructive filesystem operations ──
#
# Checked by walking the arguments rather than by regex. "Any argument is a
# root-level path" is not a thing a regex expresses well, and the first
# attempt here proved it: anchoring the pattern at end-of-string meant that
# `rm -rf /` was refused while `rm -rf / --no-preserve-root` — the spelling
# that actually works, because GNU rm declines the first — went through free.

_WIPE_TARGETS = frozenset((
    "/", "/*", "~", "~/", "/etc", "/usr", "/var", "/bin", "/sbin", "/boot",
    "/lib", "/lib64", "/home", "/root", "/srv", "/dev", "/proc", "/sys",
    "c:", "c:/", "c:/windows",
))
_WIPE_PROGRAMS = ("rm", "shred", "unlink", "srm", "wipe")


def _is_disk_wipe(effective):
    """True if any command on the line destroys a filesystem or raw device.

    Scans every position, not just the program, because a wipe reached
    through an introducer — `xargs rm -rf /`, `su alice -c rm -rf /` — is the
    same wipe. Checking only the program position was a regression the task
    review caught: it lost coverage the earlier whole-line regex happened to
    have.
    """
    tokens = effective.split()
    for index, token in enumerate(tokens):
        name = _basename(token).lower()
        if name.endswith(".exe"):
            name = name[:-4]
        arguments = tokens[index + 1:]
        if name.startswith("mkfs") or name == "wipefs":
            return True
        # Read-only invocations of the partitioning tools are recon the agent
        # legitimately needs; only their destructive subcommands count.
        if name == "fdisk" and not any(a in ("-l", "--list") for a in arguments):
            return True
        if name == "parted" and any(
                a in ("mklabel", "mkpart", "rm", "mkfs") for a in arguments):
            return True
        if name == "badblocks" and any(a == "-w" for a in arguments):
            return True
        if name == "dd":
            if any(a.startswith(("of=/dev/", "if=/dev/")) for a in arguments):
                return True
            continue
        if name not in _WIPE_PROGRAMS:
            continue
        for argument in arguments:
            if argument.startswith("-"):
                continue
            if argument in _WIPE_TARGETS or argument.rstrip("/") in _WIPE_TARGETS:
                return True
            if argument.startswith("/dev/"):
                return True
            # `rm -rf ~/*` and `rm -rf /.` are the same instruction.
            if re.match(r"^(?:~|/)[./*]*$", argument):
                return True
    return False


_MALFORMED = _row(TIER_HARD, "malformed", "input",
                  "command is not a string and cannot be classified")

_BEACON_HARD_VERBS = ("kill", "unpersist", "reconfig")
_SLEEP_LIMIT_SECONDS = 3600

# The two halves of _RULES are consulted at different points in classify, so
# that the tier-1-before-tier-2 ordering is structural rather than a property
# of where an entry happens to sit in one long list.
_RULES_HARD = [(p, k) for p, k in _RULES if RISK_TABLE[k].tier == TIER_HARD]
_RULES_KNOCK = [(p, k) for p, k in _RULES if RISK_TABLE[k].tier == TIER_KNOCK]
_EXPLOIT_RULE = next(p for p, k in _RULES if k == "exploit_known_poc")


# ── Classification ──


def _forms(command):
    """Both readings of an ambiguous backslash — see the _RULES comment."""
    stripped = _CONTROL.sub("", command)
    squashed = _normalise(stripped)
    pathed = _WHITESPACE.sub(
        " ", re.sub(r"[\"']", "", stripped.replace("\\", "/")).lower()).strip()
    return (squashed, pathed)


def _classify_sleep(effective):
    parts = effective.split()
    if len(parts) < 2:
        return RISK_TABLE["sleep_too_long"]
    try:
        seconds = float(parts[1])
    except ValueError:
        return RISK_TABLE["sleep_too_long"]
    # Written as a positive test so that nan and inf both fall through to the
    # refusal rather than comparing their way past it.
    if seconds < _SLEEP_LIMIT_SECONDS:
        return _FREE
    return RISK_TABLE["sleep_too_long"]


def _classify_iface(candidates, is_uplink_iface):
    names = set()
    for pattern in _IFACE_RULES:
        for text in candidates:
            for match in pattern.finditer(text):
                names.add(_basename(match.group("if")))
    if not names:
        return None
    row = RISK_TABLE["iface_change"]
    for name in sorted(names):
        try:
            carries_c2 = is_uplink_iface(name)
        except Exception:
            return row._replace(
                tier=TIER_HARD,
                reason="cannot establish which interface carries the C2 "
                       "channel; refusing rather than guessing")
        if carries_c2:
            return row._replace(
                tier=TIER_HARD,
                reason="would change '%s', the interface carrying the C2 "
                       "channel" % name)
    return row


def classify(command, target_kind, is_uplink_iface, phase5_enabled):
    """Sort a proposed command into one of the three tiers.

    target_kind is "beacon", "dropbox" or "server". Anything else is treated
    as the drop-box, which is the strictest reading — an unrecognised target
    must not quietly lose the lifeline protections.

    The order of the checks below is the ordering guarantee: everything that
    can refuse outright is consulted before anything that can merely gate,
    so a line carrying both reaches the refusal.
    """
    if not isinstance(command, str):
        return _MALFORMED

    forms = _forms(command)
    effective = tuple(_effective(form) for form in forms)
    candidates = forms + effective

    program = _program(effective[0])
    first_token = program

    if first_token in _BEACON_HARD_VERBS:
        return RISK_TABLE["beacon_control"]
    if first_token == "sleep":
        return _classify_sleep(effective[0])

    if any(_is_disk_wipe(text) for text in effective):
        return RISK_TABLE["disk_wipe"]

    if target_kind not in ("beacon", "server"):
        if any(_LIFELINE.search(text) for text in candidates):
            return RISK_TABLE["dropbox_lifeline"]

    # A verb in a reader's argument list is a string, not an instruction.
    # Readers cannot wipe, cannot touch a lifeline and cannot change an
    # interface, so this check sits after those three. It applies only to a
    # single command: once the line carries a separator, the first token no
    # longer speaks for the rest of it.
    if program in _READERS and not has_shell_metachars(command):
        return _FREE

    for pattern, key in _RULES_HARD:
        if any(pattern.search(text) for text in candidates):
            return RISK_TABLE[key]

    # Promotion is checked before the interface verdict as well as before the
    # tier-2 scan, so that nothing which can merely gate pre-empts a refusal.
    if not phase5_enabled and any(_EXPLOIT_RULE.search(t) for t in candidates):
        return RISK_TABLE["exploit_known_poc"]._replace(
            tier=TIER_HARD,
            reason="the exploitation phase is switched off for this run")

    verdict = _classify_iface(candidates, is_uplink_iface)
    if verdict is not None:
        return verdict

    for pattern, key in _RULES_KNOCK:
        if not any(pattern.search(text) for text in candidates):
            continue
        row = RISK_TABLE.get(key)
        if row is None:
            return _row(TIER_KNOCK, key, "unknown",
                        "gated action with no risk-table row; treated "
                        "conservatively", *_UNKNOWN_KNOCK)
        return row

    # A rule added at runtime lands in neither half, since both are frozen at
    # import. Scan for those rather than silently ignoring them.
    known = set(id(p) for p, _ in _RULES_HARD) | set(id(p) for p, _ in _RULES_KNOCK)
    for pattern, key in _RULES:
        if id(pattern) in known:
            continue
        if not any(pattern.search(t) for t in candidates):
            continue
        row = RISK_TABLE.get(key)
        if row is not None:
            return row
        return _row(TIER_KNOCK, key, "unknown",
                    "gated action with no risk-table row; treated "
                    "conservatively", *_UNKNOWN_KNOCK)

    return _FREE


# ── Scan rate limits ──
#
# Applied after classification, and applied regardless of what the model
# asked for. Aggressive scanning can take consumer switches down, and a
# disrupted network is both an engagement failure and a detection event.

_SCANNER_LIMITS = {
    "nmap": {
        # The `=`-joined spellings carry their value in the same token; the
        # bare spellings take the next token with them. Keeping the two
        # groups disjoint matters — a pattern that matches both swallows the
        # flag and leaves the value behind as a stray argument.
        "strip": (
            re.compile(r"^-t\d$"),
            re.compile(r"^-t(?:insane|aggressive|normal|polite|sneaky|paranoid)$"),
            re.compile(r"^--(?:max|min)-rate="),
            re.compile(r"^--(?:max|min)-parallelism="),
            re.compile(r"^--(?:max|min)-hostgroup="),
            re.compile(r"^--timing="),
        ),
        "strip_with_value": (
            re.compile(r"^-t$"),
            re.compile(r"^--timing$"),
            re.compile(r"^--(?:max|min)-rate$"),
            re.compile(r"^--(?:max|min)-parallelism$"),
            re.compile(r"^--(?:max|min)-hostgroup$"),
        ),
        "inject": ("-T2", "--max-rate", "50"),
    },
    "masscan": {
        "strip": (re.compile(r"^--(?:max-)?rate="),),
        "strip_with_value": (re.compile(r"^--(?:max-)?rate$"),),
        "inject": ("--rate", "50"),
    },
    "netdiscover": {
        "strip": (re.compile(r"^-c\d+$"),),
        "strip_with_value": (re.compile(r"^-c$"),),
        "inject": ("-c", "1"),
    },
}


def _scanner_of(token):
    name = _basename(token).lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name if name in _SCANNER_LIMITS else None


def enforce_scan_limits(command):
    """Rewrite a scanning command to gentle timing. Idempotent.

    Only fires when the scanner is in command position — possibly behind
    privilege or wrapper prefixes — so that `man nmap` and
    `grep nmap /etc/services` are left alone.
    """
    if not isinstance(command, str):
        return command

    tokens = command.split()
    index = None
    position = 0
    while position < len(tokens):
        token = tokens[position]
        name = _basename(token).lower()
        if name.endswith(".exe"):
            name = name[:-4]
        if name in _SCANNER_LIMITS:
            index = position
            break
        # Only wrappers, the beacon verb and their own arguments may precede
        # the scanner. A separately-given option value is skipped too, so
        # `timeout -s KILL 600 nmap …` still gets limited.
        if name in ("shell", "sudo", "doas", "runas", "pkexec") \
                or name in _WRAPPERS:
            position += 1
            consumed = _skip_wrapper_arguments(tokens[position:], name)
            position = len(tokens) - len(consumed)
            continue
        if token.startswith("-") or re.match(r"^\d+(?:\.\d+)?[smhd]?$", token) \
                or re.match(r"^\w+=", token):
            position += 1
            continue
        return command
    if index is None:
        return command

    limits = _SCANNER_LIMITS[_scanner_of(tokens[index])]
    head = tokens[:index + 1]
    rest = []
    skip_next = False
    for token in tokens[index + 1:]:
        if skip_next:
            skip_next = False
            continue
        lowered = token.lower()
        if any(p.match(lowered) for p in limits["strip"]):
            continue
        if any(p.match(lowered) for p in limits["strip_with_value"]):
            skip_next = True
            continue
        rest.append(token)

    return " ".join(head + list(limits["inject"]) + rest)


# ── Stored scripts ──


def validate_script(code, language):
    """Check a stored script line by line. Returns a message, or None if clean.

    Scripts are checked in the strictest context available: drop-box target,
    every interface assumed to carry the C2 channel, exploitation disabled.
    A stored script has no caller to supply context, and the reference
    implementation this project is modelled on let scripts bypass the safety
    layer entirely — which made the whole leash removable in three lines.
    """
    if not isinstance(code, str):
        return "script is not a string"

    normalised = code.replace("\r\n", "\n").replace("\r", "\n")
    for number, raw in enumerate(normalised.split("\n"), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if has_shell_metachars(line):
            return "line %d: shell metacharacters are not permitted" % number
        verdict = classify(line, target_kind="dropbox",
                           is_uplink_iface=lambda name: True,
                           phase5_enabled=False)
        if verdict.tier != TIER_FREE:
            return "line %d: %s" % (number, verdict.reason or verdict.action_key)
    return None


