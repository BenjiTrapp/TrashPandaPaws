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

import bisect
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
             "ionice", "busybox", "command", "time", "xargs", "watch")

# Commands that read rather than act. A verb appearing as their argument is
# a string, not an instruction: `grep reboot /var/log/syslog` must not be
# refused, or the agent cannot read its own logs.
_READERS = ("grep", "egrep", "fgrep", "rgrep", "man", "cat", "less", "more",
            "tail", "head", "ls", "echo", "file", "stat", "wc", "strings",
            "nl", "od", "dirname", "basename", "realpath")

# Readers only while they are not asked to act. Deleting them outright, as
# an earlier attempt did, turned `sed -n /reboot/p /var/log/syslog` and
# `find /tmp -name reboot` into hard refusals.
#
# Stored as regexes rather than flag names because a flag-cluster match on
# its own is not precise enough: lowercasing turns awk's `-F:` field
# separator into `-f:`, which a prefix match reads as awk's script flag and
# escalates a log grep to a refusal. A flag whose value is attached must not
# match, so those entries are anchored with $.
_CONDITIONAL_READERS = {
    "find": (r"^-exec(?:dir)?$", r"^-delete$", r"^-ok$", r"^-fprint", r"^-fls"),
    # `-f` may carry its value attached, so the anchor admits a path start
    # but not `-F:`, which is awk's field separator after lowercasing.
    "sed": (r"^-[a-z]*i", r"^--in-place", r"^-[a-z]*f(?:$|[/.~])",
            r"^--file", r"^-[a-z]*e(?:$|\s)"),
    "awk": (r"^-[a-z]*f(?:$|[/.~])", r"^--file", r"^-i$", r"^inplace"),
    "xxd": (r"^-[a-z]*r(?:$|[/.~])", r"^--revert"),
}

# Anything that can put a nested command in argument position.
_COMMAND_INTRODUCERS = _WRAPPERS + (
    "su", "sudo", "doas", "runas", "pkexec", "sh", "bash", "zsh", "dash",
    "shell", "cmd", "powershell", "pwsh")


def _is_reader(program, tokens):
    """True if the program only reads, given how it was invoked."""
    if program in _READERS:
        return True
    acting = _CONDITIONAL_READERS.get(program)
    if acting is None:
        return False
    for token in tokens:
        for pattern in acting:
            if re.match(pattern, token):
                return False
    return True


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
_PRIVILEGE_VALUE_FLAGS = ("-u", "-U", "--user", "-g", "--group")

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
    "sudo": _PRIVILEGE_VALUE_FLAGS,
    "doas": _PRIVILEGE_VALUE_FLAGS,
    "runas": _PRIVILEGE_VALUE_FLAGS,
}


def _wrapper_argument_count(tokens, start, wrapper):
    """How many of a wrapper's own arguments follow, counted without slicing."""
    value_flags = _WRAPPER_VALUE_FLAGS.get(wrapper, ())
    index = start
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("-"):
            index += 1
            if index < len(tokens) and token in value_flags:
                index += 1
            continue
        if re.match(r"^\d+(?:\.\d+)?[smhd]?$", token) or re.match(r"^\w+=", token):
            index += 1
            continue
        break
    return index - start


def _skip_wrapper_arguments(tokens, wrapper=""):
    """Drop a wrapper's own arguments, including values given separately.

    `timeout -s TERM 30 cmd` has to reduce to `cmd`. The first attempt at
    this skipped the flag but not its value, which left `term` in program
    position — hiding the real command and making a signal name look like one.
    """
    return list(tokens[_wrapper_argument_count(tokens, 0, wrapper):])


def _strip_wrappers(text):
    """Drop leading wrappers that put the real program in argument position.

    Works on one token list with an advancing index. Re-joining the string at
    every wrapper made this quadratic: 20k chained introducers took 21
    seconds, which would stall a campaign on one malformed command.
    """
    tokens = text.split()
    index = 0
    while index < len(tokens):
        wrapper = _basename(tokens[index]).lower()
        if wrapper not in _WRAPPERS:
            break
        index += 1 + _wrapper_argument_count(tokens, index + 1, wrapper)
    return " ".join(tokens[index:])


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
    # The adjudication that ends five rounds of enumeration: a program this
    # module does not recognise, pointing a write at storage, is a question
    # for the operator rather than a refusal. An allowlist of read-only tools
    # can never be complete — sg_inq, dmsetup, mountpoint, e2label were all
    # missing — and at tier 1 every omission is an unoverridable refusal of
    # ordinary recon. At tier 2 an omission costs one approval click, so the
    # list's incompleteness stops being a correctness problem.
    "device_write_unknown": _row(
        TIER_KNOCK, "device_write_unknown", "destructive",
        "an unrecognised program is pointing a write at storage",
        points=0, p_success=0.8, p_detect=0.3),
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
                r"|\bnft\b(?=.*\b(?:add|insert|replace|create)\b)"
                r"(?=.*\b(?:drop|reject)\b)"
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
                r"|\bcoercer\b|\bpetitpotam(?:\.py)?\b|-m\s+coerce"
                r"|\b(?:impacket-)?(?:psexec|wmiexec|smbexec|atexec|dcomexec)"
                r"(?:\.py)?\b"
                r"|\bevil-winrm\b"), "ntlm_relay"),

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
                r"|\breg(?:\.exe)?\s+add\b.*currentversion/?run"
                r"|\bsc(?:\.exe)?\s+create\b"
                r"|\b(?:useradd|adduser)\b"
                r"|\bnet\s+user\b.*\s/add\b"
                r"|\bnet\s+localgroup\b.*\s/add\b"
                r"|\blaunchctl\s+load\b"
                r"|authorized_keys\b"
                r"|/etc/rc\.local\b"
                r"|\.bashrc\b|\.zshrc\b|\.profile\b"), "persist"),

    (re.compile(r"\baireplay-ng\b.*(?:--deauth|\s-0\b)"
                r"|\bmdk[34]\b|\bbesside-ng\b|wifi\.deauth"), "deauth"),

    (re.compile(r"\bmsf(?:console|cli|venom)\b|\broutersploit\b"
                r"|\bnmap\b.*--script[= ]\S*(?:exploit|vuln|dos|brute)"
                r"|\bpython3?\b\s+\S*exploit\S*\.py\b"
                r"|\bsqlmap\b"), "exploit_known_poc"),
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

# The destructive direction is decided by a broad predicate, and read-only
# work is exempted by name. Five rounds of this module oscillated between a
# broad premise that over-matched (mount, lsblk, smartctl refused at a tier
# with no override) and a narrow program list that under-matched (cryptsetup
# luksFormat, blkdiscard, sgdisk -Z, mke2fs, nvme format all free). Neither
# direction works alone, so both are here: anything not a reader and not a
# listed inspector that names storage is writing to it.
_DEVICE_INSPECTORS = {
    # program: markers that make this invocation destructive. An empty tuple
    # means the program never writes a device, so it is always exempt.
    #
    # Expressed as destructive markers rather than read-only ones, because
    # the read-only form was any-flag: `hdparm -I --security-erase /dev/sda`
    # matched the read flag and exempted the whole line. A destructive marker
    # cannot be defeated by adding a harmless flag next to it.
    "mount": (), "umount": (), "lsblk": (), "blkid": (), "findmnt": (),
    "df": (), "du": (), "lsof": (), "fuser": (), "udevadm": (), "partx": (),
    "dumpe2fs": (), "smartctl": (), "mountpoint": (), "sg_inq": (),
    "pvs": (), "vgs": (), "lvs": (),
    "pvdisplay": (), "vgdisplay": (), "lvdisplay": (),
    "sha1sum": (), "sha256sum": (), "sha512sum": (), "md5sum": (),
    "cmp": (), "hexdump": (), "bcache-super-show": (),
    "fsck": ("-y", "--yes", "-a", "-p"),
    "e2fsck": ("-y", "--yes", "-a", "-p", "-f"),
    "tune2fs": ("-l1", "-u", "-c", "-i", "-m", "-r", "-o", "-e", "-j", "-o"),
    "hdparm": ("--security-erase", "--security-erase-enhanced",
               "--trim-sector-ranges", "--make-bad-sector", "--write-sector",
               "--dco-restore", "--security-set-pass"),
    "nvme": ("format", "sanitize", "write", "write-zeroes", "delete-ns",
             "create-ns"),
    "cryptsetup": ("luksformat", "reencrypt", "erase", "lukserase",
                   "luksaddkey", "luksremovekey", "lukskillslot",
                   "luksconvertkey", "luksheaderrestore"),
    "sgdisk": ("-z", "--zap-all", "-o", "--clear", "-n", "--new", "-d",
               "--delete", "-t", "--typecode", "-g", "--mbrtogpt"),
    "mdadm": ("--zero-superblock", "--create", "-c", "--add", "--fail",
              "--remove", "--grow"),
    "dmsetup": ("create", "remove", "load", "reload", "wipe_table", "clear"),
    "e2label": ("--",),
    "fsfreeze": (),
}

# tune2fs's read-only flag is -l; every other flag it has changes something.
# Listing the destructive ones individually is error-prone for that binary,
# so it is special-cased below rather than by marker.
_TUNE2FS_READ_ONLY = ("-l", "--list")

# Programs whose last argument is the destination. `cp /dev/sda /tmp/img` is
# imaging; `cp /tmp/img /dev/sda` overwrites the disk.
# dcfldd is deliberately absent: it spells its destination `of=`, like
# dd, so the generic `=`-aware branch handles it.
_DESTINATION_LAST = ("cp", "install", "rsync", "mv")

# Programs whose write to storage is unambiguously destruction. Anything
# outside this set that writes storage earns a knock instead — see the
# device_write_unknown row.
_KNOWN_DESTROYERS = (
    "tee", "xxd", "shred", "wipe", "srm", "cpio", "cat", "cp",
    "install", "rsync", "mv", "dcfldd", "cryptsetup", "sgdisk", "sfdisk",
    "cfdisk", "gdisk", "mdadm", "pvcreate", "vgcreate", "lvcreate",
    "lvremove", "vgremove", "pvremove", "nvme", "hdparm", "debugfs",
    "blkdiscard", "fdisk", "parted", "dd", "perl", "python", "python3",
)


def _is_storage_device(path):
    if not path.startswith("/dev/"):
        return False
    head = path[5:].split("/", 1)[0]
    return head not in _SAFE_PSEUDO_DEVICES \
        and head.rstrip("0123456789") not in _SAFE_PSEUDO_DEVICES

# Pseudo-paths under /dev/ that are not storage. tmpfs at /dev/shm is the
# framework's own staging area and must stay writable.
_SAFE_PSEUDO_DEVICES = frozenset((
    "null", "zero", "random", "urandom", "full", "tty", "stdin", "stdout",
    "stderr", "console", "ptmx", "fd", "shm", "pts", "net", "input", "snd",
    "char", "bus", "cpu", "mem", "kmsg", "log", "dri", "hugepages", "mqueue",
))


def _is_device_inspector(program, arguments):
    """True if this invocation of a dual-purpose tool is only reading."""
    if program not in _DEVICE_INSPECTORS:
        return False
    if program == "tune2fs":
        flags = [a for a in arguments if a.startswith("-")]
        return bool(flags) and all(a in _TUNE2FS_READ_ONLY for a in flags)
    destructive = _DEVICE_INSPECTORS[program]
    lowered = [a.lower() for a in arguments]
    # Exempt unless a destructive marker is present anywhere. The reverse —
    # exempt if a read-only marker is present — let `hdparm -I
    # --security-erase` through on the strength of the harmless flag.
    return not any(marker in lowered or any(a.startswith(marker) for a in lowered)
                   for marker in destructive)


def _operands(arguments):
    """Bare operands: not flags, not redirects, not KEY=value."""
    return [a for a in arguments
            if not a.startswith(("-", ">", "<", "&", "|", "2>"))
            and "=" not in a.split("/", 1)[0]]


def _writes_storage(program, arguments):
    """True if this invocation points a write at storage."""
    if program in _DESTINATION_LAST:
        # Every operand after the first is a destination. Taking only the
        # final bare token meant any trailing flag or redirect hid it:
        # `cp /tmp/img /dev/sda -v` and `… >/dev/null` were both free.
        return any(_is_storage_device(a) for a in _operands(arguments)[1:])
    for argument in arguments:
        if _is_storage_device(argument):
            return True
        # `of=/dev/sda`, as dd and dcfldd spell it.
        if "=" in argument and _is_storage_device(argument.split("=", 1)[1]):
            return True
    return False


def _command_positions(tokens):
    """Indices where a token is a program rather than an argument.

    Three attempts converged here. Index 0 only missed `xargs rm -rf /`;
    every token turned `man fdisk` into a hard refusal; and seeding only from
    index 0 missed `ls ; rm -rf /`, because a separator introduces a command
    just as surely as `-c` does. One worklist, and introducers are re-checked
    at every position it pops — the earlier two-loop split meant a nested
    introducer like `su alice -c xargs rm -rf /` was never expanded.
    """
    separators = (";", "&&", "||", "|", "&", ";;", "|&")
    # `-c` only introduces a command after a shell-like program. Seeding it
    # unconditionally made `grep -c "rm -rf /" log` and `sort -c rm -rf /`
    # plant a command position inside argument text.
    shell_like = ("sh", "bash", "zsh", "dash", "ksh", "su", "cmd", "powershell",
                  "pwsh", "ssh", "doas", "sudo", "runuser")

    # One prefix pass: whether a shell-like program has been seen before
    # each index. Scanning the prefix per `-c` token was quadratic — 8k of
    # them took 11 seconds.
    shell_before = [False] * (len(tokens) + 1)
    for index, token in enumerate(tokens):
        shell_before[index + 1] = (
            shell_before[index] or _basename(token).lower() in shell_like)

    pending = [0]
    for index, token in enumerate(tokens):
        if token in separators:
            pending.append(index + 1)
        elif token.endswith(";") and len(token) > 1:
            pending.append(index + 1)
        elif token in ("-exec", "-execdir", "/c", "/k"):
            # `--` is deliberately absent: it marks the end of options, not
            # the start of a command. Treating it as one bounded the real
            # command's arguments and let `rm -rf -- /` through free.
            pending.append(index + 1)
        elif token == "-c" and index > 0:
            # Only a shell-like program's -c introduces a command. Seeding it
            # unconditionally made `grep -c "rm -rf /" log` plant a command
            # position inside argument text. The lookback scans the whole
            # prefix because `su alice -c …` puts a username in between.
            if shell_before[index]:
                pending.append(index + 1)

    positions = set()
    while pending:
        index = pending.pop()
        if index >= len(tokens) or index in positions:
            continue
        # A flag is never a program. `grep -- -la /dev/sda` used to plant
        # `-la` as one and refuse the line.
        if tokens[index].startswith("-"):
            continue
        positions.add(index)
        name = _basename(tokens[index]).lower()
        if name.endswith(".exe"):
            name = name[:-4]
        if name in _COMMAND_INTRODUCERS:
            # Index arithmetic rather than slicing: slicing the tail at every
            # introducer made this quadratic, and 20k chained introducers
            # took seconds.
            pending.append(index + 1 + _wrapper_argument_count(
                tokens, index + 1, name))
    return positions


def _disk_verdict(effective):
    """Which disk-related key this line earns, or None.

    Returns "disk_wipe" for a recognised destructive operation and
    "device_write_unknown" for an unrecognised program pointing a write at
    storage — see the RISK_TABLE comment for why those are different tiers.
    """
    tokens = re.sub(r"([;|&])", r" \1 ", effective).split()
    positions = sorted(_command_positions(tokens))
    if not positions:
        return None

    boundaries = set(positions)
    for index, token in enumerate(tokens):
        if token in (";", "&&", "||", "|", "&", ";;", "|&"):
            boundaries.add(index)
    ordered_boundaries = sorted(boundaries)

    unknown_write = False
    for index in positions:
        cut = bisect.bisect_right(ordered_boundaries, index)
        end = ordered_boundaries[cut] if cut < len(ordered_boundaries) else len(tokens)
        name = _basename(tokens[index]).lower()
        if name.endswith(".exe"):
            name = name[:-4]
        arguments = tokens[index + 1:end]
        if (name.startswith("mkfs") or name in ("wipefs", "mke2fs", "mkdosfs",
                                                "mkswap", "mkntfs", "blkdiscard")) \
                and any(_is_storage_device(a) for a in arguments) \
                and not any(a in ("-n", "--no-act", "-l", "--list")
                            for a in arguments):
            return "disk_wipe"
        # Programs with their own destructive/read-only distinction are
        # decided here and here only — falling through to the generic
        # block-device rule below would refuse `fdisk -lu /dev/sda`, which
        # is recon.
        if name == "fdisk":
            if not any(re.match(r"^(?:-[a-z]*l|--list)", a) for a in arguments):
                return "disk_wipe"
            continue
        if name == "parted":
            # Interactive parted on a device can destroy it, so the test is
            # for a read-only subcommand rather than for a destructive one.
            if any(_is_storage_device(a) for a in arguments) and not any(
                    a in ("print", "p", "unit", "version", "help", "select")
                    for a in arguments):
                return "disk_wipe"
            continue
        if name == "badblocks":
            if any(re.match(r"^-[a-z]*w", a) for a in arguments):
                return "disk_wipe"
            continue
        if name == "dd":
            # Destructive when it writes to storage. Reading a device into a
            # file is imaging; writing /dev/null or /dev/zero is nothing.
            for argument in arguments:
                if argument.startswith("of=") \
                        and _is_storage_device(argument[3:]):
                    return "disk_wipe"
            continue
        # Broad predicate plus explicit exemptions: anything that is neither
        # a reader nor a listed device inspector, pointing a write at
        # storage, is touching a disk. A recognised destroyer is refused; an
        # unrecognised program only earns a knock, so that an incomplete
        # inspector list costs an approval rather than a hard refusal.
        if not _is_reader(name, arguments) \
                and not _is_device_inspector(name, arguments) \
                and _writes_storage(name, arguments):
            if name in _KNOWN_DESTROYERS:
                return "disk_wipe"
            unknown_write = True
        if name not in _WIPE_PROGRAMS:
            continue
        for argument in arguments:
            if argument.startswith("-"):
                continue
            if argument in _WIPE_TARGETS or argument.rstrip("/") in _WIPE_TARGETS:
                return "disk_wipe"
            if argument.startswith("/dev/"):
                return "disk_wipe"
            # `rm -rf ~/*` and `rm -rf /.` are the same instruction.
            if re.match(r"^(?:~|/)[./*]*$", argument):
                return "disk_wipe"
    return "device_write_unknown" if unknown_write else None


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

    # Checked against both the raw and the effective form: the raw form still
    # carries the privilege prefix, and `su alice -c rm -rf /` needs `su` to
    # be visible for the -c lookback to fire. A refusal outranks a knock.
    disk_keys = set()
    for text in candidates:
        key = _disk_verdict(text)
        if key:
            disk_keys.add(key)
    if "disk_wipe" in disk_keys:
        return RISK_TABLE["disk_wipe"]

    if target_kind not in ("beacon", "server"):
        if any(_LIFELINE.search(text) for text in candidates):
            return RISK_TABLE["dropbox_lifeline"]

    # A verb in a reader's argument list is a string, not an instruction.
    # Readers cannot wipe, cannot touch a lifeline and cannot change an
    # interface, so this check sits after those three. It applies only to a
    # single command: once the line carries a separator, the first token no
    # longer speaks for the rest of it.
    if _is_reader(program, effective[0].split()[1:]) \
            and not has_shell_metachars(command):
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

    # Rules appended at runtime land in neither frozen half. Their tier-1
    # entries are consulted here, before the frozen tier-2 scan, so the
    # ordering guarantee holds for them too — deferred three rounds, closed
    # now because "only the suite does this" is a reason to keep it cheap,
    # not a reason to leave the ordering wrong.
    frozen = set(id(p) for p, _ in _RULES_HARD) | set(id(p) for p, _ in _RULES_KNOCK)
    runtime = [(p, k) for p, k in _RULES if id(p) not in frozen]

    for pattern, key in runtime:
        row = RISK_TABLE.get(key)
        if row is None or row.tier != TIER_HARD:
            continue
        if any(pattern.search(text) for text in candidates):
            return row

    if "device_write_unknown" in disk_keys:
        return RISK_TABLE["device_write_unknown"]

    for pattern, key in _RULES_KNOCK:
        if not any(pattern.search(text) for text in candidates):
            continue
        row = RISK_TABLE.get(key)
        if row is None:
            return _row(TIER_KNOCK, key, "unknown",
                        "gated action with no risk-table row; treated "
                        "conservatively", *_UNKNOWN_KNOCK)
        return row

    for pattern, key in runtime:
        if not any(pattern.search(text) for text in candidates):
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


# Python punctuation is syntax, not shell, so the metacharacter screen cannot
# apply. What matters is a line that reaches back out to a shell, and those
# are refused by name. This is a screen for the obvious spellings, not a
# sandbox: an aliased import gets past it.
_PYTHON_SHELL_ESCAPES = re.compile(
    r"subprocess"
    r"|\bos\s*\.\s*(?:system|popen|exec)"
    r"|\b(?:eval|exec)\s*\("
    r"|__import__"
    r"|\bpty\s*\.\s*spawn"
    r"|\bcommands\s*\.\s*getoutput")


def validate_script(code, language):
    """Check a stored script line by line. Returns a message, or None if clean.

    Scripts are checked in the strictest context available: drop-box target,
    every interface assumed to carry the C2 channel, exploitation disabled.
    A stored script has no caller to supply context, and the reference
    implementation this project is modelled on let scripts bypass the safety
    layer entirely — which made the whole leash removable in three lines.

    A python script is screened for shell-escape constructs instead of being
    classified as shell commands. Any other language, recognised or not, takes
    the strict shell path.
    """
    if not isinstance(code, str):
        return "script is not a string"

    is_python = language == "python"
    normalised = code.replace("\r\n", "\n").replace("\r", "\n")
    for number, raw in enumerate(normalised.split("\n"), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if is_python:
            escape = _PYTHON_SHELL_ESCAPES.search(line)
            if escape:
                return "line %d: shell escape '%s' is not permitted in a python " \
                       "script" % (number, re.sub(r"\s+", "", escape.group(0)))
            continue
        if has_shell_metachars(line):
            return "line %d: shell metacharacters are not permitted" % number
        verdict = classify(line, target_kind="dropbox",
                           is_uplink_iface=lambda name: True,
                           phase5_enabled=False)
        if verdict.tier != TIER_FREE:
            return "line %d: %s" % (number, verdict.reason or verdict.action_key)
    return None


