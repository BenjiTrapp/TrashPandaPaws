#!/usr/bin/env python3
"""The preambles: what each role is told about its situation.

Two roles, two preambles. The orchestrator's is long because it plans against
everything the run is: the beacons and what they can do, the scoring, how the
approval gate decides, the scan limits, the scope, what is refused outright,
and which phases it may work in. The executor's is short: one task, its tools,
a ban on widening the scope, and a fixed report.

Three rules shape what is written, and each exists because the opposite
teaches the model something false:

  * A phase that is not enabled is not mentioned at all. A model told about a
    locked phase plans towards it and walks into the wall.
  * The tier lists are generated from safety.RISK_TABLE and not typed out
    here. The table is the single source of truth for what is refused and what
    knocks, it has changed more than once, and a preamble that disagrees with
    the classifier is wrong in a way the model cannot detect.
  * The scan flags are read back from safety.enforce_scan_limits, for the same
    reason.

`scope` is anything with `scope_allow` and `scope_deny` lists, which is what a
CampaignConfig is; `phases` is the set of phase numbers the run enables.

Usage:
    p = prompts.orchestrator(caps_by_beacon, campaign_cfg, campaign_cfg.phases,
                             tier)
    p = prompts.executor(caps, campaign_cfg, tier)
"""

import re

from software.agent import safety
from software.agent.executor import beacon as beacon_exec
from software.agent.tools import registry, scoring

# ── Capabilities ──

# Spec §7.3, plus "dropbox", which the router reads. Only a capability a beacon
# actually reports is explained, so a run with no sniffer never hears of one.
_CAPABILITY_MEANING = {
    "batch": "accepts several tasks in one check-in",
    "sniffer": "a bridge tap is running, so there are packet captures to read",
    "wifi:scan": "has a wireless interface that can scan",
    "wifi:monitor": "has an adapter that can monitor and inject",
    "smbloot": "has a built-in SMB client",
    "windows": "runs Windows",
    "posix": "runs a POSIX system",
    "dropbox": "is the drop-box itself: its bridge, NAC bypass, cover identity "
               "and tunnel are off limits",
}


def _meaning_lines(caps):
    return ["- %s: %s" % (c, _CAPABILITY_MEANING[c])
            for c in sorted(set(caps)) if c in _CAPABILITY_MEANING]


def _platform_name(reported) -> str:
    """The OS string a beacon reported, or "" if it reported nothing.

    Self-reported, like the capability list the router already acts on, so
    it is trusted no further than that: it tells the model which family of
    commands to reach for, and a command that is wrong anyway still comes
    back as an error it can read.
    """
    return str(reported).strip() if reported else ""


def capability_section(caps_by_beacon, os_by_beacon=None) -> str:
    if not caps_by_beacon:
        return "No beacon is attached to this campaign."
    os_by_beacon = os_by_beacon or {}
    lines = ["Target beacons and what each can do:"]
    seen = set()
    for beacon in sorted(caps_by_beacon):
        caps = list(caps_by_beacon[beacon] or [])
        seen.update(caps)
        # The platform goes next to the capabilities because `posix` only
        # separates Windows from the rest, leaving Linux and macOS
        # indistinguishable -- and that is the difference that decides
        # whether /proc exists. A beacon that reported no OS is left
        # without one rather than given a default.
        platform = _platform_name(os_by_beacon.get(beacon))
        lines.append("- %s%s: %s" % (
            beacon, " (%s)" % platform if platform else "",
            ", ".join(caps) or "no capabilities reported"))
    meanings = _meaning_lines(seen)
    if meanings:
        lines.append("")
        lines.append("What these mean:")
        lines.extend(meanings)
    lines.append("")
    lines.append("Plan against these capabilities. A tool or command that "
                 "needs one a beacon does not have will not work on it.")
    return "\n".join(lines)


# ── Tools ──


def _first_sentence(text):
    return re.split(r"(?<=\.)\s", text.strip(), maxsplit=1)[0]


def _tool_section(role, caps, tier, heading):
    lines = [heading]
    for spec in registry.specs(role, caps, tier):
        lines.append("- %s: %s" % (spec.name, _first_sentence(spec.description)))
    return "\n".join(lines)


# ── Scoring ──


def _score_section():
    lines = ["Scoring. Call log_score as outcomes happen; the points are fixed "
             "by this table:"]
    for action, points in scoring.SCORE_ACTIONS.items():
        lines.append("- %s: %+d" % (action, points))
    lines.append("A detection costs 100 points, and every detection makes "
                 "each later gated action harder to approve. Report one with "
                 "log_score as soon as you see it.")
    return "\n".join(lines)


# ── Approval and expected value ──


def _ev_section(phases):
    lines = [
        "Approval and expected value. Some actions are gated (listed below). "
        "When the operator is not watching, an expected-value check decides: "
        "EV = value of the outcome x P(success) - R x P(detection), and the "
        "action runs only if EV is above the run's threshold. The numbers "
        "behind it are built in. An executor may pass a p_success_estimate with a "
        "command; it is advisory and held to a narrow band around the "
        "built-in estimate, so it will not rescue an action the check has "
        "priced as too risky.",
        "",
        "CVSS guidance for planning, not an input to the gate:",
        "- 9.0 to 10.0, CRITICAL: look at first",
        "- 7.0 to 8.9, HIGH: look at once the critical ones are done",
        "- 4.0 to 6.9, MEDIUM: record it, and come back when time allows",
        "- below 4.0, LOW: record it only",
        "A high score is a reason to look closer, not to act. Confirm the "
        "version before relying on it.",
    ]
    if 5 in phases:
        lines.append("A critical or high CVE with a public exploit is what "
                     "Phase 5 plans around. Say so in the task, and have the "
                     "executor pass its own p_success_estimate.")
    return "\n".join(lines)


# ── Scan limits ──


def _forced_flags(program):
    """The flags enforce_scan_limits puts on `program`, read back from it."""
    probe = "192.0.2.1"
    tokens = safety.enforce_scan_limits("%s %s" % (program, probe)).split()
    return " ".join(tokens[1:-1])


def _scan_section():
    # The duration is stated because the rate limit turns a port range into
    # one. Prose alone was tried first and did not work: the model asked for
    # `-p-` in two separate live runs after being told it would not finish,
    # so the limiter now narrows the request and this says what it does.
    # Both numbers are read back from the code that enforces them.
    from software.agent.executor import server_tool
    nmap_timeout = server_tool._TOOL_TIMEOUTS["nmap"]
    return "\n".join([
        "Scan rate limits. These are applied to every scan whether you ask or "
        "not, and asking for faster has no effect:",
        "- nmap: %s" % _forced_flags("nmap"),
        "- masscan: %s" % _forced_flags("masscan"),
        "- netdiscover: %s" % _forced_flags("netdiscover"),
        "Scan hosts one at a time rather than running service detection "
        "across a whole /24 in one command.",
        "Ports. At this rate all 65535 ports would take about 20 minutes and "
        "would not finish inside the %d-second limit nmap runs under, so a "
        "request for all of them (-p-, or a range that wide) is narrowed to "
        "nmap's %d most common ports. The result carries "
        "effective_command, which is what actually ran — report that and "
        "not what you asked for. To scan something outside that set, name "
        "the ports. Leave the timeout alone unless you have a reason: each "
        "program has a built-in limit chosen for it."
        % (nmap_timeout, safety.SCAN_TOP_PORTS),
    ])


# ── Scope ──


def _scope_section(scope, for_executor):
    allow = list(scope.scope_allow)
    deny = list(scope.scope_deny)
    lines = ["Authorised scope. Allowed: %s." % ", ".join(allow)]
    if deny:
        lines.append("Never target: %s." % ", ".join(deny))
    lines.append(
        "A target outside the allowed ranges, or inside a denied one, is "
        "refused, and so is any target that cannot be positively matched to "
        "an allowed range. Name targets individually: every target in a "
        "command must be an address, a CIDR block or a range written out in "
        "the command itself. Target files (such as -iL), variables and shell "
        "substitution are refused. A hostname is a target only once a finding "
        "ties it to an address inside the scope; record one with "
        "log_discovery, with data such as {\"ip\": \"10.0.1.5\"}.")
    if not for_executor:
        lines.append("In your task descriptions, name the targets one at a "
                     "time as well.")
    return "\n".join(lines)


# ── Tier lists ──


def _tier_section(phases, wifi_on):
    """Never-allowed and gated actions, from the classifier's own table."""
    hard, knock = [], []
    for row in safety.RISK_TABLE.values():
        # action_class values as safety.RISK_TABLE spells them. An
        # exploitation row is refused outright while Phase 5 is off, so
        # listing it as merely gated would be false, and listing it as
        # refused would mention the locked phase.
        if row.action_class == "exploitation" and 5 not in phases:
            continue
        if row.action_class == "wifi" and not wifi_on:
            continue
        if row.tier == safety.TIER_HARD:
            hard.append(row)
        elif row.tier == safety.TIER_KNOCK:
            knock.append(row)
    lines = ["Never allowed. These are refused in every mode and cannot be "
             "approved; do not ask for them or look for a way around them:"]
    lines.extend("- %s: %s" % (r.action_key, r.reason) for r in hard)
    lines.append("")
    lines.append("Gated. Each of these passes an approval gate that can "
                 "refuse it: the operator answers when watching, and the "
                 "expected-value check answers otherwise. A refusal is "
                 "normal. Read the reason, then choose another route rather "
                 "than asking again:")
    lines.extend("- %s: %s" % (r.action_key, r.reason) for r in knock)
    return "\n".join(lines)


# ── Phases ──

_WIFI_PHASES = (6, 7, 8)


# The short name of each phase, and the single source for both renderings:
# the prose the model is given below, and the checkbox label the operator
# ticks in the GUI. They were separate, and they disagreed -- the GUI called
# phase 3 "Credential access" and phase 4 "Lateral movement", activities
# this agent has no phases for, while the model was told 3 is port and
# service enumeration and 4 is OS and vulnerability fingerprinting. The
# phase list is the operator's main control over what the agent may do, so a
# label naming the wrong activity is not a cosmetic fault. Names follow the
# design, section 12.
PHASE_NAMES = {
    1: "Wire Intel",
    2: "Orientation and Discovery",
    3: "Port and Service Enumeration",
    4: "OS and Vulnerability Fingerprinting",
    5: "Exploitation",
    6: "Wifi Survey",
    7: "Wifi Capture",
    8: "Wifi Crack",
}


def _phase(number, body) -> str:
    return "Phase %d - %s: %s" % (number, PHASE_NAMES[number], body)


def _phase_section(caps_by_beacon, phases):
    caps = set(c for cs in caps_by_beacon.values() for c in cs or [])
    lines = []
    if 1 in phases and "sniffer" in caps:
        lines.append(_phase(1, "read what the capture on the bridge "
                            "already holds (hosts, protocols and any "
                            "plaintext credentials) before sending a single "
                            "packet of your own. It is the quietest source "
                            "there is."))
    if 2 in phases:
        lines.append(_phase(2, "establish interfaces, neighbours and the "
                            "live hosts inside the scope, with passive and "
                            "low-rate methods first."))
    if 3 in phases:
        lines.append(_phase(3, "find open ports and identify the services "
                            "on hosts already found."))
    if 4 in phases:
        lines.append(_phase(4, "fingerprint operating systems, and look up "
                            "known vulnerabilities for the versions you "
                            "identified (the executor's lookup_cve)."))
    if 5 in phases:
        lines.append(_phase(5, "only against a confirmed service version "
                            "with a known exploit, and only as far as the "
                            "approval gate allows."))
    if "wifi:monitor" in caps:
        if 6 in phases:
            lines.append(_phase(6, "list the access points and clients in "
                                "range."))
        if 7 in phases:
            lines.append(_phase(7, "capture handshakes and PMKIDs. "
                                "Deauthentication is gated."))
        if 8 in phases:
            lines.append(_phase(8, "recover keys from what was "
                                "captured."))
        if any(p in phases for p in _WIFI_PHASES):
            lines.append("Never dispatch wifi tasks in parallel: there is one "
                         "adapter, and it is a single physical resource.")
    if not lines:
        return ""
    return "\n".join(["Phases. Work through them in this order and report "
                      "each move with set_phase:"] + lines)


def _wifi_phases_shown(caps_by_beacon, phases):
    caps = set(c for cs in caps_by_beacon.values() for c in cs or [])
    return "wifi:monitor" in caps and any(p in phases for p in _WIFI_PHASES)


# ── Assembly ──


def orchestrator(caps_by_beacon, scope, phases, tier, os_by_beacon=None) -> str:
    caps_by_beacon = caps_by_beacon or {}
    phases = set(phases)
    every_cap = sorted(set(c for cs in caps_by_beacon.values() for c in cs or []))
    sections = [
        "You are the orchestrator of an authorised penetration-testing "
        "campaign run from a Raccoon C2. You plan; you do not run commands. "
        "Hand focused tasks to executors with dispatch_task, one task per "
        "target or per question, and put the exact targets in the "
        "description: an executor cannot see this conversation. Each "
        "executor ends its report with TASK, STATUS, FINDINGS and ERRORS. "
        "Score outcomes with log_score, and keep the findings you rely on "
        "where recall_findings can find them.",
        capability_section(caps_by_beacon, os_by_beacon),
        _tool_section("orchestrator", every_cap, tier, "Your tools:"),
        _score_section(),
        _ev_section(phases),
        _scan_section(),
        _scope_section(scope, for_executor=False),
        _tier_section(phases, _wifi_phases_shown(caps_by_beacon, phases)),
        _phase_section(caps_by_beacon, phases),
    ]
    return "\n\n".join(s for s in sections if s)


def _beacon_verb_section() -> str:
    """The language a beacon command is written in.

    A beacon does not take a program name: it dispatches on its own verb as
    the first word. Leaving this out cost a live campaign -- `arp -a`,
    `ifconfig -a` and `netstat -an` all came back "Unknown command", the
    model retried variants for 39 calls, and the run ended on its token
    budget with no findings. Several native verbs also do the job directly,
    so a model that knows them need not reach for a program at all.
    """
    lines = ["Beacon commands. A command sent to a beacon starts with one of "
             "the beacon's own verbs, not with a program name. Anything else "
             "is answered with \"Unknown command\". To run a program, use "
             "shell <command> -- `shell arp -a`, not `arp -a`. Commands with "
             "server_side go to the C2 host instead and are ordinary command "
             "lines.",
             "The verbs:"]
    for verb in sorted(beacon_exec.BEACON_VERBS):
        hint = beacon_exec.VERB_HINTS.get(verb)
        lines.append("- %s%s" % (verb, ": %s" % hint if hint else ""))
    return "\n".join(lines)


def executor(caps, scope, tier, caps_by_beacon=None,
             os_by_beacon=None) -> str:
    caps = list(caps or [])
    lines = [
        "You are an executor in an authorised penetration-testing campaign. "
        "You have one task, given in the next message. Do that task and "
        "nothing else.",
        _tool_section("executor", caps, tier, "Your tools:"),
        _scope_section(scope, for_executor=True),
        "Do not expand the scope. Do not wander off the task, pick up targets "
        "you happened to notice, or follow a lead outside the ranges above. "
        "If the task cannot be done inside the scope, say so under ERRORS and "
        "stop.",
        "Commands. Give run_command one plain command at a time, with no "
        "shell syntax. If a result carries blocked_reason, the command was "
        "refused: read the reason and change the command, or report it, and "
        "never send the same one again. Some actions pass an approval gate "
        "that can refuse them, and a refusal is not a fault. Record each "
        "finding with log_discovery as you go.",
        # The executor writes the commands, so it gets the rate limits in
        # full rather than the one-line summary it had: the summary named
        # the flags without saying what they cost in time, which is the
        # part it was getting wrong.
        _scan_section(),
        _beacon_verb_section(),
    ]
    if caps_by_beacon:
        # The same table the orchestrator gets, from the same function: the
        # id, the platform and the capabilities are one description of one
        # fleet. The executor needs the id because run_command takes a
        # beacon_id, and with nothing to go on it invented one out of the
        # capability words -- "batch-posix-smbloot" -- which made every
        # beacon-path command fail and pushed it onto server_side instead.
        lines.append(capability_section(caps_by_beacon, os_by_beacon))
        lines.append(
            "Pass one of those ids as run_command's beacon_id. Use the "
            "commands that exist on that beacon's platform, and do not "
            "spend turns working out which system you are on. A command "
            "with server_side instead runs on the C2 server, which is a "
            "different host with a different platform.")
    lines.append(
        "End your final answer with exactly this block:\n"
        "TASK: <the task name you were given>\n"
        "STATUS: <success, partial or failed>\n"
        "FINDINGS: <what you found, one per line, or none>\n"
        "ERRORS: <what went wrong or was refused, or none>")
    return "\n\n".join(lines)
