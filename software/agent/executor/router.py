#!/usr/bin/env python3
"""The single path every proposed command takes before it runs.

The model never reaches the C2 except through `Router.run_command`, and that
method runs the same checks in the same order for every command. They live
here, outside anything the model can call, so that it cannot skip one by not
asking for it. The order is the specification:

    1. shell metacharacters       refuse
    2. scope                      refuse, fail-closed
    3. classification             tier 1 refuses
    4. tier 2: the gate           a refusal refuses; an unknown named beacon is
                                  refused before it, so no decision is spent
    5. scan rate limits           rewrite
    6. path: server or beacon     refuse if it names neither or both
    7. execute
    8. scan the output for a detection
    9. truncate

Scope comes before classification because a target outside the authorised
ranges is refused even when the action is harmless. The gate comes after it
because the gate prices an action and needs the classification's numbers.

Every refusal is a returned ActionResult with `blocked_reason` set, never an
exception: the model reads the reason and corrects itself. Two things do
escape. RouterAborted ends the campaign when the detection budget is spent,
and GatePauseRequested passes through from the gate, because a run configured
to pause for the operator has to stop and not merely be told no.

Usage:
    r = Router(c2, gate, scope, conn=conn, run_id=run_id, beacon_ids=ids,
               caps_by_beacon=caps, uplink_by_beacon=uplinks,
               phase5_enabled=True, truncate_chars=4000)
    result = await r.run_command("netscan 10.0.1.0/24", beacon_id="raccoon-fox")
    if result.blocked_reason:
        tell_model(result.blocked_reason)
"""

import ipaddress
import json
import re
import shlex
from typing import List, NamedTuple, Optional, Union

from software.agent.control import ControlSignal
from software.agent import safety
from software.agent.executor import ActionResult, blocked
from software.agent.executor.beacon import run_on_beacon
from software.agent.executor.server_tool import run_on_server, tool_name
from software.agent.gate import GatePauseRequested, scan_for_detection
from software.agent.llm.loop import truncate
from software.agent.scope import extract_targets
from software.agent.store import queries

__all__ = ["ActionResult", "Router", "RouterAborted"]


class RouterAborted(ControlSignal):
    """The detection budget is spent; the campaign is over.

    A ControlSignal so the tool-calling loop re-raises it instead of handing
    the model an error string to work around — see software/agent/control.py.
    """


# ── What scope is shown ──
#
# scope.check reads a command the way the tools do, but three shapes get past
# it because a word is judged whole. All three are closed here by rewriting
# the command into the words the checker should see, before it runs. The
# rewrite is for the scope check only: what executes is the original command.
#
#   key=value            `RHOSTS=dc.corp.local` is one word that is neither an
#                        address nor a hostname, so it was ignored. Split at
#                        `=`, and the value is judged on its own.
#   -oA/tmp/out          a short flag with its value attached was never
#                        scanned. A tail holding a path, host or address
#                        character is split off the flag so it is.
#   http://h/x,10.9.9.9  only a URL's host was checked. Split at commas and
#                        at a nested scheme, so what follows is judged too.
#
# Splitting refuses more than it should now and then (a query string such as
# `?ids=1,2` reads as two addresses). A refusal costs the model one retry; a
# pass costs the engagement.

# Where a short flag's own letters end and its value begins is a per-tool
# grammar this module does not have. These characters never occur in the
# letters of a flag bundle (-sV, -Pn, -vvv) or a number (-T4, -p22,80), and
# every path, host or address contains at least one.
_VALUE_CHARS = frozenset("/.:=@~\\")
_URL_START = re.compile(r"(?<![A-Za-z0-9+.-])(?=[A-Za-z][A-Za-z0-9+.-]*://)")
# scope already refuses these by prefix, and splitting would hide the prefix.
# Must equal scope._TARGET_FLAG_PREFIXES; a test pins it.
_WHOLE_FLAGS = ("-iL", "-iR")


def _split_equals(word: str) -> List[str]:
    return [piece for piece in word.split("=") if piece]


def _scope_words(word: str) -> List[str]:
    if "://" in word:
        return [piece for part in _URL_START.split(word)
                for piece in part.split(",") if piece]
    if word.startswith("--"):
        flag, equals, value = word.partition("=")
        if equals and "=" in value:
            return [flag] + _split_equals(value)
        return [word]
    if (len(word) > 2 and word[0] == "-" and word[1].isalpha()
            and not word.startswith(_WHOLE_FLAGS)):
        if any(char in _VALUE_CHARS for char in word[2:]):
            return [word[:2]] + _split_equals(word[2:])
        return [word]
    return _split_equals(word) if "=" in word else [word]


_NETWORK_VERBS = frozenset(("netscan", "smbloot", "avenum"))


def _reaches_the_network(command: str, server_side: bool) -> bool:
    """Whether the scope checker must insist on a named target.

    A command that only touches the host it runs on has no target to name —
    `cat /etc/shadow`, `ls /opt`, `systemctl stop x`. Insisting on one there
    was the bug: scope refused every path, which made reading a file
    impossible, and that is most of what there is to do on a host once you
    are on it.

    A command that reaches out over the network does have a target, and if
    none can be found the targets are hidden where the checker cannot see
    them — in a file, typically — so it is refused.

    Two signals, and `server_side` is deliberately not one of them: the
    server runs arbitrary commands too, so `systemctl stop raccoon` would
    otherwise be refused for naming no host.
    """
    if safety.takes_network_targets(command):
        return True
    words = command.split()
    first = words[0].lower() if words else ""
    if first == "shell" and len(words) > 1:
        return _reaches_the_network(command.split(None, 1)[1], server_side)
    return first in _NETWORK_VERBS


def _route_problem(beacon_id, server_side, beacon_ids) -> Optional[str]:
    """Why this request can never run, or None if the route is viable.

    Separate from the path selection below so the gate can consult it first:
    everything here is knowable without asking anyone.
    """
    if server_side and beacon_id is not None:
        return "give either beacon_id or server_side, not both"
    if server_side:
        return None
    if beacon_id is None:
        return "name a beacon_id, or set server_side"
    if beacon_id not in beacon_ids:
        return "unknown beacon '%s'" % str(beacon_id)[:_CLIP]
    return None


def _scope_view(command: str) -> Optional[str]:
    """The command as scope should read it, or None if it will not tokenise."""
    try:
        words = shlex.split(command)
    except ValueError:
        return None
    return " ".join(shlex.quote(piece) for word in words
                    for piece in _scope_words(word))


# ── Hostnames ──
#
# Where a finding keeps the address a hostname points to. A fixed list, not
# "any string that parses as an address": an address under `gateway` or
# `dns_server` says something about the host, not what the host is.
_ADDRESS_KEYS = ("ip", "ips", "address", "addresses")


def _addresses_in(data) -> List[str]:
    try:
        parsed = json.loads(data)
    except (TypeError, ValueError):
        return []
    if not isinstance(parsed, dict):
        return []
    found = []
    for key in _ADDRESS_KEYS:
        value = parsed.get(key)
        for item in value if isinstance(value, list) else [value]:
            if not isinstance(item, str):
                continue
            try:
                found.append(str(ipaddress.ip_address(item.strip())))
            except ValueError:
                continue
    return found


# ── Router ──


class _Plan(NamedTuple):
    path: str
    command: str
    argv: Optional[List[str]]
    view: str


_CLIP = 80


class Router:
    def __init__(self, c2, gate, scope, *, conn, run_id, beacon_ids,
                 caps_by_beacon, uplink_by_beacon, phase5_enabled,
                 truncate_chars, limit_scan_rate=True):
        self._c2 = c2
        self.gate = gate
        self._scope = scope
        self._conn = conn
        self._run_id = run_id
        # Held, not copied: the orchestrator refreshes these as beacons
        # check in and drop out, and the router has to see the current state.
        self._beacon_ids = beacon_ids
        self._caps = caps_by_beacon
        self._uplinks = uplink_by_beacon
        self._phase5_enabled = phase5_enabled
        # The yolo OpSec profile turns this off: scans run at the tool's own
        # defaults, which is loud on the target network. It changes nothing
        # about the tier-1 blocks or the gate, and a test pins that.
        self._limit_scan_rate = limit_scan_rate
        self._truncate_chars = truncate_chars

    # ── Target ──

    def target_kind(self, beacon_id, *, server_side: bool = False) -> str:
        """"server", "dropbox" or "beacon": which safety rules apply here.

        This decides whether safety's dropbox_lifeline rule applies, and that
        rule is the hard block that protects the bridge, the NAC bypass, the
        cover services and the SSH lifeline: what keeps the box reachable and
        hidden. So the answer is asymmetric on purpose. A beacon is only an
        ordinary beacon when its capabilities are known and do not include
        "dropbox"; empty, missing or malformed caps read as the drop-box.
        Misreading a victim host as the drop-box costs a refused command, and
        only one that names a raccoon service, so the cost is near zero.
        Misreading the drop-box as an ordinary beacon costs the box, with no
        way back. Do not simplify this to `"dropbox" in caps`.
        """
        if server_side:
            return "server"
        caps = self._caps.get(beacon_id)
        if not isinstance(caps, (list, tuple, set, frozenset)) or not caps:
            return "dropbox"
        return "dropbox" if "dropbox" in caps else "beacon"

    def _uplink_check(self, beacon_id):
        def is_uplink_iface(name) -> bool:
            uplink = self._uplinks.get(beacon_id)
            if not isinstance(uplink, str) or not uplink.strip():
                # With no uplink known, any interface might be the one the C2
                # channel runs over, so all of them are. Safety then refuses
                # every monitor-mode switch rather than risk cutting the
                # agent off from its own beacon.
                return True
            # Case-folded: a mismatch only ever makes the answer "not the
            # uplink", which is the permissive error.
            return str(name).strip().lower() == uplink.strip().lower()
        return is_uplink_iface

    # ── Hostnames ──

    def _resolve_host(self, name: str) -> Optional[List[str]]:
        """Every address findings tie to `name`, or None if there are none.

        Reads this run's findings and nothing else. A name the agent has
        not seen tied to an address is not a target it may act on, which is
        the fail-closed reading of scope. And a lookup would send the name to
        whichever resolver this host uses; during an engagement that may be
        the client's, and a name the model invented would go with it. That is
        both noisy and an exposure.

        Scoped to the run, not to the whole table: a finding from a different
        engagement resolving a name for this one is a read across clients.
        The cost is that a scheduled follow-up campaign rediscovers names it
        already knew, which is a scan, not a leak.

        All addresses come back, not one picked: scope requires every one of
        them to be in range, because the tool may well choose the one that
        is not.
        """
        found = set()
        for finding in queries.get_findings_by_host(
                self._conn, name, run_id=self._run_id):
            found.update(_addresses_in(finding.get("data")))
        return sorted(found) or None

    def _host_was_responsive(self, view: str) -> bool:
        """Whether a target of the command had answered before.

        An earlier finding at an address means it did. A hostname counts
        through the addresses it points to, not through the finding that
        ties it to them: that records where the name leads, not that anything
        answered there. Networks are not expanded; a sweep has no one host to
        have gone quiet.
        """
        targets, _ = extract_targets(view)
        for target in targets:
            try:
                addresses = [str(ipaddress.ip_address(target))]
            except ValueError:
                addresses = self._resolve_host(target) or []
            for address in addresses:
                if queries.get_findings_by_host(
                        self._conn, address, run_id=self._run_id):
                    return True
        return False

    # ── Run ──

    async def run_command(self, command: str, *, beacon_id=None,
                          server_side: bool = False, timeout=None,
                          p_success_override=None) -> ActionResult:
        try:
            screened = await self._screen(command, beacon_id, server_side,
                                          p_success_override)
        except GatePauseRequested:
            raise
        except Exception as exc:
            # A check that crashes has not approved anything.
            return blocked("a safety check failed (%s); refusing the command"
                           % type(exc).__name__)
        if isinstance(screened, ActionResult):
            return screened

        if screened.path == "server":
            result = await run_on_server(
                self._c2, screened.argv, tool=tool_name(screened.argv),
                timeout=timeout)
        else:
            result = await run_on_beacon(
                self._c2, beacon_id, screened.command, timeout=timeout)

        # Before truncation: the signal can sit in the part that is cut.
        signal = scan_for_detection(
            result.output,
            host_was_responsive=self._host_was_responsive(screened.view))
        if signal is not None and self.gate.note_detection(signal):
            raise RouterAborted(
                "detection budget spent (last signal: %s)" % signal)

        text, cut = truncate(result.output, self._truncate_chars)
        # The rewrite is reported only when there was one, so an untouched
        # command carries no noise. `command` is the model's own string.
        rewritten = (screened.command
                     if screened.command.strip() != command.strip() else None)
        return result._replace(output=text, truncated=result.truncated or cut,
                               effective_command=rewritten)

    async def _screen(self, command, beacon_id, server_side,
                      p_success_override) -> Union[ActionResult, _Plan]:
        """Steps 1 to 6: a refusal, or the plan for step 7."""
        if safety.has_shell_metachars(command):
            return blocked(
                "shell syntax (; & | ` $ ( ) < > or a line break) is not "
                "accepted; give one plain command")

        view = _scope_view(command)
        if view is None:
            return blocked("the command could not be tokenised (unbalanced "
                           "quotes?), so it cannot be checked against the scope")
        reason = self._scope.check(view, self._resolve_host,
                                   require_target=_reaches_the_network(
                                       command, server_side))
        if reason:
            return blocked(reason)

        kind = self.target_kind(beacon_id, server_side=server_side)
        classification = safety.classify(
            command, kind, self._uplink_check(beacon_id), self._phase5_enabled)
        if classification.tier == safety.TIER_HARD:
            return blocked(classification.reason or "irreversible action")
        if classification.tier == safety.TIER_KNOCK:
            # Before the gate, not after: in supervised mode a request whose
            # route is already impossible would put a question in front of
            # the operator, take their answer, and then be refused anyway. A
            # decision spent on something that cannot run teaches people to
            # click through.
            #
            # Three ways the route is impossible, all knowable now: both
            # targets given, neither given, or a named beacon this job does
            # not have. The named-beacon case is checked again below, because
            # beacon_ids is live and an approval can wait minutes.
            route = _route_problem(beacon_id, server_side, self._beacon_ids)
            if route:
                return blocked(route)
            decision = await self.gate.request(
                classification, p_success_override=p_success_override)
            if not decision.allowed:
                return blocked("refused by the approval gate: %s"
                               % decision.reason)
        elif classification.tier != safety.TIER_FREE:
            return blocked("unrecognised tier %r; refusing"
                           % (classification.tier,))

        limited = (safety.enforce_scan_limits(command)
                   if self._limit_scan_rate else command)

        route = _route_problem(beacon_id, server_side, self._beacon_ids)
        if route:
            return blocked(route)
        if server_side:
            try:
                argv = shlex.split(limited)
            except ValueError:
                return blocked("the command could not be split into arguments")
            if not argv:
                return blocked("the command is empty")
            return _Plan("server", limited, argv, view)
        return _Plan("beacon", limited, None, view)
