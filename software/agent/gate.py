#!/usr/bin/env python3
"""Approval gate for the autonomous agent.

Decides whether a classified action runs: tier 1 never, tier 3 always, and
tier 2 by asking the operator (supervised) or by an expected-value
calculation standing in for them (auto). Also reads the run's detection
count, because the EV is only honest if each detection raises the risk the
arbiter reasons with.

The gate runs in the router, not as a tool the model can call, so the model
cannot skip it by not asking.

Usage:
    from software.agent import gate

    g = gate.Gate(conn, run_id, mode="auto", ev_threshold=0.0,
                  p_detect_prior=0.15, detection_budget=3,
                  unattended_behavior="decide", approval_timeout=300.0)
    decision = await g.request(classification)
    if not decision.allowed:
        tell_model(decision.reason)
"""

import asyncio
import json
import re
from typing import Dict, List, NamedTuple, Optional

from software.agent import safety
from software.agent.control import ControlSignal
from software.agent.store import queries

# ── Verdicts ──


class GateDecision(NamedTuple):
    allowed: bool
    reason: str
    # "hard", "free", "ev", "operator", "timeout" or "skip". "free" is the
    # only one that writes no row — a tier-3 action has nothing to ask and
    # would flood the table. "hard" and "skip" write a row that is already
    # decided: audited, yet unanswerable, because pending() filters on
    # decision IS NULL and answer() finds no future for it.
    decided_by: str
    ev: Optional[float]
    # The verdict between allowed and refused: allowed, but only because the
    # model's own advisory p_success moved the EV over the line, where the
    # prior alone would have been refused. A boolean would have to round
    # that to allow (hiding it) or to refuse (making the override
    # pointless), so it travels as its own flag.
    override_decisive: bool = False


class GatePauseRequested(ControlSignal):
    """Raised for a tier-2 action when unattended_behavior is "pause".

    A ControlSignal so the tool-calling loop re-raises it: a pause is an
    instruction, not a failed step — see software/agent/control.py.
    """


_MODES = ("supervised", "auto")
_UNATTENDED = ("decide", "skip", "pause")

# approvals.decision is TEXT; test_agent_store pins "approved".
_APPROVED = "approved"
_REFUSED = "refused"

# ── Detection tracking ──

_DETECTION_POINTS = -100
_DETECTION_STEP = 0.15
_DETECTION_CAP = 0.95

# A detection costs 100 points, raises p_detect for every later decision and
# can end the run by spending the budget, so which signal fired belongs in the
# record. The name arrives from scanned tool output, so it is normalised and
# capped before it is written: untrusted text must not be able to put an
# unbounded or deceptive value into the audit trail.
_SOURCE_MAX = 40

# The EV's risk coefficient, deliberately not the score penalty's 100. That
# −100 is what a detection costs in the CTF ledger; this prices what being
# noticed once costs the *run*, which is not total loss — the default
# detection budget is 3, so one detection spends about a third of the
# tolerance. Hence ≈ 100/3. Settable rather than derived from the budget,
# so changing the budget cannot silently shift how aggressive the agent is.
_DEFAULT_RISK_COEFFICIENT = 33.0


def _audit_source(source) -> str:
    if not isinstance(source, str):
        return "unnamed"
    cleaned = re.sub(r"[^a-z0-9]+", "_", source.lower()).strip("_")
    return cleaned[:_SOURCE_MAX] or "unnamed"


# ── Output scanning ──
#
# Each entry: (name, pattern, needs_prior_contact). The list is short on
# purpose. A false positive is not free — it raises p_detect by 0.15 and
# spends detection budget, which can end the run — so a phrase that also
# describes an ordinary failure is left out.
#
# Left out deliberately: "connection refused" (a closed port), "timed out"
# (a dropped packet or a dead host), "access denied" and "permission denied"
# (a wrong credential), and a bare "blocked" (nmap prints it for filtered
# ports, and "0 blocked" is a clean result). A defence pushing back shows up
# as a reset, a named policy, or a host that answered before and now does
# not.

_SIGNALS = (
    # An active reset mid-conversation is what a firewall or IPS sends. The
    # Windows wording is the same event; matching only the Unix text would
    # miss it when the tool ran on a Windows beacon.
    ("connection_reset",
     re.compile(r"connection (?:was )?reset(?: by peer)?|econnreset"
                r"|forcibly closed by the remote host"), False),
    # Weaker than a reset (an ended ssh session reads this way too), but the
    # plan names it, and a close from the far side in the middle of a tool's
    # work is the usual shape of a session kill.
    ("connection_closed",
     re.compile(r"connection (?:closed|terminated) by (?:the )?remote host"),
     False),
    # The enforcer has to be named: "blocked by policy" is an enforcement
    # message, "blocked" alone is a port state.
    ("policy_block",
     re.compile(r"\b(?:blocked|denied|rejected) by (?:the |a )?"
                r"(?:security |network )?"
                r"(?:policy|firewall|waf|ids|ips|administrator)\b"), False),
    # A route or a ping reply that disappears after the host had answered is
    # a block going up or a host pulled; the same text for a host that never
    # answered is just a wrong address, so these two need prior contact.
    ("no_route_after_contact", re.compile(r"no route to host"), True),
    ("host_vanished", re.compile(r"host seems down"), True),
)


def scan_for_detection(output, *, host_was_responsive):
    """Name the detection signal in tool output, or None.

    host_was_responsive says whether the target had answered earlier in the
    run. It gates the signals that only mean something against a host that
    was reachable before. Output that is not a string is no signal.
    """
    if not isinstance(output, str):
        return None
    text = output.lower()
    for name, pattern, needs_contact in _SIGNALS:
        if needs_contact and not host_was_responsive:
            continue
        if pattern.search(text):
            return name
    return None


# ── Gate ──


class Gate:
    def __init__(self, conn, run_id, *, mode, ev_threshold, p_detect_prior,
                 detection_budget, unattended_behavior, approval_timeout,
                 risk_coefficient=_DEFAULT_RISK_COEFFICIENT):
        # An unknown mode would otherwise fall through to one of the two
        # branches in request(), and which one would be an accident.
        if mode not in _MODES:
            raise ValueError("mode must be one of %s, got %r" % (_MODES, mode))
        if unattended_behavior not in _UNATTENDED:
            raise ValueError("unattended_behavior must be one of %s, got %r"
                             % (_UNATTENDED, unattended_behavior))
        self._conn = conn
        self._run_id = run_id
        self.mode = mode
        self.ev_threshold = ev_threshold
        self.p_detect_prior = p_detect_prior
        self.detection_budget = detection_budget
        self.unattended_behavior = unattended_behavior
        self.approval_timeout = approval_timeout
        self.risk_coefficient = risk_coefficient
        # approval_id -> the future its request() is waiting on. Presence
        # here is what makes an approval answerable: tier-1 and tier-3 never
        # get an entry, and a decided one has been removed.
        self._waiting = {}  # type: Dict[int, asyncio.Future]

    # ── Detection state ──

    @property
    def detection_count(self):
        # Read from the store rather than kept in a counter: a Gate rebuilt
        # for the same run, and a detection the model reports through
        # log_score, both have to tighten the leash too.
        return queries.get_score_context(
            self._conn, self._run_id)["detection_count"]

    def effective_p_detect(self, prior):
        """The prior, raised by 0.15 per recorded detection, capped at 0.95."""
        count = self.detection_count
        if count == 0:
            return prior
        # max(prior, …) so the cap can never lower a prior that is already
        # above it; tracking only ever makes the estimate worse.
        return max(prior, min(_DETECTION_CAP, prior + _DETECTION_STEP * count))

    def note_detection(self, source):
        """Record a detection. True if the detection budget is now spent."""
        queries.log_score(self._conn, self._run_id,
                          "detection:" + _audit_source(source),
                          _DETECTION_POINTS, "high", True)
        return self.detection_count >= self.detection_budget

    # ── Approvals ──

    def pending(self) -> List[dict]:
        return queries.get_pending_approvals(self._conn, self._run_id)

    def answer(self, approval_id, allowed):
        """Resolve a waiting request. False if it is unknown or already decided.

        The future leaves _waiting in the same synchronous step that writes
        the row, so whichever of this and the timeout path runs first takes
        it and the other finds nothing.
        """
        # "false" is truthy; an approval has to be an unmistakable True.
        if not isinstance(allowed, bool):
            raise TypeError("allowed must be a bool, got %r" % (allowed,))
        fut = self._waiting.pop(approval_id, None)
        if fut is None or fut.done():
            return False
        queries.decide_approval(
            self._conn, approval_id, _APPROVED if allowed else _REFUSED,
            "operator")
        fut.set_result(allowed)
        return True

    def _expire(self, approval_id, fut, *, decide=True):
        """Close an unanswered wait; return the answer if one got there first.

        `decide` off leaves the row pending for the caller to settle. The
        timeout path needs that: "pause" must leave the knock open so the
        operator can still answer it after resuming, and "decide" needs an
        undecided row for the expected-value arbiter to write.
        """
        if self._waiting.pop(approval_id, None) is fut:
            fut.cancel()
            if decide:
                queries.decide_approval(
                    self._conn, approval_id, _REFUSED, "timeout")
            return None
        # answer() took it between the timer firing and this running; its
        # row is already written, so report its outcome, not a timeout.
        if fut.done() and not fut.cancelled():
            return fut.result()
        return None

    # ── The decision ──

    async def request(self, classification, *, p_success_override=None):
        tier = classification.tier

        # None of these writes a row: a row is an invitation to answer, and
        # an irreversible action must not be answerable, while a free one
        # has nothing to ask. Tier is compared for equality against the three
        # known values so that anything else is refused, not waved through.
        if tier == safety.TIER_FREE:
            return GateDecision(True, "no approval needed", "free", None)
        if tier == safety.TIER_HARD:
            return GateDecision(
                False, classification.reason or "irreversible action",
                "hard", None)
        if tier != safety.TIER_KNOCK:
            return GateDecision(
                False, "unrecognised tier %r; refused" % (tier,), "hard", None)

        if self.mode == "auto":
            if self.unattended_behavior == "pause":
                raise GatePauseRequested(classification.action_key)
            if self.unattended_behavior == "skip":
                return self._skip(classification)

        numbers = self._evaluate(classification, p_success_override)
        approval_id = queries.create_approval(
            self._conn, self._run_id, classification.action_key,
            json.dumps(classification._asdict(), default=str),
            json.dumps(numbers, default=str))

        if self.mode == "auto":
            return self._decide_by_ev(approval_id, numbers)
        return await self._ask_operator(approval_id, numbers, classification)

    def _skip(self, classification):
        """Refuse without evaluating, but on the record.

        The rule for this layer is that the agent may act unleashed and
        everything is logged, so a skip cannot be a refusal with no trace.
        No EV is computed — the point of "skip" is that nothing decides in
        the operator's absence — so the row carries why instead of numbers.
        """
        approval_id = queries.create_approval(
            self._conn, self._run_id, classification.action_key,
            json.dumps(classification._asdict(), default=str),
            json.dumps({"skipped": True,
                        "reason": "unattended_behavior is skip"}))
        queries.decide_approval(self._conn, approval_id, _REFUSED, "skip")
        return GateDecision(
            False, "no operator is present and this run skips gated actions",
            "skip", None)

    def _evaluate(self, classification, p_success_override):
        # A missing p_detect is substituted, not floored. safety._row defaults
        # p_detect to 0.0, so a risk-table row that omits it would otherwise
        # yield ev = points * p_success - 0 — a risk-free expected value for
        # an action that is supposed to knock. Flooring a low-but-real value
        # instead would silently overrule the table.
        substituted = not classification.p_detect
        p_detect = self.effective_p_detect(
            self.p_detect_prior if substituted else classification.p_detect)
        p_success = classification.p_success
        if p_success_override is not None:
            p_success = safety.clamp_llm_adjustment(
                classification.p_success, p_success_override)
        ev = classification.points * p_success - self.risk_coefficient * p_detect
        ev_prior = classification.points * classification.p_success \
            - self.risk_coefficient * p_detect
        return {
            "ev": ev,
            "ev_prior": ev_prior,
            "threshold": self.ev_threshold,
            "risk_coefficient": self.risk_coefficient,
            "points": classification.points,
            "p_success_prior": classification.p_success,
            "p_success_effective": p_success,
            "p_detect_prior": classification.p_detect,
            "p_detect_effective": p_detect,
            "p_detect_substituted": substituted,
            "detections": self.detection_count,
            "override_decisive": (ev > self.ev_threshold
                                  and not ev_prior > self.ev_threshold),
        }

    def _decide_by_ev(self, approval_id, numbers):
        ev = numbers["ev"]
        allowed = ev > self.ev_threshold
        queries.decide_approval(
            self._conn, approval_id, _APPROVED if allowed else _REFUSED, "ev")
        decisive = numbers["override_decisive"]
        if decisive:
            reason = ("allowed only because of the model's p_success override: "
                      "EV %.1f with it, %.1f on the prior alone, threshold %.1f"
                      % (ev, numbers["ev_prior"], self.ev_threshold))
        elif allowed:
            reason = "EV %.1f exceeds threshold %.1f" % (ev, self.ev_threshold)
        else:
            reason = ("EV %.1f does not exceed threshold %.1f "
                      "(p_detect %.2f after %d detection(s))"
                      % (ev, self.ev_threshold, numbers["p_detect_effective"],
                         numbers["detections"]))
        if numbers["p_detect_substituted"]:
            reason += ("; the risk table named no p_detect for this action, "
                       "so the configured prior %.2f was used"
                       % self.p_detect_prior)
        return GateDecision(allowed, reason, "ev", ev, decisive)

    def _unanswered(self, approval_id, numbers, classification):
        """Settle a knock the operator did not answer.

        The row is still pending here; this is what settles it. "pause"
        leaves it that way on purpose — the campaign suspends and the knock
        is waiting when the operator comes back, which is the difference
        between one suspension and a run that refuses the same action over
        and over. That is what happened live: three identical refusals for
        exploit_known_poc, 300 seconds apart.
        """
        behaviour = self.unattended_behavior
        if behaviour == "pause":
            raise GatePauseRequested(
                getattr(classification, "action_key", "a gated action"))
        if behaviour == "decide":
            return self._decide_by_ev(approval_id, numbers)
        # "skip": refused, and recorded as a timeout because that is why it
        # was decided without anyone.
        queries.decide_approval(self._conn, approval_id, _REFUSED, "timeout")
        return GateDecision(
            False, "no operator answer within %ss, and this run skips "
            "gated actions nobody answers" % self.approval_timeout,
            "timeout", numbers["ev"])

    async def _ask_operator(self, approval_id, numbers, classification=None):
        ev = numbers["ev"]
        fut = asyncio.get_running_loop().create_future()
        self._waiting[approval_id] = fut
        try:
            # Shielded so the timer cancels only its own wrapper. A
            # wait_for that cancelled `fut` itself would leave answer()
            # unable to tell "timed out" from "answered at the same
            # moment", and that ambiguity is the race.
            allowed = await asyncio.wait_for(
                asyncio.shield(fut), self.approval_timeout)
        except asyncio.TimeoutError:
            # Design section 10.7 lists the timeout as its own case, with
            # the behaviour taken from the configuration. It can only
            # happen here: Full Automated decides at once and never waits.
            # An operator who has not answered for the whole timeout is,
            # for this purpose, not attending.
            allowed = self._expire(approval_id, fut, decide=False)
            if allowed is None:
                return self._unanswered(approval_id, numbers, classification)
        except asyncio.CancelledError:
            # A request nobody is waiting on any more must not stay
            # answerable: an approval would be recorded as granted for an
            # action that never ran.
            self._expire(approval_id, fut)
            raise
        if allowed:
            return GateDecision(True, "approved by operator", "operator", ev)
        return GateDecision(False, "refused by operator", "operator", ev)
