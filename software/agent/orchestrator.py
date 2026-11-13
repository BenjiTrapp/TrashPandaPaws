#!/usr/bin/env python3
"""The campaign lifecycle: one database row, one background job.

A `Campaign` owns the life of one `runs` row. `start()` writes the row and
launches the orchestrator as an asyncio task, then returns the id without
waiting; `wait()` awaits that task and returns the final report. `pause()`,
`resume()` and `stop()` move the row between

    running ─► paused ─► running        (pause, then resume)
    running ─► completed | failed | aborted

and the web UI reads it through `status()` and `stream(since)`.

Which exception ends the row in which state is the heart of this module:

    GatePauseRequested, operator pause   paused     interval stays lowered
    RouterAborted, BudgetExceeded, stop  aborted    interval restored
    anything else                        failed     interval restored
    the loop returning                   completed  interval restored

Pause is the only exit that leaves the remote records polling fast, because a
resume is likely and putting the interval back only to lower it again would
spend two check-in cycles for nothing. Every other exit puts it back, whatever
the reason, including a model client that raises on its very first call: a job
that dies at once must not leave a beacon polling every 15 seconds.

Control signals (software/agent/control.py) are never turned into text. The
tool-calling loop re-raises them and so does everything in this file, with one
deliberate seam: the nested executor loops convert *every other* failure into
"[ERROR] Task '<name>' failed: ..." so the orchestrator's model can read it,
and the `except` that does so sits after the one that lets a ControlSignal
through. Swapped, a spent detection budget would reach the model as one more
failed step, and the run would carry on.

Usage:
    camp = orchestrator.Campaign(agent_cfg, campaign_cfg, conn, c2, client)
    run_id = await camp.start()
    camp.stream(since=0)           # events for the GUI, fetched incrementally
    report = await camp.wait()
"""

import asyncio
import copy
import dataclasses
import functools
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from software.agent import c2client, gate, prompts
from software.agent.control import ControlSignal
from software.agent.executor.router import Router, RouterAborted
from software.agent.llm import loop as llm_loop
from software.agent.llm.provider import TIER_LIMITS, LlmClient
from software.agent.scope import Scope
from software.agent.store import queries
from software.agent.tools import memory, registry

logger = logging.getLogger(__name__)

# ── Signals ──


class BudgetExceeded(ControlSignal):
    """The token or the runtime budget is spent; the campaign is over.

    A ControlSignal so the loop re-raises it. A budget the model could read as
    an error string and work around would not be a budget.
    """


class _PauseRequested(ControlSignal):
    """The operator asked for a pause; raised at the next model call."""


# ── Constants ──

# What the C2 is told when a polling interval is changed: the GUI's "Apply
# Sleep" form takes seconds and a jitter percentage, and the project has only
# ever used this one jitter. It is not an operator setting, so restoring uses
# the same value rather than reading one back.
_JITTER_PERCENT = 20

_PAUSED_REPLY = "[PAUSED] dispatch suspended"
_STOPPED = "[ABORTED] stopped by the operator"

_TERMINAL = ("completed", "failed", "aborted")
_UNFINISHED = ("running", "paused")

STREAM_KINDS = ("dispatch", "finding", "score", "ev", "detection", "phase",
                "approval", "error", "info")
# Long enough for a command line or a refusal reason, short enough that a
# tool result cannot turn the stream into a copy of the transcript.
_TEXT_MAX = 300

# Finished campaigns the manager keeps for the GUI to read back. Without a
# bound, a service that runs for days holds every stream it ever produced.
KEEP_FINISHED = 20


def _clip(text, limit=_TEXT_MAX) -> str:
    text = str(text)
    return text if len(text) <= limit else text[:limit - 1] + "…"


# How many stream events a campaign keeps. Capped because every tool call
# emits one and a campaign runs for hours; the durable record is the
# database, and the GUI shows only the newest few hundred anyway.
_STREAM_MAX = 2000

# What a polled event carries. The full detail — the model's arguments and
# the command's raw output — is fetched per event when a line is opened,
# because the stream is polled every 1.5 seconds and a scan's output is
# measured in kilobytes.
_DETAIL_PREVIEW = 400


def _clipped_event(entry) -> Dict[str, Any]:
    detail = {}
    for key, value in entry["detail"].items():
        if isinstance(value, str) and len(value) > _DETAIL_PREVIEW:
            detail[key] = value[:_DETAIL_PREVIEW - 1] + "\u2026"
            detail["_clipped"] = True
        elif isinstance(value, (dict, list)):
            # Shapes stay out of the poll: `full` says there is more to read.
            detail[key] = "<%s>" % type(value).__name__
            detail["_clipped"] = True
        else:
            detail[key] = value
    return dict(entry, detail=detail)

def _now() -> str:
    # The store's own spelling (queries._iso), so a timestamp in the stream
    # sorts against one in the database.
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


# ── The model client, guarded ──


class _Guard(LlmClient):
    """The campaign's client with the budgets and the pause check around it.

    A decorator rather than a change to loop.run, which is reviewed and knows
    nothing of budgets: it implements the same interface, calls through, and
    then checks. That gives one check per response and applies equally to the
    orchestrator and to every executor, because all of them are handed one.

    It reads `campaign.client` on every call instead of holding the client it
    was built with, so replacing the client between a pause and a resume takes
    effect.

    `pausable` is the difference between the two roles. The orchestrator's
    guard refuses a new model call once a pause is requested; an executor's
    does not, because an executor that is already running is allowed to
    finish (see Campaign.pause). Only the orchestrator's next turn stops.
    """

    def __init__(self, campaign, *, pausable):
        self._campaign = campaign
        self._pausable = pausable

    @property
    def provider(self):
        return self._campaign.client.provider

    @property
    def model(self):
        return self._campaign.client.model

    @property
    def supports_tools(self):
        return self._campaign.client.supports_tools

    async def complete(self, system, messages, tools, max_tokens, temperature):
        camp = self._campaign
        # Before the call, so a pause costs no tokens: raising after would
        # throw away a response that was already paid for.
        if self._pausable and camp._pause.is_set():
            raise _PauseRequested("paused by the operator")
        completion = await camp.client.complete(
            system, messages, tools, max_tokens, temperature)
        camp._check_budgets(completion.total_tokens)
        return completion


# ── The gate, observed ──


class _ObservedGate(gate.Gate):
    """A Gate that reports its decisions to the campaign's stream.

    A subclass, so the Router and the tools see an ordinary Gate and the
    decision logic stays in gate.py. Nothing here changes a verdict.
    """

    def __init__(self, *args, observer, **kwargs):
        super().__init__(*args, **kwargs)
        self._observer = observer

    async def request(self, classification, *, p_success_override=None):
        decision = await super().request(
            classification, p_success_override=p_success_override)
        # "ev" is the arbiter standing in for the operator; everything else
        # is a person, a timeout, or a rule.
        kind = "ev" if decision.decided_by == "ev" else "approval"
        self._observer(
            kind, "%s %s: %s" % (
                classification.action_key,
                "allowed" if decision.allowed else "refused", decision.reason),
            allowed=decision.allowed, decided_by=decision.decided_by,
            ev=decision.ev)
        return decision

    def note_detection(self, source):
        spent = super().note_detection(source)
        self._observer("detection", "detected: %s" % source,
                       source=str(source)[:40], budget_spent=spent)
        return spent


# ── Campaign ──


class Campaign:
    def __init__(self, agent_cfg, campaign_cfg, conn, c2, client):
        self._agent_cfg = agent_cfg
        self._cfg = campaign_cfg
        self._conn = conn
        self._c2 = c2
        # Public and replaceable: a resumed run may be handed another model.
        self.client = client
        # Raised here, not in start(): a bad tier or scope is a mistake in
        # the caller's configuration and should not leave a run row behind.
        self._limits = TIER_LIMITS[agent_cfg.capability_tier]
        self._scope = Scope(campaign_cfg.scope_allow, campaign_cfg.scope_deny)
        self._scope_key = memory.scope_key(campaign_cfg.scope_allow)

        self.run_id = None  # type: Optional[int]
        # Built in start(), because a Gate belongs to a run id.
        self.gate = None  # type: Optional[gate.Gate]
        self._router = None  # type: Optional[Router]
        self._task = None  # type: Optional[asyncio.Task]
        self._state = "idle"
        self._events = []  # type: List[Dict[str, Any]]
        # Counted separately from the list length: the list is capped, and
        # `since` is an absolute sequence number the GUI holds across polls.
        # Indexing by position would start replaying old events the moment
        # the first one is dropped.
        self._seq = 0

        # Created in start(), inside the running loop: on Python 3.9 both
        # bind to whichever loop is current when they are constructed.
        self._pause = None  # type: Optional[asyncio.Event]
        self._sem = None  # type: Optional[asyncio.Semaphore]
        self._stop_requested = False
        self._entered = False

        # Held by identity and updated in place: the router was given these
        # objects and reads the current state through them.
        self._beacon_ids = []  # type: List[str]
        self._caps = {}  # type: Dict[str, List[str]]
        self._platforms = {}  # type: Dict[str, str]
        self._uplinks = {}  # type: Dict[str, Optional[str]]
        self._lowered = []  # type: List[str]

        self._token_base = 0
        self._armed_at = None  # type: Optional[float]
        self._ended_at = None  # type: Optional[float]

    # ── Lifecycle ──

    @property
    def state(self) -> str:
        """"idle" before start(), then the row's status."""
        return self._state

    @property
    def is_unfinished(self) -> bool:
        return self._state in _UNFINISHED

    @property
    def config(self):
        """The CampaignConfig this run was started with. Read it, do not edit."""
        return self._cfg

    async def start(self) -> int:
        if self._task is not None:
            raise RuntimeError("this campaign has already been started")
        self._pause = asyncio.Event()
        self._sem = asyncio.Semaphore(self._agent_cfg.max_concurrent_executors)
        self.run_id = queries.create_run(
            self._conn, "campaign", None, self._cfg.mode,
            json.dumps(self._config_record()))
        self._state = "running"
        cfg = self._cfg
        self.gate = _ObservedGate(
            self._conn, self.run_id, mode=cfg.mode,
            ev_threshold=cfg.ev_threshold, p_detect_prior=cfg.p_detect_prior,
            detection_budget=cfg.detection_budget,
            unattended_behavior=cfg.unattended_behavior,
            approval_timeout=self._agent_cfg.approval_timeout,
            risk_coefficient=cfg.risk_coefficient, observer=self._emit)
        self._router = Router(
            self._c2, self.gate, self._scope, conn=self._conn,
            run_id=self.run_id, beacon_ids=self._beacon_ids,
            caps_by_beacon=self._caps, uplink_by_beacon=self._uplinks,
            phase5_enabled=5 in cfg.phases,
            truncate_chars=self._limits["truncate_chars"],
            limit_scan_rate=cfg.limit_scan_rate)
        self._emit("info", "campaign started", beacons=list(cfg.beacons))
        self._launch(resumed=False)
        return self.run_id

    async def wait(self) -> str:
        if self._task is None:
            raise RuntimeError("this campaign has not been started")
        # Awaited directly, not shielded: if the caller is cancelled (a
        # timeout, a shutdown) the job should end with it, and _run turns
        # that into an aborted row with the interval restored. A shielded
        # wait would leave the job running with nobody to collect it.
        return await self._task

    def pause(self) -> None:
        """Ask for a pause. Takes effect at the orchestrator's next model call.

        A new nested loop is refused from now on (see _dispatch_*). One that
        is already running is not interrupted: cutting an executor off in the
        middle of a command leaves a task on the beacon that nobody reads.
        """
        if self._state != "running" or self._pause is None:
            return
        self._pause.set()
        self._emit("info", "pause requested")

    async def resume(self) -> None:
        if self._state != "paused" or self._stop_requested or (
                self._task is not None and not self._task.done()):
            raise RuntimeError(
                "only a paused campaign can be resumed (this one is %s)"
                % self._state)
        self._pause.clear()
        self._set_state("running")
        self._emit("info", "campaign resumed")
        self._launch(resumed=True)

    def stop(self) -> None:
        if self._task is None or self._state in _TERMINAL:
            return
        self._stop_requested = True
        if not self._task.done():
            # Only once the body has begun. Cancelling a task that has not
            # taken its first step skips the whole coroutine, finally and
            # all, and the row would stay "running" for good; _run looks at
            # the flag when it starts.
            if self._entered:
                self._task.cancel()
            return
        # Paused: nothing is running. The restore is a call to the C2, so it
        # needs a task of its own, and wait() must have something to await.
        self._task = asyncio.get_running_loop().create_task(
            self._conclude("aborted", _STOPPED))

    def _launch(self, resumed) -> None:
        self._arm_budgets()
        self._entered = False
        self._ended_at = None
        self._task = asyncio.get_running_loop().create_task(self._run(resumed))

    def _set_state(self, state) -> None:
        queries.set_run_status(self._conn, self.run_id, state)
        self._state = state

    async def _run(self, resumed) -> str:
        self._entered = True
        if self._stop_requested:
            return await self._conclude("aborted", _STOPPED)
        status, report, cancelled = "failed", "", False
        try:
            await self._attach_beacons()
            await self._lower_intervals()
            report = await llm_loop.run(
                _Guard(self, pausable=True),
                system=prompts.orchestrator(
                    self._caps, self._cfg, self._cfg.phases,
                    self._agent_cfg.capability_tier,
                    os_by_beacon=self._platforms),
                prompt=self._brief(resumed),
                tools=self._watch(registry.orchestrator_tools(
                    self._conn, self.run_id,
                    dispatch_single=self._dispatch_single,
                    dispatch_parallel=self._dispatch_parallel,
                    tier=self._agent_cfg.capability_tier,
                    scope_key=self._scope_key, c2=self._c2)),
                max_turns=self._limits["orchestrator_turns"],
                conn=self._conn, run_id=self.run_id,
                caller_context="orchestrator",
                log_level=self._agent_cfg.llm_log_level,
                truncate_chars=self._limits["truncate_chars"])
            status = "completed"
        except gate.GatePauseRequested as signal:
            status, report = "paused", "[PAUSED] waiting for the operator: %s" % signal
        except _PauseRequested:
            status, report = "paused", "[PAUSED] paused by the operator"
        except (RouterAborted, BudgetExceeded) as signal:
            status, report = "aborted", "[ABORTED] %s" % signal
        except asyncio.CancelledError:
            cancelled = True
            status = "aborted"
            report = _STOPPED if self._stop_requested else "[ABORTED] cancelled"
        except Exception as exc:
            # A ControlSignal nobody here knows lands in this branch too: an
            # unrecognised instruction is not a reason to pause or to carry on.
            # Class and message, like the nested loops' error strings.
            report = "[FAILED] %s: %s" % (type(exc).__name__, exc)
        await self._conclude(status, report)
        if cancelled and not self._stop_requested:
            raise asyncio.CancelledError()
        return report

    async def _conclude(self, status, report) -> str:
        self._ended_at = time.monotonic()
        self._set_state(status)
        self._emit("info", report or "campaign %s" % status, status=status)
        if status == "paused":
            # Set so that nothing starts while paused; resume() clears it.
            self._pause.set()
            return report
        failed = await _restore_intervals(
            self._c2, [(b, self._cfg.restore_interval) for b in self._lowered])
        self._lowered = []
        for beacon_id in failed:
            self._emit("error", "could not restore the polling interval of "
                       "%s; set it by hand" % beacon_id, beacon=beacon_id)
        return report

    # ── The remote records ──

    async def _attach_beacons(self) -> None:
        """What the C2 knows of the campaign's beacons, now.

        Read at every launch and not only the first: a resume can be days
        later, and the router must not act on capabilities that were
        reported before a beacon was replaced.
        """
        ids, caps, uplinks, platforms = [], {}, {}, {}
        for beacon_id in self._cfg.beacons:
            agent = await self._c2.get_agent(beacon_id)
            if agent is None:
                self._emit("error", "beacon %s is not known to the C2"
                           % beacon_id, beacon=beacon_id)
                continue
            ids.append(beacon_id)
            reported = agent.get("caps")
            caps[beacon_id] = list(reported) if isinstance(reported, list) else []
            uplinks[beacon_id] = agent.get("uplink_iface")
            # Read with the capabilities, from the same record and at the
            # same moment: a resume days later may find the host replaced,
            # and a prompt naming the old platform would be worse than one
            # naming none.
            platforms[beacon_id] = str(agent.get("os") or "").strip()
        if not ids:
            raise RuntimeError("none of the campaign's beacons is known to the C2")
        self._beacon_ids[:] = ids
        self._caps.clear()
        self._caps.update(caps)
        self._platforms.clear()
        self._platforms.update(platforms)
        self._uplinks.clear()
        self._uplinks.update(uplinks)

    async def _lower_intervals(self) -> None:
        for beacon_id in self._beacon_ids:
            # Recorded before the call: a request that failed half way may
            # have been applied, and restoring one that was not is harmless.
            if beacon_id not in self._lowered:
                self._lowered.append(beacon_id)
            await self._c2.set_beacon_interval(
                beacon_id, self._cfg.campaign_interval, _JITTER_PERCENT)

    # ── Prompts ──

    def _brief(self, resumed) -> str:
        lines = [
            "Begin the campaign against: %s." % ", ".join(self._beacon_ids),
            "Enabled phases: %s." % ", ".join(
                str(p) for p in sorted(self._cfg.phases)),
            "Work through the phases, dispatch tasks to executors, and end "
            "with a report of what was found, the score, and what remains "
            "undone."]
        if resumed:
            readers = [s.name for s in registry.specs(
                "orchestrator", (), self._agent_cfg.capability_tier)
                if s.name in ("get_run_summary", "recall_findings")]
            lines.insert(
                0, "This campaign is being resumed after a pause. Your "
                   "earlier conversation is gone, but the work is on record: "
                   "read it first (%s) and do not repeat what is done."
                   % (", ".join(readers) or "the findings you have"))
        return "\n".join(lines)

    # ── Budgets ──

    def _arm_budgets(self) -> None:
        # A resume gets a fresh budget: the operator who resumes a run that
        # stopped for lack of tokens has decided to spend more, and one who
        # resumes after a pause should not find the hours spent paused
        # counted against the run.
        self._token_base = queries.get_run_token_summary(
            self._conn, self.run_id)["total_tokens"]
        self._armed_at = time.monotonic()

    def _task_prompt(self, name, description) -> str:
        """The task, with what remains of the budget when it starts.

        Here rather than in the preamble: the preamble is built once per
        task and would be stale by the turn the figure mattered. The
        wording in prompts.budget_line says as of when, so the numbers
        are not read as holding for the whole task.
        """
        budget = prompts.budget_line(
            max(0, self._cfg.max_tokens_total - self._tokens_used()),
            max(0.0, self._cfg.max_runtime_seconds - self._elapsed()))
        head = "Task name: %s\n\n%s" % (name, description)
        return "%s\n\n%s" % (head, budget) if budget else head

    def _tokens_used(self, pending=0) -> int:
        total = queries.get_run_token_summary(
            self._conn, self.run_id)["total_tokens"]
        return total - self._token_base + pending

    def _elapsed(self) -> float:
        if self._armed_at is None:
            return 0.0
        end = self._ended_at if self._ended_at is not None else time.monotonic()
        return end - self._armed_at

    def _check_budgets(self, pending_tokens) -> None:
        """Raise BudgetExceeded if this response put the run over a budget.

        `pending_tokens` is the response being checked. The loop writes a
        response to llm_interactions only after complete() returns, so the
        stored total lags by exactly this one; adding it makes the check
        refuse the response that crosses the line and not the one after. A
        sibling executor's unlogged response is not counted, so with N
        executors the total can run at most N-1 responses over.
        """
        used = self._tokens_used(pending_tokens)
        if used > self._cfg.max_tokens_total:
            raise BudgetExceeded("token budget exceeded: %d of %d tokens"
                                 % (used, self._cfg.max_tokens_total))
        elapsed = self._elapsed()
        if elapsed > self._cfg.max_runtime_seconds:
            raise BudgetExceeded("runtime budget exceeded: %.1fs of %gs"
                                 % (elapsed, self._cfg.max_runtime_seconds))

    # ── Dispatch ──

    async def _dispatch_single(self, name, description) -> str:
        if self._pause.is_set():
            return _PAUSED_REPLY
        async with self._sem:
            return await self._execute(name, description)

    async def _dispatch_parallel(self, tasks) -> str:
        """Run the tasks together, bounded by the semaphore.

        The semaphore is acquired here, in the loop, before each task is
        created, and released by the task's own done-callback. That ordering
        is what lets Semaphore(1) serialise instead of deadlock: acquiring
        inside the created tasks would start all of them, each holding one
        slot's worth of nothing, while this loop waited for them. Releasing
        from a callback and not a `finally` covers a task that is cancelled
        before it ever ran, whose coroutine body never executes.
        """
        running = asyncio.get_running_loop()
        results = [_PAUSED_REPLY] * len(tasks)
        futures = []  # type: List[tuple]
        try:
            for index, task in enumerate(tasks):
                if self._pause.is_set() or _signalled(futures):
                    break
                await self._sem.acquire()
                # Again: the wait for a slot can be long, and a pause or a
                # sibling's signal may have arrived during it.
                if self._pause.is_set() or _signalled(futures):
                    self._sem.release()
                    break
                future = running.create_task(
                    self._execute(task["name"], task["description"]))
                future.add_done_callback(lambda _f: self._sem.release())
                futures.append((index, future))
            if futures:
                await asyncio.wait([f for _, f in futures],
                                   return_when=asyncio.FIRST_EXCEPTION)
        finally:
            # Reached with work still running only when a signal or a
            # cancellation cut the wait short; on the ordinary path every
            # future is already done and this cancels nothing.
            for _, future in futures:
                if not future.done():
                    future.cancel()
            if futures:
                await asyncio.gather(*(f for _, f in futures),
                                     return_exceptions=True)
        for index, future in futures:
            if future.cancelled():
                results[index] = "[ERROR] Task '%s' failed: cancelled" \
                    % tasks[index]["name"]
                continue
            error = future.exception()
            if isinstance(error, ControlSignal):
                raise error
            results[index] = future.result()
        return "".join("=== Task: %s ===\n%s\n\n" % (task["name"], text)
                       for task, text in zip(tasks, results))

    async def _execute(self, name, description) -> str:
        """One nested loop. The caller holds a semaphore slot."""
        # Checked again under the slot: a pause that arrived while this
        # waited for one must not start a loop the operator has just stopped.
        if self._pause.is_set():
            return _PAUSED_REPLY
        phase = queries.get_run(self._conn, self.run_id)["phase"]
        task_id = queries.create_task(
            self._conn, self.run_id, name, description, "agent", phase)
        queries.update_task(self._conn, task_id, "running", None)
        self._emit("dispatch", "task %s started" % name, task=name,
                   task_id=task_id, phase=phase)
        try:
            tier = self._agent_cfg.capability_tier
            # An executor may use any of the campaign's beacons, so it is
            # offered what any of them can do.
            caps = sorted({c for each in self._caps.values() for c in each})
            tools = registry.executor_tools(
                self._router, self._conn, self.run_id, caps=caps, tier=tier,
                scope_key=self._scope_key, online=self._cfg.online_lookups)
            result = await llm_loop.run(
                _Guard(self, pausable=False),
                system=prompts.executor(caps, self._cfg, tier,
                                        caps_by_beacon=self._caps,
                                        os_by_beacon=self._platforms),
                prompt=self._task_prompt(name, description),
                tools=self._watch(tools),
                max_turns=self._limits["executor_turns"],
                conn=self._conn, run_id=self.run_id,
                caller_context="executor:%s" % name,
                log_level=self._agent_cfg.llm_log_level,
                truncate_chars=self._limits["truncate_chars"])
        except (ControlSignal, asyncio.CancelledError) as signal:
            # Listed before `except Exception` and propagated: a signal ends
            # or suspends the whole job, and handing it to the model as
            # text would let it read "budget spent" and carry on. The row is
            # closed first so it is not left "running" for a task that will
            # never report.
            queries.update_task(
                self._conn, task_id, "failed",
                "[INTERRUPTED] %s: %s" % (type(signal).__name__, signal))
            self._emit("dispatch", "task %s interrupted" % name, task=name,
                       task_id=task_id, status="failed")
            raise
        except Exception as exc:
            message = "[ERROR] Task '%s' failed: %s" % (name, exc)
            queries.update_task(self._conn, task_id, "failed", message)
            self._emit("error", message, task=name, task_id=task_id)
            return message
        queries.update_task(self._conn, task_id, "completed", result)
        self._emit("dispatch", "task %s completed" % name, task=name,
                   task_id=task_id, status="completed")
        return result

    # ── Read models ──

    def status(self) -> Dict[str, Any]:
        out = {
            "run_id": self.run_id, "status": self._state, "phase": None,
            "score": 0, "detections": 0,
            "budgets": {
                "tokens": {"used": 0, "limit": self._cfg.max_tokens_total},
                "runtime_seconds": {"elapsed": 0.0,
                                    "limit": self._cfg.max_runtime_seconds},
                # A count on its own does not say how close the run is to
                # being stopped, and this budget is a hard abort.
                "detections": {"used": 0,
                               "limit": self._cfg.detection_budget}},
            # The drawer shows the scope while the campaign runs, so the
            # operator can see what it is allowed to touch without reopening
            # the form.
            "scope": {"allow": list(self._cfg.scope_allow),
                      "deny": list(self._cfg.scope_deny)},
            "phases": sorted(self._cfg.phases),
            "risk_profile": self._cfg.risk_profile,
            "opsec_profile": self._cfg.opsec_profile,
            "tasks": {"total": 0, "completed": 0, "failed": 0},
            "findings": 0,
            "stream_length": self._seq}
        if self.run_id is not None:
            summary = queries.get_run_summary(self._conn, self.run_id)
            out["phase"] = summary["phase"]
            out["score"] = summary["total_score"]
            out["detections"] = summary["detection_count"]
            out["budgets"]["detections"]["used"] = summary["detection_count"]
            out["tasks"] = {"total": summary["task_count"],
                            "completed": summary["completed_task_count"],
                            "failed": summary["failed_task_count"]}
            out["findings"] = summary["finding_count"]
            out["budgets"]["tokens"]["used"] = self._tokens_used()
            out["budgets"]["runtime_seconds"]["elapsed"] = round(
                self._elapsed(), 3)
        return out

    def stream(self, since: int = 0) -> List[Dict[str, Any]]:
        """Events with seq greater than `since`; seq counts from 1.

        Pass the number of events already seen (the last seq) to fetch only
        what is new. Copies, so a caller cannot edit the record it reads.
        """
        start = since if isinstance(since, int) and since > 0 else 0
        # Filtered on seq, not sliced by position: the list is capped, so a
        # position is not a stable reference. The detail is clipped here —
        # it is polled every 1.5 seconds and a scan's raw output is large.
        # `event(seq)` serves the full one when a line is actually opened.
        return [_clipped_event(e) for e in self._events if e["seq"] > start]

    def event(self, seq: int) -> Optional[Dict[str, Any]]:
        """One event with its detail unclipped, or None if it has aged out."""
        for entry in self._events:
            if entry["seq"] == seq:
                return dict(entry, detail=copy.deepcopy(entry["detail"]))
        return None

    def _emit(self, kind, text, **detail) -> None:
        self._seq += 1
        self._events.append({
            "seq": self._seq, "ts": _now(), "kind": kind,
            "text": _clip(text), "detail": detail})
        # A campaign runs for hours and every tool call emits, so the list is
        # capped rather than left to grow. The GUI keeps only the newest
        # MAX_LINES anyway; what is lost is scrollback, and the database
        # holds the durable record.
        if len(self._events) > _STREAM_MAX:
            del self._events[:len(self._events) - _STREAM_MAX]

    def _watch(self, tools: List[llm_loop.Tool]) -> List[llm_loop.Tool]:
        """The tools, each reporting its outcome to the stream."""
        return [tool._replace(fn=self._watched(tool.spec.name, tool.fn))
                for tool in tools]

    def _watched(self, name, fn):
        # functools.wraps sets __wrapped__, which inspect.signature follows:
        # the loop binds the model's arguments against the real signature.
        @functools.wraps(fn)
        async def watched(**arguments):
            result = await fn(**arguments)
            self._note_tool(name, arguments, result)
            return result
        return watched

    def _note_tool(self, name, arguments, result) -> None:
        # Every event carries the call that produced it: the tool's name, the
        # arguments the model chose and the result it got back. The detail
        # panel is supposed to show exactly that (spec §17.1), and it had
        # nothing to show while only a summary line was recorded. The poll
        # clips all of it — see _clipped_event — and `event(seq)` serves the
        # full record when a line is opened.
        full = {"tool": name, "arguments": arguments, "result": result}
        if isinstance(result, dict) and "error" in result:
            self._emit("error", "%s: %s" % (name, result["error"]), **full)
        elif name == "set_phase" and isinstance(result, dict):
            self._emit("phase", "phase %s" % result.get("phase"),
                       phase=result.get("phase"), **full)
        elif name == "log_score" and isinstance(result, dict):
            action = result.get("action")
            self._emit("detection" if action == "detection" else "score",
                       "%s (%+d)" % (action, result.get("points", 0)),
                       action=action, points=result.get("points"), **full)
        elif name in ("log_discovery", "remember_finding"):
            self._emit("finding", "%s %s" % (
                arguments.get("finding_type"), arguments.get("host") or ""),
                **full)
        elif name == "run_command" and isinstance(result, dict):
            self._emit("info", "run_command: %s" % arguments.get("command"),
                       success=result.get("success"),
                       blocked_reason=result.get("blocked_reason"), **full)
        else:
            # Everything else still gets a line, so the panel can open any
            # call rather than the five that happened to be special-cased.
            self._emit("info", name, **full)

    # ── Record ──

    def _config_record(self) -> Dict[str, Any]:
        """What is stored in runs.config_json.

        restore_orphans reads `beacons` and `restore_interval` from here.
        Built from the campaign's settings and a named handful of the
        service's, never from the AgentConfig as a whole: that class carries
        the LLM key and two tokens, and everything in this column is readable
        by anyone who can read the database.
        """
        settings = dataclasses.asdict(self._cfg)
        settings["phases"] = sorted(settings["phases"])
        beacons = settings.pop("beacons")
        restore_interval = settings.pop("restore_interval")
        return {
            "beacons": beacons, "restore_interval": restore_interval,
            "campaign": settings,
            "agent": {"provider": self._agent_cfg.provider,
                      "model": self._agent_cfg.model,
                      "capability_tier": self._agent_cfg.capability_tier}}


def _signalled(futures) -> bool:
    """Whether a started nested loop has already ended on a ControlSignal."""
    return any(f.done() and not f.cancelled()
               and isinstance(f.exception(), ControlSignal)
               for _, f in futures)


# ── Remote intervals ──


async def _restore_intervals(c2, pairs) -> List[str]:
    """Put each (beacon, seconds) back; the beacons that could not be reached.

    Never raises: this runs on the way out of a job and at service start,
    where a C2 that is down must not take the rest of the clean-up with it.
    Once the C2 itself fails to answer, the remaining calls are not tried:
    each would wait out its own timeout to learn the same thing. A single
    beacon that is gone is only that beacon's problem, and the rest go on.
    """
    failed = []
    unreachable = False
    for beacon_id, seconds in pairs:
        if unreachable:
            failed.append(beacon_id)
            continue
        try:
            await c2.set_beacon_interval(beacon_id, seconds, _JITTER_PERCENT)
        except (c2client.C2Unavailable, c2client.C2Unauthorized) as exc:
            unreachable = True
            failed.append(beacon_id)
            logger.warning("cannot restore beacon intervals: the C2 is not "
                           "usable (%s)", type(exc).__name__)
        except Exception as exc:
            failed.append(beacon_id)
            logger.warning("cannot restore the interval of %s (%s)",
                           beacon_id, type(exc).__name__)
    return failed


async def restore_orphans(conn, c2) -> List[int]:
    """Clean up after a crash: every unfinished run, by id.

    A run still marked "running" belonged to a process that is gone, so it is
    marked failed; one marked "paused" keeps its status and can be resumed.
    Both had their beacons' polling interval lowered, so both have it put
    back (a resume lowers it again). The database is corrected first and the
    C2 asked afterwards, so a C2 that is down costs the intervals and nothing
    else; they are logged, and the service starts regardless.

    Call it once at service start, before any campaign is started: it cannot
    tell a crashed run from one this process began a moment ago.
    """
    handled = []
    pairs = []
    for row in queries.list_unfinished_runs(conn):
        run_id = row["id"]
        handled.append(run_id)
        if row["status"] == "running":
            queries.set_run_status(conn, run_id, "failed")
        try:
            record = json.loads(row["config_json"])
        except (TypeError, ValueError):
            record = {}
        record = record if isinstance(record, dict) else {}
        beacons = record.get("beacons")
        seconds = record.get("restore_interval")
        if (not isinstance(beacons, list)
                or isinstance(seconds, bool)
                or not isinstance(seconds, (int, float)) or seconds <= 0):
            # Not guessed at: writing an interval nobody chose onto a beacon
            # is a worse mistake than leaving one for the operator to see.
            logger.warning("run %d records no beacons or restore interval; "
                           "polling intervals left as they are", run_id)
            continue
        pairs.extend((b, seconds) for b in beacons if isinstance(b, str))
    failed = await _restore_intervals(c2, pairs)
    if failed:
        logger.warning("polling interval not restored on: %s",
                       ", ".join(failed))
    return handled


# ── Manager ──


class CampaignManager:
    """The live Campaign objects, found by run id.

    Holds finished campaigns too, up to KEEP_FINISHED, because the GUI reads
    a run's stream after it has ended.
    """

    def __init__(self):
        self._campaigns = []  # type: List[Campaign]

    def add(self, campaign) -> None:
        """Register a campaign, before or after its start()."""
        self._campaigns.append(campaign)
        finished = [c for c in self._campaigns if c.state in _TERMINAL]
        for old in finished[:max(0, len(finished) - KEEP_FINISHED)]:
            self._campaigns.remove(old)

    def get(self, run_id) -> Optional[Campaign]:
        for campaign in self._campaigns:
            if campaign.run_id == run_id:
                return campaign
        return None

    def active(self) -> List[Dict[str, Any]]:
        return [c.status() for c in self._campaigns if c.is_unfinished]

    @property
    def running_run_ids(self) -> Set[int]:
        """Runs that have not ended, paused ones included.

        The scheduler's overlap lock reads this, and what it protects is a
        network: a paused run still has its interval lowered and will come
        back, so a second run against the same targets must wait for it.
        """
        return {c.run_id for c in self._campaigns if c.is_unfinished}
