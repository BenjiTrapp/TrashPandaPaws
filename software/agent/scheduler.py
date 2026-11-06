#!/usr/bin/env python3
"""Recurring campaigns: cron schedules, polled, with an overlap guard.

A schedule is a row in `scheduled_tasks`: a cron expression, a stored
campaign form, and the id of the run it started last. `poll_once` starts what
is due and `start_loop` calls it every minute for as long as the service
lives. Nothing here is a second way to run a campaign; a due schedule builds
a Campaign exactly as POST /campaign does and hands it to the same manager.

Three rules decide whether a due schedule starts, and each exists because
the alternative is a campaign nobody agreed to:

  * Not while its previous run has not ended. A paused run counts as not
    ended: the operator means to resume it, its beacons' polling intervals
    are still lowered, and a second campaign against them would share one
    task queue.
  * Not while another campaign holds one of its beacons, for the same
    reason. The row only knows its own last run; a campaign started by hand
    is invisible to it.
  * Not if the slot is long past. A service that was down over a 02:00
    window and comes back at 09:00 does not run the 02:00 job at 09:00.

A slot that is passed over is dropped, not queued: `next_run` always moves to
the next slot after now. A schedule that cannot start is recorded on its own
row and the poll carries on with the next one.

Usage:
    task = scheduler.start_loop(conn, manager, cfg, c2=c2)
    ...
    task.cancel()
"""

import asyncio
import dataclasses
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from croniter import CroniterBadDateError, CroniterError, croniter

from software.agent import config
from software.agent.llm import failover, provider
from software.agent.orchestrator import Campaign
from software.agent.store import queries

logger = logging.getLogger(__name__)

# ── Constants ──

POLL_SECONDS = 60

# A poll finds a slot at most a poll late, so anything much older than this
# was missed by a process that was not running.
MISFIRE_GRACE_SECONDS = 300

_FIELDS = ("minute", "hour", "day-of-month", "month", "day-of-week")


# ── Cron ──


def validate_cron(expr) -> Optional[str]:
    """Why `expr` is not usable as a schedule, or None if it is.

    Five fields, as in crontab. croniter would also take six and seven
    (seconds, years) and `@daily`; a schedule that runs every second is not
    something to offer, so those are refused here.

    When both day-of-month and day-of-week are restricted, cron means OR:
    `0 0 13 * 5` fires on every Friday and on the 13th. croniter implements
    that and the tests pin it.
    """
    if not isinstance(expr, str):
        return "the schedule must be a cron expression in text form"
    fields = expr.split()
    if len(fields) != len(_FIELDS):
        return ("a cron expression has five fields (%s), got %d"
                % (" ".join(_FIELDS), len(fields)))
    for field in fields:
        # R and H are croniter's randomised and hashed fields. With no
        # hash_id, R picks a value at random on every parse: the schedule
        # would be a different one each time it was read back.
        if any(token[:1] in "rRhH" for token in re.split(r"[^A-Za-z0-9]+", field)
               if token):
            return ("%r is randomised or hashed, which would make the "
                    "schedule differ each time it is read" % field)
    try:
        croniter(" ".join(fields), datetime.now(timezone.utc)).get_next(datetime)
    except CroniterBadDateError:
        return "%r never fires (a date that does not exist, such as 31 February)" % expr
    except (CroniterError, ValueError) as exc:
        return "%r is not a valid cron expression: %s" % (expr, exc)
    return None


def next_occurrence(expr, after: Optional[datetime] = None) -> str:
    """The first slot strictly after `after` (default: now), RFC3339 in UTC.

    Strictly after, or a schedule advanced at the very moment of a slot
    would be due again at once.
    """
    base = after if after is not None else datetime.now(timezone.utc)
    # queries._iso: every timestamp column is compared as text, so the
    # spelling has to be the one the rest of the store writes.
    return queries._iso(croniter(expr, base).get_next(datetime))


def campaign_form(campaign_cfg) -> Dict[str, Any]:
    """The form to store for a validated campaign: its settings and nothing else.

    Built from the CampaignConfig, never from the operator's raw payload and
    never from the AgentConfig. The payload may carry any key a client chose
    to send, and `config_json` is read back by anyone who can read the
    database. Every setting is written out in full, so what the operator
    agreed to when creating the schedule is what runs, even if a risk
    profile's defaults change afterwards.
    """
    form = dataclasses.asdict(campaign_cfg)
    form["phases"] = sorted(form["phases"])
    return form


# ── Overlap ──


def beacons_in_use(manager) -> Dict[str, int]:
    """Beacon id -> the unfinished campaign holding it.

    Paused campaigns hold theirs: see the module docstring. Shared with
    POST /campaign, so a campaign started by hand and one started by a
    schedule refuse each other the same way.
    """
    held = {}  # type: Dict[str, int]
    for run_id in sorted(manager.running_run_ids):
        campaign = manager.get(run_id)
        if campaign is None:
            continue
        for beacon in campaign.config.beacons:
            held.setdefault(beacon, run_id)
    return held


def _state_of(manager, run_id) -> str:
    campaign = manager.get(run_id)
    return " (%s)" % campaign.state if campaign is not None else ""


# ── Polling ──


class _Refused(Exception):
    """A start that cannot go ahead, with a reason fit for the row."""


async def poll_once(conn, manager, cfg, *, c2,
                    client_factory=failover.create_chain) -> List[int]:
    """Settle the runs that ended, then start what is due; the ids started.

    `c2` and `client_factory` are what a Campaign is built from, which the
    manager does not hold. One schedule's failure is that schedule's: it is
    recorded, and the next one is tried.
    """
    _settle_finished(conn, manager)
    started = []
    for row in queries.get_due_schedules(conn):
        try:
            if await _fire(conn, manager, cfg, c2, client_factory, row):
                started.append(row["id"])
        except Exception as exc:
            # Not the starting itself, which _fire answers for, but what is
            # left: the store failing on this row. The class only; the
            # message may carry what the layer below put in it.
            logger.warning("schedule %s could not be processed (%s)",
                           row["id"], type(exc).__name__)
            logger.debug("schedule failure", exc_info=True)
    return started


async def _fire(conn, manager, cfg, c2, client_factory, row) -> bool:
    """Start one due schedule, or record why not. Whether a run began."""
    sid = row["id"]
    try:
        reason = _passed_over(manager, row)
        if reason is None:
            campaign_cfg = _load_config(row, cfg)
            reason = _beacon_conflict(manager, campaign_cfg)
        if reason is not None:
            queries.advance_schedule(conn, sid, "SKIPPED: " + reason, ran=False)
            return False
        run_id = await _launch(conn, manager, cfg, c2, client_factory,
                               campaign_cfg)
    except (_Refused, config.ConfigError, provider.ProviderError) as exc:
        # Messages written to be read by the operator, none carrying a key.
        queries.advance_schedule(conn, sid, "ERROR: %s" % exc)
        return False
    except Exception as exc:
        logger.warning("schedule %s did not start (%s)", sid,
                       type(exc).__name__)
        logger.debug("schedule start failure", exc_info=True)
        # The class only, as everywhere here that a message from below
        # might name a URL or a header.
        queries.advance_schedule(conn, sid, "ERROR: %s" % type(exc).__name__)
        return False
    # Recorded after the start, so "started run N" names a run that exists.
    # A start that failed was recorded above, and moved next_run on just
    # the same: a schedule that fails every time must not be retried at
    # every poll.
    queries.advance_schedule(conn, sid, "started run %d" % run_id)
    queries.set_schedule_running(conn, sid, run_id)
    return True


def _passed_over(manager, row) -> Optional[str]:
    """Why this slot is not run, if it is not: too late, or still running."""
    due = datetime.fromisoformat(row["next_run"])
    late = (datetime.now(timezone.utc) - due).total_seconds()
    if late > MISFIRE_GRACE_SECONDS:
        return ("missed its slot at %s; not run late, outside the time it "
                "was set for" % row["next_run"])
    run_id = row["running_run_id"]
    if run_id is not None and run_id in manager.running_run_ids:
        return "run %d has not ended%s" % (run_id, _state_of(manager, run_id))
    return None


def _load_config(row, cfg):
    try:
        form = json.loads(row["config_json"])
    except (TypeError, ValueError):
        raise _Refused("the stored campaign form is not valid JSON") from None
    # The tier of the agent as it is now, not as it was when the schedule was
    # created: the ceiling on phases is the agent's, not the schedule's.
    return config.CampaignConfig.from_form(form, tier=cfg.capability_tier)


def _beacon_conflict(manager, campaign_cfg) -> Optional[str]:
    held = beacons_in_use(manager)
    for beacon in campaign_cfg.beacons:
        if beacon in held:
            return "%s is in use by run %d%s" % (
                beacon, held[beacon], _state_of(manager, held[beacon]))
    return None


async def _launch(conn, manager, cfg, c2, client_factory, campaign_cfg) -> int:
    ok, reason = cfg.available()
    if not ok:
        raise _Refused("the agent is not available: %s" % reason)
    campaign = Campaign(cfg, campaign_cfg, conn, c2, client_factory(cfg))
    run_id = await campaign.start()
    # After start(), as POST /campaign does: a start that fails leaves
    # nothing in the manager that would never finish.
    manager.add(campaign)
    return run_id


# ── Settling ──


def _settle_finished(conn, manager) -> None:
    """Record how each run that has ended ended, and tell the operator.

    Read from the manager on every poll rather than by a callback on the
    campaign: a run can be paused, resumed days later and finish in a task
    nobody was watching, and the service can restart in between. Asking
    "is this run still live?" covers all of those the same way, at the cost
    of a notification up to one poll interval late.
    """
    live = manager.running_run_ids
    for row in queries.list_schedules(conn):
        run_id = row["running_run_id"]
        if run_id is None or run_id in live:
            continue
        try:
            result = _describe_run(conn, run_id)
            if queries.finish_schedule(conn, row["id"], run_id, result):
                _notify(row, run_id, result)
        except Exception as exc:
            logger.warning("schedule %s could not be settled (%s)",
                           row["id"], type(exc).__name__)
            logger.debug("settle failure", exc_info=True)


def _describe_run(conn, run_id) -> str:
    run = queries.get_run(conn, run_id)
    if run is None:
        return "run %d ended; the store has no record of it" % run_id
    summary = queries.get_run_summary(conn, run_id)
    return "run %d %s: %d findings, score %d, %d detections" % (
        run_id, run["status"], summary["finding_count"],
        summary["total_score"], summary["detection_count"])


def _notify(row, run_id, result) -> None:
    # Imported here, as the rest of the package imports requests: the
    # service and its tests should not need it just to be loaded.
    try:
        from software import notifications
    except ImportError:
        return
    # None when no webhook is configured, which is the ordinary case; and in
    # this process only if something called init_notifier.
    notifier = notifications.get_notifier()
    if notifier is None:
        return
    try:
        notifier.notify("schedule", "Scheduled campaign %r: %s"
                        % (row["prompt"][:80], result),
                        schedule=row["id"], run=run_id)
    except Exception as exc:
        logger.warning("notification for schedule %s failed (%s)",
                       row["id"], type(exc).__name__)


# ── Loop ──


def start_loop(conn, manager, cfg, *, c2, client_factory=failover.create_chain,
               interval=POLL_SECONDS) -> asyncio.Task:
    return asyncio.get_running_loop().create_task(
        _loop(conn, manager, cfg, c2, client_factory, interval))


async def _loop(conn, manager, cfg, c2, client_factory, interval) -> None:
    # Runs for days unattended: an exception that ended it would stop every
    # schedule with nothing to say so. CancelledError is not an Exception,
    # so cancelling still ends it.
    while True:
        try:
            await poll_once(conn, manager, cfg, c2=c2,
                            client_factory=client_factory)
        except Exception as exc:
            logger.warning("schedule poll failed (%s); trying again in %ss",
                           type(exc).__name__, interval)
            logger.debug("schedule poll failure", exc_info=True)
        await asyncio.sleep(interval)
