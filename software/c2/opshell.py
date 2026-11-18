#!/usr/bin/env python3
"""The operator shell's bookkeeping: who is watching, and whose channel is it.

The channel to the implant is raised and dropped with beacon tasks that
only take effect at the next check-in, up to 300 seconds away. This module
keeps the bookkeeping that tells it when a `tunnel stop` is owed
(`Claims`, `reconcile`), and the helpers that queue the tasks and decide
whether a stop is allowed at all (`queue_tunnel`, `may_stop`,
`expected_checkin`). Nothing here sends a `sleep` task or writes a
beacon's interval. The bookkeeping answers two questions:

- how many browser sessions currently hold a claim on an agent's channel
  (a refcount, because one bearer token can mean two tabs), and
- which agents' channels this view started, which must survive a restart
  of the team server, because a stop owed by a dead process is a channel
  left open on a target with nobody to close it.

The first lives in memory and is meant to die with the process: a claim is
a promise by a browser that is gone once the process is. The second is a
small JSON file, `{agent_id: {"since": iso8601}}`, written 0600 on every
change. Ownership outlives the last session on purpose: closing the view
only *queues* the stop, so ownership is released by `release` once the stop
has been acknowledged, or by `forget` when the agent no longer exists.

The third is the bridge from the browser's side to the shell port. The
tunnel server exposes the implant's pty as a raw TCP port on its own
loopback, behind a one-line handshake; `Bridge` is the Flask process's end
of that exchange, the same one `tools/raccoon_shell.py` speaks from a
workstation. It receives the shell password and puts it on that socket.
Nothing else here holds it, and nothing a browser can read does either.

Stdlib only.
"""

import json
import os
import secrets
import selectors
import socket
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .beacon import (
    SHELL_DEFAULT_COLS,
    SHELL_DEFAULT_ROWS,
    SHELL_GEOMETRY_MAX,
)
from .tunnel.shell import PROMPT

_DEFAULT_INTERVAL = 300

# How long `connect` waits for the prompt. `ShellFront`'s own handshake
# timeout is 15.0 s, so a port that has not prompted by then is not going
# to.
_CONNECT_TIMEOUT = 15.0

# The longest one `write` may take in total: a socket's timeout bounds the
# whole of a `sendall`, not each stalled send inside it, so a large write
# to a peer that has stopped reading raises after this long, and so does
# a large one to a slow peer. Set once on the socket for its life; `read`
# waits on a selector and never touches it.
_WRITE_TIMEOUT = 15.0

_CHUNK = 65536


class OwnershipRecordError(ValueError):
    """The ownership record cannot be trusted: damaged, or unreadable.

    Raised rather than reading the file as "owns nothing", which would
    silently drop every stop that was owed. `path` names the file.
    """

    def __init__(self, path: Path, why: str):
        super().__init__("ownership record %s: %s" % (path, why))
        self.path = path


#: How long a session may be silent before any driver calls it gone.
#:
#: The lapse used to be skipped entirely at the check-in, on the argument
#: that a request with no heartbeat must not judge a browser's liveness.
#: The argument is sound and the conclusion was wrong: the check-in is the
#: only driver that arrives when no browser exists at all, and the only
#: moment a stop can be delivered, so switching it off made "the operator
#: closed the browser" the one way to leave a channel up for ever -- this
#: feature's stated anti-goal, reached by closing a tab.
#:
#: The repair gave that driver a wider margin and left this view's own
#: poll on a 60 second one. Two numbers to reason about, and the second was
#: then missed: a hidden browser tab is throttled to about one poll a
#: minute, 60 seconds exactly, so a *second* panel polling every two
#: seconds retired the hidden tab's session and stopped a channel nobody
#: had finished with.
#:
#: So: one margin, wide enough for the slowest poll a live browser makes.
#: 240 seconds is four times a throttled tab's period.
#:
#: What it costs, stated honestly rather than as "nothing": at the shipped
#: 300 second interval the margin disappears inside the wait for the next
#: check-in, because a stop can only ride one. Below about 180 seconds it
#: does not: a 10 second beacon would have carried the stop within ten
#: seconds of the lapse, so the width costs roughly four extra minutes of
#: channel on the device. That is the price of not retiring a live
#: operator's session, and it is a price, not a free lunch.
LAPSE_GRACE = 240.0


class Claims:
    """Sessions per agent, plus the persisted record of whose channel it is."""

    def __init__(self, path: Path, grace: float = LAPSE_GRACE):
        self.path = Path(path)
        self.grace = grace
        self._lock = threading.RLock()
        # agent_id -> {session_id: time of last beat}
        self._sessions = {}  # type: Dict[str, Dict[str, float]]
        self._owned = self._load()  # type: Dict[str, dict]

    def open(self, agent_id: str, *, raised: bool) -> str:
        """Take a claim and return its session id.

        The ownership record is written before the claim is taken. If the
        write fails the exception propagates and nothing is claimed, so a
        channel is never started on the strength of a record that was not
        saved.

        `raised` has no default, deliberately. Either value would be the
        wrong one to forget: False leaves channels up, which is this
        feature's stated anti-goal, and True lets a forgotten argument stop
        a channel somebody else raised. A keyword with no default makes the
        caller say which it is, and a caller that does not say fails at
        once rather than quietly.

        It says whether this claim is the one that *brought the channel
        up*, as opposed to adopting one that was already there.
        Only the first kind may be stopped: one child process on the device
        serves both the SOCKS port and the shell port, so stopping a
        channel somebody raised from the tunnel panel would drop their
        pivot. The distinction is sticky -- once we raised it, the stop is
        ours to owe, and a later adopting claim must not downgrade it.
        """
        with self._lock:
            known = self._owned.get(agent_id)
            # Nothing on file for an adopting claim. The record exists to
            # say "a stop is owed here"; an adopted channel is never this
            # view's to stop, so a record for it could never be released --
            # `settled` cannot be true for a stop that was never queued, so
            # `reconcile` reported it owed on every sweep for ever, at one
            # relay round trip each. The refcount still counts the session,
            # which is what stops another tab's close acting under it, and
            # `raised()` answers False for an agent with no record, which
            # is already the right answer.
            if raised and (known is None or not known.get("raised")):
                updated = dict(self._owned)
                updated[agent_id] = {
                    "since": (known or {}).get("since") or _now_iso(),
                    "raised": True,
                }
                self._save(updated)
                self._owned = updated
            session_id = secrets.token_hex(8)
            self._sessions.setdefault(agent_id, {})[session_id] = time.time()
            return session_id

    def raised(self, agent_id: str) -> bool:
        """Whether this view brought that channel up, rather than adopting it.

        A record written before this field existed describes a channel the
        view did raise -- that was the only way to get one -- so a missing
        field reads as True. Reading it as False would orphan those stops
        for ever.
        """
        with self._lock:
            known = self._owned.get(agent_id)
            if known is None:
                return False
            return bool(known.get("raised", True))

    def holds(self, agent_id: str, session_id: str) -> bool:
        """Whether that exact session is one of this agent's live claims.

        `sessions(agent_id)` answers "is anyone holding one", which is not
        the same question and must not stand in for it: a stream that
        adopted a stale or invented session id whenever *somebody else* was
        live ran uncounted, and the other tab's close then queued a stop
        underneath it.
        """
        with self._lock:
            return session_id in (self._sessions.get(agent_id) or {})

    def close(self, agent_id: str, session_id: str) -> bool:
        """Release one claim; True when that was the last one.

        An unknown session answers False: it was already released (a lapse
        removed it) and the stop that release owed has been reported then.
        Ownership is not released here; see `release`.
        """
        with self._lock:
            held = self._sessions.get(agent_id)
            if not held or session_id not in held:
                return False
            del held[session_id]
            if held:
                return False
            del self._sessions[agent_id]
            return True

    def beat(self, agent_id: str, session_id: str) -> None:
        """Say this session is still watching. Unknown sessions are ignored,
        so a claim that already lapsed is not silently revived."""
        with self._lock:
            held = self._sessions.get(agent_id)
            if held and session_id in held:
                held[session_id] = time.time()

    def lapsed(self, now: float,
               grace: Optional[float] = None) -> List[str]:
        """Agents whose every session missed the grace, as of `now`.

        A session is stale when `now` is more than `grace` past its last
        beat (opening counts as a beat). `grace` overrides this claim
        record's own, which only the tests do: production has one margin,
        and `LAPSE_GRACE` carries why. Stale sessions are removed here,
        for agents that still have a live one as well: a ghost left in the
        count would make the live session's later close answer "not the
        last", and the stop would never be queued. An agent is reported
        once, at the call that removed its last session; its ownership
        stays until `release`, so `reconcile` still sees it.
        """
        with self._lock:
            out = []
            for agent_id in sorted(self._sessions):
                held = self._sessions[agent_id]
                limit = self.grace if grace is None else grace
                for sid in [s for s, t in held.items() if now - t > limit]:
                    del held[sid]
                if not held:
                    del self._sessions[agent_id]
                    out.append(agent_id)
            return out

    def sessions(self, agent_id: str) -> int:
        with self._lock:
            return len(self._sessions.get(agent_id, ()))

    def owned(self) -> List[str]:
        """Agents whose channel this view started and has not seen closed."""
        with self._lock:
            return sorted(self._owned)

    def release(self, agent_id: str) -> bool:
        """Drop ownership once the stop has been acknowledged; True if dropped.

        Only when no session holds a claim. A view that opened after the
        stop was queued has queued a start behind it, and that channel is
        this view's to close; dropping ownership then would leave it open
        with no owner and no pending stop. The check and the drop happen
        under one lock, which is why this is not left to the caller.
        """
        with self._lock:
            if self._sessions.get(agent_id) or agent_id not in self._owned:
                return False
            self._drop(agent_id)
            return True

    def forget(self, agent_id: str) -> None:
        """Drop ownership and every claim: the agent no longer exists.

        Unconditional, unlike `release`. There is no queue to put a stop
        on, so a live claim has nothing left to protect. A channel that is
        merely acknowledged closed is `release`'s case, not this one.
        """
        with self._lock:
            self._sessions.pop(agent_id, None)
            if agent_id in self._owned:
                self._drop(agent_id)

    def _drop(self, agent_id: str) -> None:
        updated = dict(self._owned)
        del updated[agent_id]
        self._save(updated)
        self._owned = updated

    def _load(self) -> Dict[str, dict]:
        try:
            raw = self.path.read_text()
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise OwnershipRecordError(self.path, "unreadable (%s)" % exc)
        except UnicodeDecodeError as exc:
            # Not an OSError, so it used to escape this method, escape
            # `opshell_claims()`'s `except OwnershipRecordError`, and reach
            # Flask: every route of this feature answered 500. That defeats
            # the whole point of this class of error -- a damaged record is
            # meant to degrade to `channel: unknown` with a reason, not to
            # take the view down.
            raise OwnershipRecordError(self.path, "not UTF-8 (%s)" % exc)
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise OwnershipRecordError(self.path, "not valid JSON (%s)" % exc)
        if not isinstance(data, dict):
            raise OwnershipRecordError(self.path, "not a JSON object")
        return data

    def _save(self, record: Dict[str, dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent),
                                   prefix=self.path.name + ".")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(record, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, str(self.path))
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def reconcile(claims: Claims, agent_ids: Iterable[str]) -> List[str]:
    """Owned agents with no live claim, for which a stop must be queued.

    An owned agent that is not in `agent_ids` is forgotten and not
    returned: a stop cannot be queued for an agent with no queue, and
    reporting it closed would claim something nobody checked.
    """
    present = set(agent_ids)
    owed = []
    for agent_id in claims.owned():
        if agent_id not in present:
            claims.forget(agent_id)
        elif claims.sessions(agent_id) == 0:
            owed.append(agent_id)
    return owed


def queue_tunnel(agent_id: str, action: str, task_queues: dict,
                 history: dict, now: str) -> dict:
    """Queue `tunnel <action>` for an agent and return the task.

    The task and its history entry are built here in the shape
    `api_create_task` in server.py builds them, key for key, rather than by
    calling the route: a task missing a key the dispatcher reads is one the
    implant never runs. The history entry is what lets the operator see
    that this feature queued something. Only `start` and `stop` are the
    feature's to queue; nothing here ever sends `sleep`.
    """
    if action not in ("start", "stop"):
        raise ValueError("tunnel action must be 'start' or 'stop', got %r"
                         % (action,))
    task = {
        "id": str(uuid.uuid4())[:8],
        "cmd": "tunnel",
        "args": action,
        "data": "",
        "timeout": 300,
        "lane": "operator",
        "queued": now,
        "status": "pending",
    }
    task_queues.setdefault(agent_id, []).append(task)
    history.setdefault(agent_id, []).append({
        "task_id": task["id"],
        "cmd": task["cmd"],
        "args": task["args"],
        "lane": task["lane"],
        "timestamp": task["queued"],
        "status": "pending",
        "output": None,
    })
    return task


def may_stop(endpoint_row: Optional[dict], owned: bool) -> Tuple[bool, str]:
    """Whether a `tunnel stop` may be queued, and why not when it may not.

    `tunnel start` and `tunnel stop` control one child process on the
    implant that serves both the SOCKS port and the shell port, so a stop
    is allowed only for a channel this view owns and only when the endpoint
    reports no live SOCKS session; otherwise it would drop a pivot the
    operator raised from the tunnel panel for something else.

    `endpoint_row` is the tunnel server's row for the agent's endpoint, or
    None when no endpoint is connected. A row whose `socks` is None says no
    SOCKS port is open, so there is no session to protect. A row that does
    not say how many sessions there are is not read as zero.
    """
    if not owned:
        return False, "this channel was not started by the operator shell"
    if endpoint_row is None:
        return False, ("the endpoint is not connected, so its socks "
                       "sessions cannot be checked")
    if "socks" not in endpoint_row:
        return False, "the endpoint row does not report its socks sessions"
    socks = endpoint_row["socks"]
    if socks is None:
        return True, ""
    sessions = socks.get("sessions") if isinstance(socks, dict) else None
    if isinstance(sessions, bool) or not isinstance(sessions, int):
        return False, "the endpoint reports no usable socks session count"
    if sessions > 0:
        return False, ("%d live socks session(s) ride this channel"
                       % sessions)
    return True, ""


def expected_checkin(agent: dict, now: float) -> Optional[float]:
    """Seconds until the agent's next check-in; negative when overdue.

    From `_last_seen_ts` and `interval`; an absent or unreadable interval
    is the server's own default of 300. None when the agent has never been
    seen. The overdue case is returned as the negative number it is: the
    view shows it. This reads the agent and never writes it.
    """
    last = agent.get("_last_seen_ts")
    if isinstance(last, bool) or not isinstance(last, (int, float)):
        return None
    interval = agent.get("interval")
    if isinstance(interval, bool) or not isinstance(interval, (int, float)):
        interval = _DEFAULT_INTERVAL
    return last + interval - now


#: How many missed intervals make a device's report stale rather than late.
#:
#: One missed interval is ordinary -- jitter, a slow link, a host that was
#: busy -- and calling that "unknown" would make the word useless. Two is
#: already a statement: the device has gone past its own schedule twice,
#: and every claim made from its last report is that old. Reporting
#: `channel: open` about such a device is a positive claim nothing has
#: checked, and the operator's close then queues a stop that cannot be
#: delivered to anybody.
STALE_AFTER_INTERVALS = 2

#: The generator's own default jitter, in percent, for an agent that has
#: not reported a profile. `server.py` defaults the generator to 20, so a
#: beacon built with the defaults sleeps in [0.8, 1.2] of its interval.
_DEFAULT_JITTER = 20


def report_is_overdue(agent: dict, now: float) -> bool:
    """Whether this agent's last report is too old to speak for the device.

    Counted in the agent's own interval rather than in seconds, because a
    beacon on a 10-second interval and one on 300 are both "two intervals
    late" at wildly different clock times. An agent that has never been
    seen is not overdue -- it is unknown for a different reason, and
    `expected_checkin` already answers None for it.
    """
    due = expected_checkin(agent, now)
    if due is None:
        return False
    interval = agent.get("interval")
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) \
            or interval <= 0:
        interval = _DEFAULT_INTERVAL
    # Jitter widens the line, because it widens the beacon's own sleep.
    # `beacon.py` draws from [interval*(1-j), interval*(1+j)] and the
    # operator may set j as high as 100%, so a flat two-interval line calls
    # a perfectly healthy agent overdue with no missed check-in at all --
    # and the view would flap to `unknown` on a working device.
    # `agents[id]["c2_profile"]["jitter"]`, which is where the server
    # stores what the beacon reported (`server.py` on the check-in,
    # `beacon.py` when it builds the profile). The first version read a
    # top-level `jitter` that nothing writes, so the widening never
    # happened and the test that proved it invented the key.
    #
    # An agent that has reported no profile is given the generator's own
    # default of 20%, not zero: its beacon still jitters, and assuming no
    # jitter is what calls a healthy device overdue.
    profile = agent.get("c2_profile")
    jitter = (profile or {}).get("jitter") if isinstance(profile, dict) \
        else None
    if isinstance(jitter, bool) or not isinstance(jitter, (int, float)) \
            or jitter < 0:
        jitter = _DEFAULT_JITTER
    slack = interval * (1 + min(jitter, 100) / 100.0)
    return due < -(interval * (STALE_AFTER_INTERVALS - 2) + slack)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def decide_stop(claims, agent_id, endpoint_row, agent_reports_running,
                task_queues, history, now, already_pending=False):
    """The stop is owed: queue it, or say why it cannot be queued yet.

    Separate from `end_session` because the sweep's sessions are already
    gone -- `lapsed` removed them -- and `Claims.close` answers False for a
    session it no longer has, by design. The first version of this reached
    the decision through a sentinel session id and therefore never reached
    it at all: `close` said "not the last" and the sweep queued nothing.

    Returns `(queued, reason)`. A refusal leaves ownership on file, so the
    stop stays owed for the next caller.

    `already_pending` is the brake, and it is not optional. Without it the
    sweep queued a fresh `tunnel stop` on *every* poll for as long as the
    stop was outstanding -- measured as five identical tasks after four
    polls -- because `reconcile` reports an owned agent with no sessions
    every time it is asked, which is exactly what an owed stop looks like.
    """
    if already_pending:
        return False, "a tunnel task is already queued for this agent"
    # "Raised by this view", not merely "claimed by it". `/open` writes
    # ownership whenever a session is taken, including onto a channel that
    # was already up -- so `owned` answered True for a pivot somebody
    # raised from the tunnel panel, and the view's Attach button made that
    # one click away from a stop. The plan's constraint is the stronger
    # word.
    owned = claims is None or claims.raised(agent_id)
    allowed, why = may_stop(endpoint_row, owned)
    if not allowed and owned and endpoint_row is None \
            and agent_reports_running:
        # `may_stop` refuses a row it has not got, by contract. The agent's
        # own report is the second source: a channel it reports has no
        # SOCKS session this server could drop.
        allowed, why = True, ""
    if not allowed:
        return False, why
    queue_tunnel(agent_id, "stop", task_queues, history, now)
    return True, ""


def end_session(claims, agent_id, session_id, endpoint_row,
                agent_reports_running, task_queues, history, now):
    """Close one session and, if it was the last, ask `decide_stop`.

    The close route's entry point. `decide_stop` is where the decision
    lives; this is the half that owns the refcount. Before the two were
    split the decision sat in four callers with different knowledge, and
    two successive attempts to fix one opened a hole in another: a stream
    released a claim it had not created, and a reconnect released the
    session the new stream was using. A refcount with four writers is not
    a refcount.

    Returns `(queued, last, reason)`.
    """
    last = claims.close(agent_id, session_id) if claims is not None else True
    if not last:
        # A reason, not an empty string. This is correct behaviour -- the
        # channel is still being watched -- but the route sent nothing, so
        # the view had nothing to show and its button looked broken. Right
        # behaviour with no explanation is indistinguishable from a bug.
        return False, False, ("another view is holding this channel, so it "
                              "stays up; this session is closed")
    queued, why = decide_stop(claims, agent_id, endpoint_row,
                              agent_reports_running, task_queues, history,
                              now)
    return queued, True, why




def sweep(claims, agents_now, endpoint_rows, reports_running, task_queues,
          history, now, clock, pending=None, settled=None):
    """Queue the stop for every claim nobody is watching any more.

    `agents_now` is the fleet's agent ids, `endpoint_rows` maps an agent to
    its relay row or None, and `reports_running` maps an agent to whether
    its own check-in says a child is running. Returns the agents a stop was
    queued for.

    This is what makes a browser that stopped asking harmless, and it is
    the half no route can do: a view that is gone sends nothing, so some
    other request has to be what notices. An agent that has left the fleet
    is forgotten rather than queued for, because a task cannot be handed to
    a queue nobody reads.

    Two clocks, because this module already has two: `now` is the ISO stamp
    a task carries, `clock` is the float `lapsed` measures a grace against.
    There is no per-driver grace; `LAPSE_GRACE` carries why.
    Passing one where the other belonged is how the first version of this
    raised a TypeError on its first call.
    """
    pending = pending or {}
    settled = settled or {}
    queued = []

    def owe(agent_id):
        if agent_id in queued:
            return
        if decide_stop(claims, agent_id, endpoint_rows.get(agent_id),
                       bool(reports_running.get(agent_id)), task_queues,
                       history, now,
                       already_pending=bool(pending.get(agent_id)))[0]:
            queued.append(agent_id)

    # Always, and with the claim record's own margin. Both knobs that sat
    # here are gone: a boolean that let a driver abstain -- its only False
    # caller was the one that needed the lapse most -- and then a
    # per-driver grace, whose second number was missed, so a second panel
    # retired a hidden tab. `LAPSE_GRACE` carries the reasoning.
    for agent_id in list(claims.lapsed(clock)):
        if agent_id not in agents_now:
            claims.forget(agent_id)
            continue
        owe(agent_id)
    for agent_id in reconcile(claims, agents_now):
        if settled.get(agent_id):
            # The stop this view owed has been carried out, so the
            # ownership that made it owed is released here. Nothing called
            # `release` before, so an agent stayed owned for ever -- and
            # once a sweep existed, that stale ownership started stopping
            # *later* channels the view never raised, including a pivot
            # someone else had brought up from the tunnel panel.
            claims.release(agent_id)
            continue
        owe(agent_id)
    return queued


def _dimension(value, default: int) -> int:
    """One terminal dimension, inside `1..SHELL_GEOMETRY_MAX`.

    The clamp the port and the implant apply: a number out of range is
    pulled in rather than refused, and anything that is not an integer
    takes the default.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return max(1, min(SHELL_GEOMETRY_MAX, value))


def auth_line(password: str, cols: int, rows: int) -> bytes:
    """The wire's first line: `<password> <cols>x<rows>` and a newline.

    The password is not quoted or escaped: the port takes the geometry
    off the end only when the tail is entirely a geometry, so a password
    with spaces in it arrives whole. The size is clamped here as well, so
    what is on the wire is always what `Bridge.geometry` says it was. A
    password with a line ending in it cannot be sent -- the newline is the
    end of the line -- and is refused rather than truncated into a wrong
    password.
    """
    if "\n" in password or "\r" in password:
        raise ValueError("that password has a line ending in it, and the "
                         "shell port's handshake is one line, so it cannot "
                         "be sent")
    cols = _dimension(cols, SHELL_DEFAULT_COLS)
    rows = _dimension(rows, SHELL_DEFAULT_ROWS)
    return ("%s %dx%d\n" % (password, cols, rows)).encode("utf-8")


class Bridge:
    """One connection to the shell port, from the team server's own side.

    `connect` dials the loopback port, waits for the prompt and sends the
    auth line; after that the socket is raw bytes both ways. The terminal
    size is part of that line and cannot be renegotiated, so `geometry`
    is fixed at construction and is the only size a view may state.

    `read` is meant for one thread and `write` for another; `close` may
    come from any, including while `connect` is still waiting for the
    prompt, and ends whatever is waiting.

    **Closing never closes a descriptor someone is using.** `close` shuts
    the connection down and writes a byte to a private socketpair that
    every wait also listens on, so a waiting `connect` or `read` wakes at
    once; the descriptors themselves are closed by whichever thread is
    the last one using them. Closing a descriptor under a thread that is
    about to `recv` on it is the one way to hand its number to another
    socket in this process.

    **A refusal is bytes, not an exception.** The port writes its refusal
    onto the connection, in place of a shell, so that an operator reads
    the reason instead of looking at what resembles a dead tunnel. That
    includes the refusals the accept loop writes without ever prompting:
    those are held for the first `read`, and the password is not sent to
    a peer that did not ask for it. `accepted` says which of the two
    happened.
    """

    def __init__(self, port: int, password: str, cols: int, rows: int,
                 host: str = "127.0.0.1"):
        self._host = host
        self._port = port
        self._password = password  # type: Optional[str]
        self._geometry = (_dimension(cols, SHELL_DEFAULT_COLS),
                          _dimension(rows, SHELL_DEFAULT_ROWS))
        # Serialises `connect`, which may hold it for the whole timeout,
        # so nothing else may wait on it: `_mu` guards the state below.
        self._lock = threading.Lock()
        self._mu = threading.Lock()
        self._sock = None  # type: Optional[socket.socket]
        self._sel = None  # type: Optional[selectors.BaseSelector]
        self._wake_r = None  # type: Optional[socket.socket]
        self._wake_w = None  # type: Optional[socket.socket]
        self._pending = b""
        self._connecting = False
        self._established = False
        self._accepted = False
        self._closed = False
        # Threads inside `read` or `write`: the descriptors stay open
        # while this is above zero.
        self._users = 0

    def __repr__(self) -> str:
        return "Bridge(%s:%s, %dx%d)" % (self._host, self._port,
                                         self._geometry[0], self._geometry[1])

    @property
    def geometry(self) -> Tuple[int, int]:
        """The `(cols, rows)` the port is sent, clamped. Fixed for good."""
        return self._geometry

    @property
    def is_open(self) -> bool:
        return self._established and not self._closed

    @property
    def accepted(self) -> bool:
        """True when the port prompted and was sent the auth line.

        False means the port answered with a refusal in place of the
        prompt: `read` has it, and `write` has nowhere to go. A caller
        shows that text before it treats a failed `write` as the end.
        """
        return self._accepted

    def connect(self, timeout: float = _CONNECT_TIMEOUT) -> None:
        """Dial, wait for the prompt, send the auth line.

        `timeout` bounds the whole of it, the wait for the prompt
        included, and a port that does not prompt in time raises
        `socket.timeout`. The password is sent only after the prompt, and
        not at all once `close` has been called: that raises
        `ConnectionError`, as does a port that hangs up before sending a
        byte. Anything else arriving before the prompt is a refusal in
        its place, kept for `read`; `connect` then returns without
        sending the password.

        A bridge connects once. After any failure it is closed and its
        password dropped.
        """
        with self._lock:
            with self._mu:
                if (self._sock is not None or self._connecting
                        or self._closed):
                    raise RuntimeError("a bridge connects once; make "
                                       "another")
                # Before anything exists to be left open.
                line = auth_line(self._password, *self._geometry)
                self._wake_r, self._wake_w = socket.socketpair()
                self._connecting = True
            try:
                self._handshake(line, timeout)
            except BaseException:
                with self._mu:
                    self._closed = True
                    self._password = None
                    self._connecting = False
                    self._release_if_idle()
                raise

    def _handshake(self, line: bytes, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        sock = socket.create_connection((self._host, self._port),
                                        timeout=timeout)
        # Published at once so that `close` can reach it.
        with self._mu:
            self._sock = sock
            if self._closed:
                raise ConnectionError("closed before the shell port "
                                      "answered")
        sock.settimeout(_WRITE_TIMEOUT)
        sel = selectors.DefaultSelector()
        with self._mu:
            self._sel = sel
        sel.register(sock, selectors.EVENT_READ)
        sel.register(self._wake_r, selectors.EVENT_READ)
        head = self._await_prompt(sel, sock, deadline)
        accepted = head.startswith(PROMPT)
        with self._mu:
            # The last look before the password leaves.
            if self._closed:
                raise ConnectionError("closed before the password was sent")
        if accepted:
            sock.sendall(line)
            head = head[len(PROMPT):]
        with self._mu:
            if self._closed:
                raise ConnectionError("closed while the password was sent")
            self._pending = head
            self._accepted = accepted
            self._password = None
            self._connecting = False
            self._established = True

    def _await_prompt(self, sel: selectors.BaseSelector,
                      sock: socket.socket, deadline: float) -> bytes:
        """Bytes read until they are the prompt or can never become it.

        A prompt may come in pieces, so a prefix of it is waited on. The
        deadline is absolute: a per-recv timeout restarts on every byte.
        """
        head = b""
        while not head.startswith(PROMPT):
            if head and not PROMPT.startswith(head):
                return head
            left = deadline - time.monotonic()
            if left <= 0:
                raise socket.timeout("the shell port did not prompt in time")
            ready = {key.fileobj for key, _ in sel.select(left)}
            if self._wake_r in ready:
                raise ConnectionError("closed before the shell port "
                                      "answered")
            if sock not in ready:
                continue
            chunk = sock.recv(_CHUNK)
            if not chunk:
                if head:
                    return head
                raise ConnectionError("the shell port hung up without "
                                      "saying anything")
            head += chunk
        return head

    def read(self, timeout: float) -> bytes:
        """What the port has sent, up to a chunk; `b""` once it has ended.

        `b""` is also what a closed bridge answers. Raises
        `socket.timeout` when the port says nothing for `timeout`
        seconds, which is not the end of anything: an idle shell is the
        normal state of one, so the caller asks again. A stream that ends
        in a reset is an `OSError` and not an end, because a shell that
        exited and a tunnel that was lost are not the same news. One
        thread reads at a time.
        """
        with self._mu:
            if self._closed:
                return b""
            if not self._established:
                raise OSError("this bridge is not connected")
            if self._pending:
                data, self._pending = self._pending, b""
                return data
            self._users += 1
            sock, sel = self._sock, self._sel
        try:
            ready = {key.fileobj for key, _ in sel.select(timeout)}
            if not ready:
                raise socket.timeout("the shell port sent nothing for %g s"
                                     % timeout)
            if self._wake_r in ready or self._closed:
                return b""
            return sock.recv(_CHUNK)
        except OSError:
            if self._closed:
                return b""
            raise
        finally:
            self._leave()

    def write(self, data: bytes) -> None:
        """Try to send every byte of `data`; raise `OSError` on failure.

        **Not all-or-nothing, and the caller has to know it.** This is
        `sendall` under a timeout, and a `sendall` that times out
        mid-transfer has already put bytes on the wire with no way to
        report how many. So a raise here means "some unknown prefix may
        have arrived", not "nothing did" -- the route turns it into a 502
        and the view says exactly that. The docstring used to promise
        every byte or an exception, which is a guarantee `sendall` does
        not give, and the view repeated the promise to the operator.

        `BrokenPipeError` when the bridge is closed or no password was
        sent -- a peer that refused has no shell to type into -- and an
        `OSError` when the peer has stopped reading for `_WRITE_TIMEOUT`.
        """
        with self._mu:
            if self._closed:
                raise BrokenPipeError("this bridge is closed")
            if not self._established or not self._accepted:
                raise BrokenPipeError("the shell port did not accept this "
                                      "session, so there is nothing to "
                                      "write to")
            self._users += 1
            sock = self._sock
        try:
            sock.sendall(data)
        finally:
            self._leave()

    def close(self) -> None:
        """End the connection; safe to repeat, and from any thread.

        Wakes a waiting `read` or `connect` and shuts the connection
        down. The descriptors are closed here only when nothing is using
        them; otherwise by the last thread that was.
        """
        with self._mu:
            if self._closed:
                return
            self._closed = True
            if self._wake_w is not None:
                try:
                    self._wake_w.send(b"x")
                except OSError:
                    pass
            if self._sock is not None:
                try:
                    self._sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            self._release_if_idle()

    def _leave(self) -> None:
        with self._mu:
            self._users -= 1
            self._release_if_idle()

    def _release_if_idle(self) -> None:
        """Close every descriptor, once the bridge is closed and unused.

        Called with `_mu` held. `connect` counts as a user until it
        returns or fails, so it is the one that releases after a close
        that came during the handshake.
        """
        if not self._closed or self._users or self._connecting:
            return
        for name in ("_sel", "_sock", "_wake_r", "_wake_w"):
            held = getattr(self, name)
            setattr(self, name, None)
            if held is not None:
                try:
                    held.close()
                except OSError:
                    pass
