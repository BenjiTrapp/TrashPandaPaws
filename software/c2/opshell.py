#!/usr/bin/env python3
"""The operator shell's bookkeeping: who is watching, and whose channel is it.

The channel to the implant is raised and dropped with beacon tasks that
only take effect at the next check-in, up to 300 seconds away. This module
decides nothing about tasks. It answers two questions the rest of the
feature needs in order to know when a `tunnel stop` is owed:

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

Stdlib only.
"""

import json
import os
import secrets
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List


class OwnershipRecordError(ValueError):
    """The ownership record cannot be trusted: damaged, or unreadable.

    Raised rather than reading the file as "owns nothing", which would
    silently drop every stop that was owed. `path` names the file.
    """

    def __init__(self, path: Path, why: str):
        super().__init__("ownership record %s: %s" % (path, why))
        self.path = path


class Claims:
    """Sessions per agent, plus the persisted record of whose channel it is."""

    def __init__(self, path: Path, grace: float = 60.0):
        self.path = Path(path)
        self.grace = grace
        self._lock = threading.RLock()
        # agent_id -> {session_id: time of last beat}
        self._sessions = {}  # type: Dict[str, Dict[str, float]]
        self._owned = self._load()  # type: Dict[str, dict]

    def open(self, agent_id: str) -> str:
        """Take a claim and return its session id.

        The ownership record is written before the claim is taken. If the
        write fails the exception propagates and nothing is claimed, so a
        channel is never started on the strength of a record that was not
        saved.
        """
        with self._lock:
            if agent_id not in self._owned:
                updated = dict(self._owned)
                updated[agent_id] = {"since": _now_iso()}
                self._save(updated)
                self._owned = updated
            session_id = secrets.token_hex(8)
            self._sessions.setdefault(agent_id, {})[session_id] = time.time()
            return session_id

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

    def lapsed(self, now: float) -> List[str]:
        """Agents whose every session missed the grace, as of `now`.

        A session is stale when `now` is more than `grace` past its last
        beat (opening counts as a beat). Stale sessions are removed here,
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
                for sid in [s for s, t in held.items() if now - t > self.grace]:
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


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
