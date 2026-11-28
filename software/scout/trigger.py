#!/usr/bin/env python3
"""Rung 4's cross-process trigger, from the side that owns the component.

The predecessor design ruled a NAC verb out of the egress decider because
*"a cross-process trigger is a mechanism this repository does not have"*.
This is that mechanism, and it exists for its own reason: `beacon.py` runs
under `raccoon-beacon.service` and `software/nac_bypass.py` is a component
of `main.py` under `raccoon-implant.service`, so the verb that asks and
the code that acts are in different processes.

One file, under the state directory the handoff already uses. The beacon
writes it once per deployment -- rung 4 is one-shot, and it is the only
move here that cannot be undone from the far side -- and `main.py` polls
it inside the one-second loop it already runs.

**A request stays pending until it is taken.** `main.py` can be restarted
between reading a request and acting on it, and a request that cleared
itself on being read would be a rung spent on nothing. `taken` is what
closes it: the scout reads that one field to publish
`identity_pre_spent`, and `detail` is for whoever recovers the device --
"the bypass was started" and "no ebtables" are different things to be
told, and the second is the one worth keeping. The beacon never reads
either; the file *existing* is its own one-shot latch.

**Nothing here raises.** It is polled from a loop with no guard of its
own, and an exception would take the whole implant down over a file.
"""

import logging
import os
import stat
import time
from typing import Optional

from . import handoff

logger = logging.getLogger("raccoon.scout.trigger")


class IdentityTrigger(object):
    """The request file, as `main.py` reads and closes it."""

    def __init__(self, state_dir: str):
        self.state_dir = state_dir
        self.path = handoff.identity_path(state_dir)

    def pending(self) -> Optional[dict]:
        """The open request, or None.

        None for every reason there is not one: no file, no directory, no
        permission, half a file, a version this reader does not know, or a
        request that has already been taken.

        **And for one more: a request this implant did not write.** Rung 4
        is the one move that cannot be undone from the far side, and this
        file is the whole authorisation for it -- so write access to the
        directory was write access to the move until a review said so.

        Checked by ownership and mode rather than by a shared secret. The
        beacon and this process are both root on the same device, so there
        is no key to distribute and no secret that would not be readable by
        whoever can read the request; what there is to answer is the
        *unprivileged* local attacker who pre-created the directory or the
        file. A request not owned by this euid, or writable by group or
        other, or in a directory that is, is refused. A root attacker owns
        the device and nothing here changes that -- which is a limit, and
        it is written down rather than implied.
        """
        if not self._ours(self.path) or not self._ours(self.state_dir):
            return None
        request = handoff.read_document_at(self.path, handoff.STATE_VERSION)
        if request is None or request.get("taken"):
            return None
        return request

    def _ours(self, path: str) -> bool:
        """Whether this euid wrote it and nobody else can. Raises nothing."""
        try:
            found = os.lstat(path)
        except OSError:
            return False
        if stat.S_ISLNK(found.st_mode):
            logger.warning("way out: %s is a symbolic link, so rung 4's "
                           "request was not acted on", path)
            return False
        if found.st_uid != os.geteuid():
            logger.warning("way out: %s is owned by uid %d and this process "
                           "is uid %d, so rung 4's request was not acted on",
                           path, found.st_uid, os.geteuid())
            return False
        loose = stat.S_IMODE(found.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
        if loose:
            logger.warning("way out: %s is mode %o, which somebody else can "
                           "write, so rung 4's request was not acted on",
                           path, stat.S_IMODE(found.st_mode))
            return False
        return True

    def identity_taken(self) -> Optional[str]:
        """The MAC an earlier run actually took, or None. Raises nothing.

        **Which host**, and not only whether. The restore path runs the
        whole sequence again, and that sequence *re-discovers* the
        downstream host -- it takes whatever speaks on the port now. So
        `started: true` alone would make a swapped laptop, a re-cabled
        desk or a visitor's machine into a **new** irreversible move: on
        a port already latched to the first host, a second address is
        what a port-security violation is, and the one-shot latch means
        the implant has no further moves. Recorded here so the restore
        can refuse a host nothing priced.
        """
        if not self._ours(self.path) or not self._ours(self.state_dir):
            return None
        request = handoff.read_document_at(self.path, handoff.STATE_VERSION)
        if request is None or request.get("started") is not True:
            return None
        mac = request.get("victim_mac")
        return mac if isinstance(mac, str) and mac else None

    def was_started(self) -> bool:
        """Whether an earlier run of this process actually started it.

        The one thing the request file records that is a fact about the
        **switch** rather than about this process: the MAC has moved, and
        the port may already be latched to it. `main.py` stops its
        components on shutdown, and `NACBypass.stop()` puts this implant's
        own MAC back -- so without this a reboot released an identity the
        rung had already paid the irreversible price for, and the one-shot
        latch kept it from ever being taken again.

        False for a request that was taken and did *not* start it: that
        record is a failure, and retrying a failure on every boot is the
        per-cycle retry the one-shot exists to prevent. One check and not
        two: `started` is written only by `taken` below, so "started" and
        "taken and started" are the same condition, and a second test for
        `taken` would be a branch no input can reach. A *planted* file is
        refused by the ownership check instead, which is what answers that
        threat for `pending` too.

        Raises nothing, and refuses a file this euid did not write, for
        the reason `pending` gives.
        """
        if not self._ours(self.path) or not self._ours(self.state_dir):
            return False
        request = handoff.read_document_at(self.path, handoff.STATE_VERSION)
        if request is None:
            return False
        return request.get("started") is True

    def taken(self, detail: str, started: bool = False,
              victim_mac: str = "") -> None:
        """Close the request, recording what happened. Raises nothing.

        `detail` is read by whoever recovers the device: "the bypass was
        started" and "no ebtables" are different things to be told, and
        the second is the one worth keeping.

        `started` is read by `was_started` above, and it is a separate
        field rather than a phrase in `detail` because the restore path
        turns on it: a sentence is for a human and a boolean is for the
        next run of this process.
        """
        request = handoff.read_document_at(self.path, handoff.STATE_VERSION)
        if request is None:
            request = {"version": handoff.STATE_VERSION}
        request["taken"] = time.time()
        request["started"] = bool(started)
        # Which host's identity was taken, so a restore can refuse a
        # different one. Kept rather than overwritten with "" by a later
        # write, because it is the record of an irreversible move.
        if victim_mac:
            request["victim_mac"] = str(victim_mac).strip().lower()
        request["detail"] = " ".join(str(detail).split())
        try:
            handoff.write_private_json(self.path, request)
        except (OSError, ValueError) as exc:
            logger.warning(
                "way out: the identity request at %s could not be closed "
                "(%s), so it will be read as pending again", self.path, exc)
