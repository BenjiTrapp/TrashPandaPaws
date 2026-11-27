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
closes it, and what it records is read back by the scout for the trail.

**Nothing here raises.** It is polled from a loop with no guard of its
own, and an exception would take the whole implant down over a file.
"""

import logging
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
        """
        request = handoff.read_document_at(self.path, handoff.STATE_VERSION)
        if request is None or request.get("taken"):
            return None
        return request

    def taken(self, detail: str) -> None:
        """Close the request, recording what happened. Raises nothing.

        `detail` is read back by the scout and by whoever recovers the
        device: "the bypass was started" and "no ebtables" are different
        things to be told, and the second is the one worth keeping.
        """
        request = handoff.read_document_at(self.path, handoff.STATE_VERSION)
        if request is None:
            request = {"version": handoff.STATE_VERSION}
        request["taken"] = time.time()
        request["detail"] = " ".join(str(detail).split())
        try:
            handoff.write_private_json(self.path, request)
        except (OSError, ValueError) as exc:
            logger.warning(
                "way out: the identity request at %s could not be closed "
                "(%s), so it will be read as pending again", self.path, exc)
