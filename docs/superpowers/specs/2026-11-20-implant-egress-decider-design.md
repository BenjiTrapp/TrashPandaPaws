# An egress decider on the implant — design

**Date:** 2026-11-20
**Status:** approved 2026-11-20

---

## Intent

When a dropped implant cannot get out, the thing that decides what to try
next lives on the team server. `software/agent/tools/egress.py` reads the
beacon's rescue record, and the orchestrator's model queues **one** next
attempt. That is a good design with one hole in it: it sits on the far side
of exactly the connection it is trying to establish.

Today the hole is covered by DNS. The rescue record goes out as a bare TXT
query, the server attaches it to the agent as `stuck`, and the DNS tasking
route delivers the chosen attempt back. The loop is closed — *provided* the
resolver answers and somebody, or some model, is watching.

This work closes it for the case where neither is true: the implant decides
for itself, from the same evidence, within a boundary it cannot leave.

It is **for one thing only**: getting a connection to the team server after
the device has been dropped. It has no other job, and the design's whole
safety argument rests on that being structurally true rather than a matter
of intent.

### Why it is bigger than a policy

The obvious reading of this work is "a decision table on the implant". That
part is cheap. The reason it is a project is that **the implant has almost
nothing to decide between.**

`egress.py` states the limit in its own comment, and a test holds it against
the beacon's dispatch:

> the implant has no command that changes its proxy or its transport. Those
> are fixed when it is generated. What can be changed at runtime is the
> traffic profile and the timing.

`ATTEMPT_VERBS` is `{"profile": "reconfig", "sleep": "sleep"}`. A decider
over those two would be theatre. So this work is, in order of weight:

1. a small set of **new connection-establishing verbs** in the beacon,
2. a **gate** that bounds what any of them may do, autonomously or not,
3. the **decider** that picks one, which is the cheap part.

The verbs are useful on their own: an operator, or the server-side model
through `try_egress`, gains them whether or not the decider is ever enabled.

---

## Goals

- Three new beacon verbs, dispatchable like every other: select a discovered
  proxy, re-run proxy discovery, bring the gsocket carrier up now.
- A decider that runs at the moment the beacon already knows it is stuck,
  picks **one** attempt from the rescue evidence, and stops.
- An **operator-configured policy** that says which attempts are allowed and
  in what order, validated as strictly as every other block in
  `configs/raccoon.yaml`.
- A gate, **in code and not in config**, that refuses anything which could
  reduce the implant's own reachability.
- A bounded autonomy budget per stuck window, after which the decider is
  silent and the rescue record does its job.
- Every autonomous action is **reported**, so the operator learns what the
  implant did to itself.
- Off by default. A fresh checkout decides nothing.
- `beacon.py` stays stdlib-only and single-file.

## Non-goals

- **No model, no weights, no inference engine.** The state the decider reads
  is five transports × one class of ten, plus four flags. That is a decision
  tree, not a neural problem. The Colibri path is a separate, later design
  (see *The seam for stage B*).
- **No NAC bypass verb.** `software/main.py:136-140` starts `NACBypass` as a
  component of the orchestrator process, and `beacon.py` imports only the
  standard library, so the beacon cannot reach it. A cross-process trigger
  is a mechanism this repository does not have; inventing one belongs in its
  own piece of work, and the decider is designed so adding it later is one
  verb and one policy row.
- **Not for generated builds.** The decider is drop-box only — see *Which
  build this ships in*.
- **No new rescue flag**, and no 802.1X or captive-portal sensing to make the
  two dead flags live. Both are named as follow-ups.
- **No sweep.** One attempt per cycle, which is `egress.py`'s own rule and
  for its reason: "a dozen attempts from a device impersonating an IP phone
  is louder than the single short query that reported the problem."
- **No new transport.** The five legs are what they are.
- Not a replacement for `try_egress`. When the server can be reached, the
  server decides; the decider exists for when it cannot.

## Anti-goals

Things that would make this a failure even if it establishes a connection:

- **An implant that makes itself less reachable.** `software/agent/safety.py`
  hard-refuses `sleep_too_long` and `dropbox_lifeline` on the server side,
  where an operator is present to be asked. On the implant there is nobody to
  ask, so those actions must be structurally impossible rather than
  discouraged.
- **An implant that acts and never says so.** An operator who recovers a
  device must be able to tell what it did on its own.
- **Thrashing.** A decider that retries on every cycle is a beacon with a new
  cadence, and cadence is the thing a defender notices.
- **A policy that can widen the gate.** Configuration may narrow what is
  allowed. If a `raccoon.yaml` somebody pasted into a ticket can authorise a
  new class of action, the gate is decoration.
- **Dead weight in the shipped beacon.** With the decider disabled, the file
  must behave exactly as it does today, and `test_status_quo.py`'s promise
  must still hold.

---

## Constraints

### 1. `beacon.py` is served as source text and is stdlib-only

The generator hands that file to a target as a single file. The decider,
its policy reader and its gate all live in it, in the standard library, with
no import from this repository. The policy's *validation* may live beside
the other validators for the operator's benefit, but the implant must read
its own block without it, the way the four transports already do: a block
that is absent, incomplete or unusable reads as **off, with the reason
logged once**.

### 2. The evidence is already assembled, and it is small

`_leg_status` carries, per transport, one class out of ten
(`dns_rescue.CLASSES`) and a two-byte code; `_rescue_flags` carries four
bits — proxy found, 802.1X seen, portal answered, DNS answered. The decider
reads exactly that, at the moment `_beacon_loop` has finished the chain and
found `delivered_by not in _RESCUE_UPSTREAM`. Nothing new has to be
measured.

### 3. Reporting is local, because the record is already gone

The rescue record's flags byte has `0x10` free, and an earlier draft spent it
on *the decider acted*. **That bit is not used, and the reason is the
operator's own decision on timing** (below): `_maybe_rescue` is a one-shot
latch per stuck window — one exhaustion, one query — so by the time the
decider acts on the following cycle, the record has been sent. A second
record would make the rescue periodic, which `_beacon_loop`'s own comment
records as a defect that was measured and fixed ("six queries in twelve
cycles before this was fixed"). A bit that can only be set in a message
already on the wire is decoration.

So the decider reports **locally**, and the operator reads it once there is a
connection — which is the only state in which the detail could reach them
anyway. See *What the operator learns*.

### 4. The proxy path exists; the NAC path does not

`ProxyDiscovery.discover_all()` is re-runnable and clears its own list;
discovered entries are `{"url", "source"}`; the beacon already holds
`self._proxy` and `self._proxy_session`, and `_https_post` uses the latter.
So selecting a discovered proxy is an in-process change to machinery that is
already there. The NAC bypass is not — see *Non-goals*.

### 5. Changing a leg's *configuration* at runtime is not on the table

`gsocket_enabled`, `callback_url` and the rest are read in `Beacon.__init__`.
The gsocket verb therefore does not flip a setting: it calls the existing
`_gsocket_start()`, which is the same thing the latch does, only sooner.
A verb that rewrote configuration would be a second source of truth for what
the implant is.

---

## Approaches

**A — policy table on the implant, plus the verbs it needs. Chosen.**

A deterministic, operator-ordered policy over the rescue evidence, with three
new verbs to decide between, a gate in code, and a per-window budget. Costs
nothing on disk beyond the beacon itself, is readable by the operator who
configured it, and degrades to today's behaviour when disabled. It cannot
reason about free text the implant discovered — a PAC file naming a proxy is
read by `ProxyDiscovery`, but *what it means* is not weighed.

**B — a decision engine on the implant (Colibri System One).** Deferred, not
rejected. Its `POST /v1/systemone` takes a `state` plus typed questions and
returns a probability per allowed option with a calibrated `confidence`,
which is the right shape for this decision and carries its own "I do not
know". Its decision engines are encoders (Laya: ModernBERT plus a decision
head; GLiNER2.5-Decide: DeBERTa-v3 plus a classification head), hundreds of
megabytes rather than gigabytes, they serve `/v1/systemone` only — chat
answers 400 — and ARM64 is supported from source with the Raspberry Pi named.
A decision engine also ignores `pin_state`, so the persistent-server argument
that applies to language models does not apply to it: start-on-stuck and
stop-on-connected is cheap, which is what the operator asked for.
It is deferred because the evidence in constraint 2 does not need it, and
weights on a device you can lose are the most identifiable artifact this
project would carry. It becomes right when the state should include free
text.

**C — leave the decision on the team server.** The status quo, named so the
rejection is deliberate: it needs DNS and an observer, which is the case this
work exists for.

---

## The design

### The three verbs

Dispatched from `_execute_task` beside the existing twenty-six, each
reporting like any other task:

| verb | argument | what it does |
|---|---|---|
| `egress proxy` | an index into the last discovery, or a URL | makes that proxy the active one and rebuilds `_proxy_session` |
| `egress rediscover` | none | re-runs `ProxyDiscovery.discover_all()` and reports what it found, as `proxyinfo` does |
| `egress gsocket` | none | calls `_gsocket_start()` now instead of waiting for the latch |

A URL argument is matched against what discovery found and refused when it
does not appear there. *(My call: the alternative — an arbitrary proxy URL
from tasking — is a nicer operator affordance and a worse one for the
decider, and one verb cannot have two gates.)*

`egress gsocket` on a build whose leg is disabled reports that, and changes
nothing.

### Where the decider runs, and when it may act

In `_beacon_loop`, inside the branch that already establishes the implant is
stuck — `delivered_by not in _RESCUE_UPSTREAM`.

**It may not act on the first stuck cycle.** *(The operator's decision.)* It
acts only on a stuck cycle that follows one where `_maybe_rescue()` ran and
brought nothing back. The reason is the non-goal: when the server can be
reached, the server decides. Acting immediately would mean the implant always
moved before the team server had even been told it was stuck, and the two
deciders would be racing on every drop.

The cost is stated under constraint 3: the rescue record is already sent by
then, so the decider cannot report through it.

One attempt per cycle. The next cycle re-reads the evidence, which has
changed if the attempt worked.

### The latch moves behind the decider, without breaking the default

*(The operator's decision, with its collision resolved as my call — check
this one.)*

`_gsocket_start()` runs today on **every** stuck cycle, immediately before
where the decider sits, which is why an `egress gsocket` rule could only ever
spend budget doing nothing. The operator chose to move the latch behind the
decider so the choice is real.

That cannot be done unconditionally: the decider ships **disabled**, and a
latch behind a disabled decider would mean a stuck implant never starts its
carrier at all — the gsocket leg would simply stop working in the default
configuration. So:

| decider | who starts the carrier |
|---|---|
| disabled (the default) | the latch, on the first stuck cycle, exactly as today |
| enabled | the decider, when a rule chooses `gsocket`; the latch remains its fallback for any stuck cycle on which the decider did not act, declined, or had spent its budget |

The second row has a consequence the documentation must state plainly: with
the decider enabled, the carrier may come up one cycle later than it does
today, because the decider may not act on the first stuck cycle. A policy
whose first rule chooses `gsocket` restores the old timing; one that does not
has traded a cycle for the chance to try a proxy first. That is the operator's
trade to make, which is why it is a policy row and not a constant.

`test_gsocket_leg.py`'s latch assertions describe the disabled case and must
keep passing unchanged. The enabled case is new tests.

### The policy, which the operator writes

`c2.egress_decider` in `configs/raccoon.yaml`, shipping disabled, read by
`beacon_config_from_fallback` like the five transports:

```yaml
c2:
  egress_decider:
    # THIS HOST AS A CLIENT, like c2.fallback above it. What an implant
    # that cannot get out may try on its own, in this order, when no
    # operator can be reached. Read docs/EGRESS_DECIDER.md before
    # enabling it: every row here is an action taken with nobody watching.
    enabled: false
    # At most this many autonomous attempts per stuck window. The window
    # closes when any upstream leg delivers.
    budget: 3
    rules:
      - when: {https: [auth_required, http_status]}
        try: rediscover
      - when: {flags: [proxy_found]}
        try: proxy
      - when: {any: [timed_out, unreachable]}
        try: gsocket
```

A rule matches on the rescue classes of named transports, on the flags, or on
any transport carrying one of a set of classes. The first matching rule whose
verb the gate allows, and whose budget is unspent, is the attempt. No match
means no attempt, which is the same as being disabled for that cycle.

*(My call on the matcher's shape: class names rather than numbers, because the
operator reads `auth_required` and not `7`, and `dns_rescue.CLASSES` already
holds the mapping both sides need.)*

**Two flag names are refused rather than accepted.** `dot1x_seen` and
`portal_answered` are declared in `dns_rescue.py` and rendered by the server,
but **nothing in the beacon ever sets them** — only `proxy_found` and
`dns_answered` are ever ORed in. A policy row naming one could never match.
The validator refuses those two names, with the reason in the message.
*(My call. Tolerating them would ship an operator-visible trap in the one
file nobody can debug remotely; implementing 802.1X sensing and captive-portal
detection to make them true is a second feature, and it is the one that would
make this decider much smarter — recorded as the obvious follow-up.)*

### The gate, which the operator cannot widen

A fixed table in `beacon.py`, mirroring the spirit of `safety.RISK_TABLE`'s
tier-1 rows for a host with nobody to ask:

| refused, always | because |
|---|---|
| any `sleep` the decider could choose | `sleep_too_long` is tier-1 on the server *with* an operator present. A decider that can slow its own check-ins can talk itself into silence. |
| disabling or deprioritising a leg | the chain is the thing that got the evidence. |
| anything touching persistence, the watchdog or the tunnel | not connection establishment, and all three are how a device is recovered. |
| any verb not in the three above | the allowed set is a list, not a judgement. |

Configuration selects *from* this set and orders it. It cannot add to it. A
policy naming an unknown verb is refused when the block is read, with the
verb in the message.

Note what this costs, deliberately: the one verb the server-side model has
today for a stuck beacon — `sleep` — is the one the implant-side decider may
never use. The two deciders are not equivalent and the documentation says so.

**`c2.proxy.mode: "none"` is a standing prohibition, not a starting
condition.** *(My call.)* `_init_proxy` treats that mode as a statement —
`trust_env = False`, "Proxy: disabled (direct connection)" — and an implant
that selected a discovered proxy on such a build would be contradicting an
explicit instruction about how it talks, with nobody watching. So on a build
configured that way, `egress proxy` and `egress rediscover` are unavailable
both to the decider and to tasking. The cost is honest: an implant that could
have got out through a proxy stays stuck, because its operator said no
proxies. Changing that is editing the config, not overriding it at runtime.

### What the campaign model may do with the new verbs

Nothing. *(My call.)* Two facts force the question and one answer settles it:

- `test_agent_prompts.py` asserts **set equality** between the executor's
  `BEACON_VERBS` and the beacon's own dispatch keys, so a new verb necessarily
  becomes visible to the campaign model.
- `safety.classify` is then the only gate on it, and `reconfig` already sits
  in `_BEACON_HARD_VERBS` for a reason that applies here word for word: "it
  can move the callback".

So all three verbs are **hard-refused** for the campaign model. It has
`try_egress` for a stuck beacon; these exist for the operator and for the
implant's own decider. `ATTEMPT_VERBS` does not grow either — `try_egress`
validates a non-empty `value` per verb, two of these take none, and widening
that tool is a separate decision about what a model may do to a live implant.

**A finding, recorded rather than fixed here:** `try_egress` queues through
`ctx.c2.queue_task` and never calls `safety.classify`, so a hard refusal in
the gate does not bind the one path that reaches a stuck beacon today. That
asymmetry predates this work and is not this work's to close, but a design
that mirrors the gate should not pretend the gate is airtight.

### What the operator learns, and when

There is no DNS-borne signal, for the reason in constraint 3. Instead:

- **Once there is a connection**, the operator reads the decider's log with
  the `cat` verb the beacon already has: a line per attempt with the rule that
  matched, the verb, and the outcome. *(My call. The alternative — a new
  check-in field — needs a key in `_system_info`, acceptance and storage in
  `_handle_beacon`'s whitelist, a size cap, a place in the panel and a rule
  for when the implant may clear a pending log, and it would carry the detail
  to an operator who, by the time it arrives, has a connection and could have
  read the file. Server and panel work for a message that cannot be early.)*
- **On a recovered device**, the same file.

**Where that log lives is bounded by the next constraint:** `beacon.py`
installs no handler of its own — `logger = logging.getLogger("raccoon.c2")`
— and the rotating file is added by `main.py` and `beacon_standalone.py`.
Both of those are the drop-box, which is the only build this ships in, so the
log has a home. The builder decides whether it is that file or its own.

### Which build this ships in

**The drop-box only.** *(The operator's decision.)* `_beacon_config_block`
writes a generated build's configuration from the generator's request body,
and `configs/raccoon.yaml` never reaches a generated artifact — a target host
has no such file to read. So `c2.egress_decider` is read by
`beacon_config_from_fallback`, like the five transports, and a generated
build has no decider and no way to be given one.

This is also the only build with a gsocket leg, which makes the verb set
coherent. It does mean the two proxy verbs are unavailable on exactly the
corporate target host where a proxy is most likely — a real limitation,
recorded here and in *Known limits* rather than argued away. Reaching that
host would mean a generator request field, panel work and validation, and
the operator chose not to pay for it now.

### Stopping, and staying stopped

The budget is per stuck window, and the window closes when any upstream leg
delivers. A beacon that has spent its budget records that it has — so the
rescue record still reports a stuck implant, and `try_egress` on the server
can still act when DNS reaches it. The implant going quiet is not the implant
giving up; it is the implant handing the decision back.

### The seam for stage B

The decider's evaluator takes one argument — a `state` dict of the rescue
evidence — and returns a verb or `None`. That is deliberately the shape
System One's `state` plus one `choice` question would take, so stage B
replaces the evaluator and nothing else: the verbs, the gate, the budget and
the reporting are already the parts that would bound a model.

---

## What is left to the builder

- The exact spelling of the rule matcher's YAML within the shape above, and
  whether `when` takes one key or several.
- Whether the decider's log is its own rotating file or lines in the beacon's.
- How `egress proxy` reports a selection that then fails to carry traffic —
  the verb succeeded and the leg did not, and those are different results.
- The validator's home: beside `gsocket/config.py`'s for the operator's
  benefit, or in `beacon.py` alone. Constraint 1 requires the implant to read
  its block without the former.

---

## The decisions behind this document

A builder check read an earlier draft and found eight places where it would
have had to guess. Three went to the operator; the rest are recorded as the
author's calls so a reader can disagree with them on sight.

| Decision | Who | What |
|---|---|---|
| Which build | **operator** | drop-box only; generated builds get no decider |
| When it may act | **operator** | only after a cycle whose rescue brought nothing back |
| `egress gsocket` | **operator** | the latch moves behind the decider, with the disabled case unchanged |
| The latch collision | author | a disabled decider leaves today's behaviour exactly as it is, or the gsocket leg would stop working by default |
| The `0x10` flag | author | dropped: the rescue record is already sent by the time the decider acts |
| Reporting | author | local log plus the existing `cat`, no new check-in field |
| `dot1x_seen`, `portal_answered` | author | refused in the policy, because nothing sets them |
| `proxy.mode: "none"` | author | a standing prohibition on both proxy verbs |
| The campaign model | author | all three verbs hard-refused; `ATTEMPT_VERBS` does not grow |
| Matcher shape | author | class names, not numbers |
| URL argument | author | matched against discovery, refused otherwise |

Findings recorded rather than closed here: `try_egress` bypasses
`safety.classify` entirely, so the gate it mirrors is not airtight on the one
path that reaches a stuck beacon today.
