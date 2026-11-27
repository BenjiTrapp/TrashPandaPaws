# A way out the implant finds for itself — design

**Date:** 2026-11-27
**Status:** proposed

---

## Intent

When every upstream leg fails, the implant is dark. The egress decider
(`2026-11-20-implant-egress-decider-design.md`) closed half of that hole: it
decides *on the implant*, because the server's model sits on the far side of
exactly the connection it would restore. What it decides with, though, is
small — five lines of evidence (`beacon.py:9558`) and three verbs
(`EGRESS_VERBS`, `beacon.py:1850`) — and the policy that orders them is a
table an operator writes by hand.

This project widens the vocabulary and moves the evaluator onto the device.
Not because a policy reasons badly: a policy over five fields and three verbs
reasons exactly as well as a model would. The reason is that the vocabulary
this device *could* have is too large for a hand-written table. The implant
is an inline tap between a switch port and a host (`README.md:62-66`): it can
see what gets out of that host, which is evidence nobody is collecting today,
and once the moves take arguments — *which* proxy, *which* credential,
*which* identity, *which* SSID — the policy becomes a table nobody maintains.

One job, and the human said it in one line: *"es soll ausschließlich dazu
dienen einen weg hinaus zu finden nicht mehr und nicht weniger."* Once the
channel is back, tasking and a shell return the way they do today. Nothing
about this project runs a campaign on the implant.

### What the human decided, in their words

Recorded because these are the choices the rest of the document rests on,
and none of them is mine:

1. **Scope.** *"ausschließlich dazu dienen einen weg hinaus zu finden"* — no
   local task queue, no local scheduling, no local repair hand, even though
   an earlier answer had wanted those too. The tunnel restores the real
   channel; the real channel brings both back.
2. **Latitude.** *"es kann alles nutzen was da ist und jede option verwenden
   die hilft das ziel > verbindung zum teamserver herstellen erfüllt."*
3. **Risk appetite.** Asked which is worse, staying dark or burning the
   implant: *"das das implantat dunkel bleibt, damit ist es nutzlos bei einem
   Rettungsversuch hat man wenigstens nochmal alles mögliche versucht."*
4. **Where it runs.** On the Pi itself, not as an image beside the team
   server. This overrides a written decision of this project; see
   Constraint 3.

---

## Goals

1. The implant collects the evidence it is uniquely placed to collect: what
   the host on the other side of the bridge does that works.
2. A widened move set, **ordered by cost**: observe, then borrow, then its
   own radio, then take an identity.
3. The evaluator runs on the device, fed by a local model, through the seam
   the decider design already left for it (`beacon.py:9628`).
4. Everything tried, and the evidence that drove it, is readable after the
   implant comes back.
5. `beacon.py` stays a single stdlib-only file. The dependency-heavy half
   lives in a separate process.
6. A run that reaches the loud rungs is a decision with a number behind it,
   not a fallthrough.

## Non-goals

- **A queue, a scheduler or a repair shell on the implant.** Ruled out by
  the human, in the same breath that set the scope.
- **A second brain.** No campaign, no orchestrator, no tools beyond the way
  out. The local model answers one question.
- **Reporting while dark.** The rescue record is already gone by the time
  the decider acts (`beacon.py:9486-9494`); a second record would make the
  channel periodic, which is the property a DNS tunnel is detected by.
- **Changing a leg's configuration at runtime.** Unchanged from the decider
  design: what is baked into a build stays baked.
- **Making `software/requirements.txt` grow.** The collector and the model
  client are their own requirements file, as the agent's are.

## Anti-goals

These would make the project a failure even if a rescue succeeded:

- **A rescue that starts loud.** The appetite says *never stop*; it does not
  say *start loud*. An irreversible move taken before the reversible ones
  were tried spends the cheap options along with the port.
- **A decision nobody can reconstruct.** A model that cannot be shown what
  it saw and what it answered is worse than a policy, because the policy at
  least names the rule that matched (`beacon.py:9628-9646`).
- **A model in `beacon.py`.** Not a style rule: that file is served to a
  target as source text, and an import there does not resolve
  (`beacon.py:5705-5711`).
- **An inference port reachable from the target segment.** The model exists
  for the implant's own decision; a listener on `0.0.0.0` would hand it to
  anyone on the network the implant is hiding in.
- **A "way out" that only looks like one.** No verb tests its own result
  today, and that is deliberate (`beacon.py:9242-9250`); a rung that claims
  success without carrying traffic would be a lie the operator cannot check.

---

## Constraints

### 1. `beacon.py` is served as source text and is stdlib-only

The rule, and its reason, are in the file: *"this file is served to a target
as source text and may import only the standard library"*
(`beacon.py:5705-5711`), and the rescue record is a **copy** rather than an
import for the same reason (`:1686-1692`). CI asserts the dependency
promise, and the plan files repeat it for every project that has touched
this file.

The consequence for this design is the whole architecture: the model and the
evidence collector cannot live in `beacon.py`. They live in a
separate process -- the scout, below -- and the beacon reads a file.

### 2. The device's budget is about 13 W, and inference on it has never been measured

Pi 4 Model B with **4 GB** (`README.md:144`), 32 GB SD card (`:146`), powered
over PoE from the switch port it taps (`:34-35`). The 802.3af budget at the
device is about **13 W** and has to cover bridging and capturing as well
(`docs/AGENT.md:482-483`, `hardware/OPEN_QUESTIONS.md:174-191`). Raspberry
Pi's own note on that class of HAT says it is *"not quite enough to power the
hungriest USB peripherals at the same time"*, and `OPEN_QUESTIONS.md:184`
adds: *"This board is that case."*

What a model costs on this hardware — watts, seconds, thermal headroom — is
**not measured anywhere in this repository**, and cannot be: there is no
device. `docs/AGENT.md:491-493` says a local link is allowed 300 seconds per
call against 120 for a hosted one, and that *"how much of that a Pi uses has
not been measured for this page."* `OPEN_QUESTIONS.md:20-22` says nothing has
been built or measured on a bench at all. Stage 1 therefore measures what a
container can measure and names what it cannot, and the power question is
carried as a named risk rather than as an assumption.

### 3. The cover identity argues against a model here, and that objection is overridden knowingly

`2026-11-08-agent-llm-providers-design.md:88-100` rejected *"a model on the
Pi whose job is to find the team server"* explicitly, so it would not be
re-guessed later. Its three arguments stand and are repeated here rather than
buried:

- it breaks the project's loudest promise (the stdlib beacon) — **this design
  answers that one**: the model is not in `beacon.py`;
- the weakest model in the system would own the decision with the least room
  for error, where every failed attempt is noise on a monitored network —
  **unanswered**, and the reason the rungs are ordered and gated;
- an unauthenticated inference server and a multi-gigabyte blob on a device
  built to look like an IP phone are *"the opposite of what the cover
  identity is for"* (`docs/AGENT.md:487-490`) — **unanswered**, and accepted
  by the human.

The override is theirs, it is recorded above in their words, and this
document does not pretend the objection was wrong.

### 4. There is no EV number for "raise a way out"

`tunnel` and `egress` are `TIER_HARD` to the campaign model
(`safety.py:1096-1099`), and a tier-1 row carries `points=0, p_success=0.0,
p_detect=0.0` because *"they are never weighed, only refused"*
(`safety.py:330-334`). So nothing in the risk table can price any of this.

New tier-2 rows are needed -- in a table of their own, see the correction
under *Where the arithmetic runs* -- and after the EV calibration amendment
the utility term is *the value of what the action unlocks*
(`safety.py:420-428`, `2026-11-02-ev-calibration-amendment.md:58-70`). With
the shipped profile — `risk_coefficient = 33`, `ev_threshold = 0`
(`config.py:652-659`), formula at `gate.py:361-363` — a rung is allowed when
`points * p_success > 33 * p_detect`. That inequality is where "quiet first"
becomes arithmetic instead of good intentions.

### 5. The evidence is five lines, and two of its flags are dead

`_egress_state` hands the evaluator one class per transport plus the flags
that are set (`beacon.py:9558-9584`). `dot1x_seen` and `portal_answered`
exist in the record, are rendered by the server, and **nobody sets them**:
a policy naming one is refused when it is read (`_EGRESS_DEAD_FLAGS`,
`beacon.py:1874`, `docs/EGRESS_DECIDER.md:165-168`). The project calls
widening this *"the one work that would make this decider much smarter"*.

`ProxyDiscovery` reads the **implant's own** environment, system settings,
PAC/WPAD and `px` (`beacon.py:2916-2917`). Nothing in `software/c2/` imports
the bridge tap; the tap writes captures for loot
(`software/sniffer/bridge_tap.py:55-61`). The host's working path is visible
and unused — measured, not assumed.

### 6. Nothing survives a cycle

The beacon holds no task queue: it fetches fresh each cycle, runs what came
back in that cycle, and a result it cannot send is **lost**
(`beacon.py:10387-10408`, `:10588-10620`). The only disk writes are
persistence artefacts. So a trail across stuck windows has to be built on
purpose, and the scout — which may write files — is where it belongs.

### 7. Python 3.9 exactly, on the implant side

CI asserts it (`.github/workflows/ci.yml:125`). The scout may use what its
own requirements file declares, but anything it shares with `beacon.py` is
3.9 syntax, stdlib only.

---

## Approaches

**A. Wider policy, no model.** Collect the new evidence, add the rungs, order
them in the operator's YAML. No blob, no listener, no watts; every decision
testable with a table-driven test. Its ceiling is real but further away than
it looks: it holds until a move needs to pick *which* of several candidates,
weighing evidence that did not exist when the policy was written.

**B. A model on the device, through the existing seam.** `_egress_decide`
takes a `state` dict and answers with a verb (`beacon.py:9628-9646`); the
decider design calls that *"the seam for stage B: a model replaces the
evaluator and nothing else — the verbs, the gate, the budget and the
reporting are already the parts that would bound a model."* The scout
collects the evidence, asks the local model, and publishes a recommendation
the beacon may read. Costs: Constraints 2 and 3, in full.

**C. A full agent on the device.** Rejected. It contradicts the human's own
narrowing, and it multiplies the forensic footprint for capabilities they
said they do not want on the implant.

**Chosen: B, built so that A is its first half.** Every part of A — the
evidence, the rungs, the gate rows, the trail — is needed by B as well, and
is testable without a model. The expensive half (the scout's model client,
Ollama on the Pi, the watt and second measurements) is last, and the system
is useful without it. If the measurements in Constraint 2 come back badly,
the project still has a decider that is strictly better than today's, and
the decision to stop there is informed rather than forced.

This is my call: the human said *"bau bitte durch"*, not *"stage it"*. I am
staging it because it is the only order in which the unmeasured risk sits at
the end instead of the beginning.

---

## The design

### What the device may see, and who collects it

A new process, `software/scout` (the name was the builder's), running on
the Pi from the same venv as `software/main.py` — which already imports
`scapy`, `yaml` and friends (`software/requirements.txt`,
`bootstrap.sh:84-86`). It collects, at a low rate and only while the beacon
is stuck:

| Evidence | From | What it feeds |
|---|---|---|
| The host's proxy: CONNECT requests, PAC fetches, WPAD lookups | the tap | borrow |
| The host's resolver, and whether its queries are answered | the tap | evidence only |
| The host's working TLS destinations (SNI, and that the handshake completed) | the tap | the test target a rung aims at |
| EAPOL frames on the port | the tap | sets `dot1x_seen` |
| HTTP redirects to a portal, and the portal's answer | the tap | sets `portal_answered` |
| Credentials already captured | loot | borrow |
| Visible SSIDs, and which are open | the Pi's radio | own radio |
| The host's MAC and IP | the tap | take identity |

**How it sees the traffic, and why not the obvious way.** The existing tap is
one `scapy.sniff(store=False)` on `br0` inside `main.py`, dispatching to pcap
rotators (`software/sniffer/bridge_tap.py:55-61`). The scout does **not**
read those pcaps — they may be encrypted at rest
(`sniffer.encrypt_captures`), which would make the evidence path depend on an
operator's storage choice — and it does **not** call into `BridgeTap`, which
would couple the C2 half to the sniffer that `beacon.py` deliberately does
not import. It runs its own narrow capture with a BPF filter for exactly
what the table above needs: EAPOL, DNS, HTTP `CONNECT` and redirects, and
TLS `ClientHello`. That is a second promiscuous reader on a 13 W device, so
its cost is part of what stage 1 measures — not only the model's.

**How it knows the beacon is stuck.** `_stuck_cycles` and `_rescue_answered`
are in-memory state of a *different process*: `raccoon-beacon.service` runs
`beacon_standalone`, `raccoon-implant.service` runs `main.py`. So the beacon
writes one small state file when a stuck window opens and when it closes,
and the scout reads it. **This is a new disk artefact on the implant, and it
is a cost, not a detail**: Constraint 6 says the beacon keeps nothing but
persistence artefacts, and this adds one. It is one line of JSON, it says
nothing about the team server, and it is removed when a leg delivers.

**Where the two files live.** Not `/tmp`: both units set `PrivateTmp=true`
(`services/raccoon-beacon.service:20`, `raccoon-implant.service:20`), so
each process would get its own private `/tmp` and the handoff would silently
never happen — the same isolation the existing `/tmp/.raccoon_beacon.pid`
already lives under. They live under the configured data directory.

A document older than the scout's publishing interval is ignored, so a dead
scout degrades to today's five lines instead of to a stale decision. The two
dead flags stop being dead as a side effect, which makes the existing policy
smarter whether or not stage 4 ever ships.

### The rungs, ordered by cost

The order is the design's backbone. **Rung 1 is evidence only — it has no
verb and no risk-table row.** An earlier draft had it "use the host's
resolver", which contradicted this project's own non-goal (a leg's
configuration stays as it was built) and would not have helped anyway: `dns`
is deliberately not in `_RESCUE_UPSTREAM` because it carries nothing *out*
(`beacon.py:1694-1700`). What rung 1 produces is the target a louder rung
aims at: a destination the host proves is reachable.

**1. Observe (no verb).** What the host proves works. Costs nothing, leaves
nothing of its own, and decides nothing on its own.

**2. Borrow.** The host's proxy, including answering a `407` with a captured
credential, and a captive portal answered as the host answered it.
Reversible. Leaves lines in logs a human *could* read: a proxy auth, an
account that locked out.

*Corrected by the build.* This paragraph named a third arm -- "DNS over
HTTPS through a resolver that answered" -- and it is **not built**, for a
reason this document already contains: every implementable reading of it
changes a leg's resolution path or its URL at runtime, which is this
project's own non-goal ("what is baked into a build stays baked"). The
evidence table above is the version that was right: the host's resolver is
*evidence only*. The scout collects it and publishes it; nothing moves on
it. A network that blocks plain DNS to the host's resolver but allows DoH
is therefore not helped by rung 2, and that is a known gap rather than an
oversight.

**3. Its own radio.** An open or guest SSID, which leaves the tapped port
altogether. There is **no wifi code in this repository today** — `--wifi` in
`build_image.sh` only seeds a headless first boot, and `wpa_supplicant`
appears in `software/` only as a *pattern the risk table watches*
(`safety.py:520`). So this rung is new work, and it is bounded: the onboard
radio only — a USB adapter is refused on the power budget
(`OPEN_QUESTIONS.md:184`) — a time-boxed association, and a **scoped** route
for the beacon's own traffic by source or mark. It must never take the
global default route: an implant that strands itself off the path it still
has is the predecessor design's hardest anti-goal. Rollback on failure is
part of the rung, not a follow-up.

**4. Take an identity — which already exists.** `software/nac_bypass.py`
does exactly this, in three phases: forward EAPOL so the downstream device
stays authenticated, learn its MAC, IP and the gateway's MAC from the
bridge, then originate the implant's own traffic under that identity while
still forwarding the victim's. It ships `enabled: false`
(`configs/raccoon.yaml:15-18`) and is started as a component of `main.py`.

So rung 4 is **a trigger, not an implementation**. The predecessor design
ruled a NAC verb out because *"a cross-process trigger is a mechanism this
repository does not have"* — this project introduces exactly that mechanism
for its own reasons, which is what makes the rung affordable. Two
consequences: on a build where the operator already set
`nac_bypass.enabled: true`, the identity is taken at boot and rung 4 is
**pre-spent** — the scout reads that config and offers the rung as already
taken rather than offering it twice. And this is still the rung that can
**turn the port off**: sticky MAC, port security or a NAC violation ends the
implant's connectivity for good, with nobody's hand on the device.

New verbs follow the existing ones in shape: an argument-taking verb that
does one thing and does not test its own result. `EGRESS_VERBS` grows
(`beacon.py:1850`), and the policy may order the set but not extend it —
unchanged from the decider design.

### Who decides, and how the beacon asks a model without importing one

`_egress_decide` keeps its signature and its narrowness. It gains one step:

1. read the scout's document, if it is fresh;
2. if it carries a recommendation for *this* evidence, take it;
3. otherwise evaluate the operator's policy, exactly as today.

The recommendation is produced by the scout on its own clock: it collects
evidence, asks the local model one question with the evidence and the
allowed rungs, validates the answer against `EGRESS_VERBS`, and publishes
it. The rung *ceiling* is deliberately **not** re-checked there: the
beacon's arithmetic refuses a rung the curve has not reached whether the
policy or the model proposed it, and a second copy of the curve in the
scout would be a second place for the ladder to be wrong. A model that answers something that is not
an allowed verb is a refusal, logged, not a crash — the same stance
`read_egress_policy` takes toward a rule naming a dead flag.

So the beacon never blocks on inference, never imports a client, and behaves
identically if the scout is absent. That is the property that keeps
Constraint 1 intact and makes the model optional at runtime as well as in
the plan.

### The gate, and the term that makes it move

The first draft of this section said `points` is the same for all four rungs
and the probability pair does the ordering. **That was wrong, and the
builder check caught it.** With `points` fixed and the priors written into
the table, `points * p_success > 33 * p_detect` is a *constant per rung*,
decided when the table is authored: either it is set high enough that the
loudest rung always passes, in which case the gate orders nothing, or low
enough that it never fires, which contradicts the appetite the human stated.
The term that varies on a server run — `effective_p_detect`, which climbs
with a campaign's detection count (`gate.py:72-74`, `:196-203`) — has no
analogue on a dark implant.

So the arithmetic needs a term that moves with the implant's own situation,
and there are two, both honest:

**`points` grows with time dark.** `points` is the value of what the action
unlocks (`safety.py:420-428`, `2026-11-02-ev-calibration-amendment.md:58-70`),
and that value is not constant: a channel restored in the first hour is worth
a check-in, and a channel restored after a week is the difference between an
operation and a dead device in a rack. The operator writes the curve in the
policy, with a default in code. This is the mechanism behind the human's
appetite — *"dunkel ist nutzlos"* — expressed as a number rather than as a
rule that fires.

**`p_detect` moves with the evidence.** `dot1x_seen` raises the identity
rung's detection probability, because a port that authenticates is a port
somebody configured and therefore watches. `portal_answered` lowers the
borrow rung's, because a network that redirects every browser sees
credential prompts answered all day. These are the two flags nobody sets
today, which is why widening the evidence and pricing the rungs are one
project rather than two.

Together: the quiet rungs are allowed almost immediately, the loud ones cross
the threshold later, and the evidence moves the crossing earlier or later.
The ladder is arithmetic, not a policy line an operator can invert.

**Where the arithmetic runs.** Not in `gate.Gate`: it needs a SQLite
connection, a `run_id`, an approvals table and an event loop
(`gate.py:258-307`), none of which exists on an implant with no channel.

*Corrected by the build:* the authority is `safety.WAY_OUT_TABLE`, a table
of its own beside `RISK_TABLE` rather than three rows inside it. Three
reasons, and they are about modelling rather than tidiness. `classify()`
turns a *command string* into a row and can never return one of these.
The server's gate cannot know how long an implant it cannot reach has been
dark, so it would price the benefit term wrongly -- and that term is the
whole mechanism below. And a row the server can never reach would still
appear in the operator's gate lists and in the *measured* "reachable
unattended" counts on `docs/AGENT.md`, making a measured claim false. The
copy-comparison test holds `beacon.py`'s copy against that table, which is
what this paragraph's intent asks for.

The three rows and the inequality are a **stdlib copy inside `beacon.py`**,
following the pattern this file already uses for the rescue record — *"a copy
and not an import, because the generator serves this file to a target as
source text"* (`beacon.py:1686-1692`) — and held against the real
`RISK_TABLE` by a copy-comparison test, the way `test_dns_rescue.py:360-424`
holds the record format. `risk_coefficient` and the threshold come from the
egress policy block with defaults in code, not from the agent's
`RISK_PROFILES`: a drop-box has no campaign configuration.

Both paths go through it. The policy evaluator and (in stage 4) the model
propose a rung; the arithmetic decides whether it may be taken. That is what
closes the hole the builder found in the earlier draft, where the no-model
fallback would have reached the loud rungs ungated.

Two further pieces, both existing machinery: a model's probability estimate
is advisory and clamped to ±0.2 around the prior
(`safety.clamp_llm_adjustment`, `:305-327`), and a decision that passed only
because of that override is marked, the way `override_decisive` marks it on
the server (`gate.py:376-389`), so the trail says which ones they were.

The campaign model's refusal does not change: `egress` and `tunnel` stay
tier 1 to it (`safety.py:1096-1099`). These rows price the *implant's own*
decision, which no gate covers today.

### Stopping, and the rung that can end the operation

The budget stays per stuck window and is spent **before** the attempt
(`beacon.py:9737-9741`), and the window closes when an upstream leg delivers.

**One mechanism orders the rungs, not two.** An earlier draft had both a
time-based rung ceiling in the policy *and* the gate's arithmetic, which
would have been two places to read and one to forget. The arithmetic above
does the ordering, because `points` already grows with time dark. What stays
in the policy is the curve's numbers, not the order.

What the ceiling kept, and the arithmetic does not express, is **how often**:

- Rung 4 is one-shot per deployment unless the operator re-arms it. A move
  that can turn the port off does not get retried on a hunch, however the
  arithmetic looks on the next cycle.
- A rung that was already taken outside this project is pre-spent, not
  offered again: `nac_bypass.enabled: true` means the identity was taken at
  boot, and the scout reads that rather than counting it as available. A
  consequence the build added: because that fact lives only in the scout's
  document, rung 4 is **not offered at all** without a fresh one. The safe
  answer to an unknown is not to make the one irreversible move.

Staying stopped means the same as today: the implant hands the decision back
rather than giving up, and the rescue record — if DNS ever answers again —
still reports a stuck implant.

### What the operator learns, and when

Nothing while dark; that is unchanged and deliberate. The scout keeps the
trail: one line per attempt with the evidence that drove it, the rung, the
verb and its argument, the gate's numbers, and whether the model or the
policy chose. It is readable on the device after recovery, and it is what
makes a burned implant a lesson instead of a mystery.

When a channel comes back, the first check-in carries what it always carries.
Whether the trail should be *fetched* by a verb is left to the builder: it is
loot, and loot has a path already.

### Which build this ships in

Drop-box only, like the decider (`docs/AGENT.md:1079-1085`): a generated
single-file build has no `raccoon.yaml`, no venv and no scout. The
generated build keeps exactly today's behaviour, which is also the honest
default — the expensive, loud capability exists only where somebody
provisioned a device for it.

---

## Stages

1. **Measure what a container can measure, and name what it cannot.** There
   is no device: the human has none, and a container is the bench. That
   splits stage 1 in two honest halves.

   *Measurable in a container, and fully:* the scout's capture and parse
   (CPU time per packet against a replayed capture), the document handoff,
   the beacon's fresh-or-ignore rule, the arithmetic, and whether a small
   model answers the question at all in a form the validator accepts.

   *Measurable only as a proxy:* latency. An arm64 container with `--cpus`
   and `--memory` limits approximates the Pi's four cores and 4 GB, but not
   an A72's clock — so every second it reports is **optimistic by a factor
   nobody here can pin down**, and the number goes in the plan as a bound,
   not as a result.

   *Not measurable at all:* watts and thermals. `OPEN_QUESTIONS.md:20-22` —
   *"Nothing has been ordered, built or measured on a bench"* — and a
   container cannot fix that. It is carried as a named risk below instead of
   being quietly assumed away.

2. **Evidence.** The scout, the tap-derived fields, the two dead flags
   alive, the document the beacon reads, the beacon's stuck-window state
   file, and the fresh-or-ignore rule. Policy still decides, and the loud
   rungs are not yet reachable.
3. **Rungs and gate.** The borrow and radio rungs, the rung-4 trigger into
   the existing `NACBypass`, the risk-table rows, the stdlib copy of the
   arithmetic in `beacon.py` with its copy-comparison test, the one-shot
   latch, and the trail. Still no model: the system is complete and useful
   at the end of this stage.
4. **The model.** The scout asks Ollama, validates the answer against the
   allowed verbs, publishes it. **Ships default-off**, and that is not
   timidity: without a device, nobody can say what inference costs on PoE,
   so the first operator to switch it on is the first measurement.

**Why the missing device does not block stage 4, and what it does cost.**
The beacon reads a file and ignores a stale one; it never calls the model and
never waits for it. A model too slow for the hardware therefore degrades to
the policy — the rescue still happens, with the decision today's evaluator
would have made — instead of blocking it. That property was chosen for
Constraint 1, and it happens to absorb the unmeasured latency as well. What
it does *not* absorb is power: inference drawing more than the 802.3af budget
leaves while the device is bridging is a hardware failure mode, not a
software one, and no architecture here makes it safe.

## Measurements

Taken 2026-11-27 with `tools/way_out_bench.py` in the bench this document
asks for: `python:3.9-slim` on `linux/arm64`, `--cpus 4 --memory 4g`, which
are the Pi 4 Model B's four cores and 4 GB. Rebuild and re-run it with

```
docker build -f tools/way_out_bench.Dockerfile -t raccoon-way-out-bench .
docker run --rm --platform linux/arm64 --cpus 4 --memory 4g \
    -v "$PWD:/repo" -w /repo raccoon-way-out-bench --json
```

**Every second below is an optimistic bound, not a result.** A
Cortex-A72's clock is not an aarch64 container host's, and nothing in the
bench is bridging a host's traffic, drawing from a 13 W PoE budget, or
sharing an IP phone's thermal envelope while it runs. The factor between
the two is not something anybody in this project can pin down.

### What the container measured fully

| What | Number | Reading |
|---|---|---|
| The scout's parse | **24.4 µs CPU per packet** over 4000 replayed frames | At 1000 packets/s through the filter that is about 2.4% of one core. Every row of the evidence table, TLS included, with a **distinct** destination, resolver and flow per round: the run read both flags, 256 resolvers, 256 TLS destinations and one credential, and ended with 333 unanswered CONNECTs still waiting. So this is the cost of reading at a real tap's cardinality -- the first version of this measurement replayed seven frames in a loop and reported 14.3 µs, which was the cost of the loop |
| The handoff | **1286 µs per write-and-read round**, 500 rounds | Includes an `fsync`, so it measures the bench's storage as much as the code. Against a 300 s beacon interval it is noise |
| The arithmetic | **4.9 µs per decision**, 500 rounds | The gate costs nothing worth naming |
| Fresh-or-ignore | all three rules hold: a fresh document is read, a stale one is ignored, one from the future is ignored | This is the property that makes a dead scout -- or a model too slow for the hardware -- harmless |
| The ladder's crossings | borrow at **1 h** dark, radio at **5 h**, identity at **7 h**; `portal_answered` moves borrow to **0 h**, `dot1x_seen` moves identity to **9 h** | Read out of `beacon.py`'s own numbers by the bench, not typed into it. The ladder is ordered, and the evidence moves the crossings in the directions the design argues for |

And what the bounds look like under that load: both published lists hit
their 256-entry ceiling and stayed there, and what was waiting for an
answer stayed two orders of magnitude below its 2048 ceiling. Before the
bounds the same 4000 frames left every one of those collections growing,
and 40,000 frames of ordinary traffic measured 400 MB resident.

### What it found that nobody was looking for

The **first** container run measured a *disabled* feature and reported
nonsense that looked plausible: the borrow rung crossing at hour 0, the two
loud rungs never crossing, and "a fresh document is read: **false**". The
cause is a rule of this design working exactly as written --
`read_way_out_policy` refuses a `state_dir` under `/tmp`, because both
implant units set `PrivateTmp=true` -- and `tempfile.gettempdir()` is
`/tmp` on Linux and `/var/folders/...` on the macOS machine where the bench
was written. So the bench now scratches outside `/tmp` and a test forces
that case rather than asking the host.

### The model, and what the validator took

`qwen2.5:0.5b` pulled by a stock `ollama/ollama` in a second arm64
container with the same limits, reached on **its own loopback** (the bench
runs in that container's network namespace, because the design allows no
other address).

Reproduce it with `--model-asks 12`, which is the flag this section needed
and did not have at first: the figures below are a ratio, and the command
written here asked once.

- **It answers, and fast enough:** **0.49 s to 3.34 s** per question over
  twelve asks. Against a 300 s beacon interval and a 900 s freshness
  window, a model this size is not the bottleneck. Optimistic bound.
- **The validator accepted eleven of twelve.** The one refusal was the
  failure every refusal in every run has been: the model answered with the
  whole menu line -- `"proxy -- use a proxy this host already found"` --
  instead of the verb. `validate` refused it by name, the scout logged
  why, and the beacon decided on its policy, which is the degradation this
  design relies on.
- **It never produced a `p_success`.** Twelve asks, no estimate. So the
  clamp and the `override_decisive` mark exist and are tested, and a model
  this size never exercises them.
- **It named `identity`.** Among the four verbs it chose across twelve asks
  -- `gsocket`, `identity`, `portal`, `rediscover` -- is the irreversible
  one, on evidence one hour old. The arithmetic refused it, which is
  exactly what both paths going through the gate is for, and it is the
  sharpest measurement here of Constraint 3's unanswered objection: the
  weakest model in the system reached for the move that can end the
  engagement, and what stopped it was a number and not the model.
- **Its reasoning and its verb disagreed at least once.** An earlier run's
  accepted answer named `rediscover` while its `why` argued for bringing up
  a relay leg, and this run's `why` fields are truncated mid-sentence. The
  verb is what the implant acts on, so the answers were usable.

**A bad result is a measurement.** Eleven of twelve is better than the
nine of twelve an earlier run measured and neither is a number this
document is pleased with. Both are an argument for the shape that was
chosen for another reason: a refused answer costs one log line and a
policy decision, not a rescue.

### What no container can measure

| | Why |
|---|---|
| **Watts** | There is no device. The 802.3af budget at the board is about 13 W and has to cover bridging and capturing too; a container draws from a wall socket. Stage 4 ships off because of this |
| **Thermals** | There is no device. A Pi 4 in an IP-phone-shaped enclosure under sustained inference is a hardware question, and a container shares its host's cooling |

Both stay in the risk table below rather than being assumed away.

## Risks, and what each would look like

| Risk | What it looks like | What this design does about it |
|---|---|---|
| The model is too slow on real hardware | The scout's document is always stale; the trail has only policy decisions | Nothing needed: the beacon degrades to the policy. The cost is the effort of stage 4, not a failed rescue |
| Inference exceeds the PoE budget | A Pi that resets, throttles, or drops the bridge while the scout runs — on a device nobody can reach | Stage 4 is default-off and the risk is written here. The first deployment that enables it is an experiment and should be one that can be power-cycled |
| The second capture reader costs too much CPU while bridging | Dropped packets in the tap, or a visibly slower bridge | Measured in stage 1's functional half, which a container does honestly. If it is too expensive, the BPF filter narrows or the scout samples |
| The blob and the inference port are a forensic artefact | An IP phone with several gigabytes of model on disk and a listener with no authentication | Accepted by the human, over this project's written objection (Constraint 3). The listener binds loopback only; the blob has no mitigation |
| A rung succeeds and the channel still does not carry | A verb that reports success while the implant stays dark | Unchanged from the decider: no verb tests its own result, and the next cycle's evidence is the only verdict |
| Rung 4 kills the port | A device that never returns | One-shot until re-armed, last in the arithmetic, and the human chose this trade explicitly: dark is useless |
| **The tap's evidence is written by an adversary** | A defender who suspects a tap plants frames: a `Proxy-Authorization` naming their host, a redirect and a POST naming their canary URL. The implant then routes its C2 through them, or identifies itself to them -- and the same frames set `portal_answered`, which *lowers* the borrow rung's `p_detect` and moves its crossing to hour zero | **Added after the build, and it is a gap in this document rather than in the code it describes**: every paragraph above treats "what the host proves works" as ground truth, and it is unauthenticated frames. The build narrows both arms -- a credential needs a `407` on an earlier `CONNECT` to the same proxy; a portal needs a private or link-local address, or a name, with a capped body, and the whole redirect/POST/2xx sequence on one flow. What is left is a portal **named** rather than addressed: an implant that cannot resolve a name cannot check where it points, so a forger who names their canary gets one replayed POST. Stated in `docs/WAY_OUT.md` |
| **The scout outlives its own memory** | A tapped host at ordinary rates fills the evidence for as long as the outage lasts -- the worst case here is a week -- and the OOM killer takes the scout, the sniffer or the beacon | Every container is bounded: 256 published entries, 2048 waiting for an answer, oldest evicted. The CPU row above used to say this was measured in stage 1, and it was not: the bench replayed seven frames in a loop, so nothing ever grew. The bench now generates distinct destinations and reports what is waiting |

## What is left to the builder

- The scout's name, module path and systemd unit, following the three
  existing units (`services/install.sh:30-38`).
- The document's exact schema and its publishing interval, within "fresh or
  ignored", and the same for the beacon's stuck-window file.
- The BPF filter's exact expression, and whether the scout parses TLS
  `ClientHello` itself or leans on `scapy`'s layers.
- Whether rung 2's credential source is the loot store directly or a
  narrower file the scout maintains.
- Which small model to pull, and whether its name's size suffix matters here
  the way it does for the agent's capability tier (`provider.py:440-452`).
- Whether the trail is its own file or lines in the scout's log.
- The default numbers for the `points` curve and the two evidence
  modifiers, within the shape above.

## The decisions behind this document

- **Staging, with the measurement first.** Mine. The human asked for the
  whole thing; the order puts the unmeasured risk last and leaves three
  stages that stand on their own.
- **A container as the bench, and the model half default-off.** Theirs that
  there is no device (*"ich habe kein gerät zur Hand dafür war der Docker
  Container gedacht"*); mine what follows from it: stage 1 splits into what
  a container measures honestly, what it can only approximate, and what it
  cannot touch at all. The power question stays open in the risk table
  instead of being answered by a number from the wrong machine.
- **The model outside `beacon.py`, reached through a file.** Mine. It is the
  only shape that keeps the stdlib promise *and* never makes the beacon wait
  on inference.
- **`points` that grows with time dark, and `p_detect` that moves with the
  evidence.** Mine, and it replaces a wrong first draft in which the
  inequality was a constant per rung and ordered nothing. The builder check
  found that; it is recorded rather than quietly fixed.
- **The arithmetic as a stdlib copy in `beacon.py`, with both paths through
  it.** Mine. `gate.Gate` cannot run on a dark implant, and a gate that only
  the model path honoured would have let the policy path reach the loud
  rungs.
- **Rung 1 is evidence, not an action.** Mine, correcting a draft that had
  it repoint the resolver — which this project's own non-goal forbids and
  which would not have carried anything out anyway.
- **Rung 4 triggers the existing `nac_bypass.py`.** Mine, after the builder
  check found it. The predecessor design ruled a NAC verb out for want of a
  cross-process trigger; this project builds that trigger for its own
  reasons, which is what makes the rung affordable.
- **Rung 4 one-shot until re-armed, and pre-spent when the operator already
  enabled the bypass.** Mine. It is the only move here that cannot be undone
  from the far side.
- **The scout captures for itself rather than reading the pcaps or calling
  into `BridgeTap`.** Mine: encrypted captures would make the evidence path
  depend on a storage setting, and a callback would couple the C2 half to
  the sniffer.
- **A new disk artefact on the implant** — the beacon's stuck-window file.
  Mine, and named as a cost in the design rather than left to be discovered.
- **A model on the implant at all.** Theirs, over a written objection of this
  project, recorded in Constraint 3 with the objection intact.
- **No queue, no scheduler, no local shell.** Theirs.
