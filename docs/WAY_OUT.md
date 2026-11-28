# A way out the implant finds for itself

When a dropped implant cannot reach its team server, the thing that normally
decides what to try next sits on the far side of exactly the connection it is
trying to establish. [`docs/EGRESS_DECIDER.md`](EGRESS_DECIDER.md) closed half
of that hole: the implant chooses one of the verbs it already has for
itself, from a policy you write — three of them, before this page's four.

This page is the other half. It widens what the implant can *see* — it is an
inline tap between a switch port and a host, so it can watch what gets out of
that host and works — and it replaces your ordering of the moves with an
inequality that moves with how long the implant has been dark and with what
the tap found. The quiet moves are allowed almost immediately. The loud ones
are not available until the arithmetic says so, and you cannot write a policy
line that inverts that.

**Read all of this before you switch it on.** The last rung takes the
downstream host's MAC and IP. On a port with sticky MAC, port security or a
NAC posture check, that ends this implant's connectivity **for good**, with
nobody's hand on the device. The human who asked for this chose that trade
explicitly — *a dark implant is useless; at least a rescue attempt tried
everything* — and the point of the ladder below is that the implant reaches
that move last and only once.

**Drop-box only.** A build the team server generates is a single file with no
`raccoon.yaml`, no venv and no scout, so it carries none of this and behaves
exactly as it does today.

---

## The ladder

Four rungs, in order of what each costs you if it is noticed. **Rung 1 has no
verb at all**: what it produces is the target a louder rung aims at.

### 1. Observe — no verb, no risk-table row

A second process, the **scout** (`software/scout/`, started by
`services/raccoon-scout.service`), runs its own narrow capture on the bridge
while the beacon is stuck. Five protocols, one BPF filter, and nothing else:

| What it watches | What it feeds |
|---|---|
| EAPOL frames on the port | sets `dot1x_seen` |
| HTTP redirects to a portal, and whether the host got **past** one | sets `portal_answered` |
| `CONNECT` requests, PAC fetches, WPAD lookups | the borrow rung |
| Plaintext proxy credentials | the borrow rung |
| The host's resolver, and whether its queries are answered | evidence only |
| TLS destinations whose handshake completed | evidence only |
| Visible SSIDs, and which are open | the radio rung |
| The host's MAC and IP | the identity rung |

It is quiet on a healthy implant: it captures nothing, scans nothing and
publishes nothing until the beacon says a stuck window is open. That matters
because this is a *second* promiscuous reader on a device whose whole power
budget is about 13 W and which is already bridging and capturing. While the
beacon *is* stuck it publishes on a clock — half the freshness window, 450
seconds with the shipped numbers — and scans the radio at most once per
publish, because a device shaped like an IP phone that scans for wireless
networks four times a minute for ever is its own detection signature.

**This evidence is written by anybody on the tapped segment.** It is not
what the host proves; it is what frames on a wire say, and a defender who
suspects a tap can write them. Two of the rungs act on it, so both are
narrowed:

- all of it is read only from frames whose sender is the **host behind the
  tap**, and which addresses those are is read off the bridge's own
  forwarding table (`bridge fdb show br <bridge> dev <downstream>`) — the
  kernel's record of what it has actually seen on the port the host is on,
  re-read on every publish because a bridge learns and ages entries while
  the implant is dark. Only when that cannot be read at all does the scout
  fall back to the first request it sees;
- a credential is borrowed only from a `CONNECT` to a proxy on this
  network that **answered `407`** on an earlier `CONNECT` of its own — the
  rung answers a refusal, so the refusal has to have happened;
- a captive portal is recorded only at a **private or link-local address**,
  or at a name, with a body capped at 4 kB, and only after the whole
  sequence — a redirect, a POST on one flow, and a 2xx on that same flow.

What is left is a residual risk and it is stated rather than implied, and
it is larger than an earlier version of this page admitted. Asking the
bridge narrows **which MAC counts** — a stranger's address is refused
however many frames it sends, so the implant can no longer be made to
anchor on the first thing that speaks. It does **not** narrow **who may
send that MAC**: the scout is handed frames captured on the bridge,
nothing in that pipeline knows which interface a frame arrived on, so
anybody who copies the host's source address off the wire still passes,
from either side of the tap. Answering that would need a direction-aware
capture on the downstream interface, which this does not do. And a portal
**named rather than addressed** cannot be checked by an implant that
cannot resolve names, so a forger who names their canary `portal.example`
and plants all three frames on one flow gets one replayed POST — and sets
`portal_answered`, which moves the borrow rung's crossing earlier. Both
flags the tap sets reach the operator's panel, so a forged one is a false
bit in a record somebody reads. The design's risk table carries that row.

Every container the scout keeps is bounded — 256 published entries and 2048
waiting for an answer — because it runs for as long as the outage does, and
the design's own worst case for an outage is a week.

`dot1x_seen` and `portal_answered` used to be dead — in the rescue record's
format, rendered by the team server, and set by nothing. This is what makes
them live, so a policy rule may finally name one.

### 2. Borrow — what the host proves works

| Verb | What it changes |
|---|---|
| `egress rediscover` | looks for a proxy on this host again |
| `egress proxy <index\|url>` | makes a discovered proxy the active one |
| `egress gsocket` | brings the relay leg up now |
| `egress credential [index\|account]` | posts through the proxy the host uses, as an account the tap saw in the clear |
| `egress portal` | replays the captive-portal answer the host got past |

Reversible, and it leaves lines in logs a human *could* read: a proxy auth, an
account that locks out. The credentials live in a `0600` file of their own and
never in the document the beacon reads every cycle; the verb's answer names
the account and the proxy and never the password.

**And not from a previous outage.** The scout removes that file when a stuck
window closes, so the only way a stale one survives is a scout that died in
an earlier outage with its capture still on disk — and the beacon refuses a
borrow file written before the open window began, by the window's own stamp
rather than by a second age setting. A scout that dies *during* an outage
costs nothing here: its capture is this outage's, and the rung still works.
`egress credential` typed by hand is not second-guessed; with no window open
there is nothing to compare against, and the operator has already decided.

**The DNS arm is not built.** An earlier draft of the design had "DNS over
HTTPS through a resolver that answered" on this rung. Every implementable
version of it changes a leg's URL or its resolution path at runtime, which
this project forbids: what is baked into a build stays baked. The resolver
evidence is still collected, and nothing acts on it. A network that blocks
plain DNS to the host's resolver but allows DoH is not helped by this rung.

### 3. Its own radio — off the tapped port altogether

`egress radio [ssid]` associates with an **open** SSID the scout saw and
routes this implant's own traffic through it. Three bounds, all in code:

- **The onboard radio only.** A USB adapter is refused by name on the power
  budget: 802.3af gives the board about 13 W and it is already bridging and
  capturing, and Raspberry Pi's own note on that class of HAT says it is not
  quite enough for the hungriest USB peripherals.
- **A deadline per command**, because this runs on the beacon's own thread
  and a `dhclient` that never returned would cost the implant its loop.
  It is **not** a time box on the association: nothing *times out* of the
  network, so once this rung succeeds the implant stays on it until the
  device is restarted or the rung is rolled back — a rollback is the one
  thing that disassociates, and it runs only when a step of the rung
  fails. The design said "a time-boxed association"; that was not built,
  and this is the limit instead.
- **A scoped route, never the default one.** The route goes into table `100`
  with a source rule for the address DHCP gave, so the host's own default
  route is untouched. DHCP runs with `-sf /bin/true` and the lease is parsed
  by the implant, because dhclient's own script installs a default route —
  the one thing this rung may never do. An implant that stranded itself off
  the path it still has is the worst outcome available here.
- **And the implant's own sockets are bound to that address**, which is what
  makes the rule mean anything: `ip rule from <address>` matches only
  packets whose source *is* that address, and a locally-generated connection
  has no source until something binds it. Without the bind the rung
  installed a route nothing could ever select and reported that it had
  changed how the implant gets out. Every HTTP session the beacon builds,
  the hop an NTLM relay makes to its upstream proxy, and every DNS query
  the beacon composes itself leave by the leased address — and they keep
  doing so after a leg delivers, because a leg delivering while the bind
  holds is the moment this rung is *working*. A rollback is what unbinds.
  Three things are **not** bound, and they are named rather than implied: a
  forward to `127.0.0.1`, because its peer is on this host and no source
  rule can match it; `wpad` name lookups during proxy discovery, which go
  through the system resolver and it takes no source address; and the
  gsocket carrier, because `gs-netcat` is a **child process** and a
  parent cannot bind its sockets — so `egress gsocket` while the radio
  holds a lease starts a relay that dials out of the tapped port. The
  verb says so in its answer.

Repeating the rung is the ordinary case — no verb tests its own result — so
`ip addr replace` and `ip route replace` are used rather than `add`, and the
source rule is deleted before it is added. Nothing flushes the interface: a
management address an operator keeps on the onboard radio is not this rung's
to delete.

A failure at any step rolls back every step it took, and says so.

### 4. Take an identity — once per deployment

`egress identity` asks this host's **own main process** to start
`software/nac_bypass.py`, which forwards EAPOL so the downstream device stays
authenticated, learns its MAC, IP and the gateway's MAC from the bridge, and
then originates this implant's traffic under that identity. The beacon and
that component run in different processes, so the request is one file under
the state directory and `software/main.py` polls it.

- **Once per deployment.** A leg delivering does not re-arm it, and a restart
  of the beacon does not either: the request file on the disk is the latch,
  not a flag in memory. Re-arming means a new deployment — or deleting
  `way_out_identity.json` from the state directory by hand, which is the only
  way back and is written here because nothing else says it.
- **And it survives a restart of the implant.** `software/main.py` stops its
  components on shutdown, which puts this implant's own MAC back on the
  bridge — so a reboot, a config change or a `systemctl restart` used to
  release the identity while the latch kept the rung spent: all of the
  irreversible cost and none of the benefit. The request file records that
  the bypass was actually started, and the next run of that process restores
  it. Going back to this implant's own MAC is also the *louder* of the two
  states on a port with sticky MAC: a second address on a port that has seen
  one is what a NAC violation is.
- **Already spent when you enabled the bypass yourself.** With
  `nac_bypass.enabled: true` the identity was taken at boot, and the rung is
  not offered again.
- **Not offered at all without a fresh scout document**, because that is where
  the pre-spent fact lives. The safe answer to an unknown is not to make the
  one irreversible move.
- **It can turn the port off.** Sticky MAC, port security or a NAC violation
  ends this implant's connectivity **for good**.

---

## The arithmetic you cannot invert

Every rung is priced with the expected-value check the team server's gate
uses:

```
points(hours dark) × P(success)  >  risk coefficient × P(detect)
```

`points` is the value of what the move unlocks, and that value is not
constant: a channel back in the first hour is worth a check-in, and a channel
back after a week is the difference between an operation and a dead device in
a rack. So it **grows with time dark**, from the beacon's own stuck-cycle
count and not from a clock an implant with no channel cannot trust: `20` to
start, `5` per whole hour, capped at `100`.

`P(detect)` **moves with the evidence**. `dot1x_seen` raises the identity
rung's by `0.15`, because a port that authenticates is a port somebody
configured and therefore watches. `portal_answered` lowers the borrow rung's
by `0.10`, because a network that redirects every browser sees credential
prompts answered all day.

With the shipped numbers — risk coefficient `33`, threshold `0` — that is:

| Rung | P(success) | P(detect) | Allowed from |
|---|---|---|---|
| borrow | 0.5 | 0.35 | **1 hour** dark — or **0 hours** with `portal_answered` |
| radio | 0.4 | 0.5 | **5 hours** dark |
| identity | 0.5 | 0.8 | **7 hours** dark — **9 hours** with `dot1x_seen` |

Those hours are not typed into this page twice: a test computes them from the
implant's own code and fails if the page and the code disagree.

Every number in that block is floored or bounded so that none of them can
make the gate meaningless: `points_per_hour` below 1 would close it for
ever — including for the three verbs that worked before this existed — and
`risk_coefficient: 1` or a very negative `ev_threshold` would open the
irreversible rung on the first cycle the decider may act. The two modifiers
are checked for **direction** as well as range: `dot1x_detect` may only
raise and `portal_detect` may only lower, because one legal sign put rung 4
two hours ahead of rung 3.

**And the order is enforced, not merely arranged.** A louder rung is
refused until every quieter rung has crossed on the table's own priors —
so neither a configured number nor a model's estimate can offer you rung 4
before rung 3 was available. That rule is here because the arithmetic alone
did not keep the promise: see the clamp below.

`points` is floored by the **cycle count** as well as by the clock: a cycle
is worth at most one step of the curve, whatever `beacon_interval_seconds`
says. Without that, a long interval made two stuck cycles read as two days
dark and handed the irreversible rung the first cycle the decider may act —
so the ladder needs elapsed time *and* repeated failure, and you cannot buy
a loud rescue with a number in a file.

**Switching this on costs the borrow rung its first hour.** With
`c2.way_out` off, the three verbs the decider has always had fire on the
first cycle the decider may act. With it on they are priced like everything
else, so the first attempt waits for the curve — one hour dark, **twelve
cycles** at the shipped 300-second interval. A portal the host got past buys
that hour back. It is the same shape as the decider's own one-cycle cost,
and it is the price of the ladder.

**Both paths go through it, and a refusal is not the end of the cycle.**
Your policy's choice and the model's recommendation are both proposals; the
arithmetic decides whether each may be taken, and when it refuses one the
**next** candidate of that cycle is tried — the model's answer first, then
your rules in your own order. So a policy whose first matching rule is loud
does not silence the quiet rules below it, and a model that keeps naming
`identity` falls back to your policy rather than taking the cycle with it. A
refused rung costs no budget, and every refusal is logged with its numbers. A recommendation may also carry an **argument** — which SSID,
which account — and it is passed to the verb; one with whitespace in it is
dropped, because the task string is split on whitespace and a model wrote
that string.

A model may propose its own `P(success)`. It is clamped to ±0.2 of the
built-in prior, and it can move a crossing earlier within that latitude —
that is what it is for. What it cannot do is **reorder the ladder**: a rung
is refused until every quieter rung has crossed on the table's own priors,
whatever the model says about the one it named, so the clamp bounds the
probability and this bounds the order. Without that rule an estimate of
0.99 on `identity` moved rung 4 from hour 7 to hour 4 while rung 3 stayed
at hour 5 — the irreversible move offered before the implant had ever been
allowed to try its own radio. A decision that passed *only* because of the
override is marked as such in the trail, and a refusal names the quieter
rung that is still holding it back.

## The block you write

```yaml
c2:
  way_out:
    enabled: false
    # The beacon and the scout meet here; the table further down says
    # which six files this puts on the disk. NOT under /tmp:
    # both implant units set PrivateTmp=true, so each process would get its
    # own and the handoff would silently never happen. The reader refuses a
    # /tmp path by name.
    state_dir: "/opt/raccoon/state"
    # A scout document older than this is ignored, so a dead scout degrades
    # to the five lines of evidence the decider already had.
    document_max_age_seconds: 900
    points_per_hour: 5
    points_max: 100
    risk_coefficient: 33
    ev_threshold: 0
    dot1x_detect: 0.15
    portal_detect: -0.10
    model:
      enabled: false
      endpoint: "http://127.0.0.1:11434"
      name: ""
      timeout_seconds: 120
```

It ships **off**, and it is validated whether it is on or not, so a typo
surfaces now rather than on the stuck cycle it would have fired. A rule in
`c2.egress_decider` that names `dot1x_seen` or `portal_answered` on a build
where this block is off is a rule that can never match: the beacon says so in
its log and keeps your numbering rather than dropping the rule.

## The model half, and why it ships off

With `model.enabled: true` the scout asks a model on **loopback only** one
question — here is the evidence, here are the moves, which one — validates the
answer against the verbs the implant actually has, and publishes it. The
beacon never calls the model and never waits for it: it reads a file, and
ignores a stale one. So a model too slow for this hardware degrades to your
policy rather than blocking the rescue.

**It ships off, and that is not timidity.** What inference costs on a Pi
powered over PoE — watts, seconds, thermal headroom — **is not measured
anywhere in this repository and cannot be: there is no device.** The first
operator to switch it on is the first measurement, and it should be a
deployment that can be power-cycled.

What *was* measured, in an arm64 container with `--cpus 4 --memory 4g`, is in
the design's *Measurements* section. In short: the scout's parse costs about
**24 µs** of CPU per packet at a real tap's cardinality, the handoff about
**1 ms** per write-and-read round — an `fsync`, so that number is the bench's
storage as much as the code, and it moved between 0.7 and 1.3 ms across runs
— the arithmetic about **4 µs** per decision, and a real `qwen2.5:0.5b`
answered in **0.49–3.34 seconds**. The validator took **eleven of twelve**
answers in the run recorded there, and **nine of twelve** in an earlier one;
both numbers are kept, because the refusal is the point: it costs one log
line and a policy decision, not a rescue. The model also named `identity` —
the irreversible rung — on hour-old evidence, and the arithmetic refused it.
**Every second there is an optimistic bound, not a result** — a container is
not a Cortex-A72 under a 13 W budget — and watts and thermals are named as
not measurable rather than assumed away.

## What you learn, and when

Nothing while the implant is dark; that is unchanged and deliberate. Each
attempt is one line in the beacon's log, as the decider's already are, and
the beacon keeps a **trail**: one line per attempt with the evidence that
drove it, the rung, the verb and its argument, the gate's numbers, and
whether your policy or the model chose. It is written at the moment the
attempt is made and it outlives the stuck window, which is what makes a
burned implant a lesson instead of a mystery. (The scout kept it at first,
copying lines on its own clock — which lost every attempt made in a window's
last interval, and on a recovered implant that is the attempt that worked.)

```
cat /opt/raccoon/logs/raccoon.log
cat /opt/raccoon/state/way_out_trail.jsonl
```

The trail holds no password: a line names the verb, its argument, the rung
and the gate's numbers. The one file that *does* hold one — a proxy
credential the scout took off the wire — is `way_out_borrow.json`, and **the
scout is the only thing that deletes it**: it does so when the window
closes, so in the ordinary case a captured password does not outlive the
outage it was captured for. A scout that is killed, OOM-killed or whose
unit gave up leaves that file on the disk until somebody reimages the
device, and the beacon's own guard against replaying it — a capture older
than the open window — is written precisely because that happens. If you
pull a device for any reason, that file is the one to look for.

**What this puts on the implant's disk**, under `state_dir`, 0600 in a 0700
directory — six files and not the "two" an earlier draft of this page
claimed, because the forensic footprint of a device built to look like an IP
phone is the one number that has to be right:

| File | Written by | What it is |
|---|---|---|
| `way_out_state.json` | the beacon | the open stuck window: how long, on what evidence, and how much of the budget it has spent; removed when a leg delivers |
| `way_out_scout.json` | the scout | the handoff: the tap's reading, and a recommendation if the model is on; removed when the window closes |
| `way_out_borrow.json` | the scout | the credentials and the portal request — the only one that can carry a secret, and removed when the window closes |
| `way_out_trail.jsonl` | the beacon | the trail, append-only, which outlives the window |
| `way_out_identity.json` | the beacon | rung 4's request, and what came of it |
| `way_out_radio.lease` | `dhclient` | rung 3's lease, which a later rollback reads to undo a rule it did not install |

The directory's mode is enforced on every write, not only when it is
created, and a symlink in place of any of these is refused rather than
written through. Rung 4's request is acted on only if it is owned by this
process's own uid and not writable by anyone else — write access to this
directory would otherwise be write access to the one irreversible move. A
*root* attacker on the implant host owns the device and nothing here
changes that.

## See also

- [`docs/EGRESS_DECIDER.md`](EGRESS_DECIDER.md) — the policy this widens, and
  the three verbs it started with.
- [`docs/LISTENERS.md`](LISTENERS.md#the-fifth-transport-gsocket-over-the-gsrn)
  — the gsocket carrier the `gsocket` verb brings up.
- [The design](superpowers/specs/2026-11-27-implant-way-out-design.md) — the
  rungs, the arithmetic, the measurements, and the objection to a model on
  this device that the human overrode knowingly.
