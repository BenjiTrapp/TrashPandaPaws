# A way out the implant finds for itself

When a dropped implant cannot reach its team server, the thing that normally
decides what to try next sits on the far side of exactly the connection it is
trying to establish. [`docs/EGRESS_DECIDER.md`](EGRESS_DECIDER.md) closed half
of that hole: the implant chooses one of three verbs for itself, from a policy
you write.

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
budget is about 13 W and which is already bridging and capturing.

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
- **Time-boxed.** Every command has a deadline, because this runs on the
  beacon's own thread.
- **A scoped route, never the default one.** The route goes into table `100`
  with a source rule for the address DHCP gave, so the host's own default
  route is untouched. DHCP runs with `-sf /bin/true` and the lease is parsed
  by the implant, because dhclient's own script installs a default route —
  the one thing this rung may never do. An implant that stranded itself off
  the path it still has is the worst outcome available here.

A failure at any step rolls back every step it took, and says so.

### 4. Take an identity — once per deployment

`egress identity` asks this host's **own main process** to start
`software/nac_bypass.py`, which forwards EAPOL so the downstream device stays
authenticated, learns its MAC, IP and the gateway's MAC from the bridge, and
then originates this implant's traffic under that identity. The beacon and
that component run in different processes, so the request is one file under
the state directory and `software/main.py` polls it.

- **Once per deployment.** A leg delivering does not re-arm it. Re-arming is a
  new deployment.
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

**Both paths go through it.** Your policy's choice and the model's
recommendation are both proposals; the arithmetic decides whether the move may
be taken. A rung it refuses costs no budget, and the refusal is logged with
its numbers.

A model may propose its own `P(success)`. It is clamped to ±0.2 of the
built-in prior, so it cannot talk the implant onto a rung the curve has not
reached, and a decision that passed *only* because of the override is marked
as such in the trail.

## The block you write

```yaml
c2:
  way_out:
    enabled: false
    # The beacon and the scout meet over two files here. NOT under /tmp:
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
14 µs of CPU per packet, the handoff about 700 µs per round, the arithmetic
about 3 µs per decision, and a real `qwen2.5:0.5b` answered in 0.26–3.44
seconds with the validator accepting nine of twelve answers. **Every second
there is an optimistic bound, not a result** — a container is not a
Cortex-A72 under a 13 W budget — and watts and thermals are named as not
measurable rather than assumed away.

## What you learn, and when

Nothing while the implant is dark; that is unchanged and deliberate. Each
attempt is one line in the beacon's log, as the decider's already are, and the
scout keeps a **trail**: one line per attempt with the evidence that drove it,
the rung, the verb and its argument, the gate's numbers, and whether your
policy or the model chose. It outlives the stuck window, which is what makes a
burned implant a lesson instead of a mystery.

```
cat /opt/raccoon/logs/raccoon.log
cat /opt/raccoon/state/way_out_trail.jsonl
```

The trail holds no password: the credential verb's line names the account.

## See also

- [`docs/EGRESS_DECIDER.md`](EGRESS_DECIDER.md) — the policy this widens, and
  the three verbs it started with.
- [`docs/LISTENERS.md`](LISTENERS.md#the-fifth-transport-gsocket-over-the-gsrn)
  — the gsocket carrier the `gsocket` verb brings up.
- [The design](superpowers/specs/2026-11-27-implant-way-out-design.md) — the
  rungs, the arithmetic, the measurements, and the objection to a model on
  this device that the human overrode knowingly.
