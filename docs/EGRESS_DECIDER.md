# The egress decider

When a dropped implant cannot reach its team server, the thing that normally
decides what to try next is on the team server. `software/agent/tools/egress.py`
reads the beacon's rescue record and queues one next attempt — a good design
with one hole in it: it sits on the far side of exactly the connection it is
trying to establish. The loop closes only while DNS answers and somebody, or
some model, is watching.

The egress decider closes it for the case where neither is true. From the same
evidence the rescue record carries, the implant decides for itself, inside a
boundary it cannot leave. It is for one thing only: getting a connection back
to the team server after the device has been dropped. It has no other job, and
the whole safety argument rests on that being structurally true rather than a
matter of intent.

This page is for the operator who configures it in `c2.egress_decider` of
`configs/raccoon.yaml`. Read it before you enable the block, because every
rule in it is an action the implant takes with nobody watching.

---

## What it may never do

The decider chooses from exactly three verbs: select a discovered proxy
(`proxy`), re-run proxy discovery (`rediscover`), or bring the gsocket carrier
up now (`gsocket`). That set is fixed **in code**, in `beacon.py`, and your
policy cannot widen it — configuration chooses from these three and orders
them, and **cannot add to it**. A `raccoon.yaml` somebody pasted in from a
ticket cannot authorise a new class of action, because there is nothing in the
file that the gate reads. These four things are refused always, whatever the
policy says:

- **It may never `sleep`.** This is the pointed one. `sleep` is the only verb
  the server-side model has for a stuck beacon — on the team server, where an
  operator is present to be asked whether an implant should slow its check-ins.
  The implant's own decider may never use it: a thing that can slow its own
  check-ins with nobody to ask can talk itself into silence. So the two
  deciders are not equivalent, and that is deliberate.
- **It may never disable or deprioritise a leg.** Disabling or deprioritising
  a leg weakens the chain of transports that got the evidence the decider
  reads, and blinds the next cycle.
- **It may never touch persistence, the watchdog or the tunnel.** None of them
  is connection establishment, and all three are how a dropped device is
  recovered. An autonomous action against any of them is an implant making
  itself harder to get back.
- **It may name no other verb.** The allowed set is a list, not a judgement. A
  policy that names a verb the implant does not have is refused when the block
  is read, with the verb in the message.

The gate is in code and not in config for the reason above: configuration that
could add to the set would make the gate decoration. What the file does is
narrow — choose from the three, order them, and give each a condition.

## The policy you write

A rule is a condition (`when`) and a verb to try (`try`). The first rule whose
condition holds, and whose verb this build can actually run, is the single
attempt made that cycle. One attempt per cycle, never a sweep — a dozen
attempts from a device impersonating an IP phone is louder than the one short
query that reported the problem.

```yaml
c2:
  egress_decider:
    enabled: false
    # At most this many autonomous attempts per stuck window. The window
    # closes, and the budget refills, when any upstream leg delivers.
    budget: 3
    rules:
      - when: {https: [auth_required, http_status]}
        try: rediscover
      - when: {flags: [proxy_found]}
        try: proxy
      - when: {any: [timed_out, unreachable]}
        try: gsocket
```

A `when` key is a transport name (`https`, `dns`, `smb`, `quic`, `gsocket`),
`flags`, or `any`. A transport names the rescue classes that leg may carry
(`auth_required`, `timed_out`, `unreachable`, `tls_failed`, and the rest in
`dns_rescue.py`); `any` is "any transport carrying one of these classes";
`flags` is the record's flag byte. Several keys in one `when` all have to hold,
which can only narrow a rule — the reading that cannot surprise somebody who is
not there to be surprised. A value may be one name or a list of them, and a
list means "any of these".

**Two flag names are refused, not accepted.** `dot1x_seen` and
`portal_answered` are in the rescue record's format and the team server renders
them, so the panel gives you every reason to think you can name them — but
nothing in the beacon ever sets them. No 802.1X sensing and no captive-portal
detection exists on the implant, so a rule naming one could never match. The
reader refuses those two by name, with the reason, rather than ship a rule that
silently never fires in the one file nobody can debug remotely. Only
`proxy_found` and `dns_answered` are live flags.

Everything ships **disabled**: a fresh checkout decides nothing. The shipped
rules above are a draft, validated whether the block is enabled or not, so a
typo surfaces now and not on the stuck cycle it would have fired. Switching the
decider on is changing one word.

## The one-cycle cost, and how a policy undoes it

The decider **may not act on the first stuck cycle**. When the server can be
reached, the server decides; acting immediately would mean the implant always
moved before the team server had even been told it was stuck, with the two
deciders racing on every drop. So the decider acts only from the second
consecutive stuck cycle on — one cycle where the rescue went out and brought
nothing back has to pass first.

That has a cost the operator has to see. Today, with the decider disabled, a
stuck implant starts its gsocket carrier on the first stuck cycle, through a
latch at the top of the loop. With the decider enabled, that latch moves behind
the decider, so an `egress gsocket` rule is a real choice rather than spending
budget on a carrier that was already up. The consequence: **the carrier may
come up one cycle later than it does today**, because the decider may not act on
the first stuck cycle and its fallback latch may not either.

**A policy whose first rule chooses `gsocket` restores the old timing** — the
carrier comes up on the first cycle the decider may act. A policy that tries a
proxy first has traded that cycle for the chance of a proxy. That is the
operator's trade to make, which is why it is a policy row and not a constant in
the code.

## What you learn, and when

The decider does not report through the rescue record. By the time it may act,
the record for this stuck window has already been sent — the rescue is one query
per window — so there is no message left to attach the news to, and a second
record would make the rescue periodic, which is a measured defect the beacon
already fixed.

So each attempt writes **one line to the beacon's log**, and you read it once
there is a connection, which is the only state in which the detail could reach
you anyway. The beacon installs no log file of its own — the drop-box's own
startup does, under `log_dir` (`/opt/raccoon/logs` by default), so the lines
land in `raccoon.log` there, or in `beacon.log` for the standalone build:

```
cat /opt/raccoon/logs/raccoon.log
```

Each line names the rule of your file that matched and what it said, the verb as
you would have typed it, how much of the budget this window has now spent, and
what the attempt answered. On a recovered device, the same file. The implant
going quiet once the budget is spent is not the implant giving up — it is the
implant handing the decision back to a team server that can still act the moment
DNS reaches it.

## Limits

Three limits are worth stating plainly, and they are recorded in *Known limits*
in [`docs/AGENT.md`](AGENT.md#known-limits) as well:

- **Drop-box only.** A build the team server generates carries no decider and
  has no way to be given one — it is a single file with no `raccoon.yaml` to
  read. This also means the two proxy verbs are unavailable on exactly the
  corporate target host where a proxy is most likely. Reaching that host would
  mean a generator request field, panel work and validation, and that is not
  built.
- **The decider may never `sleep`.** The one verb the server-side model has for
  a stuck beacon is the one the implant's own decider may never use. The two
  deciders are not equivalent; see above.
- **`dot1x_seen` and `portal_answered` are dead flags.** They are in the record
  and rendered by the server, but nothing sets them, so a rule naming one is
  refused. Making them live — 802.1X sensing, captive-portal detection — is a
  separate piece of work, and the one that would make this decider much smarter.

## See also

- [`docs/LISTENERS.md`](LISTENERS.md#the-fifth-transport-gsocket-over-the-gsrn)
  — the gsocket carrier the `gsocket` verb brings up, and what that leg costs.
- *Egress Proxy & NTLM Authentication* in the [README](../README.md) — the
  proxy machinery the `proxy` and `rediscover` verbs drive.
- [The design](superpowers/specs/2026-11-20-implant-egress-decider-design.md) —
  the verbs, the gate, the budget, and the alternatives it rejected.
