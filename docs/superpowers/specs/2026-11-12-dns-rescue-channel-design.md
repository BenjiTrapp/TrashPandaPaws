# A rescue channel over DNS — design

**Date:** 2026-11-12
**Status:** approved 2026-11-12

---

## Intent

`_FALLBACK_TRANSPORTS = ("https", "dns", "smb", "quic")`. Three of those four
carry traffic both ways. DNS does not, and `listeners/dns.py` says so in its
first line: "This is the one transport that carries nothing upstream." The
beacon sends a bare TXT query for `<base32(agent_id)>.b.<zone>` and decrypts
whatever comes back. There is no payload in the question and no
`_send_result_dns` in the client.

So a beacon whose HTTPS, SMB and QUIC legs have all failed is in a particular
state: the team server can still *task* it, and will never hear anything
again. The operator interface is honest about this — an agent whose
`last_channel` is `dns` gets a **VIA DNS** tag whose tooltip reads "That
channel carries tasking only: a task is delivered once and its result is never
reported. Queue a task here and it will run with no outcome shown."

That is the worst moment to be blind. The drop-box is stuck behind something
the automated ladder could not get through, and the one thing that would help
— knowing *what* it could not get through — is the one thing that cannot
leave.

**This work gives that beacon a mouth: one short encrypted diagnostic in a
DNS query name, carried by the relay that already exists, decrypted by the
server machinery that already exists.**

A second finding shapes it. The beacon already holds everything the diagnostic
needs and throws it away: each `_beacon_<transport>` returns `Optional[dict]`,
and on failure it writes the reason to `logger.debug` and returns `None`.
`_beacon_dns` catches `Exception as e` and logs "DNS beacon failed: %s". The
caller sees `None` and learns nothing. So this is not new probing. It is
keeping what already passes through the beacon's hands.

---

## Goals

1. **The beacon keeps why each leg failed**, per cycle, as a fixed-width
   record — a failure class and a code per transport, plus the environment
   flags it already observes.
2. **The DNS probe costs nothing extra.** DNS is second in the ladder, so when
   it is configured the query already happens every cycle. Recording its
   outcome adds no query and changes no signature.
3. **One short encrypted diagnostic leaves over DNS** when the ladder is
   exhausted — once per exhaustion event, not per cycle.
4. **The server decrypts it through the existing path** and shows it where the
   VIA DNS tag is today, so the half of that tooltip which says "its result is
   never reported" stops being true.
5. **The same exchange carries the answer back.** The listener relays the
   payload and answers with the TXT record the relay returns, so a rescue
   costs one query, not two.
6. **The agent reads the diagnostic and tasks back a concrete next attempt**
   (the second half; see Shape of the work).

---

## Non-goals

- **DNS as a general upstream transport.** This is a rescue, not a channel. No
  results, no loot, no chunking of anything larger than one label. The
  listener's docstring states the download-only property as deliberate, and it
  stays deliberate everywhere except this one path.
- **Periodic payload-bearing queries.** Asked for and ruled out by the
  operator: the diagnostic is rescue only. The *probe* may run early because it
  is free; the payload may not.
- **A model on the Pi.** That is the next project. This one defines the trigger
  it would hang from — "the rescue went out and nothing came back" is a state
  only this work can produce.
- **Changing the ladder's order, its retries, or its intervals.**
- **Acknowledgement.** DNS tasking is fire-and-forget by design, because a task
  that stayed in the queue would be handed out at every check-in forever. The
  rescue inherits that: it is sent once and nothing confirms receipt.

## Anti-goals

Each of these makes the work a failure even if every goal is met.

- **A DNS signature that reads as tunnelling.** This repository carries
  detection skills that hunt exactly this, and they key on **query volume,
  query rate, and subdomain length/entropy**. Today's query is short, constant
  per beacon, and identical every cycle. One extra query per exhaustion event,
  of bounded length, is noise. A stream of them is a tunnel, and a tunnel on a
  device impersonating an IP phone is the end of the engagement.
- **A key in a listener.** `relay.py` "never decrypts, never validates and is
  never given a key -- two tests pin that". The rescue path must use it exactly
  as the other listeners do.
- **The beacon gaining a dependency.** Stdlib only, asserted by
  `test_status_quo.py`.
- **A diagnostic that is itself worth stealing.** Codes and flags only: no
  hostnames, no usernames, no credentials, no URLs. The payload is encrypted,
  but its existence, length and timing are observable by every resolver on the
  path, and whoever runs that resolver may be the blue team.

---

## Constraints

| Constraint | Where it comes from | What it forces |
|---|---|---|
| A DNS label is ≤ 63 characters | RFC 1035 | base32 of 39 bytes, no more |
| AES-GCM costs 28 bytes (12 nonce + 16 tag) | the beacon's `_encrypt` | see the budget below |
| `_encrypt(self, data: dict)` **serialises its argument as JSON** | `beacon.py` | the record cannot be passed as bytes, and the JSON wrapper is part of the plaintext — this is what forces two labels |
| Full query name ≤ 253 characters | RFC 1035 | the payload label plus the agent label plus the zone must fit |
| `relay(payload, *, url, timeout)` takes an already-encrypted base64 string and returns one | `listeners/relay.py:77` | the upstream path exists; do not write a second one |
| `ServerCrypto.unwrap` checks fourteen field names, then scans any string over 32 chars | `relay.py`'s comment | a relayed blob needs **no** server-side decryption change |
| `_AGENT_SOCKET_ENDPOINTS = {"beacon_handler", "api_dns_tasking"}` | `server.py` | the rescue lands on one of those two, not a third |
| `_encrypt(self, data: dict)` serialises its own argument | `beacon.py` | a bytes payload must be wrapped in a dict, or it raises — this exact mistake killed the SMB and QUIC legs silently for the life of the file |
| DNS tasking leaves the queue on delivery | `listeners/dns.py` | nothing acknowledges; the beacon cannot know the rescue arrived |
| The beacon is served as **source text** by the generator | `relay.py`'s comment | the beacon cannot import shared constants; copies are the convention here |

---

## Approaches

**A — a payload label on the existing query, relayed through the existing
machinery.** The beacon puts one base32 label in front of the name it already
sends; the listener recognises it, calls `relay(...)` instead of
`fetch_tasking`, and answers with whatever comes back. Nothing new on the
server. One query per rescue.

**B — a second zone or a second record type for rescue traffic.** Cleaner to
read on the wire, and that is precisely the problem: two zones double the
configuration, double what a defender can fingerprint, and give the beacon a
second name to be caught resolving. No gain over A.

**C — no upstream at all; infer the failure from silence and blind-task a
sweep of candidate egress attempts.** The cheapest by far: zero beacon
changes. It loses because it is guessing, and a guessed sweep is loud. Trying
twelve candidate proxies in sequence from a device that is supposed to be a
phone is more detectable than the single short query A sends, and it still
does not know whether it worked.

**Chosen: A.** It reuses the relay, needs no server decryption change, and
spends exactly one query of bounded length at the one moment when the
alternative is being invisible.

---

## How it is built

### 1. The diagnostic record — 14 bytes, and why it needs two labels

A fixed-width binary struct, not JSON at the record level: JSON of the same
facts would not fit at all, and `struct` is in the standard library.

| Field | Bytes | Meaning |
|---|---|---|
| version | 1 | so a server can refuse a record it does not understand |
| per transport × 4 | 12 | one byte failure class, **two** bytes of code, for https / dns / smb / quic |
| flags | 1 | proxy discovered, 802.1X seen, captive portal answered, DNS resolved, and four spare bits |
| | **14** | |

The failure class is an enum (unreachable, refused, timed out, TLS failed,
HTTP status, authentication required, bad payload, resolve failed, plus
`answered` and `not_attempted`). The code carries the detail — an HTTP status,
an errno, a DNS RCODE. **Nothing is a string.** That is what keeps the record
small and what keeps a hostname from riding along by accident.

**The code is two bytes, and that is the first thing the tests corrected.**
The draft said one, and one byte cannot hold 407 — a proxy demanding
authentication, which is the most useful single thing this channel can carry.
No three-digit status above 255 fits. The alternative was dropping the best
diagnostic or encoding it as an offset a reader has to undo in their head.

**The budget, worked through, because the first version of this design got it
wrong twice.** `_encrypt` takes a dict and serialises it, so the record cannot
be handed over as bytes and the JSON wrapper is part of the plaintext:

| Step | Size |
|---|---|
| the struct | 14 bytes |
| base64 for JSON transport | 20 chars |
| wrapped as `{"d":"…"}` with **compact separators** | 28 bytes of plaintext |
| AES-GCM | 56 bytes of ciphertext |
| base32, unpadded | **90 characters** |

Those numbers are computed, not estimated, and they are what `_encrypt`
already produces: it passes `separators=(",", ":")` itself, so the compact
form is not something a caller has to remember.

**One trap on the way to the label.** `_encrypt` returns **base64**, not bytes.
A DNS label needs base32 of the *raw* ciphertext, so the base64 must be decoded
back to bytes first. Base32-ing the base64 *string* yields 116 characters and
three labels — arithmetically plausible, silently wrong, and the kind of thing
that only shows up as an over-long name on a live network.

90 does not fit in a 63-character label, and **no record size does**: the GCM
overhead alone is 28 bytes, which is 45 base32 characters before a single byte
of payload, and the shortest useful JSON wrapper pushes even a 3-byte record
past 63. So the one-label shape in the first draft was arithmetically
impossible.

**Two labels, split at `ceil(len/2)`** — not at a hard-coded 45. The margin
here is one character wide, so a later change to the record or the key name
would silently produce a third label if the boundary were a constant. Halving
is correct for any length up to 126 characters, and a payload past that is
refused rather than emitted as three, and the test asserts both that
there are exactly two labels and that each is ≤ 63.

The record is wrapped in a dict because that is what `_encrypt` takes, and
since the SMB/QUIC incident it enforces that with an explicit `TypeError`
naming the type it got. So this is no longer a silent trap — it fails at the
boundary, immediately. It is still worth knowing before writing the call.

### 2. Keeping it

Each `_beacon_<transport>` records its class and code where it currently writes
to `logger.debug`, then returns `None` as before. The debug log stays: it is
the only thing an operator with console access has today.

The accumulator lives on the beacon instance and is **cleared at the top of
every cycle**. Without that, a failure from three cycles ago rides along in a
later rescue and the operator reads a stale reason as a current one.

### 3. The probe, which is free

DNS sits second in the ladder, so when it is configured the query already goes
out every cycle. Its outcome — resolved, NXDOMAIN, SERVFAIL, no answer,
timeout — is recorded like any other leg. **No new query.** When DNS is *not*
configured, no probe happens and no query is invented: a beacon told not to
speak DNS stays silent on DNS.

### 4. The trigger — a latch, not a timer, written against the real loop

`_beacon_loop` is not a loop over `_FALLBACK_TRANSPORTS`; it is four guarded
calls, each skipped once `tasking` is non-`None`:

```python
if self.https_enabled:                      tasking = self._beacon_https()
if tasking is None and self.dns_enabled:    tasking = self._beacon_dns()
if tasking is None and self.smb_enabled:    tasking = self._beacon_smb()
if tasking is None and self.quic_enabled:   tasking = self._beacon_quic()
```

Two consequences the trigger has to be written around.

**DNS short-circuits SMB and QUIC.** If DNS returns tasking, the two legs below
it are never attempted that cycle. That is fine: a beacon receiving tasking is
not stuck, and no rescue is wanted. But it means the trigger cannot be phrased
as "all three upstream legs failed" — in that cycle, two of them were never
tried.

**`tasking is None` does not mean DNS failed.** `_beacon_dns` returns `None`
both when the query fails *and* when it succeeds with nothing to deliver — an
empty queue produces no TXT record to decrypt. Those two are
indistinguishable at the loop level, and telling them apart is exactly the
free information in goal 2.

So the condition is **both** of:

- no leg delivered tasking this cycle (the existing `tasking is None` arm, the
  one that increments `_consecutive_failures`), **and**
- the recorded DNS probe outcome says the resolver **answered** — otherwise a
  rescue cannot leave, and that case is the trigger the next project hangs
  from.

The latch is a flag set when a rescue is sent and cleared the moment any leg
returns non-`None`. One exhaustion, one query, and no rate for a detector to
find.

### 5. The query

    <payload-1>.<payload-2>.<base32(agent_id)>.r.<zone>

`r` rather than `b` in the marker label, so the listener can tell a rescue from
a tasking query by its name and not by counting labels. This makes the rescue
name longer than the ordinary one, which is a signature cost paid once per
exhaustion and recorded here as deliberate.

**When the name will not fit.** 90 payload characters plus two dots, plus the
agent label (52 characters for a 32-hex-character id), plus `.r.`, is 147
characters — leaving **106 for the zone** before the 253-character ceiling. A
longer zone than that means the rescue **is not sent** and the fact is written
to the debug log. It is not truncated: a truncated record decrypts to nothing
and would be indistinguishable, at the server, from an attacker's noise.

**Before registration.** The beacon uses `self._agent_id or self._implant_id`.
An implant that never reached anything has no agent id, so the rescue carries
the implant id and the server cannot attach it to an agent row. It is still
sent and still shown — as an unattributed rescue, which is a real and useful
thing to see — because a drop-box that never managed to register is precisely
the case with the least other evidence.

### 6. The listener

On a name whose marker label is `r`: take the two payload labels,
base32-decode them, and pass the result to `relay(payload, url=self.relay_url)`
— the same call `smb.py:222` and `quic.py:253` already make, imported the same
way (`from .relay import relay`). Put the base64 string that comes back into
the TXT answer. On a name whose marker is `b`: `fetch_tasking`, unchanged.

The listener needs no new configuration: `DnsListener.__init__` already takes
`relay_url` and keeps it, because `fetch_tasking` appends
`/api/v1/dns/<agent_id>` to that same base. And `relay`'s POST lands on
`beacon_handler`, which is already in `_AGENT_SOCKET_ENDPOINTS` — so the server
needs no new route either.

The listener still holds no key, still decrypts nothing, still validates
nothing. The two tests that pin that must keep passing untouched.

### 7. The server

Nothing is needed for decryption: the blob lands in `beacon_handler` and
`ServerCrypto.unwrap` already finds it. What is needed is **display** — the
agent row that shows VIA DNS gains the decoded diagnostic, and that tooltip's
second half is rewritten, because it will no longer be true.

### 8. The second half: the agent answers

The agent reads the decoded record and queues one concrete next attempt — a
specific proxy, a specific port, a specific transport — which the TXT answer
carries down on the next cycle. It is a tool over the existing C2 API, on the
team-server side, where the model and the context already are. No model on the
implant.

---

## Tests

| What | Where |
|---|---|
| The record plus its JSON wrapper plus GCM, base32'd from the **raw bytes**, splits into exactly two labels of ≤ 63 characters — and the arithmetic is asserted, not assumed | a new `software/tests/test_dns_rescue.py` |
| Base32 is applied to the decoded ciphertext, not to `_encrypt`'s base64 string — the wrong one yields 116 characters and three labels | same |
| A name that would exceed 253 characters is **not sent** and not truncated | same |
| `_encrypt` receives a **dict** — it raises `TypeError` otherwise, so this is a guard, not a hope | same |
| The accumulator is cleared each cycle: a failure from an earlier cycle never appears in a later rescue | same |
| A DNS leg that answered with no tasking still counts as "the resolver answered", so the rescue fires; a DNS leg that failed to resolve does not | same |
| DNS delivering tasking suppresses the rescue entirely, and leaves SMB and QUIC untried, as the loop already does | same |
| A rescue from an implant with no agent id is sent and shown unattributed | same |
| A rescue query whose payload does not decrypt is answered exactly like any other, so the listener is no oracle | `test_listeners.py` |
| The listener holds no key on the rescue path | the two existing relay tests, unchanged |
| One rescue per exhaustion event, and none after an upstream leg recovers | the new file |
| The record contains no hostname, username or URL — walk every field | same |
| `test_status_quo.py` green: the beacon's dependencies do not grow | unchanged |
| The VIA DNS tooltip no longer claims results are never reported | `test_docs.py` / `test_c2_agent_gui.py`, which already pin that copy |

---

## What is left to the builder

- **The failure-class and code taxonomy per transport.** The table above names
  the shape; which classes earn a distinct value is a judgement best made while
  reading the four `_beacon_*` methods.
- **Whether the TXT answer to a rescue needs a different wrap** from the one
  `fetch_tasking` returns. The relay's answer is already wrapped for this
  agent, so probably not — but it is the one place where the two paths meet.
- **The operator-facing copy** for the decoded diagnostic. It should read as a
  sentence an operator can act on, not as a hex dump.
- **Whether the spare flag bits are worth naming now.** Leaving them zero and
  documented is also an answer.
