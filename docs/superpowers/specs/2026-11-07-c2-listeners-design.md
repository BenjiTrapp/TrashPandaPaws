# C2 listeners for SMB, QUIC and DNS — design

**Date:** 2026-11-07
**Status:** awaiting approval

---

## Intent

The beacon implements four transports. Only one of them has a counterpart in
this repository.

`README.md:43` advertises "4 independent channels: HTTPS, DNS, SMB named
pipes, QUIC-style UDP — with automatic fallback". That describes four
*client* implementations. The team server is a Flask application: it answers
HTTPS and nothing else. A beacon configured for DNS queries an authoritative
nameserver that does not exist here; one configured for SMB connects to port
445 of an SMB server that does not exist here; one configured for QUIC sends
datagrams to a listener that does not exist here.

Two of the three are additionally broken on the client side, and the way they
are broken matters. Measured by reading each full call expression, not line
by line:

| Call site | Passes to `_encrypt` | Result |
|---|---|---|
| `_beacon_smb` | `json.dumps({...}).encode()` → **bytes** | `TypeError`, swallowed |
| `_send_result_smb` | `json.dumps(result).encode()` → **bytes** | `TypeError`, swallowed |
| `_quic_send` | `json.dumps(data).encode()` → **bytes** | `TypeError`, swallowed |

`_encrypt(data: dict)` serialises its own argument. Given `bytes` it raises,
and the surrounding `except` discards the error. So neither transport has
ever put a byte on the wire, for as long as the code has existed.

A note on how this was established, because it was got wrong once: a `grep`
for `self._encrypt(json.dumps(` truncates at the line break and makes
`_beacon_smb` look as though it passes a `str`, which would double-encode
silently rather than raise. It does not — the dict literal spans lines and
ends `}).encode())`. The claim here comes from reading each complete
expression and from executing all three paths.

Worth keeping in mind for the builder: `_encrypt` *would* accept a `str`
without complaint and double-encode it. That is why the fix below is at the
contract and not only at the three call sites.

**This work gives SMB and QUIC working counterparts, fixes the client-side
contract that made them silent, and adds DNS to the same footing — with one
honest limit recorded below.**

---

## Goals

1. A beacon configured for **SMB only** completes a full cycle against this
   repository's software: check in, receive tasking, execute, report the
   result.
2. The same for **QUIC only**.
3. **DNS** as what it actually is: a **tasking side channel for an agent that
   is already registered**. Not a standalone transport — see the non-goal,
   which is sharper than it first looks.
4. Listeners are first-class, configured, named objects that can be listed,
   started and stopped, in the manner of a conventional C2 framework.
5. A **📡 Listeners** entry in the operator interface's header, between
   🚀 (Beacon Generator) and 💎 (Loot), that lists them, shows state and
   carries their configuration.
6. The whole thing works out of the box: no manual firewall step, no
   capability granted to a service, nothing an operator can forget whose
   failure looks like "the beacon is not calling back".
7. A local test rig that runs all three against the real beacon, in Docker.

## Non-goals

1. **DNS is not a standalone transport, and this is narrower than "no result
   path".** Three facts from the beacon, each read from the code:

   - `_beacon_dns` only reads. It queries `<base32-id>.b.<domain>` for TXT
     and decrypts the answer.
   - There is no `_send_result_dns`. The result block at `beacon.py:4176`
     tries HTTPS, then SMB, then QUIC, and drops the result if none is
     enabled.
   - `_beacon_dns` sends no `register` action — unlike `_beacon_smb`, which
     does. A beacon on DNS alone would query tasking for an id the server
     has never seen; `task_queues.get(agent_id)` finds nothing and there is
     no way for it to enrol.

   So a DNS listener serves an agent that registered over HTTPS, SMB or
   QUIC, hands it tasking, and receives nothing back. **The operator chose
   this scope deliberately**, over the alternative of giving the beacon an
   upstream DNS path — results encoded into query labels, with chunking and
   reassembly — which is real DNS tunnelling and roughly three times this
   work. That remains a separate project.

   The Listeners panel must state the limit where an operator will read it:
   tasking only, and only for an agent already known.

   Consequence for the documentation: `README.md:43`'s "4 independent
   channels" is still not accurate after this work. Three are independent;
   DNS is a dependent side channel. The README correction below must say
   so.

2. **No real QUIC.** The beacon's "QUIC" is a custom framing over UDP:
   `[4-byte length][payload]`, fragmented into 1200-byte datagrams carrying
   `[len][stream_id][frag_idx][total]`. The counterpart implements that
   framing. Nothing here speaks RFC 9000, and the name stays as the beacon
   uses it.

3. **The team server's two-socket property does not change.** A day of work
   established that the process holding the fleet, the loot and the operator
   interface listens on exactly two sockets, and that a request arriving on
   the agent socket cannot reach the interface. No listener runs inside that
   process and no new protocol parser enters it.

4. **No new dependency.** `software/requirements.txt` and
   `software/agent/requirements.txt` do not grow. The beacon is stdlib-only
   and its counterparts will be too.

5. **No change to the beacon's wire protocol.** The beacon is the
   specification; the counterparts are written to it. Where the beacon is
   wrong — the `_encrypt` contract — the fix restores the contract it already
   documents in its own type hint, and changes no bytes on the wire for a
   correctly-formed payload.

## Anti-goals

Things that would make this a failure even if the transports worked:

- **A listener that holds the encryption key.** It must not be able to read
  or forge beacon traffic.
- **A start button that silently does nothing.** Where starting is
  impossible, the control must be visibly disabled with the reason shown.
- **A setup step whose omission looks like a beacon failure.** This project
  has repeatedly paid for silent misconfiguration; two docstrings record a
  lost afternoon over a key mismatch, and a 10-second sleep floor currently
  makes a healthy beacon look stale.
- **Returning the team server to five listening sockets** without saying so.

---

## Constraints

- Python 3.9, stdlib only, no new dependency.
- The beacon's existing bytes on the wire are fixed; counterparts conform.
- The suite is 2223 tests and must stay green. Whole-suite command:
  `python3 -m unittest discover -s software/tests -t . -p "test_*.py"`.
- The repository's two long-standing port occupants on this machine —
  `tls-viewer` on 8443 and `rdpview` on 8099 — mean test rigs must take
  ephemeral or explicitly chosen free ports, never defaults.
- `docker-compose.yml` runs the existing two services with
  `network_mode: host`, which is justified for the team server (Responder and
  the relay tooling need broadcast) and therefore cannot host port mapping.

---

## Approaches considered

**A — listeners inside the team-server process.** The literal model of
Sliver and similar frameworks: one process hosts every listener as a job.
Rejected. Ports 445 and 53 are privileged, so the process would need root or
a capability; three new protocol parsers would run inside the process holding
the fleet and the operator interface, where a fault in the SMB parser takes
the team server with it; and it reverses the two-socket property established
the day before.

**C — separate processes, file configuration only.** Started like the team
server, configured in `raccoon.yaml`, visible only in logs. Rejected because
it does not meet goal 4: no listing, no runtime start or stop.

**B — separate listener processes, managed from the interface. Chosen.**
Each transport is a small stdlib service that terminates its protocol,
carries the opaque payload to the team server's existing agent socket as an
HTTP POST, and carries the response back. The team server is unchanged. The
interface lists, starts, stops and configures them, so the operator
experience matches A while the isolation matches C.

It trades an extra hop, and a control surface that has to be careful, for
three properties the others do not have: a listener can run as its own user
or container with one port and no privilege; a crash costs one transport;
and it is the same shape as the redirector arrangement already documented in
`docs/REDIRECTOR.md`.

---

## The design

### A listener is a dumb pipe

`ServerCrypto.unwrap` (`server.py`) tries each of 14 known field names and
then falls back to *any* string value longer than 32 characters. So a
listener can POST `{"d": "<ciphertext>"}` to the agent socket and the server
will find the payload. In the other direction the server answers
`crypto.wrap(...)`, and the listener hands the ciphertext back over its own
transport without opening it.

**Therefore no listener is given the encryption key, ever.** It cannot read
beacon traffic and cannot forge it. A compromised listener can drop messages
or replay them — and replay is already a recorded open finding of the
protocol itself, not something this introduces.

This is the property that keeps each listener small enough to review.

### Privilege lives where it already is

Both privileged ports are bound by something that already holds the
privilege, and the listener process never does:

- **Docker:** the listeners get their own bridge network — not
  `network_mode: host`, which is what makes port mapping possible — and
  publish `"445:8445"`, `"53:8053/udp"`. `dockerd` binds the low port on the
  host and forwards to the unprivileged container.
- **Host install:** systemd socket activation. A `.socket` unit declares
  `ListenStream=445`; systemd binds it as root and passes the file descriptor
  to a service running as an unprivileged user. Python takes it with
  `socket.socket(fileno=3)` after reading `$LISTEN_FDS` — stdlib, no
  dependency.

No `iptables` rule, no `setcap`, no `cap_add`, and nothing for an operator to
remember. Goal 6 is met by construction rather than by documentation.

A listener in the bridge network reaches the host-networked team server via
`extra_hosts: ["host.docker.internal:host-gateway"]`, which behaves the same
on Linux and Docker Desktop. *(My call, not discussed.)*

### What each counterpart must speak

The beacon's client code is the specification. A builder reads these methods
and implements the other side:

**SMB** — `beacon.py:1811-2021`. Real SMB2 over TCP: NetBIOS session wrapper
(`_smb_netbios_wrap`), Negotiate, Session Setup, Tree Connect to `IPC$`,
Create on the named pipe (default `msrpc_6e2f`, `_smb2_create_pipe`), then
Write and Read on that pipe (`_smb_write_pipe`, `_smb_read_pipe`). The
counterpart must answer enough of SMB2 for that sequence and treat the pipe
as a request/response channel. It does not need to be a file server.

Two facts that bound the size of this, both read from the code:
`_smb2_session_setup` sends an **NTLMSSP Negotiate (Type 1), anonymous** —
so the counterpart answers an anonymous handshake and needs no credential
store. And `_beacon_smb` sends `action: register` on first contact and
`action: beacon` after, so a beacon on SMB alone registers itself; the
counterpart needs no out-of-band enrolment.

**QUIC** — `beacon.py:2084-2152`. UDP. Frame is `[4-byte big-endian
length][payload]`, fragmented into 1200-byte datagrams each prefixed with
`[len][stream_id][frag_idx][total]`. The counterpart reassembles by
`stream_id`, and replies with the same framing. Note the client currently
accepts fragments without checking the source address or that `stream_id`
matches the one it generated; the counterpart must not rely on that
laxness, and it is listed below as a finding to record rather than fix here.

**DNS** — `beacon.py:1789-1807`. The beacon queries
`<base32(agent_id) lowercased, padding stripped>.b.<domain>` for TXT via the
configured resolver, and decrypts each returned record until one succeeds.
The counterpart is an authoritative nameserver for that zone that answers
with the wrapped ciphertext as TXT. Tasking only, per the non-goal.

### The client-side contract

The root cause is that `_encrypt(data: dict)` accepts anything
JSON-serialisable. The fix is at the contract, not only at the three call
sites:

- `_encrypt` rejects a non-`dict` argument explicitly, so a future caller
  gets an error at the boundary instead of a double-encoded payload or a
  swallowed `TypeError`.
- The three call sites pass the dict.
- The SMB and QUIC paths adopt `_wrap_payload` where the envelope is
  appropriate, or `_encrypt` where it is not — the builder decides per
  transport and records why. HTTP uses the envelope for its decoy fields;
  a named pipe and a UDP frame have no HTTP body to disguise.

### Configuration

A new `c2.listeners` block in `configs/raccoon.yaml`, one entry per listener,
each with `enabled`, its bind address and port, and its transport-specific
settings (pipe name; zone and TTL; fragment size). The shipped file has these
disabled, and documents that they are the server side — the existing
`c2.fallback.*` block remains the beacon side. Note the shipped fallback
block currently has only `https` and `dns`; `smb` and `quic` are readable by
the beacon but absent from the file, and this work adds them.

### The interface

A **📡** button in the header between 🚀 and 💎, opening a panel that lists
each listener with its transport, bind address, state, and the count of
beacons that have arrived through it. Per listener: start, stop, and its
configuration.

Where the listeners run as child processes of the team server, start and stop
work. Under Docker they are sibling compose services, and a container cannot
start a sibling without the Docker socket — which the audit flagged and the
compose file deliberately does not mount. **In that mode the controls are
visibly disabled and the panel states the reason.** A control that silently
does nothing is an anti-goal.

The panel must also carry the DNS limit in plain words: tasking only, no
results.

### Control path

The team server supervises listeners it started and reaches them over a
loopback control socket for state. The control surface is new and must be
treated as such: loopback only, authenticated with the operator token the
same way `/api/*` is, and incapable of anything but start, stop and status —
no arbitrary command, no path, no key.

### Test rig

A compose profile that brings up the team server, the three listeners and a
real beacon configured for one transport at a time, and asserts a full cycle:
registration appears in the fleet, a queued task reaches the beacon, and the
result comes back. One profile per transport, because the point is that each
works *alone*. For DNS the assertion stops at "tasking arrived", per the
non-goal.

The existing rig (`tools/demo_env.py`) is the model: it stands up a server
and a beacon in one process and is already used for figures. It takes free
ports, mints one key for both ends, and must keep doing both.

---

## Findings to record, not fix here

These surfaced while reading and belong in `docs/AGENT.md`'s *Known limits*,
where a drift test will hold them:

- The QUIC client accepts fragments without checking the source address or
  that `stream_id` matches the one it generated, so any sender that reaches
  the port can inject or truncate a reassembly. The AEAD still protects the
  content; availability is not protected.
- `README.md:43` and `:609` describe four working channels. Before this work
  two of them had never put a byte on the wire. After it, three are
  independent transports and DNS is a dependent tasking side channel — so
  the line needs correcting either way, and the correction should outlive
  this work's success or failure. The accurate shape is "three independent
  channels plus a DNS tasking side channel", and `:609`'s claim that the
  beacon "tries them in order and falls through to the next on failure"
  needs the same qualification, since falling through to DNS alone leaves a
  beacon that cannot report.

---

## What is left to the builder

- The SMB2 subset: which responses satisfy the beacon's sequence, and how to
  keep the implementation small enough to review. The beacon's request
  builders are the only specification that matters.
- The internal shape of each listener: whether they share a relay module or
  each carry their own HTTP client.
- The supervision mechanism for child processes, and how state is reported
  over the control socket.
- Whether the DNS listener answers for one zone or several.
- How the panel presents a listener that is configured but not running, and
  one running but unreachable.
