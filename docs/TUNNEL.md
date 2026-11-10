# The reverse SOCKS tunnel

The beacon's four transports carry *messages* — a registration, a
check-in, a result. This carries *traffic*: an operator points
`proxychains`, `nmap` or a browser at a port on the team server and
reaches the network an implant sits in, with every byte inside a Noise
session the implant dialled out to establish.

This document is what an operator needs to run it. For the design, the
alternatives it rejected and the protocol it derives from, see
[`docs/superpowers/specs/2026-11-09-reverse-socks-tunnel-design.md`](superpowers/specs/2026-11-09-reverse-socks-tunnel-design.md)
and the module docstring on
[`software/c2/tunnel/protocol.py`](../software/c2/tunnel/protocol.py).

---

## The happy path, in four steps

**Prerequisite: the build must have been generated with the tunnel
enabled.** A build with no enabled `c2.tunnel` block refuses `tunnel
start` with "Generate the build with the tunnel enabled" — there is no
server, port, public key or PSK in it to dial with, and no way to add
one after the fact. Ask for a tunnel in the generation request; the
server mints that build's identity and PSK then and registers them.

Everything below is detail on one of these.

1. **Start the tunnel server.** Tunnel panel (the plug icon in the
   header) → **Start**. It is a separate process on the team server host;
   nothing dials in until it is running. See
   [*Running it*](#running-it).
2. **Task the agent `tunnel start`.** On the endpoint's row, or as a
   task to the agent. It takes effect at that agent's **next check-in**,
   not now — the row shows `pending` with the expected time. See
   [*The two objects*](#the-two-objects-and-what-each-start-and-stop-does).
3. **Read the port and the password off the row.** Once the endpoint
   connects, its row shows `SOCKS 127.0.0.1:<port>` and the RFC 1929
   username and password. The port is fixed per identity and stable
   across restarts. See [*The SOCKS port*](#the-socks-port-and-why-it-asks-for-a-password).
4. **Point a client at it.** `proxychains`, `nmap --proxies`, or a
   browser's SOCKS5 settings, with those credentials.

```
# proxychains.conf -- the values from step 3
[ProxyList]
socks5 127.0.0.1 19050 tun-a1b2c3d4e5f6 <the password from the panel>
```

To take it down: `tunnel stop` to the agent for one endpoint (again a
check-in away), or stop the server, which **drops every endpoint at
once**.

If step 2 produces a refusal instead of a connection, the likeliest
cause is the crypto path — see [*The crypto path*](#the-crypto-path-and-the-tunnel-that-refuses-to-start),
and note that the remedy differs for a generated build and a standalone
one.

---

## The one property that is different here

**The tunnel server holds key material and a listener does not.**

[`docs/LISTENERS.md`](LISTENERS.md) opens with the property everything
there rests on: no listener is ever given the encryption key, which is
what makes one safe to put on a cheap forwarding host you do not mind
losing. The tunnel server inverts it. It mints and holds an X25519 static
private key, and it holds the pre-shared key of every build that was
generated against it — under `Noise_NKpsk0` those two things *are* the
whole credential an implant presents, so whoever has the tunnel server's
key store can complete the command handshake and claim any identity in
it.

Three consequences, and none of them is optional:

- **It runs on the team server host, not on a forwarding host.** It is a
  separate process there, not a thread in the team server, so the
  operator interface can be lost without losing the fleet — but it is not
  a thing to put somewhere exposed.
- **It is deliberately not a listener and is not in `c2.listeners`.** Its
  configuration block is `c2.tunnel_server`, it is not in the transport
  registry, and it has its own panel. Filing it with the listeners would
  quietly contradict the guarantee that document leads with.
- **Its key store is mode `0600` and lives with the team server's other
  secrets**, at `<data dir>/tunnel/keys.json`. The generator writes each
  build's PSK there; the tunnel server reads its candidates out of the
  same file on every connection, so **retiring a burned build is deleting
  its PSK** and nothing else has to be rotated and nothing restarted.

---

## The two objects, and what each start and stop does

There are two things called "start" in the Tunnel panel and they are not
the same thing. Conflating them would give you a button that promises
something it cannot deliver.

| Object | Start/stop is | How fast |
|---|---|---|
| The tunnel **server** | `start`/`stop` on a local supervised process | **Immediate**, and stopping it **drops every endpoint at once** |
| An **endpoint** | a `tunnel start` / `tunnel stop` task queued for that agent | Takes effect at that agent's **next check-in** — the row shows **pending** with the expected time until the agent confirms |

**Stopping the server drops every endpoint at once.** The panel asks
before it acts and says how many are connected; the API answer repeats
the number. Every one of them then needs `tunnel start` tasked to its
agent again, which is a whole check-in interval away. There is no way to
stop one endpoint from the server's button and no way to stop the server
from an endpoint's.

**An endpoint's stop is a queued task, and the latency is displayed
rather than hidden.** A stop that silently takes five minutes is the
cousin of a start button that silently does nothing. So the row shows
`pending until ~<time>` and its button is disabled until the agent
reports back.

An endpoint whose `_implant_id` matches no fleet agent is shown as
**unlinked** rather than hidden, and its buttons are disabled with the
reason: it was started without a beacon above it — from
`services/raccoon-tunnel.service` on a drop-box — so it is started and
stopped there.

Per row the panel shows state, the fixed SOCKS port, the hostname, OS and
peer address the endpoint reported, open sessions against the cap, bytes
each way, the crypto path, the SOCKS credential, how many connections the
port refused and why, and whether the row is linked or unlinked. The
`/api/server/tunnel` row carries two more the panel does not draw:
`last_seen_age`, the age of the last keep-alive, and `connected_for`.

A disconnected identity keeps its row, because it keeps its port. Hiding
it would make an endpoint that aged out look like one that was never
issued a port.

---

## The SOCKS port, and why it asks for a password

**One fixed SOCKS port per identity**, on loopback, assigned from
`socks_port_first`–`socks_port_last` (`19050`–`19099` as shipped),
recorded against the **tunnel identity** and **stable across restarts**.
The panel never re-points a port at another identity, because a port that
quietly moved to another network would be worse than no port at all.

The identity is generated **per build** and baked into the artifact
beside its PSK. It is deliberately *not* the `agent_id`: that is a
server-assigned display name from a counter that can rewind across a
restart, so a port pinned to it could end up pointing at a different
host than you believe. Two builds on one host get two identities and two
ports, which is what you want.

**The port authenticates, with SOCKS5 user/pass per RFC 1929.** The
username is the identity — not a secret, and it makes a `proxychains`
entry say which endpoint it reaches — and the password is random, minted
per identity by the tunnel server, held in memory, never written to disk,
and shown in the panel row. Read it from there to write your config.

The reason it authenticates at all: **loopback is not isolation from
other local users** on the team server. Binding to `127.0.0.1` keeps
other hosts out and does nothing whatsoever about anyone else with a
shell on that machine, and an unauthenticated port there is a free pivot
into the target network. A bind address that is not an IP literal on
loopback is refused rather than trusted.

The `proxychains.conf` line these two values go into is in
[*The happy path*](#the-happy-path-in-four-steps) above.

---

## The crypto path, and the tunnel that refuses to start

A tunnel endpoint **refuses to start when the host has no libcrypto**,
and says so rather than running slowly.

AES-256-GCM in pure Python moves roughly **50-200 KB/s**. That is fine
for the small messages the rest of the beacon sends and useless for a
tunnel — and the failure mode is the expensive part, because every other
sign is of a working tunnel. "It is slow" would otherwise be diagnosed
for hours as a **network fault** in the target's own network, which is
exactly the afternoon this refusal exists to prevent.

So the refusal is the default. **Where you set the override depends on
which kind of endpoint refused, and the two are not the same place:**

| Endpoint | Where `allow_slow_crypto` lives | What to do |
|---|---|---|
| A **generated build** (the common case) | baked into the artifact at **generation time**, from the generation request — the build **reads no config file** | **regenerate the build** with the flag set. Editing `raccoon.yaml` on the target changes nothing |
| A **standalone endpoint** under `services/raccoon-tunnel.service` | the `c2.tunnel` block in `configs/raccoon.yaml` | edit the file and restart the unit |

```yaml
# configs/raccoon.yaml -- the standalone endpoint only. A generated build
# carries its own copy of this field and never reads this file.
c2:
  tunnel:
    allow_slow_crypto: false   # true runs on the slow path deliberately
```

**The runtime refusal names the field, not the place.** It says to set
`c2.tunnel.allow_slow_crypto`, which reads like the YAML path and is the
right field either way — but for a generated build that field is already
in the artifact and the YAML is not consulted. So read the refusal
against the table above rather than literally. The same split applies to
all eight `c2.tunnel` fields; see *Configuring it* below.

A tunnel at 100 KB/s still beats no tunnel when that is the decision you
want to make, so the override exists. When it is used, the panel shows
`crypto pure-python` on that row in warning colour with the number
beside it, so the slow case is visible where it would otherwise be
mistaken for the network. The refusal itself reaches the panel too: the
tunnel child's stderr is closed, so the row's refusal line is where that
sentence arrives or nowhere.

On a brought-interpreter host the gate is satisfied for free — the
Windows embeddable distribution ships a real `libcrypto`.

---

## Staging onto a host with no Python

The ordinary artifact is `python3 -c '…'`, and a one-liner cannot install
Python. The second artifact shape from the same generator is a **stager**
— a POSIX shell script and a PowerShell script — which:

1. **probes** for a usable interpreter and, finding one, runs the
   ordinary one-liner and stops there;
2. otherwise walks an ordered **dead-drop list** until one answers with
   the bytes its pinned hash names;
3. lays out `<base>/` with the interpreter, `Lib/sitecustomize.py` and
   the payload under the build's generated names;
4. starts the brought interpreter bare.

"Optional" is a runtime property, not a build flag: it brings something
only when it finds nothing.

### The dead-drop list, and the hash that has no override

The list is `[{url, sha256}]`, **ordered**, and the team server is
optional and last — or absent, which is the point of it. With an external
drop the target speaks only to GitHub, S3 or a CDN until the first beacon
check-in, so staging does not burn the C2 address. An empty list is
supported: the script probes, and refuses.

**Hash verification is mandatory and has no override.** There is no
argument, no environment variable in the emitted text and no branch in
either template that unpacks or starts anything before a `sha256` has
matched its pin. A host with no digest tool refuses rather than proceeds.

The reason is blunt: **an unverified drop is remote code execution in our
own implant**, and whoever could write to that location would own every
host staged from it. Revocation is deleting the drop; the liveness check
beside `beacon-gist` is reused only to ask "is this drop still
answering", never as an upload path.

Build the bundle locally and upload it by hand:

```sh
python3 tools/build_interpreter_bundle.py \
    --distribution python-3.11.9-embed-amd64.zip \
    --expect-sha256 <the hash published for that file> \
    --payload <the build's generated artifact> \
    --payload-name <the build's generated payload name> \
    --base-dir <the build's base_dir> \
    --gate path \
    --out bundle.zip
```

It renders the startup hook itself, verifies the distribution **before**
it opens it, writes one zip, and prints the `{url, sha256}` entry to
paste into the build's drop list once the file is uploaded. No server
route builds or publishes anything.

### Two things the build decided that are easy to assume otherwise

**No tool assembles a POSIX bundle.** `tools/build_interpreter_bundle.py`
takes the **Windows embeddable distribution** and nothing else, so the
POSIX stager has a verified fetch mechanism and no supported bundle
source. Point it at a drop and it will fetch, verify and unpack whatever
is there; nothing in this repository produces that file for a POSIX host.
Its value today is its **probe-and-delegate** path: on a host that has a
Python it runs the ordinary one-liner, which is the common case on Linux
and macOS.

**The stager installs no persistence**, although an earlier design step
said it would. The per-build autorun name, the gate and the payload name
live in the build's `persistence` block and are acted on by the beacon's
own persist task, which already removes exactly what it installed; a
second copy of that logic in two shell languages would drift. So
persistence is an **explicit operator action** — task `persist` to the
agent — rather than an automatic consequence of staging. The stager's
last act is to start the brought interpreter bare, which is what runs the
startup hook under either gate.

### The gate, since two things above refer to it

A brought-interpreter build carries a `sitecustomize.py` inside the
interpreter's own `Lib/`, which `site` imports at startup. What it does
then depends on a per-build switch, `gate: "path" | "argc"`:

| Gate | The autorun entry | The trade |
|---|---|---|
| `path` (**default**) | names a plausible script path beside the interpreter | unremarkable in Autoruns; the payload path is on the command line |
| `argc` | names the interpreter and nothing else; the hook checks its own `argc` through `ctypes.pythonapi.Py_GetArgcArgv` and runs the payload only when launched bare | nothing in command-line telemetry, at the cost of a `pythonw.exe` with no arguments — which barely occurs legitimately, and was the lead that unravelled the original |

`path` is the default because that trade is the right way round for most
engagements, and flipping it is one build flag. It is also the safer
default against the `._pth` trap in *Known limits* below: if the hook
never runs at all, the `path` gate still works — the command line names
the payload and the interpreter runs it — whereas `argc` leaves an
autorun entry that starts an interpreter and nothing else.

**`sitecustomize.py` requires an interpreter we brought:** dropped into a
host's system Python it would arm on every Python invocation by every
user. So the two features are coupled — no brought interpreter, no hook,
and the gate switch has no effect.

---

## Configuring it

Two blocks in `configs/raccoon.yaml`, and the key names do not say which
is which, so each says so in the file.

| Block | What it is | A drop-box runs |
|---|---|---|
| `c2.tunnel` | **this host as the near end** — the endpoint, which dials out | yes, on the Pi, with no beacon above it |
| `c2.tunnel_server` | **this host as the far end** — opens the socket endpoints dial in to | never |

A build generated by the team server carries the same eight `c2.tunnel`
fields baked in and **reads none of this file**. So every one of those
eight is a **generation-time** choice for a generated build and a
**file** choice only for a standalone endpoint — which is why the crypto
section above has a table instead of a YAML snippet, and why "edit the
YAML and restart" is the wrong instruction for the common artifact.
Changing any of the eight on a generated build means generating a new
build.

**The PSK is deliberately not in the file.** Under `Noise_NKpsk0` the
endpoint presents no static key, so the PSK plus the server's public key
is the entire credential, and a shared secret does not belong in
something that is in git and will be pasted into a ticket — the same rule
that keeps `RACCOON_LISTENER_TOKEN` out of it. It comes from
`RACCOON_TUNNEL_PSK`, which `services/raccoon-tunnel.service` supplies
through an `EnvironmentFile`, and a `psk` key found in the YAML is
refused **by name** rather than ignored.

One port on the server side serves the command channel and every relay,
so a single `CONNECT` rule is enough to cross a corporate proxy. That is
also why the endpoint can get out at all: it reuses the beacon's own
proxy discovery and its NTLM `CONNECT` relay.

---

## Running it

From the panel: the plug icon in the header. By hand, the server side:

```sh
python3 -m software.c2.tunnel --bind-host 0.0.0.0 --bind-port 8446 \
    --socks-port-first 19050 --socks-port-last 19099 \
    --key-store ~/.raccoon-c2/tunnel/keys.json \
    --state-path ~/.raccoon-c2/tunnel/ports.json
```

No secret is ever an argument: the control token comes from the
environment, and `--key-store` is a *path*, not key material. The process
prints one line to stdout (`control-port <n>`) and sends everything else
to stderr.

The endpoint side on a drop-box is
`python -m software.c2.tunnel_standalone` under
`services/raccoon-tunnel.service` — unprivileged, opening no socket. The
unit file's own comments say why the server side must never run there.

---

## Not matching the rules the protocol came from

This protocol is derived from **VIPERTUNNEL**, the Python reverse-SOCKS
backdoor InfoGuard Labs documented in *Slithering Through the Noise*
(2026-04-09). It keeps that family's **shape** — one command channel, a
SOCKS5-shaped exchange per relay in which the implant is the server — and
replaces its **bytes**. The first four rows below will read as *bugs* to
anybody who knows the original, and are not: they are RFC 1928 as
written, which the original was not.

| Field | The original | Here |
|---|---|---|
| SOCKS version byte | stripped from greeting, request and reply | restored, `0x05`, and checked on decode |
| `RSV` | absent | present, `0x00`, and checked on decode |
| Ports | **little-endian** | **big-endian**, per RFC 1928 §4 |
| Success status | `1`, with `0` for failure | **`0`**, per RFC 1928 §6 |
| `ATYP=4` (IPv6) | refused | supported |
| Keep-alive | a zero `uint16` | `MSG_PING` / `MSG_PONG` |
| Getting out | a bare `socket.connect((ip, 443))` | a configured proxy, then discovery, then direct — with its own `CONNECT` and NTLM relay |
| Session dial-back | a fresh high port per pending session | one port, with a 32-byte token in the first authenticated payload |
| The second process | the payload on the command line, where `ps` and `/proc/<pid>/cmdline` published it to every local user — and is how the family's hosts were enumerated | `python -` with the source on stdin: an unremarkable command line and nothing on disk |

The frame length prefix is big-endian for the same reason the ports are,
and not because the framing needs it either way: the original's
little-endian numbers are a published, scannable trait, and a fingerprint
we do not need is one we do not keep. Its keep-alive was a zero `uint16`
— the bytes `00 00`, answered to every connection on its port, which is
how its infrastructure was mapped across hosting providers with one scan.
So an empty frame, which is those two bytes exactly, is refused by both
`write_frame` and `read_frame` here rather than merely left unused, and an
unauthenticated peer gets no bytes at all.

The write-up that documented that family published YARA rules, two of
which bear on this work, and `software/tests/test_tunnel_yara.py` is what
measures the result. **It is two tiers, and they prove different things** —
worth knowing before quoting either.

| Tier | What runs | What it proves |
|---|---|---|
| 1 | the two published rules, compiled by real **YARA** against the generated artifact | the real claim: the rules as published do not match. **Skipped when the `yara` binary is not on `PATH`** |
| 2 | a substring assertion over the rules' distinctive strings, always | that **no listed marker survives generation** — **not that no rule matches** |

Tier 2 is weaker in two specific ways. A rule can match on a string
nobody listed, and a string can survive in a form a substring search does
not see. It is a regression guard, not a proof.

**And tier 1 has a caveat that has to be stated wherever it is quoted:
both published rules are bounded by `filesize < 60KB`, and the generated
artifact is roughly five times that.** Neither rule can fire on it
whatever it contains, so a bare "no match" would have two independent
causes and only one of them is about our bytes. Two tests beside it
remove that ambiguity rather than leaving it in a footnote:

- `test_the_checked_in_rules_still_match_what_they_were_written_for`
  synthesises a small file out of the marker list and requires both rules
  to fire on it, so a zero-match on the artifact is at least a statement
  about a working rule file and a working engine rather than about a rule
  that compiled to nothing.
- `test_the_rules_do_not_match_even_without_their_filesize_bound` strips
  the `filesize` clause at run time, into a temporary directory, and
  scans the artifact again. **It passes: neither rule matches the
  artifact even unbounded.** So the artifact escapes the published rules
  on their strings and not merely on its size — which is the claim worth
  making, and the one the size bound would otherwise have hidden.

The checked-in copies are `software/tests/data/vipertunnel.yar` and
`vipertunnel_typos.yar`. **They are not the rules as published:** the
`vt.metadata.file_type` clause is removed from each condition, because
plain YARA cannot evaluate the `vt` module, and a header comment in each
file records that edit and names its source. Removing a condition only
makes a rule easier to match, so a "no match" from these copies is at
least as strong a claim as one from the originals.

One honest note on the strings. `beacon.py` has a `_bridge` method on its
NTLM proxy relay that predates this work entirely, and one of the rules
looks for `def _bridge(self):`. Both of our methods take arguments, so
the published string does not appear — the name collides and the
signature does not. The test is what settles that, and it is why the
marker list carries the literal rather than the name.

What the delivered artifact also does not carry is **its own
attribution**. Those three names are written at the top of this section
and in `software/c2/tunnel/protocol.py`, and they are deliberately in
neither `beacon.py` nor anything the generator renders onto a host: the
generator reads `beacon.py` and ships its comments verbatim, so a section
comment naming the family or citing the analysis would hand an analyst
both the family and the write-up that burned it. The marker list carries
those three names alongside the rule strings, so a future paste cannot
bring them back. **Name the provenance here; never in a file that is
delivered.**

---

## Known limits of this arrangement

- **No tool assembles a POSIX bundle**, as above. The POSIX stager
  fetches and verifies correctly and has nothing in this repository to
  fetch.
- **The `._pth` and the `argc` gate are pending verification on a real
  Windows host.** The embeddable distribution ships a `python<XY>._pth`
  that does not import `site`, and `site` is what imports
  `sitecustomize`; the bundle builder rewrites it and refuses any shape
  it has not seen, but both halves want checking against the exact pinned
  distribution.
- **The bundle hash is not reproducible across zlib builds.** Member
  names, order, timestamps, modes, contents and the deflate level are
  pinned; the deflate stream belongs to zlib, so a build against
  zlib-ng can differ from byte-identical inputs. The consequence is a
  false alarm between two operators comparing hashes, never a weakening
  of what the stager verifies — that is the hash of the file actually
  uploaded.
- **An endpoint stop is never immediate.** It is a task. If you need the
  tunnel gone now, stop the server and accept that it takes every other
  endpoint with it.
- **A tunnel on the pure-Python cipher is slow, not broken.** The panel
  says so per row because nothing else will.

---

## See also

- [`docs/LISTENERS.md`](LISTENERS.md) — the other arrangement, and the
  one whose central guarantee this inverts.
- [`docs/REDIRECTOR.md`](REDIRECTOR.md) — putting a front host in front
  of the beacon socket.
- [`docs/AGENT.md`](AGENT.md#known-limits) — *Known limits*, held by a
  test that fails if an entry is fixed and left in the list.
