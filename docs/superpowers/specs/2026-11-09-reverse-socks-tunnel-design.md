# A reverse SOCKS5 pivot tunnel, derived from VIPERTUNNEL — design

**Date:** 2026-11-09
**Status:** awaiting approval

---

## Intent

This repository can task a host and take loot off it. It cannot route traffic
through it.

`README.md` advertises a "pivot map", and the name is generous: `server.py`
draws a canvas from `netscan` results. It is a picture of the target network,
not a path into it. There is no SOCKS proxy, no port forward and no tunnel
anywhere in `software/` — a grep for `socks` finds a port-number label in the
GUI's service table (`server.py:5939`) and nothing else. So an operator who
wants `nmap`, `netexec` or `impacket` to see the target network has to put a
second tool on the host, outside everything this project knows about.

The work closes that, by building both halves of a reverse SOCKS5 tunnel:
the endpoint runs where the beacon runs, and the operator gets an ordinary
SOCKS5 port on the team server.

### Why VIPERTUNNEL is the starting point

VIPERTUNNEL is a Python reverse-SOCKS backdoor documented by InfoGuard Labs
in *Slithering Through the Noise* (2026-04-09), attributed to UNC2165/EvilCorp
activity and observed as a follow-on payload to FAKEUPDATES infections. A
client sample is public. It is a good starting point for three reasons: it
solves exactly this problem, it is pure-Python like our beacon, and its
protocol is small enough to read in full.

**Only the client is public.** The C2 side has never been published, so the
counterpart here is derived from the client's code rather than copied. That
derivation is written out under "The protocol we inherit" below, because it
is the one part of this design that cannot be re-read from a source if it is
lost.

Two things about the original are deliberately **not** inherited, and both are
decisions the operator made during design:

1. **Its wire is plaintext.** Raw TCP on 443, no encryption at any layer.
   That is why a Shodan probe of a VIPERTUNNEL C2 returns the static bytes
   `00 00` — the keep-alive, leaking from the command socket to anyone who
   connects. This project encrypts every channel, so the tunnel is
   re-specified over the Noise Protocol Framework.
2. **Its persistence is its best-documented indicator.** The investigators
   found it by aggregating Autoruns across endpoints and noticing a scheduled
   task with a numeric name launching `pythonw.exe` with no arguments — per
   the write-up, atypical to the point of being the lead itself. The
   *mechanism* is worth having. The *artifacts* are burned.

---

## Goals

1. An operator points `proxychains`, `nmap` or `netexec` at a port on the team
   server and reaches the network the beacon sits in. Standard RFC 1928
   SOCKS5 on that side, so no tool needs to know this project exists.
2. **One fixed SOCKS port per tunnel identity**, stable across restarts of
   the tunnel, the endpoint and the team server. See "Identity and the port
   table" for why the agent's display name cannot be that identity.
3. The tunnel endpoint runs **both on the Pi and on any other host the beacon
   reaches**, from the same generated artifact — including the Pi case where
   systemd starts it and no beacon hands it anything.
4. Every byte on both the command and the relay channel is encrypted and
   authenticated, with forward secrecy, under
   `Noise_NKpsk0_25519_AESGCM_SHA256`.
5. A tunnel that dies, hangs or is killed **cannot take the beacon with it**.
6. The tunnel is a configured, named object in the operator interface that can
   be listed, started and stopped, in the manner of the Listeners panel — with
   the two objects of that sentence kept apart, per "The operator surface".
7. **Optional** bring-your-own interpreter: a stager that probes for a usable
   Python and fetches one only when it finds none, from a configurable
   **dead-drop list** with a pinned hash per entry — so a deployment can be
   staged without the target ever contacting the team server. The bundle is
   **assembled and hashed by a repository script; uploading and revoking it
   are the operator's**, per "Bringing an interpreter".
8. The generated artifact **does not match the published VIPERTUNNEL YARA
   rules**, proven by a two-tier test: real YARA where the engine is present,
   and an always-on marker assertion where it is not.
9. IPv6 target addresses work (`ATYP=4`). The original refuses them; we write
   both sides, so the refusal is a bug we do not need to reproduce.
10. The whole Windows chain is **verified on a real Windows host**, not
    asserted: `python._pth`, the `argc` gate, task creation, and a stager run
    from nothing to a checked-in beacon.

## Non-goals

1. **Not a faithful VIPERTUNNEL on the wire.** This was the explicit fork in
   the design conversation: either the thing is byte-faithful so a
   network-side detection can be measured against it, or it is a usable,
   consistently encrypted pivot tool. The operator chose the tool. A
   byte-faithful build for detection measurement remains possible and belongs
   in the Mythic engagement next door (`../Mythic2`), which exists for exactly
   that and whose rules differ — see "Findings to record".

2. **No SOCKS5 `BIND`, no `UDP ASSOCIATE`.** The original refuses both and
   logs them. We refuse them too, with a reason on the wire. UDP through the
   tunnel would carry its own session table and buffering discipline and is a
   separate project.

3. **No Mythic integration.** The conversation started there, and the answer
   turned out to be that this repository is the better home: stdlib-only like
   the original, an egress proxy already solved, and a real capability gap.
   Nothing here depends on Mythic, and nothing here is built for it.

4. **No change to the beacon's existing wire protocol**, and no change to the
   team server's two-socket property. The tunnel server is a separate process
   with its own sockets; the process holding the fleet, the loot and the
   operator interface still listens on exactly two.

5. **No new dependency on the implant side.** `beacon.py` stays stdlib-only.
   The server side may use `cryptography`, which `software/requirements.txt`
   already carries.

6. **Not a general-purpose SOCKS server on the implant.** It answers what the
   tunnel asks of it and nothing else, the way the SMB listener answers the
   beacon's handshake and nothing else.

## Anti-goals

Things that would make this a failure even if traffic flowed:

- **A tunnel whose failure costs the beacon.** The beacon is the access; the
  tunnel is the convenience. This ordering decides the architecture below.
- **A dead-drop fetch without hash verification.** An unverified drop is a
  remote-code-execution hole in our own implant: whoever can write to that
  gist or bucket owns every host staged from it.
- **A SOCKS port that points at a different agent than the operator thinks.**
  The failure mode is scanning the wrong network and finding out in the
  report.
- **A tunnel that is unusably slow without saying why.** Pure-Python AES-GCM
  moves roughly 50–200 KB/s. That is fine for the beacon's small messages and
  useless for a pivot, and "nmap is slow" must not be debuggable only as a
  network problem.
- **Matching the published VIPERTUNNEL YARA rules.** Five rules are in the
  write-up's appendix. A build that trips them inherits the detection along
  with the design.
- **A new scanner fingerprint.** `00 00` on connect is how the original's
  infrastructure was enumerated across providers. Anything equally
  deterministic on an unauthenticated connection is the same mistake with
  different bytes.
- **The tunnel server holding the beacon encryption key.** It has no business
  reading beacon traffic, and it is a new secret-bearing process either way.

---

## Constraints

- Python 3.9, implant side stdlib-only, no new entry in
  `software/requirements.txt`.
- **An HTTP `CONNECT` proxy will carry port 443 and nothing else.** Squid
  ships `acl SSL_ports port 443` with `http_access deny CONNECT !SSL_ports`,
  and the lab Squid next door is an allowlist on top of that. Any design that
  needs a second, unpredictable destination port does not work behind a
  corporate proxy — which is most of the hosts this is for. This constraint
  killed the original's dial-back-to-an-ephemeral-port shape; see "One port".
- Noise transport messages are capped at 65535 bytes including the 16-byte
  tag, so the framing and the relay read size are bounded by it, not chosen
  freely.
- The existing suite must stay green:
  `python3 -m unittest discover -s software/tests -t . -p "test_*.py"`.
  Read the current count at build time rather than trusting a number written
  here.
- `docker-compose.yml` runs with `network_mode: host`, so there is no port
  mapping available to the tunnel container either; a bind address is a real
  bind address.
- This machine has long-standing occupants on 8443 and 8099. Test rigs take
  ephemeral or explicitly chosen free ports, never defaults.
- The team server's operator socket is loopback-only, and the operator-facing
  SOCKS ports must be too — but loopback is not isolation from other local
  users, which is why those ports authenticate.
- **A Windows host is available for verification** (confirmed by the operator
  during design), so goal 10 is a real test rather than a documented gap.

---

## Approaches considered

All three put the same server-side component on the team server. They differ
in where the endpoint lives on the target host, which is the decision that
matters.

| | Approach | Trades |
|---|---|---|
| A | **Thread inside the beacon**, started by a `tunnel` command in the existing `cmd ==` dispatch (`beacon.py:4111`) | One artifact, `ProxyDiscovery` and `_NtlmProxyRelay` in-process for free. But the tunnel carries operator-chosen traffic that hangs and crashes, and takes the beacon with it when it does; and it shares the GIL with the beacon loop, so bulk crypto distorts the beacon's cadence |
| B | **Separate process from the same artifact** — the generated blob knows a tunnel mode and re-executes itself into it | Failure isolation; crypto load cannot touch the beacon's timing; on the Pi it becomes a systemd unit beside `raccoon-beacon.service`, matching `beacon_standalone.py`. Still one *delivered* artifact, because delivery is a generated one-liner that can carry both modes. Costs a second process on the host, and a parent/child relationship is itself an indicator |
| C | **Multiplexed over the existing beacon transports** — no new socket at all | Zero new network surface, inherits profiles, redirector and listeners. But every SOCKS segment becomes a beacon round trip, which makes `nmap` and `netexec` unusable; DNS carries nothing upstream at all; and the derived protocol disappears |

**Chosen: B.** The reasoning is already in this repository. For the listeners,
separate processes were chosen over threads for failure isolation and the
choice was written down. On the implant side the same argument is stronger,
because here the unstable component and the access are different things: the
tunnel is the part that will be killed, hung and crashed, and the beacon is
what gets you back. B's usual drawback — a second artifact to deliver —
does not apply, because `api_beacon_gen` (`server.py:1106`) already emits a
single self-contained blob and can emit one that holds both modes.

C is recorded so the decision against it is documented, not because it was
close. It is the most consistent with the repository and the wrong tool for
the stated purpose.

---

## The design

### The protocol we inherit

Derived from the public client by reading it, since no server exists to read.
This is reference material: our own protocol keeps the **shape** and replaces
the bytes.

The command connection, implant → C2, port 443:

| Direction | Bytes | Meaning |
|---|---|---|
| C2 → implant | `uint16` **little-endian** | A relay port to dial. `0` is a keep-alive |
| implant → C2 | `uint16` = 0 | Keep-alive answer. This is the `00 00` Shodan reads |

For each non-zero port the implant dials `(c2_address, port)` and then speaks
a SOCKS5-shaped exchange in which **the implant is the server and the C2 is
the client**:

| Step | Bytes | Deviation from RFC 1928 |
|---|---|---|
| Greeting | `nmethods(1) \| methods(n)` | **No version byte** |
| Method select | `1` byte: `0` none, `2` user/pass, `255` unacceptable | — |
| Auth | `ulen(1) \| plen(1) \| uname \| passwd` | RFC 1929 interleaves them as `VER ULEN UNAME PLEN PASSWD` |
| Auth reply | `1` ok / `0` fail | **Inverted**: RFC uses `0` for success |
| Request | `cmd(1) \| atyp(1) \| addrlen(1) \| addr \| port(2 LE)` | No version, no RSV, `addrlen` always present even for IPv4 where it is then ignored, port **little-endian** |
| Reply | `status(1)`, then `atyp(1)=1 \| addrlen(1)=4 \| addr(4) \| port(2 LE)` | `1` = success, `0` = failure |
| Then | raw bidirectional relay | — |

Two structural properties follow, and both shape our version:

- **A relay connection carries no identity.** The implant simply dials the
  port it was given. The C2 must therefore open one relay port per pending
  session and pair by port — which is why the write-up's Shodan scans show a
  spread of five-digit ports on these hosts. It also means that in the
  original, whoever reaches the relay port first takes the session.
- **There is no implant identity on the command channel either.** The C2
  knows a connection, not a host.

### Our protocol

Same shape, three changes.

**1. Everything is Noise.** `Noise_NKpsk0_25519_AESGCM_SHA256`, on both the
command and the relay channel.

| Part | Why this one |
|---|---|
| `NK` | The initiator (implant) is configured with the responder's (server's) static public key, and presents no static key of its own. That is the deployment model this repository already has for `c2.encryption_key`: one value baked into the build. It authenticates the server and gives forward secrecy, and the implant stays anonymous on the wire |
| `psk0` | The pre-shared key is mixed in before anything else, so the **first** handshake message is already unforgeable and indistinguishable from random without it. An unauthenticated prober gets no deterministic response at all, which is the direct answer to the `00 00` fingerprint |
| `AESGCM` | Both backends already exist and are tested in `beacon.py`: OpenSSL via ctypes (`_load_libcrypto`, `:101`; `_aes_gcm_encrypt`, `:374`) and a complete pure-Python fallback, selected by `_USE_PURE_PYTHON_AES` (`:329`). ChaChaPoly is the more usual Noise pairing and was rejected: it buys nothing here and costs new pure-Python cipher code with no reuse |
| `SHA256` | `hashlib`; HKDF is `hmac` over it, about ten lines |

The only new primitive on the implant is **X25519**, and it follows the
pattern the AES code already set: ctypes OpenSSL (`EVP_PKEY_X25519`) as the
fast path, a pure-Python Montgomery ladder as the fallback. Handshake-only, so
the slow path costs one scalar multiplication per connection rather than
per byte.

Framing: `uint16` **big-endian** length, then the Noise message. Big-endian
deliberately — the original's little-endian ports are a documented
VIPERTUNNEL trait and there is no reason to keep a fingerprint we do not need.

**2. One port, and the role of a connection is decided inside the
encryption.** The original opens a fresh ephemeral relay port per pending
session; the constraint above makes that undeployable behind a proxy. So
**every connection — command and relay — goes to the same port**, and the
responder learns which it is from the first handshake payload: `HELLO` for a
command channel, `RELAY(token)` for a relay. `NKpsk0`'s first message carries
a payload that is already confidential and authenticated, so the token is
never visible and an unauthenticated party cannot even produce a
well-formed first message.

That costs the prologue binding and keeps the property it existed for: a
connection that cannot present the 32-byte token the server issued over the
authenticated command channel cannot take the session. "Whoever connects
first" still does not work. It also means a scan of the port sees one TCP
service that answers nothing deterministic, and a proxy sees one destination
on 443.

**3. The implant identifies itself.** The command channel's `HELLO` carries a
tunnel identity, the host's `_implant_id`, hostname and OS. The original has
no identity on the command channel at all — the C2 knows a connection, not a
host — and goal 2 is impossible without one. Which identity, and why not the
obvious one, is the next section.

Message types on the command channel, one leading byte: `HELLO`, `RELAY`,
`OPEN_RELAY`, `PING`, `PONG`, `CLOSE`. Keep-alive is `PING`/`PONG` on a
configurable interval — not a zero port, because that is the published trait.

Inside a relay channel, the SOCKS exchange keeps the original's shape with the
deviations removed: version bytes restored, ports big-endian, `0` for success,
`ATYP=4` supported. **The inherited user/pass step is dropped**: under Noise
with a token-bound relay it authenticates nothing, and its credentials in the
original are `AnyLogin` / `AnyPassword`, which are themselves two of the YARA
strings in goal 8.

### Identity and the port table

The obvious identity is the one the fleet already uses, and it is the wrong
one. `agent_id` is assigned server-side by `_assign_name` (`server.py:168`)
from a word list plus `name_counter`, and `_save_state` (`:217`) is called
only from the result and scan-save paths (`:463`, `:2346`) — never on
registration. Register agents that never return a result, restart the team
server, and the counter rewinds: the next host to register takes a name a
previous host had. A SOCKS port pinned to that name then points at a different
network than the operator believes, which is this document's own anti-goal
word for word.

So:

| Thing | Where it comes from | What it is for |
|---|---|---|
| **Tunnel identity** | generated **per build**, baked into the config block beside the PSK | The key of the port table. Stable by construction, because it is a constant in the artifact |
| `_implant_id` | the implant computes it (`beacon.py:1443`, sha256 over node, machine and MAC) | Correlating a tunnel to a fleet row, and to other tunnels on the same host |
| `agent_id` | server-assigned display name | Display only. Never a key |

Two consequences worth stating. A tunnel whose `_implant_id` matches no known
agent is shown as **unlinked** rather than hidden — on the Pi, systemd starts
the endpoint with no beacon involved, and that is a supported deployment, not
an error. And two builds deployed to one host get two identities and two
ports, which is the behaviour one wants; a second connection claiming an
identity that is already connected is refused, and the refusal is logged with
both peers.

### Keys, PSKs and who holds what

| Secret | Minted by | Lives | Scope |
|---|---|---|---|
| Noise static keypair | the tunnel server, on first start | private half with the server's other secrets, `0600`, **not** in `raccoon.yaml` | one per deployment |
| Static **public** key | — | read by the generator over the control socket | baked into every build |
| PSK | the generator, per build | registered with the tunnel server at generation time | **one per build** |
| Tunnel identity | the generator, per build | baked into the build, registered alongside the PSK | one per build |

A per-build PSK is the part that matters. Under `NKpsk0` the implant presents
no static key, so possession of the PSK plus the server's public key *is* the
whole credential — one PSK shared across every build would mean a single
captured implant lets anyone complete the command handshake and assert any
identity in `HELLO`, which walks straight back into the anti-goal above.
Per-build means the credential and the identity are issued together, the
server can hold several at once, and **retiring a burned build is deleting its
PSK** rather than rotating everything.

The secret stays out of the config file, following the rule this repository
already set for `RACCOON_LISTENER_TOKEN`: a shared secret does not belong in
something somebody will paste into a ticket. On the Pi, where goal 3 needs the
endpoint configured without a beacon, a `c2.tunnel` block in
`configs/raccoon.yaml` carries the server address, port and public key, and
`beacon_config_from_fallback` (`beacon.py:551`) is extended to read it — with
the PSK supplied through the environment and a systemd `EnvironmentFile`.
**That extension is in scope for this work**; without it goal 3 is unreachable.

### Two sockets, and the tunnel is a third kind of thing

The tunnel server is a **separate supervised process** on the team server
host, reusing `Supervisor` and `_Child` from `software/c2/listeners/`
(`supervisor.py:64`, `:196`, `spawn` at `:206`, `ask_status` at `:312`) and
their control-socket-plus-token discipline.

It is **not a listener**, and must not be registered in `registry.py`'s
`_TRANSPORTS`. Two reasons, and the second is the important one:

- It relays no beacon message, so there is nothing for it to forward to the
  beacon socket.
- `docs/LISTENERS.md` opens with the property everything there rests on: **no
  listener is ever given the encryption key**, which is what makes a listener
  safe to put on a host you do not mind losing. The tunnel server holds a
  Noise static private key and the PSKs. It **inverts** that property. Filing
  it among the listeners would quietly contradict the one guarantee that
  document leads with, so it gets its own package, its own panel section and
  its own paragraph saying so.

Its sockets:

| Socket | Bound to | Purpose |
|---|---|---|
| Implant-facing | one port, reachable or behind a redirector | Command channels **and** relay channels. One destination, so a `CONNECT`-only proxy and a redirector can both carry it |
| SOCKS5 | **loopback only**, one fixed port per tunnel identity | Where the operator's tools connect |

Both are the tunnel server's own. The process holding the fleet, the loot and
the operator interface still listens on exactly two sockets and gains nothing.

### The endpoint on the host

One artifact, two modes. `api_beacon_gen` already appends a generated config
block to `beacon.py`'s source and wraps the whole thing in 1–6 zlib+base64
layers; a `tunnel` block joins `https`, `dns`, `smb`, `quic`, `proxy` and
`c2_profile` in `gen_cfg`, carrying the server address and port, its static
public key, the PSK, the tunnel identity, the keep-alive interval and whether
the mode is permitted at all.

**How the child is started, because the obvious answer is wrong.** The
delivered artifact is `python3 -c '…'`, and under `-c` **`sys.argv[0]` is the
literal string `-c`** — so "re-execute from the same path" has no path, and
`_get_beacon_path` (`beacon.py:3250`) already returns something useless in
precisely the mode this project ships. Of the four ways out, three are bad:
re-executing `python -c '<blob>'` puts the whole multi-megabyte payload in
`ps` and `/proc/<pid>/cmdline`; writing the source to disk and executing it
throws away the in-memory property the one-liner exists for; and `fork()` does
not exist on Windows, where most of this design lives.

So the tunnel child is started as **`python -`, with the source handed over on
stdin**: an unremarkable command line, no file on disk, and the same mechanism
on both platforms. The requirement this places on the generator is that **the
running artifact must be able to hand its own source to a child** — the
outermost layer keeps the payload reachable instead of discarding it after
`exec`. Several shapes satisfy that; which one is the builder's.

The beacon's `tunnel` command spawns the child, records it, and reports its
state in the check-in; `tunnel stop` terminates it. Nothing is shared in
memory, so a tunnel that hangs is a child that gets killed.

Because it is the same source, the tunnel mode already has the crypto, the
`ProxyDiscovery` (`beacon.py:1065`) and the `_NtlmProxyRelay` (`:648`) that
getting out of a corporate network needs — no refactor of a 4444-line module
is required to share them. The relay is a local CONNECT proxy, so the tunnel
dials `127.0.0.1:<relay port>` and issues its own `CONNECT <server>:443`;
`_bridge` (`:898`) already carries the raw stream afterwards. That is the
piece the original lacks entirely: VIPERTUNNEL does a bare
`socket.connect((ip, 443))` and cannot cross a proxy at all.

**The throughput gate.** When `_USE_PURE_PYTHON_AES` is true, the tunnel
refuses to start by default and says why, with an explicit override for an
operator who wants a slow tunnel anyway. This is the repository's own rule —
a config that cannot work is an error when it is read, with the offending
value in the message — applied to a performance floor instead of a typo. The
panel shows the crypto path for any running tunnel, so the slow case is
visible where it would otherwise be diagnosed as a network fault.

### The operator surface

**Two objects, deliberately not one.** The Listeners panel's start and stop
drive a supervised process; a tunnel row is an agent's endpoint. Conflating
them would give the operator a button that promises something it cannot
deliver:

| Object | Start/stop means | How fast |
|---|---|---|
| The tunnel **server** | `Supervisor.start`/`stop` on the local process | Immediate, and it drops **every** endpoint at once — the panel says so before it acts |
| An **endpoint** | a `tunnel` / `tunnel stop` task queued for that agent | Takes effect at the next check-in. The row shows **pending**, with the interval and the expected time, until the agent confirms |

A stop that silently takes five minutes is the cousin of the neighbouring
design's "start button that silently does nothing", and this is how it is
avoided: the latency is displayed rather than hidden.

Per row: state, the fixed SOCKS port, open sessions, bytes each way, the age
of the last keep-alive, the crypto path, and whether the tunnel is linked to a
fleet agent or unlinked. Ports are assigned from a configured range, recorded
against the tunnel identity, and **stable across restarts**. The panel never
re-points a port at another identity.

**The operator-facing port authenticates.** SOCKS5 user/pass per RFC 1929,
with a per-identity credential generated by the tunnel server and shown in the
panel. Loopback keeps other hosts out; it does nothing about other local users
on the team server, and an unauthenticated port there is a pivot into the
target network for anyone with a shell. It is a few lines now and a change to
every operator's `proxychains.conf` later, so it goes in from the start.
*Designer's call; the operator did not ask for it.*

### Persistence

The existing methods stay. Two changes, and one new optional layer.

**Names stop being constants.** `_exec_persist` (`beacon.py:3253`) writes the
literal `SystemHealthMonitor` as both the HKCU Run value (`:3272`) and the
scheduled task name (`:3291`), identically in every deployment — one burned
engagement burns the name everywhere. It becomes a per-build generated name,
carried in the config block, with `_exec_unpersist` (`:3353`) reading the same
value rather than its own copy of the literal.

**The payload path stops being mandatory on the command line.**
`_get_beacon_path` (`:3250`) puts `sys.argv[0]` into the command line, so the
Run key and the task both name the payload. Where we brought our own
interpreter, the VIPERTUNNEL mechanism removes that: a `sitecustomize.py`
inside the interpreter's own `Lib/` is auto-imported at startup, checks its
`argc` through `ctypes.pythonapi.Py_GetArgcArgv`, and runs the payload only
when launched bare.

**The trade this makes, stated because it is the whole point of the trick:**
an `argc == 1` gate buys invisibility in command-line telemetry and pays for
it with an anomaly in process and Autoruns telemetry — a `pythonw.exe` with no
arguments, which per the write-up barely occurs legitimately and was the lead
that unravelled the original. So the gate is a per-build switch,
`gate: "path" | "argc"`, defaulting to **`path`**: a plausible script path on
the command line, unremarkable in Autoruns. `argc` is there for an engagement
whose telemetry is the other way round. *This default is the designer's call,
not something the operator asked for; it is cheap to flip.*

**`sitecustomize.py` requires an interpreter we brought.** Dropped into a
host's system Python it would arm on every Python invocation by every user —
loud, and operationally dangerous. The two features are therefore coupled: no
brought interpreter, no sitecustomize, and the gate switch has no effect.

### Bringing an interpreter, optionally

The generator's output today is `python3 -c '…'` / `python -c "…"`, which
presupposes an interpreter: a Python one-liner cannot install Python. So
bring-your-own is a **second artifact shape** from the same generator — a
PowerShell or shell **stager**, which:

1. probes for a usable interpreter and, finding one, runs the ordinary
   one-liner and stops there;
2. otherwise walks a **dead-drop list**, in order, until a bundle verifies;
3. lays out `<base>/` with the interpreter, `Lib/sitecustomize.py` and the
   payload under generated names;
4. installs persistence under the per-build name.

"Optional" is therefore a runtime property of the stager, not a build flag:
it brings something only when it finds nothing.

**The dead-drop list is `[{url, sha256}]`, ordered, and the team server is
optional and last** — or absent, which is the point the operator raised: with
an external drop the target speaks only to GitHub, S3 or a CDN until the first
beacon check-in, so staging does not burn the C2 address. The repository
already has the pattern: `api_beacon_gist` (`server.py:1191`) creates a secret
gist and hands back a `raw_url`, with a DELETE route and a liveness check
beside it for revocation.

**Scope, as the operator chose it: build locally, upload by hand.** A script
under `tools/` assembles the bundle — fetch the pinned embeddable
distribution, verify it against its own published hash, insert
`Lib/sitecustomize.py`, adjust `python._pth`, lay out the payload under the
build's generated names, hash the result — and prints the
`{url, sha256}` entry for the operator to paste once the file is uploaded.
**No server route builds or publishes anything**, and revocation is the
operator deleting the drop. The liveness-check pattern beside `beacon-gist` is
reused only as a *check* — "is this drop still answering" — never as an upload
path. The alternative, a full build-and-publish pipeline with revocation on
the team server, is comparable in size to the tunnel server itself and was
declined.

**Hash verification is mandatory and has no override.** The precedent is the
operator's own rule from the Mythic engagement: the NSSM binary is pinned by
SHA-256 so any mirror can be used and then verified — provenance by hash, not
by trust. Here it is load-bearing rather than tidy, for the reason in the
anti-goals.

**A gist is the wrong container for this.** It is a text repository, the API
truncates files over 1 MB, and base64 of the embeddable distribution is
roughly 15 MB. A GitHub release asset fits (same account, same `gh` CLI,
binary-friendly), as does S3 or Azure Blob with a presigned URL. Splitting a
bundle across gists is possible, noisy and fragile; it is not the plan.

**What the bundle does not need.** VIPERTUNNEL shipped third-party modules —
blake3, pycryptodome — because its crypto needed them. Ours does not: stdlib
plus the `libcrypto` DLL that the embeddable distribution already carries. The
bundle is therefore the official distribution plus two files, and on a
brought-interpreter host the throughput gate above is satisfied for free,
because ctypes finds a real libcrypto.

**The `._pth` trap, and that it gets verified rather than assumed.** The
official Windows embeddable distribution ships a `python*._pth` that does not
import `site`. Where that holds, `sitecustomize.py` is never imported and the
whole hook is dead until the `._pth` is adjusted. A Windows host is available,
so this is checked against the exact distribution the stager fetches, and that
version is pinned in the dead-drop entry alongside its hash.

### What the Windows host verifies

Goal 10, enumerated so it is a checklist and not a sentiment. On the real
host, against the exact pinned distribution:

1. `python._pth` as shipped: does `sitecustomize.py` run at all, and what
   edit makes it run.
2. The `argc` gate through `ctypes.pythonapi.Py_GetArgcArgv` — including that
   it reads 1 for a bare `pythonw.exe` and more than 1 for the `path` default,
   since the whole switch rests on that number.
3. Task and Run-key creation under the per-build generated name, and their
   removal by `_exec_unpersist`.
4. A stager run from nothing: no Python on the host, bundle fetched from a
   dead drop, hash verified, layout written, persistence installed, beacon
   checked in, tunnel started, a SOCKS session carried end to end.
5. That the tunnel child's command line shows no payload (the `python -`
   decision above), read from the actual process list rather than inferred.

### Not matching the rules we came from

The write-up's appendix carries five YARA rules. Two of them bear on this
work and are reproduced in the appendix below so the builder does not have to
find them: `MALWARE_vipertunnel` and `MALWARE_vipertunnel_typos`. The other
three target the ShadowCoil packer and VirusTotal metadata — we use neither,
so they cannot match.

What would match a careless port: class names `Wire`, `Relay`, `Commander`,
`ControllerCommandConnection`, `MySocket`, `MyServiceSocket`, `Handler`; the
exception names `ConnectionTimeoutOccuredError`, `BadLengthData`,
`CloseException`, `ExitException`; the markers `main_flag_to_close`,
`TIMEOUT_FOR_SOCKET_OPERATION`, `self.must_equal`, `def _bridge(self):`,
`socket.socket = Wire`; the credentials `AnyLogin` / `AnyPassword`; and the
original's own typos, `allow_no_verifing`, `__setatrr__`, `deamon`.

**The test is two-tiered, because one tier cannot be had unconditionally.**
`yara-python` is not in `software/requirements.txt` and the Constraints
forbid growing it, so:

1. **Real YARA** against the checked-in rule files, skipped when the engine
   is absent — the `skipUnless` precedent is already in
   `test_c2_hardening.py`. This is the real claim.
2. **An always-on marker assertion** over the string list above, run against
   the *generated* artifact rather than the source. This is the weaker claim
   and the documentation must say so: it proves no listed marker survives
   generation, not that no rule matches.

Two notes for whoever writes it. The checked-in copies need their
`vt.metadata.file_type` conditions removed, because plain YARA cannot
evaluate the `vt.` module — keep the strings and the counting logic, drop the
VT clause, and record the edit in a comment so the copy is not mistaken for
the original. And one of our own reused helpers is already named `_bridge`
(`beacon.py:898`); it is a method on the NTLM relay, predates this work, and
the rule's string is `def _bridge(self):`, so the test is what settles whether
that matters rather than an argument in this document.

---

## Findings to record, not fix here

- **`_exec_persist` has a second hardcoded-name problem beyond this scope.**
  The `startup`, `bashrc` and `systemd` branches carry their own fixed
  strings. This work changes the Run key and the scheduled task because the
  brought-interpreter layout touches them; the rest should follow in one pass
  rather than drift into two conventions.
- **`README.md`'s "pivot map" invites the reading that pivoting exists.** It
  is a visualisation. After this work there will be an actual pivot, and the
  two should be named differently in the README so the picture and the path
  are not confused.
- **The neighbouring Mythic engagement forbids exactly this persistence, and
  that rule does not travel.** `../Mythic2/CLAUDE.md` records a deliberate
  service-level-only policy — no Run keys, no scheduled tasks, no WMI
  subscriptions — because host telemetry there would contaminate a
  network-side measurement. TrashPandaPaws already carries five autorun
  layers and has the opposite purpose. Anyone moving code between the two
  repositories needs to know the policies differ and why.
- **A byte-faithful VIPERTUNNEL remains unbuilt.** The derived protocol table
  above is enough to build one, and `../Mythic2` is where it would belong.
  Recorded so the derivation is not re-done from scratch.

---

## Calls the designer made

A fresh engineer read this document before it was handed over and came back
with nine questions. Two were genuine flaws and are fixed above — the
ephemeral relay port, which no corporate proxy would carry, and `agent_id` as
the port key, which could have pointed a port at the wrong host after a
team-server restart. Two went to the operator and are answered above. The
remaining five are decided here rather than asked, and are listed so they can
be checked while reading:

| Call | Where | Flip cost |
|---|---|---|
| Role of a connection decided by the first authenticated payload, not the Noise prologue | "One port" | Low, protocol-internal |
| Per-build PSK and per-build tunnel identity, static keypair minted by the server, secrets out of the YAML | "Keys, PSKs and who holds what" | Moderate: touches the generator API and the config schema |
| Tunnel child started as `python -` with the source on stdin | "The endpoint on the host" | Low, one call site |
| Server and endpoint are two objects, with the endpoint's stop shown as pending | "The operator surface" | Low, panel and routes |
| SOCKS5 user/pass on the operator-facing port, generated per identity | "The operator surface" | Cheap now, expensive later — every `proxychains.conf` |

The `gate: "path" \| "argc"` default is a sixth, recorded in "Persistence"
where the trade it makes is explained.

---

## What is left to the builder

- Module layout under `software/c2/tunnel/`, and whether the SOCKS translation
  sits with the server or in its own module.
- The exact framing constants, message-type byte values and relay read size
  under the 65535-byte Noise cap.
- Which pure-Python X25519 implementation shape to use, and how to test it
  against the ctypes path (a known-answer test against RFC 7748 vectors is the
  obvious floor).
- Which shape satisfies "the artifact can hand its own source to a child" —
  several do.
- Session bookkeeping: where open sessions, byte counters and port assignments
  live, and whether they survive a team-server restart. The port table itself
  must survive it; the counters need not.
- The panel's icon and its position in the header.
- Whether the stager is PowerShell-only on Windows or also a batch fallback,
  and what it does when every dead drop fails.
- The test rig's shape: a local tunnel server, a beacon in tunnel mode, and a
  SOCKS client, in the manner of the existing listener rig.
- Log format and where tunnel logs go, given that the team server's own logs
  are operator-visible in the interface.

---

## Appendix: the two rules goal 8 is measured against

From the write-up's appendix, reproduced so the builder has the text. **The
checked-in copies must drop the `vt.metadata.file_type` clause** — plain YARA
cannot evaluate the `vt.` module — and a comment should record that edit.

```yara
rule MALWARE_vipertunnel {
    meta:
        author = "Evgen Blohm"
        description = "hunting rule for socks5 backdoor aka VIPERTUNNEL"

    strings:
        // Unique Class Names and Functions
        $class1 = "class Wire(" ascii wide
        $class2 = "class Relay(" ascii wide
        $class3 = "class Commander(" ascii wide
        $class4 = "class ControllerCommandConnection" ascii wide
        $class5 = "class MySocket" ascii wide
        $class6 = "class MyServiceSocket" ascii wide
        $class7 = "class Handler" ascii wide

        // Custom Exception Names
        $exc1 = "ConnectionTimeoutOccuredError" ascii wide
        $exc2 = "BadLengthData" ascii wide
        $exc3 = "CloseException" ascii wide
        $exc4 = "ExitException" ascii wide
        $exc5 = "ConnectionClosedError" ascii wide
        $exc6 = "ConnectionResetError" ascii wide
        $exc7 = "ConnectionAbortedError" ascii wide
        $exc8 = "ConnectionRefusedError" ascii wide

        // Logic-specific strings
        $logic1 = "self.must_equal = " ascii wide
        $logic2 = "struct.unpack('BBB', self." ascii wide
        $logic3 = "def _bridge(self):" ascii wide
        $logic4 = "socket.socket = Wire" ascii wide

        // unique variables
        $var1 = "main_flag_to_close" ascii wide
        $var2 = "TIMEOUT_FOR_SOCKET_OPERATION" ascii wide

        // Unique Identifiers
        $user = "AnyLogin" ascii wide
        $secret = "AnyPassword" ascii wide

    condition:
        filesize < 60KB and vt.metadata.file_type == vt.FileType.PYTHON and (
            (3 of ($class*) and 3 of ($exc*)) or
            (2 of ($class*) and 2 of ($exc*) and 1 of ($logic*) and 1 of ($var*)) or
            ($user and $secret)
        )
}

rule MALWARE_vipertunnel_typos{
    meta:
        description = "Hunting for ViperTunnel Python Proxies using some left over typos"
    strings:
        $typo1 = "__setatrr__" ascii wide // __setattr__
        $typo2 = "deamon" ascii wide // daemon
        $typo3 = "allow_no_verifing" ascii wide // allow_no_verifying
        $typo4 = "ConnectionTimeoutOccuredError" ascii wide // ConnectionTimeoutOccurredError
        $typo5 = "% ((target" ascii wide // logged as tuple

    condition:
        filesize < 60KB and vt.metadata.file_type == vt.FileType.PYTHON and (
            (3 of ($typo*))
        )
}
```

Note that `$exc5`–`$exc8` are names Python itself defines
(`ConnectionClosedError` aside), so a build that merely *catches* them is not
at risk; the rule needs three of them **plus** three class names. The
`filesize < 60KB` bound is also worth knowing: the generated artifact is far
larger, so the published rules would not fire on it as written even if a
string survived. The test therefore checks the strings, and the documentation
says that is what it checks.

