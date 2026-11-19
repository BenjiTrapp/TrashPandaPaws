# Listeners

The beacon speaks five transports. The team server answers one of them —
HTTPS, on its beacon socket. Three more are answered by *listeners*: small
separate processes that terminate one protocol each and carry the payload to
that same beacon socket over HTTP. The fifth, `gsocket`, is answered by a
**carrier**: a `gs-netcat` process beside the beacon socket that meets the
implant's own on a third-party relay network, and that is the one transport
with no address to configure at all. It has [its own section
below](#the-fifth-transport-gsocket-over-the-gsrn), and you should read what
it costs before you switch it on.

This document is what an operator needs to run them. For why they are
separate processes rather than threads in the team server, see
[`docs/superpowers/specs/2026-11-07-c2-listeners-design.md`](superpowers/specs/2026-11-07-c2-listeners-design.md).

---

## The one property everything else rests on

**No listener is ever given the encryption key.** It receives a string
that is already encrypted, posts it to the team server, and hands back
the string that comes the other way. It cannot read beacon traffic and it
cannot forge it.

That is what makes a listener safe to put somewhere exposed — a cheap
forwarding host, a container with one published port, a box you do not
mind losing. A compromised listener can drop messages or replay them, and
replay is a recorded property of the protocol itself rather than
something this arrangement introduces.

Two tests hold it for every listener module, and the container image is
built so that `beacon.py` and `server.py` are not even present.

**One thing in this repository inverts this property, and it is not a
listener.** The reverse SOCKS tunnel server mints and holds an X25519
static private key and every build's pre-shared key — see *The one
property that is different here* in [`docs/TUNNEL.md`](TUNNEL.md). That
is why it is a separate package with its own panel and its own
configuration block rather than a fourth entry in `c2.listeners`: filing
it here would have left this section reading like a guarantee for the
whole project. It runs on the team server host, not on a forwarding host
you do not mind losing.

---

## The three transports

| Transport | Direction | Registration | Results | Default port |
|---|---|---|---|---|
| `smb` | bidirectional | yes | yes | 445 |
| `quic` | bidirectional | yes | yes | your choice |
| `dns` | **downstream only** | no | **no** | 53 |

### smb

An SMB2 named-pipe exchange: negotiate, session setup, tree connect,
create, write, read. A beacon that speaks only SMB is a complete client —
it registers, receives tasking and reports results.

It is **not a general SMB server**. It answers the handshake the beacon
performs, in the order it performs it, and nothing else: session setup is
answered with success where a real server would answer
`STATUS_MORE_PROCESSING_REQUIRED` and an NTLMSSP challenge, and there is
no signing, no encryption, no compound requests and no share but the
pipe. Anything that speaks real SMB will find it odd, and a scanner will
notice.

The whole of a result arrives in one write, so the message cap is the
ceiling on loot over this channel: 16 MiB, which is roughly an 11 MB file
once it is base64 inside the encrypted payload.

### quic

A length-prefixed framing over UDP datagrams. Not real QUIC — it looks
like it on a flow record, which is the point. Bidirectional, including
registration.

### dns

**Tasking only, and the limit matters.** The beacon sends a bare TXT
query whose name carries its identity, and reads tasking out of the
answer. Nothing travels upstream: there is no registration over DNS and
no result ever comes back.

So:

- An agent must already exist, registered over another transport, before
  DNS can reach it.
- **A task delivered this way is fire-and-forget.** It leaves the queue on
  delivery, because a task that stayed would be handed out again at every
  check-in for ever — and nothing on this channel ever acknowledges it.
  `shell reboot` on a loop is worse than a task whose outcome is unknown.
- **An agent reached this way will never report a result.** The interface
  flags one whose last contact came over DNS, and the panel repeats the
  limit next to the listener, because an operator queueing a task against
  it is owed the warning where they are doing it.

This is the one listener that needs a secret, because it reads tasking
from an authenticated route on the team server rather than relaying a
payload the beacon sent. See `RACCOON_LISTENER_TOKEN` below.

---

## The fifth transport: gsocket over the GSRN

The four transports above all need an address: a URL, a zone, a host and a
port. This one needs none. A `gs-netcat` child on the implant and a
**carrier** beside the team server's beacon socket both dial *out* to the
Global Socket Relay Network — the GSRN, a free relay service operated by The
Hacker's Choice — and the relay introduces the two to each other on the
strength of a shared secret. The secret *is* the address.

That is what the leg is for. It survives the one case the other four share:
the callback URL, the DNS zone, the SMB host and the QUIC host blocked or
burned at once. It needs no inbound port on the team server and leaves no
name on the implant's disk that an investigator can pivot from the device to
the operator's infrastructure.

It is also the only transport in this project whose traffic crosses
infrastructure nobody here operates, and the only one where reading the
settings is not enough to decide whether to switch it on. **So this section
states what it costs before it states a single setting.**

### What it costs

**The client's traffic crosses a third party.** Every byte of this leg goes
through a relay host run by somebody else. The session is end-to-end
encrypted — gsocket negotiates it with SRP, so the two ends derive the key
from the shared secret and the relay sees ciphertext only — and inside that
sits the beacon's own AES-256-GCM envelope, which no carrier and no relay can
read or forge either way. That answers the confidentiality question and not
the contractual one. Whether a client's data may transit a third-party relay
is a question for the **rules of engagement**, agreed with the client before
the engagement, and not something a default in a configuration file can
settle on their behalf. It is also a dependency: if the GSRN is down, gone or
unwilling, this leg is down with it.

**It disguises where our C2 is, not that gsocket is in use.** The handshake
to known GSRN hosts is recognisable, the relay addresses are published, and
gsocket is well-known tooling on the defensive side too — it is in threat
reports, and a mature SOC has signatures for it. What this leg buys is
reachability from a network that blocks everything we could name, and
infrastructure that cannot be attributed to the operator because it is not
the operator's. **It does not buy looking like nothing.** Judge it as the last
resort it is placed as: it runs when the other four have failed, which is
exactly when being seen matters least.

### One secret per implant, never fleet-wide

Whoever holds an implant's secret can dial the port that fronts the team
server's beacon socket. These implants are hardware left behind on somebody
else's site, so **a recovered implant image** must not hand its finder a
dialable path for the rest of the fleet — which is precisely what a
fleet-wide secret baked into every image would do.

The damage is bounded either way: what travels over that path is still sealed
in the **AES-256-GCM envelope** the beacon payload carries, so a dialer
reaches exactly as far as a compromised listener does and can neither read
beacon traffic nor forge a message. Fleet-wide, though, that bound applies to
the whole fleet instead of to one device. Per-implant keeps a recovered image
to itself: its secret dials its own carrier and nothing else, and burning it
is deleting one entry in the store.

Mint one with gsocket's own generator, on the team server:

```sh
gs-netcat -g
```

Then register it against that implant's identity, and the build generator
writes the implant's copy into a 0600 file. Do not type a secret you chose
yourself: this is a credential on a relay network anybody may join, a guessed
one is a dialable path to the beacon socket, and the store enforces a floor of
24 characters precisely because the one secret somebody hand-writes is the one
that matters.

The secret appears in no configuration file, in no command line and on no
panel. Both sides are handed `gs-netcat -k <path>`, never `-s <secret>`:
gsocket's own documentation warns against the second form, because `ps` is
world-readable on every machine a carrier might run on — and on an implant,
readable by whoever found the device.

### The two blocks, which are opposite sides

As with `c2.listeners` and `c2.fallback`, two blocks in
`configs/raccoon.yaml` read almost identically and mean opposite things. Both
ship inert: the leg disabled, the carrier list empty.

**`c2.fallback.gsocket` is this host as a client** — the leg an implant
running here will try, after the other four.

```yaml
c2:
  fallback:
    gsocket:
      enabled: false
      secret_file:                      # 0600, written by the generator
      binary_path: "/opt/raccoon/bin/gs-netcat"
      sha256: "d4a7dfda…"                # verified before every exec
      scheme: "http"
      local_port: 16443
      restart_delay_seconds: 30
      max_restarts: 0                   # 0 = unlimited
      ready_timeout_seconds: 20
```

| Field | Meaning |
|---|---|
| `enabled` | Ships `false`. **Hardware implant only**: a build the team server generates is a single file that spawns no child, and the generator refuses an enabled leg with a reason rather than shipping one that does nothing. |
| `secret_file` | The path to the 0600 file holding this implant's secret. Required while the leg is enabled; a bare key means "absent", which is what the file in git has to say. |
| `binary_path` | The `gs-netcat` this leg execs. Put there at image build time, never fetched on the target. |
| `sha256` | Checked before every exec. Empty means "do not verify", as `c2.sliver.sha256` does — but this binary is handed the secret that fronts the beacon socket, so leaving it empty answers a question nobody asked. |
| `scheme` | `http` or `https`, for the URL the beacon builds against its own forward. `http` by default because the team server's `--ssl` is off by default and every shipped `relay_url` is `http://127.0.0.1:8443`. |
| `local_port` | The loopback port the child forwards from on the implant. |
| `restart_delay_seconds` | At least 1. Zero would restart the child as fast as `gs-netcat` can fail — a busy loop on the implant's CPU and a flood of joins on somebody else's relay. |
| `max_restarts` | `0` is unlimited, the meaning it has for `c2.sliver`. |
| `ready_timeout_seconds` | How long the forward is given to come up before the leg counts as not ready for this cycle. |

**`c2.gsocket_carrier` is this host as a server** — the carrier processes run
beside this host's own beacon socket, one per implant.

```yaml
c2:
  gsocket_carrier:
    - name: implant-01
      identity: implant-01              # whose secret, by name; not the secret
      enabled: false
      beacon_host: "127.0.0.1"          # a destination, not an address to bind
      beacon_port: 8443
      binary_path: "/opt/raccoon/bin/gs-netcat"
      sha256: "d4a7dfda…"
```

There is deliberately **no `local_port`** here: this side listens on the
relay network and connects straight into the beacon socket, so it opens no
forward of its own. A wildcard `beacon_host` is refused by name, because
`0.0.0.0` here is a `bind_host` copied out of `c2.listeners` — the exact
confusion these two blocks invite.

Everything is checked when the file is read, enabled or not, and a block the
validators refuse **stops the team server at startup** with the offending
value in the message. That is not strictness for its own sake: a
misconfigured carrier surfaces as a process that joins the relay network and
never finds its peer, which reads as a relay problem rather than as a wrong
number, and is the hardest failure in this feature to tell from a network
that is simply hostile.

### Running a carrier

From the 📡 panel, beside the listeners. Its row reports *no socket* where a
listener reports bind host and port, and a pid where it has one; there is one
row per configured implant.

Under systemd, for a host that wants a carrier without the panel:
`services/raccoon-gsocket.service`. It has **no `.socket` sibling** — unlike
the three listener units, which inherit a bound descriptor because 53 and 445
are privileged. A carrier binds nothing at all, so it needs no privilege and
runs as `nobody`. It reads the path to its key file from
`/etc/raccoon/gsocket.env`, which must not be world-readable; a unit file is.

The binary comes from the image build: `software/setup/build_image.sh` fetches
a **pinned** `gs-netcat` release, checks it against a recorded SHA-256 and
installs it at `/opt/raccoon/bin/gs-netcat`. Nothing is ever downloaded at
runtime on the target, and the digest in `configs/raccoon.yaml` is the digest
of that file — a test holds the two in step. A team server installed some
other way needs its own copy at that path.

### The warm-up cycle, which is not a fault

The leg is **lazy with a warm latch**. The carrier does not run when the
beacon starts: a healthy implant holds no GSRN connection at all, because a
connection to a third-party relay is something a defender can see and nothing
an implant should be holding while HTTPS works. It starts the first time a
cycle ends with no upstream leg having delivered, and then stays up for the
life of the process, so a second outage costs no readiness wait.

The consequence is visible and will be read as a bug: **the first cycle after
an outage reports the leg as failed.** The rescue record and the panel say
`GSOCKET: its gs-netcat did not come up`, because the latch starts the carrier
*after* the chain has been tried, and the carrier was not there while it was.
The cycle after that is the one that gets out. That is the warm-up, and it is
**not a fault** — a leg reporting `not tried` there would be the lie.

### What is not verified yet

**Whether the implant's local forward is reachable from off the host is
unverified.** The implant's carrier opens a local forward on `local_port`,
and anything that reaches it reaches the team server's beacon socket
unauthenticated at the transport level — bounded by the AES-256-GCM envelope
to exactly what a compromised listener can do, which is to drop or replay
messages, not to read or forge them. What is not known is the *scope*:
gsocket's documentation does not say whether a client's `-p` forward binds
`127.0.0.1` or every interface, and nothing in this repository has measured
it. It was not measured on purpose — answering it means installing a
third-party binary system-wide and dialling a relay network from the
operator's own machine, which has OPSEC meaning of its own.

Settle it before an engagement, in one line: start a real
`gs-netcat -k <file> -p <port>` and read the local address off the listening
socket — `ss -ltnp` on Linux, `lsof -nP -iTCP -sTCP:LISTEN` on macOS. **This
is a blocking item before engagement use**, not a nice-to-have: if the
forward binds every interface, an implant hands its whole subnet a path to
the beacon socket, and the answer is a host firewall rule on the implant plus
a corrected entry in *Known limits*. Until somebody runs it, assume the worse
answer. The question, the check and what depends on it are also recorded
above `GsocketCarrier.argv` in `software/c2/gsocket/carrier.py`.

Nothing in the test suite touches the real GSRN, and nothing in CI ever
should: CI must not need a relay operated by somebody else. The rest of what
has to be exercised by hand once — a carrier started from the panel, an
implant registering over this leg alone, a killed child coming back, a stopped
carrier reported as `carrier_failed` rather than hanging the cycle — is the
manual-verification list at the end of
[`docs/superpowers/plans/2026-11-19-gsocket-carrier.md`](superpowers/plans/2026-11-19-gsocket-carrier.md).

---

## Configuring them

`c2.listeners` in `configs/raccoon.yaml`. **This is the server side** —
sockets this host opens for beacons to reach. Do not confuse it with
`c2.fallback`, which is the same host as a *client*: channels an implant
running here will try. Both blocks state which side they are in a comment
above themselves.

```yaml
c2:
  listeners:
    - name: smb-445
      transport: smb
      enabled: false
      bind_host: "0.0.0.0"
      bind_port: 445
      relay_url: "http://127.0.0.1:8443/api/v1/beacon"
      settings:
        pipe_name: "msrpc_6e2f"
```

| Field | Meaning |
|---|---|
| `name` | What the panel calls it, and what start and stop take. Must be unique. |
| `transport` | `smb`, `quic` or `dns`. |
| `enabled` | Ships `false` for all three. A fresh checkout opens no socket. |
| `bind_host` | Interface to bind. Under socket activation this is only what the panel displays. |
| `bind_port` | Likewise. Must be 1–65535; `0` is refused, because a beacon is configured with a fixed port. |
| `relay_url` | The team server's **beacon** socket. DNS takes the socket root; the others take the full `/api/v1/beacon` path. |
| `settings` | What that transport takes beyond the above: `pipe_name` for SMB, `zone` and `ttl` for DNS. |

Everything is checked when the file is read, and a **disabled** listener
is checked exactly as strictly as an enabled one — a typo that waits for
the day somebody switches it on has picked the worst possible moment to
appear. A config that cannot work stops the team server at startup with
the offending value in the message, because the symptom of a listener
that was silently not configured is a beacon that never checks in, and
four unrelated faults produce that same symptom.

Start the team server with `--config` to make the panel see them:

```sh
python3 -m software.c2.server --key "$RACCOON_KEY" \
    --config configs/raccoon.yaml
```

### Secrets

| Variable | Who needs it | Why |
|---|---|---|
| `RACCOON_LISTENER_TOKEN` | the team server **and** every DNS listener | Authenticates `GET /api/v1/dns/<id>`. Agent names come from a fixed word list, and tasking is handed out once, so without it anyone could walk the names and take tasking the real beacon would then never see. |

It is deliberately **not** in `configs/raccoon.yaml`: it is a shared
secret, and a config file is something people paste into tickets. It is
deliberately not a command-line flag either — a command line is readable
by every user on the host through `ps`. A DNS listener refuses to start
without it rather than starting and answering every beacon an empty
record, which looks like a healthy listener delivering nothing.

The encryption key is not on this table and never will be.

---

## Running them

### From the panel

The 📡 button between 🚀 and 💎. It lists every configured listener with
its state, pid, uptime and its own counters, and starts or stops one.
Where it cannot act it says why rather than offering a button that does
nothing.

### As processes, by hand

```sh
python3 -m software.c2.listeners \
    --transport quic --name quic-8445 \
    --bind-host 0.0.0.0 --bind-port 8445 \
    --relay-url http://127.0.0.1:8443/api/v1/beacon
```

One process serves one listener, so a crash costs that transport and
nothing else. It prints one line — its control port, or `control-port
none` — and everything else goes to stderr.

With no `RACCOON_CONTROL_TOKEN` in the environment it opens **no control
socket at all**, which is what a systemd unit with no supervisor to
answer should do.

### Under systemd

`services/raccoon-listener-{smb,quic,dns}.{socket,service}`.

The `.socket` unit binds the port. systemd already has the privilege for
445 and 53, so it binds and hands the descriptor over; the `.service`
unit runs as `nobody` and never calls bind. **That is why this package
needs no `cap_add`, no `setcap` and no sudo anywhere.** `$LISTEN_FDS` and
`$LISTEN_PID` are how the descriptor arrives, and `$LISTEN_PID` is
checked because the variable is inherited by grandchildren that were
never meant to have the socket.

The DNS unit reads its token from `/etc/raccoon/listener-dns.env`, which
should not be world-readable. A unit file is.

### Under Docker

```sh
docker compose --profile listeners up -d
```

The profile is why a plain `docker compose up` starts none of them: a
listener is a socket facing the network and nothing should open one
because a file happened to mention it.

Each container drops every capability, runs read-only as uid 65534, and
takes `no-new-privileges`. dockerd holds the privilege for the published
port — `"445:8445"` — and the process inside binds 8445 as nobody.

The listeners are **not** on the host network, unlike the team server,
because port mapping does not exist under `network_mode: host`. That also
means there is no shared compose network and no service name to resolve,
so they reach the team server through
`host.docker.internal:host-gateway`.

The image is its own, built from
`software/c2/listeners/Dockerfile`, and installs nothing: no pip, no
package manager. That is how "stdlib only" stays checkable.

---

## Known limits of this arrangement

- **A listener in a container reports no counters.** Its control socket
  binds loopback inside the container and Docker publishes to the
  container's own address, so nothing outside can reach it. Correct for
  the arrangement it was built for — supervisor and listener on one host
  — and Docker deployments run with `--no-manage-listeners` anyway, where
  the panel already states that it cannot start or stop anything.
- **Published UDP ports do not deliver on Docker Desktop for macOS.**
  Measured side by side: a TCP echo in a container answers through
  `-p 127.0.0.1:x:y` and an identical UDP one never receives the
  datagram. So the QUIC and DNS listeners cannot be exercised in a
  container on a Mac; `tools/listener_docker_rig.py` probes for it and
  says so rather than timing out. On a Linux host both work.
- **The SMB listener is not a general SMB server**, as above. If something
  other than the beacon is expected to connect, this is not the service to
  put on 445.
- **A beacon's identity is one per host, not one per implant.** Two
  implants on the same machine register as one agent and share one task
  queue, and since tasking is dequeued, whichever polls first takes the
  task. A redundant pair — HTTPS primary, DNS fallback — is therefore one
  agent, not two. Recorded in *Known limits* in
  [`docs/AGENT.md`](AGENT.md#known-limits).
- **The QUIC client reassembles datagrams from any sender.** The listener
  keys reassembly on the source address; the beacon does not, so anything
  that can reach its source port can inject fragments. A listener cannot
  compensate for a client that trusts. Also in *Known limits*.
- **A gsocket carrier depends on a relay network this project does not run,
  and the implant's forward has not been measured.** Both are in
  [*What it costs*](#what-it-costs) and
  [*What is not verified yet*](#what-is-not-verified-yet) above, and in
  *Known limits* in [`docs/AGENT.md`](AGENT.md#known-limits). The second one
  is a blocking item before engagement use rather than a note: the one-line
  check decides whether an implant hands its subnet a path to the beacon
  socket.

---

## Proving it works

Two rigs, and both drive a **real beacon** rather than a mock:

```sh
python3 tools/listener_rig.py smb        # listener in this process
python3 tools/listener_docker_rig.py smb # listener in a container
```

Each registers, queues a task, and waits for the result — except for DNS,
where the cycle stops at "the beacon decrypted the tasking", because
there is no result to wait for.

For something to click around in:

```sh
python3 tools/demo_env.py --with-listeners
```

That stands up the team server, one listener per transport as supervised
child processes, and one beacon behind each, so the panel can be used
rather than only looked at.

---

## See also

- [`docs/REDIRECTOR.md`](REDIRECTOR.md) — the same shape for HTTPS: a
  front host that carries traffic and holds no key.
- [`docs/TUNNEL.md`](TUNNEL.md) — the reverse SOCKS tunnel, which is the
  opposite shape: a process that holds key material and must stay on the
  team server host.
- [`docs/AGENT.md`](AGENT.md#known-limits) — *Known limits*, held by a
  test that fails if an entry is fixed and left in the list.
