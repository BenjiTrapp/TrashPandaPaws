# Listeners

The beacon speaks four transports. The team server answers one of them —
HTTPS, on its beacon socket. The other three are answered by *listeners*:
small separate processes that terminate one protocol each and carry the
payload to that same beacon socket over HTTP.

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
