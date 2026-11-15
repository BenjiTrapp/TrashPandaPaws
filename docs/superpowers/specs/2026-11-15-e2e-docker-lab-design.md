# A reproducible end-to-end lab in Docker

## Intent, and the why

Four defects shipped in the DNS rescue channel (#4, #5). The 3257-test
suite found none of them. What found them was running the thing: a review
with fresh context, a loopback run on the Mac, a run in a ParrotOS VM,
and opening the operator console in a browser.

Two of those four were platform defects. A dead QUIC endpoint raises
`ConnectionRefusedError` on macOS and merely times out on Linux, because
an unconnected UDP socket is never handed the ICMP port-unreachable. The
implant targets Linux. So a test that passes on the developer's Mac is
not evidence about the platform the implant runs on, and a hand-kept VM
is not evidence anyone else can reproduce: that VM lost its network and
guest agent mid-run and the second scenario never completed.

This lab makes the Linux end-to-end run reproducible, cheap enough for
CI, and extensible to the transports that come later.

## Goals

1. **Severance by topology.** A beacon whose HTTPS, SMB and QUIC legs
   fail because those addresses do not route — not because a test points
   them at a closed port and not because a stub returns `None`. Severance
   happens to a beacon that was healthy a moment ago, which is both the
   realistic life-cycle and, as it turns out, the only one the feature can
   attribute (see "The life-cycle the lab has to model").
2. **A real recursive resolver in the path.** `dnsmasq`, with the
   beacon's resolver pointing at it and `beacon._DNS_PORT` untouched, so
   the hop the rescue channel rests on is exercised rather than bypassed.
3. **Reproducible by anyone.** One command, no hand-kept VM, no state
   that survives a run.
4. **CI-capable.** Build and run inside a GitHub Actions job without
   the shipped team-server image, whose build takes many minutes.
5. **Extensible per transport.** Adding the SMB or QUIC leg as a reachable
   listener must be a compose-level change, not a rewrite.

## Non-goals

- **Replacing the unit suite.** The suite stays the primary guard. The lab
  proves integration, which is what unit tests structurally cannot.
- **Testing the shipped team-server image by default.** That image carries
  gcc, nmap, freerdp2-x11, tigervnc, pipx-installed NetExec, a Responder
  clone and a RelayKing clone. A flag may select it; CI will not.
- **Touching `software/c2/docker-compose.yml`.** That file describes a
  deployment. A lab is not a deployment and must not make the shipped one
  harder to read.
- **A second implementation of anything.** The lab runs `software/c2` as
  it stands. No test double of the server, the listener or the beacon.
- **Forcing the pure-Python cipher.** This was a goal in the first draft
  and is dropped, because there is no honest way to reach it here.
  `_USE_PURE_PYTHON_AES` is decided at import time by `_load_libcrypto()`
  with no hook, so forcing it needs either a product-side override — the
  implant growing an environment variable for a lab's benefit — or an
  image where loading genuinely fails, and deleting `libcrypto.so.3` from
  `python:3.12-slim` takes `ssl`, `requests` and the HTTPS leg with it. A
  musl image where `find_library` genuinely returns nothing would be
  honest, and is a later addition rather than a reason to hold this up.
  The cipher itself is covered: `software/tests/test_tunnel_endpoint.py`
  toggles the flag and exercises both paths. My call.

## Anti-goals

Things that would make this a failure even if it ran green:

- **A lab that only works on one developer's machine.** If it needs
  colima specifically, or a published UDP port, it has reproduced the VM
  problem in a new place.
- **Failures simulated rather than caused.** If the beacon's HTTPS leg
  fails because a Python stub returned `None`, the lab proves nothing the
  unit tests did not already prove more cheaply.
- **A green run that would stay green with the feature removed.** Each
  scenario must fail when its subject is reverted. This is checked by
  mutation, per scenario, and recorded.
- **Something nobody runs.** If it is slower or more awkward than the VM
  it replaces, it will rot.

## Constraints, measured on this machine

| Fact | Measured |
|---|---|
| Container-to-container UDP | Works. A 143-byte datagram arrived and was answered. |
| **Published** UDP ports on macOS | Do not work. `tools/listener_docker_rig.py` documents this and skips DNS and QUIC for that reason. |
| Cross-network reachability | A container on another network cannot even resolve the name. |
| Repo visibility in the VM | `/Users/derbenji` is mounted virtiofs; `/private/var/folders/...` is **not**. |
| `software.c2.server` imports | Fine with only `flask` and `cryptography`. No impacket at import time. |
| Docker here | 29.5.2, `linux/aarch64`, 4 CPU, 8 GB, via colima. |
| `docker network disconnect` on a running container | Works, and severs completely: after it the service is unreachable by name **and** by IP. |

The first two together are the whole reason for the topology below:
**no UDP may be published to the host.** The beacon runs in a container
so that the datagram never crosses the host boundary.

The measured limit is specific to UDP — the same rig measures TCP
publishing as working — so the operator's TCP socket **is** published, and
that is what the driver and a browser use. The first draft said "nothing
may be published", which was an overcorrection that would have left the
driver unable to read the very record it asserts on.

A third constraint comes from `dnsmasq`: `server=/zone/addr#port` takes an
IP address, not a hostname. Docker's embedded DNS cannot help, because
dnsmasq parses its config before it could resolve anything.

## Approaches

Three were considered. The operator picked B.

**A — extend `software/c2/docker-compose.yml` with a `lab` profile.**
Rejected. The team server and agent there use `network_mode: host`, which
removes both the service-name resolution and the network separation this
lab is built on, and the team-server image's build takes many minutes.
Reuse would cost more than it saves and would make the shipped file
harder to read.

**B — a separate lab compose plus a driver, with genuinely separated
hosts.** Chosen. Five roles on three networks; failures caused by
routing. Costs a second compose file to keep in step with the shipped
one, and by default proves the code rather than the shipped packaging —
mitigated by a flag that selects the shipped image.

**C — one container running everything over loopback.** The VM rig in a
costume. Cheapest, closes the Linux gap today, but no severance, failures
still simulated, and it does not grow into the lab the operator asked
for. Kept in mind as the fallback if B proves unworkable on a CI runner.

## The topology

Three networks, so that a leg fails because it cannot route:

```
   beacon-net                      c2-net
 ┌──────────────┐              ┌──────────────┐
 │    beacon    │──────┐       │  teamserver  │
 └──────────────┘      │       └──────┬───────┘
                       │              │
                 ┌─────▼─────┐        │
                 │  resolver │        │   relay-net
                 │ (dnsmasq) │        └──────────────┐
                 └─────┬─────┘                       │
                       │  forwards the zone          │
                 ┌─────▼──────────┐                  │
                 │ listener-dns   │──────────────────┘
                 └────────────────┘
```

- **`beacon-net`** holds the beacon, the resolver, and nothing else. The
  team server's address is not on it, so HTTPS cannot route. SMB and QUIC
  point at addresses on `c2-net`, which the beacon is not attached to.
- **`relay-net`** joins each listener to the team server's beacon socket.
  A listener needs it; the beacon must never be on it.
- **`c2-net`** carries the operator socket and is where a browser or the
  driver reaches the GUI and API.

The listener is on `beacon-net` **and** `relay-net`. That is the whole
point of a listener: it is the one thing that bridges.

### The life-cycle the lab has to model

The builder check found that a statically severed beacon cannot work, and
it is right. `_agent_id` is assigned in exactly one place in the implant —
the HTTPS registration path (`beacon.py:5443`). The rescue record is
fingerprinted from `self._agent_id or self._implant_id`, and the server
attributes it by matching `fingerprint(agent_id)` against the **fleet
key**, which is the assigned name. A beacon that has never registered
therefore fingerprints its implant id, matches nothing, and its rescue
lands in `unattributed_rescues`.

So the lab models the life-cycle instead of a frozen state, in three
steps:

1. The beacon container starts attached to `c2-net` as well, checks in
   over HTTPS for real, and is assigned a name by the server.
2. `docker network disconnect c2-net beacon` — measured above to sever
   completely, by name and by IP.
3. Only now does the driver assert the negative space, and only then does
   the stuck loop run.

This is more realistic than the static version, not less: a beacon that
matters is one that worked and then stopped being able to. It is also
entirely lab-side — no product change — which is why it was chosen over
the alternatives the check listed (adding an operator route for
unattributed rescues, or widening the server's matching).

### A product gap this exposes, and does not fix

`unattributed_rescues` is appended to and trimmed and **never served over
HTTP**. A beacon that never managed to register at all is therefore
invisible: its diagnosis is decoded, stored in memory, and cannot be read
by any operator. That is a real gap in the feature — and the affected
beacon is precisely the one most likely to be stuck, since never
registering means the way out was never open.

Out of scope here. A lab is not the place to change the product, and this
deserves its own change with its own tests. Recorded so it is not
rediscovered.

### Severance is asserted, not assumed

A lab whose isolation silently breaks would report success for the wrong
reason. So the driver asserts the negative space after the disconnect and
before it runs anything: from inside the beacon container, a TCP connect
to the team server's beacon socket must fail, and the SMB and QUIC
addresses must be unreachable. If any of them succeeds, the run aborts and
says the lab is mis-wired. This is cheap and it is the difference between
proving a property and hoping for one.

### Why the beacon is a container and not the driver process

The driver runs on the host. If the beacon ran there too, its DNS query
would have to reach the resolver through a published UDP port, which is
measured not to work on macOS. Putting the beacon in a container keeps
every datagram inside Docker's network, where it is measured to work, and
has the larger benefit that the beacon's view of the network is the
container's — which is what makes severance real.

## The images

| Image | Base | Contents |
|---|---|---|
| `lab-teamserver` | `python:3.12-slim` | `flask`, `cryptography`. Source bind-mounted. |
| `lab-beacon` | `python:3.12-slim` | `requests` only. Source bind-mounted. |
| `lab-resolver` | `debian:stable-slim` | `dnsmasq`. No project source. |
| listeners | existing `software/c2/listeners/Dockerfile` | unchanged, stdlib only, `USER 65534`, `cap_drop: [ALL]` |

The listener image is reused as it ships, unmodified. That is deliberate:
the lab should exercise the artefact the project publishes, and a listener
is the one role where that artefact is already cheap to build.

**Source arrives by read-only bind mount, not `COPY`.** The lab then tests
the working tree, which is what a developer wants from a pre-push check
and what CI wants from a pull request. `COPY` would test a snapshot taken
at build time and would need a rebuild per edit. The mount is `:ro` so a
container cannot write into the checkout.

My call, as is the choice of two thin images over one shared one: the
beacon must not have `flask` available, because a beacon that can import
the server is a beacon that might.

## The driver

`tools/e2e_lab.py`, following the house pattern that
`tools/listener_docker_rig.py` set: bring it up, run one scenario, assert,
tear down, exit non-zero on failure. It is not a unittest module, because
it needs Docker and must be skippable; it prints what it checked and why.

```
python3 tools/e2e_lab.py                 # every scenario
python3 tools/e2e_lab.py rescue          # one of them
python3 tools/e2e_lab.py --keep          # leave it up to look at
python3 tools/e2e_lab.py --shipped-image # the real team-server image
```

With no Docker it exits 2 and says so, rather than failing in a way that
looks like a product fault — the existing rig's convention.

The compose file, the resolver config template and the two Dockerfiles
live in `software/tests/lab/`. The driver lives in `tools/` with the other
rigs. Splitting them is my call: `tools/` is where this project keeps
things a human runs, and a compose file is not that.

### Scenarios

1. **`rescue`** — the named gap. HTTPS, SMB and QUIC cannot route; the
   resolver answers and the listener relays. Asserts: exactly **one**
   rescue query in the resolver's own query log across four stuck cycles,
   the name under 253 characters with no label over 63, and the operator's
   agent record carrying a `stuck` summary naming the right legs.
2. **`stale-token`** — the scenario the VM died before reaching, and the
   one that proves the leg-recording fix on Linux. The listener holds a
   token the server no longer accepts, so tasking over DNS returns nothing
   while the rescue still arrives, because the rescue goes through the
   beacon handler and needs no listener token. The ladder therefore runs
   all the way down and both lower legs are really attempted. Asserts:
   SMB and QUIC are reported as attempted-and-failed, **not** as
   `not_attempted`.
3. **`smb-up`** — the first of the later transports, and the proof that
   the shape extends. The builder check showed the first draft of this
   scenario could not pass: with DNS enabled and delivering, the ladder
   stops at DNS, `delivered_by` is `"dns"` which is not upstream, and a
   rescue **is** sent. Simply disabling DNS would make "no rescue" vacuous,
   because `_maybe_rescue` returns immediately when DNS is off. So the
   scenario keeps the stale-token listener — the resolver answers, the
   latch is genuinely armed, tasking over DNS returns nothing — and adds
   the SMB listener to `beacon-net` with a valid token. Asserts: tasking
   arrives over **SMB**, and **no** rescue is sent, because an upstream leg
   delivered while the latch was armed and could have fired.

Scenario 2 is the one that must fail against the parent of the
leg-recording fix (`3dad39e`). Scenario 1's subject is the trigger
condition `delivered_by not in _RESCUE_UPSTREAM`; reverting it to
`tasking is None` must make it fail. Scenario 3 is **exempt**: it guards a
property of the lab, not a product change, so there is nothing to revert —
stated here so its absence is not read as an oversight. Results go in the
ledger at `.superpowers/sdd/2026-11-15-e2e-docker-lab/progress.md`, the
place this project already keeps them, either way.

### What the driver asserts, and from where

Evidence comes from the components, never from the driver's own
bookkeeping:

- **the resolver's query log** (`log-queries`) for what crossed the wire,
  because a name only appears there if a real resolver parsed it;
- **the operator API** (`/api/agents`, authenticated) for what the server
  decoded;
- **the beacon container's exit code and stdout** for what the implant
  did.

Caching stays **on** in dnsmasq. The listener answers with TTL 1 and a
cached rescue would be a defect worth catching, so switching the cache off
would hide it.

## CI

`.github/workflows/ci.yml`, new; this repository has no CI today. Two
jobs, because they fail for different reasons and a reader should be able
to tell which broke:

| Job | Runs | Why |
|---|---|---|
| `tests` | the full unittest suite | the primary guard, ~7 minutes locally |
| `lab` | `python3 tools/e2e_lab.py` | the integration proof |

On `ubuntu-latest`, where Docker is present and published UDP is iptables
rather than a userspace proxy — so the lab is, if anything, less
constrained there than here.

Running both rather than only the lab is my call. A repository with no CI
gains more from the suite than from the lab, and the lab's value is
precisely that it covers what the suite cannot; running one without the
other would misrepresent either.

Two things CI must not do, and the workflow will say so: no secrets (the
lab generates its key per run with `os.urandom`), and no network egress
beyond the base images.

## Risks, and what each would look like

| Risk | How it shows | What then |
|---|---|---|
| aarch64 here, amd64 in CI | passes locally, fails in CI | base images are multi-arch; the driver prints `uname -m` so a report says which |
| `dnsmasq` needs an IP, not a name | resolver exits at start | static IPs on `beacon-net` via a declared subnet |
| compose drifts from the shipped file | lab proves a shape nobody deploys | the listener image is the shipped one; a test asserts the lab's listener command matches the shipped file's |
| the lab rots | nobody runs it | CI runs it on every push; that is the point of the workflow |
| a container leaks between runs | flaky, confusing | fixed project name, `down -v` in a `finally`, and the driver refuses to start if the project's containers already exist |

## Left to the builder

- The exact subnet numbers and static IPs.
- Whether the resolver config is a template the driver renders or a file
  per scenario. Either is fine; the driver must print the effective config
  on failure.
- How the beacon container is parameterised: environment variables or a
  JSON config on the mount. The repository's beacon takes a config dict,
  so a small entry script is expected either way.
- The waiting strategy. Poll a condition; never `sleep` a fixed guess,
  and say in the failure message which condition was still unmet.
