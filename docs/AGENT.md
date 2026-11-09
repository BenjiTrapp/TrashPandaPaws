# Automated Attack — the autonomous agent layer

An LLM-driven mode **inside** the existing operator GUI. The agent plans and
runs a campaign against beacons you select, inside a scope you authorise,
while you keep using the terminal beside it. Every action is recorded; the
ones that could cost you the drop-box or your cover come to you as a
question.

This page is the configuration guide. It is written from a build that was
run end to end against a live beacon, so the numbers in it are measured
rather than estimated, and the traps listed under
[Troubleshooting](#troubleshooting) are the ones that actually cost time.

---

## What it is, and what it is not

**It is** a separate service that drives the C2 through the same HTTP API an
operator uses. It reads the fleet, queues tasks, reads results, records
findings, and scores outcomes. It is not a second C2 and it holds no
credentials of its own beyond the model's API key and the operator token.

**It is not required.** The C2 and the beacon run exactly as they do today
with no model configured and nothing extra installed — that is a hard
promise, and it is asserted by a test suite rather than stated here:
`software/tests/test_status_quo.py` checks that the C2 imports without the
agent package, that the agent package pulls in no HTTP library the C2 does
not already have, and that the C2's requirements never grow an LLM
dependency. With no agent service running, the GUI renders the **Automated
Attack** button greyed out with the reason in its tooltip — not hidden, so
you can tell the feature exists and why it is unavailable.

---

## Before anything else: Sliver or the agent, not both

A stock install reports the agent as unavailable, and this is the first
thing everybody hits.

`configs/raccoon.yaml` ships with `c2.sliver.enabled: true`. A
Sliver-managed box checks in with the **Sliver** server, never with the
Raccoon team server — so the agent, which plans against what the team server
knows, would be looking at an empty fleet. The symptom is a campaign that
finds no beacons, which sends you looking at the agent rather than at this
setting.

```yaml
c2:
  sliver:
    enabled: false      # run the Python beacon the agent can see and task
```

Starting `software/main.py` with both switched on logs a warning saying
exactly this. The shipped default stays silent, because it has no `agent:`
block at all.

---

## Quick start

### With Docker

```bash
cd software/c2

# RACCOON_TOKEN must be fixed. Left unset, the C2 invents a random operator
# token at every start; the agent authenticates with that token, so it would
# get 401 on every call and the GUI would report it unavailable.
export RACCOON_TOKEN="$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')"

export AGENT_PROVIDER=anthropic
export AGENT_MODEL=claude-sonnet-4-5
export AGENT_API_KEY=...        # or AGENT_API_KEY_FILE=/etc/raccoon/agent.key

docker compose up --build
```

The agent is a separate service in the same compose file. It publishes no
port and binds loopback: the C2 reaches it on the host network, and an API
that starts campaigns and runs commands has no business being reachable from
anywhere else. Neither service declares `depends_on` in either direction —
the C2 comes up without the agent, and the agent survives a C2 that is not
there yet.

### Without Docker

```bash
# Terminal 1 — the C2. It asks whether to start the agent as well.
./software/c2/start_server.sh      # reads RACCOON_TOKEN (and RACCOON_KEY) from the environment

# Or terminal 2, by hand:
RACCOON_TOKEN="$RACCOON_TOKEN" python3 -m software.agent \
    --provider anthropic --model claude-sonnet-4-5 \
    --c2-url http://127.0.0.1:8444
```

No vendor SDK is needed. Every provider speaks JSON over HTTPS through
`requests`, which the C2 already declares, so `pip install -r
software/agent/requirements.txt` is the whole of it — `aiohttp` for the
service's own HTTP server and `croniter` for the scheduler are the only
additions.

### Checking it took

```bash
curl -s localhost:8444/api/ai/status -H "Authorization: Bearer $RACCOON_TOKEN"
```

`available: true` means a campaign can start. `available: false` always
comes with a `reason`.

---

## Models and the capability tier

| Provider | What it needs |
|---|---|
| `anthropic` | `AGENT_API_KEY`, a model name |
| `bedrock` | `AWS_BEARER_TOKEN_BEDROCK` is read if no key is set; the endpoint follows `AWS_REGION` |
| `openrouter` | `AGENT_API_KEY`, a `vendor/model` name |
| `opencode` | `AGENT_API_KEY` **and** `AGENT_BASE_URL` — there is no built-in endpoint |
| `local` | `AGENT_BASE_URL` for LM Studio or llama.cpp; no key; endpoint defaults to `http://127.0.0.1:11434/v1` |
| `ollama` | a model that is pulled (`ollama pull`); no key; endpoint defaults to `http://127.0.0.1:11434/v1` |
| `gemini` | `AGENT_API_KEY`, a bare model id (`gemini-3-pro`); no endpoint to set |
| `vertex` | `AGENT_VERTEX_PROJECT`, a publisher-prefixed model id (`google/gemini-3-pro`); no key, the token comes from `AGENT_TOKEN_SOURCE` (default `auto`); the endpoint follows `AGENT_VERTEX_LOCATION` (default `europe-west4`) |

A Bedrock model id carries its own region prefix (`eu.`, `us.`). An EU id
against a US endpoint fails at the first call rather than at configuration,
so set `AWS_REGION` to match the prefix.

Vertex has the same trap with a different prefix. Its model id carries a
publisher, `google/gemini-3-pro` and not `gemini-3-pro`, and a bare id is
refused at configuration instead of becoming a 404 at the first call, which
on an unattended run nobody is there to read. There is no `AGENT_BASE_URL` to
set either: the endpoint is computed from `AGENT_VERTEX_PROJECT` and
`AGENT_VERTEX_LOCATION`, because the location appears **twice** in the URL,
in the host (`europe-west4-aiplatform.googleapis.com`) and again in the path
(`/locations/europe-west4/`), and a mismatch between the two is a silent 404.
One value written twice by the code cannot disagree with itself; two values
typed by a person can. A blank location means `europe-west4`, EU first as
Bedrock's default region is. `global` is the one location whose host has no
regional prefix: it is `aiplatform.googleapis.com`, and
`global-aiplatform.googleapis.com` does not exist. Both values are checked
against Google's identifier shape (lowercase letters, digits, hyphens) before
they go into a URL, because the bearer is sent wherever that URL points.

The credential is the part that differs from Bedrock, and it has its own
section: [Vertex AI: the token, and where it runs](#vertex-ai-the-token-and-where-it-runs).

`local` and `ollama` both default to Ollama's port, so `local` with no
`AGENT_BASE_URL` still works against an Ollama on the same machine. Use
`ollama` for it anyway: that name is what the
[pre-engagement check](#checking-the-chain-before-an-engagement) knows how to
audit, and `local` is the name for LM Studio and llama.cpp, whose model list
it reads from a different endpoint.

The **capability tier** is derived from the model name and limits what a run
may do. A model nobody recognises gets `reduced`, which is the safe
direction to be wrong in; a local endpoint never reaches `full` on its name
alone, because the name is whatever you typed and the server behind it may
be anything.

| Tier | Orchestrator turns | Executor turns | Output kept | Highest phase | Tools |
|---|---|---|---|---|---|
| `full` | 20 | 16 | 4000 chars | 5 | all |
| `reduced` | 12 | 8 | 2000 chars | 4 | core |
| `minimal` | 8 | 6 | 1000 chars | 3 | bare |

`max_phase` is a safety boundary, not a performance setting: phase 5 is
exploitation, and a model that cannot be relied on to follow the rules is
not handed the most consequential actions. Override with
`AGENT_CAPABILITY_TIER` only if you know what the model behind the name is.

> **Measured:** 20 orchestrator turns is not enough for four phases with
> parallel dispatch. A run through phases 2–5 ended on `MAX_TURNS` before
> reaching 5. Selecting fewer phases, or starting at 3, is the current way
> around it.

---

## Vertex AI: the token, and where it runs

Every other provider here authenticates with a key that is good until someone
revokes it. Vertex's credential is an OAuth **access token that lives about an
hour**, and a campaign runs up to two (`max_runtime_seconds`, 7200). A token
pasted into `AGENT_API_KEY` works until the hour is up and is then refused on
every turn, partway through a run. That is why Vertex has a *token source*
instead of a key: the agent holds the current token and fetches another when
less than 5 minutes of the old one remain.

| `AGENT_TOKEN_SOURCE` | Needs | What trying it costs |
|---|---|---|
| `auto` (default) | nothing of its own: tries `metadata`, then `gcloud`, then `file`, in that order, and if none works names all three | the sum of those it has to try |
| `metadata` | to run on one of Google's own machines (a GCE VM) with a service account allowed to call Vertex | up to a 1-second timeout anywhere else |
| `gcloud` | `gcloud` on `PATH`, already logged in; the agent runs `gcloud auth print-access-token` | a subprocess, with a 30-second timeout |
| `file` | `AGENT_API_KEY_FILE` naming a file holding a current token, mode `600` | a read |

The order is by cost, cheapest first. `gcloud` does not say how old the token
it prints is, so the agent assumes half an hour and runs it again after about
25 minutes. A `file` is re-read, so a token rewritten underneath a running
agent is picked up within ten minutes.

**A key beats `auto`.** If `AGENT_API_KEY` or `AGENT_API_KEY_FILE` is set and
the source is left at `auto`, that value is used as it stands and is never
refreshed. `/api/ai/status` says so, but it is easy to read past. Name the
source (`file`, for the container below) and the explicit choice wins.

**Whether a token can be had is not checked at startup.** `gcloud` is checked
for being on `PATH` and a `file` for its mode, but `auto` always passes, since
the metadata server cannot be ruled out without asking it. A host with no
working source therefore reports `available: true` and fails at the first
model call. [`--ping`](#checking-the-chain-before-an-engagement) is the way to
find out before then.

### On the host

This is the documented path. An agent started directly inherits your shell's
`PATH`, so `gcloud` is there and `auto` finds a token with nothing to set up
beyond being logged in:

```bash
gcloud auth login
export AGENT_PROVIDER=vertex
export AGENT_MODEL=google/gemini-3-pro
export AGENT_VERTEX_PROJECT=my-project      # AGENT_VERTEX_LOCATION if not europe-west4
python3 -m software.agent
```

### In the container

Supported, through the `file` source. `gcloud` is **not** in the agent image,
and that is deliberate. The Dockerfile keeps this image slim for a reason that
applies here without change: what another place already provides is weight
and one more thing to keep patched, and the Cloud SDK is a large install next
to a handful of small Python packages, in the one image that holds an API key
and the C2 token. The host already has `gcloud` and a login, so the host
refreshes and the container reads:

```bash
# On the host. umask 077 makes the file mode 600, which the agent insists on.
umask 077
while :; do
  gcloud auth print-access-token > /etc/raccoon/vertex.token.new \
    && mv /etc/raccoon/vertex.token.new /etc/raccoon/vertex.token
  sleep 1800
done
```

```bash
export AGENT_PROVIDER=vertex AGENT_MODEL=google/gemini-3-pro
export AGENT_VERTEX_PROJECT=my-project
export AGENT_TOKEN_SOURCE=file
export AGENT_API_KEY_FILE=/etc/raccoon/vertex.token
```

Three things that are not obvious:

- **Mount the directory, not the file.** `docker-compose.yml` mounts nothing
  for the key file by default, since it cannot know your host path; under the
  agent's `volumes` there is a commented-out `- /etc/raccoon:/etc/raccoon:ro`
  to edit and uncomment. A single-file bind mount follows the inode it was created
  against, and the `mv` above replaces the inode, so the container would keep
  reading the first token for ever.
- **The file must exist before the agent starts**, and cannot be empty: the
  configuration reads it once at startup and refuses a missing, empty or
  group-readable file. Run the refresher once first.
- **The container's user has to own it.** Mode `600` means only the owner can
  read the file, and the owner is a uid on the host. The container runs as the
  unprivileged `raccoon` user; `docker compose run --rm --entrypoint id agent`
  says which uid that is, and the file, and the directory the refresher
  writes into, need to belong to it.

The refresher writes every 30 minutes against a token that lives about an
hour, so the file always holds a token with at least half its life left. If
the refresher dies, the agent carries on with the last token until it expires,
at most an hour later, and then fails; nothing warns beforehand.

### On GCE

Nothing above is needed. The container shares the host's network, so the
metadata server answers there as it does on the host, and `auto` tries it
first.

---

## If a provider goes down

One provider and one key is the normal case. A campaign runs unattended
for up to two hours, though, and a key that is rate-limited, out of credit
or revoked ends the run where it stands — on a drop-box, with nobody there
to restart it.

A chain fixes that. Each link names its own key's *environment variable*,
never the key: this file is under git, and a provider list is the one place
it would be tempted to hold several secrets.

```yaml
agent:
  llm:
    provider: bedrock
    model: eu.anthropic.claude-sonnet-4-5-20250929-v1:0
    fallbacks:
      - provider: anthropic
        model: claude-sonnet-4-5
        api_key_env: ANTHROPIC_API_KEY
      - provider: ollama
        model: qwen2.5-coder
        base_url: http://127.0.0.1:11434/v1
      - provider: gemini
        model: gemini-3-flash
        api_key_env: GEMINI_API_KEY
```

An entry takes `provider`, `model`, and optionally `base_url` and
`api_key_env`. A literal `api_key` is refused — by name, without the value
being echoed into the error. A `local` or `ollama` link needs no key at all,
which makes a model on the box itself a sensible late link: it cannot be
rate-limited and it cannot have its key revoked. `gemini` goes last because
its free tier has quota limits, so it cannot be relied on for a whole
campaign. What it lacks is a *balance*: there is no credit to run out and no
bill whose failure to be paid ends the key. A quota resets, so the link
returns on its own after its cooldown, where an empty balance stays empty
until someone tops it up.

**A `vertex` link is the exception to everything above.** A chain link
carries four fields (`provider`, `model`, `api_key_env`, `base_url`) and no
more, so it has no project, no location and no token source of its own. Two
things follow, both by design and neither visible until it bites:

- It always uses `token_source: auto`, whatever `AGENT_TOKEN_SOURCE` says for
  the primary, and never a static bearer. Naming an `api_key_env` on a
  `vertex` link is refused. In the container that means a `vertex` fallback
  finds a token only where the metadata server answers (GCE): `auto` would
  reach for a key file, and a link has none to name. A `vertex` *primary*
  has no such limit.
- It needs an explicit `base_url`, the whole endpoint, since there is
  nothing to compute it from. Leave it out and startup says so; it does not
  say "set `AGENT_VERTEX_PROJECT`", which is probably already set.

```yaml
      - provider: vertex
        model: google/gemini-3-pro
        base_url: https://europe-west4-aiplatform.googleapis.com/v1/projects/my-project/locations/europe-west4/endpoints/openapi
```

The location appears twice here too, and the same mismatch is a silent 404.

**How it behaves.** Any failure moves to the next link. The HTTP status is
not consulted, because a 401 is a revoked key *or* a header this code got
wrong and both are reasons to try the next one — and nothing is hidden,
since every attempt is written to `llm_interactions` and the final error
names every link that was tried. A link that fails **twice in a row** is
skipped for **2 minutes**; after that it gets one attempt, not a fresh
allowance, because a revoked key is still revoked.

**Why a chain matters most for `vertex`.** The token is fetched before every
model call, and a failed fetch is not cached. While `gcloud` is failing
slowly, a lone `vertex` client pays up to 30 seconds inside that fetch on each
turn (the `gcloud` timeout, after the metadata server's one second under
`auto`) and then fails. The campaign is not lost, since nothing wraps a model
call in a deadline, but twenty orchestrator turns of that is ten minutes spent
waiting for nothing. With a chain the failover counts those failures like any
other, trips the link after two, and the later turns do not pay for it.

Every link is built at startup, so a fallback that cannot be constructed is
a configuration error reported then — `/api/ai/status` says so and no
campaign starts — rather than at the first failover, which by definition
happens when the primary has already gone.

The status panel lists the chain, and the interaction rows are filed under
whichever link answered, so a run that switched is visible rather than
silently attributed to the model you configured first.

![The service panel](screenshots/35_agent_service_panel.png)

The same panel carries the **Report** button for every campaign, running or
finished — which is what makes the deliverable reachable without knowing a
URL.

---

## Checking the chain before an engagement

```bash
python3 -m software.agent.llm.preflight [--ping] [-c configs/raccoon.yaml]
```

It loads the configuration exactly as the service does, builds every link in
the chain, and prints one line each. Exit status is 0 if all are fine, 1 if
any is not, and 2 if the configuration will not load. It reports every link in
one run, where startup stops at the first it cannot build:

```
ok     vertex google/gemini-3-pro built; nothing was sent (--ping sends one request)
NOT OK ollama llama3.2            no server answering at 127.0.0.1:11434 (URLError)
```

What a line means depends on the link:

- **A local link (`local`, `ollama`) is asked for its model list**, always,
  because the commonest local failure is a model that was never pulled, which
  is otherwise invisible until the first turn of the first campaign. `ollama`
  is asked `/api/tags` and `local` is asked `/v1/models`: they are different
  servers with different lists, and one endpoint for both would report a
  working LM Studio as down. A server that is up but lacks your model prints
  what it does have. One that answers 401 or 403 is up and wants a
  credential, which the probe never sends; the line is ok only if the link has
  a key to send, and `--ping` is what tests it.
- **A hosted link without `--ping` is only "built".** The key, the model id,
  the endpoint and, for `vertex`, the project, location and source choice are
  well-formed; nothing was sent. For `vertex` that is the weakest answer it
  can give, because a broken `gcloud` passes it.
- **`--ping` sends one tiny completion per link**, capped at 16 output
  tokens, and for `vertex` it fetches a real token first, which is the only
  step that tests the source. It is opt-in because it spends tokens on a
  metered provider, and a health check that costs money is one nobody runs.

This is a separate command, not part of `/api/ai/status`, on purpose. The
status endpoint is polled by the interface and must not do I/O: probing a
local server that is not running would sit out its timeout on every poll and
stall the page that is only meant to say "not configured". Do not move the
probes into it.

---

## A model on the Pi

The implant is a Raspberry Pi, and an Ollama on it is a chain link today with
no code: a `fallbacks` entry carrying the Pi's LAN address.

```yaml
      - provider: ollama
        model: qwen2.5:7b
        base_url: http://10.0.1.50:11434/v1
```

Read the whole bill before you do. It is a last resort that keeps a run alive,
not a second brain.

- **Prompts and tool output cross the LAN in cleartext, to the implant.** The
  link has no key, so nothing stops it going over `http://`, and a link to a
  non-loopback address does. That traffic is everything the agent has learned
  about the target, flowing toward the one host on that network you least want
  associated with it. The agent host also has to reach that address, which
  means being on the implant's segment or tunnelling to it.
- **Power.** The Pi is PoE-powered, and the 802.3af budget at the device
  (the standard `README.md` names in its architecture diagram) is about 13 W.
  That is a ceiling from the standard, not a measurement, and it has to cover
  bridging and capturing as well. Neither the draw of inference nor its speed
  has been measured here.
- **It is a large forensic artefact on a device built to look like an IP
  phone.** An inference server, listening on the network with no
  authentication of its own (Ollama has none), and a model blob of several
  gigabytes on disk, are the opposite of what the cover identity is for.
- **A turn can take a long time.** The transport allows a local link 300
  seconds per call, against 120 for a hosted one. How much of that a Pi uses
  has not been measured for this page.
- **The tier does not follow the failover.** It is fixed once, at startup,
  from the *primary* model, so a run that fails over to the Pi keeps the
  primary's limits. See [Known limits](#the-agent-layer). On its own, a local
  model whose name states a size under 30 billion parameters (`qwen2.5:7b`)
  is `minimal` and stops at phase 3, and one whose name states no size is
  `reduced`. If a chain ends on a small model, `AGENT_CAPABILITY_TIER` sets
  the tier for the whole run, and the primary is held to it too.

---

## The two modes

![Mode](screenshots/31_agent_mode.png)

**Automated Attack** (supervised) — the agent works, you watch, and every
gated action asks you in the drawer. The terminal underneath stays yours:
what you type goes out at the next check-in regardless of how long the
agent's plan is. This is the default, because unattended operation should be
asked for rather than fallen into.

**Full Automated** — configured, then left alone. No knock reaches you; the
expected-value check answers in your place and every decision is recorded.

The difference is *who decides*, never *whether there is a gate*. The gate
is in both.

---

## Phases

![Phases](screenshots/32_agent_phases.png)

| | Phase | What the agent does |
|---|---|---|
| 1 | Wire Intel | Read what the bridge capture already holds — hosts, protocols, plaintext credentials — before sending a packet. Needs a beacon with `sniffer`. |
| 2 | Orientation and Discovery | Interfaces, neighbours, live hosts inside the scope; passive and low-rate first. |
| 3 | Port and Service Enumeration | Open ports and service versions on hosts already found. |
| 4 | OS and Vulnerability Fingerprinting | Fingerprint operating systems, look up CVEs for the versions identified. |
| 5 | Exploitation | Only against a confirmed service version with a known exploit, and only as far as the gate allows. **Off by default.** |
| 6 | Wifi Survey | List the access points and clients in range. Needs `wifi:monitor`. |
| 7 | Wifi Capture | Capture handshakes and PMKIDs; deauthentication is gated. |
| 8 | Wifi Crack | Recover keys from what was captured. |

Phase 1 comes first because the quietest source does: that is the direct
advantage of sitting on the bridge.

The labels in the form are the same strings the model is told, from one
table in `software/agent/prompts.py`, and a test compares the two. They used
to disagree — the form said "Credential access" for phase 3 while the model
was told "Port and Service Enumeration" — which meant unticking a box
switched off something other than what it named.

---

## Risk profiles

The profile sets four numbers; each is individually overridable, and a value
you type survives switching profiles.

| Profile | EV threshold | P(detect) start | Detection budget | Risk coefficient `R` |
|---|---|---|---|---|
| passive | +20 | 0.25 | 2 | 50 |
| normal | 0 | 0.15 | 3 | 33 |
| aggressive | −5 | 0.10 | 4 | 25 |

**What "aggressive" actually changes.** It does not unlock new classes of
action. It removes the progressive leash — measured against the finished
gate, across the eleven gated actions:

| Profile | Reachable unattended | Behaviour as detections accumulate |
|---|---|---|
| passive | 3 of 11 | collapses immediately |
| normal | 8 of 11 | tightens in steps: `lsass_dump` after 1 detection, `deauth` after 2, `ntlm_relay` and `responder` after 3 |
| aggressive | 8 of 11 | **never** tightens; only the budget stops it |

No profile makes anti-forensics or backup destruction reachable unattended.

### The expected-value check

```
EV = value_of_what_it_unlocks × P(success) − R × P(detection)_effective
```

Two things people conflate:

- **`R` is not the score penalty.** A detection costs 100 points in the
  score. `R` (33 at `normal`) prices what it costs the *run* to be noticed
  once. Without that separation, Full Automated refused every tier-2 action.
- **The benefit term is the value of what the action unlocks**, not its own
  score label. That is why `persist` carries 75 rather than 0.

An executor may pass its own `p_success_estimate`. It is advisory and
clamped to ±0.2 of the built-in prior, so it cannot rescue an action the
check has priced as too risky. When it is the only thing lifting an action
over the line, the knock card says so.

---

## OpSec profiles

![OpSec](screenshots/33_agent_opsec.png)

| Profile | Third-party lookups | Scan rate |
|---|---|---|
| `quiet` | off | limited |
| `normal` | on | limited |
| `yolo` | on | **unlimited** |

**`yolo` lifts the scan rate limits and nothing else.** Tier-1 actions stay
blocked and the approval gate stays in place in every profile; nine tests in
`software/tests/test_agent_config.py` exist to keep it that way, because the
name invites the reading "safety off".

`quiet` switches off `lookup_cve`, which queries osv.dev and nvd.nist.gov
with the service and version just found. That has a consequence worth
knowing: without it the agent cannot confirm "a known exploit exists" unless
`searchsploit` is installed on the C2 host, and phase 5's own rule then
keeps it out of exploitation. If you want a quiet run *and* CVE lookups,
install `exploitdb` on the C2 host so `check_exploit` can answer locally.

The GUI warns when a profile's name promises more than the configuration
delivers — `quiet` with a hosted model, for instance: every finding,
hostname and recovered credential still goes to that provider. Set
`provider: local` for a run that leaves nothing.

---

## Scope

Fail-closed, and that is the point. A target that cannot be *positively*
matched to an allowed range is refused.

```yaml
scope_allow: ["10.0.1.0/24", "10.0.2.0/24"]
scope_deny:  ["10.0.1.254/32"]
```

Things that surprise people, all of them deliberate:

- **A denied `/32` makes any range containing it refusable.** With
  `10.0.1.254/32` denied, `nmap 10.0.1.0/24` is refused and so is
  `10.0.1.250-255`. The agent adapts by naming hosts or sub-ranges
  individually, and the refusals are visible in the stream.
- **`--exclude` is not honoured.** `nmap -sn 10.0.1.0/24 --exclude
  10.0.1.254` is still refused. Trusting a tool's own exclude flag to
  enforce your deny list means trusting that tool's parser; refusing is the
  safe direction.
- **Paths and globs are not targets.** `nxc smb /tmp/hosts` and
  `nmap dc0[1-5].corp.local` are refused. Every target must be written out.
- **A hostname is a target only once a finding ties it to an in-scope
  address.** The agent records one with `log_discovery`; nothing resolves
  DNS on its behalf. If a name resolves to several addresses, **all** of them
  must be in scope.
- **Number arguments are known per program, not per flag.** `ping -c 4`
  passes; `nmap -c 4` does not, because `-c` takes a number for ping and not
  for nmap. A program the table does not know gets only the scanner list,
  and a bare number is then read as a target and refused. The fix is to
  attach the number to the flag: `-c4`. A handful of programs take free
  text rather than hosts -- `searchsploit`, `apt`, `pip`, `man` -- and none
  of their operands is read as a target at all.
- **A share names its host.** `//10.0.1.5/share` and `\\10.0.1.5\share`
  are both judged on the host part, so SMB tooling is addressable; the
  share name itself is not a target, `ADMIN$` included.

An observation is not an action. The agent records hosts it sees in command
output even when they are outside the scope — that is what "everything
logged" asks for — but none of them can become a target.

---

## What the target says is not an instruction

Everything a beacon returns was written by whoever controls that host:
service banners, file contents, process and service lists, directory
names, MOTDs, HTTP bodies and headers. Both preambles say so, and say what
to do when such output addresses the model directly — *"ignore previous
instructions"*, *"fetch this URL"*, *"your task has changed"*:

- it is not complied with and the task does not change;
- the payload is quoted verbatim and recorded as a possible
  prompt-injection attempt, because that is a finding in its own right — it
  says the host is defended, instrumented or decoyed;
- **a destination named by target-controlled output is not a destination.**
  Nothing is sent to an address, host or URL that appeared in a banner, a
  file or a page, even one inside the authorised scope.

The machinery bounds the damage independently of the prompt: tier 1 is
refused structurally, tier 2 knocks, and the scope is fail-closed, so a
planted instruction cannot reach an irreversible action or a host outside
the ranges. What it could otherwise do is spend the budget, talk the model
out of recording a finding, or aim an in-scope reversible action somewhere
useless.

Checked against a real model rather than asserted. A payload planted in a
file, read by a real beacon through the real router:

```
commands issued:  cat <the banner>      (and nothing else)
obeyed:           no
named it:         yes, as an injection attempt
recorded it:      yes, as a finding
```

---

## The approval gate

### Never permitted, in any mode

Eight actions are refused outright and cannot be approved, by you or by the
expected-value check. They are irreversible and, from a drop-box, not
correctable:

| Key | Why |
|---|---|
| `beacon_control` | beacon lifecycle control is irreversible without an operator |
| `sleep_too_long` | a sleep this long takes the beacon out of reach for hours |
| `dropbox_lifeline` | touches the bridge, NAC bypass, cover identity or tunnel |
| `power_off` | reboot or shutdown of the host carrying the beacon |
| `network_service` | restarting or disabling networking severs the C2 channel |
| `firewall_change` | firewall mutation can cut the C2 channel |
| `disk_wipe` | destroys the filesystem of the host |
| `airmon_check_kill` | `airmon-ng check kill` stops NetworkManager and severs C2 |

The form shows this list with its reasons, generated from the same table the
gate uses, so it cannot drift from what is enforced.

### Gated — asked about, every time

`device_write_unknown`, `iface_change`, `lsass_dump`, `responder`,
`ntlm_relay`, `remote_exec`, `log_clear`, `shadow_copy_delete`, `persist`,
`deauth`, `exploit_known_poc`.

In supervised mode the question comes to you in the drawer:

![Knock card](screenshots/30_agent_knock_card.png)

Two reasons, because you decide from them: why the action is gated at all,
and how the arbiter's numbers come out. Deciding happens in the drawer; the
stream carries one log line.

### If nobody answers

| Setting | What happens |
|---|---|
| `pause` | the campaign suspends and the knock stays on the record for your return |
| `skip` | refused and recorded; nothing is evaluated |
| `decide` | the expected-value check answers, and its decision is logged |

The default follows the mode: **supervised → `pause`**, **Full Automated →
`decide`**. That asymmetry is deliberate. In a supervised run you are the
arbiter, so stepping away must not quietly promote the EV check — and it
would matter: the EV for one real exploitation request came out at +110
against a zero threshold, which `decide` would have allowed.

`approval_timeout` (default 300 s) is how long a knock waits.

---

## Budgets and what they cost

| Field | Default | Note |
|---|---|---|
| `max_runtime_seconds` | 7200 | wall clock |
| `max_tokens_total` | 500 000 | see below |
| `campaign_interval` | 15 | beacon check-in **during** the run |
| `restore_interval` | 300 | put back afterwards, in the `finally` path |

**Measured token cost.** 400 000 tokens bought phases 2–4 against a
*single* host. Consumption scales with phases × tasks × turns, because each
parallel executor carries its own transcript. Treat 500 000 as roughly one
four-phase run against one host; a multi-host engagement needs it raised. A
budget abort is graceful — the run ends, the interval goes back.

**The interval trade.** 15 s makes the agent usable and raises check-ins
from 12 to 240 an hour. The restore runs on the way out and also after a
crash of the agent service. One consequence to expect: for
`restore_interval` seconds after a run, the beacon is asleep, so the *next*
campaign's first command waits that long. The C2's displayed interval also
lags by one check-in, because that field is filled from the beacon.

### The deadline contract

Each task is told what remains when it starts:

```
Budget, as of the start of this task: 120k tokens and 15 minutes remaining.
```

In the task prompt rather than the preamble, because the preamble is built
once per task and would be stale by the turn the figure mattered — and the
wording says *as of* when, so it is not read as holding for the whole task.

The preamble asks the model to check that a command can finish inside what
is left, to prefer the smaller variant that lands over the thorough one
that does not, and to record what it already has rather than open new work.
Below **10 minutes** or **20000 tokens** remaining the line stops
informing and starts instructing. Those thresholds are set so one
rate-limited thousand-port scan cannot fit in what remains, because that is
the command that actually overruns — see the next section for why it takes
seven minutes.

### Scan rate, and why a scan takes so long

These are applied to every scan whether the model asks or not:

| Tool | Forced flags |
|---|---|
| `nmap` | `-T2 --max-rate 50` |
| `masscan` | `--rate 50` |
| `netdiscover` | `-c 1` |

`-T2` dominates, not `--max-rate`: it inserts a delay between probes, so
**1000 ports take about seven minutes** and `-sV` on top takes several more.

A request for all 65535 ports (`-p-`, or a range that wide) is **narrowed**
to nmap's 1000 most common ports. At the forced rate the full range is about
22 minutes of probing against nmap's 900-second limit, so `-p-` returned a
partial result with `success: false` and a requested `-sV` never started —
which blocked two campaigns from ever confirming a service version. Telling
the model was tried first and did not work.

The result carries `effective_command` whenever the command was rewritten,
so the model reports what ran rather than what it asked for. `yolo` lifts
the narrowing with the rest of the rate limiting.

---

## What is recorded

Everything the agent does lands in its SQLite database and in the live
stream: tasks and their results, findings, scored outcomes, detections,
every approval request with its classification and EV numbers, and one row
per model call with provider, model, token counts, latency and status.

**Prompt and response text are not stored by default.** A prompt carries
scan output, which can include credentials recovered from the target, so
writing it to disk is an explicit choice:

```yaml
agent:
  llm:
    llm_log_level: "full"    # off (default) | full
```

The audit trail without it is the stream, `tasks`, `findings` and
`approvals` — what was done and what was decided. `full` adds what the model
was told and said.

### What makes something a finding

A finding carries the output that proves it and how it was proven:

| `proof_basis` | means |
|---|---|
| `executed-live` | run against the target, and the result was seen |
| `executed-lab` | reproduced elsewhere, not on the target |
| `inferred` | read off a version, a banner or a configuration, never triggered |

Three values and no free text: the field exists to stop "probably" and
"seems to". A finding recorded without a basis is given none — silence is
better than a default that upgrades a guess.

The preamble asks the model to try to disprove a candidate before recording
it, and says plainly that **finding nothing is a valid outcome**: "tested X
across Y with method Z, clean" is recorded as a finding with its own
evidence. Without that sentence an agent whose only measure is output
produces output.

### The report

A campaign leaves a deliverable. The status panel has a **Report** button
per campaign, running or finished, and it is also at
`GET /api/ai/campaign/<id>/report` as `text/markdown`.

```markdown
# Campaign report — run 1

- **Mode**: Automated Attack
- **Status**: completed, phase 5
- **Authorised scope**: 127.0.0.0/8
- **OpSec profile**: normal

## Summary

- Findings: **3**
- Tasks: 3 of 3 completed, 0 failed
- Gated actions: 1

## Findings

### 127.0.0.1

- **service** · executed-live — vsftpd 2.3.4 answering on 2121

  ```
  2121/tcp open  ftp     vsftpd 2.3.4
  ```

- **vuln** · inferred — CVE-2011-2523, CVSS 9.8 — read from the banner

## Decisions

| Action | Decision | By | EV |
|---|---|---|---|
| `exploit_known_poc` | refused | operator | +110.1 |
```

The decisions table is not an appendix. A report listing only what the
agent did invites the reader to assume it did everything it wanted; the
refusals are the evidence that it did not, and they are the part an
authorising party actually needs.

A campaign that found nothing still gets a report, and says so against its
completed task count — "nothing was found" and "nothing was looked for"
have to be distinguishable.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| **Agent unavailable**, reason mentions Sliver | `c2.sliver.enabled: true`. See the top of this page. |
| **Agent unavailable**, "no LLM provider configured" | `AGENT_PROVIDER` / `AGENT_MODEL` unset. |
| **401 on every agent call**, or the GUI shows it unavailable with no reason | `RACCOON_TOKEN` is not fixed, so the C2 invented one at startup. Set it for both. |
| **The GUI asks for the token again after a restart** | The token it had was rejected and dropped. With `RACCOON_TOKEN` unset the C2 invents a new one at every start; read the new token from the file the banner's `Token:` line names, or fix the variable. |
| **Campaign starts and finds zero beacons** | Same as above, or the beacon registered under a different encryption key. |
| **Beacon never appears at all** | Key mismatch. The server's `--key` and the beacon's `encryption_key` must be the same base64 value; nothing is derived from the callback URL, so the URL is not the cause. A mismatch is *silent* — registration is simply never accepted. |
| **Commands come back `Unknown command: <program>`** | A beacon command starts with a beacon **verb**. `shell arp -a`, not `arp -a`. The prompt states this; if you see it, the beacon is probably running an older build. |
| **Phase 5 never happens** | It needs a confirmed service version with a known exploit. With `quiet`, `lookup_cve` is not offered and `searchsploit` is probably not installed either. |
| **A scan seems to hang** | It is rate-limited, not stuck. 1000 ports ≈ 7 minutes; `-sV` more. The agent's stream shows the command, and `effective_command` in the event detail shows what actually ran. |
| **The first command of a run waits minutes** | The previous run restored the beacon to `restore_interval`. Lower it, or restart the beacon. |
| **`403` from the agent service** | `RACCOON_AGENT_TOKEN` is empty, which means "same machine only", and the request did not come from the same machine. Set the token for an off-box agent — and then TLS for that hop is mandatory. |

---

## Known limits

### The agent layer

- **A failover does not re-derive the capability tier.** The tier is worked
  out once, at startup, from the primary provider and model
  (`config.load`), and the orchestrator reads its limits from that single
  value for the whole run. A chain whose primary is `full` therefore keeps
  `full` limits on every link: 20 orchestrator turns, 4000 characters of
  output kept, phase 5 and every tool, including when the link answering is a
  small local model that the tier system would have put at `minimal` or
  `reduced` had it been the primary. `max_phase` is a safety boundary, and
  here a model the tier system would not trust with phase 5 can be handed
  phase 5 by a failover. The approval gate and the scope are not affected and
  still stand between that model and an action. This predates the provider
  work and is more reachable now that a [model on the Pi](#a-model-on-the-pi)
  is a documented fallback. Until the tier is re-derived per active link, put
  the weakest model you would accept as the whole run's tier in
  `AGENT_CAPABILITY_TIER`.
- **Wifi phases 6–8 are unreachable.** `max_phase` tops out at 5 for every
  capability tier, so the wifi chain cannot be selected yet. Monitor mode
  has only ever been mock-tested here: the Pi's onboard WLAN is the only
  adapter in the test rig.
- **20 orchestrator turns is tight for four phases** (see above).
- **The model may set `timeout`** on a command and override a better-informed
  per-program default — 300 s instead of nmap's 900.
- **The executor is not told the C2 host's platform**, only the beacon's, so
  a `server_side` command can be written for the wrong system. The prompt
  says `server_side` is a different host; it does not say which.
- **`agent.defaults` in `configs/raccoon.yaml` is reference only.** It
  documents what the form is pre-filled with; it is not read at runtime. A
  test keeps the two in step.
- **Answering a knock while the run is paused is not wired.** The request is
  recorded and the drawer shows it, but nothing is awaiting the answer while
  the campaign is suspended, so the buttons resolve nothing. Resuming
  re-reaches the action — with `pause` still configured it suspends again,
  so switch the behaviour to `decide` or `skip` before resuming, or stop the
  run. The record is complete either way.


### Left open by the security hardening

The hardening pass of November 2026 closed most of what an audit of the C2
found. What follows is what it did not change. Each item was checked against
the code when this was written, not copied from the audit's report, and
`software/tests/test_docs.py` re-checks the ones the code can answer for:
fix one and that test fails until the entry is deleted from here.

The groups are by consequence. **Would stop a deployment** means do not put
the C2 or a beacon on a network you do not control until it is fixed or you
have accepted it knowingly. **Would stop a release** means it should not ship
to other people as it stands, though a closed lab does not hinge on it.
**Housekeeping** is cheap to fix and visible to a reviewer, and nothing
more.

#### Would stop a deployment

- **The beacon cannot verify TLS at all.** `software/c2/beacon.py` sets
  `ssl.CERT_NONE` unconditionally on its HTTPS opener and its proxy probe,
  and `verify_ssl` is assigned from the configuration and never read, so the
  setting in `configs/raccoon.yaml` cannot be turned on. (`exfil.py` does
  pass its own copy of the flag to `requests`; the beacon's callback channel
  is the one with no switch.) Over the internet the payload encryption is the
  only control left. For a self-signed certificate the answer is pinning, not
  skipping verification.
- **No replay protection, in either direction.** There is no counter, no
  timestamp, no window and no seen-message cache. Resubmitting a captured
  result overwrites the recorded output for that task and writes its loot
  file again; replaying a check-in takes the queued task off the queue, so
  the real beacon never sees it. A captured message is enough; the key is
  not needed.
- **The staged-implant download has no integrity control in the shipped
  configuration.** Nothing is fetched until `c2.sliver.staging_url` is set,
  and it ships empty. Once it is, `software/c2/sliver.py` downloads with
  `verify=False`, and the expected hash (`c2.sliver.sha256`) also ships empty
  and is checked only when set. The file is then run by a unit that runs as
  root. Set `sha256` whenever you set `staging_url`.
- **`shell=True` on a request-derived string.** `/api/server/rdp` builds a
  command line from fields of the request and runs it through a shell. The
  VNC branch also pipes the password through
  `bash -c "echo '{password}' | vncpasswd -f"`, inside single quotes: a
  password containing `'` is a command-injection primitive, the password is
  visible in the process table in clear text, and the generated
  `/tmp/.vnc_pass_*` file is never removed. The route requires the operator
  token, so the input is whoever holds it.
- **The loot download escapes its directory.** `/api/loot/<agent_id>/<filename>`
  joins an unvalidated path and gives it to `send_file` rather than
  `send_from_directory`, so `/api/loot/%2e%2e/<name>` reaches the data
  directory. Confirmed against the Flask test client, with the operator
  token. In the container layout `docker-compose.yml` documents, that
  directory holds the server's TLS private key when TLS is on.
- **The server image runs as root.** `software/c2/Dockerfile` has no `USER`
  directive, and the compose file grants `NET_ADMIN` and mounts the host's
  X11 socket. The agent image gets this right and says why in a comment; the
  server image holds the same credential and is the one running the
  commands.

#### Would stop a release

- **`on*` handler-body injections remain, in the file browser.** A
  directory-entry name that a beacon reports from the target's file system
  reaches a JavaScript string literal inside an `onclick` attribute: the
  download, loot and `cat` buttons and the directory tree, in the operator
  page in `server.py`. The escaping helper escapes `'` as `&#39;`, which does
  not help there, because the HTML parser decodes it before the JavaScript
  parser sees it; and the sites that put a backslash before `'` never escape
  the backslash. The loot list has the same shape, but names are flattened to
  `[A-Za-z0-9._-]` when they are written, so it is reachable only through a
  file written before that change. The fix is to attach handlers in
  JavaScript instead of building them as strings. That is a GUI refactor,
  which is why it was scoped out. Read from the code, not run in a browser.
- **Nothing is pinned.** Both requirements files use lower bounds only. The
  server image installs six packages with no version constraint at all and
  builds NetExec, Responder and RelayKing from moving git branches with no
  tag. A rebuild a month later is a different image.
- **Two dependencies are old, and neither is imported here.** `netifaces`
  0.11.0 (May 2021) is its last release, and being a C extension it breaks on
  new CPython rather than merely ageing. Nothing in the repository imports it:
  it is declared in `software/requirements.txt`, listed as required by the two
  cover launchers, and checked by the first-boot test, so it can probably go,
  from those four places. `ldap3`'s last stable release is 2.9.1 (July 2021),
  with only release candidates of 2.10.2 since, the newest in April 2026: slow
  rather than abandoned, which is softer than "effectively unmaintained". The
  server image and the start scripts install it by name, but `impacket` 0.13.1
  declares it as a dependency, so removing those lines would not remove it
  from the image.
- **No request-size cap and no rate limiting.** `MAX_CONTENT_LENGTH` is never
  set, so one unauthenticated POST with a multi-gigabyte body is read into
  memory and parsed as JSON before anything asks whether it is a valid
  message. (Writing it to disk needs a message that decrypts and names a
  registered agent, so that part applies to a sender with the key, not an
  anonymous one.) There is no lockout on the operator token either: sixty
  wrong-token requests in a row all answer 401. A first check reported rate
  limiting as present, because its pattern matched the `X-RateLimit-Limit`
  and `X-RateLimit-Remaining` values in a C2 profile example in `server.py`.
  They are example response headers, not a limiter.
- **`vnc_password` is a literal `raccoon`** in `configs/raccoon.yaml`, in a
  file that says, in its agent section, "Secrets never go in this file,
  because this file is in git". VNC ships disabled and binds to loopback, so
  this is a default someone will copy rather than an open door.

#### Housekeeping, but visible

- **The operator token is compared with `==`**, not `hmac.compare_digest`
  (`check_auth` in `software/c2/server.py`). Impractical to exploit remotely
  and free to fix. The agent service already compares correctly, and the
  agent layer's design document records this one.
- **Project-written files land at `0644`**: the state file, the database, the
  logs. The configuration loader refuses to read a key file looser than
  owner-only, so the project asks of others what it does not do itself. The
  operator-token file (`0600`) and the staged implant (`0700`) are the
  exceptions. `os.umask(0o077)` at the service entry points would fix every
  instance.
- **A beacon sleep floor of 10 s silently overrides a shorter interval.**
  `_jittered_sleep` in `software/c2/beacon.py` ends in
  `time.sleep(max(10, delay))`, so any configured
  `c2.beacon_interval_seconds` below 10 is ignored — and the beacon still
  *reports* the configured value in its check-in. The server sizes its
  freshness windows from that reported number (`online` under
  `interval * 2`, `stale` under `interval * 5`), so the two disagree.
  Measured with `tools/demo_env.py`, which configures 2 s: the beacon posts
  every 10 s exactly, and a perfectly healthy agent therefore shows green
  for 4 seconds out of every 10 and yellow for the other 6. The shipped
  default is 300 s, so this only bites a lab or a capture run — but there it
  makes a working beacon look like a failing one. Either report the floored
  value, or refuse a configured interval under the floor. The floor itself
  predates the hardening pass; it is in the initial commit.
- **There is no `LICENSE` file.** The README carries a badge, but nothing in
  the repository says what anyone may do with the code, so this is not
  cosmetic.
- **Six commits carrying a former contributor's company e-mail address**
  remain readable through a read-only GitHub reference, `refs/pull/2/head`.
  No push can remove them; only GitHub Support's removal flow can. Checked by
  fetching that reference into a scratch repository: six commits, none of
  them reachable from a branch here.

#### Found while hardening, not by the audit

- **The SMB and QUIC request legs are dead in production.**
  `Beacon._encrypt(data: dict)` serialises its argument itself, and three
  call sites hand it a value that is already serialised:
  `self._encrypt(json.dumps(...).encode())`, in `_beacon_smb`, in the SMB
  result send and in `_quic_send`. `json.dumps` on bytes raises `TypeError`,
  the surrounding `except` swallows it, and neither transport ever reaches a
  response. Fixing it would switch on two transports that have never run,
  which is not a change to make inside a security fix. The README's "four
  independent channels" describes the design; two of the four have not
  worked.
- **A correction to the audit's severity.** An earlier summary of the pass
  said encryption was optional on "three of four channels", with command
  execution possible without any key. The accurate statement is narrower:
  DNS was live and exploitable, since answering one TXT query was enough,
  while SMB and QUIC could not be reached at all, so their unencrypted
  fallbacks were latent. Removing all three fallbacks was still right. The
  claim was overstated.

#### Minor, deferred

Nineteen minor findings were deferred, each by a reviewer who judged it not
worth holding the change for. Two say nearly the same thing and are one entry
below, so eighteen entries stand for nineteen findings. None is dropped. The
first five are the ones that are traps for a later change.

- **`_handle_result` still does bookkeeping for an unregistered agent.** It
  records `results[task_id]`, appends history and saves state before it checks
  that the agent is registered, so a sender who holds the beacon key but has
  no registered identity can grow a dict without bound. "Creates nothing"
  holds for the file system only: `_save_state` persists agents, history,
  the scan store and the name counter, not `results`. Same family as the
  missing request-size cap.
- **The installer's unit-file test over-reads what a unit can reach.**
  (Two findings, merged.) In `software/tests/test_c2_hardening.py`,
  `_unit_reach` treats a system interpreter's prefix as a tree, so
  `ExecStart=/usr/bin/python3` puts all of `/usr` in scope and any
  user-targeted `chown` under `/usr` fails the test; and it treats every
  absolute-path argument as a path read as root, so a unit with
  `--out /opt/raccoon/captures` would fail against the very directory the fix
  deliberately hands to the user. Latent: no current unit does either. The
  trees rule should be restricted to virtualenvs.
- **The operator listener runs unsupervised, in a thread.** If that thread
  dies the agent socket keeps serving and the interface is gone, with nothing
  logged. There is no half-started state (both sockets bind before either
  thread starts) and shutdown is clean, so a supervisor is a larger change
  than the fix that introduced the thread should carry.
- **Both PowerShell launchers are unverified.** There is no PowerShell on the
  machine this was built on. `start_server.ps1` and `test_add_agent.ps1` need
  one run on Windows, for two things: the `Read-Secret` helper, and the
  `try/finally` around the launch.
- **The no-echo test helper has a floor.** `_assert_not_echoed` (two copies,
  in `test_c2_hardening.py`) scans every 8-character window of a key, so a
  leak of seven characters or fewer still passes.
- **An unhashable `agent_id` raises** on `agent_id in history`, and the
  catch-all returns the fake response. It is not an oracle, being independent
  of registration, but it is an uncaught type error on a path any holder of
  the key reaches.
- **A registered agent still gets the fake response if `mkdir` or
  `write_bytes` raises `OSError`.** Judged not inducible by the sender
  (the file name is capped at 100 characters and the directory is named by
  the server), and hiding a real write failure behind an acknowledgement
  would be worse. The optional hardening named: catch `OSError`, log it at
  error level, and still acknowledge.
- **`_owner_of` and `_handed_away` do not normalise `..`**, so
  `chown -R "${INSTALL_DIR}/../raccoon/software"` passes the unit-file test.
- **`_unit_reach` raises a raw `ValueError` on a systemd line continuation**,
  and sees only `/bin/sh` for an `ExecStart=/bin/sh -c '… venv/bin/python …'`
  wrapper.
- **`beacon.decode_key`'s docstring claims the launchers share it.** None do.
- **`server.py`'s `except ImportError` around the beacon import** would also
  catch an `ImportError` raised from inside `beacon`, re-raising something
  less specific. It cannot happen today.
- **Two loopback-equivalent page hosts are not recognised by the prefill
  guard**: `*.localhost` (RFC 6761), and a hostname aliased to loopback in
  `/etc/hosts` or an SSH config, which JavaScript cannot know. The documented
  path, `ssh -L` and then `localhost`, is covered.
- **The Settings panel shows the interface address as `localhost` only when
  the operator host is `0.0.0.0`.** This predates the fix.
- **`aiCall()` does not clear the token on a 401.** The `/api/ai/*` proxy
  passes the companion service's status through, so a service-side 401 would
  wrongly clear a good token. Accepted: any stored token also drives
  `refreshAgents` every 3 s through `api()`, so a bad one is caught within one
  poll. A `WWW-Authenticate: Bearer` header on the C2's own 401 would be a
  sturdier marker, since the proxy forwards only body, status and
  `Content-Type` and so cannot forge it, but it is a wider change.
- **`tokenRejected` clears whatever is stored now, not the token that was
  sent.** A tiny window; `submitToken` reloads at once.
- **The route-walk test fills every URL argument with `"1"`**, so a route that
  leaks only for particular argument values would be missed.
- **The widened scanner flags an `echo` that ends a line whose successor
  starts with `$`**, when the echo ends in `--key`. No real file does this,
  the gap allows only whitespace, backslash and backtick, and it fails
  loudly.
- **The scanner matches only `--flag` forms**, so a single-dash PowerShell
  `-Key $Key` handed to a child is not covered. None exists today.

---

## See also

- [`docs/C2_DEMO.md`](C2_DEMO.md) — the operator GUI tour, including the
  agent sections with screenshots
- `docs/superpowers/specs/2026-10-30-autonomous-agent-layer-design.md` — the
  design, with the reasoning behind the gate, the phases and the EV model
- `docs/superpowers/specs/2026-11-02-ev-calibration-amendment.md` — why `R`
  is separate from the score penalty
