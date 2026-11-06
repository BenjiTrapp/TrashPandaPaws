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
./software/c2/start_server.sh --token "$RACCOON_TOKEN"

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
| `local` | a `AGENT_BASE_URL` (Ollama, LM Studio, llama.cpp); no key |

A Bedrock model id carries its own region prefix (`eu.`, `us.`). An EU id
against a US endpoint fails at the first call rather than at configuration,
so set `AWS_REGION` to match the prefix.

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
      - provider: local
        model: qwen2.5-coder
        base_url: http://127.0.0.1:11434/v1
```

An entry takes `provider`, `model`, and optionally `base_url` and
`api_key_env`. A literal `api_key` is refused — by name, without the value
being echoed into the error. A `local` link needs no key at all, which
makes a model on the box itself the sensible last resort: it cannot be
rate-limited and it cannot have its key revoked.

**How it behaves.** Any failure moves to the next link. The HTTP status is
not consulted, because a 401 is a revoked key *or* a header this code got
wrong and both are reasons to try the next one — and nothing is hidden,
since every attempt is written to `llm_interactions` and the final error
names every link that was tried. A link that fails **twice in a row** is
skipped for **2 minutes**; after that it gets one attempt, not a fresh
allowance, because a revoked key is still revoked.

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
| **Campaign starts and finds zero beacons** | Same as above, or the beacon registered under a different encryption key. |
| **Beacon never appears at all** | Key mismatch. The server's `--key` and the beacon's `encryption_key` must be the same base64 value; nothing is derived from the callback URL, so the URL is not the cause. A mismatch is *silent* — registration is simply never accepted. |
| **Commands come back `Unknown command: <program>`** | A beacon command starts with a beacon **verb**. `shell arp -a`, not `arp -a`. The prompt states this; if you see it, the beacon is probably running an older build. |
| **Phase 5 never happens** | It needs a confirmed service version with a known exploit. With `quiet`, `lookup_cve` is not offered and `searchsploit` is probably not installed either. |
| **A scan seems to hang** | It is rate-limited, not stuck. 1000 ports ≈ 7 minutes; `-sV` more. The agent's stream shows the command, and `effective_command` in the event detail shows what actually ran. |
| **The first command of a run waits minutes** | The previous run restored the beacon to `restore_interval`. Lower it, or restart the beacon. |
| **`403` from the agent service** | `RACCOON_AGENT_TOKEN` is empty, which means "same machine only", and the request did not come from the same machine. Set the token for an off-box agent — and then TLS for that hop is mandatory. |

---

## Known limits

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

---

## See also

- [`docs/C2_DEMO.md`](C2_DEMO.md) — the operator GUI tour, including the
  agent sections with screenshots
- `docs/superpowers/specs/2026-10-30-autonomous-agent-layer-design.md` — the
  design, with the reasoning behind the gate, the phases and the EV model
- `docs/superpowers/specs/2026-11-02-ev-calibration-amendment.md` — why `R`
  is separate from the score penalty
