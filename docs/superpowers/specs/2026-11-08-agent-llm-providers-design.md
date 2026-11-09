# Vertex AI, a free-tier link and a named Ollama provider — design

**Date:** 2026-11-08
**Status:** approved 2026-11-08

---

## Intent

`software/agent/llm/provider.py` accepts five provider names today:
`anthropic`, `bedrock`, `openrouter`, `opencode`, `local`. Three LLM vendors
reach the agent through two wire formats — Anthropic Messages and OpenAI Chat
Completions — plus Bedrock's Converse API. Google reaches it through none of
them.

That is the gap this work closes, and it arrived together with two smaller
ones. The starting point was `~/Downloads/trashpandapaws_agent_pr.zip`, a
self-contained second agent layer with its own `providers/` package
(Anthropic, OpenRouter, Ollama, HuggingFace), its own `agent.py` and its own
`check_providers.py`. **It is not being merged.** It would overwrite
`software/agent/__init__.py`, stand a second provider abstraction beside
`llm/`, read `api_key` out of a file that is under git, and format HTTP
response bodies into exception messages — and a response body can echo an
`Authorization` header back, which is why `provider.py` is built the way it
is. What the zip contributed is three ideas, and they are what gets built:

1. **Google.** Vertex AI beside Bedrock, so a campaign can run on a Google
   Cloud project.
2. **A free tier as the last link of the provider chain**, so a run that
   exhausts or loses every paid key still has somewhere to go.
3. **Ollama as a provider with a name**, with the pre-engagement check the
   zip's `check_providers.py` does well.

The third one is mostly about honesty. `provider: local` already defaults to
`http://127.0.0.1:11434/v1`, which is Ollama's OpenAI-compatible endpoint, so
Ollama has worked all along under a name that does not say so, with a 120 s
transport timeout that a 14B model on a CPU will exceed.

---

## Goals

1. **`provider: vertex`** drives a campaign against Gemini on a Google Cloud
   project, and it **survives a two-hour unattended run** — which a Google
   OAuth access token, valid for one hour, does not do by itself.
2. **`provider: gemini`** drives a campaign against the Gemini API with a
   static key, and works as a `fallbacks:` link with
   `api_key_env: GEMINI_API_KEY`.
3. **`provider: ollama`** is a documented name with Ollama's defaults and a
   timeout that suits CPU inference.
4. **A pre-engagement check** reports, per link in the configured chain,
   whether it is reachable — without a network probe on the polled status
   endpoint.
5. **No new runtime dependency.** Not `google-auth`, not `google-genai`, not
   the `openai` SDK. `software/tests/test_status_quo.py` keeps passing
   unchanged.
6. **A model on the Pi is expressible in configuration** and documented,
   including what it costs. No code exists for it.

---

## Non-goals

- **Service-account JSON signing.** An RS256 assertion needs `cryptography`,
  which the agent image does not declare (goal 5). The three token sources
  below cover GCE, the operator laptop, and — through a file that an external
  refresher writes — everything else. Named here as the extension point,
  because the first person who wants it will look for this paragraph.
- **Vertex Express Mode and the native `generateContent` format.** This was
  approach C in the brainstorm. Express mode takes a static API key, which is
  genuinely attractive, but only on `…:generateContent`, not on the
  OpenAI-compatible path — so it costs a third wire-format client, about the
  size of `bedrock_client.py`, to reach models that `gemini` and `vertex`
  already reach.
- **Claude on Vertex via `:rawPredict`.** Same reasoning: reachable today
  through `anthropic` or `bedrock`.
- **`Retry-After` plumbed through the transport.** A free-tier 429 is the
  common case, and the transport currently reduces it to the string
  `"HTTP 429 (rate limited)"`. Carrying a structured retry hint changes
  `Transport`, which is a documented seam with stubs in several tests, and it
  changes what `FailoverClient` does with a failure. That is its own design.
  What exists already answers the case adequately: the chain moves to the next
  link, and a link that fails twice is skipped for two minutes.
- **A second model for the executor role.** Orchestrator and executor share
  one `campaign.client` and one `capability_tier`. Splitting them is the
  prerequisite for "big model plans, small model executes", and it is not part
  of this work.
- **A model on the Pi whose job is to find the team server.** Asked and
  decided against, so it is not re-guessed later. The decision is enumerable —
  four transports, the discovered proxies, eight profiles — and the beacon
  already walks that ladder. It would break the project's loudest promise, the
  one `test_status_quo.py` asserts: the beacon is pure stdlib with no
  dependencies. And it is circular: a model that decides how to get out must
  run offline on the Pi, because asking a remote one needs the channel it is
  looking for — so the weakest model in the system would own the decision with
  the least room for error, where every failed attempt is noise on a monitored
  network. The shape that does work puts no model on the implant: a tool on the
  **team-server** side that reads a beacon's transport telemetry and proposes a
  profile or transport change, over a channel that already exists (DNS is
  exactly that side channel). Its own project.

## Anti-goals

Each of these would make the work a failure even if every goal above were met.

- **A credential reachable from an exception, a log line, or the
  `llm_interactions` table.** `provider.py` goes to unusual lengths here —
  failures are raised outside their `except` block so the `ProviderError` has
  an empty `__context__`, because a `requests` exception holds a `.request`
  whose headers carry the key. A token source that prints `gcloud`'s stdout,
  or a metadata-server failure that formats its response body, throws that
  away.
- **The C2 or the beacon gaining a dependency on any of this.** The project's
  hard promise is that both run with no model attached and nothing extra
  installed.
- **A provider that reaches `full` tier because of how it is spelled.**
  `max_phase` is a safety boundary: phase 5 is exploitation.

---

## Constraints

| Constraint | Where it comes from | What it forces |
|---|---|---|
| A Google access token lives ~1 h; a campaign runs up to 2 h | `docs/AGENT.md`, Google's token docs | A refresh seam, not a static key |
| `Transport` is `(url, headers, body) -> dict` | `provider.py`, stubbed in tests | A per-client timeout cannot change that signature |
| `config.available()` is polled by the GUI | `service.py`, status panel | No network probe in the availability check |
| Every link is built at **startup** | `failover.create_chain` | A token source that cannot be used is a configuration error reported then |
| `test_docs.py` walks `provider._PROVIDERS` | that test | Every new name must appear in `docs/AGENT.md` **and** `configs/raccoon.yaml` or the suite fails |
| `capability_tier` special-cases `provider == "local"` | `provider.py` | A second local name must join that rule, or it reaches `full` on its model name |
| Secrets never come from YAML under git | `config.py`, `_YAML_SECRET_PATHS` | Vertex configuration carries no credential, only where to get one |

---

## Approaches

Three ways to reach Google were considered. All three share the parts that are
not in tension: `gemini` is one registry entry on the existing
`OpenAiCompatibleClient`, because the Gemini API serves
`https://generativelanguage.googleapis.com/v1beta/openai/chat/completions`
with a static key as `Authorization: Bearer` and supports function calling.
Ollama is a second registry entry. The Pi is a documented `fallbacks:` entry.

**A — the OpenAI-compatible path, token supplied from outside.** Vertex serves
the same Chat Completions shape at
`…/projects/{project}/locations/{location}/endpoints/openapi/chat/completions`;
it wants an OAuth bearer where OpenRouter wants a key. So: two registry
entries, no new concept, and the token comes from the environment exactly as
`AWS_BEARER_TOKEN_BEDROCK` does today. Smallest possible change. Trades away
the thing the provider chain exists for: the token expires after an hour, and
a two-hour unattended campaign meets that as a 401 in the dark — which the
chain reads as a revoked key and which trips the link for two minutes.

**B — the same path, with the token fetched and refreshed.** A `TokenSource`
seam: a blocking callable that returns a current bearer, cached until shortly
before it expires, run off the event loop. Three sources, cheapest first:
the GCE metadata server, `gcloud auth print-access-token`, and a file that an
external refresher rewrites. Costs one new concept, and breaks the assumption
in `HttpLlmClient` that its credential is fixed for the client's life.

**C — B plus the native Gemini wire format.** Adds a third wire-format client
so that an Express Mode API key works, and `:rawPredict` makes Claude on
Vertex reachable. Most capability, and a format to maintain for as long as the
project exists.

**Chosen: B.** The reason A loses is specific rather than aesthetic: the chain
was built for unattended runs, and A's sharp edge is located exactly there. C
loses because every model it adds is already reachable by another name.

---

## How it is built

### 1. `TokenSource` — `software/agent/llm/gcp_token.py` (new)

```python
class TokenSource:
    def bearer(self) -> str: ...     # blocking; raises TokenUnavailable
```

Blocking by design: it is called through `asyncio.to_thread`, like the
transport, so an HTTP round trip or a subprocess does not stall the loop.

**Caching.** The source holds the token and its expiry and returns the cached
value until fewer than **300 seconds** remain. Five minutes of skew is more
than a turn takes and far less than the hour a token lives, so a token never
expires mid-request and a campaign makes at most two or three refreshes.

**Construction never fetches a token.** `create_client` validates only what is
cheap and local: for `gcloud`, that the binary is on `PATH`; for `file`, that
the path exists and `_read_keyfile` accepts its mode; for `auto`, that at least
one source is plausible. The first real fetch happens in the first
`complete()`.

The reason is `config.available()`. It is **synchronous** and it is called from
two aiohttp handlers, from the scheduler before every scheduled run, and from
`__main__`. If construction resolved a token, every status poll would block the
event loop for a metadata timeout plus a `gcloud` subprocess — which is the
stall this design claims to avoid, merely moved. So "a token source that cannot
be used" means, at startup, exactly the local checks above; whether a token can
actually be *obtained* is what `preflight` answers, and that is the whole
distinction between the two.

**One source per kind, process-wide.** Every campaign calls
`client_factory(cfg)` afresh, so a source owned per client would mean N caches,
N `gcloud` spawns per refresh, and the same token fetched N times. `gcp_token`
therefore hands out a **cached instance keyed by (kind, path)** from a module
registry. This also keeps `_LinkConfig` at four fields: a `vertex` link in a
chain asks for the same shared source by name rather than carrying one.

**Thread-safe, because it has to be.** One client instance per campaign is
shared by the orchestrator and by up to `max_concurrent_executors` (default 4)
executor turns, all reading `camp.client`. Four concurrent turns meeting an
expired token would otherwise spawn four `gcloud` processes and race on the
cache's read-modify-write. A `threading.Lock` around check-and-populate, and a
test that drives it from several threads at once and asserts the underlying
fetch ran **once**.

**The sources.**

| Name | How | Expiry | Notes |
|---|---|---|---|
| `metadata` | `GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`, header `Metadata-Flavor: Google` | from `expires_in` | 1 s timeout, so absence is detected fast rather than waited out |
| `gcloud` | `gcloud auth print-access-token` | assumed 30 min | stdout is the token and is never logged; on failure only the **return code** is reported, never stderr |
| `file` | re-read `api_key_file` | re-read after 10 min | the zero-dependency path: a cron job or wrapper writes a fresh token to a `chmod 600` file, which `_read_keyfile` already validates |
| `auto` (default) | `metadata` → `gcloud` → `file` | — | the failure names all three and what each said |

`TokenUnavailable` is the module's own exception and follows
`TransportError`'s discipline: the message is built from a status code, an
exception class or a return code, never from a response body, a URL or a
command's output.

The metadata address is plain `http` to a link-local name. The guard in
`_checked_base_url` that refuses a key over cleartext does not apply and must
not be extended to cover it: that guard is about the model endpoint, and
nothing is sent *to* the metadata server.

**The inverse case is a hole and gets closed.** `_checked_base_url` is called
with `has_key=bool(api_key)`, and a `vertex` client has no key at construction
— so `provider: vertex` with `base_url: http://some-proxy/…` would pass the
guard and then be handed a live OAuth bearer over cleartext. `has_key` becomes
**"a key *or* a token source"**, with a test pinning it. The Pi example in §7
is unaffected: an `ollama` link has neither.

### 2. `HttpLlmClient` learns to refresh

Two changes in `provider.py`:

- `__init__` takes `token_source: Optional[TokenSource] = None`.
- `complete()` resolves the credential before `_build_request`:
  `await asyncio.to_thread(source.bearer)`, stored as the client's current
  `Secret`. The failure path is the one already there — captured, raised once
  the `except` block has exited, so the resulting `ProviderError` carries no
  `__context__`.

Three subclasses build their auth header from `self._api_key.reveal()`, so
putting the fresh token there means `openai_client`, `anthropic_client` and
`bedrock_client` need no change at all.

**The attribute is renamed `_api_key` → `_bearer`** across those three files
(four call sites). Mechanical, and diff noise worth paying: with a token
source the thing it holds is not an API key, and this codebase's comments
repeatedly warn about exactly this kind of name that has quietly stopped being
true.

### 3. The three registry entries

```python
"vertex":  ("openai", None,  False, False),   # url computed; bearer from a token source
"gemini":  ("openai", "https://generativelanguage.googleapis.com/v1beta/openai", True, False),
"ollama":  ("openai", "http://127.0.0.1:11434/v1", False, False),
```

**`vertex`'s endpoint is computed, not written**, the way
`bedrock_base_url(region)` already is in the same module and for the same
reason: the region appears **twice** in the URL, and a mismatch is a silent
404 rather than a configuration error. `vertex_base_url(project, location)`
returns
`https://{location}-aiplatform.googleapis.com/v1/projects/{project}/locations/{location}/endpoints/openapi`
and an explicit `base_url` still overrides it through the normal cascade. The
model id carries a publisher prefix (`google/gemini-…`), which is stated in the
docs beside Bedrock's region-prefix note, because it is the same trap.

**`local` stays**, as the name for LM Studio and llama.cpp and for configs that
already use it — including the fallback example in `docs/AGENT.md`.

**`capability_tier` gets `LOCAL_PROVIDERS = frozenset({"local", "ollama"})`**
and tests both rules against it: a local endpoint never reaches `full` on its
model name, and a name declaring fewer than 30B parameters is `minimal`.
Without this, `provider: ollama` with `model: gpt-4o` would reach `full`.

Gemini lands correctly on the existing allowlist by itself — `gemini-3-pro`
matches `gemini-[2-9](\.\d+)?-pro` and so is `full`; `-flash` and `-lite` are
excluded by `_SMALL_VARIANT` and so are `reduced`. Accurate, but currently by
accident: a test pins it.

### 4. A per-client timeout, without touching `Transport`

`http_post_json` gains a keyword-only `timeout` defaulting to today's 120 s.
`HttpLlmClient` takes a `timeout` and, when it builds the **default**
transport, binds it in a closure. The `Transport` type stays
`(url, headers, body) -> dict`, so every stub in the test suite is unaffected.
`ollama` and `local` get **300 s**; everything else keeps 120 s.

### 5. The pre-engagement check — `software/agent/llm/preflight.py` (new)

`python -m software.agent.llm.preflight` loads the same configuration cascade,
builds the chain, and reports per link:

- it was **constructed** (model present, credential resolvable, endpoint sane)
- for `ollama` / `local`: the server answers `GET {root}/api/tags`, and the
  configured model is in the list — the one check that catches the most common
  local failure, a model that was never pulled
- with `--ping`: one minimal completion per link. **Opt-in**, because on a
  metered provider a health check that costs tokens is a health check nobody
  runs.

**Deliberately not part of `config.available()`.** That method is called by the
polled status endpoint; a probe against an Ollama that is not running would
stall the GUI once per poll. `available()` keeps doing what it does — build
every link and report every construction problem — and a token source that
cannot produce a token at startup is one of those problems.

### 6. Configuration

New fields, following the existing cascade (CLI → YAML → env → default) and
the rule that no credential comes from YAML:

| Field | YAML path | Env | Notes |
|---|---|---|---|
| `vertex_project` | `agent.llm.vertex_project` | `AGENT_VERTEX_PROJECT` | required for `vertex` unless `base_url` is explicit |
| `vertex_location` | `agent.llm.vertex_location` | `AGENT_VERTEX_LOCATION` | default `europe-west4`, matching Bedrock's EU-first default |
| `token_source` | `agent.llm.token_source` | `AGENT_TOKEN_SOURCE` | `auto` \| `metadata` \| `gcloud` \| `file` |

**`api_key_file`'s path has to survive load, and its reader has to move.** Today `config.load` resolves it through `_read_keyfile`, keeps the resulting string in `api_key` and **pops the path**, so the `file` source as first described had nothing to re-read. The path is kept on `AgentConfig` as `api_key_file`, and the eager read at startup stays exactly as it is.

The reader itself moves to `software/agent/secret.py` as `read_keyfile`. `gcp_token` cannot import `config` — `config` imports `llm.provider`, and that would close a cycle — and duplicating a mode check that guards a credential is not an option. `secret.py` was created for precisely this situation; its own docstring says the holder lives there rather than in either module that needs it. `config._read_keyfile` stays as a wrapper that re-raises `SecretError` as `ConfigError`, so the existing keyfile tests hold.

**Precedence, stated because an operator cannot see it otherwise.** For
`provider: vertex`:

1. `token_source` set explicitly to `metadata`, `gcloud` or `file` wins
   outright.
2. Otherwise, a credential that is already present — `AGENT_API_KEY` or
   `api_key_file` — is used as a **static** bearer, and `available()` says so
   in its reason text: no refresh will happen, and a run past the token's hour
   will fail. That is approach A, as an explicit opt-in for a quick supervised
   run, labelled rather than discovered.
3. Otherwise `auto` walks metadata → gcloud → file.

**A `vertex` link in `fallbacks:` refuses `api_key_env`**, by name, the way a
literal `api_key` is already refused. A static bearer on the link that exists
to catch the primary's failure reintroduces precisely the one-hour 401 that
ruled approach A out, and it would do it in the dark. Such a link spells its
`base_url` out and draws its bearer from the shared token source.
`FallbackLink` keeps its four fields, and the chain stays the one place that
holds no secrets, only the names of environment variables.

### 7. The Pi — documentation only

A model on the Pi is already expressible:

```yaml
fallbacks:
  - provider: ollama
    model: qwen2.5:1.5b
    base_url: http://10.0.0.5:11434/v1
```

`_checked_base_url` permits plain `http` here because there is no key to
leak. What the documentation has to say plainly is the rest of the bill: the
prompts and the tool output cross the LAN in cleartext **to the implant**; the
Pi is PoE-powered at about 13 W while bridging and capturing; an Ollama binary
and a multi-gigabyte model blob are a large forensic artefact on a device whose
whole purpose is to look like an IP phone; and such a model is `minimal` tier,
so it cannot go past phase 3. It is a last resort that keeps a run alive, not
a second brain.

### 8. Where `vertex` runs

**The host is the documented path.** A directly started agent has `gcloud` on
its `PATH`, so `auto` finds a token with no setup at all, and that is what the
quick-start block in `docs/AGENT.md` shows.

**The container is supported anyway**, because the alternative is that someone
sets `AGENT_PROVIDER=vertex` in `docker-compose.yml` and gets a service that
cannot authenticate with nothing to tell them why. It costs little:

- `AGENT_VERTEX_PROJECT`, `AGENT_VERTEX_LOCATION` and `AGENT_TOKEN_SOURCE`
  join the explicit environment list in `software/c2/docker-compose.yml` —
  which `test_agent_deployment.py` reads, so the test is the thing that keeps
  this honest.
- The `file` source is the container's answer: the existing
  `AGENT_API_KEY_FILE` path, mounted read-only, written by a refresher on the
  host (`gcloud auth print-access-token` from cron or a systemd timer, into a
  `chmod 600` file). `_read_keyfile` already refuses anything looser.
- `gcloud` stays **out** of the image, deliberately, and the docs say so where
  an operator will look: the Dockerfile's own comments explain why that image
  is slim, and half a gigabyte of Cloud SDK for one `print-access-token` is
  exactly what they are arguing against.
- On GCE or Cloud Run the metadata source needs none of this and `auto` finds
  it first.

So all three sources exist in both places; which one `auto` lands on differs,
and the documentation states which to expect where.

---

## Tests

| File | What it pins |
|---|---|
| `test_agent_provider.py` | the three registry entries; the computed Vertex URL; `gemini`'s default endpoint; both tier rules against `LOCAL_PROVIDERS`; Gemini Pro `full` / Flash `reduced`; a fake token source reaching the Authorization header; that a token source counts as a credential for the cleartext guard; the per-client timeout |
| `test_agent_gcp_token.py` (new) | caching and the 300 s skew; each source; `auto`'s order; that construction fetches nothing; that several threads meeting an expired token cause **one** fetch; that no message carries a token, a body or `gcloud`'s stderr; that a missing metadata server is detected within its timeout |
| `test_agent_config.py` | the new fields through all four cascade levels; `vertex` without project or `base_url` is a configuration error; the precedence rule, including the static-bearer reason text; a `vertex` fallback link, and that one with `api_key_env` is refused |
| `test_docs.py` | already walks `_PROVIDERS` — it fails until `docs/AGENT.md` and `configs/raccoon.yaml` list all three names. The forcing function, not extra work |
| `test_status_quo.py` | unchanged, and must stay green: no new dependency, C2 imports without the agent |
| `test_agent_deployment.py` | already reads the compose environment list — it fails until the three new variables are there |

---

## What is left to the builder

- **`v1` or `v1beta1`** on the Vertex openapi path. Google's own samples show
  both. Start at `v1`; if tool calling misbehaves, `v1beta1` is the documented
  alternative and the URL builder is the only place it appears.
- **Whether the Vertex compatibility layer honours `max_tokens`** or wants
  `max_completion_tokens`. `openai_client` has a comment explaining why it
  sends `max_tokens`; Vertex may be the first target that needs the other, in
  which case it is a per-provider flag, not a global switch.
- **Current Gemini model ids** for the documentation tables. Model names move
  faster than this document; the code requires an explicit model and has no
  default precisely for that reason.
- **Verification against live endpoints** is the operator's. Every test here
  runs on a stub transport, which is how the existing suite tests Bedrock and
  Anthropic too. `preflight --ping` is the tool for the live check.
