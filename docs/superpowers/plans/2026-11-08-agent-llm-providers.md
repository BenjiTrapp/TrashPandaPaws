# Agent LLM providers: Vertex AI, Gemini free tier, named Ollama — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `vertex`, `gemini` and `ollama` as LLM providers to the agent, where `vertex` refreshes its own one-hour Google access token so an unattended two-hour campaign survives, and `gemini` serves as the free-tier last link of the provider chain.

**Architecture:** All three ride on the existing `OpenAiCompatibleClient` — no new wire format. `vertex`'s endpoint is computed from project and location the way `bedrock_base_url` already computes Bedrock's. A new `gcp_token` module supplies the bearer through a blocking `TokenSource` that `HttpLlmClient.complete` resolves off the event loop, cached process-wide per source kind and guarded by a lock because up to five turns share one client.

**Tech Stack:** Python 3.9 (the interpreter the suite runs on), stdlib only for the new module (`urllib.request`, `subprocess`), `unittest` with stub transports, no vendor SDK.

**Spec:** `docs/superpowers/specs/2026-11-08-agent-llm-providers-design.md`

## Global Constraints

- **No new runtime dependency.** Not `google-auth`, not `google-genai`, not `openai`. `software/agent/requirements.txt` does not grow. `software/tests/test_status_quo.py` must stay green.
- **`gcp_token` uses the standard library only** — `urllib.request` for the metadata GET, `subprocess` for `gcloud`. Not `requests`: `provider.py` imports it lazily with a comment explaining the import is noisy, and a token fetch is one small GET.
- **No credential in any message, log line or exception.** Messages are built from a status code, an exception class name or a process return code. Never a response body, never a URL, never `gcloud`'s stdout or stderr.
- **Refresh skew is 300 seconds.** `gcloud` tokens are assumed to live 30 minutes; the `file` source is re-read after 10 minutes.
- **`Transport` stays `(url, headers, body) -> dict`.** Every stub in the suite depends on it.
- **No network call in `config.available()`.** It is synchronous and polled.
- **Vertex default location is `europe-west4`**, matching Bedrock's EU-first default.
- **Python 3.9 syntax.** The only interpreter here with the dependencies is `/usr/bin/python3` (3.9.6), which is what the 2223-test baseline ran on. Match the surrounding code: `typing.Optional`, `Dict`, `List`, `Tuple`; `# type:` comments; `%` formatting. No `X | Y` unions, no builtin generics in annotations, no `from __future__ import annotations`.
- **The test runner is `unittest`, not pytest.** pytest is not installed. Full suite: `/usr/bin/python3 -m unittest discover -s software/tests -t . -q`. One module: `/usr/bin/python3 -m unittest software.tests.test_agent_provider -v`. Narrow further by appending `.ClassName.test_name`. Every `python3 -m pytest …` line below means its unittest equivalent.
- Python 2-style string formatting (`%`) and comment voice follow the surrounding files.

## Review Focus

Five things the spec implies, that no task's own happy-path test would catch, each wired into the task that owns the code:

1. **`vertex_location` or `vertex_project` that rewrites the URL's host or path** (`europe-west4.evil.example`, `../../`, an embedded `@`). The computed URL would point somewhere else and the bearer would go with it. Validated at construction — Task 8.
2. **A token source that yields empty or whitespace.** The client would send `Authorization: Bearer ` and collect a 401 that the chain reads as a revoked key. Treated as unavailable at fetch time — Task 5.
3. **`gcloud` that hangs.** Without a subprocess timeout the thread never returns and the campaign stalls with no error at all — Task 5.
4. **`expires_in` absent, zero, negative or non-numeric** from the metadata server. Either a refresh on every single call or a token used long past its life — Task 5.
5. **A `vertex` model id with no `google/` publisher prefix.** A 404 at the first call, which on a scheduled run is discovered by nobody — Task 8.

---

### Task 1: `ollama` as a provider with a name

**Files:**
- Modify: `software/agent/llm/provider.py` (`_PROVIDERS`, new `LOCAL_PROVIDERS`, `capability_tier`)
- Modify: `docs/AGENT.md` (provider table), `configs/raccoon.yaml` (provider comment line)
- Test: `software/tests/test_agent_provider.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `provider.LOCAL_PROVIDERS: frozenset[str]` — the provider names whose endpoint is operator-supplied and whose model name therefore vouches for nothing. Tasks 2 and 9 both read it.

- [ ] **Step 1: Write the failing tests** in `TestClientSelection` and the tier test class

```python
def test_ollama_defaults_to_loopback_and_needs_no_key(self):
    c = provider.create_client(_cfg(provider="ollama", model="qwen2.5:14b"))
    self.assertEqual(c.provider, "ollama")
    self.assertIsInstance(c, openai_client.OpenAiCompatibleClient)
    stub = _Stub({"choices": [{"message": {"content": "hi"}}]})
    c._transport = stub
    _run(c.complete("", [{"role": "user", "content": "x"}], [], 16, 0.0))
    self.assertEqual(stub.calls[0][0],
                     "http://127.0.0.1:11434/v1/chat/completions")
    self.assertNotIn("Authorization", stub.calls[0][1])

def test_ollama_is_a_local_provider(self):
    self.assertIn("ollama", provider.LOCAL_PROVIDERS)
    self.assertIn("local", provider.LOCAL_PROVIDERS)

def test_a_local_provider_never_reaches_full_on_its_model_name(self):
    for name in sorted(provider.LOCAL_PROVIDERS):
        self.assertEqual(provider.capability_tier("gpt-4o", name), "reduced")

def test_a_small_model_on_any_local_provider_is_minimal(self):
    for name in sorted(provider.LOCAL_PROVIDERS):
        self.assertEqual(provider.capability_tier("qwen2.5:14b", name),
                         "minimal")
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest software/tests/test_agent_provider.py -k "ollama or local_provider" -v`
Expected: FAIL — `ollama` is not in `_PROVIDERS`, `LOCAL_PROVIDERS` does not exist.

- [ ] **Step 3: Implement in `software/agent/llm/provider.py`**

Add `LOCAL_PROVIDERS = frozenset(("local", "ollama"))` beside `_PROVIDERS`, with a comment saying why the distinction exists: the endpoint is whatever the operator typed, so the model name vouches for nothing. Add the registry entry `"ollama": ("openai", "http://127.0.0.1:11434/v1", False, False)`. In `capability_tier`, replace both `== "local"` comparisons with membership in `LOCAL_PROVIDERS`. Keep `local` in the registry: it is the name for LM Studio and llama.cpp and it appears in the shipped fallback example.

- [ ] **Step 4: Run the provider and docs suites**

Run: `python3 -m pytest software/tests/test_agent_provider.py software/tests/test_docs.py -v`
Expected: the new tests PASS; `test_every_provider_the_code_accepts_is_documented` and `test_every_provider_appears_in_the_shipped_yaml` FAIL.

- [ ] **Step 5: Add `ollama` to the two documents**

In `docs/AGENT.md`, a row in the provider table: `ollama` needs a model that is pulled, no key, endpoint defaults to `http://127.0.0.1:11434/v1`. In `configs/raccoon.yaml`, extend the `# anthropic | bedrock | openrouter | opencode | local` comment to include `ollama`.

- [ ] **Step 6: Run both suites again**

Run: `python3 -m pytest software/tests/test_agent_provider.py software/tests/test_docs.py -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add software/agent/llm/provider.py software/tests/test_agent_provider.py docs/AGENT.md configs/raccoon.yaml
git commit -m "feat(agent): ollama as a provider with a name and a local-provider set"
```

---

### Task 2: A per-client timeout, without touching the `Transport` signature

**Files:**
- Modify: `software/agent/llm/provider.py` (`http_post_json`, `HttpLlmClient.__init__`, `create_client`)
- Test: `software/tests/test_agent_provider.py`

**Interfaces:**
- Consumes: `provider.LOCAL_PROVIDERS` (Task 1).
- Produces: `http_post_json(url, headers, body, *, timeout=_TIMEOUT_SECONDS)`; `HttpLlmClient.__init__(..., timeout: Optional[float] = None)`; `provider.LOCAL_TIMEOUT_SECONDS = 300`.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_transport_timeout_is_per_client(self):
    seen = {}

    class _FakeRequests:
        class RequestException(Exception):
            pass

        @staticmethod
        def post(url, headers=None, json=None, timeout=None,
                 allow_redirects=None):
            seen["timeout"] = timeout
            raise _FakeRequests.RequestException()

    with unittest.mock.patch.dict(sys.modules,
                                  {"requests": _FakeRequests}):
        with self.assertRaises(provider.TransportError):
            provider.http_post_json("https://x.example", {}, {},
                                    timeout=7)
    self.assertEqual(seen["timeout"], 7)

def test_a_local_provider_gets_the_long_timeout(self):
    c = provider.create_client(_cfg(provider="ollama", model="qwen2.5:14b"))
    self.assertEqual(c._timeout, provider.LOCAL_TIMEOUT_SECONDS)

def test_a_remote_provider_keeps_the_default_timeout(self):
    c = provider.create_client(_cfg(provider="openrouter", api_key="k",
                                    model="vendor/model"))
    self.assertEqual(c._timeout, provider._TIMEOUT_SECONDS)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest software/tests/test_agent_provider.py -k timeout -v`
Expected: FAIL — `http_post_json` takes no `timeout`, clients have no `_timeout`.

- [ ] **Step 3: Implement in `software/agent/llm/provider.py`**

Give `http_post_json` a keyword-only `timeout` defaulting to `_TIMEOUT_SECONDS` so the existing module-level constant stays the documented default. Add `LOCAL_TIMEOUT_SECONDS = 300` with a comment: a 14B model answering from a CPU exceeds two minutes, and that is the normal case, not a fault. `HttpLlmClient.__init__` stores `self._timeout` and, **only when no transport was passed**, binds it: `self._transport = lambda u, h, b: http_post_json(u, h, b, timeout=self._timeout)`. In `create_client`, pass `timeout=LOCAL_TIMEOUT_SECONDS` when `name in LOCAL_PROVIDERS`.

- [ ] **Step 4: Run the whole provider suite**

Run: `python3 -m pytest software/tests/test_agent_provider.py -v`
Expected: PASS, including every existing stub-transport test — the `Transport` signature is unchanged.

- [ ] **Step 5: Commit**

```bash
git add software/agent/llm/provider.py software/tests/test_agent_provider.py
git commit -m "feat(agent): per-client transport timeout, 300s for local endpoints"
```

---

### Task 3: `gemini` — the free-tier link

**Files:**
- Modify: `software/agent/llm/provider.py` (`_PROVIDERS`)
- Modify: `docs/AGENT.md`, `configs/raccoon.yaml`
- Test: `software/tests/test_agent_provider.py`

**Interfaces:**
- Consumes: nothing.
- Produces: provider name `gemini`, default base URL `https://generativelanguage.googleapis.com/v1beta/openai`.

- [ ] **Step 1: Write the failing tests**

```python
def test_gemini_posts_to_the_openai_compatible_endpoint(self):
    c = provider.create_client(_cfg(provider="gemini", api_key=_KEY,
                                    model="gemini-3-pro"))
    stub = _Stub({"choices": [{"message": {"content": "hi"}}]})
    c._transport = stub
    _run(c.complete("", [{"role": "user", "content": "x"}], [], 16, 0.0))
    url, headers, _ = stub.calls[0]
    self.assertEqual(url, "https://generativelanguage.googleapis.com"
                          "/v1beta/openai/chat/completions")
    self.assertEqual(headers["Authorization"], "Bearer " + _KEY)

def test_gemini_requires_a_key(self):
    with self.assertRaises(provider.ProviderError) as cm:
        provider.create_client(_cfg(provider="gemini", api_key=None,
                                    model="gemini-3-pro"))
    self.assertNotIn(_KEY, str(cm.exception))

def test_gemini_pro_is_full_and_the_small_variants_are_not(self):
    self.assertEqual(provider.capability_tier("gemini-3-pro", "gemini"),
                     "full")
    self.assertEqual(provider.capability_tier("gemini-3-pro-preview",
                                              "gemini"), "full")
    for small in ("gemini-3-flash", "gemini-2.5-flash-lite"):
        self.assertEqual(provider.capability_tier(small, "gemini"),
                         "reduced")
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest software/tests/test_agent_provider.py -k gemini -v`
Expected: FAIL — unknown provider `gemini`.

- [ ] **Step 3: Implement the registry entry**

`"gemini": ("openai", "https://generativelanguage.googleapis.com/v1beta/openai", True, False)`. No change to `capability_tier`: the existing allowlist pattern already matches `gemini-[2-9](\.\d+)?-pro` and `_SMALL_VARIANT` already excludes flash and lite. The tier test above exists to pin behaviour that is currently correct by accident.

- [ ] **Step 4: Run the provider and docs suites**

Run: `python3 -m pytest software/tests/test_agent_provider.py software/tests/test_docs.py -v`
Expected: the gemini tests PASS, the two documentation tests FAIL.

- [ ] **Step 5: Document it as the chain's last link**

In `docs/AGENT.md`: a provider-table row (`gemini` — `AGENT_API_KEY`, a bare model id, no endpoint to set), and in the fallback chain example a final link

```yaml
      - provider: gemini
        model: gemini-3-flash
        api_key_env: GEMINI_API_KEY
```

with one sentence on why it is last: a free tier cannot be relied on for a whole campaign, but it cannot run out of credit either. Extend the `configs/raccoon.yaml` provider comment.

- [ ] **Step 6: Run both suites again**

Run: `python3 -m pytest software/tests/test_agent_provider.py software/tests/test_docs.py -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add software/agent/llm/provider.py software/tests/test_agent_provider.py docs/AGENT.md configs/raccoon.yaml
git commit -m "feat(agent): gemini provider as the free-tier link of the chain"
```

---

### Task 4: Rename `_api_key` to `_bearer`

**Files:**
- Modify: `software/agent/llm/provider.py`, `software/agent/llm/openai_client.py`, `software/agent/llm/anthropic_client.py`, `software/agent/llm/bedrock_client.py`
- Test: no new test; the existing suite is the test

**Interfaces:**
- Consumes: nothing.
- Produces: `HttpLlmClient._bearer: Secret` — the credential currently in use. A token source may replace it between turns, which is the whole reason for the name.

- [ ] **Step 1: Rename the attribute and its three readers**

In `provider.py`, `HttpLlmClient.__init__` assigns `self._bearer = Secret(api_key)`, with a docstring line stating that this holds whatever credential is current and that a token source may replace it. Update the one reader in each of `openai_client._build_request`, `anthropic_client._build_request` and `bedrock_client._build_request`.

- [ ] **Step 2: Confirm nothing else reads the old name**

Run: `grep -rn "_api_key" software/`
Expected: only `config.py`'s own `api_key` / `api_key_file` fields and their tests. No `self._api_key`.

- [ ] **Step 3: Run the full agent suite**

Run: `python3 -m pytest software/tests/ -q`
Expected: PASS, unchanged. A failure here means something read the attribute from outside, which is the thing this step is checking for.

- [ ] **Step 4: Commit**

```bash
git add software/agent/llm/
git commit -m "refactor(agent): _api_key -> _bearer, because a token source replaces it"
```

---

### Task 5: `gcp_token` — the token source

**Files:**
- Create: `software/agent/llm/gcp_token.py`
- Test: `software/tests/test_agent_gcp_token.py` (new)

**Interfaces:**
- Consumes: `software.agent.secret.read_keyfile` — **moved there in this task**. The reader currently lives in `config.py` as `_read_keyfile`, and `gcp_token` cannot import `config`, because `config` imports `llm.provider` and that would close a cycle. `secret.py` exists for exactly this situation: its own docstring says the holder lives there rather than in either module that needs it. Duplicating a mode check that guards a credential is the one alternative worth refusing outright.
- Produces:
  - `class TokenUnavailable(Exception)`
  - `class TokenSource` with `bearer() -> str` (blocking) and `kind: str`
  - `SKEW_SECONDS = 300`, `GCLOUD_ASSUMED_LIFETIME = 1800`, `FILE_REREAD_SECONDS = 600`, `METADATA_TIMEOUT = 1.0`, `GCLOUD_TIMEOUT = 30.0`
  - `KINDS = ("auto", "metadata", "gcloud", "file")`
  - `source(kind: str, *, key_file: Optional[str] = None, read=None, now=None, fetchers=None) -> TokenSource` — returns the **shared** instance for `(kind, key_file)`, creating it once; `read` defaults to `secret.read_keyfile` and exists so the tests need no real file
  - `validate(kind: str, *, key_file: Optional[str] = None) -> None` — the cheap local check, raising `TokenUnavailable`; performs no I/O beyond `shutil.which` and a stat
- Also produces: `software.agent.secret.read_keyfile(path) -> str` and `software.agent.secret.SecretError`.

- [ ] **Step 1: Move the keyfile reader to `software/agent/secret.py`**

Move `config._read_keyfile`'s body there as `read_keyfile(path)`, raising a new `SecretError` instead of `ConfigError`. Keep every behaviour exactly: `fstat` on the descriptor that is then read, so the file cannot be swapped between check and read; any group or other bit refused; every message naming the path and the mode and nothing of the content. In `config.py`, `_read_keyfile` becomes a two-line wrapper that calls it and re-raises `SecretError` as `ConfigError`, so the existing keyfile tests and the existing error type are untouched. Extend `secret.py`'s module docstring: a third caller now needs the same guarantee.

- [ ] **Step 2: Run the config suite to confirm the move changed nothing**

Run: `python3 -m pytest software/tests/test_agent_config.py -v`
Expected: PASS, unchanged — including the mode, empty-file and not-a-regular-file cases.

- [ ] **Step 3: Write the failing tests**

```python
class TestCaching(unittest.TestCase):
    def test_a_cached_token_is_reused_until_the_skew_window(self):
        # fetcher returns ("tok-1", 3600) then ("tok-2", 3600); clock is a list
        # advanced by the test. Asserts: one fetch for t=0 and t=3600-SKEW-1,
        # a second fetch at t=3600-SKEW.
    def test_concurrent_callers_meeting_an_expired_token_fetch_once(self):
        # 8 threads call bearer() on a source whose fetcher sleeps 50 ms and
        # counts. Asserts count == 1 and all 8 got the same string.
    def test_the_shared_source_is_returned_per_kind_and_path(self):
        self.assertIs(gcp_token.source("gcloud"), gcp_token.source("gcloud"))
        self.assertIsNot(gcp_token.source("file", key_file="/a"),
                         gcp_token.source("file", key_file="/b"))

class TestMetadata(unittest.TestCase):
    def test_the_request_carries_the_metadata_flavor_header(self): ...
    def test_an_absent_metadata_server_raises_within_its_timeout(self): ...
    def test_expires_in_is_clamped(self):
        for raw in (None, 0, -5, "soon", 10 ** 9):
            # Asserts the resulting lifetime is between SKEW_SECONDS + 1
            # and 3600, never negative and never unbounded.
    def test_a_failure_message_holds_no_body_and_no_url(self):
        # body is '{"access_token": "tok-SECRET"}', status 500
        self.assertNotIn("SECRET", str(exc))
        self.assertNotIn("metadata.google.internal", str(exc))

class TestGcloud(unittest.TestCase):
    def test_stdout_becomes_the_token_and_is_not_in_any_message(self): ...
    def test_a_nonzero_exit_reports_only_the_return_code(self):
        # stderr is 'ERROR: account bob@corp.example has no credentials'
        self.assertNotIn("bob@corp.example", str(exc))
        self.assertIn("2", str(exc))
    def test_a_hanging_gcloud_is_killed_and_reported(self):
        # subprocess.run raising TimeoutExpired -> TokenUnavailable
    def test_the_assumed_lifetime_is_used(self): ...

class TestEmptyAndBlank(unittest.TestCase):
    def test_an_empty_or_blank_token_is_unavailable(self):
        for raw in ("", "   ", "\n"):
            # every source: metadata body, gcloud stdout, file contents
            with self.assertRaises(gcp_token.TokenUnavailable):
                ...

class TestAuto(unittest.TestCase):
    def test_auto_tries_metadata_then_gcloud_then_file(self): ...
    def test_auto_reports_all_three_when_every_source_fails(self):
        for word in ("metadata", "gcloud", "file"):
            self.assertIn(word, str(exc))

class TestValidate(unittest.TestCase):
    def test_validate_does_no_io(self):
        # patches the three fetchers to raise AssertionError if called
    def test_gcloud_not_on_path_is_a_configuration_error(self): ...
    def test_file_validate_refuses_a_world_readable_file(self): ...
```

- [ ] **Step 4: Run them to verify they fail**

Run: `python3 -m pytest software/tests/test_agent_gcp_token.py -v`
Expected: FAIL — no module `software.agent.llm.gcp_token`.

- [ ] **Step 5: Implement `software/agent/llm/gcp_token.py`**

A module docstring in the voice of `provider.py`: say that Google is the first provider here whose credential expires inside a campaign, that the sources are ordered by what they cost to try, and that every message is built from a status code, an exception class or a return code because this project writes LLM interactions to SQLite.

`TokenSource` holds `(token, expires_at)`, a `threading.Lock`, and a fetcher chosen by `kind`. `bearer()` takes the lock, returns the cached value when `expires_at - now() > SKEW_SECONDS`, otherwise fetches, strips, raises `TokenUnavailable` on an empty result, and stores. Clamp every lifetime into `[SKEW_SECONDS + 1, 3600]`, so a missing, absurd or unparseable `expires_in` can neither cause a fetch per call nor outlive the real token.

Fetchers return `(token, lifetime_seconds)`:
- `metadata`: `urllib.request.urlopen` with `Metadata-Flavor: Google` and `timeout=METADATA_TIMEOUT`, reading `access_token` and `expires_in`.
- `gcloud`: `subprocess.run(["gcloud", "auth", "print-access-token"], capture_output=True, text=True, timeout=GCLOUD_TIMEOUT)`; lifetime `GCLOUD_ASSUMED_LIFETIME`. On failure raise with the return code only. `stdout` is the token: it is returned and never formatted into anything.
- `file`: `read(key_file)`, lifetime `FILE_REREAD_SECONDS`.
- `auto`: tries the three in order, collects each failure's message, and raises one `TokenUnavailable` naming all three.

`source()` keeps a module dict keyed by `(kind, key_file)` behind a lock. `validate()` checks only `shutil.which("gcloud")` for `gcloud`, and for `file` that `key_file` is set — `auto` passes if any one source could plausibly work, which on a machine with neither `gcloud` nor a key file is still true, because the metadata server cannot be ruled out without asking it.

- [ ] **Step 6: Run the new suite**

Run: `python3 -m pytest software/tests/test_agent_gcp_token.py -v`
Expected: PASS.

- [ ] **Step 7: Confirm no new dependency**

Run: `python3 -m pytest software/tests/test_status_quo.py -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add software/agent/secret.py software/agent/config.py software/agent/llm/gcp_token.py software/tests/test_agent_gcp_token.py
git commit -m "feat(agent): a Google access token source that refreshes itself"
```

---

### Task 6: `HttpLlmClient` resolves a token source, and the cleartext guard counts it

**Files:**
- Modify: `software/agent/llm/provider.py` (`HttpLlmClient.__init__`, `complete`, `_checked_base_url`, `create_client`'s call to it)
- Test: `software/tests/test_agent_provider.py`

**Interfaces:**
- Consumes: `gcp_token.TokenSource`, `gcp_token.TokenUnavailable` (Task 5); `HttpLlmClient._bearer` (Task 4).
- Produces: `HttpLlmClient.__init__(..., token_source=None)`; `_checked_base_url(name, url, has_credential)`.

- [ ] **Step 1: Write the failing tests**

```python
class _FakeSource:
    kind = "fake"

    def __init__(self, *tokens):
        self.tokens = list(tokens)
        self.calls = 0

    def bearer(self):
        self.calls += 1
        if isinstance(self.tokens[0], BaseException):
            raise self.tokens[0]
        return self.tokens.pop(0) if len(self.tokens) > 1 else self.tokens[0]


def test_a_token_source_supplies_the_authorization_header(self):
    src = _FakeSource("tok-first", "tok-second")
    stub = _Stub({"choices": [{"message": {"content": "a"}}]},
                 {"choices": [{"message": {"content": "b"}}]})
    c = openai_client.OpenAiCompatibleClient(
        provider="vertex", model="google/gemini-3-pro", api_key=None,
        base_url="https://x-aiplatform.googleapis.com/v1/p/openapi",
        transport=stub, token_source=src)
    _run(c.complete("", [{"role": "user", "content": "x"}], [], 16, 0.0))
    _run(c.complete("", [{"role": "user", "content": "y"}], [], 16, 0.0))
    self.assertEqual(stub.calls[0][1]["Authorization"], "Bearer tok-first")
    self.assertEqual(stub.calls[1][1]["Authorization"], "Bearer tok-second")

def test_a_token_source_failure_is_a_provider_error_naming_the_model(self):
    src = _FakeSource(gcp_token.TokenUnavailable("no source answered"))
    c = openai_client.OpenAiCompatibleClient(
        provider="vertex", model="google/gemini-3-pro", api_key=None,
        base_url="https://x.googleapis.com/v1/p/openapi",
        transport=_Stub(), token_source=src)
    with self.assertRaises(provider.ProviderError) as cm:
        _run(c.complete("", [{"role": "user", "content": "x"}], [], 16, 0.0))
    self.assertIn("google/gemini-3-pro", str(cm.exception))
    self.assertEqual(_walk_chain(cm.exception).count("no source answered"),
                     1)

def test_a_token_source_counts_as_a_credential_for_the_cleartext_guard(self):
    with self.assertRaises(provider.ProviderError) as cm:
        provider._checked_base_url("vertex", "http://proxy.example/v1", True)
    self.assertIn("https", str(cm.exception))
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest software/tests/test_agent_provider.py -k token_source -v`
Expected: FAIL — `OpenAiCompatibleClient` takes no `token_source`.

- [ ] **Step 3: Implement in `provider.py`**

`HttpLlmClient.__init__` stores `self._token_source`. `OpenAiCompatibleClient.__init__` passes `token_source` through — the other two clients need no change, since only `vertex` uses one, but the parameter lives on the base class so a future provider does not have to re-invent it.

In `complete()`, before `_build_request`: when a source is set, `token = await asyncio.to_thread(self._token_source.bearer)` and `self._bearer = Secret(token)`. Follow the file's established failure discipline exactly — capture the reason inside the `except`, raise `self._fail(...)` only after the block has exited, so the `ProviderError` has an empty `__context__`. A `TokenUnavailable` message is already safe to show; nothing else from the call is formatted.

Rename `_checked_base_url`'s third parameter to `has_credential` and, at its one call site in `create_client`, pass `bool(api_key) or token_source is not None`. Add a comment: without this, `provider: vertex` with an `http://` base URL would pass the guard and then be handed a live OAuth bearer.

- [ ] **Step 4: Run the provider suite**

Run: `python3 -m pytest software/tests/test_agent_provider.py -v`
Expected: PASS, including `test_cleartext_http_is_fine_on_loopback` and the Pi-shaped case of an `ollama` link over plain `http` with no credential.

- [ ] **Step 5: Commit**

```bash
git add software/agent/llm/provider.py software/agent/llm/openai_client.py software/tests/test_agent_provider.py
git commit -m "feat(agent): clients refresh a bearer from a token source"
```

---

### Task 7: Configuration — Vertex fields, the keyfile path, precedence

**Files:**
- Modify: `software/agent/config.py` (`_FIELDS`, `AgentConfig`, `load`, `_read_fallbacks`, `available`, `opsec_warnings`)
- Test: `software/tests/test_agent_config.py`

**Interfaces:**
- Consumes: `gcp_token.KINDS`, `gcp_token.validate` (Task 5).
- Produces on `AgentConfig`: `vertex_project: Optional[str]`, `vertex_location: str`, `token_source: str`, `api_key_file: Optional[str]` (the path, kept), and `static_bearer: bool` — true when a `vertex` run is using a key that will not be refreshed. `available()` states that in its reason text.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_vertex_fields_resolve_through_the_cascade(self):
    # each of the three through CLI, YAML, env and default, like the
    # existing cascade tests; default location is "europe-west4",
    # default token_source is "auto"
def test_an_unknown_token_source_is_a_configuration_error(self):
    with self.assertRaises(config.ConfigError):
        _load(env={"AGENT_TOKEN_SOURCE": "magic"})
def test_the_api_key_file_path_survives_load(self):
    cfg = _load(env={"AGENT_API_KEY_FILE": path})
    self.assertEqual(cfg.api_key_file, path)
    self.assertEqual(cfg.api_key, _FAKE_KEY)   # unchanged behaviour
def test_an_explicit_token_source_beats_a_present_key(self):
    cfg = _load(env={"AGENT_PROVIDER": "vertex", "AGENT_MODEL": "google/m",
                     "AGENT_API_KEY": _FAKE_KEY,
                     "AGENT_TOKEN_SOURCE": "gcloud"})
    self.assertFalse(cfg.static_bearer)
def test_a_key_with_vertex_and_auto_is_a_labelled_static_bearer(self):
    cfg = _load(env={"AGENT_PROVIDER": "vertex", "AGENT_MODEL": "google/m",
                     "AGENT_VERTEX_PROJECT": "proj",
                     "AGENT_API_KEY": _FAKE_KEY})
    self.assertTrue(cfg.static_bearer)
    ok, reason = cfg.available()
    self.assertIn("will not be refreshed", reason)
    self.assertNotIn(_FAKE_KEY, reason)
def test_a_vertex_fallback_link_refuses_api_key_env(self):
    with self.assertRaises(config.ConfigError) as cm:
        _load(data={"agent": {"llm": {
            "provider": "anthropic", "model": "claude-sonnet-4",
            "fallbacks": [{"provider": "vertex", "model": "google/m",
                           "base_url": "https://x.googleapis.com/v1/p/openapi",
                           "api_key_env": "SOME_TOKEN"}]}}})
    self.assertIn("api_key_env", str(cm.exception))
    self.assertIn("vertex", str(cm.exception))

def test_a_quiet_profile_does_not_warn_about_any_local_provider(self):
    campaign = types.SimpleNamespace(opsec_profile="quiet")
    for name in sorted(provider.LOCAL_PROVIDERS):
        agent = types.SimpleNamespace(provider=name)
        self.assertEqual(
            [w for w in config.opsec_warnings(agent, campaign)
             if "goes to it" in w], [])
    hosted = types.SimpleNamespace(provider="anthropic")
    self.assertTrue(any("goes to it" in w
                        for w in config.opsec_warnings(hosted, campaign)))
```

**Routed finding (Task 1's review).** `opsec_warnings` compares `getattr(agent, "provider", None) != "local"`, so `opsec_profile: quiet` with `provider: ollama` warns that every finding goes to a hosted model and advises "Set provider to local" — where the operator already is. Same drift Task 1 removed from `capability_tier`, one file further on. Fix it here: compare against `provider.LOCAL_PROVIDERS` (the module is already imported as `llm_provider`), and reword the closing sentence so it names the set rather than one value.

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest software/tests/test_agent_config.py -k "vertex or token_source or api_key_file_path" -v`
Expected: FAIL — the fields do not exist.

- [ ] **Step 3: Implement in `software/agent/config.py`**

Three `_Field` entries: `vertex_project` / `agent.llm.vertex_project` / `AGENT_VERTEX_PROJECT` / `_text` / `None`; `vertex_location` likewise with default `"europe-west4"`; `token_source` with `_enum(*gcp_token.KINDS)` and default `"auto"`. Import `gcp_token` beside the existing `llm_provider` import.

In `load`, stop popping `api_key_file`: keep the path on the config and go on reading the key eagerly, so the existing keyfile tests are untouched. Compute `static_bearer`: provider is `vertex`, `token_source` is `auto`, and a key came from `AGENT_API_KEY` or the file.

`available()` appends a line when `static_bearer` is set — that the credential will not be refreshed and a run past the token's hour will fail. It is a *reason*, reported beside any others, and the existing scrub at the end of the method already covers it.

In `opsec_warnings`, replace the `!= "local"` comparison with a membership test against `llm_provider.LOCAL_PROVIDERS` and reword the advice accordingly.

In `_read_fallbacks`, refuse `api_key_env` on a link whose provider is `vertex`, by name, with the reason: a static bearer on the link that exists to catch the primary's failure brings back the expiry this design removed.

- [ ] **Step 4: Run the config and docs suites**

Run: `python3 -m pytest software/tests/test_agent_config.py software/tests/test_docs.py -v`
Expected: PASS. `test_docs` does not yet require `vertex` — the name reaches `_PROVIDERS` in Task 8.

- [ ] **Step 5: Commit**

```bash
git add software/agent/config.py software/tests/test_agent_config.py
git commit -m "feat(agent): vertex configuration, keyfile path, bearer precedence"
```

---

### Task 8: `vertex` — the computed endpoint and the wiring

**Files:**
- Modify: `software/agent/llm/provider.py` (`vertex_base_url`, `_PROVIDERS`, `create_client`)
- Modify: `docs/AGENT.md`, `configs/raccoon.yaml`
- Test: `software/tests/test_agent_provider.py`

**Interfaces:**
- Consumes: Tasks 5, 6, 7.
- Produces: `vertex_base_url(project: str, location: str) -> str`; provider name `vertex`.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_vertex_endpoint_is_computed_from_project_and_location(self):
    self.assertEqual(
        provider.vertex_base_url("my-proj", "europe-west4"),
        "https://europe-west4-aiplatform.googleapis.com/v1/projects/"
        "my-proj/locations/europe-west4/endpoints/openapi")

def test_a_location_that_would_move_the_host_is_refused(self):
    for bad in ("europe-west4.evil.example", "eu/../x", "eu@evil.example",
                "eu west4", "", "EU_WEST"):
        with self.assertRaises(provider.ProviderError):
            provider.vertex_base_url("proj", bad)

def test_a_project_that_would_move_the_path_is_refused(self):
    for bad in ("../../admin", "proj/x", "proj?x=1", ""):
        with self.assertRaises(provider.ProviderError):
            provider.vertex_base_url(bad, "europe-west4")

def test_a_vertex_model_without_a_publisher_prefix_is_refused(self):
    with self.assertRaises(provider.ProviderError) as cm:
        provider.create_client(_cfg(provider="vertex", model="gemini-3-pro",
                                    vertex_project="proj"))
    self.assertIn("google/", str(cm.exception))

def test_vertex_without_a_project_says_what_to_set(self):
    with self.assertRaises(provider.ProviderError) as cm:
        provider.create_client(_cfg(provider="vertex",
                                    model="google/gemini-3-pro"))
    self.assertIn("AGENT_VERTEX_PROJECT", str(cm.exception))

def test_vertex_builds_a_client_with_a_token_source_and_no_key(self):
    c = provider.create_client(_cfg(
        provider="vertex", model="google/gemini-3-pro",
        vertex_project="proj", vertex_location="europe-west4",
        token_source="gcloud"))
    self.assertEqual(c.provider, "vertex")
    self.assertIsNotNone(c._token_source)
    self.assertFalse(bool(c._bearer))
```

`_cfg` gains `vertex_project=None, vertex_location="europe-west4", token_source="auto", api_key_file=None` so existing calls are unaffected.

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest software/tests/test_agent_provider.py -k vertex -v`
Expected: FAIL — no `vertex_base_url`, unknown provider.

- [ ] **Step 3: Implement in `provider.py`**

`vertex_base_url(project, location)` validates both against `re.compile(r"\A[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\Z")` — Google's own shape for a project id and a location — and raises `ProviderError` naming the field otherwise. Comment why: both are interpolated into a URL, so a value with a dot, a slash or an `@` moves the host or the path, and a bearer follows the URL. Return the `/v1/…/endpoints/openapi` form; note in a comment that `v1beta1` is the documented alternative if tool calling misbehaves and that this function is the only place it appears.

Registry: `"vertex": ("openai", None, False, False)`. In `create_client`, when the name is `vertex`: require a model whose first segment is a publisher (`google/…`) and say so, because a bare id is a 404 at the first call; compute `base_url` from the config's project and location when none was given explicitly, and report `AGENT_VERTEX_PROJECT` by name when the project is missing; call `gcp_token.validate(cfg.token_source, key_file=cfg.api_key_file)` and then `gcp_token.source(cfg.token_source, key_file=cfg.api_key_file)` — whose `file` fetcher defaults to `secret.read_keyfile`, so `provider.py` never imports `config` and the cycle stays open. When `cfg.static_bearer` is set, no source is built and the key is used as-is.

- [ ] **Step 4: Run the provider, config and docs suites**

Run: `python3 -m pytest software/tests/test_agent_provider.py software/tests/test_agent_config.py software/tests/test_docs.py -v`
Expected: the vertex tests PASS, the two documentation tests FAIL on the new name.

- [ ] **Step 5: Add `vertex` to the two documents**

A provider-table row in `docs/AGENT.md` and the name in the `configs/raccoon.yaml` comment, plus the three new YAML keys in the `agent.llm` block with comments (no credential among them). The prose section comes in Task 10.

- [ ] **Step 6: Run the three suites again**

Run: `python3 -m pytest software/tests/test_agent_provider.py software/tests/test_agent_config.py software/tests/test_docs.py -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add software/agent/llm/provider.py software/tests/test_agent_provider.py docs/AGENT.md configs/raccoon.yaml
git commit -m "feat(agent): vertex provider on a computed, validated endpoint"
```

---

### Task 9: The pre-engagement check

**Files:**
- Create: `software/agent/llm/preflight.py`
- Test: `software/tests/test_agent_preflight.py` (new)

**Interfaces:**
- Consumes: `config.load`, `failover.create_chain`, `provider.LOCAL_PROVIDERS`.
- Produces: `check(cfg, *, ping=False, probe=None) -> List[dict]` with keys `provider`, `model`, `ok`, `detail`; `main(argv=None) -> int`. `probe` is the injectable HTTP GET so the tests make no network call.

- [ ] **Step 1: Write the failing tests**

```python
def test_every_link_in_the_chain_is_reported(self): ...
def test_a_construction_failure_is_reported_per_link_not_raised(self): ...
def test_an_ollama_link_is_checked_for_a_server_and_a_pulled_model(self):
    # probe returns {"models": [{"name": "qwen2.5:14b"}]}; asserts ok
    # for that model and a detail naming the model when it is absent
def test_the_tags_url_is_derived_from_the_base_url(self):
    # base http://127.0.0.1:11434/v1 -> http://127.0.0.1:11434/api/tags
def test_an_unreachable_ollama_is_not_ok_and_does_not_raise(self): ...
def test_nothing_is_pinged_unless_asked(self):
    # a transport that raises if called; check(..., ping=False) passes
def test_no_detail_carries_a_credential(self): ...
def test_main_returns_nonzero_when_a_link_is_not_ok(self): ...
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest software/tests/test_agent_preflight.py -v`
Expected: FAIL — no module.

- [ ] **Step 3: Implement `software/agent/llm/preflight.py`**

A docstring crediting the idea and stating the boundary plainly: this is what `config.available()` deliberately is not, because that method is polled by the status endpoint and a probe against a dead Ollama would stall the GUI once per poll.

`check` builds each link the way `failover.create_chain` does but catches `ProviderError` per link instead of aborting, so one bad link does not hide the rest. For a link whose provider is in `LOCAL_PROVIDERS`, derive the root from the base URL by dropping a trailing `/v1`, GET `{root}/api/tags` through `probe` with a short timeout, and report whether the configured model is in the returned names — the most common local failure is a model that was never pulled. With `ping=True`, one minimal completion per link; opt-in, because a health check that costs tokens on a metered provider is a health check nobody runs.

`main` prints one aligned line per link and returns 1 if any is not ok, so it works in a pre-engagement script.

- [ ] **Step 4: Run the new suite**

Run: `python3 -m pytest software/tests/test_agent_preflight.py -v`
Expected: PASS.

- [ ] **Step 5: Check it against the shipped configuration by hand**

Run: `AGENT_PROVIDER=ollama AGENT_MODEL=qwen2.5:14b python3 -m software.agent.llm.preflight`
Expected: one line for `ollama`, not ok, naming either an unreachable server or a model that is not pulled — and no traceback.

- [ ] **Step 6: Commit**

```bash
git add software/agent/llm/preflight.py software/tests/test_agent_preflight.py
git commit -m "feat(agent): a pre-engagement check for the provider chain"
```

---

### Task 10: The documentation, the container, and the note about the Pi

**Files:**
- Modify: `docs/AGENT.md`, `software/c2/docker-compose.yml`
- Test: `software/tests/test_docs.py`, `software/tests/test_agent_deployment.py`

**Interfaces:**
- Consumes: everything above.
- Produces: nothing the code reads.

- [ ] **Step 1: Run the deployment test to see what it asks for**

Run: `python3 -m pytest software/tests/test_agent_deployment.py -v`
Expected: PASS today. Read how it reads the compose environment list before changing it.

- [ ] **Step 2: Write the failing test**

In `test_agent_deployment.py`, assert that `AGENT_VERTEX_PROJECT`, `AGENT_VERTEX_LOCATION` and `AGENT_TOKEN_SOURCE` are among the agent service's environment entries — in the style the file already uses for `AGENT_PROVIDER`.

- [ ] **Step 3: Run it to verify it fails**

Run: `python3 -m pytest software/tests/test_agent_deployment.py -v`
Expected: FAIL — the three variables are not in the compose file.

- [ ] **Step 4: Add the three entries to `software/c2/docker-compose.yml`**

Beside `AGENT_API_KEY_FILE`, with a comment: `gcloud` is deliberately absent from this image, so inside the container the token comes from the metadata server or from a `chmod 600` file that a refresher on the host rewrites.

- [ ] **Step 5: Write the three documentation sections in `docs/AGENT.md`**

**Vertex AI**, beside the Bedrock note, because they are the same kind of trap: the model id carries a `google/` publisher prefix, the endpoint is computed from project and location, and the token refreshes itself. A table of the sources and what each needs. One sentence that the access token lives about an hour while a campaign runs two, which is why there is a source at all rather than a key.

**Where it runs**: host is the documented path and `auto` finds `gcloud` there; the container works through the file source; GCE needs neither.

**The check**: `python3 -m software.agent.llm.preflight`, what it reports, that `--ping` costs tokens, and that it is separate from `/api/ai/status` on purpose.

**A model on the Pi**, as a `fallbacks:` entry, with the whole bill stated: prompts and tool output cross the LAN in cleartext *to the implant*; the Pi is PoE-powered at about 13 W while bridging and capturing; an inference server and a multi-gigabyte model blob are a large forensic artefact on a device built to look like an IP phone; and such a model is `minimal` tier, so it cannot go past phase 3. A last resort that keeps a run alive, not a second brain.

- [ ] **Step 6: Run the whole suite**

Run: `python3 -m pytest software/tests/ -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add docs/AGENT.md software/c2/docker-compose.yml software/tests/test_agent_deployment.py
git commit -m "docs(agent): vertex, the free-tier link, ollama, and the Pi's bill"
```
