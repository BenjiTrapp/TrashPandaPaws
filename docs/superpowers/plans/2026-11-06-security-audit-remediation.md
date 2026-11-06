# Security Audit Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the six findings the operator accepted from the security audit, so that reaching the C2's network port no longer yields control of the fleet and the beacon channel's encryption is no longer optional.

**Architecture:** The C2 keeps one Flask app and gains a second listener. An *operator* socket carries the GUI and `/api/*` and binds `127.0.0.1` by default; a *beacon* socket carries only `beacon_handler` and binds the public interface. One `before_request` hook decides what each socket may serve, keyed on `request.environ["SERVER_PORT"]` — verified empirically that two `make_server` listeners over one app report distinct `SERVER_PORT` values. The operator token leaves the served HTML: the page asks for it once and keeps it in `sessionStorage`. The AES key must be supplied explicitly; the derive-from-URL path and the `SHA256(":")` default are removed. A redirector stays outside this repository, as a documented config aimed at the beacon socket only (see Task 9 for the reasoning).

**Tech Stack:** Python 3.9, Flask (vendored), `werkzeug.serving.make_server`, stdlib `unittest`. No new dependencies.

**Spec:** `.superpowers/sdd/2026-11-06-security-audit/findings.md`

## Global Constraints

- `software/requirements.txt` and `software/agent/requirements.txt` **must not grow**. No new third-party dependency, for any task.
- **No vendored third-party code.** InfraGuard (BSD-2-Clause) and lambda-redirector (MIT) are permissively licensed and could legally be copied; the ruling is to point at them in documentation instead, for the reasons in Task 9. This repository has no LICENSE file, which is itself unresolved.
- **The C2 and the status quo must keep working with no LLM attached.** Every task is verified without the agent service running.
- Python **3.9** compatible — `software/.venv` is 3.9. No `match`, no `X | Y` type unions, no `str.removeprefix`.
- Baseline before the first commit: **2094 tests green**, whole-suite command
  `python3 -m unittest discover -s software/tests -t . -p "test_*.py"` (~222 s). Per-module runs hide cross-suite interference; the whole suite is the gate.
- No `@deutschebahn.com` in any file, commit message, or author field.
- `tools/storyboards/agent_run_script.json` keeps `Hackepeter-2.local` and `uid=501(derbenji)` — explicitly approved by the operator. Do not "fix" it.
- Error messages about a key or token name the **path and the mode**, never the value or a prefix of it. `software/agent/config.py:415-451` is the house pattern; follow it.

## Review Focus

Input classes the spec implies but no task's own happy path exercises. Each line has its test added to the owning task.

- **A beacon `agent_id` that is absolute (`/tmp`), contains `..`, is empty, or names an unregistered agent.** A reasonable person expects the loot write to stay inside the loot directory and an unknown agent to create nothing. → Task 3.
- **An operator opening the GUI with no stored token, and with a *wrong* token.** Expect a usable prompt and a clear rejection, not a blank page, not a silent retry loop, and not a stored bad token that survives reload. → Task 7.
- **A request with no meaningful `SERVER_PORT`** — which is every one of the 2094 existing tests, because `app.test_client()` does not go through a socket. Expect the split to be inert when no beacon port is configured, so single-socket operation stays exactly as it is today. → Task 6.
- **A key that is absent, malformed base64, or the right encoding but the wrong length.** Expect a startup refusal naming the problem and not the value. → Task 5.
- **A channel whose decryption fails.** Expect a *failed* check-in, not an empty-but-successful one — an empty success silently resets registration state every fifth time. → Task 1.

---

## File Structure

| File | Responsibility in this plan |
|---|---|
| `software/c2/beacon.py` | Remove three plaintext fallbacks (T1); require an explicit key (T5) |
| `software/c2/server.py` | Contain the loot path (T3); require a key (T5); two listeners + socket policy (T6); token out of the HTML, login prompt (T7); `esc()` and three raw interpolations (T2); read secrets from the environment (T8) |
| `software/c2/start_server.sh` | Loopback default + beacon port (T6); secrets out of argv (T8) |
| `software/c2/start_server.ps1` | Mirror of T8 |
| `software/c2/docker-entrypoint.sh` | Secrets out of argv (T8) |
| `software/c2/docker-compose.yml` | Operator socket loopback, beacon socket public (T6) |
| `software/setup/bootstrap.sh` | Remove the ownership handover (T4) |
| `configs/raccoon.yaml` | Key is required, not derived (T5) |
| `tools/demo_env.py` | Explicit shared key (T5); two sockets (T6) |
| `tools/storyboards/c2_tour.json`, `agent_run.json` | One login step (T7) |
| `docs/C2_DEMO.md`, `docs/AGENT.md`, `README.md` | Access path, key requirement, redirector (T6, T7, T9) |
| `docs/REDIRECTOR.md` | New: redirector guidance and nginx/Caddy config (T9) |
| `software/tests/test_c2_hardening.py` | New: the audit's regressions, one class per finding |

Tasks 1–4 are independent and have no fallout; they come first so the suite stays green in small commits. Tasks 5–7 change key provisioning and GUI access, which the demo tooling and the e2e tests depend on.

---

### Task 1: The AEAD is no longer optional on DNS, SMB and QUIC

Finding C4 — the most severe in the audit. Three channels fall back to `json.loads` when decryption fails, and the result reaches command execution. Verified verbatim at `beacon.py:1744-1752`, `:1988-1991`, `:2087-2090`.

**Files:**
- Modify: `software/c2/beacon.py:1744-1752` (`_beacon_dns`), `:1988-1991` (SMB), `:2087-2090` (QUIC)
- Test: `software/tests/test_c2_hardening.py` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: nothing. `_beacon_dns` keeps returning `Optional[dict]`; the change is that an undecryptable response yields `None` rather than a parsed dict.

- [ ] **Step 1: Write the failing tests**

In a new `software/tests/test_c2_hardening.py`, class `TestAeadIsNotOptional`:

```python
def test_dns_plaintext_tasking_is_refused(self):
    # A TXT record carrying b64(json) that was never encrypted must not
    # become tasking. Patch _dns_query to return such a record.
def test_smb_plaintext_tasking_is_refused(self):
def test_quic_plaintext_tasking_is_refused(self):
def test_undecryptable_response_is_a_failed_checkin_not_an_empty_one(self):
    # Review Focus: an empty-but-successful check-in resets _registered
    # every fifth time (beacon.py:4177-4182). Assert the failure counter
    # advanced.
```

Each of the first three builds `base64.b64encode(json.dumps({"tasks": [{"cmd": "shell", "args": "id"}]}).encode())`, feeds it through the patched channel, and asserts the return is `None` **and** that no task was produced. Assert on the absence of the task, not merely on `None` — a narrower assertion than the test's name is this project's most recurring defect (~15 instances).

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest software.tests.test_c2_hardening.TestAeadIsNotOptional -v`
Expected: the three plaintext tests FAIL — the fallback currently returns the task dict.

- [ ] **Step 3: Delete the three fallbacks**

In each of the three sites, the `except Exception:` body becomes a failure rather than a `json.loads`. Keep the DNS loop's shape (it iterates several TXT records, so one undecryptable record must not abort the loop — it must just not count). Add a comment at each site saying what the fallback used to permit, because the audit's note was that these three had no comment in a codebase that comments its reasoning.

- [ ] **Step 4: Run the tests and the two beacon modules**

Run: `python3 -m unittest software.tests.test_c2_hardening software.tests.test_beacon software.tests.test_beacon_caps -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/c2/beacon.py software/tests/test_c2_hardening.py
git commit -m "fix(beacon): refuse plaintext tasking on DNS, SMB and QUIC

The three channels fell back to json.loads when decryption failed and
the result reached _process_tasking_batch, so a party with no key could
task an implant by answering a TXT query."
```

---

### Task 2: `esc()` escapes `'`, and the three raw interpolations are closed

Findings H1, H2, H3. Verified: `esc()` at `server.py:3323` escapes `&` first (correct) and handles `<`, `>`, `"` but **not** `'`. `info.pid` goes raw into `innerHTML` at `:3188` while both immediate neighbours are wrapped. `curInterval` goes raw into an attribute at `:6071`. Header *names* go raw at `:6178`/`:6189`.

**Files:**
- Modify: `software/c2/server.py:3323` (`esc`), `:3188` (pid), `:6071` (interval), `:6133` and `:6178` (the two `tbl` helpers), `:3510` (the `RegExp`), `:1934`/`:1910` (coerce `pid`), `:1935`/`:2012` (coerce `interval`)
- Test: `software/tests/test_c2_hardening.py`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing.

- [ ] **Step 1: Write the failing tests**

Class `TestGuiEscaping`. These are source-level assertions plus server-side coercion tests, because the SPA is an inlined Python string and there is no JS test runner in this project:

```python
def test_esc_escapes_single_quote(self):
    # Read the esc() body out of _OPERATOR_HTML and assert it contains
    # the &#39; replacement, and that & is still replaced first.
def test_agent_reported_pid_is_escaped(self):
    # Assert the PID span at :3188 wraps info.pid in esc(), by locating
    # the line and matching on esc(info.pid, not on "esc" anywhere.
def test_beacon_config_interval_is_escaped(self):
def test_last_request_header_names_are_escaped(self):
def test_pid_from_a_beacon_is_coerced_to_int(self):
    # register with {"pid": "<img src=x onerror=alert(1)>"} and assert
    # the stored value is an int.
def test_interval_from_a_beacon_is_coerced_to_int(self):
    # and that GET /api/agents still answers 200 afterwards -- a string
    # interval currently 500s the whole route at server.py:333.
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest software.tests.test_c2_hardening.TestGuiEscaping -v`
Expected: all six FAIL.

- [ ] **Step 3: Fix the helper, the three sinks, and the two sources**

`esc()` gains `.replace(/'/g,"&#39;")` as the **last** step. Wrap `info.pid`, `curInterval`, and `label` in both `tbl` definitions. Escape the `RegExp` interpolation at `:3510` or require an integer. Coerce `pid` and `interval` with `int(...)` and a `try/except` default at all four server-side assignment sites.

Note for the implementer: `&#39;` fixes attribute context but **not** `on*` handler bodies — the HTML parser decodes it back to `'` before the JS parser sees it. The handler-body injections (loot names, file names) are *not* in this task; they need handlers attached in JS rather than built as strings, and that is recorded as remaining work in Task 9's docs.

- [ ] **Step 4: Run the GUI suites**

Run: `python3 -m unittest software.tests.test_c2_hardening software.tests.test_c2_server software.tests.test_c2_agent_gui -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 3: The loot write stays inside the loot directory

Finding C5. `server.py:2084` builds `data_dir / sub / agent_id` from `payload.get("agent_id", "")`. Verified: `Path("/data/loot") / "/tmp"` is `/tmp` — an absolute component discards the base. The local is named `safe_name` and only prepends a timestamp.

**Files:**
- Modify: `software/c2/server.py:2081-2090` (`_handle_result`)
- Test: `software/tests/test_c2_hardening.py`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing. `_handle_result` keeps its signature.

- [ ] **Step 1: Write the failing tests**

Class `TestLootWriteIsContained`, covering the Review Focus line in full:

```python
def test_absolute_agent_id_cannot_escape_the_loot_dir(self):
    # agent_id="/tmp" -- assert nothing was written outside data_dir,
    # using a tmp data_dir and os.walk over it.
def test_dotdot_agent_id_cannot_escape(self):
def test_empty_agent_id_writes_nothing(self):
def test_unregistered_agent_creates_no_directory(self):
def test_filename_with_separators_is_flattened(self):
def test_a_registered_agent_still_receives_its_loot(self):
    # The guard must not break the feature it protects.
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest software.tests.test_c2_hardening.TestLootWriteIsContained -v`
Expected: the escape tests FAIL.

- [ ] **Step 3: Contain the path**

Reject an `agent_id` that is not a known agent; resolve the candidate directory and require the loot base to be a parent of it (`realpath` plus a prefix check, *after* resolution, not before); sanitise `filename` to its basename with a conservative character class. Rename `safe_name` or make it true — the audit's point was that the name asserted a property the code did not provide.

- [ ] **Step 4: Run the tests and the server suite**

Run: `python3 -m unittest software.tests.test_c2_hardening software.tests.test_c2_server -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 4: The installer stops handing root's code to an unprivileged user

Finding C6. Verified: `setup/bootstrap.sh:90` chowns `/opt/raccoon` — which holds the application code and the venv interpreter — to `${SUDO_USER}`, while `services/raccoon-implant.service:10` and `raccoon-watchdog.service:8` run that interpreter as `User=root` with `Restart=always`.

**Files:**
- Modify: `software/setup/bootstrap.sh:90`
- Test: `software/tests/test_c2_hardening.py`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing.

- [ ] **Step 1: Write the failing test**

Class `TestInstallerOwnership` — a source-level guard, since the test suite cannot run a root installer:

```python
def test_install_dir_is_not_handed_to_the_invoking_user(self):
    # Assert no chown -R of INSTALL_DIR to ACTUAL_USER remains.
def test_the_two_data_dirs_are_still_user_owned(self):
    # captures/ and logs/ keep their chmod 700 and their owner, or the
    # implant cannot write to them.
def test_every_unit_running_as_root_executes_a_root_owned_path(self):
    # Parse services/*.service for User=root plus ExecStart, and assert
    # the path's tree is not chowned away in bootstrap.sh.
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m unittest software.tests.test_c2_hardening.TestInstallerOwnership -v`
Expected: FAIL.

- [ ] **Step 3: Narrow the ownership**

Keep `INSTALL_DIR` root-owned; hand over only `captures/` and `logs/`, which lines 91-92 already `chmod 700`. Add a comment naming what the broad `chown` permitted, so the next reader does not restore it.

- [ ] **Step 4: Run the test and the deployment suite**

Run: `python3 -m unittest software.tests.test_c2_hardening software.tests.test_agent_deployment -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 5: A key must be supplied; the public derivation and the fixed default are gone

Findings C2 and C3. Verified: `beacon.py:1317` and `server.py:7523` both compute `SHA-256("<callback_url>:<dns_domain>")`, one iteration, no salt, from two values an outsider observes first; `server.py:7526` falls back to `SHA-256(":")` with two warnings and no refusal.

This task has fallout: the derivation is duplicated in `tools/demo_env.py:32`, `software/tests/test_c2_server.py:65`, `software/tests/test_agent_e2e.py:61`, `software/c2/test_add_agent.py:51`, `start_server.sh:260` and `start_server.ps1:296`. All six must move to an explicit shared key. The comments at `demo_env.py:33-40` and `test_agent_e2e.py:52-63` record that a key mismatch is *silent* — the fleet simply stays empty — and that this cost the project an afternoon. Read them before changing those files.

**Files:**
- Modify: `software/c2/beacon.py:1317-1322`, `software/c2/server.py:7520-7530` and the `--derive-key` argument at `:7502`, `configs/raccoon.yaml:107-110`, `tools/demo_env.py:32-42`, `software/c2/start_server.sh:195-275`, `software/c2/start_server.ps1:296`, `software/tests/test_c2_server.py:65`, `software/tests/test_agent_e2e.py:61`, `software/c2/test_add_agent.py:51`
- Test: `software/tests/test_c2_hardening.py`

**Interfaces:**
- Consumes: nothing.
- Produces: a single helper that both the demo and the tests use to mint a key, so the derivation is not re-duplicated: `random_key() -> bytes` and `key_b64(key: bytes) -> str` in `tools/demo_env.py`. Tasks 6 and 7 use `demo_env` and must keep working.

- [ ] **Step 1: Write the failing tests**

Class `TestKeyMustBeSupplied`, including the Review Focus line:

```python
def test_server_refuses_to_start_without_a_key(self):
def test_server_refuses_a_malformed_base64_key(self):
def test_server_refuses_a_key_of_the_wrong_length(self):
def test_the_refusal_names_neither_the_key_nor_a_prefix_of_it(self):
def test_no_sha256_of_a_url_remains_in_the_server(self):
def test_no_sha256_of_a_url_remains_in_the_beacon(self):
def test_beacon_refuses_an_empty_encryption_key(self):
def test_shipped_config_does_not_claim_a_derived_key(self):
    # raccoon.yaml's comment currently promises the derivation.
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest software.tests.test_c2_hardening.TestKeyMustBeSupplied -v`
Expected: all FAIL.

- [ ] **Step 3: Remove both paths and make the absence fatal**

Server: drop `--derive-key`; `main()` errors out when no `--key` is given, with a message that includes the `python3 -c` one-liner `raccoon.yaml:109` already documents. Beacon: drop the `else` branch; an empty `encryption_key` is a configuration error at construction. Config: `encryption_key` becomes required, and its comment says what it is rather than how it is derived. Launchers: offer *generate a key* where they offered *derive from callback URL*, and keep the existing red-key-type display honest. `start_server.sh:267` computes a `CALLBACK` variable it never uses — delete it rather than wire it up.

- [ ] **Step 4: Run the tests, then the whole suite**

Run: `python3 -m unittest discover -s software/tests -t . -p "test_*.py"`
Expected: 2094 + new, all green. This task touches four test modules' fixtures, so the whole suite is the only honest gate here.

- [ ] **Step 5: Commit**

---

### Task 6: Two sockets, and a policy that says what each may serve

The structural half of finding C1, plus the operator's choice (c). Verified empirically: two `werkzeug.serving.make_server` listeners over one Flask app report distinct `request.environ["SERVER_PORT"]`.

The discriminator cannot be the path: `beacon_handler` is registered as `POST /` and `POST /<path:path>`, i.e. the catch-all, deliberately, so the C2 profile can send beacons to arbitrary paths. The socket is therefore the only reliable split.

**Files:**
- Modify: `software/c2/server.py` — `create_app` (`:279`) gains the policy hook; `main()` (`:7495`-end) gains `--beacon-host`/`--beacon-port` and replaces `app.run()` with two `make_server` threads
- Modify: `software/c2/start_server.sh:21` (`HOST` default), and the usage line at `:43`
- Modify: `software/c2/docker-compose.yml:12-13`
- Modify: `tools/demo_env.py` — expose both sockets
- Modify: `docs/C2_DEMO.md`, `README.md:765` (the `RACCOON_HOST` default table row)
- Test: `software/tests/test_c2_hardening.py`

**Interfaces:**
- Consumes: `random_key()` from Task 5.
- Produces: `create_app(crypto, operator_token, data_dir, server_config=None, beacon_port=None)` — when `beacon_port` is `None` the hook is inert and the app behaves exactly as today. `DemoEnv` gains a `beacon_port` attribute; Task 7's storyboards use `DemoEnv`.

- [ ] **Step 1: Write the failing tests**

Class `TestSocketPolicy`. The third test is the Review Focus line and is the one that protects the other 2094:

```python
def test_beacon_socket_refuses_the_operator_page(self):
def test_beacon_socket_refuses_the_operator_api_even_with_a_valid_token(self):
def test_beacon_socket_serves_a_beacon_checkin(self):
def test_operator_socket_serves_the_page_and_the_api(self):
def test_operator_socket_still_serves_a_beacon_checkin(self):
    # Local beacons in the demo reach the operator socket; that stays.
def test_the_split_is_inert_when_no_beacon_port_is_configured(self):
    # app.test_client() does not go through a socket, so SERVER_PORT is
    # not meaningful. Assert a default-constructed app serves GET / --
    # otherwise this task breaks every existing test.
def test_refusal_on_the_beacon_socket_is_indistinguishable_from_the_cover(self):
    # Must reuse _fake_response(), not a 403 that fingerprints the C2.
def test_operator_socket_binds_loopback_by_default(self):
def test_beacon_socket_binds_the_configured_interface(self):
```

The socket tests need real sockets, not the test client. Use `make_server` on two ephemeral ports in `setUp` and `urllib` against them; pick the ports by binding `('127.0.0.1', 0)` and reading them back. **Do not hardcode a port** — the audit's own first measurement ran against a foreign process on a port assumed free and returned the opposite of the truth.

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest software.tests.test_c2_hardening.TestSocketPolicy -v`
Expected: the beacon-socket tests FAIL; `test_the_split_is_inert_...` PASSES already and must keep passing.

- [ ] **Step 3: Add the hook and the second listener**

A `before_request` in `create_app` that returns `_fake_response()` unless the request is either on the operator socket or handled by `beacon_handler`. Decide by comparing `request.environ.get("SERVER_PORT")` to `beacon_port`; when `beacon_port` is `None`, return nothing and let everything through. Put the reasoning in a comment: why the socket and not the path, and what `None` means.

`main()` builds the app once and starts two `make_server` threads, each `threaded=True`; the operator socket defaults to `127.0.0.1`, the beacon socket to `args.host`. The banner prints both, and says plainly that the GUI is loopback-only and names the SSH-tunnel command. Keep a single-socket mode: if `--beacon-port` equals `--port`, run one listener and leave the hook inert, so nothing that exists today breaks.

- [ ] **Step 4: Run the suite**

Run: `python3 -m unittest discover -s software/tests -t . -p "test_*.py"`
Expected: all green. Then a live check: start the C2 with the two sockets, confirm `GET /` on the beacon socket returns the cover response and that a beacon registers through it.

- [ ] **Step 5: Commit**

---

### Task 7: The operator token leaves the served HTML

The credential half of finding C1, plus the operator's choice (a). `GET /` currently substitutes the token into the page (`server.py:319`, landing at `:3031`). Adding `@require_auth` to `/` does not work — a browser navigation sends no `Authorization` header — so the token has to move, not the route.

**Files:**
- Modify: `software/c2/server.py:319-321` (`index`), `:3031` (`const TOKEN`), and the SPA's startup path
- Modify: `tools/storyboards/c2_tour.json`, `tools/storyboards/agent_run.json` — one leading step each
- Modify: `docs/C2_DEMO.md`, `docs/AGENT.md`, `README.md`
- Test: `software/tests/test_c2_hardening.py`, `software/tests/test_docs.py`

**Interfaces:**
- Consumes: `DemoEnv` from Tasks 5 and 6.
- Produces: the page reads and writes `sessionStorage` under the key `raccoon_token`; the storyboards set that key.

- [ ] **Step 1: Write the failing tests**

Class `TestTokenIsNotServed`, covering the Review Focus line:

```python
def test_get_root_does_not_contain_the_operator_token(self):
    # The regression test for the whole audit. Assert the token string
    # is absent from the body, not merely that {{TOKEN}} was replaced.
def test_get_root_still_serves_the_application(self):
def test_no_route_returns_the_token_without_authentication(self):
    # Walk every rule, call it unauthenticated, assert the token is in
    # no response body. This catches a future re-introduction anywhere.
def test_the_page_prompts_when_no_token_is_stored(self):
def test_a_wrong_token_is_reported_and_not_retained(self):
    # Source-level: assert the 401 path clears sessionStorage, so a bad
    # token does not survive a reload into a silent retry loop.
def test_the_token_is_never_placed_in_a_url(self):
    # Option (b) was rejected; assert no location/search/?t= handling
    # crept in.
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest software.tests.test_c2_hardening.TestTokenIsNotServed -v`
Expected: the first, third and sixth FAIL.

- [ ] **Step 3: Serve the page without the token and ask for it once**

`index()` serves `_OPERATOR_HTML` with the placeholder emptied. The SPA reads `sessionStorage.getItem("raccoon_token")`; absent, it shows a small prompt and stores what it is given. `H` becomes a function of the stored token rather than a constant built at load. On a 401, clear the stored token and prompt again. `api()` is the single place that builds the header, so this is one edit, not many — confirm that before spreading changes.

- [ ] **Step 4: One new leading storyboard step, then rebuild the figures**

Each storyboard gains a first step setting `sessionStorage` and reloading — every step is already a `js` expression, so this is one entry, not a rewrite. Rebuild both GIFs and the stills: `tools/capture_figures.sh tour`, `agent`, `stills`.

Two traps the ledger records: a finished campaign restores the beacon interval, so **restart the beacon**, not just the agent, before a second capture; and the status panel needs `agentInit()` then `agentOpenPanel()` because `agent.js` runs in an IIFE.

- [ ] **Step 5: Run the suite, including the documentation drift guard**

Run: `python3 -m unittest discover -s software/tests -t . -p "test_*.py"`
Expected: all green. `test_docs.py` is the gate for the README/`C2_DEMO.md` edits. Append new tests **above** the `__main__` guard — `cat >>` has put them below it eight times.

- [ ] **Step 6: Commit**

---

### Task 8: Secrets leave the command line

Finding H8, measured in `ps`: `--token SECRET-OPERATOR-TOKEN-xyz123`. Not one of the operator's six, added because it is small, it is a credential leak I reproduced, and `software/agent/config.py` already holds the project to a stricter bar for the LLM key than the C2 holds itself.

**Files:**
- Modify: `software/c2/server.py` (`main()` reads `RACCOON_TOKEN`/`RACCOON_KEY` from the environment as a fallback), `software/c2/docker-entrypoint.sh:45-47`, `software/c2/start_server.sh:306,313,321-323`, `software/c2/start_server.ps1:336,345,354-355`
- Test: `software/tests/test_c2_hardening.py`

**Interfaces:**
- Consumes: Task 5's key requirement — `--key` and `RACCOON_KEY` must agree on precedence.
- Produces: nothing.

- [ ] **Step 1: Write the failing tests**

```python
def test_token_can_be_supplied_by_environment(self):
def test_key_can_be_supplied_by_environment(self):
def test_no_launcher_passes_a_secret_as_an_argument(self):
    # Scan all three launchers and the entrypoint for --token/--key
    # followed by a variable.
def test_launchers_do_not_echo_a_full_key(self):
    # start_server.sh:276 already computes ENC_KEY_PREVIEW and never
    # uses it; :313 prints the whole key.
```

- [ ] **Step 2: Run them to verify they fail**

- [ ] **Step 3: Read from the environment and stop echoing**

The Docker entrypoint already *has* these in the environment and converts them to argv — a strict downgrade; delete the conversion. Print `ENC_KEY_PREVIEW`, the variable that already exists. Keep the token discoverable to the operator: write it to a `0600` file in the data directory and print the *path*.

- [ ] **Step 4: Run the suite**

- [ ] **Step 5: Commit**

---

### Task 9: The redirector — documented, not vendored — and the remaining findings recorded

The operator asked whether a redirector can sit in front of the team server, naming two projects. The answer and its reasoning belong in the repository, because a future reader will ask the same question.

**Assessment, to be written into the doc:**

- **lambda-redirector (MIT) is the wrong tool**, not a smaller version of the right one. It emits `301`/`302` with a `Location` header; its only parameters are `NewDomain` and `HTTPResponse ∈ {301, 302}`. A beacon POSTs an encrypted body; a redirect cannot carry it, and a `301` on `POST` drops the body or degrades to `GET`. It redirects browsers between domains, which is a different problem.
- **InfraGuard (BSD-2-Clause) is the right category and could legally be vendored** — unlike ARTEX, whose AGPL forced ideas-only. It is not vendored for three reasons: it is a product (Redis, Helm, Terraform rotation, 29 plugins, an Ollama integration) that would dwarf a Pi drop-box; its headline feature is malleable-profile conformance for seven C2 frameworks, and Raccoon's own profile format is not among them; and putting the block on `GET /` into an external proxy's rules would place a safety property in a user-editable config — the exact trade-off this project rejected in ARTEX's `guard`.
- **What a redirector genuinely buys** is address-hiding: a defender who catches a beacon learns the redirector's address, not the team server's. That requires a *second host*. On one Pi, a redirector to loopback hides nothing, which is why Task 6 is the change that carries the security property and the redirector is additive.
- After Task 6 a redirector becomes **safe to misconfigure**: point it at the beacon socket and it cannot reach the GUI even if its rules are wrong.

**Files:**
- Create: `docs/REDIRECTOR.md` — the assessment above, an nginx server block and a Caddyfile aimed at the beacon socket only, the SSH-tunnel command for the GUI, and InfraGuard named with its licence and a link
- Modify: `README.md` — one Highlights row and a link
- Modify: `docs/AGENT.md` *Known limits* — add what this plan did **not** fix
- Test: `software/tests/test_docs.py`

**Interfaces:**
- Consumes: Task 6's `--beacon-port`, whose name the config examples must match.

- [ ] **Step 1: Write the failing tests**

In `test_docs.py`:

```python
def test_redirector_doc_exists_and_is_linked_from_the_readme(self):
def test_redirector_config_names_the_beacon_port_flag(self):
    # Drift guard: the example must use the flag Task 6 actually added.
def test_redirector_config_does_not_proxy_the_operator_routes(self):
def test_known_limits_records_the_unfixed_audit_findings(self):
```

- [ ] **Step 2: Run them to verify they fail**

- [ ] **Step 3: Write the document and update *Known limits***

Record, as still open with the reason: the `on*` handler-body injections (loot and file names — need handlers attached in JS, a GUI refactor); no replay protection (H7); TLS verification off unconditionally and `verify_ssl` dead (H6); `shell=True` with request data on the RDP/VNC path (H5); the loot-download traversal (H4); the C2 container running as root with `NET_ADMIN` and the host X11 socket (H9); the unverified Sliver download (H10); `0o644` on `state.json` and `agent.db`; nothing pinned in either requirements file; `netifaces` and `ldap3` unmaintained; `vnc_password: "raccoon"`; no request-size cap; no rate limiting; `==` instead of `compare_digest`; the missing LICENSE file; and the six commits still readable via `refs/pull/2/head`.

- [ ] **Step 4: Run the suite**

Run: `python3 -m unittest discover -s software/tests -t . -p "test_*.py"`
Expected: all green.

- [ ] **Step 5: Commit**

---

## Self-Review

**Spec coverage.** The six accepted points map to Tasks 1 (C4), 5 (C2+C3), 7 (C1 credential), 3 (C5), 4 (C6), 2 (H1–H3). Task 6 carries the structural half of C1 and the operator's choice (c). Task 8 adds H8, flagged as beyond the six. Task 9 answers the redirector question and records the rest. The audit's remaining findings are deliberately **not** fixed here; Task 9 makes that explicit rather than silent.

**Type consistency.** `create_app` gains one keyword argument, `beacon_port`, defaulting to `None`, and `None` means inert — used identically in Tasks 6 and 7. `random_key()`/`key_b64()` are introduced in Task 5 and consumed in Tasks 6 and 7. The `sessionStorage` key is `raccoon_token` in Task 7's code, its tests, and both storyboards. `--beacon-port` is the flag name in Task 6 and in Task 9's config examples, with a drift test.

**Proportion.** Nine tasks over roughly the length of the findings document, with test names and assertions rather than bodies. The one empirical claim the architecture rests on — two listeners, distinct `SERVER_PORT` — was measured before planning, not assumed.

**Ordering risk.** Tasks 1–4 are independent and touch no shared fixture. Task 5 changes key provisioning in four test modules; Tasks 6 and 7 change how the GUI is reached, which the capture tooling depends on. Hence the whole-suite gate on 5, 6 and 7 rather than a per-module run.

**Residual risk I want a reviewer to look at.** Task 6 introduces a `before_request` that can deny service. Its failure mode when `beacon_port` is `None` must be *allow*, or 2094 tests and every existing deployment break at once. That is why `test_the_split_is_inert_when_no_beacon_port_is_configured` is written to pass before the change and asserted to keep passing after.
