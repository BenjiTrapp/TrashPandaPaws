# Linux end-to-end: a reproducible lab, and the three defects it found

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the project's Linux behaviour provable — a Docker lab where a beacon's legs fail because they do not route, a CI job that runs it and the suite, and fixes for the three Linux defects that writing the CI job uncovered.

**Architecture:** Three container networks put the beacon somewhere the team server is not, so HTTPS, SMB and QUIC fail by routing rather than by stub. A `dnsmasq` container sits in front of the DNS listener, so the hop the rescue channel rests on is exercised. A driver in `tools/` brings the lab up, runs one scenario, asserts against the resolver's own query log and the operator API, and tears down.

**Tech Stack:** Docker Compose, `dnsmasq`, `python:3.12-slim`, the project's existing `software/c2/listeners/Dockerfile`, stdlib `unittest`, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-15-e2e-docker-lab-design.md`

## Global Constraints

- The suite runs as `/usr/bin/python3 -m unittest discover -s software/tests -t .` (Python 3.9.6, ~7 minutes, 3258 tests on macOS). `pytest` is not installed.
- CI pins **Python 3.9** and installs **`git`, `ffmpeg`, `procps`**; without them the suite reports 19 errors and 6 failures that say nothing about the code.
- The beacon stays **stdlib-only**. `software/c2/listeners/` stays stdlib-only and must not import `server.py` or `beacon.py`.
- `software/c2/docker-compose.yml` is **not modified**. It describes a deployment.
- The lab publishes **no UDP port**. TCP for the operator socket is published and is how the driver and a browser reach it.
- Linux refuses any single `argv` entry over **131072** bytes (measured: 131072 passes, 131073 raises `OSError 7`).
- The rescue record stays **16 bytes**. No task widens the wire format.
- The stage carries no `$`, backtick, backslash or `"`. Any new one-liner form must keep that invariant true.
- Tasks 1 and 2 touch tunnel and implant code that `reverse-socks-tunnel` and `implant-shell-session` are working in. They come first, in their own commits, so they can be split out if a conflict demands it.

## Review Focus

1. **The stage grows past 131072 again.** Task 1 removes today's limit by moving the payload to stdin, but nothing bounds the one-liner's size, so a future form that reverts to `-c` would fail silently on Linux only. Task 1 adds a test that no generated artifact puts a payload in an `argv` entry.
2. **A toast storm.** The notification in Task 5 polls a list that is capped at 50 and never cleared, so a naive poll re-fires for every record on every tick. Task 5 adds a test that a record already seen raises no second notification.
3. **A rescue for a beacon the operator removed.** Attribution matches the live fleet, so a record for an agent that has since been deleted lands in the unattributed list. Task 3 adds a test that this is reported rather than dropped, and that nothing from the record is trusted as an agent id.
4. **Containers left behind by a crashed run.** A driver that reuses a stale container would report a pass that means nothing. Task 7 adds a test that the driver refuses to start when its project's containers already exist.
5. **`printf` is not a builtin.** Task 1's form relies on `printf` being internal to the shell; where it is an external binary the payload becomes an `argv` entry again and the limit returns. Task 1 adds a test asserting the one-liner uses only shell-internal mechanisms for the payload, and `docs/TUNNEL.md` states the requirement.

---

## File Structure

| File | Responsibility |
|---|---|
| `software/c2/server.py` | Modify: the one-liner's form (~1896); `_log_event` on the unattributed branch and the new route (~2951) |
| `software/c2/beacon.py` | Modify: `_NtlmProxyRelay.stop` (~2097) |
| `software/agent/c2client.py` | Modify: add `unattributed_rescues()` beside `list_agents()` (~270) |
| `software/agent/tools/egress.py` | Modify: `get_stuck_beacons` gains an `unattributed` key |
| `docs/TUNNEL.md` | Modify: the Linux argv limit, and that the payload travels on stdin |
| `software/tests/lab/docker-compose.yml` | Create: the five roles on three networks |
| `software/tests/lab/teamserver.Dockerfile` | Create: `python:3.12-slim` + flask, cryptography |
| `software/tests/lab/beacon.Dockerfile` | Create: `python:3.12-slim` + requests |
| `software/tests/lab/resolver.Dockerfile` | Create: `debian:stable-slim` + dnsmasq |
| `software/tests/lab/beacon_entry.py` | Create: builds the beacon config, runs the stuck loop, prints a verdict |
| `tools/e2e_lab.py` | Create: the driver — up, scenario, assert, down |
| `software/tests/test_e2e_lab.py` | Create: tests of the driver and the compose file that need no Docker |
| `software/tests/test_dns_rescue.py` | Modify: the unattributed surfaces |
| `software/tests/test_tunnel_spawn.py` | Modify: the one-liner's form |
| `software/tests/test_beacon.py` | Modify: the relay teardown |
| `.github/workflows/ci.yml` | Create: the `tests` and `lab` jobs |

---

### Task 1: The Unix one-liner stops putting its payload in argv

**Files:**
- Modify: `software/c2/server.py:1896` (`oneliner_unix`)
- Modify: `docs/TUNNEL.md:516` and `:586`
- Test: `software/tests/test_tunnel_spawn.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `oneliner_unix` is `printf %s "<stage>" | python3 -`. `oneliner_win` is unchanged. `render_stager("posix", oneliner=…)` already escapes single quotes for `eval '…'`, so no change there.

- [ ] **Step 1: Write the failing tests**

In `software/tests/test_tunnel_spawn.py`, in the class that owns the one-liner (`TestGeneratedArtifactKeepsItsSource`):

```python
def test_no_generated_artifact_puts_the_payload_in_an_argv_entry(self):
    # Review Focus 1. Linux refuses any single argv entry over 131072
    # bytes, so a payload passed as `python3 -c "<stage>"` cannot be
    # executed there at all -- not by any quoting, and not through the
    # POSIX stager, which `eval`s the same text and then has to exec
    # python with it. macOS has no such limit, which is why this was
    # invisible here.
    MAX_ARG_STRLEN = 131072
    body = self.generate(1)
    one = body["oneliner_unix"]
    self.assertGreater(len(one), MAX_ARG_STRLEN,
                       "the stage shrank; this test no longer proves anything")
    self.assertNotIn("python3 -c", one)
    self.assertIn("| python3 -", one)

def test_the_payload_travels_on_stdin_through_a_shell_builtin(self):
    # Review Focus 5. `printf` is internal to dash, bash and busybox ash,
    # so nothing execs the payload. An external printf would put it back
    # in an argv entry and restore the limit.
    one = self.generate(1)["oneliner_unix"]
    self.assertTrue(one.startswith("printf %s \""), one[:40])

def test_the_quoting_invariant_still_holds(self):
    # The one-liner gains a pipe and keeps its double quotes; what must
    # stay absent is what would make the double-quoted form unsafe.
    # `printf %s` puts the format in its own argument, so a `%` inside
    # the stage is data and not a directive.
    one = self.generate(1)["oneliner_unix"]
    for forbidden in ("$", "`", "\\"):
        self.assertNotIn(forbidden, one)
```

Keep the existing `test_a_real_shell_hands_the_stage_over_as_one_argument`, renaming it to `test_a_real_shell_delivers_the_stage_to_python` and changing its `subprocess.run` to execute the one-liner as a **script** (`["sh", scriptpath]` with the one-liner as the file's only line), not as `sh -c <command>` — passing it to `-c` makes the whole line one argv entry and reintroduces the limit the artifact no longer has.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_tunnel_spawn -v`
Expected: the three new tests FAIL (`"python3 -c" unexpectedly found`), the renamed one FAILs on macOS only if the script form is wrong.

- [ ] **Step 3: Change the one-liner's form in `software/c2/server.py`**

`oneliner_unix = f'printf %s "{stage}" | python3 -'`. Leave `oneliner_win` as `f'python -c "{stage}"'`: it is already documented as undeliverable at this size and is used through `Invoke-Expression`, where no length limit applies. The comment above it must say why the two now differ.

- [ ] **Step 4: Run the tunnel tests**

Run: `/usr/bin/python3 -m unittest software.tests.test_tunnel_spawn software.tests.test_tunnel_stager software.tests.test_docs -v`
Expected: PASS. `test_docs` is in the list because this task edits `docs/TUNNEL.md` and that module asserts over the documentation.

- [ ] **Step 5: Update `docs/TUNNEL.md`**

At `:516` the Windows paragraph stays. Add the Linux one beside it: the kernel refuses an `argv` entry over 131072 bytes, the generated stage exceeds it, so the payload travels on stdin through a shell builtin and the artifact is still one line. At `:586` correct "it runs the ordinary one-liner, which is the common case on Linux and macOS" — the sentence is right again once the form changes, but it must name the reason the form is what it is.

- [ ] **Step 6: Commit**

```bash
git add software/c2/server.py docs/TUNNEL.md software/tests/test_tunnel_spawn.py
git commit -m "fix(stager): the Unix one-liner could not run on Linux at all"
```

---

### Task 2: `stop()` wakes a blocked `accept()`

**Files:**
- Modify: `software/c2/beacon.py:2097` (`_NtlmProxyRelay.stop`)
- Test: `software/tests/test_beacon.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `stop()` calls `shutdown(socket.SHUT_RDWR)` before `close()`. `_accept_loop`'s existing `except OSError: break` arm catches the result and needs no change.

- [ ] **Step 1: Write the failing test**

The two existing tests (`TestNtlmRelayTunnel.test_stop_closes_listener`, `TestBeaconNtlmWiring.test_stop_tears_down_relay`) fail on Linux and pass on macOS, so they cannot drive a red cycle on the developer's machine. Add one that can, in `TestNtlmRelayTunnel`:

```python
def test_stop_shuts_the_listener_down_before_closing_it(self):
    # Closing a descriptor another thread is blocked in accept() on is
    # undefined in POSIX: macOS wakes the accept, Linux leaves the socket
    # bound and ACCEPTING until it returns. So on Linux the operator
    # stops the relay and the target keeps an open port. shutdown()
    # wakes a blocked accept on both platforms; close() alone does not.
    #
    # A recording proxy on `relay._server`, not a monkeypatch on the
    # socket: socket objects use __slots__ and reject attribute
    # assignment (measured), and this way the test pins the ORDER, which
    # is the whole property -- shutdown after close would fix nothing.
    class _Recorder:
        def __init__(self, inner):
            self._inner, self.calls = inner, []

        def shutdown(self, how):
            self.calls.append("shutdown")
            return self._inner.shutdown(how)

        def close(self):
            self.calls.append("close")
            return self._inner.close()

        def __getattr__(self, name):
            return getattr(self._inner, name)

    relay = self._setup()
    recorder = _Recorder(relay._server)
    relay._server = recorder
    relay.stop()
    self.relay = None
    self.assertEqual(recorder.calls, ["shutdown", "close"])
```

- [ ] **Step 2: Run it to verify it fails**

Run: `/usr/bin/python3 -m unittest software.tests.test_beacon.TestNtlmRelayTunnel.test_stop_shuts_the_listener_down_before_closing_it -v`
Expected: FAIL — `[] != ['shutdown', 'close']`.

- [ ] **Step 3: Add the shutdown to `stop()` in `software/c2/beacon.py`**

Before `self._server.close()`, call `self._server.shutdown(socket.SHUT_RDWR)` in its own `try/except Exception: pass` — a socket that is already gone must not turn a teardown into an exception. The comment must say which platform needed it and why.

- [ ] **Step 4: Run the beacon tests**

Run: `/usr/bin/python3 -m unittest software.tests.test_beacon -v`
Expected: PASS on macOS. The two pre-existing tests are verified on Linux by Task 9's job; the Docker suite run is the interim check.

- [ ] **Step 5: Verify on Linux**

Run: `docker run --rm -v "$PWD:/repo:ro" python:3.9-slim sh -c 'apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends git ffmpeg procps >/dev/null && cp -a /repo /work && cd /work && pip install -q -r software/tests/requirements.txt && python3 -m unittest software.tests.test_beacon 2>&1 | tail -20'`
Expected: PASS, including `test_stop_closes_listener` and `test_stop_tears_down_relay`, which fail there today.

- [ ] **Step 6: Commit**

```bash
git add software/c2/beacon.py software/tests/test_beacon.py
git commit -m "fix(relay): stop() left the port accepting on Linux"
```

---

### Task 3: An unattributed rescue is logged and served

**Files:**
- Modify: `software/c2/server.py` — the unattributed branch (~2951) and a new route beside the other `/api/` routes
- Test: `software/tests/test_dns_rescue.py`

**Interfaces:**
- Consumes: `unattributed_rescues` (module-level list), `_RESCUE_UNATTRIBUTED_MAX = 50`, `_log_event(category, message, agent_id="", details=None)`.
- Produces: `GET /api/rescues/unattributed` → `{"unattributed": [<record>, …]}`, `@require_auth`, newest first. Each record is the same dict `_handle_rescue` builds: `summary`, `dns_answered`, `fingerprint`, `at`, and the four leg keys.

- [ ] **Step 1: Write the failing tests**

In `software/tests/test_dns_rescue.py`, a new class `TestARescueNobodyCanClaim`:

```python
def test_an_unattributed_rescue_is_logged_so_it_is_not_silent(self):
    # It used to be appended to a list nothing read: decoded, stored and
    # discarded. The beacon that cannot be attributed is the one most
    # likely to be stuck, because never registering means the way out was
    # never open.

def test_the_route_returns_it_newest_first(self):

def test_the_route_needs_the_operator_token(self):

def test_the_route_is_not_on_the_agent_socket(self):
    # Same policy as every other /api/ route.

def test_a_rescue_for_a_deleted_agent_is_reported_not_dropped(self):
    # Review Focus 3. Attribution matches the live fleet, so a record for
    # an agent the operator has removed lands here.

def test_nothing_in_the_record_is_treated_as_an_agent_id(self):
    # Review Focus 3. The record carries a 2-byte fingerprint and leg
    # codes. No string from the target can reach it, and the route must
    # not invent an id from the fingerprint.

def test_the_list_stays_capped(self):
    # Review Focus 2's other half: 51 records leave 50.
```

Build each record by the real path — encrypt with the beacon's `_encrypt` and POST to `/`, as `TestTheServerDecodesARescue` already does — not by appending to the list directly.

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_dns_rescue.TestARescueNobodyCanClaim -v`
Expected: FAIL — 404 from the route, and no log entry.

- [ ] **Step 3: Implement both in `software/c2/server.py`**

In `_handle_rescue`'s unattributed branch, call `_log_event("RESCUE", …)` with the summary before the append. Safe to log in full: the record holds no string from the target. Add the route next to `api_agents`, decorated `@require_auth`, returning the list reversed.

- [ ] **Step 4: Run the rescue and hardening tests**

Run: `/usr/bin/python3 -m unittest software.tests.test_dns_rescue software.tests.test_c2_hardening -v`
Expected: PASS. `test_c2_hardening` owns the socket-policy assertions and will fail if the route is reachable on the agent socket.

- [ ] **Step 5: Commit**

```bash
git add software/c2/server.py software/tests/test_dns_rescue.py
git commit -m "feat(rescue): a rescue nobody can claim is no longer silent"
```

---

### Task 4: The agent tool reports them, separately

**Files:**
- Modify: `software/agent/c2client.py` (beside `list_agents`, ~270)
- Modify: `software/agent/tools/egress.py` (`get_stuck_beacons`)
- Test: `software/tests/test_dns_rescue.py`

**Interfaces:**
- Consumes: Task 3's route; `self._request("GET", path)` from `c2client`.
- Produces: `async def unattributed_rescues(self) -> List[dict]` on the client. `get_stuck_beacons()` returns `{"stuck": [...], "unattributed": [...]}`.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_tool_reports_unattributed_rescues_under_their_own_key(self):
    # Separate from "stuck" on purpose: there is no beacon id to task, so
    # a model must not be able to mistake one for something it can act on.

def test_an_unattributed_entry_carries_no_beacon_id_field(self):

def test_the_tool_still_works_when_the_c2_has_no_such_route(self):
    # An older team server answers 404. The tool degrades to {"stuck": …}
    # rather than failing the whole call.

def test_the_tool_description_says_they_cannot_be_tasked(self):
```

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_dns_rescue -v -k unattributed`
Expected: FAIL — `KeyError: 'unattributed'`.

- [ ] **Step 3: Implement the client method and extend the tool**

`unattributed_rescues()` mirrors `list_agents()`'s shape checking and uses `allow_missing=True` so a 404 returns `None`; `get_stuck_beacons` treats `None` as an empty list. Extend the tool's `description` in its spec to state that these entries have no id and cannot be tasked.

- [ ] **Step 4: Run the agent tool tests**

Run: `/usr/bin/python3 -m unittest software.tests.test_dns_rescue software.tests.test_agent_tools -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/agent/c2client.py software/agent/tools/egress.py software/tests/test_dns_rescue.py
git commit -m "feat(rescue): the agent sees the rescues it cannot act on"
```

---

### Task 5: The operator is notified, and the browser says so

**Files:**
- Modify: `software/c2/server.py` (`_OPERATOR_HTML`)
- Test: `software/tests/test_dns_rescue.py`

**Interfaces:**
- Consumes: Task 3's route; the page's existing `toast(type, title, msg, duration)` and `api(path)`.
- Produces: a poll that raises one `toast("warning", …)` per record it has not seen.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_record_already_seen_raises_no_second_notification(self):
    # Review Focus 2. The list is capped at 50 and never cleared, so a
    # naive poll re-fires for every record on every tick. Asserted at
    # source level: the poll must key on something per-record, not on the
    # list's length.

def test_the_notification_escapes_with_a_helper_that_exists(self):
    # The rule this feature's worst defect earned: escHtml(...) was my
    # own invented spelling, the operator console calls its escaper esc,
    # and the whole agent panel threw and rendered nothing.
```

The second test reuses `_operator_script()` and the definedness check already in this module. `TestTheTwoGuisDoNotShareHelpers` covers the cross-GUI class automatically.

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_dns_rescue -v -k notification`
Expected: FAIL.

- [ ] **Step 3: Add the poll and the toast to `_OPERATOR_HTML`**

Alongside the existing `setInterval(refreshAgents, 3000)`. Key seen records on `fingerprint + at`, which is unique per record and present in every one. Escape with `esc`.

- [ ] **Step 4: Verify in a browser, not in a regex**

This step is the task's acceptance. Start a server with an unattributed record present, open the operator console, unlock it, and confirm: the toast appears, the bell count rises, the notification panel lists it, and **the console reports no errors**. A source-level assertion that a string is present is what shipped the last defect; a screenshot is the evidence here.

- [ ] **Step 5: Run the full suite**

Run: `/usr/bin/python3 -m unittest discover -s software/tests -t .`
Expected: OK.

- [ ] **Step 6: Commit**

```bash
git add software/c2/server.py software/tests/test_dns_rescue.py
git commit -m "feat(rescue): the operator is told when something unknown is stuck"
```

---

### Task 6: The lab's images and compose

**Files:**
- Create: `software/tests/lab/docker-compose.yml`, `teamserver.Dockerfile`, `beacon.Dockerfile`, `resolver.Dockerfile`, `beacon_entry.py`
- Create: `software/tests/test_e2e_lab.py`

**Interfaces:**
- Consumes: `software/c2/listeners/Dockerfile` as it ships, unmodified.
- Produces: compose project `raccoon-lab`; services `teamserver`, `resolver`, `listener-dns`, `listener-smb`, `beacon`; networks `beacon-net` (declared subnet, static IP for `resolver` and `listener-dns`), `relay-net`, `c2-net`. The operator port is published on TCP; **no UDP port is published**. `beacon_entry.py` takes `--scenario`, `--zone`, `--cycles`, and the key and ports from the environment.

- [ ] **Step 1: Write the failing tests**

`software/tests/test_e2e_lab.py` — these need no Docker and run in the normal suite:

```python
def test_the_lab_publishes_no_udp_port(self):
    # Measured: published UDP does not arrive on macOS. The beacon is a
    # container so the datagram never crosses the host boundary; a
    # published UDP port would mean someone had moved it back.

def test_the_beacon_is_not_on_the_relay_network(self):
    # The listener is the one thing that bridges. A beacon on relay-net
    # could reach the team server and the severance would be a fiction.

def test_the_dns_listener_is_on_both_the_beacon_and_relay_networks(self):

def test_the_resolver_forwards_the_zone_to_the_listener_by_ip(self):
    # dnsmasq's server=/zone/addr#port takes an IP, not a hostname: it
    # parses its config before it could resolve anything.

def test_the_labs_listener_command_matches_the_shipped_compose(self):
    # Risk from the spec: a lab that drifts proves a shape nobody
    # deploys. Compares the lab's listener flags against
    # software/c2/docker-compose.yml's.

def test_the_lab_uses_the_shipped_listener_dockerfile(self):

def test_dnsmasq_keeps_its_cache(self):
    # The listener answers with TTL 1 and a cached rescue would be a
    # defect worth catching, so turning the cache off would hide it.
```

Parse the compose file with `yaml` — PyYAML 6.0.3 is installed and
`software/requirements.txt` already requires `pyyaml>=6.0`, so this adds no
dependency. Do not hand-roll a reader.

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_e2e_lab -v`
Expected: FAIL — the compose file does not exist.

- [ ] **Step 3: Write the compose file, the three Dockerfiles and the entry script**

The teamserver image installs `flask` and `cryptography` and nothing else — measured sufficient to import `software.c2.server`. The beacon image installs `requests`. Source arrives by read-only bind mount of the repository root, not `COPY`. The resolver's config sets `log-queries` and a `log-facility` on a path the driver reads, `no-resolv`, `no-hosts`, and keeps `cache-size` at its default.

- [ ] **Step 4: Run the tests**

Run: `/usr/bin/python3 -m unittest software.tests.test_e2e_lab -v`
Expected: PASS.

- [ ] **Step 5: Build the images once by hand**

Run: `docker compose -p raccoon-lab -f software/tests/lab/docker-compose.yml build`
Expected: all four images build. The shipped team-server image is **not** built.

- [ ] **Step 6: Commit**

```bash
git add software/tests/lab/ software/tests/test_e2e_lab.py
git commit -m "test(lab): the containers and networks for a Linux end-to-end run"
```

---

### Task 7: The driver, and the `rescue` scenario

**Files:**
- Create: `tools/e2e_lab.py`
- Modify: `software/tests/test_e2e_lab.py`

**Interfaces:**
- Consumes: Task 6's compose project.
- Produces: `build_parser() -> argparse.ArgumentParser` (the house convention `tools/demo_env.py` set, and what its test asserts against), `main(argv=None) -> int`. Scenario names positional; flags `--keep`, `--shipped-image`. Exit 0 pass, 1 fail, 2 no Docker.

- [ ] **Step 1: Write the failing tests**

```python
def test_it_exits_2_and_says_so_without_docker(self):
    # tools/listener_docker_rig.py's convention: never fail in a way that
    # looks like a product fault.

def test_it_refuses_to_start_when_the_projects_containers_exist(self):
    # Review Focus 4. A reused container would report a pass that means
    # nothing.

def test_the_parser_flags_mean_what_the_design_says(self):
    # As test_c2_hardening does for demo_env's parser.

def test_every_scenario_name_is_reachable_from_the_parser(self):

def test_it_reports_the_architecture_it_ran_on(self):
    # From the spec's risk table: aarch64 here, amd64 in CI. A report
    # that does not say which machine produced it cannot be acted on,
    # and this project has already been bitten twice by a platform
    # difference nobody recorded.
```

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_e2e_lab -v`
Expected: FAIL — `tools.e2e_lab` does not exist.

- [ ] **Step 3: Implement the driver and the `rescue` scenario**

The scenario, in order: bring the stack up with the beacon also attached to `c2-net`; wait for the beacon to register (poll the operator API for an agent, never a fixed sleep, and name the unmet condition on timeout); `docker network disconnect c2-net beacon`; assert the negative space from inside the beacon container — the team server's beacon socket, the SMB and the QUIC addresses must all be unreachable, and the run aborts saying the lab is mis-wired if any succeeds; run the stuck loop for four cycles; assert.

Assertions come from the components, never the driver's bookkeeping: the resolver's query log for exactly **one** rescue name across four cycles, with the whole name under 253 characters and no label over 63; the operator API for a `stuck` summary naming the right legs. Tear down in a `finally` with `down -v` unless `--keep`.

- [ ] **Step 4: Run the driver**

Run: `python3 tools/e2e_lab.py rescue`
Expected: exit 0, and the printed evidence shows one rescue and the operator's summary.

- [ ] **Step 5: Prove the scenario can fail**

Revert the trigger in `software/c2/beacon.py` from `delivered_by not in _RESCUE_UPSTREAM` to `tasking is None`, run `python3 tools/e2e_lab.py rescue`, and record the result in `.superpowers/sdd/2026-11-15-e2e-docker-lab/progress.md`. Restore the trigger. A scenario that passes either way proves nothing.

- [ ] **Step 6: Run the suite and commit**

Run: `/usr/bin/python3 -m unittest discover -s software/tests -t .`

```bash
git add tools/e2e_lab.py software/tests/test_e2e_lab.py
git commit -m "test(lab): a driver, and the rescue scenario through a real resolver"
```

---

### Task 8: The `stale-token` and `smb-up` scenarios

**Files:**
- Modify: `tools/e2e_lab.py`, `software/tests/lab/docker-compose.yml`, `software/tests/test_e2e_lab.py`

**Interfaces:**
- Consumes: Task 7's driver.
- Produces: scenarios `stale-token` and `smb-up`; a compose override or profile that gives `listener-dns` an invalid token and puts `listener-smb` on `beacon-net`.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_stale_token_listener_holds_a_token_the_server_rejects(self):
    # Tasking over DNS needs that token; the rescue does not, because it
    # goes through the beacon handler. So the ladder runs all the way down
    # and SMB and QUIC are really attempted -- which is the only way this
    # lab can prove the leg-recording fix on Linux.

def test_smb_up_keeps_the_dns_leg_armed(self):
    # Disabling DNS would make "no rescue was sent" vacuous: _maybe_rescue
    # returns immediately when DNS is off.
```

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_e2e_lab -v`
Expected: FAIL.

- [ ] **Step 3: Implement both scenarios**

`stale-token` asserts that SMB and QUIC are reported as attempted-and-failed and **not** as `not_attempted`. On Linux a dead QUIC endpoint raises nothing and merely times out, so this is where that fix is proved end to end. `smb-up` asserts tasking arrived over SMB and that **no** rescue was sent, because an upstream leg delivered while the latch was armed and could have fired.

- [ ] **Step 4: Run all three scenarios**

Run: `python3 tools/e2e_lab.py`
Expected: exit 0, three scenarios reported.

- [ ] **Step 5: Prove `stale-token` can fail**

Revert Task 2's sibling — the leg recording in `_quic_send`'s quiet paths, from commit `3dad39e` — run `python3 tools/e2e_lab.py stale-token`, record the result in the ledger, restore. `smb-up` is **exempt**: it guards a property of the lab, not a product change, so there is nothing to revert.

- [ ] **Step 6: Commit**

```bash
git add tools/e2e_lab.py software/tests/lab/ software/tests/test_e2e_lab.py
git commit -m "test(lab): the scenario the VM died before reaching"
```

---

### Task 9: CI

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: `software/tests/test_docs.py` if it asserts over the repository's file set

**Interfaces:**
- Consumes: Tasks 1–8.
- Produces: two jobs on `ubuntu-latest` — `tests` (Python 3.9, `git ffmpeg procps`, the full suite) and `lab` (`python3 tools/e2e_lab.py`).

- [ ] **Step 1: Write the failing test**

In `software/tests/test_e2e_lab.py`:

```python
def test_ci_installs_the_three_packages_the_suite_needs(self):
    # Measured: without git, ffmpeg and procps the suite reports 19
    # errors and 6 failures that say nothing about the code.

def test_ci_pins_the_python_the_suite_is_documented_for(self):
    # software/tests/requirements.txt says 3.9 and says the suite has
    # only ever run against it.

def test_ci_runs_both_the_suite_and_the_lab(self):

def test_ci_passes_no_secret_to_either_job(self):
    # The lab generates its key per run with os.urandom.
```

- [ ] **Step 2: Run it to verify it fails**

Run: `/usr/bin/python3 -m unittest software.tests.test_e2e_lab -v -k ci`
Expected: FAIL — the workflow does not exist.

- [ ] **Step 3: Write the workflow**

Two jobs, not one: they fail for different reasons and a reader should be able to tell which broke. No `secrets` in either. A comment at the top states what the three packages are for, so the next person does not remove them.

- [ ] **Step 4: Run the tests and the full suite**

Run: `/usr/bin/python3 -m unittest discover -s software/tests -t .`
Expected: OK.

- [ ] **Step 5: Verify the suite is green on Linux**

Run the Docker command from Task 2 Step 5, with `discover` instead of one module.
Expected: OK — and if anything still fails, it is a finding to record, not to hide.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/ci.yml software/tests/test_e2e_lab.py
git commit -m "ci: run the suite and the lab on Linux"
```
