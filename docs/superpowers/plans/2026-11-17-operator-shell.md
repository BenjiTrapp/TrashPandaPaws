# Operator shell on the hardware implant — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A terminal glyph in the team server's header opens a real pty on the operator's own hardware implant, dialled only on an explicit action and closed without relying on the browser.

**Architecture:** A new module `software/c2/opshell.py` holds the claim, the ownership record and the bridge to the shell port; `server.py` gains five routes that call into it plus the header glyph and the view. The channel is raised and dropped with the existing `tunnel start` / `tunnel stop` beacon tasks — no new transport, no change to `ShellFront` or the wire.

**Tech Stack:** Python 3 stdlib + Flask (already present), `xterm.js` vendored under `software/c2/static/`, no new Python dependency.

**Spec:** `docs/superpowers/specs/2026-11-17-operator-shell-design.md`

## Global Constraints

- **No new Python dependency.** `software/requirements.txt` and the image's pip block stay as they are.
- **The vendored terminal is pinned as a file**, with its version and SHA-256 recorded in `software/c2/static/VENDOR.md`. No package-manager entry: "nothing is pinned" is an open finding in `AGENT.md` and this must not add to it.
- **No response body belonging to these routes may contain `shell_password`.** The panel keeps showing it; that is out of scope.
- **No path in this feature may send `sleep`** or otherwise write an agent's interval.
- **Geometry is fixed at session open**, clamped to `1..SHELL_GEOMETRY_MAX` (1000), defaults `SHELL_DEFAULT_COLS`/`ROWS` = 120/40 (`beacon.py:1266`).
- **Stop is queued only for a channel this view owns, and only when the endpoint reports no live SOCKS session.**
- **The new routes must not be reachable on the agent socket.** `_AGENT_SOCKET_ENDPOINTS` (`server.py:837`) is an allow-list of two; confirm by test, do not assume.
- Tasks are queued with `lane="operator"` into `task_queues` in the shape `api_create_task` builds (`server.py:962`).

## Review Focus

Five conditions the spec implies that no task's own happy path exercises. Each has its test added to the task that owns the code.

1. **The agent disappears while a claim is held** (removed from `agents`, or never checks in again). The stop can then never be queued; the claim must be dropped, the ownership record cleared, and the view must say the channel's fate is unknown rather than reporting it closed. → Task 1.
2. **The shell port's session cap is reached** (4, `tunnel/shell.py:131`). The refusal must arrive as text on the stream the operator is watching, which is where `ShellFront` already puts it — not as an HTTP error before the stream exists. → Task 3.
3. **A second browser opens the view** with the same bearer token. Two claims exist and the refcount must not let the first `exit` queue a stop while the second session is live. → Task 1.
4. **The tunnel server dies while a session is live.** The stream must end with a named reason within one read timeout, not hang until the browser gives up. → Task 3.
5. **Absurd geometry** (`0x0`, `5000x9000`, non-numeric). It is clamped, and the strip states the geometry actually used, because the pty cannot be renegotiated. → Task 3.

---

### Task 1: The claim, the refcount and the ownership record

**Files:**
- Create: `software/c2/opshell.py`
- Test: `software/tests/test_operator_shell.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `class Claims` with `open(agent_id: str) -> str` (returns a session id), `close(agent_id: str, session_id: str) -> bool` (True when that was the last one), `beat(agent_id: str, session_id: str) -> None`, `lapsed(now: float) -> list[str]` (agent ids whose every session missed the grace), `sessions(agent_id: str) -> int`, `owned() -> list[str]`, `forget(agent_id: str) -> None`
  - `Claims(path: pathlib.Path, grace: float = 60.0)` — `path` is the ownership record's file
  - `reconcile(claims: Claims, agent_ids: Iterable[str]) -> list[str]` — owned agents with no live claim, for which a stop must be queued

- [ ] **Step 1: Write the failing tests**

```python
class TestTheClaimCounts(unittest.TestCase):
    def test_the_last_session_out_is_the_one_that_closes(self):
        c = opshell.Claims(self.path)
        a, b = c.open("raccoon-bandit"), c.open("raccoon-bandit")
        self.assertFalse(c.close("raccoon-bandit", a))
        self.assertTrue(c.close("raccoon-bandit", b))

    def test_a_second_browser_does_not_lose_the_first_ones_channel(self):
        # Review Focus 3. One bearer token, two views: the refcount is the
        # only thing standing between `exit` in one tab and a dead session
        # in the other.
        c = opshell.Claims(self.path)
        first, second = c.open("raccoon-bandit"), c.open("raccoon-bandit")
        c.close("raccoon-bandit", first)
        self.assertEqual(c.sessions("raccoon-bandit"), 1)

    def test_a_silent_browser_lapses_and_a_beating_one_does_not(self):
        c = opshell.Claims(self.path, grace=10.0)
        quiet, alive = c.open("quiet-one"), c.open("alive-one")
        c.beat("alive-one", alive)
        self.assertEqual(c.lapsed(now=time.time() + 11), ["quiet-one"])

    def test_ownership_survives_a_restart_and_reconciles(self):
        # The anti-goal: a restart between start and stop must not leave a
        # channel with nobody to close it.
        opshell.Claims(self.path).open("raccoon-bandit")
        fresh = opshell.Claims(self.path)          # a new process
        self.assertEqual(fresh.owned(), ["raccoon-bandit"])
        self.assertEqual(opshell.reconcile(fresh, ["raccoon-bandit"]),
                         ["raccoon-bandit"])

    def test_an_agent_that_vanished_is_forgotten_not_reported_closed(self):
        # Review Focus 1. No agent, no task, no honest claim of closure.
        c = opshell.Claims(self.path)
        c.open("gone-raccoon")
        self.assertEqual(opshell.reconcile(c, []), [])
        self.assertEqual(c.owned(), [])
```

- [ ] **Step 2: Run them and watch them fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_operator_shell -v`
Expected: FAIL with `AttributeError: module 'software.c2.opshell' has no attribute 'Claims'` (or `ModuleNotFoundError`).

- [ ] **Step 3: Implement `Claims` and `reconcile` in `software/c2/opshell.py`**

The ownership record is a JSON object `{agent_id: {"since": iso8601}}` written `0600` on every change — the file answers one question only, "whose channel does this view own", and the design's start-up rule needs nothing else. `reconcile` drops ownership for an agent that is no longer in the fleet rather than returning it, because a stop cannot be queued for an agent that has no queue.

- [ ] **Step 4: Run the tests and watch them pass**

Run: `/usr/bin/python3 -m unittest software.tests.test_operator_shell -v`
Expected: PASS — every test in the file green.

- [ ] **Step 5: Commit**

```bash
git add software/c2/opshell.py software/tests/test_operator_shell.py
git commit -m "feat(opshell): the claim, its refcount and the ownership record"
```

---

### Task 2: Raising and dropping the channel

**Files:**
- Modify: `software/c2/opshell.py`
- Test: `software/tests/test_operator_shell.py`

**Interfaces:**
- Consumes: `Claims` from Task 1.
- Produces:
  - `queue_tunnel(agent_id: str, action: str, task_queues: dict, history: dict, now: str) -> dict` — appends a task in `api_create_task`'s shape (`server.py:962`) with `cmd="tunnel"`, `args=action`, `lane="operator"`, and returns it
  - `may_stop(endpoint_row: dict | None, owned: bool) -> tuple[bool, str]` — the design's rule, with the reason when False
  - `expected_checkin(agent: dict, now: float) -> float | None` — seconds until the next check-in from `_last_seen_ts` and `interval`, `None` when the agent has never been seen

- [ ] **Step 1: Write the failing tests**

```python
class TestRaisingAndDroppingTheChannel(unittest.TestCase):
    def test_start_is_queued_as_an_operator_lane_tunnel_task(self):
        queues, hist = {}, {}
        task = opshell.queue_tunnel("raccoon-bandit", "start", queues, hist, "now")
        self.assertEqual((task["cmd"], task["args"], task["lane"]),
                         ("tunnel", "start", "operator"))
        self.assertEqual(queues["raccoon-bandit"], [task])

    def test_a_live_socks_session_forbids_the_stop(self):
        ok, why = opshell.may_stop({"socks": {"sessions": 1}}, owned=True)
        self.assertFalse(ok)
        self.assertIn("socks", why.lower())

    def test_a_channel_this_view_did_not_start_is_left_alone(self):
        ok, why = opshell.may_stop({"socks": {"sessions": 0}}, owned=False)
        self.assertFalse(ok)

    def test_an_owned_idle_channel_may_be_stopped(self):
        ok, _ = opshell.may_stop({"socks": {"sessions": 0}}, owned=True)
        self.assertTrue(ok)

    def test_the_expected_checkin_counts_down_from_the_last_one(self):
        agent = {"_last_seen_ts": 1000.0, "interval": 300}
        self.assertEqual(opshell.expected_checkin(agent, now=1100.0), 200.0)
        self.assertIsNone(opshell.expected_checkin({}, now=1100.0))
```

- [ ] **Step 2: Run them and watch them fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_operator_shell -v`
Expected: FAIL, `AttributeError: ... has no attribute 'queue_tunnel'`.

- [ ] **Step 3: Implement the three functions in `software/c2/opshell.py`**

`queue_tunnel` builds the task dict itself rather than calling the route, so a route and this module cannot drift in the task's shape; copy the key set from `server.py:962` verbatim. `expected_checkin` returns a value that may be negative — an overdue beacon is a fact the view shows, not an error to swallow.

- [ ] **Step 4: Run the tests and watch them pass**

Expected: PASS — every test in the file green.

- [ ] **Step 5: Commit**

```bash
git add software/c2/opshell.py software/tests/test_operator_shell.py
git commit -m "feat(opshell): queue the channel's start and stop, with the stop's rule"
```

---

### Task 3: The bridge to the shell port

**Files:**
- Modify: `software/c2/opshell.py`
- Test: `software/tests/test_operator_shell.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `class Bridge` with `Bridge(port: int, password: str, cols: int, rows: int, host: str = "127.0.0.1")`, `connect(timeout: float = 15.0) -> None`, `read(timeout: float) -> bytes` (`b""` on a clean end), `write(data: bytes) -> None`, `close() -> None`, and a read-only `geometry` property returning the clamped `(cols, rows)` actually sent
  - `auth_line(password: str, cols: int, rows: int) -> bytes` — the wire's first line

- [ ] **Step 1: Write the failing tests**

A fake shell port is a helper class in the test file: it listens on loopback, writes `b"password: "`, reads one line, and then behaves as the case needs. It exposes `.port` (the integer to hand `Bridge`) and `.first_line()` (the auth line it received).

```python
class TestTheBridge(unittest.TestCase):
    def test_the_auth_line_carries_the_password_then_the_geometry(self):
        self.assertEqual(opshell.auth_line("pw with space", 100, 30),
                         b"pw with space 100x30\n")

    def test_geometry_is_clamped_and_reported_as_sent(self):
        # Review Focus 5. The pty cannot be renegotiated, so what was sent
        # is the only truth the strip may state.
        b = opshell.Bridge(port=1, password="x", cols=0, rows=9000)
        self.assertEqual(b.geometry, (1, beacon.SHELL_GEOMETRY_MAX))

    def test_it_waits_for_the_prompt_before_sending(self):
        port = self._fake(prompt=b"password: ")
        b = opshell.Bridge(port.port, "secret", 80, 24); b.connect()
        self.assertEqual(port.first_line(), b"secret 80x24\n")

    def test_a_refusal_arrives_as_bytes_on_the_stream(self):
        # Review Focus 2. ShellFront writes its refusal onto the stream;
        # the bridge must pass it through, not turn it into an exception.
        port = self._fake(prompt=b"password: ", then=b"too many sessions\n")
        b = opshell.Bridge(port.port, "secret", 80, 24); b.connect()
        self.assertIn(b"too many sessions", b.read(timeout=2))

    def test_a_port_that_dies_ends_the_read_within_the_timeout(self):
        # Review Focus 4. A hang here is a view that lies about being live.
        port = self._fake(prompt=b"password: ", die_after_auth=True)
        b = opshell.Bridge(port.port, "secret", 80, 24); b.connect()
        self.assertEqual(b.read(timeout=2), b"")

    def test_a_port_that_never_prompts_raises_inside_the_timeout(self):
        port = self._fake(prompt=None)
        with self.assertRaises(OSError):
            opshell.Bridge(port.port, "secret", 80, 24).connect(timeout=1.0)
```

- [ ] **Step 2: Run them and watch them fail**

Expected: FAIL, `AttributeError: ... has no attribute 'auth_line'`.

- [ ] **Step 3: Implement `auth_line` and `Bridge` in `software/c2/opshell.py`**

`auth_line` appends `<cols>x<rows>` after a single space; `tunnel/shell.py:37` takes the geometry off only when the tail is entirely a geometry, so a password with spaces needs no quoting and must not be quoted here. Clamp with `beacon._shell_geometry`'s bounds — import `SHELL_DEFAULT_COLS`, `SHELL_DEFAULT_ROWS`, `SHELL_GEOMETRY_MAX` from `software.c2.beacon` rather than restating the numbers. `read` uses a socket timeout and returns `b""` on EOF.

- [ ] **Step 4: Run the tests and watch them pass**

Expected: PASS — every test in the file green.

- [ ] **Step 5: Commit**

```bash
git add software/c2/opshell.py software/tests/test_operator_shell.py
git commit -m "feat(opshell): the bridge from the operator socket to the shell port"
```

---

### Task 4: The routes

**Files:**
- Modify: `software/c2/server.py` (inside `create_app`, beside the other `/api/server/tunnel*` routes)
- Test: `software/tests/test_operator_shell.py`

**Interfaces:**
- Consumes: everything from Tasks 1–3; `tunnel_supervisor.status()`, `agents`, `task_queues`, `history` from `server.py`.
- Produces five routes, all `@require_auth`:
  - `GET /api/opshell/state` → `{"target": str|None, "candidates": [agent_id], "state": "idle"|"waiting"|"live"|"closing", "sessions": int, "host": str, "user": str, "root": bool, "recording": bool, "transcript_dir": str|None, "channel": "open"|"closed"|"unknown", "geometry": [cols, rows], "expected_checkin": float|None, "reason": str}`
  - `POST /api/opshell/open` → designates the target **and remembers the designation**, starts the tunnel server when it is configured but not running, queues `tunnel start` when no channel is up, takes a claim, returns the state
  - `POST /api/opshell/close` → releases the claim; queues `tunnel stop` when `may_stop` allows it; returns the state with `"closing"` or the reason
  - `GET /api/opshell/stream` → a chunked response pumping `Bridge.read`
  - `POST /api/opshell/keys` → `{"session": str, "data": str}` (base64) written to the bridge

- [ ] **Step 1: Write the failing tests**

```python
class TestTheRoutes(unittest.TestCase):
    def test_every_route_needs_the_operator_token(self):
        for path, method in self.ROUTES:
            self.assertEqual(self.unauth(path, method).status_code, 401)

    def test_no_route_answers_on_the_agent_socket(self):
        # Exercised, not compared: a frozenset of two is trivially true
        # today and would stay true if a route were added to it. This asks
        # the app, through the policy create_app installs.
        agent_client = self.agent_socket_client()
        for path, method in self.ROUTES:
            answer = agent_client.open(path, method=method,
                                       headers=self.auth)
            self.assertIn(answer.status_code, (403, 404), path)

    def test_no_response_body_carries_the_shell_password(self):
        # A Global Constraint. The panel may show it; these routes may not.
        body = self.get("/api/opshell/state").get_data(as_text=True)
        self.assertNotIn(self.shell_password, body)

    def test_a_missing_tunnel_server_is_a_named_reason_not_a_500(self):
        state = self.get("/api/opshell/state", supervisor=None).get_json()
        self.assertEqual(state["state"], "idle")
        self.assertTrue(state["reason"])

    def test_a_missing_shell_port_range_names_itself(self):
        state = self.get("/api/opshell/state",
                         supervisor=self.running_without_shell_ports()).get_json()
        self.assertIn("shell port", state["reason"].lower())

    def test_open_queues_one_tunnel_start_and_nothing_else(self):
        self.post("/api/opshell/open", {"agent": "raccoon-bandit"})
        queued = [(t["cmd"], t["args"]) for t in sm.task_queues["raccoon-bandit"]]
        self.assertEqual(queued, [("tunnel", "start")])

    def test_no_route_ever_queues_sleep(self):
        # A Global Constraint: this feature does not touch the interval.
        for path, payload in self.EVERY_WRITE:
            self.post(path, payload)
        every = [t["cmd"] for q in sm.task_queues.values() for t in q]
        self.assertNotIn("sleep", every)

    def test_close_reports_closing_and_never_closed(self):
        state = self.post("/api/opshell/close", {...}).get_json()
        self.assertEqual(state["state"], "closing")

    def test_open_starts_the_tunnel_server_when_it_is_configured_and_down(self):
        # The operator's second rule: the server runs on this host, so
        # starting it costs the implant nothing and the glyph stays one
        # click. The configuration file is not touched.
        sup = self.configured_but_stopped()
        self.post("/api/opshell/open", {"agent": "raccoon-bandit"}, supervisor=sup)
        self.assertEqual(sup.status()["state"], "running")

    def test_open_does_not_write_the_configuration_file(self):
        before = self.config_path.read_bytes()
        self.post("/api/opshell/open", {"agent": "raccoon-bandit"})
        self.assertEqual(self.config_path.read_bytes(), before)

    def test_the_designated_target_is_remembered_across_app_restarts(self):
        self.post("/api/opshell/open", {"agent": "raccoon-bandit"})
        fresh = sm.create_app(self.crypto, "tok", self.data_dir)
        self.assertEqual(self.get("/api/opshell/state", app=fresh)
                         .get_json()["target"], "raccoon-bandit")
```

- [ ] **Step 2: Run them and watch them fail**

Expected: FAIL with 404s from the test client — the routes do not exist.

- [ ] **Step 3: Implement the five routes in `create_app`**

Each reads the endpoint row with the helper the tunnel panel already uses, so one shape of "what the supervisor says" serves both. `/api/opshell/stream` returns a `Response(generator, mimetype="application/octet-stream")` with `direct_passthrough=True`; the generator yields `Bridge.read(timeout=…)` and ends on `b""`. The claim's heartbeat is the `state` call itself — the view polls it, so no separate beat route exists.

- [ ] **Step 4: Run the tests and watch them pass**

Expected: PASS — every test in the file green.

- [ ] **Step 5: Commit**

```bash
git add software/c2/server.py software/tests/test_operator_shell.py
git commit -m "feat(opshell): the five operator-socket routes"
```

---

### Task 5: Closing what nobody is watching

**Files:**
- Modify: `software/c2/server.py` (`create_app`), `software/c2/opshell.py`
- Test: `software/tests/test_operator_shell.py`

**Interfaces:**
- Consumes: `reconcile`, `Claims.lapsed` (Task 1), `queue_tunnel`, `may_stop` (Task 2).
- Produces:
  - `sweep(claims: Claims, agents: dict, endpoint_rows: dict, task_queues: dict, history: dict, now: float) -> list[str]` in `opshell.py` — queues `tunnel stop` for every lapsed claim the rule allows, returns the agent ids it queued for
  - a module-level `_reconcile_opshell_ownership(data_dir)` in `server.py`, called once from `create_app`

This is the task that keeps the anti-goal from happening, in both of its
forms: a browser that stops asking, and a team server that was restarted.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_browser_that_stops_asking_loses_the_channel(self):
    # Spec test #1, and the anti-goal: the stop is queued even though
    # nothing in the browser ever asked for it.
    claims = opshell.Claims(self.path, grace=10.0)
    claims.open("raccoon-bandit")
    queues = {}
    queued = opshell.sweep(claims, {"raccoon-bandit": {"caps": ["batch"]}},
                           {"raccoon-bandit": {"socks": {"sessions": 0}}},
                           queues, {}, now=time.time() + 11)
    self.assertEqual(queued, ["raccoon-bandit"])
    self.assertEqual([(t["cmd"], t["args"]) for t in queues["raccoon-bandit"]],
                     [("tunnel", "stop")])

def test_a_lapsed_claim_over_a_busy_pivot_is_left_standing(self):
    # The operator's rule wins over the sweep: a dropped browser must not
    # take a pivot down with it.
    claims = opshell.Claims(self.path, grace=10.0)
    claims.open("raccoon-bandit")
    queues = {}
    opshell.sweep(claims, {"raccoon-bandit": {}},
                  {"raccoon-bandit": {"socks": {"sessions": 2}}},
                  queues, {}, now=time.time() + 11)
    self.assertEqual(queues, {})

def test_a_restart_queues_the_stop_the_dead_process_owed(self):
    self.write_ownership({"raccoon-bandit": {"since": "2026-11-17T10:00:00Z"}})
    sm.agents["raccoon-bandit"] = {"id": "implant-1", "caps": ["batch"]}
    sm.create_app(self.crypto, "tok", self.data_dir)
    queued = [(t["cmd"], t["args"]) for t in sm.task_queues["raccoon-bandit"]]
    self.assertEqual(queued, [("tunnel", "stop")])
```

- [ ] **Step 2: Run them and watch them fail**

Expected: FAIL — `AttributeError: ... has no attribute 'sweep'`.

- [ ] **Step 3: Implement `sweep` and `_reconcile_opshell_ownership`**

`sweep` is called from `/api/opshell/state` — the view's own poll drives it,
and a view that is gone is exactly the case where some *other* operator's
poll, or the next one from any tab, performs the close. A thread would be
the alternative and is not worth one: this costs a dict walk.

Both log one line per queued stop through `_log_event`, because a stop the
operator did not ask for has to be findable afterwards.

- [ ] **Step 4: Run the tests and watch them pass**

Expected: PASS — every test in the file green.

- [ ] **Step 5: Commit**

```bash
git add software/c2/server.py software/c2/opshell.py \
        software/tests/test_operator_shell.py
git commit -m "feat(opshell): close a channel nobody is watching, after a lapse or a restart"
```

---

### Task 6: The vendored terminal

**Files:**
- Create: `software/c2/static/xterm.js`, `software/c2/static/xterm.css`, `software/c2/static/VENDOR.md`
- Test: `software/tests/test_operator_shell.py`

**Interfaces:**
- Produces: the two static files, served by the existing `/static/<path:filename>` route (`server.py:902`).

- [ ] **Step 1: Write the failing test**

```python
class TestTheVendoredTerminal(unittest.TestCase):
    # `_parse_vendor_md` is a few lines in this test file: it reads the
    # table and returns {filename: {"version": ..., "sha256": ...}}.

    def test_vendor_md_records_a_version_and_a_sha256_for_every_file(self):
        recorded = self._parse_vendor_md()
        self.assertEqual(set(recorded), {"xterm.js", "xterm.css"})
        for name, entry in recorded.items():
            self.assertRegex(entry["version"], r"^\d+\.\d+\.\d+$", name)

    def test_each_file_matches_its_recorded_hash(self):
        # The pin. "Nothing is pinned" is an open finding in AGENT.md; a
        # vendored file with no recorded hash would be a new instance of it.
        for name, entry in self._parse_vendor_md().items():
            digest = hashlib.sha256((STATIC / name).read_bytes()).hexdigest()
            self.assertEqual(digest, entry["sha256"], name)
```

- [ ] **Step 2: Run them and watch them fail**

Expected: FAIL — `FileNotFoundError` for `VENDOR.md`.

- [ ] **Step 3: Add the files**

Fetch one `xterm.js` release's browser bundle and its CSS, place them unmodified, and write `VENDOR.md` with, per file: name, version, SHA-256, upstream URL, licence, and the date fetched. Unmodified is the point: a local edit would make the hash a record of nothing.

- [ ] **Step 4: Run the tests and watch them pass**

Expected: PASS — every test in the file green.

- [ ] **Step 5: Commit**

```bash
git add software/c2/static/xterm.js software/c2/static/xterm.css \
        software/c2/static/VENDOR.md software/tests/test_operator_shell.py
git commit -m "feat(opshell): vendor xterm.js, pinned by hash in VENDOR.md"
```

---

### Task 7: The glyph and the view

**Files:**
- Modify: `software/c2/server.py` (the header at `server.py:4230`, and a new drawer beside `showListeners`, `server.py:7325`)
- Test: `software/tests/test_operator_shell.py`

**Interfaces:**
- Consumes: the five routes (Task 4), the vendored files (Task 6).
- Produces: `showOperatorShell()` in the inline JS and a `.topbar-ico-btn` in the header.

- [ ] **Step 1: Write the failing tests**

The GUI is inline in `server.py` and this repository already tests it by reading that source (`test_tunnel_gui.py`, and `TestTheTwoGuisDoNotShareHelpers` in `test_dns_rescue.py`, which carries its own small JS reader). Write the two parsers this task needs — "the header block" and "one named JS function's body" — in the test file, the same way.

```python
class TestTheViewDoesNotOverclaim(unittest.TestCase):
    def test_the_header_carries_a_terminal_glyph_that_opens_the_view(self):
        self.assertIn("showOperatorShell()", self.header_block())

    def test_the_view_dials_nothing_until_the_operator_asks(self):
        # The goal: nothing happens on open, on hover, or on page load.
        self.assertNotIn("/api/opshell/open",
                         self.js_function("showOperatorShell"))

    def test_the_word_closed_is_never_rendered_from_the_closing_state(self):
        # "Closing" and "closed" are different facts. The render function
        # must not reach the second from the first.
        render = self.js_function("opshellRender")
        self.assertIn('"closing"', render)
        for line in render.splitlines():
            if '"closing"' in line:
                self.assertNotIn("closed", line.lower())

    def test_the_strip_states_the_user_and_does_not_assume_root(self):
        self.assertIn("state.user", self.js_function("opshellRender"))

    def test_the_first_terminal_line_claims_only_what_the_code_does(self):
        self.assertIn("history is off in this session",
                      self.js_function("opshellRender"))

    def test_there_is_no_cancel_button_for_a_queued_task(self):
        # This server has no task withdrawal; a button that cannot do what
        # it says is worse than its absence.
        self.assertNotRegex(self.js_function("opshellRender"),
                            r"(?i)cancel|zur\u00fccknehmen")

    def test_the_view_states_the_geometry_it_actually_sent(self):
        # The pty cannot be renegotiated, so the number on screen is the
        # only honest one.
        self.assertIn("state.geometry", self.js_function("opshellRender"))
```

- [ ] **Step 2: Run them and watch them fail**

Expected: FAIL — `showOperatorShell` is not in the source.

- [ ] **Step 3: Implement the glyph and the view**

The glyph uses the existing `.topbar-ico-btn` pattern with a terminal character and a `title`, and calls `showOperatorShell()`. The state rendering lives in `opshellRender(state)` — the name the tests read. The view renders the four states from `/api/opshell/state`, polls it at the console's existing 2000 ms cadence (which is also the claim's heartbeat), opens the stream with `fetch` and a `ReadableStream` — `EventSource` cannot send the `Authorization` header the operator socket requires (`server.py:880`) and a token in a URL is forbidden by `test_docs.py:424` — and posts batched keystrokes to `/api/opshell/keys`.

- [ ] **Step 4: Run the tests and watch them pass**

Expected: PASS — every test in the file green.

- [ ] **Step 5: Run the whole suite**

Run: `/usr/bin/python3 -m unittest discover -s software/tests -t .`
Expected: OK. `test_docs.py` enforces documentation invariants and `test_c2_hardening.py` reads the Dockerfile; both must stay green.

- [ ] **Step 6: Commit**

```bash
git add software/c2/server.py software/tests/test_operator_shell.py
git commit -m "feat(opshell): the header glyph and the operator shell view"
```

---

### Task 8: Say it in the documentation

**Files:**
- Modify: `README.md`, `docs/AGENT.md`
- Test: `software/tests/test_docs.py`

**Interfaces:**
- Consumes: the finished feature.

- [ ] **Step 1: Run the documentation tests first**

Run: `/usr/bin/python3 -m unittest software.tests.test_docs -v`
Expected: PASS before the edit — so that a failure afterwards is the edit's doing and nothing else.

- [ ] **Step 2: Write the documentation**

`README.md`: the glyph, what it opens, that the build must carry a tunnel (`server.py:5480`), that the channel is raised on demand and dropped after the session, and that both cost one check-in. `docs/AGENT.md`: the three operator rules from the design, and the geometry limitation in plain words — the size is fixed when the session opens and cannot be renegotiated.

- [ ] **Step 3: Run the documentation tests again**

Expected: PASS. If a "Known limits" probe now reads differently, fix the probe to ask what the finding claims rather than deleting the finding — `_nothing_is_pinned` was defeated once by a continuation backslash and reported an open finding as fixed.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/AGENT.md
git commit -m "docs: the operator shell, and what it costs to open"
```
