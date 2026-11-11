# Implant Shell Session Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An operator attaches their own terminal to an authenticated loopback port on the team server and lands in a real root PTY on the implant host, carried as a new session type on the existing Noise tunnel.

**Architecture:** The tunnel already dials out from the implant and opens one connection per session. Two new message kinds turn that into a shell session: the server asks over the command channel, the endpoint dials back, claims with its token, and then raw PTY bytes flow inside the existing Noise framing. On the server a `ShellFront` — modelled on `SocksFront` — owns one stable loopback port per build identity, authenticates it, and pairs it with a session. Nothing new listens on the implant.

**Tech Stack:** Python 3.9, stdlib only on the implant side (`pty`, `fcntl`, `termios`, `subprocess`, `socket`, `threading`), Flask for the operator API and its embedded SPA, `unittest` for the suite.

**Spec:** [`docs/superpowers/specs/2026-11-10-implant-shell-session-design.md`](../specs/2026-11-10-implant-shell-session-design.md)

## Global Constraints

- **The implant side lives in `software/c2/beacon.py` only.** `api_beacon_gen` builds the delivered artifact by reading that one file. `software/c2/tunnel/protocol.py` re-exports names from it and must never define one.
- **No new dependency anywhere.** `software/requirements.txt` must not grow; the implant side is stdlib only.
- **Tests are `unittest`**, run by `software/.venv/bin/python`. Full suite: `software/.venv/bin/python -m unittest discover -s software/tests -t .`
- **An operator-facing port binds loopback only, from an IP literal**, and authenticates. Credentials are compared with `hmac.compare_digest` and without short-circuiting between absent and wrong.
- **Every refusal carries a reason and names the field.** A damaged state field is refused by name rather than guessed at.
- **Files 0600, directories 0700, state replaced atomically.**
- **No secret on a command line.** Paths go on the command line; tokens and passwords do not.
- **The PTY is POSIX-only.** A host without `pty` refuses the session in plain text on the stream.
- **Fixed values from the spec:** four concurrent shell sessions per endpoint on both ends; default geometry 120×40; `cwd=/`; `TERM=xterm-256color`.

## Review Focus

Five conditions the spec implies that no task's happy path exercises. Each one's test is added to the task that owns the code, named in brackets.

- **A live shell session when the stream dies** — tunnel server stopped, network gone, operator's terminal killed — must leave no `bash` running as root on the implant. An orphaned root shell is the worst artifact this feature can produce. [Task 2]
- **A password with a space in it, and a line with no geometry**, must both authenticate correctly: the geometry is parsed off the end of the same line, so a naive split reads part of the password as a size. [Task 5]
- **Absurd geometry** — `0x0`, `9999x9999`, negative or non-numeric — must be clamped or rejected before it reaches `ioctl`, not passed through. [Task 2 clamps, Task 5 validates]
- **Two operators attached to one identity at the same time** must get two independent PTYs with no bytes crossing between them. [Task 5]
- **A transcript directory that is unwritable, or a session that hits the ceiling**, must cost the recording and never the session. [Task 6]

---

## File Structure

| File | Responsibility |
|---|---|
| `software/c2/beacon.py` | Modify: two message kinds, `HELLO`'s `features`, and `TunnelEndpoint`'s PTY session |
| `software/c2/tunnel/protocol.py` | Modify: re-export the new names |
| `software/c2/tunnel/server.py` | Modify: shell sessions, kind-matched claims, the second port table |
| `software/c2/tunnel/shell.py` | Create: `ShellFront`, the operator-facing shell port, and its transcripts |
| `software/c2/tunnel/socks.py` | Modify: three helpers become public names so `shell.py` can import them |
| `software/c2/tunnel/__main__.py` | Modify: the shell port range, the transcript directory, `_Fronts` |
| `software/c2/server.py` | Modify: `tunnel_server_config`, the panel row, the Beacon Gen tunnel section |
| `configs/raccoon.yaml` | Modify: the new `c2.tunnel_server` keys, shipped off |
| `tools/raccoon_shell.py` | Create: the attach client |
| `software/tests/test_tunnel_shell.py` | Create: `ShellFront` and transcripts |
| `software/tests/test_raccoon_shell.py` | Create: the attach client |
| `software/tests/test_tunnel_protocol.py`, `test_tunnel_endpoint.py`, `test_tunnel_server.py`, `test_tunnel_config.py`, `test_tunnel_gui.py`, `test_docs.py` | Modify: the new behaviour in the module that already owns its area |
| `docs/TUNNEL.md`, `README.md` | Modify: the operator documentation |

---

### Task 1: The wire — two message kinds and `HELLO`'s feature list

**Files:**
- Modify: `software/c2/beacon.py` (the `MSG_*` block at 1227-1243, `TunnelEndpoint._hello` at ~3263)
- Modify: `software/c2/tunnel/protocol.py` (the docstring table, the import block, `__all__`)
- Test: `software/tests/test_tunnel_protocol.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `MSG_OPEN_SHELL = 7`, `MSG_SHELL = 8`, both in `MESSAGE_KIND_NAMES` as `"OPEN_SHELL"` and `"SHELL"`; `TUNNEL_FEATURES = ("shell",)`; `SHELL_DEFAULT_COLS = 120`, `SHELL_DEFAULT_ROWS = 40`, `SHELL_GEOMETRY_MAX = 1000`; `_hello()` returns a body whose `"features"` is `list(TUNNEL_FEATURES)`.

The three geometry values live here, with the codec, because both ends clamp against them: the endpoint before its `ioctl` and the front before it asks for a session. Two modules with the same literal is the same failure as two copies of the codec.

- [ ] **Step 1: Write the failing tests**

In `TestMessageCodec`:

```python
def test_the_two_shell_kinds_round_trip(self):
    for kind, body in ((MSG_OPEN_SHELL, {"port": 8446, "token": "ab" * 32,
                                         "cols": 120, "rows": 40}),
                       (MSG_SHELL, {"token": "ab" * 32})):
        self.assertEqual(decode_message(encode_message(kind, body)),
                         (kind, body))

def test_a_kind_outside_the_table_is_still_refused(self):
    with self.assertRaises(ValueError):
        encode_message(9, {})
    with self.assertRaises(ValueError):
        decode_message(b"\x09{}")

def test_the_names_of_the_two_shell_kinds(self):
    self.assertEqual(MESSAGE_KIND_NAMES[MSG_OPEN_SHELL], "OPEN_SHELL")
    self.assertEqual(MESSAGE_KIND_NAMES[MSG_SHELL], "SHELL")
```

In `TestTheReExport`, extend the existing identity check so the two new names are covered by it, and add:

```python
def test_hello_advertises_the_shell_feature(self):
    body = _an_endpoint()._hello()          # the module's existing helper
    self.assertEqual(body["features"], ["shell"])

def test_a_hello_without_features_still_decodes(self):
    kind, body = decode_message(encode_message(MSG_HELLO, {"identity": "x"}))
    self.assertEqual(kind, MSG_HELLO)
    self.assertNotIn("features", body)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_protocol -v`
Expected: FAIL — `MSG_OPEN_SHELL` is not defined.

- [ ] **Step 3: Add the constants and the feature list in `software/c2/beacon.py`**

`MSG_OPEN_SHELL = 7` and `MSG_SHELL = 8` beside the existing kinds, both entered in `MESSAGE_KIND_NAMES` so `MESSAGE_KINDS` and `_code_list` pick them up with no second list. `TUNNEL_FEATURES = ("shell",)` and the three `SHELL_*` geometry values near them, and `_hello()` adds `"features": list(TUNNEL_FEATURES)` to the body it already builds.

- [ ] **Step 4: Re-export them in `software/c2/tunnel/protocol.py`**

Add `MSG_OPEN_SHELL`, `MSG_SHELL`, `TUNNEL_FEATURES`, `SHELL_DEFAULT_COLS`, `SHELL_DEFAULT_ROWS` and `SHELL_GEOMETRY_MAX` to the import block and to `__all__`, and add the two rows to the docstring's wire table with the bodies from the spec.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_protocol -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add software/c2/beacon.py software/c2/tunnel/protocol.py software/tests/test_tunnel_protocol.py
git commit -m "feat(tunnel): the two shell message kinds, and a feature list in HELLO"
```

---

### Task 2: The implant — a PTY session on the endpoint

**Files:**
- Modify: `software/c2/beacon.py` (`TunnelEndpoint`, class at 3008; `_control_loop`'s dispatch at ~3355; the relay section after `_spawn_relay` at ~3425)
- Test: `software/tests/test_tunnel_endpoint.py`

**Interfaces:**
- Consumes: Task 1's `MSG_OPEN_SHELL`, `MSG_SHELL`, `TUNNEL_FEATURES`.
- Produces, on `TunnelEndpoint`:
  - `_spawn_shell(self, body: dict) -> None` — validates the body and starts `_shell` on a thread, with `_spawn_relay`'s `RuntimeError` arm and registration in `_relay_threads`.
  - `_shell(self, token: str, cols: int, rows: int) -> None` — dials `self.port`, registers the socket, handshakes with `encode_message(MSG_SHELL, {"token": token})`, serves, and tears down in a `finally` like `_relay`.
  - `_serve_shell(self, sock: socket.socket, noise: NoiseSession, cols: int, rows: int) -> None`
  - `_shell_bridge(self, sock: socket.socket, noise: NoiseSession, master: int) -> None`
  - Module constants `_SHELL_MAX_SESSIONS = 4` and `_SHELL_TERM_GRACE = 2.0`. The geometry bounds are Task 1's `SHELL_DEFAULT_COLS`, `SHELL_DEFAULT_ROWS` and `SHELL_GEOMETRY_MAX`; do not define a second set.

- [ ] **Step 1: Write the failing tests**

The module's existing pattern — an endpoint against a fake server socket — carries these. Names and assertions:

```python
def test_an_open_shell_dials_back_and_claims_with_its_token(self):
    # the second connection's first message is (MSG_SHELL, {"token": …})

def test_a_command_echoes_back_through_the_pty(self):
    # write b"echo hello_pty\n"; the stream carries b"hello_pty" within the deadline

def test_the_prompt_starts_in_the_root_directory(self):
    # write b"pwd\n"; the stream carries b"/"

def test_the_shell_is_reaped_when_the_stream_dies(self):     # Review Focus
    # close the server side; within _SHELL_TERM_GRACE + 1s the recorded child
    # pid is gone — os.kill(pid, 0) raises ProcessLookupError

def test_history_is_off_after_an_rc_file_that_sets_it(self):
    # HOME points at a tmpdir whose .bashrc sets HISTFILE; `echo $HISTFILE`
    # comes back empty, and the tmpdir holds no .bash_history afterwards

def test_the_generated_rcfile_leaves_nothing_on_disk(self):
    # no new file under the tmpdir or /tmp between before and after

def test_absurd_geometry_is_clamped_before_the_ioctl(self):  # Review Focus
    # cols=0, rows=99999 -> `stty size` reports values inside 1.._SHELL_GEOMETRY_MAX

def test_the_fifth_concurrent_session_is_refused_in_text(self):
    # the fifth stream carries a line mentioning "four" or the cap, then closes

def test_a_host_without_a_pty_refuses_in_text(self):
    # patch the lazy import to raise ImportError; the stream carries a readable
    # reason and no traceback

def test_an_open_shell_without_a_token_is_ignored(self):
    # no second connection is dialled

def test_bin_sh_is_used_when_bash_is_absent(self):
    # patch the executable probe; the spawned argv[0] is /bin/sh
```

Mark the PTY tests `@unittest.skipUnless(hasattr(os, "openpty"), …)`.

- [ ] **Step 2: Run them to verify they fail**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_endpoint -v`
Expected: FAIL — `TunnelEndpoint` has no `_spawn_shell`.

- [ ] **Step 3: Add the `MSG_OPEN_SHELL` arm to `_control_loop`**

One `elif` beside the `MSG_OPEN_RELAY` arm, calling `_spawn_shell(body)`. The arm must not fall through to the `else` that drops the channel.

- [ ] **Step 4: Implement `_spawn_shell` and `_shell`**

`_spawn_shell` reads `token` (a non-empty string or the message is logged and ignored, as `_spawn_relay` does), clamps `cols` and `rows` into `1.._SHELL_GEOMETRY_MAX` with the defaults for anything absent or non-integer, refuses past `_SHELL_MAX_SESSIONS` live sessions, and starts the thread. `_shell` mirrors `_relay` exactly, with `MSG_SHELL` in the handshake.

- [ ] **Step 5: Implement `_serve_shell` and `_shell_bridge`**

`_serve_shell` opens the PTY, spawns the shell with `start_new_session=True`, closes the slave in the parent, applies `TIOCSWINSZ`, then bridges. Two threads as in `_bridge`: one carrying `os.read(master, …)` to the stream, one carrying stream frames to `os.write(master, …)`; `EIO` on the master and an empty frame both end the session. Teardown sends `SIGHUP` to the process group, waits `_SHELL_TERM_GRACE`, sends `SIGKILL`, reaps, and closes the master — in a `finally`, so a thread that could not start takes the same path.

The shell is chosen and the environment built as the spec fixes it: `/bin/bash` when executable else `/bin/sh`; `TERM=xterm-256color`; `COLUMNS`/`LINES` from the message; `cwd="/"`. History is held off by an rcfile written to a pipe and passed as `--rcfile /dev/fd/<n>`, whose content is exactly:

```sh
[ -f /etc/bash.bashrc ] && . /etc/bash.bashrc
[ -f "$HOME/.bashrc" ] && . "$HOME/.bashrc"
unset HISTFILE
set +o history
```

Where `/dev/fd` is unavailable, or the shell is `/bin/sh`, fall back to `HISTFILE=/dev/null` in the environment and log that the weaker path was taken.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_endpoint -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add software/c2/beacon.py software/tests/test_tunnel_endpoint.py
git commit -m "feat(tunnel): a PTY session on the endpoint, dialled out like a relay"
```

---

### Task 3: The second port table

**Files:**
- Modify: `software/c2/tunnel/server.py` (`TunnelServer.__init__` at 400, `endpoints` at 524, `_assign_port` at 1041, `_load_state` at 1069, `_write_state` at 1110, `_STATE_VERSION` at 117)
- Test: `software/tests/test_tunnel_server.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `TunnelServer(…, shell_port_range: Optional[Tuple[int, int]] = None, …)` — keyword, after `port_range`; `self.shell_first_port` / `self.shell_last_port` are `None` when it is absent.
  - `_assign_shell_port(self, identity: str) -> Optional[int]` — called with the lock held; `None` when there is no range or none left, never an exception.
  - `endpoints()` rows gain `"shell_port": Optional[int]` and `"shell_detail": str` (empty when a port is assigned).
  - `_STATE_VERSION = 2`; the document gains `"shell_ports": {identity: port}`.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_shell_port_is_stable_across_a_restart(self)
def test_a_server_with_no_shell_range_assigns_none_and_says_why(self)
def test_an_exhausted_shell_range_leaves_registration_and_the_socks_port_intact(self)
def test_a_state_document_from_version_one_loads_with_an_empty_shell_table(self)
def test_a_shell_port_colliding_with_an_assigned_port_is_refused_by_field_name(self)
def test_a_damaged_shell_port_entry_is_refused_by_field_name(self)
```

The third asserts that `endpoints()` still reports the identity, its SOCKS port and `state == "connected"` while `shell_port` is `None` and `shell_detail` names the exhausted range. The fifth and sixth assert the `ValueError` message contains `shell_ports[` and the path.

- [ ] **Step 2: Run them to verify they fail**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_server -v`
Expected: FAIL — `TunnelServer` takes no `shell_port_range`.

- [ ] **Step 3: Implement the table**

`_assign_shell_port` beside `_assign_port`, sharing its "already assigned keeps its port" rule, and differing in one way the docstring must state: it returns `None` instead of raising, because a shell port must never cost an endpoint its registration or its pivot. `_load_state` validates `shell_ports` with the same per-field refusals and treats an absent key as `{}`; `_write_state` writes both tables.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_server -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add software/c2/tunnel/server.py software/tests/test_tunnel_server.py
git commit -m "feat(tunnel): a shell port table that cannot cost an endpoint its pivot"
```

---

### Task 4: Shell sessions on the tunnel server

**Files:**
- Modify: `software/c2/tunnel/server.py` (`RelaySession` at 278, `_CommandChannel` at 330, `open_session` at 614, `_dispatch` at 721, `_serve_command` at 751, `_serve_relay` at 923, `_claim` at 950, `status` at 592)
- Test: `software/tests/test_tunnel_server.py`

**Interfaces:**
- Consumes: Task 1's kinds; Task 3's `_assign_shell_port`.
- Produces:
  - `RelaySession(number, identity, token, kind: str = "relay")` with `.kind`.
  - `TunnelServer.open_shell_session(self, identity: str, cols: int = 120, rows: int = 40) -> RelaySession` — raises `ValueError` naming the reason when no endpoint is connected, when the endpoint advertised no `shell` feature, or when the channel send fails.
  - `_serve_claimed(self, conn, peer, noise, identity, body, kind: str) -> bool` — the shared claim-reply-pair body `_serve_relay` had.
  - `_claim(self, token: bytes, identity: str, peer: str, kind: str) -> Optional[RelaySession]`.
  - `_CommandChannel.features: Tuple[str, ...]`, read from the `HELLO` body, `()` when absent.
  - `endpoints()` rows gain `"features": List[str]`; `status()` rows gain `"kind"`.

- [ ] **Step 1: Write the failing tests**

```python
def test_open_shell_session_sends_open_shell_with_a_token_and_the_geometry(self)
def test_a_shell_claim_pairs_the_session_and_bytes_flow_both_ways(self)
def test_a_relay_token_cannot_claim_a_shell_session(self)
def test_a_shell_token_cannot_claim_a_relay(self)
def test_an_endpoint_that_advertised_no_shell_feature_is_refused(self)
def test_the_refusal_sends_nothing_on_the_command_channel(self)   # Review Focus
def test_a_hello_without_features_leaves_the_tuple_empty(self)
def test_the_status_row_names_the_kind(self)
```

`test_the_refusal_sends_nothing_on_the_command_channel` is the one that matters most: it asserts the channel carried no frame at all after the refusal, because the failure it prevents is an older endpoint dropping its command channel and taking its live SOCKS sessions with it.

- [ ] **Step 2: Run them to verify they fail**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_server -v`
Expected: FAIL — `TunnelServer` has no `open_shell_session`.

- [ ] **Step 3: Implement the session kind and the feature gate**

`kind` on `RelaySession`; `features` on `_CommandChannel` from the `HELLO` body; `open_shell_session` checking the feature *before* it mints a token or sends anything; `_dispatch` gaining the `MSG_SHELL` arm; `_serve_relay` and the new arm both calling `_serve_claimed`; `_claim` comparing kinds and logging a mismatch the way it already logs an identity mismatch.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_server -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add software/c2/tunnel/server.py software/tests/test_tunnel_server.py
git commit -m "feat(tunnel): shell sessions, kind-matched claims, and a feature gate"
```

---

### Task 5: `ShellFront`, the operator-facing shell port

**Files:**
- Create: `software/c2/tunnel/shell.py`
- Modify: `software/c2/tunnel/socks.py` (`_loopback`, `_credential`, `_positive` become `loopback_bind`, `credential`, `positive`, with their call sites updated and `__all__` extended)
- Test: `software/tests/test_tunnel_shell.py`

**Interfaces:**
- Consumes: Task 4's `open_shell_session(identity, cols, rows)` and `RelaySession.wait_paired(timeout)` / `.sock` / `.close()`; `RelayStream.sendall(bytes)` / `.recv(int)` / `.close()` / `.bytes_in` / `.bytes_out`.
- Produces:
  - `ShellFront(tunnel_server, identity: str, bind_port: int, password: str, *, max_sessions: int = 4, max_pending: Optional[int] = None, bind_host: str = "127.0.0.1", handshake_timeout: float = 15.0, backlog: int = 16, transcripts=None)` with `.start()`, `.stop()`, `.stats() -> dict`, `.port`, `.identity`.
  - `DEFAULT_MAX_SESSIONS = 4` and `PROMPT = b"password: "`. The geometry values are imported from `protocol` (Task 1), never redefined.
  - `parse_auth_line(line: str) -> Tuple[str, int, int]` — module-level and tested on its own.
  - `stats()` **conforms to `SocksFront.stats()` key for key**: the live count is `sessions`, `refused` is an integer total, and the detail is one `refused_<why>` key per kind over `auth`, `capacity`, `pending`, `tunnel`, `timeout`, `threads`, `unsupported`. The panel's reader is generic over the `refused_` prefix and already ships against the SOCKS row, so the new row conforms to it rather than the reverse. *(Ruled 2026-11-11, after the first draft of this plan said `live` and a nested dict.)*

- [ ] **Step 1: Write the failing tests**

`parse_auth_line` first, because the Review Focus item lives there:

```python
def test_a_bare_password_takes_the_default_geometry(self):
    self.assertEqual(parse_auth_line("s3cret"), ("s3cret", 120, 40))

def test_a_trailing_geometry_is_taken_off_the_end(self):
    self.assertEqual(parse_auth_line("s3cret 200x50"), ("s3cret", 200, 50))

def test_a_password_containing_a_space_survives(self):            # Review Focus
    self.assertEqual(parse_auth_line("two words"), ("two words", 120, 40))
    self.assertEqual(parse_auth_line("two words 200x50"),
                     ("two words", 200, 50))

def test_a_tail_that_is_not_a_geometry_stays_in_the_password(self):
    self.assertEqual(parse_auth_line("pw 200x"), ("pw 200x", 120, 40))

def test_geometry_outside_the_bounds_is_clamped(self):            # Review Focus
    self.assertEqual(parse_auth_line("pw 0x99999"), ("pw", 1, 1000))
```

Then the front, against a fake tunnel server in the shape `test_tunnel_socks.py` already uses:

```python
def test_a_non_loopback_bind_is_refused(self)
def test_the_prompt_is_written_before_anything_is_read(self)
def test_the_right_password_pairs_and_bytes_flow_both_ways(self)
def test_a_wrong_password_is_refused_and_counted_under_auth(self)
def test_an_empty_line_is_refused_and_counted_under_auth(self)
def test_a_client_that_never_sends_a_line_is_dropped_on_the_deadline(self)
def test_a_line_longer_than_the_bound_is_refused(self)
def test_the_geometry_reaches_open_shell_session(self)
def test_two_operators_on_one_identity_do_not_cross_streams(self)   # Review Focus
def test_beyond_max_sessions_the_client_is_refused_in_text(self)
def test_an_endpoint_without_the_feature_is_refused_in_text_and_counted(self)
def test_stop_drops_a_live_session(self)
def test_stats_counts_bytes_both_ways(self)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_shell -v`
Expected: FAIL — no module `software.c2.tunnel.shell`.

- [ ] **Step 3: Make the three `socks.py` helpers public**

Rename in place, update the call sites in `socks.py`, extend its `__all__`. No copies: `shell.py` imports them.

- [ ] **Step 4: Run the SOCKS suite to prove the rename broke nothing**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_socks -v`
Expected: PASS

- [ ] **Step 5: Implement `parse_auth_line`**

One `rsplit(" ", 1)`, and the tail is taken as geometry only when it fully matches `\d{1,5}x\d{1,5}`; otherwise the whole line is the password. Values clamp into `1..SHELL_GEOMETRY_MAX`.

- [ ] **Step 6: Implement `ShellFront`**

`SocksFront`'s lifecycle, caps, counters and `stop()` discipline, with its SOCKS greeting and request replaced by: write `PROMPT`, read one bounded line under an absolute deadline, authenticate, `open_shell_session`, `wait_paired`, then the two pumps. A refusal after the prompt is one line of text and a close, never a silent drop — the operator is looking at a terminal. `ValueError` from `open_shell_session` is counted as `unsupported` when it names the feature and `tunnel` otherwise, and its text goes to the client.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_shell -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add software/c2/tunnel/shell.py software/c2/tunnel/socks.py software/tests/test_tunnel_shell.py
git commit -m "feat(tunnel): ShellFront, one authenticated loopback shell port per identity"
```

---

### Task 6: Session transcripts, off unless switched on

**Files:**
- Modify: `software/c2/tunnel/shell.py`
- Test: `software/tests/test_tunnel_shell.py`

**Interfaces:**
- Consumes: Task 5's `ShellFront(…, transcripts=None)`.
- Produces:
  - `Transcripts(directory)` with `.open(identity: str, session: int, peer: str) -> Optional[Recorder]` and `.enabled: bool`.
  - `Recorder` with `.write(data: bytes) -> None`, `.close(reason: str) -> None`, `.truncated: bool`, `.path: str`.
  - `TRANSCRIPT_MAX_BYTES = 16 * 1024 * 1024`.
  - Files: `<directory>/<identity>/<UTC ISO-8601 basic>-<session>.typescript`, mode 0600, directories 0700, with a `.json` sibling carrying `identity`, `session`, `peer`, `started`, `ended`, `bytes`, `truncated`, `reason`.

- [ ] **Step 1: Write the failing tests**

```python
def test_no_directory_records_nothing(self)
def test_a_session_writes_a_typescript_and_a_sidecar(self)
def test_the_typescript_is_0600_in_a_0700_directory(self)
def test_the_attach_password_is_in_neither_file(self)
def test_only_the_output_direction_is_recorded(self)
def test_the_ceiling_stops_recording_and_records_that_it_did(self)   # Review Focus
def test_an_unwritable_directory_costs_the_recording_not_the_session(self)  # Review Focus
def test_the_sidecar_is_written_when_the_session_ends(self)
```

The password test writes a known password through the auth step and then greps both files for it. The unwritable test chmods the directory `0o500` and asserts the session still carries bytes both ways and `stats()` reports the session as carried.

- [ ] **Step 2: Run them to verify they fail**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_shell -v`
Expected: FAIL — `Transcripts` is not defined.

- [ ] **Step 3: Implement `Transcripts` and `Recorder`**

Recording is opened after pairing, so the auth line cannot reach it. Opening and closing one is a log event naming the file, as the spec requires. Every failure to open or write is logged once and sets the recorder aside; the session continues untouched. At the ceiling the recorder stops writing, sets `truncated`, and the sidecar says so.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_shell -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add software/c2/tunnel/shell.py software/tests/test_tunnel_shell.py
git commit -m "feat(tunnel): optional session transcripts, written after the password line"
```

---

### Task 7: Process wiring — arguments, fronts, config

**Files:**
- Modify: `software/c2/tunnel/__main__.py` (`_parser` at ~160, `_Fronts.reconcile` and `.decorate` at ~185-290, `_ControlHandler._status` at ~390)
- Modify: `software/c2/server.py` (`tunnel_server_config` in `software/c2/tunnel/supervisor.py`'s `_DEFAULTS` and validator; `_build_tunnel_supervisor` at 9119)
- Modify: `software/c2/tunnel/supervisor.py`
- Modify: `configs/raccoon.yaml`
- Test: `software/tests/test_tunnel_config.py`, `software/tests/test_tunnel_gui.py`

**Interfaces:**
- Consumes: Task 5's `ShellFront`, Task 6's `Transcripts`, Task 3's `shell_port_range`.
- Produces:
  - `--shell-port-first`, `--shell-port-last`, `--shell-transcript-dir`, all optional.
  - `tunnel_server_config(config)` output keys `shell_port_first`, `shell_port_last` (both `None` when absent) and `shell_transcript_dir` (`None` when absent).
  - `decorate(row)` adds `shell` (the front's `stats()` or `None`), `shell_password` (`Optional[str]`), `shell_detail` (`str`), `shell_recording` (`bool`).
  - `_status()` gains `shell_port_first`, `shell_port_last`, `shell_transcripts`.

- [ ] **Step 1: Write the failing tests**

In `test_tunnel_config.py`, beside the existing `tunnel_server_config` cases:

```python
def test_the_shell_range_is_read_and_passed_on(self)
def test_a_reversed_shell_range_is_refused_by_field_name(self)
def test_a_shell_range_overlapping_the_socks_range_is_refused_by_field_name(self)
def test_no_shell_keys_means_no_shell_range_and_no_transcripts(self)
def test_the_shipped_config_ships_both_keys_commented_out(self)
```

In `test_tunnel_gui.py`'s `TestTheTunnelProcess` / `TestTheSupervisor`:

```python
def test_a_configured_range_opens_a_shell_front_per_connected_identity(self)
def test_no_range_opens_no_shell_front_and_the_status_says_so(self)
def test_the_shell_password_is_not_the_socks_password(self)
def test_the_decorated_row_reports_recording_when_a_directory_is_configured(self)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_config software.tests.test_tunnel_gui -v`
Expected: FAIL — `tunnel_server_config` returns no `shell_port_first`.

- [ ] **Step 3: Add the arguments and the config fields**

The validator refuses by field name, as the SOCKS pair's does, for a non-integer, a reversed pair, a port outside 1-65535, and an overlap with the SOCKS range. `--shell-transcript-dir` is a path on the command line, which is allowed; nothing secret goes there.

- [ ] **Step 4: Open a `ShellFront` in `_Fronts.reconcile`**

Beside the `SocksFront`, only when the range is configured and the row has a `shell_port`, with a password minted by `secrets.token_urlsafe` separately from the SOCKS one. `decorate` reports the four new fields. **`shell_detail` belongs to Task 3's row**: `decorate` fills it only when it arrives empty, so a front that failed to bind can explain itself without overwriting "no range configured" or "the range is exhausted". The per-identity failure reason is recorded exactly as the SOCKS one is.

- [ ] **Step 5: Ship the config keys off in `configs/raccoon.yaml`**

Both keys commented out in the `c2.tunnel_server` block, with the one-line warning that the port is a root shell on the implant host.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_config software.tests.test_tunnel_gui -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add software/c2/tunnel/__main__.py software/c2/tunnel/supervisor.py software/c2/server.py configs/raccoon.yaml software/tests/test_tunnel_config.py software/tests/test_tunnel_gui.py
git commit -m "feat(tunnel): one switch for the shell port, and one for transcripts"
```

---

### Task 8: The attach client

**Files:**
- Create: `tools/raccoon_shell.py`
- Test: `software/tests/test_raccoon_shell.py`

**Interfaces:**
- Consumes: Task 5's wire — `PROMPT`, then one line `<password> <cols>x<rows>`, then raw bytes.
- Produces: `main(argv: List[str]) -> int`; usage `python3 tools/raccoon_shell.py <host> <port>`; the password comes from `RACCOON_SHELL_PASSWORD` or a `getpass` prompt; `geometry() -> Tuple[int, int]` from `shutil.get_terminal_size`.

- [ ] **Step 1: Write the failing tests**

```python
def test_it_sends_the_password_and_the_local_geometry(self)
def test_the_password_comes_from_the_environment_when_it_is_set(self)
def test_it_carries_bytes_both_ways(self)
def test_it_restores_the_terminal_when_the_stream_ends(self)
def test_a_refusal_line_is_shown_and_the_exit_code_is_nonzero(self)
```

Against a fake server on an ephemeral loopback port, with `sys.stdin` not a tty so the raw-mode path is skipped.

- [ ] **Step 2: Run them to verify they fail**

Run: `software/.venv/bin/python -m unittest software.tests.test_raccoon_shell -v`
Expected: FAIL — no module `tools.raccoon_shell`.

- [ ] **Step 3: Implement the client**

Stdlib only. `termios`/`tty` for raw mode guarded by `sys.stdin.isatty()` and restored in a `finally`; a `select` loop between the socket and stdin; on `SIGWINCH` it prints the `stty rows … cols …` line the spec names, because the size cannot be renegotiated.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `software/.venv/bin/python -m unittest software.tests.test_raccoon_shell -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tools/raccoon_shell.py software/tests/test_raccoon_shell.py
git commit -m "feat(tools): the shell attach client, with the local geometry"
```

---

### Task 9: The panel row

**Files:**
- Modify: `software/c2/server.py` (`_tunnel_row` at 780, `drawTunnel` at ~7206)
- Test: `software/tests/test_tunnel_gui.py`

**Interfaces:**
- Consumes: Task 7's `shell`, `shell_password`, `shell_detail`, `shell_recording` row fields.
- Produces: no new route. `_tunnel_row` passes the four fields through unchanged, and the existing `TestTheRowFixtureMatchesTheRealThing` fixture grows them.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_row_carries_the_shell_fields_through_unchanged(self)
def test_the_panel_shows_the_shell_port_and_its_password(self)
def test_the_panel_shows_the_ssh_forward_before_the_attach_command(self)
def test_the_panel_names_the_attach_client_and_the_socat_fallback(self)
def test_the_panel_says_the_session_is_a_root_shell_on_the_implant_host(self)
def test_a_row_without_a_shell_port_shows_the_reason(self)
def test_the_panel_shows_a_recording_badge_only_when_recording_is_on(self)
```

The panel tests read the served page as `TestTheTunnelPanel` already does.

- [ ] **Step 2: Run them to verify they fail**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_gui -v`
Expected: FAIL — the page says nothing about a shell port.

- [ ] **Step 3: Pass the fields through `_tunnel_row` and render them in `drawTunnel`**

Two copy-ready lines per row — the `ssh -L` forward first, then `python3 tools/raccoon_shell.py 127.0.0.1 <port>` — with `socat -,raw,echo=0,escape=0x1d TCP:127.0.0.1:<port>` named as the fallback, the sentence about a root shell and about forwarding it, and the recording badge.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_gui -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add software/c2/server.py software/tests/test_tunnel_gui.py
git commit -m "feat(c2): the tunnel panel shows the shell port, its password and how to attach"
```

---

### Task 10: The Beacon Gen form asks for a tunnel

**Files:**
- Modify: `software/c2/server.py` (the Beacon Gen form at ~5205-5250, `runBeaconGen` at ~5403, `runBeaconGist`, the result block at ~5436)
- Test: `software/tests/test_tunnel_config.py`, `software/tests/test_tunnel_gui.py`

**Interfaces:**
- Consumes: the route's existing contract — `api_beacon_gen` and `api_beacon_gist` accept `body["tunnel"]` with `enabled`, `server`, `port`, `keepalive_seconds`, `allow_slow_crypto`, validated in `_tunnel_config_for_build`, and both return `tunnel_identity`.
- Produces: no server-side change. Form ids `bg-tunnel`, `bg-tunnel-server`, `bg-tunnel-port`, `bg-tunnel-keepalive`, `bg-tunnel-slow`; `bgCollectTunnel()` returning the block or `null`.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_form_has_a_tunnel_section_with_server_and_port(self)
def test_both_delivery_paths_post_the_tunnel_block(self)
def test_the_form_posts_no_tunnel_key_when_the_box_is_unchecked(self)
def test_a_url_shaped_server_is_refused_before_the_request(self)
def test_the_result_renders_the_tunnel_identity(self)
```

And in `test_tunnel_config.py`, beside `TestTheGeneratorBakesATunnelBlock`, one route-level test that a body shaped as the form builds it produces a build whose config carries the tunnel block and whose response carries `tunnel_identity`.

- [ ] **Step 2: Run them to verify they fail**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_gui software.tests.test_tunnel_config -v`
Expected: FAIL — the page has no `bg-tunnel`.

- [ ] **Step 3: Add the form section and `bgCollectTunnel`**

An enable checkbox revealing the four fields, the route's own wording as the placeholders, and the slow-crypto warning. `bgCollectTunnel()` returns `null` when the box is clear, so no `tunnel` key is posted at all.

- [ ] **Step 4: Wire both delivery paths and the result**

`runBeaconGen` **and** `runBeaconGist` include the block; the result block renders `tunnel_identity` labelled as the key of the SOCKS and shell port tables and what to delete to retire the build. Client-side validation mirrors the route's refusals only; anything else is shown as the route's 400 came back.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `software/.venv/bin/python -m unittest software.tests.test_tunnel_gui software.tests.test_tunnel_config -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add software/c2/server.py software/tests/test_tunnel_gui.py software/tests/test_tunnel_config.py
git commit -m "feat(c2): the Beacon Gen form can ask for a tunnel, on both delivery paths"
```

---

### Task 11: The operator documentation

**Files:**
- Modify: `docs/TUNNEL.md`, `README.md`
- Test: `software/tests/test_docs.py`

**Interfaces:**
- Consumes: everything above.
- Produces: a *Shell session* section in `docs/TUNNEL.md`; the *Asking for a tunnel* section reduced to `drops` and the stagers.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_tunnel_page_documents_the_shell_switch_and_the_attach_command(self)
def test_the_tunnel_page_says_the_session_is_root_and_how_to_resize(self)
def test_the_tunnel_page_says_what_a_transcript_holds(self)
def test_the_tunnel_page_lists_the_detection_indicators(self)
def test_the_curl_section_no_longer_claims_the_form_cannot_ask_for_a_tunnel(self)
def test_the_readme_capability_table_names_the_shell_session(self)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `software/.venv/bin/python -m unittest software.tests.test_docs -v`
Expected: FAIL

- [ ] **Step 3: Write the documentation**

The *Shell session* section covers: what it is and that nothing listens on the implant; the one switch and the transcript switch; the SSH forward and the attach command, with `socat` as the fallback; that it is a root shell on the implant host; that the geometry is set once and `stty` is the remedy; what a transcript holds and that credentials typed inside a session are in it; that it needs a tunnel-enabled build whose endpoint advertises the feature; and the indicators it leaves — a `bash` child of a `python3 -` process, a PTY on the host, a second connection on the same outbound port. The `curl` section keeps only `drops` and the stagers.

- [ ] **Step 4: Run the whole suite**

Run: `software/.venv/bin/python -m unittest discover -s software/tests -t .`
Expected: PASS, with no test count lower than before the branch.

- [ ] **Step 5: Commit**

```bash
git add docs/TUNNEL.md README.md software/tests/test_docs.py
git commit -m "docs(tunnel): the shell session, its switches and what it leaves behind"
```
