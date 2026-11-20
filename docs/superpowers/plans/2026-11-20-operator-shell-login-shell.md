# Operator Shell, Part Two: the session looks like the operator's own shell

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A shell session runs the login shell of the user the endpoint runs as, so the operator's own prompt, colours and completion apply — and the view's claim about command history stays exactly true for whichever shell ran.

**Architecture:** Three changes on the endpoint (`software/c2/beacon.py`): the shell is chosen from the passwd entry rather than always bash; the generated rcfile gains colour defaults for the bash fallback; and the pipe failure that used to downgrade history silently now refuses the session, which makes the history mechanism a **host capability** rather than a per-session accident. That capability then rides the existing `HELLO` path — the same five hops `user` already travels — to `GET /api/opshell/state`, and the view's first terminal line states what it was told instead of a constant.

**Tech Stack:** Python 3.9 standard library only (`pwd`, `os`, `platform`, `subprocess`, `pty`); `unittest`; the page's inline JavaScript against the hand-written node harness in `software/tests/test_operator_shell.py`.

**Spec:** `docs/superpowers/specs/2026-11-19-operator-shell-window-design.md`, "Part two: the session should look like the operator's own shell" (`:449-583`).

## Global Constraints

- **Nothing reaches the target's disk.** The rcfile is the contents of a pipe the child opens as `/dev/fd/<n>` (`beacon.py:3312-3333`). No `ZDOTDIR`, no generated file, no temporary directory.
- **Nothing is installed on the device.** If the operator wants as-you-type highlighting they install `zsh-syntax-highlighting` themselves; this change is what makes it then apply.
- **The view never recolours output.** A character the operator takes for shell output came from the shell. No browser-side painting of IPs, paths or error words.
- **The operator's own configuration wins** over any default this code sets: colour defaults are sourced *before* the host's rc files, never after.
- Python 3.9 is the floor (CI runs `suite (python 3.9, linux)`); standard library only.
- `_SHELL_CWD = "/"`, `_SHELL_BASH = "/bin/bash"`, `_SHELL_SH = "/bin/sh"`, `_DEV_FD = "/dev/fd"`, `_SHELL_TERM = "xterm-256color"` (`beacon.py:3180-3183`, `:3179`) keep their values.
- **A `HELLO` is written by whatever is at the other end of the tunnel.** Every field read off one is coerced, never trusted — `_text` (`tunnel/server.py:1447`) is the existing instrument.
- The browser baseline is Safari 14.1; anything newer sits behind a `typeof` check.
- Commit messages explain why, in prose, and state what was measured.

### The decision this plan rests on, which the spec left open

The spec says the beacon "reports which history mechanism it used — the rcfile or the weaker environment variable — **as a field on the shell session**" (`design:521-522`) and leaves to the builder "whether the history-mechanism field rides on the existing shell status dict or a new one" (`design:569-570`).

**There is no such dict and no such channel.** `user` travels on `MSG_HELLO`, sent once at connect (`beacon.py:3808-3816` → `tunnel/server.py:886-891` → `:629` → `server.py:1892`); `root` is computed on the team server (`server.py:1893`). Once a session exists the endpoint's only upward channel is the raw PTY byte stream plus the two plain-text refusals in `_refuse_shell` (`beacon.py:4518`). The one structured per-session channel, `MSG_OPEN_SHELL`, runs server → endpoint (`tunnel/server.py:760-762`).

So the mechanism cannot be reported per session without widening the protocol. The operator chose the alternative: **report the host's capability on `HELLO`, and make the one per-attempt reason impossible.** `_shell_invocation` picks the weaker path for three reasons (`beacon.py:3366-3374`) — the shell is not bash, the host has no `/dev/fd`, or the rcfile pipe could not be opened. The first two are host facts that do not change between `HELLO` and a spawn. The third is per-attempt, so **it stops being a downgrade and becomes a refusal** (Task 2): the session fails with a reason instead of quietly recording the operator's commands. What `HELLO` reports is then exact for every session that runs.

## Review Focus

1. **A passwd entry naming a shell that is not there.** A login shell of `/usr/bin/fish` on a host where fish was removed, or an empty `pw_shell`. Expected: the session still starts, on the bash/sh preference, and nothing claims the login shell ran.
2. **A `HELLO` whose history field is a number, a list, or absent.** An endpoint from an older build sends no field at all. Expected: the view does not claim history is off on the strength of a field it did not receive — the unknown value reads as the weaker path, never as "off".
3. **A channel the agent reports but the relay has no row for.** `user` and `root` are populated only inside `if row is not None` (`server.py:1890`), and the blind answer (`server.py:1766-1788`) has neither. Expected: the first terminal line claims neither "off" nor "not guaranteed", because the page was told nothing.
4. **A login shell that is zsh on a host whose `/dev/fd` exists.** Both weaker-path reasons are about bash and `/dev/fd`, and this case has only the first. Expected: the reported reason names the shell, not the host, so the operator can tell a zsh session apart from an ancient host.
5. **An `LSCOLORS` or prompt the operator already set.** Expected: theirs survives, because the defaults are sourced before `$HOME/.bashrc` — and a test proves the order rather than the presence.

---

### Task 1: The session runs the login shell

**Files:**
- Modify: `software/c2/beacon.py` (new `_login_shell`; `_shell_program` at `:3288-3296`)
- Test: `software/tests/test_tunnel_endpoint.py`

**Interfaces:**
- Produces:
  - `_SHELL_ZSH = "/bin/zsh"` beside `_SHELL_BASH`/`_SHELL_SH` (`beacon.py:3181-3182`) — a default path, not the chooser's only source
  - `def _login_shell() -> str` — the effective user's `pw_shell` when it is executable and its basename is `bash` or `zsh`; `""` otherwise. Modelled on `_process_user` (`beacon.py:3491-3512`): `pwd.getpwuid(os.geteuid())`, never `$SHELL`, and `""` on any exception
  - `def _shell_program() -> str` keeps its name and signature; it now answers `_login_shell()` first and its current bash-then-sh preference second
- Consumes: `_shell_executable(path)` (`beacon.py:3285`).

- [ ] **Step 1: Write the failing tests**

In `software/tests/test_tunnel_endpoint.py`, beside the existing `_shell_program` neighbours. Each patches `beacon.pwd.getpwuid` and `beacon._shell_executable` rather than touching the host.

```python
    def test_the_login_shell_of_the_effective_user_is_what_runs(self):
        """`$SHELL` under the shipped service unit is the service
        manager's environment, not a user's choice, so the passwd entry
        is what is asked."""
        with self._passwd("/bin/zsh"), self._executable({"/bin/zsh"}):
            self.assertEqual(beacon._shell_program(), "/bin/zsh")

    def test_a_login_shell_that_is_not_there_does_not_cost_the_session(self):
        for shell in ("/usr/bin/fish", "", "/nonexistent/zsh"):
            with self._passwd(shell), self._executable({"/bin/bash"}):
                self.assertEqual(beacon._shell_program(), "/bin/bash", shell)

    def test_a_shell_nobody_has_driven_with_flags_is_not_driven(self):
        """fish and tcsh take neither `--rcfile` nor bash's `-i`
        semantics, so the preference runs rather than an untested flag."""
        with self._passwd("/usr/bin/fish"), \
                self._executable({"/usr/bin/fish", "/bin/bash"}):
            self.assertEqual(beacon._shell_program(), "/bin/bash")

    def test_the_environments_shell_variable_is_never_consulted(self):
        with self._passwd("/bin/zsh"), self._executable({"/bin/zsh"}), \
                mock.patch.dict(os.environ, {"SHELL": "/bin/ksh"}):
            self.assertEqual(beacon._shell_program(), "/bin/zsh")
        self.assertNotIn("SHELL", beacon.inspect.getsource(beacon._login_shell))

    def test_a_passwd_lookup_that_raises_falls_back_rather_than_throwing(self):
        with mock.patch.object(beacon.pwd, "getpwuid",
                               side_effect=KeyError("no such uid")), \
                self._executable({"/bin/bash"}):
            self.assertEqual(beacon._shell_program(), "/bin/bash")
```

Add the two context managers `_passwd(shell)` and `_executable(paths)` as helpers on the test case: the first patches `beacon.pwd.getpwuid` to return an object whose `pw_shell` is `shell`, the second patches `beacon._shell_executable` to answer membership in `paths`.

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_tunnel_endpoint -v -k login_shell -k shell_variable -k passwd_lookup -k driven_with_flags`
Expected: FAIL — `module 'software.c2.beacon' has no attribute '_login_shell'`.

- [ ] **Step 3: Add `_login_shell` and rewrite `_shell_program`**

`_login_shell` carries a docstring in `_process_user`'s register: say why the passwd entry rather than `$SHELL`, and say what the shipped `services/raccoon-beacon.service` means — the unit runs as root, so "the login shell" is root's, which on most Linux hosts is `/bin/bash` and the behaviour is unchanged. The operator's own machine is the case this helps, and that is the device this feature exists for.

`_shell_program`'s docstring keeps its existing reasoning about bash-completion and `/bin/sh` as the floor, and gains the new first preference.

- [ ] **Step 4: Run the endpoint file**

Run: `/usr/bin/python3 -m unittest software.tests.test_tunnel_endpoint`
Expected: OK. The `_HAS_PTY`/`_HAS_BASH` suites (`:126`, `:142`) spawn real shells; a change to the chooser is exactly what they are there to catch.

- [ ] **Step 5: Commit**

```bash
git add software/c2/beacon.py software/tests/test_tunnel_endpoint.py
git commit -m "feat(tunnel): a session runs the login shell of the user the endpoint runs as"
```

---

### Task 2: A pipe failure refuses the session instead of downgrading it

**Files:**
- Modify: `software/c2/beacon.py` (`_shell_invocation` at `:3336-3382`)
- Test: `software/tests/test_tunnel_endpoint.py`

**Interfaces:**
- Produces:
  - `def _history_guard() -> Tuple[str, str]` — `("off", "")` when the chosen shell is bash and `_DEV_FD` is a directory; otherwise `("weak", <reason>)` with the reason worded for an operator. The two reasons are exactly the two host-stable ones already in `_shell_invocation` (`:3367`, `:3369`).
  - `_shell_invocation(cols, rows)` keeps its name, its parameters and its three-element return. What changes: an `OSError` from `_shell_rcfile_fd()` (`:3372`) **propagates** instead of setting `weaker`, and the two host-stable branches ask `_history_guard` rather than spelling their reasons inline.
- Consumes: `_shell_program()` from Task 1, `_shell_rcfile_fd()` (`:3312`), `_DEV_FD`.

**The refusal has to be written, not merely allowed to happen.** I read the caller: `_serve_shell` (`:4274`) has a `try`/`finally` and no `except`, so an `OSError` from `_shell_invocation` at `:4331` would unwind past it with the descriptors correctly closed and **nothing said** — the operator's terminal would simply go quiet. That is better than recording their commands and worse than it needs to be, because `_refuse_shell` (`:4518`) exists for exactly this: "what is at the other end of this stream is the operator's terminal, so a sentence is the only refusal they can read … Every refusal says what happened and what to do about it."

So the call at `:4331` is wrapped where it stands: an `OSError` becomes `self._refuse_shell(sock, noise, <reason>)` and a return. Both arguments are already `_serve_shell`'s parameters, the `finally` still runs, and nothing above needs changing.

- [ ] **Step 1: Write the failing tests**

```python
    def test_a_pipe_that_cannot_be_opened_refuses_rather_than_records(self):
        """The downgrade this replaces was the worst trade available: a
        session that quietly wrote the operator's commands to their own
        history file while the view said history was off."""
        with self._passwd("/bin/bash"), self._executable({"/bin/bash"}), \
                mock.patch.object(beacon, "_shell_rcfile_fd",
                                  side_effect=OSError("too many files")):
            with self.assertRaises(OSError):
                beacon._shell_invocation(80, 24)

    def test_the_operator_is_told_why_the_session_was_refused(self):
        """A stream that simply goes quiet is the one failure worse than
        a wrong answer: `_refuse_shell`'s own docstring says a terminal
        can only read a sentence."""
        refusals = []
        with self._passwd("/bin/bash"), self._executable({"/bin/bash"}), \
                mock.patch.object(beacon, "_shell_rcfile_fd",
                                  side_effect=OSError("too many files")), \
                mock.patch.object(beacon.TunnelEndpoint, "_refuse_shell",
                                  lambda self, s, n, reason:
                                  refusals.append(reason)):
            self._endpoint()._serve_shell(self._fake_sock(),
                                          self._fake_noise(), 80, 24)
        self.assertEqual(len(refusals), 1)
        self.assertRegex(refusals[0], r"(?i)histor")
        self.assertNotRegex(refusals[0], r"Traceback|OSError\(")

    def test_the_guard_a_host_reports_is_the_guard_a_session_gets(self):
        """What `HELLO` carries has to be what the spawn does, or the
        view states a fact about the wrong thing."""
        cases = (("/bin/bash", True, "off"),
                 ("/bin/zsh", True, "weak"),
                 ("/bin/bash", False, "weak"))
        for shell, has_dev_fd, expected in cases:
            with self._passwd(shell), self._executable({shell}), \
                    mock.patch.object(beacon.os.path, "isdir",
                                      return_value=has_dev_fd):
                guard, detail = beacon._history_guard()
                argv, env, fds = beacon._shell_invocation(80, 24)
                self.assertEqual(guard, expected, (shell, has_dev_fd))
                self.assertEqual("--rcfile" in argv, guard == "off",
                                 "the spawn disagreed with the report")
                self.assertEqual(env.get("HISTFILE") == os.devnull,
                                 guard == "weak")
                self.assertEqual(bool(detail), guard == "weak")

    def test_a_zsh_session_blames_the_shell_and_not_the_host(self):
        """Review Focus 4: the operator can tell a login zsh apart from
        an ancient host only if the reason says which it was."""
        with self._passwd("/bin/zsh"), self._executable({"/bin/zsh"}), \
                mock.patch.object(beacon.os.path, "isdir", return_value=True):
            _, detail = beacon._history_guard()
        self.assertIn("zsh", detail)
        self.assertNotIn(beacon._DEV_FD, detail)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_tunnel_endpoint -v -k pipe_that_cannot -k guard_a_host -k zsh_session_blames`
Expected: FAIL — no `_history_guard`, and the pipe case returns a downgraded invocation instead of raising.

- [ ] **Step 3: Add `_history_guard`, change `_shell_invocation`, and write the refusal**

Three edits, in that order, so each has its own failing test to satisfy. The third is the wrap at `:4331` described above.

`_shell_invocation`'s docstring currently explains the fallback and admits "the host's own rc files run after that and are free to set `HISTFILE` again" (`:3348-3350`). Rewrite that paragraph: the weaker path is now reached only for the two reasons a host cannot change under it, the pipe failure refuses the session, and the guard is reported upward so that the view states this rather than guessing.

Keep the `logger.info` at `:3377-3379` — a weaker path is still worth a line in the log — and keep `--rcfile` before `-i` with its bash 3.2 reasoning (`:3352-3354`).

- [ ] **Step 4: Run the endpoint file**

Run: `/usr/bin/python3 -m unittest software.tests.test_tunnel_endpoint`
Expected: OK.

- [ ] **Step 5: Commit**

```bash
git add software/c2/beacon.py software/tests/test_tunnel_endpoint.py
git commit -m "fix(tunnel): a pipe that cannot be opened refuses the session rather than recording it"
```

---

### Task 3: The guard travels to the team server

**Files:**
- Modify: `software/c2/beacon.py` (`_hello` body at `:3808-3816`)
- Modify: `software/c2/tunnel/server.py` (`_CommandChannel.__init__` at `:581`; the `HELLO` read at `:886-891`; the row in `endpoints()` at `:618-649`)
- Modify: `software/c2/server.py` (`opshell_state`'s `out` at `:1746-1765` and `:1890-1895`)
- Test: `software/tests/test_tunnel_endpoint.py`, `software/tests/test_tunnel_server.py`, `software/tests/test_operator_shell.py`

**Interfaces:**
- Produces, as two fields with the same names at every hop:
  - `history` — `"off"` or `"weak"`; **anything else, including absent, reads as `"weak"`**
  - `history_detail` — the operator-facing reason, `""` when `history` is `"off"`
  - on `/api/opshell/state`: `out["history"]` defaulting to `""` (told nothing) and `out["history_detail"]` defaulting to `""`
- Consumes: `_history_guard()` from Task 2; `_text` (`tunnel/server.py:1447`).

**The five hops, and the shape pins that will fail if one is missed.** `user` travels this exact route; copy it.

| Hop | Where |
|---|---|
| 1 | `beacon.py:3808-3813` — two keys in the `_hello()` body |
| 2 | `tunnel/server.py:581` — two attributes on `_CommandChannel` |
| 3 | `tunnel/server.py:886-891` — read with `_text`, then `history` validated against the two known words, unknown → `"weak"` |
| 4 | `tunnel/server.py:629` — two keys on the row in `endpoints()` |
| 5 | `server.py:1746-1765` defaults, `:1890-1895` populated from `row.get(...)` |

`tunnel/supervisor.py`, `listeners/child.py` and `tunnel/__main__.py:_status()` are generic pass-throughs and need no edit. `/open` (`server.py:2062`) and `/close` (`:2108`) re-use `opshell_state()` and need none either.

Pins:

- `software/tests/test_operator_shell.py:2208` `test_an_endpoint_row_reports_the_fields_the_server_reads` — its hard-coded list at `:2221-2223` must gain both names, **and** each must appear as a literal `"name"` in `tunnel/server.py` or `tunnel/__main__.py`.
- The three endpoint-row fixtures: `test_operator_shell.py:974-983`, `:1006-1015`, `:2865-2874`.
- `software/tests/test_tunnel_server.py:165` `_CommandPeer.hello(...)` — the helper's body at `:167-178` omits `user` when `None`; the new keywords follow that pattern.
- `software/tests/test_tunnel_protocol.py:567` `TestTheReExport` — only if a shared constant is introduced. **Prefer plain string literals and introduce none**, so this pin stays untouched.

- [ ] **Step 1: Write the failing tests**

Three files, each at the hop it owns. The endpoint side, modelled on `test_hello_advertises_the_shell_feature` (`test_tunnel_endpoint.py:1013`):

```python
    def test_hello_reports_the_history_guard_a_session_here_would_get(self):
        with self._passwd("/bin/bash"), self._executable({"/bin/bash"}), \
                mock.patch.object(beacon.os.path, "isdir", return_value=True):
            body = self._endpoint()._hello()
        self.assertEqual(body["history"], "off")
        self.assertEqual(body["history_detail"], "")
```

The relay side, modelled on `test_the_row_carries_the_user_from_the_hello` (`test_tunnel_server.py:375`) and `test_an_endpoint_that_reports_no_user_gets_no_user_invented` (`:381`):

```python
    def test_the_row_carries_the_history_guard_from_the_hello(self):
        row = self._row_after_hello(history="weak",
                                    history_detail="/bin/zsh takes no --rcfile")
        self.assertEqual(row["history"], "weak")
        self.assertIn("zsh", row["history_detail"])

    def test_a_history_guard_this_server_does_not_know_reads_as_weak(self):
        """Review Focus 2. A HELLO is written by whatever is at the other
        end, and the safe reading of an unknown word is the weaker one:
        claiming history is off is the only answer that can mislead."""
        for sent in ("", "OFF", "off ", 1, True, ["off"], None, {}):
            row = self._row_after_hello(history=sent)
            self.assertEqual(row["history"], "weak", repr(sent))

    def test_an_endpoint_from_an_older_build_reports_no_guard(self):
        row = self._row_after_hello()  # no history keyword at all
        self.assertEqual(row["history"], "weak")
```

The state answer, in `software/tests/test_operator_shell.py`:

```python
    def test_the_state_answer_carries_the_history_guard_the_row_has(self):
        state = self._state_with_row(history="weak",
                                     history_detail="/bin/zsh takes no --rcfile")
        self.assertEqual(state["history"], "weak")
        self.assertIn("zsh", state["history_detail"])

    def test_a_channel_with_no_row_is_told_nothing_about_history(self):
        """Review Focus 3: `user` and `root` are populated only inside
        `if row is not None`, and so is this. An empty guard is the page's
        signal to claim neither."""
        self.assertEqual(self._state_without_row()["history"], "")
        self.assertEqual(self._blind_state()["history"], "")
```

Use the existing helpers for building a state answer where the file has them; where it does not, add `_state_with_row`, `_state_without_row` and `_blind_state` as thin wrappers over the fixtures at `:974-983` and `:1006-1015`.

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_tunnel_endpoint software.tests.test_tunnel_server software.tests.test_operator_shell -v -k history`
Expected: FAIL at every hop, beginning with `KeyError: 'history'`.

- [ ] **Step 3: Make the five edits, then the pins**

Edit the hops in order, running the three files after each so that a missing hop is a failing test rather than a `KeyError` three layers away. Then add both names to the list at `test_operator_shell.py:2221-2223` and to the three fixtures.

- [ ] **Step 4: Run every file that reads a row or a state answer**

Run: `/usr/bin/python3 -m unittest software.tests.test_tunnel_endpoint software.tests.test_tunnel_server software.tests.test_tunnel_protocol software.tests.test_operator_shell software.tests.test_tunnel_gui`
Expected: OK.

- [ ] **Step 5: Commit**

```bash
git add software/c2/beacon.py software/c2/tunnel/server.py software/c2/server.py \
  software/tests/test_tunnel_endpoint.py software/tests/test_tunnel_server.py \
  software/tests/test_operator_shell.py
git commit -m "feat(opshell): the endpoint reports which history guard a session here gets"
```

---

### Task 4: The first terminal line states what it was told

**Files:**
- Modify: `software/c2/server.py` (the first line at `:9576`; `opshellRender` at `:9195-9210`)
- Test: `software/tests/test_operator_shell.py`

**Interfaces:**
- Consumes: `state.history` and `state.history_detail` from Task 3.
- Produces: nothing a later task reads.

Three wordings, one per value, and the third is the point of the whole task:

| `state.history` | the line says |
|---|---|
| `"off"` | `history is off in this session` — unchanged from today |
| `"weak"` | that history is **not guaranteed off**, with `history_detail`'s reason, because this shell could not be given an rcfile and the operator's own configuration runs after |
| `""` | neither — the page was told nothing |

- [ ] **Step 1: Write the failing tests**

The first two in `TestTheViewDoesNotOverclaim` (`test_operator_shell.py:3352`), beside `test_the_strip_states_the_user_and_does_not_assume_root` (`:3363`); the third replaces the body of `test_the_first_terminal_line_claims_only_what_the_code_does` (`:3370`), which today asserts the constant string is present.

```python
    def test_the_first_line_states_the_history_guard_it_was_given(self):
        render = self.js_function("opshellRender")
        self.assertIn("state.history", render)
        self.assertIn("state.history_detail", render)

    def test_the_first_line_claims_nothing_when_it_was_told_nothing(self):
        """Review Focus 3. A page that defaults to "history is off" would
        claim it for a channel the relay has no row for."""
        for guard in ("", "weak"):
            got = self._node(
                "els['opshell-body'] = el('opshell-body');\n"
                "globalThis.Terminal = function(){ return fakeTerm(); };\n"
                "opshellSession = 'sid';\n"
                "nextReply = {ok:true, status:200, stream: fakeStream(['x'])};\n"
                "await opshellAttach({state:'live', host:'parrot',"
                " history:'%s', history_detail:'/bin/zsh takes no --rcfile'});\n"
                "console.log(JSON.stringify({said: said.join(' ')}));" % guard)
            self.assertNotRegex(got["said"], r"(?i)history is off",
                                "claimed history was off on %r" % guard)

    def test_a_weak_guard_says_why_and_an_off_guard_says_it_is_off(self):
        lines = {}
        for guard, detail in (("off", ""),
                              ("weak", "/bin/zsh takes no --rcfile")):
            got = self._node(
                "els['opshell-body'] = el('opshell-body');\n"
                "globalThis.Terminal = function(){ return fakeTerm(); };\n"
                "opshellSession = 'sid';\n"
                "nextReply = {ok:true, status:200, stream: fakeStream(['x'])};\n"
                "await opshellAttach({state:'live', host:'parrot',"
                " history:'%s', history_detail:'%s'});\n"
                "console.log(JSON.stringify({said: said.join(' ')}));"
                % (guard, detail))
            lines[guard] = got["said"]
        self.assertRegex(lines["off"], r"(?i)history is off")
        self.assertNotRegex(lines["weak"], r"(?i)history is off")
        self.assertRegex(lines["weak"], r"(?i)not guaranteed")
        self.assertIn("zsh", lines["weak"])
        self.assertNotEqual(lines["off"], lines["weak"])
```

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_operator_shell -v -k history_guard -k told_nothing -k weak_guard`
Expected: FAIL — the line is a constant, so the `""` case claims history is off.

- [ ] **Step 3: Make the line conditional**

`:9576` is one concatenation inside the attach's opening lines. The reason text comes from `history_detail` through `esc()`, because it is a string the endpoint wrote — the strip's other endpoint-written values are escaped the same way (`:9205`).

- [ ] **Step 4: Raise the floor and run the file**

`test_the_count_of_behavioural_tests_has_not_quietly_dropped` (`:3732`) carries a numeric floor with its arithmetic written out, and eleven named methods (`:3775-3797`). Raise the floor to two under the new real count, carry the arithmetic, and update the `skipUnless(node)` docstring's number.

Run: `/usr/bin/python3 -m unittest software.tests.test_operator_shell software.tests.test_c2_hardening`
Expected: OK.

- [ ] **Step 5: Commit**

```bash
git add software/c2/server.py software/tests/test_operator_shell.py
git commit -m "feat(opshell): the first line says whether history is off or only not guaranteed"
```

---

### Task 5: Colour defaults, for the bash fallback only

**Files:**
- Modify: `software/c2/beacon.py` (`_SHELL_RCFILE` at `:3241-3251`)
- Test: `software/tests/test_tunnel_endpoint.py`

**Interfaces:**
- Consumes: nothing. The rcfile is only ever handed to bash (Task 2 guarantees it), so nothing here runs when the session is a login shell — that shell's own configuration is the point.

What is appended, **before** the lines that source the host's rc files, so the operator's own settings override them:

- `CLICOLOR=1` and an `LSCOLORS` default, for BSD and macOS `ls`
- `LS_COLORS` left alone, because GNU `ls` reads it from the environment the host already has and `dircolors` is the host's business
- a prompt naming the host and the working directory in the interface's own red, so the operator can tell this session from a local one at a glance

- [ ] **Step 1: Write the failing tests**

Beside `test_the_rcfile_sources_nothing_it_has_not_checked_for` (`:1874`) and `test_the_generated_rcfile_leaves_nothing_on_disk` (`:1893`).

```python
    def test_the_colour_defaults_are_set_before_the_host_is_sourced(self):
        """Review Focus 5. Order is the whole requirement: after the
        host's files these would overwrite the operator's own prompt."""
        rc = beacon._SHELL_RCFILE
        self.assertLess(rc.index("CLICOLOR"), rc.index('"$HOME/.bashrc"'))
        self.assertLess(rc.index("LSCOLORS"), rc.index('"$HOME/.bashrc"'))
        self.assertLess(rc.index("PS1"), rc.index('"$HOME/.bashrc"'))

    def test_the_defaults_do_not_touch_what_the_host_already_has(self):
        self.assertNotIn("LS_COLORS", beacon._SHELL_RCFILE)

    def test_the_rcfile_still_ends_by_turning_history_off(self):
        """The colour lines went in above the sourcing; the history lines
        must stay below it, or the host's rc runs after them."""
        rc = beacon._SHELL_RCFILE
        self.assertGreater(rc.index("unset HISTFILE"),
                           rc.index('"$HOME/.bashrc"'))
        self.assertTrue(rc.rstrip().endswith("set +o history"))
```

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_tunnel_endpoint -v -k colour -k defaults_do_not_touch -k ends_by_turning`
Expected: FAIL — `substring not found` for `CLICOLOR`.

- [ ] **Step 3: Extend `_SHELL_RCFILE`**

The existing comment above it (`:3236-3240`) explains the three candidate completion paths and why each is tested before it is read; add a paragraph saying why the colour lines sit above the sourcing and why `LS_COLORS` is left alone. The prompt's red is the interface's own; take the value from the page's `--red` rather than inventing one.

- [ ] **Step 4: Run the endpoint file, with a real shell**

Run: `/usr/bin/python3 -m unittest software.tests.test_tunnel_endpoint`
Expected: OK. The `_HAS_BASH` suite spawns a real bash against a real generated rcfile — a syntax error in the new lines fails there and nowhere else, which is why this step is not optional.

- [ ] **Step 5: Commit**

```bash
git add software/c2/beacon.py software/tests/test_tunnel_endpoint.py
git commit -m "feat(tunnel): the bash fallback gets colour so the session is not monochrome"
```

---

### Task 6: Say it in the documentation, and close the spec

**Files:**
- Modify: `docs/TUNNEL.md` (the artifact list, and the session-strip prose at `:466-477`)
- Modify: `docs/superpowers/specs/2026-11-19-operator-shell-window-design.md` (`:501-530`, `:567-574`)
- Modify: `README.md` (the Operator Shell capability row at `:608`)
- Test: `software/tests/test_docs.py`

**Interfaces:**
- Consumes: nothing. Produces the operator-facing account of Tasks 1–5.

- [ ] **Step 1: Write the failing test**

`test_docs.py:978` `test_the_tunnel_page_says_the_session_is_root_and_how_to_resize` already pins `root`, `set once`, `stty rows` and `SIGWINCH` in `docs/TUNNEL.md`; this is its sibling. Assert on flattened text, scoped to the paragraph that makes the claim — the page wraps, and a pattern that matches any paragraph is the defect this suite has found twice.

```python
    def test_the_tunnel_page_says_which_shell_runs_and_what_history_costs(self):
        text = " ".join(TUNNEL_DOC.read_text().split())
        self.assertRegex(text, r"(?i)login shell")
        self.assertRegex(text, r"(?i)not guaranteed off")
        self.assertNotRegex(
            text, r"(?i)history is (always )?off (on|in) every session",
            "the page still promises history is off for every shell")
```

- [ ] **Step 2: Run it to verify it fails**

Run: `/usr/bin/python3 -m unittest software.tests.test_docs -v -k which_shell_runs`
Expected: FAIL.

- [ ] **Step 3: Rewrite the three operator-facing passages**

- `docs/TUNNEL.md`: which shell a session runs and why the passwd entry rather than `$SHELL`; that on a shipped implant the unit runs as root so the behaviour is unchanged, and the operator's own machine is the case this helps. Then the artifact list gains the distinction: history is off where bash took an rcfile, and **not guaranteed off** where it could not, with the reason the view shows. And that a pipe failure now refuses the session rather than recording it.
- `README.md:608`: one clause for the login shell.
- Prose only. `test_docs.py` derives the README's section count from `^## \d+\. ` headings and its badge from the file count in `docs/screenshots`.

- [ ] **Step 4: Close the spec's two open points**

- `design:501-530` describes the history consequence on the assumption that the mechanism is reported per session. Replace that with what was built and why: there is no upward per-session channel, so the guard is a **host capability** on `HELLO`, and the one per-attempt reason became a refusal. Keep the paragraph's conclusion, which is still the point — a feature that gave the operator colour and quietly started recording their commands would be the worst trade on this branch.
- `design:567-574` "Left to the builder": record the three answers. The field rides the `HELLO` row as `history`/`history_detail`; the `LSCOLORS` string is whatever Task 5 chose; and zsh gets no "no rc" variant, which was already the spec's own call.
- The Known limitations section gains a seventh entry: **the guard is what the endpoint reported about itself.** The team server cannot verify it, exactly as it cannot verify `user` — a modified endpoint could claim `off` and not do it. That is the same trust boundary `docs/TUNNEL.md` already states for the user ("Which user that is, the endpoint reports"), and saying so keeps the view's claim honest about whose claim it is. Note that `test_the_design_records_the_six_things_this_cannot_do` counts the entries, so its name, its count and its subject list all move together.

- [ ] **Step 5: Run the docs file and the full suite**

Run: `/usr/bin/python3 -m unittest software.tests.test_docs`
Expected: OK, including `test_the_design_records_the_six_things_this_cannot_do` — the design's Known limitations section is pinned by subject, and this task edits the document it lives in.

Run: `/usr/bin/python3 -m unittest discover -s software/tests -t .`
Expected: OK. About nine minutes; this is the task that runs it, so budget for it and report the final count.

- [ ] **Step 6: Commit**

```bash
git add docs/TUNNEL.md README.md \
  docs/superpowers/specs/2026-11-19-operator-shell-window-design.md \
  software/tests/test_docs.py
git commit -m "docs: which shell a session runs, and what that costs for history"
```

---
