# An interactive shell session on the implant, carried by the tunnel — design

**Date:** 2026-11-10
**Status:** awaiting approval

Written in English to match the spec it extends,
[`2026-11-09-reverse-socks-tunnel-design.md`](2026-11-09-reverse-socks-tunnel-design.md),
whose vocabulary this document uses throughout.

---

## Intent

The implant runs on ParrotOS, and ParrotOS is why: `nmap`, `tcpdump`,
`scapy`, `aircrack`, `john`, `hashcat` and the rest are already installed
on the host the beacon sits on. Today an operator reaches them one command
at a time, through the beacon verb `shell`, and pays a check-in for each
one: `_MIN_INTERVAL` is 10 seconds, jitter is on top, and one task carries
one result. Nothing interactive is possible, and nothing completes.

What an operator actually wants on that host is a session: a prompt,
history within that session, Tab completion for `nmap`'s flags, a
long-running capture they can interrupt. The same thing an SSH session
would give them — without an `sshd` on the target, without credentials on
the target, and without an entry in its auth log.

The tunnel already carries a persistent, authenticated, outward-dialled
channel to that host. This work puts a PTY on the far end of it and an
authenticated loopback port on the near end, so the operator attaches with
their own terminal and lands in a real shell on the implant host.

---

## Goals

1. **A real PTY on the implant host**, running as the user the tunnel
   endpoint runs as — root, under the shipped systemd unit — directly on
   the host, nothing containerised.
2. **Its own session.** Independent of the beacon's task channel: no
   check-in latency, no task row, and several sessions can be open at once.
3. **Native completion and line editing.** `readline` and
   `bash-completion` run on the implant, so flag completion for the tools
   installed there comes for free. We write no completion logic at all.
4. **The operator attaches from their own terminal** to one stable,
   authenticated loopback port per build identity on the team server.
5. **Entirely inside the existing tunnel**: one outbound connection per
   session, Noise end to end, the same single destination port on the
   target side.
6. **The panel can be read.** Port, password, a copy-ready attach command,
   live session counts, and one sentence saying what this is.

## Non-goals

- **No terminal in the browser.** That is the follow-up, on exactly the
  session API this builds; see *Approaches*.
- **No Windows.** `pty` is POSIX-only. A Windows build refuses the session
  with a reason the operator can read, rather than failing opaquely.
- **No window-size propagation.** The size is set once from the attach
  request and not tracked afterwards; the documented remedy for a resize
  is one `stty` inside the session.
- **No replacement for the `shell` verb.** Tasking stays what it is, and
  the autonomous agent is deliberately **not** given this capability: it
  is an operator feature, and an interactive session has no approval gate
  in front of it.
- **No new transport.** Nothing here touches HTTPS, DNS, SMB or QUIC.
- **Recording is off unless it is switched on.** See *Session
  transcripts*.
- **The `drops` list and the stager fields stay out of the Beacon Gen
  form.** The tunnel goes in (see below); those two remain the documented
  interim gap, with the `curl` route as their answer.

## Anti-goals

Each of these would make the work a failure even if it functioned.

- **A listening socket on the implant.** A shell service on the target,
  even on loopback, is a backdoor every local user on that host can reach,
  and it is a port a scan of the Pi would find. The session is dialled
  **out**, like everything else in this tunnel.
- **An unauthenticated port on the team server.** This port is a root
  shell on the implant host. Loopback keeps other hosts out and does
  nothing about other local users — the argument `tunnel/socks.py` already
  makes in its docstring, and it applies here with more force.
- **A port that moves under the operator** between restarts of the tunnel
  server.
- **A second copy of the wire codec.** `tunnel/protocol.py` re-exports
  from `beacon.py` and must keep doing so; a codec defined server-side
  would pass every test here and be absent at runtime on target.
- **A secret on a command line**, in `ps`, or in the artifact beyond what
  the tunnel already carries.

---

## Constraints the code imposes

Read out of the tree, because each one closed off a design that looked
reasonable from outside it.

- **The task channel cannot carry a session.** `_MIN_INTERVAL = 10`
  (`beacon.py`), plus jitter, plus one result per task.
- **The tunnel's shape is one connection per session.** The server sends
  `MSG_OPEN_RELAY` down the command channel; the endpoint dials *its
  configured port* — the advertised one is deliberately ignored, see
  `_spawn_relay`'s docstring — claims the session with `MSG_RELAY {token}`
  over a fresh Noise handshake, and then carries bytes. `TunnelServer.
  open_session()` and `RelayStream` already give the server side a byte
  stream, and `_dispatch` already branches on the kind of the first
  message. A shell session is one more branch, not a new mechanism.
- **The implant side of the codec lives in `beacon.py`.**
  `api_beacon_gen` builds the delivered artifact by reading that one file.
- **The endpoint is already its own process.** `_tunnel_start` re-runs the
  artifact as `python3 -`, so a PTY spawned there is a child of the tunnel
  process, not of the beacon.
- **This needs a tunnel-enabled build and a running tunnel server.** The
  Beacon Gen form still cannot request a tunnel (a documented gap in
  `docs/TUNNEL.md`); the `curl` route can. Out of scope here, but the new
  documentation has to say so rather than let an operator discover it.
- **The port table is a versioned, 0600, atomically replaced JSON
  document.** `_assign_port`, `_load_state`, `_write_state` in
  `tunnel/server.py`. A damaged table refuses by field name instead of
  guessing, because a guess moves somebody's port.
- **`SocksFront` is the pattern for an operator-facing port**: loopback-only
  bind from an IP literal, `hmac.compare_digest` credentials with no
  short-circuit, caps on both live sessions and pending handshakes, stats
  plus per-kind refusal counters, and a `stop()` that unparks its pumps
  rather than waiting for them to notice.
- **The control socket has exactly one verb, `status`, on purpose.**
  Nothing here adds a verb: the shell port advertises itself in `status`,
  the way the SOCKS port does.
- **Threads are a resource the beacon may fail to get.** Every
  `threading.Thread.start()` in the endpoint has a `RuntimeError` arm that
  degrades with a reason. New threads here have the same obligation.

---

## Approaches

Four were considered; the first is chosen.

**A — A shell front on loopback, attached from the operator's own
terminal.** *(chosen)* A `ShellFront` per identity, modelled on
`SocksFront`, on its own stable port. The operator attaches with `socat`
and lands in a PTY on the implant. Completion, history and line editing are
the implant's own, because the real `readline` is at the far end. No
terminal emulator and no third-party JavaScript anywhere.
*Trades away:* the terminal is not in the browser.

**B — A terminal in the operator GUI.** Same implant side, plus a VT
emulator in the page. Writing one by hand is not realistic, so it means
vendoring xterm.js into `software/c2/static/`, plus a byte bridge over SSE
down and POST up — Flask alone speaks no WebSocket — plus resize and
session lifecycle in HTTP. It would be the first third-party JS bundle in a
repository that ships hand-written vanilla JS with no build step.
*Deferred, not rejected:* it is a pure addition on top of A's session API,
and A is what makes it cheap.

**C — A line-mode REPL in the existing terminal, with completion computed
on the implant.** Least work, fits the current UI exactly. Dropped: no
interactive programs, no flag completion, output only when the command
ends. It does not meet "like an SSH session", which is the requirement.

**D — SOCKS `CONNECT` to a loopback shell service on the implant.**
Needs no protocol change at all: the existing relay can already reach
`127.0.0.1:<port>` on the target. Dropped — it puts a listening shell on
the implant, which is the first anti-goal.

**E — The operator's own `ssh` through the existing SOCKS port to an
`sshd` on the Pi.** Zero new code and perfect fidelity. Dropped: it needs
`sshd` running on the target, credentials on the target, and it writes the
one log line this whole project exists to avoid.

---

## The design

### The wire

Two new message kinds in `beacon.py`, added to `MESSAGE_KIND_NAMES` so
that `MESSAGE_KINDS` and `_code_list` pick them up without a second list
to keep in step, re-exported from `tunnel/protocol.py`, added to its
`__all__`, and written into its docstring table:

| Kind | Direction | Body |
|---|---|---|
| `MSG_OPEN_SHELL = 7` | server → endpoint, on the command channel | `{"port": <advisory>, "token": hex, "cols": int, "rows": int}` |
| `MSG_SHELL = 8` | endpoint → server, first message of a new connection | `{"token": hex}` |

`port` is advisory and ignored by the endpoint, for the reason
`_spawn_relay` documents.

**The Noise framing is unchanged.** Every chunk is a frame and a Noise
message, exactly as a relay's bytes are; `RelayStream` and `write_frame`
are used as they stand. "Raw" means only that there is nothing *inside*
the payload: no SOCKS request, no reply, no header of our own. That is the
one structural difference from a relay — a relay's first operator byte is
a SOCKS request, a shell session's first operator byte is already input
for the shell.

**`HELLO` gains `features`,** a list of strings, `["shell"]` on a build
that has this code. The server records it per channel and
`open_shell_session` refuses an endpoint that did not advertise it, with a
reason the front writes to the operator.

This is not politeness. An endpoint built before this change meets kind 7
in `_control_loop`'s final `else` arm, which logs and **returns** — and
`_forget` then closes every session for that identity. One attach against
an older build would drop the operator's live SOCKS pivots and cost a
reconnect, and nothing in today's `HELLO` lets the server tell. An absent
`features` key reads as "no shell", so an old build is refused rather than
broken.

### The implant (`software/c2/beacon.py`)

- `_control_loop` gains an `MSG_OPEN_SHELL` arm calling `_spawn_shell`,
  which starts a thread exactly as `_spawn_relay` does, including the
  `RuntimeError` arm and the registration in `_relay_threads`.
- `_shell(token, cols, rows)` dials the configured port, registers the
  socket, handshakes with `encode_message(MSG_SHELL, {"token": …})`, and
  serves the session. Its error handling is `_relay`'s: one failed session
  costs that session and is logged, never the endpoint.
- `_serve_shell` opens a PTY with `pty.openpty()`, starts the shell with
  `subprocess.Popen([shell, "-i"], stdin=slave, stdout=slave,
  stderr=slave, start_new_session=True, env=…)`, closes the slave in the
  parent, sets the window size with `fcntl.ioctl(TIOCSWINSZ)` from the
  message, and then bridges.
- **The bridge mirrors `_bridge`/`_to_relay`/`_to_target`** with the
  target socket replaced by the master descriptor: `os.read` instead of
  `recv`, `os.write` instead of `sendall`, `EIO` on the master treated as
  the child having gone. The operator-side half is unchanged, including
  the `_bytes_waiting` peek that keeps an orderly FIN out of the warning
  path. Both directions ending ends the session, as in a relay.
- **Teardown kills the process group**: `SIGHUP` to the group, a short
  grace, `SIGKILL`, then reap. A session whose stream dies must not leave
  a shell running on the target.
- **The shell** is `/bin/bash` when it is executable, else `/bin/sh`.
- **The environment** inherits, then sets `TERM=xterm-256color` and
  `COLUMNS`/`LINES` from the message.
- **History is off after the host's own rc files have run.** `bash -i`
  must read `/etc/bash.bashrc` and `~/.bashrc`, because that is where
  `bash-completion` is sourced and completion is the point. Those same
  files are free to set `HISTFILE`, and on Debian and ParrotOS they are
  the files most likely to. So the shell is started with
  `--rcfile /dev/fd/<n>` on a pipe this process writes: the generated
  rcfile sources the system and user files, then unsets `HISTFILE` and
  runs `set +o history`. Nothing is written to disk. Where `/dev/fd` is
  not available the session falls back to a plain `bash -i` with
  `HISTFILE=/dev/null` in the environment and logs that it did, and the
  documentation claims only what this construction holds: no history file
  on the target unless something re-enables it *after* rc processing.
- **The working directory is `/`**, not the install directory — a prompt
  that names the install path is a free finding.
- **POSIX-only, lazily.** `pty`, `fcntl` and `termios` are imported inside
  the function, so the module stays importable where they do not exist.
  Where they do not, the session writes one line of plain text on the
  stream — the operator is looking at a terminal, so text is the natural
  refusal — and closes.
- **At most four concurrent sessions per endpoint**, refused the same way,
  because fds and threads on a Pi are finite and the beacon already treats
  a thread it cannot get as a condition rather than a crash.

### The tunnel server (`software/c2/tunnel/`)

- `TunnelServer.open_shell_session(identity, cols, rows)`, the sibling of
  `open_session`, sends `MSG_OPEN_SHELL`. One session object serves both
  kinds, with a `kind` field (`"relay"` / `"shell"`) so a status row and a
  log line can tell them apart.
- `_dispatch` gains an `MSG_SHELL` arm. The claim-and-pair body of
  `_serve_relay` becomes shared code taking the kind, and **`_claim`
  checks that the claim's kind matches the session's**: a relay token must
  not pair a shell session, and the reverse must not either.
- **New module `tunnel/shell.py`, `ShellFront`**, modelled on
  `SocksFront` and sharing its helpers rather than copying them —
  `_loopback`, `_credential` and `_positive` become public names in
  `socks.py` and are imported here. Per connection:
  1. accept, counted against `max_pending`, with an absolute deadline;
  2. write one prompt line, read one bounded line, and compare the
     password with `hmac.compare_digest` and with no short-circuit between
     absent and wrong. The line is `<password>` or
     `<password> <cols>x<rows>`; the geometry is optional and defaults to
     120×40. Only a password, no username: the username would be the
     identity, which is not a secret and buys nothing on a raw stream;
  3. `open_shell_session(identity, cols, rows)`, `wait_paired(timeout)`,
     then the two pumps in the shape the SOCKS data path already uses.
  Caps default to four live sessions, matching the implant. Stats and
  refusal counters follow `SocksFront`'s names (`auth`, `capacity`,
  `pending`, `tunnel`, `timeout`, `threads`), because the panel reads them
  generically, plus `unsupported` for an endpoint that advertised no
  `shell` feature.
- **The shell password is a second secret**, minted per identity beside
  the SOCKS pair and never equal to it. Somebody who was handed the SOCKS
  credential for a pivot should not thereby hold a root shell on the host,
  and the two are read from the same panel row, so the separation has to
  be in the mint rather than in how carefully the row is copied.
- **The geometry is set once, at attach, and never tracked.** `socat`
  sends no terminal size and there is no resize channel, so
  `tools/raccoon_shell.py` ships as the recommended attach client: ~100
  lines of stdlib that put the local terminal in raw mode, read the
  password from `RACCOON_SHELL_PASSWORD` or a prompt, send it with the
  local `cols`×`rows`, and restore the terminal on exit. `socat` stays
  documented as the no-helper fallback, with the geometry typed on the
  password line or left at the default. A `SIGWINCH` mid-session is still
  not propagated; the remedy is `stty rows … cols …` inside the session,
  and the helper prints that line on resize so it can be pasted.
- **A second port table.** `shell_ports` beside `ports` in the same state
  document, `_assign_shell_port` beside `_assign_port`, `_STATE_VERSION`
  bumped. A document written by the previous version has no `shell_ports`
  and must load as an empty table rather than an error — that file exists
  on disk at upgrade time. A shell port colliding with any assigned port
  is refused by field name, like every other damaged field.
- **A shell port must never cost an endpoint its pivot.** `_assign_port`
  runs inside `_serve_command`, so a `ValueError` there refuses the whole
  command-channel registration — correct for a SOCKS port, wrong for this
  one. The shell range is therefore an **optional** constructor argument,
  the shell port is assigned only where it is needed, and a row carries
  `shell_port: None` when there is no range or none left. `reconcile` and
  `decorate` tolerate that and say which of the two it is. An exhausted
  shell range degrades the shell feature for that identity and leaves its
  tunnel and its SOCKS port untouched.
- **`tunnel/__main__.py`** takes `--shell-port-first` / `--shell-port-last`.
  **Absent means no shell front is opened at all**, and `status` says so.
  That is the single switch, and it is server-side: nothing opens a root
  shell port because a file mentioned it, which is the reasoning behind the
  listeners' compose profile. `_Fronts.reconcile` opens a `ShellFront`
  next to the `SocksFront` for every connected identity when the range is
  configured; `decorate` adds the shell stats, its password and its detail
  line.

### The team server and the panel (`software/c2/server.py`, `configs/`)

- `tunnel_server_config` learns `shell_port_first` / `shell_port_last`,
  validated like the SOCKS pair and refused by field name when reversed or
  when they overlap the SOCKS range, and passes them to the child.
- `_tunnel_row` passes the new fields through unchanged.
- `drawTunnel` renders, on each endpoint row: `Shell 127.0.0.1:<port>`,
  the shell password, and **two** copy-ready lines, because the panel is
  routinely reached over an SSH forward and the port is on the team
  server, not on the operator's workstation:
  `ssh -L <port>:127.0.0.1:<port> <user>@<c2-host>` and
  `python3 tools/raccoon_shell.py 127.0.0.1 <port>`, with
  `socat -,raw,echo=0,escape=0x1d TCP:127.0.0.1:<port>` named as the
  fallback. Plus one sentence stating that this is a **root shell on the
  implant host**, and that forwarding the port to a workstation extends
  that reach to whatever can reach the workstation's loopback.
- A row whose endpoint advertised no `shell` feature, or that has no shell
  port, renders the reason instead of a port.
- **No new route.** The panel reads `/api/server/tunnel`; the port serves
  itself. Said out loud because "add an endpoint" is the reflex, and here
  there is nothing to POST.
- `configs/raccoon.yaml` gains the two keys in the `c2.tunnel_server`
  block, commented out with the warning, the way the listeners ship off.

### Session transcripts, off by default

The approver asked for recording that can be switched on, so it is one
switch with a path behind it: `c2.tunnel_server.shell_transcript_dir`,
passed to the child as `--shell-transcript-dir`. Absent means no recording
and no directory, and `status` says which it is.

- **What is recorded is the output stream**, implant → operator, byte for
  byte including its escape sequences — a typescript, the same thing
  `script(1)` keeps. It already contains everything the operator typed,
  because the PTY echoes it, so there is no second keystroke log to write
  and no second file to protect.
- **Recording starts at pairing**, which is after the front has read the
  password line. The attach password is therefore never in a transcript.
  Credentials typed *inside* the session are, unavoidably, and the
  documentation says so in those words.
- **One file per session**, `<identity>/<ISO-8601>-<session>.typescript`,
  mode 0600 in a 0700 directory, beside a `.json` sibling carrying
  identity, session number, start and end, the operator's peer, the byte
  counts and whether it was truncated.
- **A per-session ceiling**, after which recording stops, the session
  carries on untouched, and the sidecar records the truncation. A full
  disk on the team server must not be something a long `tcpdump` can
  cause.
- **The panel says when it is on**, on the row, next to the port — a
  recording an operator did not know about is the failure mode here.
  Opening and closing a transcript is also a server log event naming the
  file.
- **Switched on globally**, not per identity: one deployment-wide answer
  to "is this engagement recorded", which is how the question is actually
  asked.

### The Beacon Gen form learns to ask for a tunnel

The approver's answer to question 1 was yes, and reading the route made it
much smaller than it looked: `api_beacon_gen` **already** accepts a
`tunnel` block, validates it field by field in
`_tunnel_config_for_build` — refusing a supplied `psk`, `identity` or
`public_key`, a `server` that is a URL or carries a space, a `port`
outside 1–65535 — mints the identity and PSK, registers them, and already
returns `tunnel_identity`. The gap is in the form alone, which posts no
`tunnel` key, and in the result, which drops the identity it is handed.

So:

- A **Tunnel section** in the Beacon Gen form: an enable checkbox that
  reveals `server` (bare host or IP, with the refusal's own wording as the
  placeholder), `port`, `keepalive_seconds` showing the endpoint's own
  default, and `allow_slow_crypto` with a one-line warning that it selects
  the pure-Python cipher at roughly 50–200 KB/s.
- **Both delivery paths send it.** `runBeaconGen` and `runBeaconGist`
  build their own bodies, and `api_beacon_gist` runs the same
  `_beacon_gen_config`; a tunnel block wired into only the first would
  silently vanish when an operator picks gist delivery.
- **The result shows `tunnel_identity`**, labelled as what it is: the key
  of the SOCKS and shell port tables, the SOCKS username, and what you
  delete to retire the build.
- **Client-side validation mirrors the route's refusals** rather than
  inventing its own, so the two cannot drift: an empty or URL-shaped
  server and an out-of-range port are caught before the request, and
  anything else is the route's 400 shown as it came.
- `docs/TUNNEL.md`'s *Asking for a tunnel, which the Beacon Gen form
  cannot do yet* section shrinks to `drops` and the stager fields, which
  are still only reachable by `curl`.

### What a test must fail on

- **Codec:** both kinds round-trip; an unknown kind is still refused;
  `protocol.py` re-exports every new name and its `__all__` agrees;
  `HELLO` carries `features` and a body without it still decodes.
- **Capability gate:** an endpoint whose `HELLO` advertised no `shell`
  feature is refused by the front with a readable reason, and **no
  `MSG_OPEN_SHELL` is sent** — the test holds that by asserting on the
  command channel, because the failure it prevents is a dropped channel
  and lost SOCKS sessions.
- **Implant:** `MSG_OPEN_SHELL` produces a PTY and an `echo` round-trips
  through it; EOF on the stream leaves no child behind, checked by pid;
  the fifth concurrent session is refused in text; a host without `pty`
  gets the written refusal; a relay token cannot claim a shell session,
  nor the reverse; the generated rcfile leaves no file on disk and the
  session has history off after a `~/.bashrc` that sets `HISTFILE`.
- **`ShellFront`:** a non-loopback bind is refused; no password and a
  wrong password are both refused and counted under `auth`; the right one
  pairs; a password line with `<cols>x<rows>` sets the size and one
  without it takes the default; the shell password is not the SOCKS
  password; capacity refuses with its own counter; `stop()` drops a live
  session.
- **Port table:** a shell port survives a restart; a collision is refused
  by field name; a pre-upgrade document loads; **an exhausted or absent
  shell range leaves the endpoint's registration and its SOCKS port
  intact**.
- **Config and supervisor:** no range means no front and a status that
  says why; an overlapping or reversed range is refused by field name.
- **Panel:** a row with a shell port renders port, password, the forward
  line and the attach line; a row without one renders the reason; a row
  shows the recording badge when transcripts are on and not when they are
  off.
- **The attach client:** it sends the password and the local geometry, and
  restores the terminal when the stream ends.
- **Transcripts:** off by default writes no file; on writes the
  typescript 0600 in a 0700 directory with its sidecar; the attach
  password appears in neither; the ceiling stops the recording, leaves the
  session running and records the truncation.
- **Beacon Gen:** a form with the tunnel enabled posts a `tunnel` block
  the route accepts and the response's `tunnel_identity` is rendered; the
  gist path posts the same block; a URL-shaped server is refused before
  the request; a form with the tunnel disabled posts no `tunnel` key at
  all.

### Documentation

- `docs/TUNNEL.md` gains a *Shell session* section: what it is, the one
  switch, the attach command and the SSH forward in front of it, the
  facts an operator needs (root, geometry set once, history off after rc
  processing and what that does not cover, whether transcripts are on and
  what a transcript holds), that it needs a tunnel-enabled build whose
  endpoint advertises the feature, and the detection indicators it leaves
  — a `bash` child of a `python3 -` process, a PTY on the host, and a
  second connection on the same outbound port. Its *Asking for a tunnel*
  section shrinks to `drops` and the stagers.
- `README.md` gains a line in the capability table, and the Beacon Gen
  row no longer has to say the form cannot ask for a tunnel.
- Nothing goes into *Known limits* in `docs/AGENT.md`: that list is the
  agent layer's, and the agent is deliberately not given this.

---

## Decisions

The approver answered both open questions on 2026-11-11: **the Beacon Gen
form learns to ask for a tunnel in this pass** — a separate build route
for a shell session would be the wrong shape — and **transcripts are
switchable**. Both are designed above.

These were mine, and are the ones to check while reading:

- **One switch for the shell, server-side.** A build-side flag was
  considered and dropped: the command channel is already
  PSK-authenticated and the server is ours, so a second switch is friction
  without a property.
- **`HELLO` carries a `features` list**, so that asking an old endpoint
  for a shell refuses instead of dropping its command channel and its live
  SOCKS sessions. Cheap now, awkward to add later.
- **The shell password is a second secret**, not the SOCKS one.
- **Geometry is sent on the password line and set once**, and
  `tools/raccoon_shell.py` ships so that the normal path sends the right
  size without the operator thinking about it.
- **History is held off by a generated rcfile on `/dev/fd`**, not by an
  environment variable the host's own `~/.bashrc` can undo, and the
  documented claim is exactly what that construction holds.
- **An absent or exhausted shell port range degrades the shell and
  nothing else** — never an endpoint's registration or its pivot.
- **A transcript records the output stream only**, because the PTY's echo
  already puts the operator's input in it, and a second file holding
  keystrokes is a second file to protect.
- **`cwd=/`**, four concurrent sessions on both ends.

## Left to the builder

- The exact reuse of the relay pumps versus two small variants, thread
  names, and log wording.
- Whether the shared `socks.py` helpers become public names there or move
  into a small module of their own — either is fine; no copies.
- The precise refusal texts and the numbers behind the session cap, the
  auth deadline and the `SIGHUP` grace, within the shapes above.
- The panel's markup.
- The transcript's per-session ceiling and the sidecar's exact field
  names.
