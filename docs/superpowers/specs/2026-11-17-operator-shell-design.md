# A dedicated operator shell on the hardware implant — design

**Date:** 2026-11-17
**Status:** for approval

---

## Intent

One terminal, reached from the team server's header, onto the operator's own
hardware implant. Full fidelity: `msfconsole`, `vim`, colours, a resizable
pty — the ParrotOS arsenal, used the way it is used on a console.

It is **not** a per-agent feature. Lateral movement keeps the task-based
`shell` command it has today. This is the operator's own planted device, and
there is one of it.

## Why

The mechanism is already complete and the path to it is not. Reaching that
shell today means knowing that a tunnel exists at all, typing `tunnel start`
into a command line that never advertises it, waiting without being told
how long, opening the tunnel panel, reading a port and a password out of a
card, leaving the GUI, forwarding a port with `ssh -L`, and running
`tools/raccoon_shell.py`. Every step of that is documented and correct. The
operator still will not find it.

Measured, in a running server, before any of this was designed: the
endpoint connects, reports `features: ['shell']`, and the panel prints the
attach command. Nothing in the agent console mentions it.

## Goals

- A terminal glyph in the header opens the session. **Nothing happens until
  the operator triggers it**, by the operator's explicit decision: no
  channel is dialled, no task is queued, nothing stands by.
- The session is a real pty: redraw, colours, raw keys, and a geometry
  chosen when it opens. **Not** a geometry that follows the window — see
  "Geometry is fixed at open" below, which corrects an overclaim in the
  first draft of this document.
- The channel exists only while the operator wants it, and closing it does
  not depend on the browser surviving.
- The view never reports a state it has not got. "Closing" and "closed" are
  different words because they are different facts.

## Non-goals

- Per-agent shells. The agent console's command line stays exactly as it is.
- Any change to the shell wire protocol, `ShellFront`, the Noise handshake,
  the record format, or the transcript format.
- Replacing `tools/raccoon_shell.py`. It stays the documented client, and
  the `socat` fallback stays documented too.
- Replacing the tunnel panel. It remains the place where the tunnel server,
  the SOCKS ports and every endpoint are managed.
- Starting the shipped `raccoon-tunnel.service`. `install.sh` does not
  install it today and this work does not change that.

## Anti-goals

These would make the work a failure even if every test passed.

- **A channel left open on the device while the operator believes it
  closed.** This is the one outcome that costs more than the feature is
  worth. Every lifecycle decision below is made against it.
- **Making the beacon noisier to feel faster.** `sleep 10` would turn a
  five-minute wait into seconds and the beacon into something that knocks
  every ten seconds. Ruled out explicitly; the interval is never touched.
- **A spinner where a number belongs.** A spinner invites the operator to
  help it along. The wait is the price of staying quiet and is shown as
  what it is.
- **A green pill that was not measured.** The panel already carries the
  scar: it "used to state root for every row", and the user is now read
  from a HELLO field because guessing there was an overclaim.

## Constraints

All measured in this repository, not assumed.

**There is no streaming anywhere in this GUI.** No WebSocket, no SSE. The
console polls `/api/agents/<id>/history` every 2000 ms (`server.py:4521`).
The operator socket is served by `make_server(..., threaded=True)`
(`server.py:9769`), so one thread per connection: a long-lived response is
possible.

**`/static` exists and vendoring is possible.** `software/c2/static/` holds
`agent.js` (67 KB), `agent.css`, favicons and `wallpaper.jpg` (2.3 MB),
served by a `/static/<path:filename>` route (`server.py:902`). File size is
no taboo here. No third-party JavaScript is vendored yet; this would be the
first.

**The shell port is loopback-only, by refusal.** `_SHELL_HOST =
"127.0.0.1"` and "`ShellFront` refuses a non-loopback address for itself as
well" (`tunnel/__main__.py:94`). It is a port on the *team server*, which
is where the Flask process also runs — so the bridge is a local connection
and no forwarding is involved.

**The wire is a prompt, a line, then raw bytes.** `password: `, then
`<password>` or `<password> <cols>x<rows>`, and the geometry is taken off
only when the tail is entirely a geometry, so a password containing a space
needs no quoting (`tunnel/shell.py:29-43`). Defaults 120x40, clamped to
1000 (`beacon.py:1266-1268`). Caps: 4 sessions, 8 pending,
`handshake_timeout` 15 s.

**Starting and stopping the channel are beacon tasks.** Not API calls
against the tunnel server: "the only way to start or stop one is to task
the agent that runs it -- which happens at its next check-in, up to a whole
interval away" (`server.py:1349`). The builder's default interval is 300 s
(`server.py:5446`), the beacon's floor is 10 s (`beacon.py:4840`).

**Cutting the TCP from the server side does not close a channel.** The
endpoint "blocks until `stop()`, reconnecting on the beacon's backoff"
(`beacon.py:3503`). A dropped connection is redialled.

**Two tasks can land in one check-in.** `caps = ["batch", ...]` is reported
by every current build (`beacon.py:5169`) and `BATCH_MAX = 8`
(`server.py:159`), so `batching` is on (`server.py:3203`).

**The build must carry a tunnel block.** It comes from a builder checkbox,
"Carry a tunnel: SOCKS and shell ports back through this build"
(`server.py:5480`). Without it `tunnel start` refuses by name. This feature
cannot add what is missing from the artifact. *(Confirmed with the user:
the implant in question was built with it.)*

**Privileges follow the start path.** `install.sh` installs
`raccoon-implant.service` and `raccoon-beacon.service`, both `User=root`,
and does **not** install `raccoon-tunnel.service`, which is `User=nobody`
with an empty `CapabilityBoundingSet`. A beacon-spawned tunnel child is
therefore root, and the arsenal works. The unit path would not run
`responder` or `nmap -sS` at all.

**The session's own hygiene is already built.** `unset HISTFILE` and
`set +o history` **after** the rc files, because those files are what set
`HISTFILE` on Debian and ParrotOS (`beacon.py:3196-3229`). The tunnel child
is started as `python3 -` with its source on stdin — nothing on disk, no
payload in `/proc/<pid>/cmdline` — with stdout and stderr to `DEVNULL`
(`beacon.py:7101`, `7148`). bash-completion is loaded deliberately, because
"completion for the tools on the target is the whole reason for using the
target's own shell".

**Transcripts are on the team server**, one
`<identity>/<when>-<n>.typescript` 0600 in a 0700 directory with a `.json`
sibling, and recording is **off** unless a directory is configured — "one
answer for the whole deployment rather than one per identity, because 'is
this engagement recorded' is how the question is actually asked"
(`tunnel/shell.py:390`).

**There is no task withdrawal.** No route removes a queued task; the queue
is drained by the dispatcher.

## Approaches

### The shape in the interface

Three were drawn as mockups and the operator chose from them.

1. **A sticky card** floating over the console, one per agent, surviving a
   view change. Rejected: this project has no floating windows anywhere, so
   dragging, resizing and stacking would all be new, for the largest build
   of the three.
2. **A dedicated view with a tab per agent**, opened from the agent
   toolbar. **Chosen**, then narrowed: the operator does not want this per
   agent at all. The tabs are gone and the entry point moved from the agent
   toolbar to the header, next to the listener, builder and tunnel glyphs.
   One target, one session.
3. **A mode switch on the existing command line** (`repl` turns it live).
   Cheapest to build and rejected on judgement: two modes on one input is
   how a keystroke lands on the wrong machine, and the line would also have
   to stop being task-paced to feel like a shell at all.

### How the browser gets a terminal

1. **A line-oriented terminal, nothing vendored.** Output over a streaming
   response, input per line. Handles `nmap`, `responder`, pipelines. Cannot
   handle `msfconsole`, `vim`, `top`, or a hidden-echo prompt. Rejected:
   the arsenal this exists for includes full-screen tools.
2. **`xterm.js` vendored, output streamed, keystrokes POSTed.** **Chosen.**
   A real terminal with no new Python dependency. First vendored
   third-party file in the project, pinned as a file with its version and
   hash recorded rather than as a package-manager entry — "nothing is
   pinned" is an open finding in `AGENT.md` and this must not add to it.
3. **`xterm.js` plus a real WebSocket** (`flask-sock`). Lowest latency and
   the cleanest bidirectional stream, rejected for the Python dependency:
   on a loopback bridge the latency it buys is not perceptible.

### The channel's lifecycle

The operator's decision is: the channel opens only on an explicit action
and closes when the session ends. No standing connection, smallest
footprint.

1. **An idle-timeout watchdog**: close after N seconds without a session.
   Rejected: a timeout cannot tell "the operator paused" from "the browser
   is gone", and those deserve opposite answers. It also invites an
   invented number.
2. **A claim plus the counter-task.** **Chosen.** The server queues
   `tunnel stop` itself when the session ends or the browser's claim lapses
   — so a browser that dies cannot leave a channel behind, because it was
   never the thing responsible for closing it. An operator who comes back
   before the check-in queues `tunnel start` again; with `batch` both land
   in the same check-in, stop then start, and nothing is lost. This needs
   no grace period and no task withdrawal.

## The design

### The entry point

A terminal glyph in the header, in the existing `.topbar-ico-btn` pattern
(`server.py:4230`), opening a view in the manner of the listener and tunnel
drawers. It queues nothing on hover, on open, or on page load: the channel
is dialled only when the operator presses the button in the view that says
it will.

### The target

The agents whose build carries a tunnel block are the candidates. With
exactly one, it is preselected and the view says which host it is. With
several, the operator picks and the choice is remembered. *(My call, not
discussed: there is one such device in the case that motivated this, and a
picker that appears only when it is needed costs nothing.)*

### The four states

**Wait.** The task is queued. The view shows the host, the expected
check-in as a count-down — the API already returns the expected time
(`server.py:1349`) — and the interval and jitter it is derived from, with
the explicit statement that the interval is not being changed. No cancel
button: there is no task withdrawal in this server, and a button that
cannot do what it says is worse than its absence.

**Live.** A strip above the terminal carries the host, the user as reported
by HELLO, a root marker when that is what it is, whether the session is
being recorded, and the channel's state. The terminal's first line states
that history is off in this session — a claim the code backs
(`beacon.py:3228`).

**Closing.** `exit`, or the view being closed, queues `tunnel stop`. The
strip says *closing*, with the expected check-in. This is the state the
first mockup got wrong by printing "stop acknowledged" at the moment of
`exit`, when the channel in fact stands until the beacon picks the task up.

**Closed.** Only when the stop is acknowledged at a check-in. The view says
what remains: the session's duration, and the transcript's path when
recording was on.

### The bridge

One streaming response per session carries the pty's output; keystrokes
arrive by POST, batched. The Flask process opens the TCP connection to
`127.0.0.1:<shell_port>` itself and sends `<password> <cols>x<rows>`.

**The shell password never leaves the server.** The browser authenticates
with the operator token it already holds; the password is read from the
supervisor's status server-side and goes onto the socket. No response body
may contain it.

### What this does not touch

`ShellFront`, the wire format, the geometry clamp, the session caps, the
transcript format, `raccoon_shell.py`, the `socat` fallback, the tunnel
panel, and the beacon — except that the beacon is tasked with `tunnel
start` and `tunnel stop`, which is what those tasks are for.

### The three rules the operator decided

The builder check surfaced three places where a wrong guess would have been
operationally expensive. All three were answered by the operator.

**One child serves both ports, so the stop is not unconditional.**
`tunnel start` and `tunnel stop` control a single child process
(`beacon.py:7087`, one `_tunnel_proc`) carrying both the SOCKS port and the
shell port. An unconditional stop would therefore drop a live pivot,
including one raised from the tunnel panel for something else entirely.

The rule: **this view stops only a channel it started itself, and only when
the port reports no live SOCKS session.** Otherwise the channel is left
standing and the view says why. Ownership is part of the claim, not
inferred from the channel's existence.

**The glyph may start the tunnel server, because that costs the implant
nothing.** As shipped, `c2.tunnel_server.enabled` is `false` and the shell
port range is commented out in `configs/raccoon.yaml` — and that absence is
the feature switch (`tunnel/supervisor.py:91`). Read strictly against the
non-goal, the glyph would answer "go and open the other panel first", which
is the detour this work exists to remove.

The rule: **the view may start the tunnel server process.** That process
runs on the team server, not on the target, so starting it has no footprint
on the implant at all — which is why this does not conflict with the
minimal-footprint decision. It does **not** edit the configuration file: a
missing shell port range is named as the reason, and changing it stays with
the panel and the file.

**A team-server restart must not leave a channel behind.** The claim in
module state does not survive a restart. `stop_all()` kills the tunnel
server child while the implant's endpoint keeps redialling on the beacon's
backoff (`beacon.py:3503`), so a restart between the start and the stop
would leave a channel open on the device with nothing left that would ever
queue the stop. That is this document's anti-goal, reached by an ordinary
operator action.

The rule: **ownership is persisted and reconciled at start-up.** A small
marker — which agent's channel this view owns — is written where the claim
is taken and read when the server starts; a channel found owned with no
live claim gets its stop queued. No identity needs storing: the beacon
reports its tunnel's state in its own check-in (`beacon.py:5309`), so
start-up only has to know whose channel this was.

## Decisions made after the builder check

A fresh engineer read this document against the code and asked eight
questions. Three went back to the operator and are answered under "The
design". These five are mine, and they are marked as mine because nobody
agreed to them.

### Geometry is fixed at open

The first draft promised "a resizable pty". **That was wrong, and the code
says so.** The geometry rides once on the auth line, `MSG_OPEN_SHELL`
carries `cols`/`rows` once, and the endpoint does one `TIOCSWINSZ` at spawn
(`beacon.py:4308`). `tools/raccoon_shell.py` already states it: *"The size
is sent once and cannot be renegotiated"*, and it answers `SIGWINCH` with a
note to the operator rather than a lie.

So: the terminal opens at the size the view has at that moment, the strip
states that geometry, and a window resize produces the same kind of note
the existing client gives — not a silent mismatch between what xterm.js
draws and what the pty believes. Changing the wire to renegotiate is a
non-goal; a fit-addon that resizes the canvas alone would make the pty's
geometry a quiet fiction, which the "never reports a state it has not got"
goal forbids.

### The Closed state names the directory, not the file

The transcript's filename carries a per-port session counter known only
inside the tunnel server child, and `ShellFront.stats()` has no path field
(`tunnel/shell.py:762`). Plumbing one through is a change to `ShellFront`,
which is a non-goal. Closed therefore says that the session was recorded
and under which directory, and the operator finds the newest file there.

### The claim is refcounted, and it only counts this view's sessions

The port's cap is four sessions, and one of them may be a terminal attached
with `raccoon_shell.py` or `socat` — both of which stay documented. A
single claim would tear the channel out from under such a session. So: the
claim counts the sessions this view holds, and the stop is queued when the
last of them ends, not the first.

### The agent↔identity link is learned, not looked up

There is no mapping from an agent to its tunnel identity while the channel
is down: the identity is six random bytes unrelated to the agent
(`server.py:252`), and `channel.implant_id` exists only while the endpoint
is connected (`tunnel/server.py:618`). So the view does not pre-filter
candidates by inspecting builds. The operator designates the device once
and that designation is remembered; the identity and the shell port are
read from the supervisor when the endpoint connects, which is the only
moment they exist and the only moment they are needed.

The cost is honest and stated in the view: on a build with no tunnel block,
the refusal arrives with the beacon's answer at the check-in, not before
it. The alternative — recording identity↔implant_id at generation — is new
persisted fleet state for a message that is one interval late, and that
trade is not worth it for a device the operator designated themselves.

### "The password never leaves the server" scopes to the new routes

The tunnel panel already puts `shell_password` on the endpoint row
(`tunnel/__main__.py:471`), deliberately and with a documented reason:
`raccoon_shell.py` needs the operator to read it. Keeping both the panel
and that client is a non-goal of changing them. The rule therefore reads:
**no response body belonging to this feature's routes may contain the
password.** Removing it from the panel would be a separate change with its
own document.

## What is left to the builder

- **The streaming mechanism**: a chunked response read with `fetch` and a
  `ReadableStream`. `EventSource` is ruled out and not by taste — the
  operator socket authenticates by `Authorization` header only
  (`server.py:880`), `EventSource` cannot send one, and a token in a URL is
  forbidden by a test (`test_docs.py:424`). Prove the framing against the
  real `make_server(threaded=True)`, not the Flask test client.
- **The route's socket**: the new routes must stay off the agent socket.
  The `_AGENT_SOCKET_ENDPOINTS` allow-list already does this by omission;
  confirm it rather than assume it.
- **The vendored file**: which `xterm.js` release, and recording its
  version and hash where a reader will find them.
- **The keystroke batching window**, and the claim's heartbeat cadence —
  the existing 2000 ms poll is the obvious thing to ride.
- **Where the claim lives**: module state beside `agents` and
  `task_queues`, with the same lifetime.

### The tests that matter

Ordered by what they protect, not by what is easy.

1. The stop is queued when the browser never comes back. This is the
   anti-goal; it is the first test.
2. "Closing" is never rendered as "closed", and "closed" appears only after
   an acknowledged stop.
3. No response body on the operator socket contains the shell password.
4. A build with no tunnel block produces a named reason in the view, not a
   spinner and not a silent failure.
5. The interval is never written by this feature — no path from the view
   sends `sleep`.
6. Two sessions cannot be opened onto one channel beyond the port's cap,
   and a refusal arrives as text on the stream the operator is watching,
   which is where `ShellFront` already puts it.
