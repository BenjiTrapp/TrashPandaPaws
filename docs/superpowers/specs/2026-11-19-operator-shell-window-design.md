# The operator shell as a window, not a modal

**Date:** 2026-11-19
**Branch:** `feat/operator-shell` (PR #9), on top of the merge with `main`
**Status:** implemented, Tasks 1–6, commits `0e05888..9fe7b93`. Part two
below was built afterwards, on `feat/opshell-login-shell`, in six tasks of
its own; the sections of it that the build changed say what was built beside
what was proposed. Builder-checked once
before the work began, and the corrections that check produced are folded
in and marked; the corrections the *implementation* produced are folded in
the same way, beside the statement each replaces, and what it could not do
is *Known limitations, as built* near the end. **Why now** describes the
code as it stood before the change, and its line references are that
code's — the `pagehide` listener it cites no longer exists.

## Why now

The operator opened a shell, attached, and the shell died. Measured against
the live tunnel with the container endpoint, in this order:

| What was measured | Result |
|---|---|
| `opshell.Bridge` against the real shell port 19630 | the container's own prompt, then quiet; `read` hits its timeout, which the pump treats as "still open" |
| `/open` + `/stream` server-side | the stream was still open after 120 s |
| attached in a browser | the terminal drew the real prompt and lived **2 min 41 s** |
| then: **only reloaded the page** | `POST /api/opshell/close`, `sessions: 0` |

So the shell does not die on its own. **Its lifetime is bound to one page
load.** `window.addEventListener("pagehide", ...)` (`server.py:10936`) posts
the close, and `pagehide` fires on a reload and on any navigation, not only
on a closed tab. That listener was the fix for a Critical finding in the
fourth review — "a closed tab must not leave the channel up" — and the
reasoning was right while the implementation was too coarse: it treats *the
page is going away* as *the operator is finished*, and those are different
things.

A second measurement explains why a live shell also *looks* dead: the
terminal is a fixed 120×40 at 12 px, about 840 px wide, inside
`.loot-panel.panel-wide` — 900 px with 20 px of padding, so an **860 px
content box**. The first line is cut mid-word, a horizontal scrollbar
appears, and 39 blank rows sit below a single prompt. The 120×40 is not
even a server fact: `state.geometry` is `None` until a bridge exists, so
`opshellAttach`'s `(state.geometry||[120,40])` is the view's own guess sent
back to itself.

And one more, which decides how far this can go:

| | session 1 | after the bridge closed, session 2 |
|---|---|---|
| shell pid | 75 | **78** |
| working directory | `/etc` | **`/`** |
| a variable that was set | `ichbinsitzung1` | **empty** |

The bridge's TCP connection **is** the shell. When it closes the pty dies,
and a new connection gets a fresh `bash`. Today `cleanup()` closes the
bridge as soon as the HTTP stream ends (`server.py:2160`, wired by
`answer.call_on_close(cleanup)` at `:2213`), and `Bridge.connect` refuses
to reconnect by contract ("a bridge connects once; make another",
`opshell.py:753`).

## Intent

The operator wants to work in this shell for an hour, keep it while doing
something else in the interface, put it away without losing it, and end it
deliberately — the way a window behaves.

## Goals

- A reload or a navigation no longer ends the session.
- The shell is a **card in the content column**, with the agent list still
  visible beside it.
- `_` minimises it and the shell **keeps running**; `✕` ends the session.
- Minimised, it parks as a card under the agent list with the `>_` glyph
  and a red border; a click brings it back.
- A reload **restores the card and reattaches**, saying in the terminal
  that this is a new shell and the previous one is gone.
- The terminal's size comes from the space it actually has.

## Non-goals

- **More than one card per page.** This is one terminal onto the operator's
  own device; lateral movement keeps the task-based `shell`.
- **Dragging and free resizing.** Not asked for, and a resizable card would
  make the terminal's size a fiction: the wire sends the geometry once and
  cannot renegotiate it (`tools/raccoon_shell.py:38`). The card fills the
  content column and the geometry is measured once, when the session opens.
- **A shell that survives a reload.** Chosen against: it would mean the
  server keeps the bridge — and therefore a live pty on the device — with
  nobody watching, plus a ring buffer for the output in between. New server
  state, against the small-footprint principle. A reattach is a new shell
  and says so.

## Anti-goals

The feature's standing anti-goal holds: **a channel left open on the device
while the operator believes it closed.** This change moves one of its
guards, so it is stated plainly:

- Before this change, a closed tab ended the session **immediately**, via
  `pagehide`.
- Since it, a closed tab ends the session through the **lapse**: the claim
  goes silent and the next check-in retires it, bounded by
  `opshell.LAPSE_GRACE` (240 s, `opshell.py:111`) plus one interval.

The bound is one interval and not two for a reason the builder check
established: `opshell_sweep()` runs **before** `_handle_beacon`
(`server.py:3696` vs `:3705`), so the check-in that notices the lapse is
the same one that carries the stop.

That is a real loosening, approved with the trade on the table. It is
acceptable because the lapse is implemented, driven from both `/state` and
the check-in, and covered (`test_a_check_in_retires_a_claim_no_browser_is_
behind`, `test_a_check_in_does_not_retire_a_tab_that_is_merely_throttled`).
The guard being removed was the *faster* of two; the slower one stays. And
the restore-on-load below buys most of it back: an operator who reloads and
walks away finds the parked card on their next look.

A second anti-goal, from the view's own rules: **the card may never look
alive when the session is gone.** A minimised card whose session ended says
so rather than sitting there as if it were working.

## Constraints

- The geometry is fixed when the session opens. The strip states the pair
  that was sent, and nothing else.
- `pagehide` cannot tell a reload from a closed tab, and no browser signal
  can. The distinction is not detected; it is made irrelevant by not acting
  on `pagehide`.
- A reload gives a **new** shell. The view says so, or it is the lying
  interface this feature exists to avoid.
- **The browser baseline, honestly.** The page's JavaScript is roughly
  2020 (164 uses of `?.`, the Clipboard API) and its CSS already goes to
  **flexbox `gap`, which is Safari 14.1** — 95 `gap:` declarations,
  including the opshell strip's own. So the baseline is Safari 14.1, not
  13.1, and the test that polices it
  (`test_no_browser_feature_newer_than_the_page_is_used_unguarded`) names
  exactly four JavaScript identifiers and says nothing about CSS. My
  earlier claim that "there is a test for this" was wrong in scope: new CSS
  gets no warning, so `:has()`, `aspect-ratio` and `replaceChildren` are
  out by judgement, not by a guard.
- The layout: `#app` is a flex column (`:4253`); `.main` is a flex row
  (`:4278`) holding `.sidebar` (260 px, flex column, `:4281`) whose
  `.agent-list` is `flex:1` (`:4289`), and `.content` (`:4306`).
- **`refreshAgents` rebuilds `#agent-list.innerHTML` every 3 s**
  (`:5453`). Appending the minimised card to `.sidebar` *after* the list is
  the only placement that survives, which is also where the operator
  pointed. This needs a comment in the code, or the next person tidies it
  into the list and it vanishes within three seconds.
- **`renderAgentView` overwrites `#content.innerHTML` on every agent
  click** (`:5522`), and the design wants the agent list visible and
  therefore clickable.
- Behavioural properties of this view are named individually in
  `test_the_count_of_behavioural_tests_has_not_quietly_dropped` and may not
  lose their tests. Seven were named when this was written, with a floor of
  35 against 43 present; the work took that to **eleven named** and a floor
  of **90 against 92**.

## Approaches considered

**A — the sticky card; a reload restores and reattaches to a fresh shell.**
Browser-side only. While the page lives the shell runs, minimised or not. A
reload ends the pty, and the restored card attaches a new `bash`; the claim
and the channel survive, so the operator loses the session and not the
tunnel. **Chosen.**

**B — the bridge outlives the stream, so a reload finds the same shell.**
Rejected: a live pty on the device with nobody watching, plus new server
state and a ring buffer.

**C — keep the modal, only fix the sizing.** Rejected: a modal over a
dimmed fleet is not a place to spend an hour, which is what it is for.

## What this looks like

### The card, open

A **flex sibling of `.content` inside `.main`, with `.content` hidden**
while the card is there. That replaced "a layer over `.content`" during
execution and keeps its reason: `.main` is a row spanning the 260 px agent
list as well, so a layer with `inset:0` over it would cover the list this
layout exists to keep clickable, and two `flex:1` siblings would split the
column in half. A hidden `#content` keeps its children untouched, which is
the point of the decision below. A header row with the `>_` glyph, the
device's name (`Operator Shell` until the first `/state` answer names the
host), and `_` and `✕` at the right; under it the strip that already exists
(host, user, a `root` marker only when the endpoint reported one, the
geometry that was sent, recording, channel state); then the terminal,
filling the rest; then the line about how the session ends. That line was
to be carried over verbatim, and the final review found it could not be:
it said "closing it queues the channel's shutdown" in a card whose two
buttons are a `✕` that closes and a `_` that does not, so it names the
`✕` now and says what the `_` does instead. The terminal's own opening
lines carry what only it can say: the host, what history will do in this
session (off, or only not guaranteed off, or nothing at all, as part two
built it), the pair
that was sent — and, when the measurement fell back, that this session is
not fitted to the card and why.

The agent list stays visible to its left, so an agent going offline is
visible while working — which matters here, because a channel that drops is
the operator's own way in.

### The card, minimised

Appended to `.sidebar` after `.agent-list`, so it sits at the bottom:

- the `>_` glyph, as in the header
- a red border — and **visibly not an agent row**: full width, the glyph,
  no status dot. `--red-dim` is specifically the border of the *selected*
  agent card (`.agent-card.active`, `:4295`), so without that
  differentiation a parked shell reads as another selected agent.
- the device's name and the channel's state in the sidebar's small type
- a `<button>`, not a div with an `onclick`: the header glyph was already
  corrected from stray text to a button once (`ca65f70`). As built it is a
  row of two real buttons, because a button cannot nest one: the restore
  takes the whole row, and the `✕` that dismisses a remnant is its own
  button beside it

While minimised the poll keeps running, so the claim keeps beating, the
stream stays attached, and output keeps arriving in the terminal's buffer.
Restoring shows what arrived.

### The card, when the session ended while minimised

It says `session ended` with the duration, drops the live border, and
carries the `✕` that dismisses it. This is the second anti-goal. The
duration comes from `opshellLast`, which `opshellEndSession` stashes
(`:8861`) and the poll folds over an `idle` answer (`:9025`) — so the poll
must still be running when the session ends while minimised, and the
dismiss path must not clear `opshellLast` before the duration has been
shown (`opshellTeardown` clears it, `:8924`).

### After a reload

The session id is kept in the tab's `sessionStorage`. On load, if the
server says `live` and reports at least one session for the claim, the card
comes back as it was — open or minimised — and attaches. *At least one*,
and not *this one*: the state body carries a count, which is the first of
the known limitations below. The terminal says, among its opening lines and
in the same dim style as its other notes, that this is a new shell and the
previous one is gone.

## Decided here, by me, and marked as such

- **The open card is a layer over `.content`, not a replacement of its
  children.** `renderAgentView` writes `#content.innerHTML` on every agent
  click, and the design wants that list clickable; without the layer one
  click detaches the xterm host under a live stream — the same defect class
  as `test_a_failed_poll_does_not_destroy_a_live_terminal`, reached by a
  click instead of a blip. **As built it is a flex sibling with `.content`
  hidden rather than a layer over it** — ruled before Task 4, for the
  reason in *The card, open* above. The decision is unchanged, because what
  it was about is the children: a hidden column keeps them, and still shows
  the last-clicked agent when the card goes away.
- **Minimising hides the card in place; it does not take it apart.**
  `opshellPoll` returns when `#opshell-body` is missing (`:8968`), and that
  poll *is* the claim's heartbeat. Taking the card apart would let the
  240 s lapse fire under a parked session — precisely the failure the
  branch's most-defended test exists to prevent.
- **The geometry is measured with a probe element**, divided into the
  card's inner box, floored at 20×5 and capped at `SHELL_GEOMETRY_MAX`
  (1000). Not "xterm's own measurement before `open()`", which my first
  draft offered and which does not exist in this build (no fit addon, by
  design). **Two rounds changed what the probe is**, and the result is what
  landed: it is an `inline-block` holding a 32-character run whose rect
  width is divided by 32 — the vendored library's own
  `.xterm-char-measure-element`, declaration for declaration, so the probe
  and the thing it sizes agree by construction rather than by measurement
  on whichever fonts anyone could test. And its font is the **resolved**
  `--mono` stack, not the custom property: the library prefers an
  `OffscreenCanvas` strategy whose `ctx.font` cannot resolve one and
  silently measures 10 px sans-serif instead, so the stack is read once
  from the computed style and handed to both the terminal and the probe.
- **The strip shows no geometry until the stream is up.** `state.geometry`
  is `None` before a bridge exists and is pinned that way
  (`test_with_no_session_live_there_is_no_geometry_to_report`). Showing the
  measured pair pre-attach would be a second source, which is how a strip
  ends up stating a pair that was never sent.
- **`#opshell-body` stays the single element `opshellRender` fills.** About
  fifteen node tests set it and read `.innerHTML` back, and two refusal
  paths write into it. The card's header and controls sit *outside* it.
- **The `✕` is not wired as `onclick="opshellEndSession()"` from
  `opshellRender`.** `test_a_live_channel_with_no_local_session_offers_both_
  controls` asserts that string is absent from the render, to keep the inert
  handler off a button. The card's controls get their own function.
- **`✕` asks nothing.** The panel's text already says what ending costs.
- **"Only `✕`" means only among the window controls.** `exit`, Ctrl-D, a
  stream that ends, a refused stream and a failed fetch all still end the
  session, each pinned by a test. My first draft said "and only `✕`", which
  was wrong and contradicted its own footer line four lines later.

## Left to the builder

- The exact red, from the existing variables, given the differentiation
  requirement above.
- Whether the restored card reattaches immediately on load or after the
  first `/state` answer confirms the session is still held. Both are
  honest; the second avoids a stream request that cannot succeed.
- Where the minimised flag lives: page state, as a module-level
  `let opshellMinimised = …` — it must be a single-line `let opshell… = …`
  or the harness's `decls` regex (the `re.findall(r"^let opshell\w+ = .*$")`
  in `_node`, `test_operator_shell.py`) will not lift it, and the server
  must not learn what "minimised" means.

**As built**, all three: the border is `--red-dim`, told apart from a
selected agent by spanning the sidebar edge to edge with no radius, by the
glyph, by its monospace and by having no status dot; the resume asks
`/state` first and draws the card only on a `live` answer, so no stream
request goes out that cannot succeed; and the flag is
`let opshellMinimised = false` beside a `sessionStorage` key under the
session id's own prefix, which is what lets a reload come back parked
rather than open over the work. The server still does not know the word.

## What will bite the implementer

From the builder check, kept because each one is a collision rather than a
preference — and kept in its pre-implementation voice, as the list the
tasks were actually dispatched against, so its counts and line numbers are
the ones that were true then:

- **`test_a_closed_tab_ends_the_session_too` (`:3043`) pins the behaviour
  being removed.** It asserts the `pagehide` listener exists and calls
  `opshellEndSession`. It has to be **inverted** — assert that no
  `pagehide` handler ends the session — so the removal is itself defended.
  `keepalive:true` is asserted in the same test and needs a new home.
- **`opshellRender`'s output is read by assertion**, not only by the
  browser: `state.user`, `state.root`, `state.geometry`, `state.reason`,
  `expected_checkin`, the literal `"closing"`, the absence of anything
  matching `>\s*cancel`, and the absence of `opshellEndSession()`.
- **The node harness cannot see any of this yet.** `document` has only
  `getElementById`, `createElement` and `body`; `createElement()` returns a
  stub with an inert `innerHTML` and a bare `{}` for `classList`; there is
  no `querySelector`, no `getBoundingClientRect`, no `style`, no `remove()`
  on created nodes. Measuring, appending to `.sidebar`, toggling a class
  and reading the card's markup back are invisible or throw. The harness
  grows, and `_NODE_ENV`'s own comment records what a weak stub cost last
  time: six mutations survived it.
- **`_node` pins thirteen function names and the shape of the state
  declarations.** A new function is simply absent from every node test
  unless it is added to that list.
- **`js_function` counts raw braces** with no string or comment awareness.
  The card's CSS goes in the `<style>` block; a `{` inside a string inside
  a lifted function mis-slices the source and breaks all 43 node tests at
  once.
- **A parked session holds more than it used to.** The pump treats a read
  timeout as "still open", so the stream occupies a Flask worker thread, a
  `Bridge`, a pty on the device and one of the shell port's four session
  slots for as long as the card is parked. An hour's work is now an hour of
  that, by design, and it belongs in the documentation rather than in a
  surprised reading of the logs.
- **Two tabs are two claims.** `Claims` is a refcount; a parked card in one
  tab and an open card in another are two sessions on one agent, and the
  first `/close` comes back "not the last". Stickiness makes this common
  where it was rare. "One card" is per page, not per browser.
- **`tools/storyboards/c2_tour.json` sweeps `.loot-overlay`** between steps
  to clear modals. The tour does not open this view today, so nothing
  breaks now — but once the card is not an overlay, those lines can no
  longer clear it, and the boards are pinned by `test_c2_hardening.py`.

## Documentation, which the first draft forgot

- `docs/C2_DEMO.md:89` describes a panel and says "Leaving the session
  queues the shutdown" — false after this change. Prose only: `test_docs.py`
  derives the README's section count from `^## \d+\. ` headings and its
  badge from the file count in `docs/screenshots`.
- `README.md:608` says "opened from the header", which stays true, and
  should gain the window behaviour.
- `docs/TUNNEL.md:425-470` carries the three operator rules; the geometry
  paragraph stays true, the lifetime paragraph does not. The closed-tab
  bound becomes 240 s plus one interval, and the parked-session cost
  belongs there.

**Done in Task 7**, and the three pages are held by
`TestTheOperatorShellIsDocumentedAsAWindow` in `test_docs.py`: what a
closed tab costs, that a reattach is a new shell and what that loses, and
the four things a parked session holds. The three rules survived — all
three are still true — and the lifetime paragraph was replaced rather than
softened.

## How this will be verified

- The measured defect, as a test: a reload does not end the session.
- Minimised keeps the claim beating: the poll continues and `/state` is
  still asked with the session.
- A session that ends while minimised turns the card into one that says so,
  with the duration.
- A restored card after a reload attaches and announces a new shell.
- An agent click does not detach a live terminal.
- The geometry the strip states is the geometry that was sent.
- The named properties keep their tests; the removal of the `pagehide`
  guard is defended by the inverted test.
- The full suite, on this branch, on top of the merge with `main`.

## Known limitations, as built

Eight, each ruled during execution and each recorded in the ledger with its
reasoning. None is a defect left lying: every one was weighed against a
change the plan or the task forbade, and the view fails safe in the first
six. The seventh is a trust boundary and not a failure mode. The eighth is
the one window in which the first line can be out of date.

1. **The resume checks a count, not an identity.** `/api/opshell/state`
   reports how many sessions the claim has, not whether the id in this
   tab's `sessionStorage` is one of them — so an id written by a different
   team server on the same origin, a port change on localhost, can be
   adopted until the stream request refuses it. Bounded: an unknown id
   gets 400, the view says so and forgets it, and the close is refused with
   its own reason — `another view is holding this channel, so it stays up;
   this session is closed` (`opshell.py:558`) — so nothing is stopped.
   Closing it properly needs a per-session field on the state body, which
   the plan forbade.
2. **A duplicated tab duplicates the claim.** `sessionStorage` is cloned
   into a tab opened with Duplicate Tab, so both tabs resume the same id;
   the second stream takes the bridge and the first tab's close then stops
   the channel. Fails safe — both terminals print that the session ended.
3. **While the card is open the content column is hidden**, so a device
   clicked in the list renders into a hidden node: its scroll and focus
   calls are no-ops and its history poll runs at 2 s against an invisible
   view, and after the `✕` the device console reappears scrolled to the top
   and unfocused. That is the price of hiding the column rather than
   emptying it, and the answer for working beside a shell is `_`, not a
   device click.
4. **The size is fixed for the life of the connection.** There is no route
   that resizes — the pair rides the password line and the wire has no
   resize message — so a window resized afterwards does not change the
   terminal, and a session that attached while the card was hidden keeps
   the fallback 120×40. The view says that once, in the terminal, rather
   than leaving the operator to wonder.
5. **A refusal that arrives while parked is read after a restore**, not in
   the sidebar entry: the entry says `session ended · 92s`, and the
   sentence itself is in the card. This paragraph has overstated the case
   twice, both found by the final review. It first said the reason was
   "visible only after a restore; recoverable, not lost", when the poll's
   next tick replaced the card's body and took the terminal's node with
   it, so a restore showed the closed render; and the correction to that
   still said the reason was written into the card, when on a parked card
   `opshellEndSession` runs with `opshellTerm` still set — the tick that
   disposes it has not come yet — so `opshellSay` put the sentence in the
   terminal, the panel fallback was skipped as `!opshellTerm` was false,
   and two seconds later the reason was nowhere at all. It now rides on
   `opshellLast` beside the duration, which is page state and survives a
   tick, and `opshellRender` states it where it states the duration: once,
   only when the end had a reason, and not when the strip has already said
   the same sentence. What remains is the ordering — the parked entry is
   one line in a 260 px column and does not carry it, so it is read on the
   restore.
6. **A parked session is not a free one**: a worker thread, a bridge, a pty
   on the device and one of the shell port's four session slots, held for
   as long as it is parked. It belongs where an operator reads it, so it is
   in `docs/TUNNEL.md` as well as here — the alternative is a surprised
   reading of the logs.
7. **The history guard is what the endpoint reported about itself.** The
   team server cannot verify it, exactly as it cannot verify `user`: a
   modified endpoint could claim `off` and not do it. That is the trust
   boundary `docs/TUNNEL.md` already states for the user ("Which user that
   is, the endpoint reports"), and saying so here keeps the view's claim
   honest about whose claim it is: the first line is the endpoint's word,
   passed on, and not something the interface checked.
8. **The page attaches with state up to one poll old.** The first line's
   history word comes from the last `/api/opshell/state` the page read,
   up to two seconds before the attach. If the service reconnects with a
   new answer inside that window, the machine compares against its *new*
   report and runs the session, while the page prints the *old* word.
   Rare: it needs a reconnect, with a changed login shell or `/dev/fd`,
   inside one poll. Closing it would mean the attach carrying the word the
   page is about to print -- widening the protocol, which the plan chose
   against.

---

# Part two: the session should look like the operator's own shell

Added after the first part was builder-checked, on the operator's request
for "syntax highlighting". It is a change on the **implant** side, not in
the view, and that is a different risk profile from everything above.

## Why

`TERM=xterm-256color` is already set (`beacon.py:3361`), so colour would
arrive if the far end sent any. It sends none, and the reason is measured
rather than guessed:

| Measured on the operator's own machine | |
|---|---|
| `$SHELL` | `/bin/zsh` |
| `~/.bashrc` | **absent** |
| `~/.zshrc` | 715 lines, oh-my-zsh, theme `agnoster` |
| oh-my-zsh plugins | git, ansible, aws, brew, docker, docker-compose, gh, nmap, pyenv, python, tig, tmux, golang |
| `zsh-syntax-highlighting` | **not installed** |

The session runs `bash -i` with a generated rcfile that sources
`$HOME/.bashrc` (`beacon.py:3249`) — a file this operator does not have.
So **not one** of their 715 lines applies, which is why the screenshot
shows the bare `bash-3.2$` prompt and no colour anywhere.

What a terminal cannot do is colour by itself. Anything on the screen that
the operator reads as shell output has to have come from the shell.

## Goals

- The session runs the **login shell of the user the endpoint runs as**,
  where there is one and it can be driven.
- Where only bash exists — a spare Linux implant, like the container this
  was tested against — bash gets colour defaults so the session is not
  monochrome.
- The operator's own configuration wins over any default this code sets.

## Non-goals

- **Recolouring in the view.** The browser could search the output and
  paint IPs, paths or error words. Then the screen would show colour the
  far end never sent — the quiet fiction this branch has spent five review
  rounds removing. A character the operator takes for shell output comes
  from the shell.
- **A `ZDOTDIR` written to the target's disk.** zsh has no `--rcfile`, and
  the usual trick is a directory holding a generated `.zshrc`. The bash
  path is deliberately a **pipe** so that "nothing reaches the target's
  disk" (`beacon.py:3313`), and a file would give that up for colour.
- **Installing anything on the device.** If the operator wants as-you-type
  highlighting they install `zsh-syntax-highlighting` themselves; this
  change is what makes it then apply.

## The consequence that has to be said out loud

History. Today it is held off by the generated rcfile, which runs *after*
the host's own rc files and then does `unset HISTFILE; set +o history`
(`beacon.py:3250`). **That mechanism is bash-only** — `--rcfile` does not
exist in zsh.

The code already has a weaker path for a shell that is not bash:
`HISTFILE=/dev/null` in the environment, logged with its reason
(`beacon.py:3375-3380`), and its own docstring admits "the host's own rc
files run after that and are free to set `HISTFILE` again".

So a zsh session takes the weaker path, and **the operator's own rc may
switch history back on.** That matters beyond tidiness, because the
terminal's first line said `history is off in this session` as a constant,
and there is a test asserting that line claims only what the code does
(`test_the_first_terminal_line_claims_only_what_the_code_does`).

**As built, and why it is not what was first proposed.** The proposal was
that the beacon reports which mechanism *a session* used. That cannot be
done in time: the session stream does run upward, but it carries raw bytes
only, and no message the page reads before its first line says which
mechanism a session used. The only message that reaches the team server's
row for an endpoint is its `HELLO`, sent once, when the tunnel connects. So
the mechanism became a **host capability** rather than a per-session fact:

- the endpoint asks `_history_guard()` for the guard a session here would
  get and reports `history` (`"off"` or `"weak"`) and `history_detail` (the
  reason, for the weaker one) on its `HELLO`. They travel the same hops
  `user` does, to `GET /api/opshell/state`, where they default to `""`
  because a page that was told nothing must claim nothing;
- half of that answer can go stale. `/dev/fd` is the host's and does not
  change under a running service, but the login shell is the user's and does
  (`chsh`, a bash removed). So the endpoint remembers what it reported, and a
  session whose guard no longer matches is **refused**, with a message to
  reconnect the tunnel, rather than run under a claim nobody has rechecked;
- the one reason that is genuinely per attempt, a pipe for the generated
  file that cannot be opened for the moment, used to downgrade that session
  to the weaker guard silently. It is now a **refusal** that names history,
  because falling back would record the operator's commands while the page
  said it did not;
- the view's first line states only what it was told: `history is off in
  this session`, `history is not guaranteed off in this session` with the
  reason beside it, or nothing about history when the row or the field is
  absent. An endpoint too old to send the field, and a word nobody
  recognises, both read as the weaker one, never as `off`;
- `docs/TUNNEL.md`'s artifact list gains the same distinction, since it
  already enumerates what a session leaves on the host.

A feature that gave the operator colour and quietly started recording
their commands would be the worst trade on this branch.

## How the shell is chosen

In order, each tested before it is used:

1. the login shell of the effective user, from the passwd entry
   (`pwd.getpwuid(os.geteuid()).pw_shell`) — not `$SHELL`, which under the
   shipped `services/raccoon-beacon.service` is the service manager's
   environment and not a user's choice;
2. the current `_shell_program()` preference (bash, then sh).

Note what this means on a shipped implant: the unit runs as **root**, so
"the login shell" is root's, which on most Linux hosts is `/bin/bash` and
the behaviour is unchanged. The operator's own machine, where they run the
endpoint as themselves, is the case this helps — and that is exactly the
device this whole feature exists for.

A shell that is not bash and not zsh takes path 2 rather than being driven
with flags nobody has tested.

## Colour defaults, for a bash session only

Put in the generated rcfile ahead of the operator's own `~/.bashrc`, so
their settings override them rather than the other way round. `CLICOLOR`
and `LSCOLORS` go at the very top; the prompt goes **after**
`/etc/bash.bashrc` and before `~/.bashrc`, because Debian and ParrotOS set
`PS1` in the system file unconditionally and a prompt placed above it would
be overwritten before anyone saw it:

- `CLICOLOR=1` and an `LSCOLORS` default for BSD/macOS `ls`
- `LS_COLORS` not mentioned at all, since GNU `ls` reads it from the
  environment the host already has and which colours a host wants is the
  host's business
- a prompt that states the host and the working directory in the
  interface's own red, so the operator can tell this session apart from a
  local one at a glance

The file is handed to **any bash** a session runs that has a `/dev/fd` to
read it from, so a **bash login shell gets it too**, and that is deliberate
and better: it receives the stronger history guard and not the weaker one,
and a prompt that tells the operator this is not a local session is as
wanted there as on the fallback. Only a login shell that is not bash, zsh in
practice, never sees the file, and its own configuration is all there is.
A bash on a host with no `/dev/fd` runs plain `-i` and sees none of it.

## Left to the builder

- Whether the history-mechanism field rides on the existing shell status
  dict or a new one; it has to reach `/api/opshell/state` either way.
- The exact `LSCOLORS` string.
- Whether zsh gets a `-f`-style "no rc" variant as a third option for an
  operator who wants the old monochrome determinism. My call: no, until
  somebody asks — a switch nobody uses is a switch nobody tests.

**As built**, all three. The field rides the `HELLO` row as `history` /
`history_detail`, and not on a shell status dict, because a session has no
way to send one (see the consequence above). The string is
`ExFxCxDxBxegedabagacad`, with `CLICOLOR=1`, each given only where the
environment has none. And zsh gets no "no rc" variant, which was already the
call made here.

## Scope, and my recommendation

This is **not** the same piece of work as the window card. It changes the
implant's shell spawn, an area with its own tests
(`test_tunnel_endpoint.py`'s `_HAS_PTY` / `_HAS_BASH` suites), and it
changes a claim the view makes about history.

PR #9 already carries 23 commits and five review rounds. My
recommendation is to land the window card there and take part two as its
own branch, so that a defect in the shell spawn cannot hold up the fix for
the measured reload bug. The operator decides; if it is to be one PR, the
plan sequences part two last so it can be dropped without unpicking
anything.
