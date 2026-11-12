# The operator panel's layout, and the tunnel row that broke it — design

**Date:** 2026-11-12
**Status:** awaiting approval

---

## Intent

The tunnel panel is unreadable. Photographed for the first time on
2026-11-12, against a live stack, it shows a horizontal scrollbar inside the
panel, the root-shell warning clipped mid-word at the right edge, and the
shell password, the `ssh -L` forward, the attach command and the `socat`
fallback nowhere on screen at all. The DOM holds every one of them — a live
snapshot confirms the text is there and correct — and the row's last element
sits at `x=1978` in a 1440-wide window.

The cause is not the text. `.loot-item` is a **horizontal** flex row
(`display:flex; align-items:center; gap:10px`) and `.loot-panel` is capped at
`max-width:600px`. One endpoint row is now fourteen sibling `<div>`s:
identity, state, crypto, the SOCKS detail, the SOCKS credential, then the
shell block's six, then the Stop button. Fourteen columns in 560 pixels.
The vertical emptiness above and below comes from `align-items:center` on
columns of wildly unequal height.

**This is older than the shell session.** `.loot-item` was built for a loot
file — icon, name, meta, download arrow — and the SOCKS half had already
outgrown it. The shell work doubled the children and made it visible, which
is the only reason anyone looked: the tunnel panel had never been
photographed.

So the fix is not another column. The endpoint row is a **card with
fields**, and the vocabulary it needs is one the other panels can use too.

## Goals

1. **The tunnel panel is readable at 1440×900** — the size an operator
   actually has, reached over an SSH forward — with no horizontal scrolling
   and nothing clipped.
2. **Every value an operator came for is on screen**: both ports, both
   credentials, the root-shell warning, and the three commands.
3. **Commands are copyable in one gesture.** Each sits alone in a monospace
   box; none shares a line with prose.
4. **A shared card vocabulary** that Loot and Listeners can adopt later
   without inventing a third idiom — designed now, applied to the tunnel
   panel now.
5. **The panel survives five endpoints.** A card per endpoint, each short
   enough that the second one is visible without scrolling past the first.

## Non-goals

- **No third-party CSS or JavaScript, and no build step.** The page is
  hand-written and stays that way.
- **The other six panels are not rebuilt in this pass.** AV/EDR, RDP,
  RelayKing, Responder, Beacon Gen and Loot keep working exactly as they do;
  the vocabulary is designed so they *can* move, and the migration is
  somebody's later decision.
- **No change to what the routes return.** `/api/server/tunnel` and
  `_tunnel_row` are untouched; this is presentation only.
- **No new route, no new state.** Nothing is posted that is not posted today.
- **Not a design system.** Five or six classes that solve this panel and
  generalise honestly, not a framework.

## Anti-goals

Each would make the work a failure even if it looked better.

- **A second styling vocabulary living beside `.loot-*` for ever.** Two
  half-migrated idioms is worse than one inadequate one. Either the new
  classes are the ones the other panels will move to, or this is churn.
- **Losing the escaping discipline.** Every value on this row is
  endpoint-influenced, and one of them is a credential. `esc()` on all of
  them, and the test that holds it keeps holding it.
- **A layout that only works at one width.** It must degrade to one column
  rather than clip, because the panel is also opened on a laptop.
- **Weakening what the tests can hold.** There is no JavaScript runner in
  this repository, so the panel's promises are held by assertions on the
  served source. A redesign that makes those assertions untestable trades a
  visible defect for an invisible one.
- **A prettier panel that still cannot be photographed.** If nothing
  captures this panel afterwards, the next regression is found by a human
  squinting at it a year later.

## Constraints the code imposes

- The page is one Python string in `software/c2/server.py` (`_OPERATOR_HTML`)
  with an inline `<style>` block plus `software/c2/static/agent.css`.
- **The palette is not what it looks like.** The tunnel panel leans on
  `var(--dim)` for secondary text and `var(--bg3)` for hover, and **neither
  is defined in `:root`** — an undefined custom property with no fallback
  makes the declaration invalid, so that "dim" text is currently rendering
  at full brightness, inherited. What `:root` does define and resolve:
  `--bg`, `--surface`, `--surface2`, `--border`, `--text`, `--text2`,
  `--green`, `--green-dim`, `--yellow`, `--orange`, `--red`, `--red-dim`,
  `--mono`, `--sans`. Both `--yellow` (`#ffcc00`) and `--orange` (`#ff6600`)
  exist; the warning colour this panel and the Beacon Gen form use today is
  the yellow.
- `.loot-panel` is used by **eight** panels: `showAvEnumDialog`,
  `showRdpDialog`, `showRelayKingDialog`, `showResponderDialog`,
  `showBeaconGen`, `showListeners`, `showTunnel`, `showLootViewer`. Its
  `max-width:600px` and `max-height:70vh` are load-bearing for the narrow
  dialogs and must not change globally.
- `.loot-item` rows are used by four lists: Listeners, the tunnel server
  block, the tunnel endpoint rows, and the Loot vault.
- `TestTheTunnelPanel` in `software/tests/test_tunnel_gui.py` holds thirteen
  promises about this panel by reading the page the server serves. Some
  assert source order inside a window of characters; those move with the
  markup, and the move is part of the work rather than collateral.
- Prior art for a labelled field grid already exists in the page:
  `.fb-detail .fd-grid` is `display:grid; grid-template-columns:80px 1fr`.
  The new vocabulary follows it rather than inventing a different grid.

## Approaches

Three layouts were built as real mockups against the live stack's own values
and shown side by side. All three replace the flex row with a card and widen
the panel; they differ in how the access half reads.

**A — Anleitung.** Fields under the head, then the three commands as
numbered steps, each with a line of explanation above its box. Walks a
first-timer through attaching. Rejected: at five endpoints each card is
screen-high, and the step numbering implies a sequence that the fallback
command is not part of.

**B — Statusblatt.** Two columns: the endpoint's facts left, the access
right. Half the height of A. Rejected on its own: it gives a reader who does
not already know the commands nothing to go on, and this panel is where
somebody learns the feature exists.

**C — Statusblatt with explanation lines.** *(chosen)* B's two columns, with
each command keeping its one-line explanation from A. The SOCKS port moves
to the foot of the left column, which leaves the right column entirely to
the shell session — the thing this panel is now mostly about. Chosen
because the panel is a tool opened ten times a day: B's density is right,
and three lines of prose is a cheap price for not having to remember which
command sends a terminal size.

## The design

### The card vocabulary

New classes in the inline `<style>` block, named for what they are rather
than for the tunnel, because Loot and Listeners are meant to adopt them:

| Class | What it is |
|---|---|
| `.loot-panel.panel-wide` | the 900 px variant, for data-dense panels. A modifier, so the eight narrow dialogs keep their 600 px |
| `.pcard` | one object: border, `--bg2`, 11 px padding, radius 6 |
| `.pcard-head` | identity, a state pill, secondary facts, and the row's button pushed right, over a bottom rule |
| `.pcard-pill` | a state in one word — green when connected, dim when not |
| `.pcard-two` | the body: `grid-template-columns: 1fr 1.15fr`, collapsing to one column under 760 px |
| `.pcard-col-h` | the small uppercase heading over each column |
| `.pcard-kv` | a label/value line, `grid-template-columns: 52px 1fr`, label dim and right-aligned |
| `.pcard-port` | a port, large and green, with its credential on the line below |
| `.pcard-warn` | the warning band: left rule and a 7 % wash, both in the panel's existing `--yellow` |
| `.pcard-cmd` | a command alone in a box: black wash, border, monospace, `overflow-x:auto` |
| `.pcard-hint` | the one dim line above a command that says what it is for |

Every one of them uses only variables that resolve. The new markup **does
not use `--dim` or `--bg3`**: secondary text is `--text2`, surfaces are
`--bg2` and `--surface2`. The undefined pair stays in the seven other
panels, untouched, and is recorded below as a known issue — defining them
globally in this pass would restyle every one of those panels without
anybody having looked at them.

`.loot-item` stays exactly as it is. Nothing that uses it changes in this
pass.

### What the tunnel panel renders

The server block keeps its shape and gains the wide panel: it is already a
single line of facts and reads correctly today.

Each endpoint becomes one `.pcard`:

- **Head:** identity (monospace, bold), the state pill, then hostname and OS
  dim, then the Stop button right-aligned with its existing disabled state
  and reason.
- **Left column, "the endpoint":** peer, crypto (both paths), traffic
  (sessions, bytes in and out), and the fleet line — then a `socks`
  sub-heading with the port and its RFC 1929 credential.
- **Right column, "shell session":** the port large and green with the
  session count, the password below it, the root-shell warning, and then
  three `.pcard-hint` + `.pcard-cmd` pairs: forward, attach, fallback.
- **A row with no shell port** renders the reason in the right column under
  the same heading, in place of the port — so the column is never empty and
  never silent.
- **The recording badge** stays where it is, in the server block, driven by
  `srv.shell_transcripts` and both range ends, as ruled on 2026-11-11.

### What a test must fail on

The method can only read the served source, and the honest consequence is
written into the test class's docstring. What it *can* hold, and must:

- the endpoint rows use the card vocabulary and **no longer** use
  `.loot-item`;
- the panel that contains them is the wide variant, and the eight narrow
  dialogs are not;
- each of the three commands is alone inside a `.pcard-cmd`, and each is
  preceded by its `.pcard-hint`;
- the forward line still precedes the attach line, which still precedes the
  fallback;
- every endpoint-influenced value still goes through `esc()` — the existing
  assertion, unchanged;
- a row with no shell port still renders its reason;
- the recording badge's condition still reads only `srv.*`;
- `.pcard-two` carries a one-column fallback rule, so a narrow viewport
  cannot clip.

The thirteen existing `TestTheTunnelPanel` assertions move with the markup.
Their promises do not change; the windows and selectors they look through
do. Three of them are welded to how the string is built today rather than to
a promise, and those get **rewritten to assert the new structure** rather
than mechanically repointed:

- the one that counts `indexOf("refused_")` exactly once is asserting "one
  generic refusal reader, not two" — keep that promise, assert it against
  wherever the reader now lives;
- the one pinning the exact `row.shell ? shellBlock(row) : (row.shell_detail
  ? …)` expression is asserting "a row with no shell port shows the reason"
  — assert that the reason renders in the shell column, which is the new
  shape of the same guarantee;
- the badge test asserts the literal `<div id="tunnel-recording-badge"` and
  that the word `record` appears nowhere in the row source. Both survive:
  keep the id, and keep the badge out of the card.

Nothing in this list may end up asserting less than it does today. A test
that can only be repointed by loosening it is a signal the redesign moved a
promise, and that is a thing to raise rather than to absorb.

### The guard against the next one of these

This defect existed for a release and was found by photographing the panel,
so the work ends with the panel photographed. **The capture tooling cannot
do that today**, and the builder check established how far short it falls:
`tools/demo_env.py` stands up listeners but no tunnel server, no shell range
and no endpoint, so a capture today renders the empty state; and every still
comes from one storyboard, `tools/storyboards/c2_tour.json`, which has no
tunnel step. So the figure means: teaching the demo stack to run a tunnel
server with a shell range and a transcript directory, getting a real
endpoint to dial in and stay connected for the length of a capture run, and
adding the storyboard frame.

That is plausibly more work than the redesign itself, which is why its scope
is the approver's call below rather than an assumption in this document.

## Decisions I made, for the approver to check

- **The wide panel is a modifier, not a new value for `.loot-panel`.** The
  narrow dialogs are narrow on purpose.
- **`.loot-item` is untouched.** Migrating Loot and Listeners in the same
  pass would double the diff and put two unphotographed panels at risk at
  once.
- **The classes are named `.pcard-*`, not `.tunnel-*`.** They are meant to
  be adopted; a tunnel-specific name would guarantee a third idiom later.
- **SOCKS moves to the left column.** It is a fact about the endpoint; the
  shell session is what the operator came to act on.
- **The warning band keeps the panel's existing yellow, not the mockup's
  orange.** The mockup you picked was rendered with my own spike palette;
  every other warning in this GUI — the Beacon Gen slow-crypto note, the
  callback-URL note — is yellow, and one orange band would be the odd one
  out. Say so if you wanted the orange.
- **The new classes use no undefined variable.** `--dim` and `--bg3` are
  used across this page and resolve to nothing, which is why text meant to
  be secondary renders at full brightness today. The card uses `--text2`
  instead. Fixing the two globally would restyle seven other panels in a
  pass nobody photographed them in, so that stays a known issue.
- **Three test assertions get rewritten rather than repointed**, as listed
  above, because they pin the current string-building rather than a promise.

## Known issue this does not fix

`var(--dim)` and `var(--bg3)` are undefined in `:root` and used throughout
the operator page. Every declaration that names them is invalid, so
secondary text and hover states across the eight panels are not rendering as
intended. The tunnel card stops using them; the rest of the page still does.
Worth its own small pass, with each affected panel looked at — which is the
thing that was missing when this defect shipped.

## Questions for the approver — answered

The approver read the document and said it stands as it is, without picking
between the options, so the three are ruled here rather than left open:

1. **The figure is a follow-up, not this branch.** It needs the demo stack
   taught to run a tunnel server, an endpoint that stays connected through a
   capture run, and a storyboard frame — plausibly more than the redesign,
   and the redesign is what was asked for. What this branch does instead is
   commit the thing that makes the panel verifiable at all:
   `tools/tunnel_demo_env.py`, which stands up a real tunnel server, a real
   endpoint and a real shell front, so the panel can be photographed by hand
   now and wired into the figures later. *Cost if wrong: no automated guard,
   so the next layout regression is again found by eye.*
2. **Moot, and recorded as such.** With no new still in this pass, the
   README's figure-count badge and `docs/C2_DEMO.md`'s section numbering are
   untouched. Whoever does the figure answers this then.
3. **Loot and Listeners migrate in a follow-up.** The vocabulary is built to
   be adopted and the tunnel panel is the first adopter; migrating two more
   unphotographed panels in the same diff is how this defect happened in the
   first place. *Cost if wrong: two idioms live side by side until that pass
   — which the anti-goal permits only as a temporary state, so it is written
   down here as owed work.*

## Left to the builder

- The exact pixel values inside the shapes above — padding, gaps, the pill's
  radius — within the house palette and the existing variables.
- Whether `.pcard-two`'s collapse happens at 760 px or another breakpoint.
- The wording of the three `.pcard-hint` lines, which exist today in the
  panel and may be reused verbatim.
- How the card's markup is assembled in `drawTunnel` — one helper per column
  or one per card.
