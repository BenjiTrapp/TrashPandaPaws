# The operator shell looks like a window

**Date:** 2026-11-23
**Branch:** `feat/opshell-window-look`, on `main` at `500b9cf`
**Status:** design, approved direction, not yet planned
**Predecessors:** `2026-11-17-operator-shell-design.md` (part one, PR #9),
`2026-11-19-operator-shell-window-design.md` (part two, PR #9 and #13). This
is part three and changes **only how it is drawn**.

## Why now

The view is functional and honest and looks like nothing. Seen in the
browser and confirmed by the operator on 2026-11-18, carried as a project
todo since. Measured in the code on 2026-11-23, the three parts and why each
looks unfinished:

| Part | Today | Where |
|---|---|---|
| The status strip — host, user, root, geometry, recording, channel | no class at all, a hard-coded inline `style` attribute; the channel state is bare text where every other state in this interface is a pill | `server.py:9346-9358` |
| The terminal | no background, no border, no radius, no scrollbar styling — unlike `.terminal` in the agent console, which has all four | `server.py:4832` vs `:4448` |
| The device picker | no CSS whatsoever: a native white dropdown on a `#070910` card | `server.py:9333` |

Three more findings from the same reading, all of them defects rather than
taste:

- **`.fd-btn` resolves two undefined variables.** `background:var(--bg2)`
  and the hover's `var(--bg3)` are defined nowhere in the stylesheet, so the
  Open/Attach/End buttons have no background at all; and because `.fd-btn`
  is `display:flex`, "Attach" and "End the session" stack vertically instead
  of sitting side by side (`server.py:4635-4646`). The class's only other
  wearer is the file browser's detail actions, drawn by `fbShowDetail` --
  `fbLootDir`, `fbLoadDir`, `fbDownloadFile`, the `View` button and
  `fbUploadTo` -- which have the same two defects. (An earlier draft said
  the Listeners panel, citing two line numbers taken from a reading before
  other work merged. Neither was true; consumers are named by function
  here because line numbers rot.)
- **`#opshell-body` permanently carries `.loot-loading`** — added at
  creation and never removed (`:8853`), so the whole card body inherits the
  loot panel's *loading text* style, `color:var(--text2);font-size:13px`.
- **The geometry renders an empty `<span>`** whenever `state.geometry` is
  `null`, which is every state before a bridge exists — a `gap:10px` hole in
  the strip.

Every line reference in this document is against `500b9cf` and was checked
there. An earlier draft carried numbers from a reading taken before `main`'s
other work merged, all about 110 lines low; a builder check caught it.

## Intent

The operator should be able to tell, without reading a word, that this is a
shell on their own machine and not another panel of the interface. Part
two's design is titled *the operator shell as a window, not a modal*; the
drawing never caught up with the title, and borrows the loot **panel's**
classes instead.

## Goals

- The card reads as a **window**: a titlebar with depth, a frame, a shadow
  against the background, and the surface translucent like every sibling
  surface in `.main` rather than the only opaque one.
- The terminal sits in a **visible box**, with the interface's own red
  scrollbar, so the operator can see where the shell begins and ends.
- Every claim the strip makes today is still made, as a **pill** in the
  vocabulary the tunnel cards already use: host, user, root, geometry,
  recording, channel state.
- The picker and the buttons are **themed**, and the two buttons sit side by
  side.
- Nothing the view asserts gets weaker, vaguer or prettier-but-less-true.

## Non-goals

- **No new behaviour.** No dragging, no resizing, no second window, no tabs.
- **No product change behind the view.** No endpoint, beacon or state
  change; `/api/opshell/*` is untouched.
- **The parked card keeps its look.** Its appearance is a deliberate
  decision of part two, pinned by a test that forbids a `border-radius` and
  the red tint so it cannot be mistaken for a selected agent
  (`test_operator_shell.py:3310`). It is not part of this work.
- **No wording changes.** The prose in the view is pinned by `test_docs` and
  by `TestTheViewDoesNotOverclaim`; a restyle that rewords is two changes.

## Anti-goals

What would make this a failure even if it looked better:

- A claim quietly lost. The strip says six things; a prettier strip that
  says five is worse than the plain one.
- The waiting time turned into a spinner. It is a number —
  `expected_checkin` — and a test holds that (`:3495`).
- `closing` rendered as `closed`. A session being torn down is not a session
  that is gone, and a test holds that too (`:3441`).
- The terminal losing a column or a row to its own frame. See the
  constraint below; this is the one way a purely visual change here can
  break something real.
- Translucency behind the terminal text. Readability of what the shell
  prints beats depth, every time.

## Constraints, measured

1. **The frame must not go on `#opshell-term`.** `opshellMeasure` reads
   `host.getBoundingClientRect()` (`server.py:9702`) — the border box of
   that element — and divides it by a measured cell to get the `cols` and
   `rows` it then sends to `/stream`. Padding or a border on the measured
   host would report room the terminal does not have, and `overflow:hidden`
   (`:4832`) would clip the surplus column. The box therefore goes on a
   **wrapper inside `.opshell-live`**, and `#opshell-term` stays
   geometrically bare.
2. **`.opshell-card` keeps exactly one rule, and no positioning.** A test
   requires exactly one rule with that literal selector and forbids
   `position`, `inset` and `z-index` on it or on `#opshell-card`, including
   inside `@media` (`:3264`). The reason is in the code: `.main` is a row
   holding the 260px agent list beside `.content`, so a layer over `.main`
   would cover the list this layout keeps clickable. Background, radius,
   border and shadow are free; the card stays a flex sibling in the column.
3. **The pinned structure of the live state.** `class="opshell-live"` must
   appear before `id="opshell-term"`; `.opshell-live` must keep
   `display:flex`, `flex-direction:column`, `min-height:100%` and must not
   contain `;height:`; `#opshell-term` must keep `flex:1`,
   `min-height:72px`, `overflow:hidden`; `#opshell-body` must keep `flex:1`
   and `overflow:auto` (`:6839`). A wrapper between them is allowed and is
   how constraint 1 is met.
4. **The card has exactly two children.** Chrome and body, when there is no
   lost-resume note (`:7317`). No third element at card level.
5. **The `✕` in the footnote stays an entity followed by text.** The test
   matches `&#10005;[^<]*closes the card` — no tag may come between the
   glyph and the words, so it cannot be wrapped in a `<kbd>` or a `<span>`
   (`:3505`).
6. **One `loot-empty` in the closed state.** A test counts exactly one
   occurrence in that render (`:7249`), so paragraphs may not be renamed or
   multiplied there.
7. **The picker keeps `id="opshell-agent"` with a `.value`.** `opshellOpen`
   reads it (`:9312`) and three node tests set it.
8. **Handlers stay inline `onclick="fn(event)"`**, double-quoted, and no
   non-`button` element carries one (`:3331`, `:4587`).
9. **The parked markup stays byte-stable across ticks** when the state has
   not changed (`:6450`, `:6501`) — nothing non-deterministic in it.
10. **Safari 14.1 is the floor** (`:3357`): flexbox `gap` is fine, `:has()`,
    container queries and `AbortSignal.timeout` are not. `backdrop-filter`
    needs its `-webkit-` prefix to count there.
11. **The chrome keeps `opshell-title`, both controls, and no
    `opshellEndSession()`** (`:3254`).

## Approaches

Three ways to house the new rules were considered on 2026-11-23; the
operator picked the first.

1. **Own `.opshell-*` classes in the existing inline `<style>`, plus the
   shell's own button and select classes.** *Chosen.* The CSS tests slice
   their subject out of that block (`test_operator_shell.py:3089`) and
   require the `.opshell-card` and `.opshell-parked` rules to be there, so
   the existing pins keep working where they are, and no other panel
   changes. Cost: the ~1030-line stylesheet grows by 40 to 60 lines, and two
   button vocabularies live side by side.
2. **Borrow `.pcard-head`, `.pcard-pill`, `.terminal` and
   `.log-controls select`, and fix `.fd-btn` globally.** Least new CSS, and
   it would fix the same button defect in the file browser's detail
   actions. Rejected
   because it dresses the window in the panel's clothes — the very thing
   that makes it read as a panel today — and because a later change to
   `.pcard-head` for the tunnel cards would silently restyle the shell.
3. **A separate `static/opshell.css`,** like the existing
   `static/agent.css` (`server.py:5388`). Nicest to read and diff. Rejected
   on a measurement: the pins on `.opshell-card` and `.opshell-parked` look
   inside the inline `<style>`, so moving the rules would break them, and
   the change would have to rewrite the checks as well as the look — more
   blast radius in the suite than in the CSS.

**`.fd-btn` is left alone.** Fixing its two undefined variables would also
change the file browser's detail actions (`fbShowDetail`'s Loot, Open,
Download, View and Upload buttons), which deserve their own verification. It is
recorded as a separate todo, not smuggled in here.

## What it looks like

Agreed from a mockup on 2026-11-23, in the restrained variant:

- **The card:** translucent `var(--surface)` over the wallpaper, `8px`
  radius, `1px solid var(--border)`, the house's popover shadow
  `0 8px 32px rgba(0,0,0,0.6)`, and an **8 px margin** so all three are
  visible — decided with the measurement below, at a cost of 2 columns and
  1 row. It stays in the content column; nothing is positioned.
- **The titlebar:** the `>_` glyph the header button already uses, the
  session name in mono with its ellipsis, and the two controls right-
  aligned. A slight vertical gradient from `surface2` gives it the depth a
  flat row cannot have.
- **The strip:** a class of its own, a divider that **spans the card**, and
  one pill per claim — root in `--orange`, recording in `--red` with its
  `●`, the channel in `--green` when open. A claim with no value renders no
  pill, which also closes the empty-`<span>` hole.
- **The terminal:** a wrapper with a border, a `6px` radius, a padding ring
  and `rgba(0,0,0,0.6)`. The tint shows **in the ring**, not behind the
  text: xterm's own viewport paints `#000` over its area, so the backing
  would never have been visible there anyway. The text is not translucent.
- **The picker and the buttons:** themed in the `.log-controls select`
  manner, the primary action in the interface's red, the two buttons in a
  row.
- **The body:** its own text rule instead of the borrowed `.loot-loading`,
  which stays in use by the four panels that actually load.

## Decided while writing this, and why

A builder check on the first draft asked six things. Five are settled here,
as the author's calls rather than the operator's; the sixth is the open
question below.

- **No check-in pill in the titlebar**, which the first draft and the mockup
  both had. `opshellChrome` builds the chrome once (`:8805`) and only
  `opshellRetitle` writes into it per tick, and only when the string changed
  (`:9171`) — a test pins that a node appended into the title survives a
  no-change tick. A live countdown there needs a new per-tick writer, which
  is new behaviour in a change whose first non-goal forbids it; the server
  also sets `expected_checkin` for every target, not only while waiting, so
  the pill would tick during an attached session. The number stays where it
  is, in the body, as its own test requires (`:3495`).
- **The red scrollbar goes on `#opshell-body` only.** The scrollbar that
  actually moves shell output belongs to the vendored widget's
  `.xterm-viewport`, and reaching into a hash-pinned vendor class from the
  page's stylesheet is a coupling that breaks on the next bump. The
  terminal's own scrollbar therefore stays the vendored grey.
- **The strip's divider spans by bleeding into the body's padding** — a
  negative horizontal margin equal to `#opshell-body`'s `16px`, not a
  restructure. Moving that padding onto each child instead would touch all
  five render branches and change the measured room a third time, and a
  third card child is forbidden (`:7317`). To be confirmed in the browser:
  the bleed must not make `overflow:auto` produce a horizontal scrollbar.
- **The new invariants get tests, proven by mutation**, as everything else
  in this view is: the frame is not on the measured host, one pill per
  claim, no pill without a value, the two buttons are in a row. That is
  roughly half the work of the change and is not optional here.
- **The six `<p class="loot-empty">` paragraphs keep that class.** The
  defect was `.loot-loading` on a body that is not loading; `.loot-empty` is
  a shared dim-note utility four panels use legitimately. Renaming it would
  also turn a real assertion vacuous: a test counts exactly one occurrence
  in the closed render (`:7249`).

## The gutter, measured

The builder check's first finding: as the layout stands there is **no gap
anywhere on the path**. `.main` (`:4404`), `.content` (`:4432`) and
`.opshell-card` (`:4802`) carry no margin or padding, so the card's border
box exactly fills the column. Without a gutter the radius shows as four
notches of wallpaper, the border doubles the sidebar's own, and the shadow —
a named goal above — is clipped by `.main`'s `overflow:hidden` on two sides
and paints onto the sidebar on a third. A margin is legal; constraint 2
forbids only positioning.

Room is geometry here, so the cost was measured rather than estimated. A
throwaway page carried the rules of this stylesheet verbatim and ran the
**unmodified `opshellMeasure`** against three layouts at three window sizes,
on stages outside the viewport so no transform could distort a rectangle:

| Window | Today | Terminal box only | Box and an 8 px gutter |
|---|---|---|---|
| 1280×800 | 137×46 | 134×43 | 132×42 |
| 1440×900 | 159×53 | 156×50 | 154×49 |
| 1920×1080 | 226×67 | 223×64 | 221×63 |

The cell is **7.201 px wide and 14.000 px tall** at the terminal's 12 px,
with the declared stack resolving as written. So the loss is **constant, not
proportional**: the terminal's own frame costs 3 columns and 3 rows, and the
gutter adds **2 columns and 1 row** on top of it — at the narrowest window
measured, 3.6 % of the columns and 8.7 % of the rows.

Two things this corrected, both of them mine: an earlier draft estimated the
cell at about 16 px tall and the total cost at about 6 % of the width, and
the mockup showed a session at 118×34 — the real geometry in this layout is
137 to 226 columns.

The same page settled the divider question from the section above: in all
six framed bodies `scrollWidth` equalled `clientWidth` — **no horizontal
scrollbar** — and the bled divider measured 1180.0 px against a body of
1180.0 px, so it does span.

**Decided with these numbers, 2026-11-23: the gutter goes in, at 8 px.**
Two columns out of 159 are a cheaper price than a frame and a shadow that
do nothing. The plan's verification measures the geometry before and after,
because this is a value the view sends to the server.

## Size

A project, not for the amount of CSS but because eleven pinned assertions
touch the markup it rewrites, and one of the changes — the terminal's frame
— alters a value the view measures and sends to the server.

## What is left to the builder

- The exact pixel values, gradient stops and shadow spread, within the
  vocabulary above.
- Whether the pills get one shared class with modifiers or one class each.
- Whether the strip's own class is new or an extension of an existing one,
  as long as no other panel's appearance changes.
- The order of commits, and whether the body's text rule and the geometry
  hole are one commit or two.

## Known limitations, as built

Looked at on 2026-11-23 in headless Chrome, through `tools/demo_env.py`
(a real C2 with one real beacon checked in, `raccoon-bandit`, and **no
tunnel server**) and `tools/capture_gui.py`. No live device was involved,
no hardware implant and no tunnel endpoint, so nothing below was seen
carrying a real shell.

**Seen, in the state the server really put the view in:**
- The view as it opens with no session, at 1440×900 and at 900×500: the
  framed card, its 8 px gutter with the wallpaper showing through it and
  through the translucent surface, the chrome, the strip with one pill
  (`channel closed`) and no empty hole where the geometry would be, the
  themed picker and "Open a shell" **side by side**, and the server's own
  reason that no tunnel server is configured.
- That at 900×500 the idle body fits (`scrollHeight` equals
  `clientHeight`, 378 px) and nothing is clipped.

**Seen only by drawing the real `opshellRender` markup with a made-up
state**, because the state itself needs a tunnel endpoint the demo does not
have. These say how the markup lays out, not that the view reaches them:
- The live box at 900×900, 900×500 and 900×300. At 300 the host stops at
  its 72 px floor, the body overflows by 16 px and `scrollTop` moves, so a
  short card **scrolls rather than clipping** the host. The box was empty:
  no xterm was attached, so the terminal's own rendering inside the box was
  not seen.
- "Attach" and "End the session" sitting side by side, and the `root`,
  geometry, `recording` and `channel open` pills.

**Not seen at all:**
- **The device dropdown open.** Headless Chrome draws a native `<select>`'s
  list outside the page, so a page screenshot cannot contain it;
  `showPicker()` with a user gesture changed no pixel in the card. The
  closed control is themed. The open list is not styled by this change (`.opshell-pick`
  sets nothing on `option`), so on macOS it is the system menu and
  elsewhere it follows the control's colours — neither was looked at.
- The waiting state's number, the closing state's word, the closed state's
  duration, a parked card, and the terminal's text and cursor: each needs a
  tunnel endpoint or a live channel. They are covered by the node
  behavioural tests and by nothing a person has looked at.
- Any scrollbar: the capture tool runs Chrome with `--hide-scrollbars`, so
  the body's red thumb was not seen either.
- Safari. The floor is 14.1 and only Chrome was run.

**Left by decision:**
- The terminal's own scrollbar stays the vendored grey: its classes are
  hash-pinned (`static/VENDOR.md`), and this change styles nothing under
  `.xterm`.
- `.fd-btn`'s undefined `--bg2` and `--bg3` stay, fenced by a test, for the
  file browser's own change; its only wearers are `fbShowDetail`'s detail
  actions.

**Found by looking, and covered by no test:**
- With no session the strip reads `no device chosen` while the picker
  beside it already shows `raccoon-bandit` selected: the picker falls back
  to its first option when `state.target` is empty. Older than this branch,
  and a rendered sentence, so not changed here.
- The "Device" label is the body's 13 px sans and the picker 11 px mono, so
  the label reads larger than the control it names; the reason above the
  row and the note below it sit flush against it with no spacing of their
  own.
- When the user is root the strip says `root` twice, as the user and as the
  pill.
- In the live box at short heights the footnote sits directly under the
  box's border with no margin.
- The `_` control sits on its baseline, visibly lower than the `✕` beside
  it.
