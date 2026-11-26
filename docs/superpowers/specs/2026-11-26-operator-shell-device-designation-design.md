# The picker names the device `Open` will use

**Date:** 2026-11-26
**Branch:** `fix/opshell-device-designation`, on `main` at `db84655`
**Status:** short design, pending approval
**Predecessors:** `2026-11-17-operator-shell-design.md` (part one, PR #9),
`2026-11-19-operator-shell-window-design.md` (part two, PR #13),
`2026-11-23-operator-shell-window-look-design.md` (part three). Part three
recorded half of this defect under *Found by looking, and covered by no
test* and left it: "a rendered sentence, so not changed here."

This is a small change. It touches the picker and one route, and it changes
no sentence in the status strip.

## Why now

Part three's note says the strip reads `no device chosen` while the picker
shows a device. Reading the code for the fix found the harder half: the
picker's option is not decoration, it is the argument. `opshellOpen` reads
`pick.value` (`server.py:9547`) and posts it, and an option list with no
`selected` attribute hands back its first entry.

Measured on 2026-11-26 by driving the page's own `opshellRender` through the
suite's node harness, fleet `badger, clumsy-raccoon, parrot`
(`candidates` is `sorted(agents)`, so the order is alphabetical and means
nothing else):

| `state.target` | The strip says | `selected` | `Open` acts on |
|---|---|---|---|
| empty — never opened on this server | `no device chosen` | none | `badger` |
| `raccoon-bandit` — designated, stopped checking in | `raccoon-bandit` | none | `badger` |
| `parrot` — designated and present | `parrot` | on `parrot` | `parrot` |

The second row is the one no note carried. The strip names one device and
the button opens a shell on a different one, with nothing on the page
saying so. The first row is the recorded defect: a device nobody chose.

Both rows have the same cause and the same condition, and it is not "the
target is empty" — it is **no candidate equals the target**
(`server.py:9423`). Nothing keeps the remembered designation inside the
fleet: `opshell_state` reads `candidates` from `agents` and `target` from a
file written at the first successful open (`:1850`, `:1849`, `:2160`).

The window is narrow but not rare: row one lasts until the first open on a
server, row two begins the moment a designated device stops calling home,
which is the ordinary end of a drop box.

## Intent

The device the picker shows is the device `Open` will use. When the page
cannot honour that, it offers nothing to open rather than picking for the
operator.

## Goals

- No `Open` ever acts on a device the operator did not name.
- The view keeps every claim it makes today; the strip is not reworded.
- An operator who presses `Open` with nothing chosen is told that, and not
  that their device does not exist.

## Non-goals

- The strip's wording, in any state. Part three left it alone and so does
  this.
- Explaining *why* a designated device is missing from the fleet (see *Left
  by decision*).
- The picker's look, which part three settled.

## Anti-goals

- A view that silently chooses on the operator's behalf, which is the
  defect.
- A second mechanism that keeps `target` and `candidates` in step. The file
  is the operator's designation, not a cache of the fleet; pruning it when a
  device goes quiet would discard the designation exactly when the operator
  is waiting for that device to come back.

## Approaches

Three ways were drawn as mockups of the real view and put side by side.

**A — the picker offers nothing to open (chosen).** When no candidate
matches the target, the list gets a first entry that selects nothing, so
`pick.value` is empty and the page names no device. Costs one click before
the first open on a server, and needs the route to tell "nothing was named"
apart from "that device is unknown".

**B — the strip names the first candidate.** `state.host || state.target ||
candidates[0]`. No extra click, no contradiction. Rejected: it makes the
name in the strip mean two different things — a measured host during a
session, a guess before one — which is the overclaiming part two named as
an anti-goal, and it still opens on a device nobody chose.

**C — the strip drops the sentence.** `claim()` already draws nothing for an
empty value, so removing the `|| "no device chosen"` fallback is a deletion
and needs no new prose. Rejected: it removes the visible contradiction
without changing what `Open` does. The wrong-device open of row two
survives untouched and becomes harder to notice.

A is the only one that changes the behaviour rather than the description.

## What changes

1. **`opshellPicker` (`server.py:9421`).** When no candidate equals
   `state.target`, the list begins with an option whose value is empty,
   labelled `choose a device`. When one does, the list is exactly what it is
   today — the ordinary path is untouched.
2. **`api_opshell_open` (`server.py:2121`).** Today one line resolves the
   name and one answer covers two different failures: `agent_name =
   (body.get("agent") or opshell_target() or "").strip()`, then `no such
   agent` with `refused: ""` for an empty name (`:2123-2126`). The two are
   split: nothing named at all answers `400` with `choose a device first`;
   a name that is not in `agents` keeps today's `404 no such agent` with the
   name it refused. `400` for an incomplete request is this route's
   neighbour's own precedent — the close route answers `session is
   required` the same way (`:2196`).

Nothing else. The strip, `opshellRender`, the styles and the remembered
designation are not touched, so `TestTheViewDoesNotOverclaim` and the
prose-pinning tests have nothing to answer for.

A deliberate consequence of splitting the route rather than guarding the
button: in row two, pressing `Open` without choosing still posts an empty
body, the route still falls back to the remembered designation, and the
operator is told `no such agent: raccoon-bandit`. That names the dead
designation, which is more than a client-side guard could have said.

## Left by decision

- **The strip does not explain a missing designation.** In row two it names
  `raccoon-bandit` while the picker cannot offer it. The claim is true — it
  is the designated device — and the operator can see it is absent from the
  list. Saying more means new rendered prose, which is what this change set
  was chosen to avoid.
- **One device in the fleet is not special-cased.** It costs one click, once
  per server, because the first open writes the designation and every later
  render marks it `selected`. An auto-pick for a fleet of one would
  reintroduce the defect at the only size where it is invisible.

## Calls I made, for checking

- The condition is `no candidate equals the target`, not `the target is
  empty`. Measured: the empty target is row one of the table, and the
  stale target of row two is the worse half.
- The option reads `choose a device` and the route answers `choose a device
  first`. Two strings rather than one, because the option is a control and
  the error is a consequence; both are open to a different wording.
- `400` and not `404` for nothing named, following the close route.
- Part three's note (`2026-11-23-...-look-design.md:358-361`) gets a line
  saying this work overtook it, where it stands, rather than being edited
  away — the shape `f032820` used for the egress design's premise. That
  document is not prose-pinned, so nothing forces it; the repo's own habit
  does.

## Verification

- The three rows of the table above, rendered through the node harness, as
  tests: an empty target and a stale target both get the empty-valued
  option, a matching target does not.
- The route's two failures, each asserted on its own status and sentence,
  including that a named-but-unknown device still reports the name it
  refused.
- Each test driven against a mutation of the line it covers, which is how
  this repo holds its tests, and with `__pycache__` cleared under
  `python3 -B` (`.superpowers` note of 2026-11-23).
- The picker seen in a browser in all three states, because part three's
  record of this defect was made by looking and not by a test.

## What's left to the builder

Where the empty-valued option is built — inside the `map` or prepended to
it — and how the route's two failures are arranged, as long as the fallback
to the remembered designation keeps working for a body that names nothing.
