# The picker names the device `Open` will use

**Date:** 2026-11-26
**Branch:** `fix/opshell-device-designation`, on `main` at `db84655`
**Status:** approved, planned (`docs/superpowers/plans/2026-11-26-operator-shell-device-designation.md`)
**Predecessors:** `2026-11-17-operator-shell-design.md` (part one, PR #9),
`2026-11-19-operator-shell-window-design.md` (part two, PR #13),
`2026-11-23-operator-shell-window-look-design.md` (part three). Part three
recorded half of this defect under *Found by looking, and covered by no
test* and left it: "a rendered sentence, so not changed here."

This is a small change. It touches the picker and one route — and, after the
final review, the open and the poll beside them — and it changes no sentence
in the status strip.

Every line reference in this document is against `db84655`, the commit this
work started from.

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
| `raccoon-bandit` — designated, not in the fleet | `raccoon-bandit` | none | `badger` |
| `parrot` — designated and present | `parrot` | on `parrot` | `parrot` |

The second row is the one no note carried. The strip names one device and
the button opens a shell on a different one, with nothing on the page
saying so. The first row is the recorded defect: a device nobody chose.

Both rows have the same cause and the same condition, and it is not "the
target is empty" — it is **no candidate equals the target**
(`server.py:9423`). Nothing keeps the remembered designation inside the
fleet: `opshell_state` reads `candidates` from `agents` and `target` from a
file written at the first successful open (`:1850`, `:1849`, `:2160`).

Both rows follow from the same structure: row one lasts until the first open
on a server. Row two needs no device to have gone quiet, because `agents` is
never pruned for a silent device: one that stops checking in stays in the fleet,
labelled `stale` and then `offline`, and the picker still selects it. A
designation is missing from the fleet when the server was restarted and the
device has not re-registered, or when the file names a device this server has
never seen. The reason is structural: the designation is on disk and the
fleet is not. `_load_state` restores the fleet from `state.json`, but
`_save_state` (which writes the whole fleet) runs only on the scan route and
the result path, so a device that registered after the last of those is not
in the file, while its designation, written at the first successful open, is.
Only `_handle_register` and `_load_state` put a device in the fleet; a
check-in from a device the server does not hold adds nothing.

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
  device is missing from the fleet would discard the designation exactly
  when the operator is waiting for that device to come back.

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

Four more followed, all in the page and none in the markup `opshellRender`
draws: the final review added 3 to 5, and using the shell found 6.

3. **`opshellOpen` guards the empty pick.** When the picker exists and its
   value is empty, the page shows `choose a device first` and posts nothing.
   Without the guard the placeholder posted an empty body, and the route
   fell back to whatever designation existed *at the click* — which another
   tab, or any other client of the route, could have written after the
   render, so a device the view never showed. With no picker on the page at all, which is Attach,
   the guard does not apply and the empty body still goes to the route.
4. **`opshellOpen` shows `refused`.** A refusal that carries the field is
   drawn as `no such agent: <name>`.
5. **`opshellPoll` keeps the operator's pick.** The idle body is redrawn
   every two seconds and the markup selects only `state.target`, so a pick
   made a moment before a tick snapped back to the designation and `Open`
   acted on it. The poll reads the list's value before the redraw and puts
   it back afterwards when it is non-empty and still a candidate. The
   markup `opshellRender` produces is unchanged.
6. **A refusal from `Open` stays until the next attempt.** It was written
   into `#opshell-body`, which the poll rebuilds every two seconds, so
   `choose a device first` and `no such agent: <name>` were gone within one
   tick. It goes into one `#opshell-refused` node instead, a sibling of the
   body drawn by `showOperatorShell`, which gets the existing `.opshell-note`
   class only while it holds a refusal. The same reason as the resume note
   beside it: the refusal is not state. `opshellOpen` empties it at its next
   attempt. It has no timer and no dismiss button.

Nothing else. The strip, `opshellRender`, the styles and the remembered
designation are not touched, so `TestTheViewDoesNotOverclaim` and the
prose-pinning tests have nothing to answer for.

The route split stays alongside the client guard, for two reasons. It is the
API's own honesty: any client other than this page that names nothing is told
so, and one that names a device the fleet does not hold — directly, or
through the designation fallback — is told `404 no such agent` with the name
in `refused`. And Attach renders no picker and depends on that fallback.

An earlier draft argued against the client guard, on the ground that the
route's answer names the dead designation, "which is more than a client-side
guard could have said". That reason was wrong: `opshellOpen` drew only
`answer.error` and never `answer.refused`, so the operator saw a bare `no such
agent`. The page now draws `refused` when the server sends it.

## Left by decision

- **The strip does not explain a missing designation.** In row two it names
  `raccoon-bandit` while the picker cannot offer it. The claim is true — it
  is the designated device — and the operator can see it is absent from the
  list. Saying more means new rendered prose, which is what this change set
  was chosen to avoid.
- **A designation can come to name a different device.** Names are
  assigned by the server from a global counter, `_name_counter`
  (`server.py:175`), as `AGENT_NAMES[_name_counter % len(AGENT_NAMES)]`
  (`_assign_name`, `:199`). The counter is restored from `state.json`
  (`:264`) and written there only by `_save_state` (`:251`), so a restart
  after registrations that no save recorded rewinds it, and a name is handed
  out again, to whichever host registers first. A designation naming the old device then matches the new
  one, the picker marks it `selected`, and nothing on the page says so. The
  file already records the rewind, for the tunnel identity (`:272-275`).
  Not fixed here: pinning a designation to the implant id changes what a
  designation *is* and touches the register path, so it is its own piece of
  work.
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
- A refusal from `Open`, driven through a card `showOperatorShell` drew:
  still on the card after a poll has rebuilt the body, never written into
  the body, one note after two refusals, and gone at the next attempt —
  including one the token stops with a `401`.
- Each test driven against a mutation of the line it covers, which is how
  this repo holds its tests, and with `__pycache__` cleared under
  `python3 -B` (`.superpowers` note of 2026-11-23).
- The picker seen in a browser in all three states, because part three's
  record of this defect was made by looking and not by a test.

## What's left to the builder

Where the empty-valued option is built — inside the `map` or prepended to
it — and how the route's two failures are arranged, as long as the fallback
to the remembered designation keeps working for a body that names nothing.
