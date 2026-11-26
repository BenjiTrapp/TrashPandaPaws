# A designation names a device, not a slot in the list

**Date:** 2026-11-26
**Branch:** `fix/opshell-designation-by-id`, on `chore/recorded-leftovers`
**Status:** short design. Built without a prior approval round: the operator
asked three times to proceed rather than answer, so the one open decision was
ruled rather than put to them. It is named below as a ruling, not as agreement.
**Predecessors:** `2026-11-26-operator-shell-device-designation-design.md`,
whose placeholder this leans on.

This is a small change: two functions, no change to the view.

## Why now

The designation that the Operator Shell's glyph opens onto can come to name a
**different physical host**, with nothing on the page saying so. Found in the
final review of the previous branch and verified there:

| Fact | Where |
|---|---|
| `_name_counter` is global, restored from `state.json`, and written **only** by `_save_state` | `server.py:175`, `:264`, `:251` |
| `_save_state` runs on exactly two paths: a scan result and a task result | `server.py:1275`, `:4277` |
| `_assign_name` hands out `AGENT_NAMES[_name_counter % len]` | `server.py:199` |
| The designation is written at the first successful open, and opening triggers no save | `server.py:2167` |

So a restart that no save recorded **rewinds the counter**, and the next device
to register is handed a name that is already on disk as somebody's
designation. The picker then marks it `selected`, and `Open` takes a shell on
a host the operator never chose. The file already documents the rewind, for
the tunnel identity, at `server.py:272-278`.

The previous branch's placeholder covers the case where the designated name is
*absent* from the fleet. It cannot help when the name is present and wrong.

## Intent

A designation follows the device it was made for, across restarts and across
renames. When that device is not in the fleet, the designation resolves to
nothing rather than to whoever holds its old name.

## The anchor, and what it cannot do

`implant_id` is not random. The beacon derives it (`beacon.py:_generate_id`):

```
sha256("<platform.node()>:<platform.machine()>" [+ ":<eth0 MAC>"])[:16]
```

So it is stable across beacon restarts and identifies the host, which is why
`_handle_register` already uses it to recognise a returning device and keep its
name. Two limits a reader should know:

- On a host without `/sys/class/net/eth0` — any macOS box — the id is just
  `sha256("hostname:arch")`. **Two identically named machines of the same
  architecture collide.**
- Renaming a host changes its id, so it registers as a new device. The
  designation then resolves to nothing, which is the honest answer: the
  operator pointed at a host that, by this identity scheme, no longer exists.

Neither is made worse by this change; both are properties of the existing
identity.

## Goals

- A designation written for device X resolves to X's current fleet name, or to
  nothing — **never to a different device.** That last clause is the whole
  change; the first two are how it is achieved.
- A designation whose device is simply **gone** stays reportable, so the view
  can keep saying `channel unknown` with "no longer in the fleet" instead of
  claiming `closed` about a host nothing has heard from.
- A designation file written before this change keeps working.
- **No change to the view and no new rendered prose.** The absent case already
  has an answer.

## Amendment, 2026-11-26: the first draft of this design broke an existing guarantee

The draft said an absent device "resolves to `None`". The implementer built it,
measured it, and brought back the consequence: `TestTheViewNeverReportsAState
ItHasNotGot.test_an_agent_that_left_the_fleet_leaves_the_channel_unknown` went
red. That test defends a real property — `/state` answers `channel: unknown`
with *no longer in the fleet* when the designated device is absent — and the
draft silently replaced it with `closed`.

The draft had conflated two different absences. The view needs both:

| State | What the operator must read |
|---|---|
| Nothing is designated | `no device chosen`, and the picker offers the placeholder |
| Something is designated, and it is not here | `channel unknown`, *no longer in the fleet* |

So "resolves to nothing" was the wrong rule. The rule is one sentence:

> **`opshell_target()` returns the designated name only when that name cannot
> belong to a different device** — either the fleet entry holding it carries
> the matching id, or the fleet does not hold it at all.

Spelled out, with the dangerous case last:

| File | Fleet | Result |
|---|---|---|
| `id` matches the entry holding the name | present | that entry's current name |
| `id` matches an entry under a **different** name | present | that entry's current name — the designation follows the device |
| `id` matches nothing, and nobody holds the name | absent | the name, so the view says `unknown` |
| `id` present but not a usable string | — | treated as *matches nothing*: an unverifiable id must not be safer than a correct one |
| **`id` matches nothing, and another device holds the name** | present | **`None`** — this is the bug |
| no `id` at all (a file from before this change) | — | the name, as today; the next open upgrades the file |

**Ruling on the last row:** the safety rule is *not* applied to a file with no
`id`. Applying it would answer `None` whenever such a designation's device is
present — which is the common, correct case — to guard a window that lasts
only until the next open. The narrow bug is the better cost.

Two consequences of the table that a reader should not have to derive:

- **A damaged `id` is stricter than an absent one.** A file with no `id` keeps
  today's behaviour; a file with an unusable one is held to the safety rule.
  That is deliberate, and it is the only arrangement in which damaging the
  file is not a way to bypass the check. Pinned by
  `test_a_file_with_no_id_is_not_judged_by_who_holds_the_name`.
- **When two fleet entries share an id, the one holding the file's name
  wins.** Added during the build rather than designed here, and kept: the
  anchor's collision is acknowledged above as a limit this change does not
  fix, but without a tie-break *which* of the two colliding hosts the
  designation lands on would depend on registration order — that is, on dict
  order. An acknowledged limit may stay; an arbitrary outcome may not. One
  loop, its own test and its own mutation.

## Non-goals

- A better implant identity. The collision above is real and is not this
  change's to fix.
- Pruning the fleet, or persisting it on more paths. `_save_state`'s two call
  sites are a separate question.
- Anything about the ownership record, which answers a different question and
  is deliberately a separate file.

## Approaches

**A — resolve inside `opshell_target()` (chosen).** The function keeps its
signature: a name, or `None`. It reads the file, and when the file carries an
`id`, it returns the current name of the fleet entry whose `id` matches.
**All five callers and the whole view are unchanged**, because `state.target`
stays a name. The cost is that the function now reads `agents`, so it is no
longer a pure file read.

**B — return an id and resolve at each caller.** Rejected: five call sites,
four of them in routes, and the view would have to learn a second kind of
identifier. More surface for the same result.

**C — prune the fleet, or persist it on every registration, so names stop
being reused.** Rejected as the wrong layer: it changes how the fleet is
stored to fix how a designation is addressed, and it would not help a
designation whose device was renamed.

## What changes

1. **`opshell_remember(agent_name)`** also writes the implant id, read from
   `agents[agent_name]["id"]`. If it is missing — the agent vanished between
   the open and the write — it writes the name alone, which is today's
   behaviour.
2. **`opshell_target()`** resolves through the id when the file has one: the
   fleet entry whose `id` matches, by its current name, or `None`. With no
   `id` in the file it returns the name as it does today, so a designation
   written before this change keeps working; the next successful open upgrades
   the file.

Nothing else. The view, the strip, the picker, the routes and the ownership
record are untouched.

## Left by decision

- **A pre-change file is upgraded only on the next open**, not on read. A read
  that rewrote the file would make `/state` — a GET, polled every two seconds
  — a writer, and this interface already paid for a GET with a side effect
  once.
- **Two colliding hosts get one designation.** See the anchor's limits. Making
  the identity collision-proof is its own change.

## Verification

- A designation written for a device, the fleet rebuilt with that device under
  a **different** name, and the designation resolving to the new name.
- The same, with the device **absent**: resolves to `None`, and the picker
  falls into the placeholder the previous branch built.
- The counter-case that is the whole point: the designation's name handed to a
  **different** device, and the designation resolving to `None` rather than to
  that device.
- A file holding only `{"agent": name}` resolving as before.
- Each test driven against a mutation of the line it covers.

Every line reference in this document is against `chore/recorded-leftovers`
at `79b7c53`, the commit this work starts from.
