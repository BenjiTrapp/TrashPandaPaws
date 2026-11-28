# Parked items, ruled — 2026-11-28

The registers this repository keeps for open work are four, and three of
them are prose rather than checkboxes:

- *Known limits* in [`docs/AGENT.md`](../../AGENT.md#known-limits);
- the *Known limitations, as built* sections of the design documents in
  this directory;
- the ledgers under `.superpowers/sdd/*/progress.md`, which are
  git-ignored and therefore the one register a clone cannot read;
- the branches that are finished and not landed.

This document closes the third and second of those. Every item parked in a
ledger, and every entry in a spec's limitations list, is named below with
one of two outcomes: **fixed**, with where; or **ruled**, with the reason
and what it costs if the ruling is wrong. Nothing is left as "deferred"
without one of the two.

Plan checkboxes are deliberately not a register here. 884 of them are
unticked across `docs/superpowers/plans/`, while every plan's declared
deliverable exists; they record what a dispatch was told, not what is
open.

---

## 1. The agent layer's safety module (`2026-10-30-agent-layer`)

Two rulings were parked during that plan's Task 2, after six fix rounds.
Both are **reaffirmed** rather than reopened, and the reason is the same
one the ledger gives: each round tried to make a single mechanism both
complete and precise at a tier with no operator override, and that is not
achievable for "is this command about to destroy a disk".

1. **A quoted separator classifies as a wipe.** `grep "x|rm -rf /" log`
   reads as a wipe, because `_normalise` strips quotes before separators
   are spaced out. **Ruled: carried.** Fixing it means carrying quote
   state through normalisation, which is a larger change than this
   repository has a reason to make: the router screens metacharacters
   upstream, and the worst case is an approval request for a log grep. —
   If wrong, an operator sees a knock they should not have seen, which is
   the tier-2 contract everywhere else in that module.
2. **An unrecognised program pointing a write at storage earns a knock,
   not a refusal.** **Ruled: kept.** Five rounds enumerated read-only
   tools and the list was never complete (`sg_inq`, `dmsetup`,
   `mountpoint`, `e2label`, `bcache-super-show`, `fsfreeze` were all
   missing, each an unoverridable refusal of an ordinary recon command).
   Recognised destroyers stay tier 1. — If wrong, an operator approves a
   knock they should have refused.

## 2. The provider chain (`2026-11-08-agent-llm-providers`)

Four items are parked in that ledger with written rulings already. They
are **reaffirmed** and listed so that a reader of this document does not
have to find the ledger: an expiry that `config-helper` itself reports as
past; the reviewer's Concern 1, where the ledger records that the earlier
ruling was too narrow; the `gcloud` row's wording about a subprocess; and
one out-of-scope note from the re-review. None of them changes what the
chain does; each is a statement about a message or a document.

## 3. The capability tier a failover keeps (`docs/AGENT.md`)

**Ruled: stays open, and the reason is in the code.** The entry's own text
names the two possible fixes. The one that would close it entirely —
giving the whole run the weakest link's tier in `config.load` — was
decided against during the provider work, and the decision is written
above `_failover_tier_note` in `software/agent/config.py`: it would
quietly change what an existing chain may do, and a phase-5 engagement
would be refused with nothing to say why. The operator is told instead,
in `/api/ai/status`, the startup log and the campaign form.

Overturning that ruling is an operator's call, not this sweep's: it trades
a silently weaker run for a silently narrower one. The documented lever
stays `AGENT_CAPABILITY_TIER`.

## 4. The end-to-end lab (`2026-11-16-e2e-docker-lab`)

**Reaffirmed.** Minor 1 is carried: an unattributed rescue appends an
`event_log` entry, and `_log_event` trims to 1000 entries once the log
passes 5000, so a beacon retrying in a loop costs bounded memory and
nothing else.

## 5. The login shell, parked at a blocked dispatch (`2026-11-20-operator-shell-login-shell`)

The plan stopped mid-flight: Tasks 1 and 2 complete and reviewed clean,
Task 3 implemented and reviewed at `d98f948` with two Important findings
open, Tasks 4 to 6 never started. The reason was environmental and is
recorded: every Bedrock model this network may reach is refused for
`bedrock:InvokeModelWithResponseStream` by the IAM policy
`Deny-Bedrock-Outside-Network`, and the one non-Bedrock route was stopped
by the user.

**Ruled: the two open Important findings are stated as limits, and the
unstarted tasks are not silently dropped.**

- `history_detail` is not length-capped, exactly as `user` is not. Both
  are strings an endpoint reports about itself, and the trust boundary for
  them is already stated in `docs/TUNNEL.md`. The same fix belongs to
  both, which is why neither has it: a cap on one and not the other would
  read as a decision nobody made. — If wrong, a hostile endpoint can make
  one sidebar line long.
- The reconnect the refusal text promises is untested. It is reachable by
  hand and the promise is in prose rather than in a test. — If wrong, a
  reconnect regresses and the refusal keeps promising it.
- Tasks 4 to 6 are **not** work this sweep claims. They remain a plan
  whose dispatch the environment refused; restarting them needs a model
  route this network allows, which is the operator's to provide.

## 6. The operator-shell window (`2026-11-19-operator-shell-window-design.md`)

Eight limitations are listed in that document's *Known limitations, as
built*, each already weighed against a change the plan forbade, and six of
them fail safe. **Ruled: all eight stand as written, with two notes.**

- Items 1 and 2 (the resume checks a count, not an identity; a duplicated
  tab duplicates the claim) both end in a refusal the view states, so the
  cost is a surprising message and never a channel left open. Closing item
  1 needs a per-session field on the state body, which that plan forbade
  and which belongs to whoever next changes that endpoint's shape.
- Item 4 (the size is fixed for the life of the connection) is the one a
  reader is most likely to mistake for a defect. It is a wire-format
  limit: the pair rides the password line and there is no resize message.
  A resize route is its own design.
- Items 3, 5, 6, 7 and 8 are statements about what the interface shows and
  when, and each says so in the document. No change.

## 7. The window's look (`2026-11-23-operator-shell-window-look-design.md`)

That document separates what was **seen** from what was **not seen at
all**, which is the honest shape, and this sweep does not turn either into
a claim. **Ruled:**

- The four findings "only looking found" stay recorded, not fixed: the
  13 px `Device` label against the 11 px picker, `root` said twice, the
  footnote with no margin at short heights, and `_` sitting lower than
  `✕`. Each is one rule in a stylesheet and none of them is wrong on the
  screen the operator uses; they belong in one pass over the strip's
  typography rather than four commits. — If wrong, the strip stays
  slightly ragged.
- The first of those four — the strip reading `no device chosen` while the
  picker showed a device — was already **fixed**, by
  `2026-11-26-operator-shell-device-designation`, and that document says
  so in place rather than deleting the note.
- "Not seen at all" stays not seen: the open dropdown (headless Chrome
  draws a native `<select>` outside the page), the waiting number,
  `closing`, a parked card, the terminal's own text and cursor, any
  scrollbar, and Safari. This sweep added no screenshots, so nothing here
  may be upgraded.
- The `.fd-btn` undefined `--bg2`/`--bg3`, fenced by a test, stays for the
  file browser's own change.

## 8. The device designation (`2026-11-26-operator-shell-device-designation`)

**Reaffirmed, both residuals.** An open dropdown is still destroyed every
two seconds and falls back to the value it had before opening, so `Open`
still acts on a device the list showed; and the poll cannot tell an
operator's pick from the markup's own default, so after another tab
changes the designation this tab keeps restoring the old one. In both
cases the Goal holds — no host is mis-targeted — and the sharper fix
(suppressing the re-render while a menu is open, or restoring only when
the value differs from the previous render's `state.target`) is a change
that should be reviewed on its own.

## 9. The recorded leftovers (`2026-11-26-recorded-leftovers`)

That sweep closed three items and pushed four out, each with a measurement.
Of those four:

- **Fixed here: `shipped-image.yml` floated on `ubuntu-latest`** while the
  arm64 row beside it named a release. Pinned to `ubuntu-24.04`, like
  `ci.yml`'s two jobs. The specific failure of the `ce6a73e` scar cannot
  repeat in that job — it needs no particular Python — but the pattern is
  the scar.
- **Ruled: the double run per PR stays.** The sweep measured that the two
  runs are not redundant: neither workflow overrides `ref:` on checkout,
  so the `pull_request` run tests the merge result and the `push` run
  tests the branch tip. The honest options are a trade-off, not a fix —
  restrict `push` to `main` and lose branch-without-PR coverage, drop
  `pull_request` and lose merge-result coverage, or keep both and pay for
  two runs. **Kept both.** Merge-result coverage is the one thing that
  catches "green on the branch, broken after the merge", and this run paid
  for that lesson twice in one evening: a Linux-only test-fixture defect
  and a Linux-only `getaddrinfo` difference, both invisible here. — If
  wrong, the cost is CI minutes on a public repository, where they are
  free.
- **Ruled: name reuse (`3d43cf73`) is its own design.** It changes what a
  designation *is* and touches the register path. Not folded into a sweep.
- **Ruled: `/api/agents/<id>/task` reading `request.json` stays.** It is
  the same crash class the twelve-route helper closed, at one site, and
  converting it changes a second behaviour (an unparseable body becomes a
  400 where it is now a 500). It is named in the commit that closed the
  twelve and in two test docstrings. — If wrong, one authenticated route
  answers 500 to a malformed body.
- **Ruled: the 49 `tunnel: no key store` warnings in a module run stay
  recorded.** This repository holds test output to be pristine and the
  warnings are a fixture minting a fresh store per test, not a product
  defect. The fix belongs with whoever next touches that fixture. — If
  wrong, a module run stays noisy.

## 10. `netifaces`, and the one place that still names it

**Fixed, with a residual that is out of reach.** `netifaces` was declared
in `software/requirements.txt`, demanded by both cover launchers'
`REQUIRED_PKGS`, and imported nowhere -- re-measured by walking every
tracked module under `software/`. Removed from all three; the implant's
dependency surface went from nine lines to eight.

`hardware/tests/firstboot_test.sh` still checks for it among the modules
it expects on a provisioned device. **Ruled: left, and named.** That file
is under `hardware/`, which this work may not change, and its list was
already stale in the same way -- it also checks for `pyroute2`, which
`software/requirements.txt` has never declared. Nothing has ever run it,
because no device has ever been built. — If wrong, a first-boot test that
has never been run reports one more module as missing.

`ldap3` is the half a fix could not reach and the Known-limits entry is
cut down to it: the image installs it by name *and* would get it anyway
through `impacket`, so those lines are redundant rather than
load-bearing, and removing them would change nothing.

## 11. The gsocket leg, the egress decider, and the deferred minors

These are not parked items: they are *Known limits* entries with their own
section in `docs/AGENT.md`, each written as a property of an arrangement
rather than as something left undone. They are untouched here, and the
twelve remaining deferred minors keep the reviewer's judgement that each
was not worth holding a change for.

---

## What this document is not

It is not a claim that the repository has no open work. What remains open
after this sweep is in *Known limits* with its own reason, and the
findings that were fixed in this run have had their entries deleted from
that list and their predicates deleted from
`software/tests/test_docs.py` — which is what keeps the list from
describing a past state of the code.
