# Operator Panel Layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the tunnel panel readable — the endpoint row becomes a card with fields instead of fourteen flex columns in a 600 px panel — using a card vocabulary the other panels can adopt later.

**Architecture:** Three new things in the operator page's inline stylesheet: a `panel-wide` modifier on `.loot-panel`, a `.pcard-*` card vocabulary, and a one-column fallback for narrow viewports. `drawTunnel` then renders each endpoint as one card: the endpoint's facts and its SOCKS port on the left, the shell session and its three commands on the right. Nothing else on the page changes, and the routes are untouched.

**Tech Stack:** Hand-written vanilla CSS and JavaScript inside `software/c2/server.py`'s `_OPERATOR_HTML` string; `unittest` against the page the server actually serves; Python 3.9.

**Spec:** [`docs/superpowers/specs/2026-11-12-operator-panel-layout-design.md`](../specs/2026-11-12-operator-panel-layout-design.md)

## Global Constraints

- **No third-party CSS or JavaScript, and no build step.** The page is hand-written and stays that way.
- **No server-side change.** `/api/server/tunnel`, `_tunnel_row` and every route are untouched; this is presentation only. No new route, no new state.
- **The new classes use no undefined variable.** `--dim` and `--bg3` are used across this page and are **not** defined in `:root`, so every declaration naming them is invalid. The card uses `--text2` for secondary text and `--surface2`/`--surface` for surfaces. Do not define the two globally — that would restyle seven other panels in a pass nobody has looked at them in.
- **The warning band is the panel's existing `--yellow` (`#ffcc00`)**, not `--orange`, so it matches every other warning in this GUI.
- **`.loot-item` and `.loot-panel`'s own `max-width:600px` are untouched.** The wide panel is a modifier; the eight narrow dialogs keep their width.
- **Every endpoint-influenced value goes through `esc()`.** One of them is a credential.
- **`.pcard-*`, not `.tunnel-*`.** These classes are meant to be adopted by Loot and Listeners in a follow-up.
- Tests are `unittest`, run from the worktree root with the main checkout's interpreter:
  `/Users/derbenji/gitRepos/TrashPandaPaws/software/.venv/bin/python -m unittest software.tests.test_tunnel_gui -v`
  Full suite: `… -m unittest discover -s software/tests -t .` — 3303 tests, green, one expected macOS skip at this plan's base.
- There is **no JavaScript runner in this repository**. Tests assert on the served page's source and text, never on a rendered DOM. Say so where it matters rather than implying more.

## Review Focus

Five conditions the spec implies that no happy path covers. Each one's test is named in brackets.

- **A row with no shell port** — no range configured, the range exhausted, or a front that could not bind — must render its reason in the shell column, not silently drop the column. [Task 2]
- **A disconnected endpoint** must still render its assigned ports and say why there is no live session; the state pill must not read connected. [Task 2]
- **Five endpoints at once**: the panel must still scroll vertically inside `max-height:70vh` with the wide modifier on, and the second card must not sit a screen below the first. [Task 1 for the scroll, Task 2 for the rows]
- **A narrow viewport (a laptop at ~1100 px)**: `.pcard-two` must collapse to one column rather than clip, because that is the anti-goal this whole task exists to clear. [Task 1]
- **Long values** — a 40-character identity, a long hostname, a long transcript path — must wrap or ellipsis inside the card rather than widen it. [Task 2]

---

## File Structure

| File | Responsibility |
|---|---|
| `software/c2/server.py` | Modify, two regions only: the inline `<style>` block (the new classes) and `showTunnel`/`drawTunnel` (the wide modifier and the card markup) |
| `tools/tunnel_demo_env.py` | Create: stands up a real tunnel server, endpoint and shell front behind the operator GUI, so the panel can be photographed and checked by hand |
| `software/tests/test_tunnel_gui.py` | Modify: the vocabulary's own tests, and the thirteen `TestTheTunnelPanel` assertions repointed or rewritten |
| `software/tests/test_tunnel_demo_env.py` | Create: that the demo environment builds a runnable configuration without starting anything |

---

### Task 1: The card vocabulary and the wide panel

**Files:**
- Modify: `software/c2/server.py` — the inline `<style>` block, beside the existing `.loot-panel`/`.loot-item` rules
- Test: `software/tests/test_tunnel_gui.py`

**Interfaces:**
- Consumes: the `:root` variables that resolve — `--bg`, `--surface`, `--surface2`, `--border`, `--text`, `--text2`, `--green`, `--yellow`, `--red`, `--mono`.
- Produces, for Task 2 to use by name:
  - `.loot-panel.panel-wide` — `max-width:900px`; `max-height` and `overflow-y` inherited from `.loot-panel` unchanged
  - `.pcard`, `.pcard-head`, `.pcard-pill` (with `.pcard-pill-ok`), `.pcard-two`, `.pcard-col-h`, `.pcard-kv`, `.pcard-port`, `.pcard-warn`, `.pcard-cmd` (with `.pcard-cmd-alt`), `.pcard-hint`
  - `.pcard-two` is `grid-template-columns:1fr 1.15fr` and collapses to a single column under its breakpoint

- [ ] **Step 1: Write the failing tests**

In `software/tests/test_tunnel_gui.py`, a new class beside `TestTheTunnelPanel`, reading the served page the way that class already does:

```python
def test_the_wide_panel_is_a_modifier_and_the_narrow_dialogs_keep_their_width(self):
    # .loot-panel still caps at 600px; .panel-wide is a separate rule at 900px
def test_the_wide_panel_keeps_the_panel_s_own_scrolling(self):
    # .panel-wide sets no max-height and no overflow of its own
def test_the_card_vocabulary_is_defined(self):
    # every class in the Produces list above appears as a rule in the page
def test_the_card_uses_no_undefined_variable(self):
    # no rule between the first and last .pcard rule names --dim or --bg3
def test_the_two_column_body_collapses_rather_than_clipping(self):
    # a media query names .pcard-two and sets grid-template-columns to one column
def test_the_warning_band_uses_the_panel_s_yellow(self):
    # the .pcard-warn rule names --yellow and not --orange
```

- [ ] **Step 2: Run them to verify they fail**

Run: `/Users/derbenji/gitRepos/TrashPandaPaws/software/.venv/bin/python -m unittest software.tests.test_tunnel_gui -v`
Expected: FAIL — the page defines no `.pcard` rule.

- [ ] **Step 3: Add the rules to the inline `<style>` block**

Follow the shapes in the spec's table. Two things the tests do not determine: `.pcard-kv` is `grid-template-columns:52px 1fr` with the label dim and right-aligned, following the existing `.fb-detail .fd-grid` idiom; `.pcard-cmd` carries `overflow-x:auto` and `white-space:pre` so a long command scrolls inside its own box instead of widening the card.

- [ ] **Step 4: Run them to verify they pass**

Run: the same command.
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add software/c2/server.py software/tests/test_tunnel_gui.py
git commit -m "feat(c2): a card vocabulary for the operator panels, and a wide variant"
```

---

### Task 2: The tunnel panel renders cards

**Files:**
- Modify: `software/c2/server.py` — `showTunnel` (the panel's class list) and `drawTunnel`'s `rows.forEach` body plus `shellBlock`
- Test: `software/tests/test_tunnel_gui.py` — the new assertions, and the thirteen in `TestTheTunnelPanel`

**Interfaces:**
- Consumes: Task 1's classes by name; the row fields `_tunnel_row` already passes through — `identity`, `state`, `hostname`, `os`, `peer`, `sessions`, `bytes_in`, `bytes_out`, `port`, `username`, `password`, `socks`, `socks_detail`, `linked`, `agent`, `shell`, `shell_password`, `shell_detail`, `shell_recording`, `pending`, `expected`, `refusal`, `detail`; and the page's existing `esc`, `bytes` and `refusals` helpers.
- Produces: nothing other tasks consume.

- [ ] **Step 1: Write the failing tests**

New assertions:

```python
def test_the_endpoint_rows_are_cards_and_no_longer_loot_items(self)
def test_the_card_puts_the_endpoint_s_facts_and_socks_on_the_left(self)
def test_the_shell_session_has_the_right_column_to_itself(self)
def test_each_command_sits_alone_in_a_box_behind_its_own_hint(self)
def test_a_disconnected_row_does_not_claim_to_be_connected(self)   # Review Focus
def test_a_long_identity_cannot_widen_the_card(self)               # Review Focus
def test_five_rows_render_five_cards(self)                         # Review Focus
```

Then the three rewrites the spec names, each asserting the same promise against the new shape:

```python
def test_one_generic_refusal_reader_serves_both_halves(self)       # was: count('indexOf("refused_")') == 1
def test_a_row_without_a_shell_port_shows_the_reason_in_the_shell_column(self)
def test_the_panel_shows_a_recording_badge_only_when_recording_is_on(self)  # keep the id, keep "record" out of the card
```

The remaining ten `TestTheTunnelPanel` assertions keep their promises and move their windows: the forward line still precedes the attach line, which still precedes the fallback; every endpoint-influenced value still goes through `esc()`; the two objects are still separate blocks; both crypto paths and any refusal still show; the SOCKS credential is still named for proxychains; the pending stop still shows its expected time.

- [ ] **Step 2: Run them to verify they fail**

Run: `… -m unittest software.tests.test_tunnel_gui -v`
Expected: FAIL — the rows are still `.loot-item`.

- [ ] **Step 3: Add `panel-wide` in `showTunnel`**

One class, on the panel this function creates. The other seven panel functions are not touched.

- [ ] **Step 4: Rebuild the row in `drawTunnel` as one `.pcard`**

The layout the spec fixes: head (identity, state pill, hostname and OS dim, Stop pushed right with its existing disabled state and reason); left column `the endpoint` (peer, crypto for both paths, traffic, the fleet line, then a `socks` sub-heading with the port and its RFC 1929 credential); right column `shell session` (the port with its session count, the password, the warning band, then three hint-and-command pairs — forward, attach, fallback). A row with no shell port renders `shell_detail` under the same heading in place of the port. Keep the three hint wordings that are in the panel today; keep the badge where it is.

- [ ] **Step 5: Run the focused module, then the full suite**

Run: `… -m unittest software.tests.test_tunnel_gui -v` then `… -m unittest discover -s software/tests -t .`
Expected: PASS; 3303 tests plus the new ones, one expected macOS skip.

- [ ] **Step 6: Commit**

```bash
git add software/c2/server.py software/tests/test_tunnel_gui.py
git commit -m "fix(c2): the tunnel panel's endpoint row is a card, not fourteen columns"
```

---

### Task 3: A tunnel demo environment, so the panel can be looked at

**Files:**
- Create: `tools/tunnel_demo_env.py`
- Test: `software/tests/test_tunnel_demo_env.py`

**Interfaces:**
- Consumes: `tunnel_server_config(config)` and `TunnelSupervisor(block, data_dir, *, cwd=…)` with `.start()`, `.status()`, `.key_store_path()`; `KeyStore(path).register_build(identity, psk)` and `.static_public()`; `PSK_LEN`; `TunnelEndpoint(config)` with `.run()`/`.stop()`; `create_app(crypto, token, data_dir, server_config=…, operator_port=…, tunnel_supervisor=…)`; `ServerCrypto`.
- Produces: `main(argv) -> int`; `demo_config(bind_port, socks_first, socks_last, shell_first, shell_last, transcript_dir) -> dict` returning the `{"c2": {"tunnel_server": …}}` block, which is the part a test can check without starting a process.

- [ ] **Step 1: Write the failing test**

```python
def test_the_demo_config_is_one_tunnel_server_validated_by_the_real_validator(self):
    # demo_config(...) passed through tunnel_server_config() yields the same
    # ports back, with a shell range and a transcript directory set
def test_the_shell_range_does_not_overlap_the_socks_range(self):
    # the defaults it ships cannot trip TunnelServer's own overlap refusal
def test_it_starts_nothing_on_import(self)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `… -m unittest software.tests.test_tunnel_demo_env -v`
Expected: FAIL — no module `tools.tunnel_demo_env`.

- [ ] **Step 3: Write the script**

A module docstring in the voice of `tools/demo_env.py`'s, saying plainly that it stands up a real tunnel server child, a real endpoint and a real shell front, that the PSK is registered by hand because there is no artifact here to carry one, and that nothing about it is specific to the machine. `main` takes `--operator-port` and `--token`, prints the operator URL, the identity, the assigned shell port and the transcript directory, and stays in the foreground until interrupted, stopping the endpoint and the supervisor on the way out.

- [ ] **Step 4: Run the test, then use the script for what it is for**

Run the test, then start the script, open the panel at 1440×900, and capture it:

```bash
python3 tools/capture_gui.py --url http://127.0.0.1:<port>/ \
    --out /tmp/tunnel_panel.png --width 1440 --height 900 --scale 2 \
    --eval "sessionStorage.setItem('raccoon_token','<token>'); setTimeout(()=>location.reload(),0); true" \
    --sleep 2.5 --click 'button.topbar-ico-btn[title="Tunnel"]' --sleep 1.5 --clip .loot-panel
```

Expected: no horizontal scrollbar in the panel, nothing clipped, both ports, both credentials, the warning and all three commands visible. **Attach the image to your report** — this is the only check in the plan that sees what an operator sees.

- [ ] **Step 5: Commit**

```bash
git add tools/tunnel_demo_env.py software/tests/test_tunnel_demo_env.py
git commit -m "tools: a tunnel demo environment, so the panel can be photographed"
```
