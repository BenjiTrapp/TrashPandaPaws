# Operator Shell, part three: the window look — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The operator shell is drawn as a window — framed, translucent, with its claims as pills and its terminal in a visible box — without changing a single thing it asserts or does.

**Architecture:** Everything lives in one Python string, `_OPERATOR_HTML` in `software/c2/server.py`: one inline `<style>` and the JS composers that build the card's markup. New `.opshell-*` rules go into that stylesheet, where the CSS tests already look for them, and the composers stop emitting inline `style=` attributes. No product code behind the view changes; no other panel's appearance changes.

**Tech Stack:** Python 3.9 (`unittest`), vanilla JS in the served page, node for the view's behavioural tests, the vendored xterm.js. Browser floor: Safari 14.1.

**Spec:** `docs/superpowers/specs/2026-11-23-operator-shell-window-look-design.md`

## Global Constraints

Copied from the spec; every task's requirements include these.

- `.opshell-card` keeps **exactly one** rule with that literal selector, and neither it nor `#opshell-card` may set `position`, `inset` or `z-index`, including inside `@media`.
- The frame never goes on `#opshell-term`: `opshellMeasure` reads that element's bounding rect (`server.py:9702`) for the `cols`/`rows` it sends to `/stream`.
- `#opshell-term` keeps `flex:1`, `min-height:72px`, `overflow:hidden`; `.opshell-live` keeps `display:flex`, `flex-direction:column`, `min-height:100%` and no `;height:`; `#opshell-body` keeps `flex:1` and `overflow:auto`.
- The card has exactly two children when there is no lost-resume note.
- The footnote's `&#10005;` stays an entity directly followed by the words `closes the card`, with no tag between them.
- Exactly one `loot-empty` occurrence in the closed-state render.
- The picker keeps `id="opshell-agent"` and a readable `.value`.
- Handlers stay inline `onclick="fn(event)"`, double-quoted, only on `<button>`.
- Safari 14.1: flexbox `gap` yes; `:has()`, container queries and unprefixed `backdrop-filter` no.
- `--mono` stays on its own line inside `:root`, ending in `;`.
- No wording changes to any sentence the view renders.
- `.fd-btn` and `.loot-empty` are **not** edited: the first is shared with the Listeners panel, the second with four panels.

## Review Focus

Five conditions the spec implies that no task's happy path exercises. Each has its test added to the task that owns the code.

- **`geometry: null`** — every state before a bridge exists. No pill, no empty element, no gap in the strip. (Task 2)
- **A hostile host or user** — `<img src=x onerror=...>`, quotes, an apostrophe. The pill markup must still pass them through `esc()`. (Task 2)
- **A host name of 300 characters** — the strip must wrap and leave the chrome's controls reachable, not push them out. (Task 2)
- **A card shorter than the terminal** — the new wrapper must not defeat `#opshell-term`'s 72 px floor or the body's own scrolling. (Task 3)
- **A browser at the Safari 14.1 floor** — no unprefixed `backdrop-filter`, no `:has()`, and `prefers-reduced-motion` still silences the cursor. (Task 1)

---

## File Structure

- `software/c2/server.py` — the inline `<style>` block (`:4359`–`:5387`) gains the `.opshell-*` rules; `opshellChrome` (`:8805`), `showOperatorShell` (`:8843`), `opshellRender` (`:9359`) and `opshellPicker` (`:9329`) stop emitting inline styles and the borrowed classes.
- `software/tests/test_operator_shell.py` — new assertions in the existing classes: CSS facts in `TestTheGlyphAndTheView`, markup facts in `TestTheViewRunsAndIsNotJustRead`, claims in `TestTheViewDoesNotOverclaim`.
- `.superpowers/sdd/2026-11-23-operator-shell-window-look/measure-geometry.html` — the throwaway page that measures `cols`/`rows` with the unmodified `opshellMeasure`. Git-ignored; re-run it where a task says to.

## Test helpers this plan introduces

The suite's real helpers are `css_rules(name, selector=None)` — which
returns **every** matching rule body, as a list — `js_function(name)`, the
module global `STYLE_BLOCK`, and `_node(script)`, which runs the view's
functions under node and returns whatever the script logs as JSON. Two thin
wrappers keep the tests below short. Add them to `_GuiCase`, beside
`css_rules` at `:3175`, in Task 1:

```python
    def one_rule(self, name, selector):
        """The single rule for this selector, or a failure naming it."""
        rules = self.css_rules(name, selector)
        self.assertEqual(len(rules), 1,
                         "expected exactly one %s rule, found %d"
                         % (selector, len(rules)))
        return rules[0]

    def render(self, session=None, **state):
        """`opshellRender(state)`'s markup, with `opshellSession` set."""
        return self._node(
            "opshellSession = %s;\n"
            "const html = opshellRender(%s);\n"
            "console.log(JSON.stringify({html}));"
            % (json.dumps(session), json.dumps(state)))["html"]
```

`render` needs node, so every test using it carries the file's existing
`@unittest.skipUnless(shutil.which("node"), "node is not installed")`.
**`one_rule` is added in Task 1, which uses it; `render` in Task 2, its
first caller** — a helper no test calls is a finding, not a convenience.

---

### Task 1: The card is a window

**Files:**
- Modify: `software/c2/server.py:4802` (`.opshell-card`), `:4803-4808` (`.opshell-chrome`)
- Test: `software/tests/test_operator_shell.py` (`TestTheGlyphAndTheView`)

**Interfaces:**
- Consumes: nothing.
- Produces: the class names `.opshell-chrome` keeps, and the card's own surface — Tasks 2 to 5 draw inside it.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_card_is_framed_and_therefore_inset(self):
    body = self.one_rule("opshell-card", ".opshell-card")
    for prop in ("border-radius", "box-shadow", "margin"):
        self.assertIn(prop, body,
                      "a framed card needs %s; measured, the frame and the "
                      "shadow are invisible without the margin" % prop)

def test_the_card_is_translucent_like_every_sibling_surface(self):
    body = self.one_rule("opshell-card", ".opshell-card")
    self.assertIn("var(--surface)", body)
    self.assertNotIn("background:var(--bg)", body)

def test_no_css_newer_than_the_browser_floor_is_used_unprefixed(self):
    for forbidden in (":has(", "@container", "aspect-ratio:"):
        self.assertNotIn(forbidden, STYLE_BLOCK)
    for idx in _indexes(STYLE_BLOCK, "backdrop-filter"):
        self.assertIn("-webkit-backdrop-filter",
                      STYLE_BLOCK[max(0, idx - 200):idx + 200])
```

`css_rule` is the existing single-rule helper at `:3183`; `_indexes` is a two-line module helper returning every start offset of a substring.

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -B -m unittest software.tests.test_operator_shell.TestTheGlyphAndTheView -v`
Expected: the first two FAIL (`margin` absent, `background:var(--bg)` present), the third passes already.

- [ ] **Step 3: Restyle `.opshell-card` and `.opshell-chrome`**

One rule for the card, as the existing pin requires: `flex:1`, the three flex declarations it already has, `margin:8px`, `background:var(--surface)`, `border:1px solid var(--border)`, `border-radius:8px`, `box-shadow:0 8px 32px rgba(0,0,0,0.6)`. No `position`, `inset` or `z-index`. The chrome gets `border-radius:8px 8px 0 0` and a vertical gradient from `--surface2`; `backdrop-filter`, if used at all, carries its `-webkit-` partner. Keep the comment above the rule and extend it with the measured cost: 2 columns and 1 row.

- [ ] **Step 4: Run the view's whole file**

Run: `python3 -B -m unittest software.tests.test_operator_shell -v 2>&1 | tail -5`
Expected: OK. `test_the_card_takes_the_content_column_and_not_the_whole_row` must still pass — it counts the rule and forbids positioning.

- [ ] **Step 5: Measure what the gutter cost**

Serve `.superpowers/sdd/2026-11-23-operator-shell-window-look/measure-geometry.html` and read the table. Expected, from the spec: `154×49` at 1440×900 against today's `159×53`. Record the three numbers in the commit message; if they differ from the spec by more than one column, stop and report rather than adjusting the margin silently.

- [ ] **Step 6: Mutate the margin**

Delete `margin:8px` from the rule and run `test_the_card_is_framed_and_therefore_inset`: it must fail. Restore it, `cmp` against a known-good copy, and say in the commit message that the mutation was made and caught. Delete the `__pycache__` and run with `-B`: a stale `.pyc` has hidden a mutation in this repo before.

- [ ] **Step 7: Commit**

```bash
git add software/c2/server.py software/tests/test_operator_shell.py
git commit -m "feat(opshell): the card is a framed, translucent window"
```

---

### Task 2: Every claim becomes a pill

**Files:**
- Modify: `software/c2/server.py:9359-9372` (the strip in `opshellRender`), the `<style>` block
- Test: `software/tests/test_operator_shell.py` (`TestTheViewDoesNotOverclaim`, `TestTheViewRunsAndIsNotJustRead`)

**Interfaces:**
- Consumes: the card and chrome from Task 1.
- Produces: `.opshell-strip` and `.opshell-pill` with the modifiers `.opshell-pill-root`, `.opshell-pill-rec`, `.opshell-pill-ok`; Task 4 reuses none of them.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_strip_is_a_class_and_not_an_inline_style(self):
    src = self.js_function("opshellRender")
    self.assertIn('class="opshell-strip"', src)
    self.assertNotIn('style="display:flex', src)

def test_a_claim_with_no_value_renders_no_pill(self):
    # geometry is null in every state before a bridge exists
    html = self.render(state="waiting", geometry=None, host="pi",
                       channel="closed", expected_checkin=12)
    self.assertNotIn('class="opshell-pill"></span>', html)
    self.assertEqual(html.count("opshell-pill"), 1)   # the channel, alone

def test_every_claim_the_strip_made_is_still_made(self):
    html = self.render(session="mine", state="live", host="pi", user="root",
                       root=True, geometry=[118, 34], recording=True,
                       channel="open")
    for claim in ("pi", "root", "118x34", "recording", "channel open"):
        self.assertIn(claim, html)

def test_a_hostile_host_cannot_write_markup_into_a_pill(self):
    html = self.render(session="mine", state="live", channel="open",
                       host='<img src=x>"\'')
    self.assertNotIn("<img", html)
    self.assertIn("&lt;img", html)

def test_a_very_long_host_does_not_push_the_controls_away(self):
    self.assertIn("flex-wrap:wrap",
                  self.one_rule("opshell-strip", ".opshell-strip"))
```

`_render` is the existing node bridge that returns `opshellRender(state)`'s output for a state dict.

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -B -m unittest software.tests.test_operator_shell -v -k pill -k strip`
Expected: the first four FAIL (no class, no pills, an empty `<span>` for the missing geometry), the wrap test FAILs with "no such rule".

- [ ] **Step 3: Rewrite the strip and add its rules**

In `opshellRender`, build the strip from a list of present claims, each `'<span class="opshell-pill...">' + esc(value) + '</span>'`, and skip a claim whose value is empty or null — which is what closes the geometry hole. Keep the existing `chan` folding and the `state.reason` paragraph exactly as they are. In the stylesheet: `.opshell-strip` (flex, `gap`, `flex-wrap:wrap`, the bleed `margin:0 -16px 10px` with `padding:0 16px 8px`, `border-bottom:1px solid var(--border)`, `font-family:var(--mono)`), `.opshell-pill` modelled on `.pcard-pill` but its own rule, and the three modifiers in `--orange`, `--red` and `--green`.

- [ ] **Step 4: Run the file and the docs tests**

Run: `python3 -B -m unittest software.tests.test_operator_shell software.tests.test_docs 2>&1 | tail -5`
Expected: OK. `test_the_strip_states_the_user_and_does_not_assume_root` and the rest of `TestTheViewDoesNotOverclaim` must still pass.

- [ ] **Step 5: Mutate the two that matter**

Delete the skip-when-empty branch, run the file: `test_a_claim_with_no_value_renders_no_pill` must fail. Replace one `esc(` in the strip with the bare value: the hostile-host test must fail. Restore both, `cmp` the file against a known-good copy, and report both results in the commit message.

- [ ] **Step 6: Commit**

```bash
git add software/c2/server.py software/tests/test_operator_shell.py
git commit -m "feat(opshell): the strip states each claim as a pill, and none it has no value for"
```

---

### Task 3: The terminal gets a box that does not cost it room

**Files:**
- Modify: `software/c2/server.py:9377` (the live branch), `:4831-4832`, the `<style>` block
- Test: `software/tests/test_operator_shell.py` (`TestTheViewRunsAndIsNotJustRead`)

**Interfaces:**
- Consumes: `.opshell-strip` from Task 2.
- Produces: `.opshell-screen`, the wrapper that carries the frame; `#opshell-term` stays the measured host.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_frame_is_not_on_the_measured_host(self):
    body = self.one_rule("opshell-term", "#opshell-term")
    for prop in ("padding", "border:", "border-width"):
        self.assertNotIn(prop, body,
                         "opshellMeasure reads this element's rect for the "
                         "cols it sends to /stream (server.py:9702)")

def test_the_frame_is_on_a_wrapper_inside_the_live_box(self):
    html = self.render(session="mine", state="live", channel="open",
                       host="pi", geometry=[120, 40])
    self.assertLess(html.index('class="opshell-live"'),
                    html.index('class="opshell-screen"'))
    self.assertLess(html.index('class="opshell-screen"'),
                    html.index('id="opshell-term"'))
    screen = self.one_rule("opshell-screen", ".opshell-screen")
    for prop in ("flex:1", "min-height:0", "display:flex", "padding",
                 "border-radius"):
        self.assertIn(prop, screen)

def test_a_card_too_short_still_scrolls_instead_of_clipping(self):
    self.assertIn("min-height:72px",
                  self.one_rule("opshell-term", "#opshell-term"))
    self.assertIn("overflow:auto",
                  self.one_rule("opshell-body", "#opshell-body"))

def test_the_bodys_scrollbar_is_the_houses_and_the_terminals_is_not_touched(self):
    self.assertIn("#opshell-body::-webkit-scrollbar", STYLE_BLOCK)
    self.assertNotIn(".xterm", STYLE_BLOCK)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -B -m unittest software.tests.test_operator_shell -v -k frame -k scroll`
Expected: the wrapper tests FAIL (`.opshell-screen` does not exist), the scrollbar test FAILs, the other two pass already and are kept as the guard they are.

- [ ] **Step 3: Add the wrapper and its rule**

In the live branch, wrap the host: `'<div class="opshell-screen"><div id="opshell-term"></div></div>'`. Leave the footnote and its `&#10005;` entity untouched — the entity must stay directly followed by `closes the card`. In the stylesheet: `.opshell-screen{flex:1;min-height:0;display:flex;padding:8px;border:1px solid var(--border);border-radius:6px;background:rgba(0,0,0,0.6)}`, `#opshell-term` unchanged, and `#opshell-body::-webkit-scrollbar` plus its thumb in `--red-dim`, matching the house's `width:6px;border-radius:3px`.

- [ ] **Step 4: Run the file**

Run: `python3 -B -m unittest software.tests.test_operator_shell 2>&1 | tail -5`
Expected: OK, including `test_the_terminal_host_has_a_box_to_be_measured_in` and the four geometry tests at `:6574-6838`.

- [ ] **Step 5: Measure the terminal's room again**

Re-run `measure-geometry.html`. Expected: unchanged from Task 1's numbers, because the wrapper's cost was already in them. A change here means the wrapper's padding differs from the page's — report it.

- [ ] **Step 6: Mutate the frame onto the measured host**

Move the wrapper's `padding:8px` and its border onto `#opshell-term` and run `test_the_frame_is_not_on_the_measured_host`: it must fail. Then, still mutated, re-run `measure-geometry.html` and record what the geometry becomes — that number is the bug this task exists to prevent, and it belongs in the commit message beside the test's failure. Restore, `cmp` against a known-good copy, run with `-B`.

- [ ] **Step 7: Commit**

```bash
git add software/c2/server.py software/tests/test_operator_shell.py
git commit -m "feat(opshell): the terminal sits in a box, on a wrapper the measurement does not read"
```

---

### Task 4: The picker and the buttons stop being system parts

**Files:**
- Modify: `software/c2/server.py:9329-9337` (`opshellPicker`), `:9368-9372` (the attach pair), the `<style>` block
- Test: `software/tests/test_operator_shell.py`

**Interfaces:**
- Consumes: the card's surface from Task 1.
- Produces: `.opshell-btn`, `.opshell-btn-primary`, `.opshell-pick`.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_shells_buttons_sit_in_a_row(self):
    body = self.one_rule("opshell-btn", ".opshell-btn")
    self.assertIn("display:inline-flex", body)
    self.assertNotIn("display:flex;", body)

def test_the_shell_no_longer_borrows_the_file_download_button(self):
    for name in ("opshellPicker", "opshellRender"):
        self.assertNotIn("fd-btn", self.js_function(name))

def test_the_listeners_panel_keeps_its_own_button_untouched(self):
    self.assertEqual(len(_css_rules(STYLE_BLOCK, "fd-btn", ".fd-btn")), 1)
    self.assertIn("var(--bg2)", self.one_rule("fd-btn", ".fd-btn"))

def test_the_picker_is_themed_and_still_readable_by_its_id(self):
    html = self.render(state="idle", channel="closed", candidates=["pi"])
    self.assertIn('id="opshell-agent"', html)
    self.assertIn("opshell-pick", html)
    self.assertIn("var(--border)", self.one_rule("opshell-pick",
                                                ".opshell-pick"))
```

The third test is deliberate: it pins that this change does **not** fix `.fd-btn`'s undefined variable, because that belongs to the Listeners panel and its own verification.

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -B -m unittest software.tests.test_operator_shell -v -k button -k picker`
Expected: the first, second and fourth FAIL; the third passes and stays as the fence it is.

- [ ] **Step 3: Swap the classes and add the rules**

`class="fd-btn"` becomes `class="opshell-btn"` in `opshellPicker` and in the two attach-state buttons, with `opshell-btn-primary` on "Open a shell" and "Attach"; the `<select>` gains `class="opshell-pick"` and keeps `id="opshell-agent"`. All `onclick="fn(event)"` attributes stay exactly as they are. In the stylesheet: `.opshell-btn` with `display:inline-flex`, the house's `4px` radius, `font-size:11px` and the `0.15s` transition; `.opshell-btn-primary` in `rgba(255,26,26,0.12)` with a `--red-dim` border; `.opshell-pick` after `.log-controls select`'s pattern but with defined variables only.

- [ ] **Step 4: Run the file and the node class**

Run: `python3 -B -m unittest software.tests.test_operator_shell 2>&1 | tail -5`
Expected: OK, including the three node tests that set `els['opshell-agent'].value` and `test_the_end_button_actually_ends_something`, which matches `onclick="([a-zA-Z]+)\(([^"]*)\)"`.

- [ ] **Step 5: Mutate the row**

Change `.opshell-btn`'s `display:inline-flex` to `display:flex` — the defect `.fd-btn` has — and run `test_the_shells_buttons_sit_in_a_row`: it must fail. Restore, `cmp`, run with `-B`, and report it in the commit message.

- [ ] **Step 6: Commit**

```bash
git add software/c2/server.py software/tests/test_operator_shell.py
git commit -m "feat(opshell): the picker and the buttons are the interface's own, not the system's"
```

---

### Task 5: The body stops wearing the loading class

**Files:**
- Modify: `software/c2/server.py:8853` (`showOperatorShell`), `:4815` (`#opshell-body`)
- Test: `software/tests/test_operator_shell.py`

**Interfaces:**
- Consumes: everything above.
- Produces: nothing further.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_body_is_not_permanently_a_loading_message(self):
    src = self.js_function("showOperatorShell")
    self.assertNotIn('classList.add("loot-loading")', src)
    self.assertIn('class="loot-loading"', src)   # the placeholder, as the
                                                 # four other panels write it

def test_the_body_states_its_own_text_size(self):
    body = self.one_rule("opshell-body", "#opshell-body")
    self.assertIn("font-size", body)
    self.assertIn("color:var(--text)", body)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -B -m unittest software.tests.test_operator_shell -v -k loading -k body`
Expected: both FAIL.

- [ ] **Step 3: Move the class onto the placeholder**

`showOperatorShell` writes `body.innerHTML = '<div class="loot-loading">Loading...</div>'` and no longer adds the class to the body itself — the shape the Listeners, Tunnel and Loot panels already use. `#opshell-body` gains `font-size:13px;color:var(--text)` beside its existing four declarations.

- [ ] **Step 4: Run the whole suite**

Run: `python3 -B -m unittest discover -s software/tests -t . 2>&1 | tail -5`
Expected: `OK`, 4324 tests plus the ones this plan added. Anchor on the **first** `Ran N tests` line, never the tail: a module in this suite starts a nested run whose verdict can land at the end.

- [ ] **Step 5: Commit**

```bash
git add software/c2/server.py software/tests/test_operator_shell.py
git commit -m "fix(opshell): the card's body is not a loading message"
```

---

### Task 6: Look at it, and say what is not proved

**Files:**
- Modify: `docs/superpowers/specs/2026-11-23-operator-shell-window-look-design.md` (a "Known limitations, as built" section)
- Modify, only under the condition below: `docs/TUNNEL.md`
- Test: `software/tests/test_docs.py`

- [ ] **Step 1: See it in a browser**

Run the C2 with the demo data, open the operator GUI, open the shell view, and capture the live state, the waiting state and the closed state. The waiting state must still show a **number**, and the closing state must still read `closing`.

- [ ] **Step 2: Write the limitations down**

In the design doc, a section naming what the build could not measure: no live device, which states were seen in a browser and which only in tests, and the `.fd-btn` fix left to the Listeners panel.

- [ ] **Step 3: Touch `docs/TUNNEL.md` only if it now says something false**

Read its Operator Shell section. Edit it **only** if a sentence there describes the view's appearance in a way this branch made untrue — the strip's shape, the terminal's frame, the picker. If every sentence is still true, change nothing and say so in the commit message. The pills, the gutter and the box are not facts the documentation claimed, so the expected outcome is no change.

- [ ] **Step 4: Check the documentation still matches**

Run: `python3 -B -m unittest software.tests.test_docs 2>&1 | tail -3`
Expected: OK. If a doc test fails, the wording changed — which this plan forbids; revert the wording rather than the test.

- [ ] **Step 5: Commit**

```bash
git add docs software/tests
git commit -m "docs(opshell): what the window look was measured against, and what it was not"
```
