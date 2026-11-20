# Operator Shell as a Window Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the operator shell a sticky card with window controls that survives a reload, can be parked under the agent list, and sizes its terminal to the space it actually has.

**Architecture:** Browser-side only. The card becomes a layer over `.content` rather than a modal overlay, so the agent list stays visible and clickable; minimising hides it in place and moves nothing, because `opshellPoll` — which is also the claim's heartbeat — stops when `#opshell-body` disappears. The `pagehide` listener that ended the session on every reload is removed and the existing 240-second lapse takes over, with the session id kept in the tab's `sessionStorage` so a reload restores the card and attaches a fresh shell.

**Tech Stack:** The inline interface in `software/c2/server.py` (plain ES2020, no bundler), vendored xterm.js 6.0.0, `unittest` with the node harness in `software/tests/test_operator_shell.py`.

**Spec:** `docs/superpowers/specs/2026-11-19-operator-shell-window-design.md` — part one only. Part two (the login shell and colour) lands on its own branch and gets its own plan.

## Global Constraints

- **Nothing server-side changes.** No route, no `opshell.py`, no new field on `/api/opshell/state`. Part one is the view.
- **The browser baseline is Safari 14.1**: the page already uses flexbox `gap` (95 declarations) and optional chaining (164 uses). Anything later sits behind a `typeof` check. `test_no_browser_feature_newer_than_the_page_is_used_unguarded` polices four JavaScript names and **no CSS** — CSS newer than flex `gap` is out by judgement, not by a guard.
- **`#opshell-body` stays the single element `opshellRender` fills.** The card's chrome lives outside it.
- **The `✕` is never wired as `onclick="opshellEndSession()"` from `opshellRender`**: `test_a_live_channel_with_no_local_session_offers_both_controls` asserts that string is absent from the render.
- **Every new module variable is a one-line `let opshell<Name> = <value>;`** or the harness's `decls` regex (`test_operator_shell.py`, `_node`) will not lift it.
- **Every new function must be added to `_node`'s lifted name list** or it is absent from all node tests.
- **CSS goes in the `<style>` block, never in a string inside a lifted function.** `js_function` counts raw braces with no string awareness; one `{` in a JS string mis-slices the source and breaks all node tests at once.
- **The minimised card is appended to `.sidebar` after `.agent-list`**, never inside the list: `refreshAgents` rebuilds `#agent-list.innerHTML` every 3 s.
- **The strip states only the geometry that was sent.** `state.geometry` is `None` until a bridge exists and is pinned that way by `test_with_no_session_live_there_is_no_geometry_to_report`.
- **The seven properties named in `test_the_count_of_behavioural_tests_has_not_quietly_dropped` keep their tests.** Its floor is 35.
- Suite command: `/usr/bin/python3 -m unittest discover -s software/tests -t .` (~8 min). Feature file: `/usr/bin/python3 -m unittest software.tests.test_operator_shell` (~22 s).

## Review Focus

Five conditions the spec implies that no task's happy path exercises, most likely to bite first. Each one's test is added to the task that owns the code.

1. **A reload while the card is parked** comes back parked, not open — and never as two cards. Owned by Task 5.
2. **A restored session id whose session is gone** (the tab was shut longer than the 240 s lapse) must not draw a live card; the operator sees the idle picker and a reason. Owned by Task 2.
3. **A window too narrow for a terminal** — the measured geometry must never send 0 or a negative, and must stay inside `SHELL_GEOMETRY_MAX`. Owned by Task 6.
4. **Two tabs, one parked and one open**: the first `/close` answers "not the last", and the parked card must not then claim the session ended. Owned by Task 5.
5. **A session id in `sessionStorage` written by a different team server** on the same origin must not be adopted. Owned by Task 2.

---

### Task 1: The lapse takes over from `pagehide`

**Files:**
- Modify: `software/c2/server.py` (the `pagehide` listener, around `:10936`)
- Test: `software/tests/test_operator_shell.py`

**Interfaces:**
- Produces: nothing new. Removes the only caller of `opshellEndSession` that fires on a page transition.

- [ ] **Step 1: Invert the test that pins the guard being removed**

`test_a_closed_tab_ends_the_session_too` currently asserts the listener exists. Replace it with:

```python
    def test_no_page_transition_ends_the_session(self):
        """A reload is not a decision to stop working.

        `pagehide` fires on a reload and on any navigation, not only on a
        closed tab, and no browser signal tells them apart. Measured
        before this change: attach, reload, and the log shows
        `POST /api/opshell/close` with `sessions: 0` -- the session died
        because the page was replaced by itself.

        The closed tab is covered by the lapse instead:
        `opshell.LAPSE_GRACE` seconds of silence and the next check-in
        retires the claim.
        """
        self.assertNotRegex(
            SERVER_SRC, r'addEventListener\("(pagehide|beforeunload|unload)"',
            "a page-transition handler is back; it cannot tell a reload "
            "from a closed tab")
```

- [ ] **Step 2: Move the `keepalive` assertion to a test that still has a home**

`keepalive:true` on `/close` is asserted inside the test being replaced. Add to `TestTheGlyphAndTheView`:

```python
    def test_the_close_survives_a_page_that_is_going_away(self):
        # `opshellEndSession` runs from the ✕ and from `exit`; both can
        # coincide with a page being torn down, and a close that is
        # cancelled with the page leaves the claim held until the lapse.
        self.assertIn("keepalive:true", self.js_function("opshellEndSession"))
```

- [ ] **Step 3: Run both tests to verify the first fails**

Run: `/usr/bin/python3 -m unittest software.tests.test_operator_shell -v -k page_transition`
Expected: FAIL — the listener is still there.

- [ ] **Step 4: Delete the listener**

Remove the `window.addEventListener("pagehide", ...)` statement and its comment block from `software/c2/server.py`. Leave the startup block that follows it untouched: `test_c2_hardening.py` pins the shape of `if(storedToken()){ setInterval(refreshAgents, 3000); ... } else { askForToken(false); }`.

- [ ] **Step 5: Run the feature file**

Run: `/usr/bin/python3 -m unittest software.tests.test_operator_shell`
Expected: OK, with the test count one higher than before.

- [ ] **Step 6: Commit**

```bash
git add software/c2/server.py software/tests/test_operator_shell.py
git commit -m "fix(opshell): a reload is not a decision to stop working"
```

---

### Task 2: The session survives a reload

**Files:**
- Modify: `software/c2/server.py` (new module state and two functions; `showOperatorShell`; `opshellOpen`; `opshellEndSession`)
- Test: `software/tests/test_operator_shell.py`

**Interfaces:**
- Produces:
  - `let opshellStore = "raccoon_opshell_session";` — the `sessionStorage`
    key. Task 5 writes the minimised flag beside it under
    `opshellStore + "_min"`; both are cleared together.
  - `function opshellRemember(session)` — writes the id, or clears it when `session` is falsy
  - `function opshellRecall()` — returns the id or `""`
  - `async function opshellResume()` — called once at startup: if an id is remembered and `/api/opshell/state?session=<id>` answers `state: "live"` with `sessions > 0`, open the card and attach; otherwise forget the id and do nothing
- Consumes: `opshellSession`, `opshellAttach`, `showOperatorShell` from the existing code.

- [ ] **Step 1: Write the failing tests**

In `TestTheViewRunsAndIsNotJustRead`:

```python
    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_remembered_session_is_resumed_on_load(self):
        got = self._node(
            "sessionStorage.setItem(opshellStore, 'kept-1');\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot', sessions:1}}];\n"
            "await opshellResume();\n"
            "console.log(JSON.stringify({session: opshellSession,"
            " urls: posted.map(p => p.url)}));")
        self.assertEqual(got["session"], "kept-1")
        self.assertTrue(got["urls"][0].startswith("/api/opshell/state"),
                        got["urls"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_session_that_is_gone_is_forgotten_rather_than_drawn(self):
        """Review Focus 2.

        The tab was shut for longer than the lapse, so the claim was
        retired and the channel stopped. A card drawn from the remembered
        id would look live over nothing.
        """
        got = self._node(
            "sessionStorage.setItem(opshellStore, 'stale-1');\n"
            "replies = [{ok:true, status:200, body:{state:'idle',"
            " channel:'closed', sessions:0}}];\n"
            "await opshellResume();\n"
            "console.log(JSON.stringify({session: opshellSession,"
            " remembered: sessionStorage.getItem(opshellStore),"
            " bodies: Object.keys(els)}));")
        self.assertIsNone(got["session"])
        self.assertIsNone(got["remembered"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_session_this_server_does_not_know_is_not_adopted(self):
        """Review Focus 5.

        Two team servers on one origin -- a port change on localhost is
        the common case -- leave each other's ids in the same
        `sessionStorage`. An id the server answers `sessions: 0` for is
        not this server's.
        """
        got = self._node(
            "sessionStorage.setItem(opshellStore, 'other-servers-id');\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot', sessions:0}}];\n"
            "await opshellResume();\n"
            "console.log(JSON.stringify({session: opshellSession,"
            " remembered: sessionStorage.getItem(opshellStore)}));")
        self.assertIsNone(got["session"])
        self.assertIsNone(got["remembered"])
```

And a source-level test in `TestTheGlyphAndTheView`, because the startup wiring is not reachable from the harness:

```python
    def test_the_page_resumes_a_shell_at_startup(self):
        # Inside the `storedToken()` branch, so a page behind the token
        # gate asks nothing.
        at = SERVER_SRC.index("setInterval(refreshAgents, 3000)")
        gate = SERVER_SRC[at - 200:at + 400]
        self.assertIn("opshellResume()", gate)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_operator_shell -v -k resume`
Expected: FAIL — `no function opshellResume in server.py`.

- [ ] **Step 3: Add `opshellStore`, `opshellRemember(session)`, `opshellRecall()` and `opshellResume()`**

`opshellRemember` is called wherever `opshellSession` is assigned: with the new id in `opshellOpen`, and with `""` in `opshellEndSession`. `opshellResume` reuses the existing `fetch`-with-`H()` shape rather than `api()`, so a 401 does not throw into startup.

- [ ] **Step 4: Announce the new shell on a resume**

The spec requires it: a reload gives a **new** shell, because the bridge
closed with the stream and a reconnect is a fresh `bash` — measured, pid 75
to 78, `/etc` back to `/`, a set variable gone. Silence about that is the
lying interface this feature exists to avoid.

`opshellResume` sets a flag that `opshellAttach` reads once, so the
terminal's first line — beside the existing `live on … · history is off …`
note — says that this is a new shell and the previous one is gone. Test, in
the same class:

```python
    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_resumed_session_says_it_is_a_new_shell(self):
        got = self._node(
            "sessionStorage.setItem(opshellStore, 'kept');\n"
            "els['opshell-term'] = el('opshell-term');\n"
            "const term = fakeTerm();\n"
            "globalThis.Terminal = function(){ return term; };\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot', sessions:1}},"
            " {ok:true, status:200, stream: fakeStream(['x'])}];\n"
            "await opshellResume();\n"
            "console.log(JSON.stringify({said: term.lines.join(' ')}));")
        self.assertRegex(got["said"], r"(?i)new shell")
        self.assertRegex(got["said"], r"(?i)previous|earlier|gone")
```

- [ ] **Step 5: Call `opshellResume()` from the startup block**

Inside the existing `if(storedToken()){ ... }` branch, after `refreshAgents();`.

- [ ] **Step 6: Add the harness pieces this needs**

`_node`'s lifted name list gains `opshellRemember`, `opshellRecall`, `opshellResume`. The environment's `sessionStorage` stub already supports `getItem`/`setItem`/`removeItem`.

- [ ] **Step 7: Run the feature file**

Run: `/usr/bin/python3 -m unittest software.tests.test_operator_shell`
Expected: OK.

- [ ] **Step 8: Commit**

```bash
git add software/c2/server.py software/tests/test_operator_shell.py
git commit -m "feat(opshell): a reload restores the card and attaches again"
```

---

### Task 3: The harness grows a DOM

**Files:**
- Modify: `software/tests/test_operator_shell.py` (`_NODE_ENV`)

**Interfaces:**
- Produces, inside `_NODE_ENV`:
  - `document.querySelector(sel)` — resolves `.sidebar`, `.content`, `.agent-list` and `#id` against the same `els` registry
  - `el(id)` gains `classList` with `add`/`remove`/`contains`/`toggle`, a `style` object, `remove()`, `appendChild(child)` recording into `children`, and `getBoundingClientRect()` returning a settable `box`
  - `document.createElement(tag)` returns a node of the same shape, with a real `innerHTML` setter that records
  - `fakeBox(w, h)` — sets the next created node's rect, so a measurement can be driven

- [ ] **Step 1: Write the test that the harness reports what a browser would**

```python
    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_harness_dom_answers_like_a_browser(self):
        """The harness has lied twice, in the same way both times.

        Its `fetch` could not reject and its `abort()` only recorded a
        string, and six mutations survived because of it. Every stub this
        task adds is therefore exercised here, so that a stub which
        quietly does nothing fails this test rather than a later one.
        """
        got = self._node(
            "const n = document.createElement('div');\n"
            "n.classList.add('a'); n.classList.toggle('b');\n"
            "n.style.display = 'none';\n"
            "n.innerHTML = '<p>x</p>';\n"
            "const host = el('host'); host.appendChild(n);\n"
            "fakeBox(820, 600);\n"
            "const probe = document.createElement('span');\n"
            "const box = probe.getBoundingClientRect();\n"
            "console.log(JSON.stringify({cls: [n.classList.contains('a'),"
            " n.classList.contains('b'), n.classList.contains('c')],"
            " style: n.style.display, html: n.innerHTML,"
            " kids: host.children.length, box: [box.width, box.height],"
            " found: document.querySelector('#host') === host}));")
        self.assertEqual(got["cls"], [True, True, False])
        self.assertEqual(got["style"], "none")
        self.assertEqual(got["html"], "<p>x</p>")
        self.assertEqual(got["kids"], 1)
        self.assertEqual(got["box"], [820, 600])
        self.assertTrue(got["found"])
```

- [ ] **Step 2: Run it to verify it fails**

Run: `/usr/bin/python3 -m unittest software.tests.test_operator_shell -v -k harness_dom`
Expected: FAIL — `classList.add is not a function`.

- [ ] **Step 3: Extend `_NODE_ENV`**

Keep the existing `els` registry and `el(id)` as the single source of nodes, so the fifteen tests that set `els['opshell-body']` and read `.innerHTML` keep working unchanged.

- [ ] **Step 4: Run the whole feature file, not only the new test**

Run: `/usr/bin/python3 -m unittest software.tests.test_operator_shell`
Expected: OK. A changed `innerHTML` setter is the likeliest way to break the existing tests; they must all still pass.

- [ ] **Step 5: Commit**

```bash
git add software/tests/test_operator_shell.py
git commit -m "test(opshell): the harness gets a DOM that can be measured"
```

---

### Task 4: The card, with window controls, as a layer

**Files:**
- Modify: `software/c2/server.py` (the `<style>` block; `showOperatorShell`; new functions)
- Test: `software/tests/test_operator_shell.py`

**Interfaces:**
- Produces:
  - `.opshell-card` and `.opshell-chrome` CSS in the `<style>` block: the card absolutely positioned over `.content`, a flex column, the chrome a flex row
  - `function opshellChrome(name)` — returns the chrome's markup: the `>_` glyph, `name`, then `_` and `✕` buttons wired to `opshellMinimise(event)` and `opshellClose(event)`
  - `async function opshellClose(ev)` — ends the session and takes the card down; the only path the `✕` uses
- Consumes: `opshellTeardown`, `opshellEndSession`.

- [ ] **Step 1: Write the failing tests**

```python
    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_card_sits_over_the_content_and_not_inside_it(self):
        # `renderAgentView` writes `#content.innerHTML` on every agent
        # click, and this design wants the agent list clickable. A card
        # that lived inside `.content` would lose its terminal to a click.
        got = self._node(
            "els['content'] = el('content');\n"
            "els['content'].innerHTML = '<div class=\"empty\"></div>';\n"
            "await showOperatorShell();\n"
            "console.log(JSON.stringify({content: els['content'].innerHTML,"
            " bodyExists: !!document.getElementById('opshell-body')}));")
        self.assertIn("empty", got["content"])
        self.assertTrue(got["bodyExists"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_cross_ends_the_session_and_takes_the_card_down(self):
        got = self._node(
            "opshellSession = 'sid'; els['opshell-card'] = el('opshell-card');\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "nextReply = {ok:true, status:200, body:{state:'closing'}};\n"
            "await opshellClose();\n"
            "console.log(JSON.stringify({urls: posted.map(p => p.url),"
            " session: opshellSession, removed}));")
        self.assertEqual(got["urls"], ["/api/opshell/close"])
        self.assertIsNone(got["session"])
        self.assertIn("opshell-card", got["removed"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_an_agent_click_does_not_detach_a_live_terminal(self):
        # The condition the layer exists for, driven rather than reasoned
        # about: `renderAgentView` writes `#content.innerHTML`, and the
        # card is a sibling layer, so the terminal's host must survive.
        got = self._node(
            "els['content'] = el('content');\n"
            "await showOperatorShell();\n"
            "opshellTerm = fakeTerm();\n"
            "els['content'].innerHTML = '<div class=\"pcard\">agent</div>';\n"
            "console.log(JSON.stringify({"
            " host: !!document.getElementById('opshell-term') ||"
            " !!document.getElementById('opshell-body'),"
            " content: els['content'].innerHTML}));")
        self.assertTrue(got["host"],
                        "an agent click took the card's body with it")
        self.assertIn("pcard", got["content"])

    def test_the_chrome_carries_both_window_controls(self):
        chrome = self.js_function("opshellChrome")
        self.assertIn("opshellMinimise(", chrome)
        self.assertIn("opshellClose(", chrome)
        # Not the inert handler, and not from the render: the render is
        # asserted elsewhere to be free of it.
        self.assertNotIn("opshellEndSession()", chrome)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_operator_shell -v -k card`
Expected: FAIL — `no function opshellChrome in server.py`.

- [ ] **Step 3: Add the CSS**

In the `<style>` block. `.opshell-card{position:absolute;inset:0;z-index:50;display:flex;flex-direction:column;background:var(--bg)}` over `.content`, which is already `position:relative` or becomes so; the chrome in the page's own red and mono, the controls as `.topbar-ico-btn`-sized buttons.

- [ ] **Step 4: Rewrite `showOperatorShell` to build the card**

It stops creating `.loot-overlay`/`.loot-panel` and instead appends a `.opshell-card` to `.content`'s parent, containing the chrome and `#opshell-body`. The `✕` in the heading that `opshellTeardown` used goes away with the overlay; `opshellTeardown(card)` keeps its signature and its named test.

- [ ] **Step 5: Add `opshellChrome(name)` and `opshellClose(ev)`**

- [ ] **Step 6: Register the new names in `_node`**

- [ ] **Step 7: Run the feature file and the hardening file**

Run: `/usr/bin/python3 -m unittest software.tests.test_operator_shell software.tests.test_c2_hardening`
Expected: OK. The hardening file is in because `tools/storyboards/c2_tour.json` sweeps `.loot-overlay` and is pinned there; the tour does not open this view, so nothing should change, and this run proves it.

- [ ] **Step 8: Commit**

```bash
git add software/c2/server.py software/tests/test_operator_shell.py
git commit -m "feat(opshell): the shell is a card over the content, with window controls"
```

---

### Task 5: Minimise, park, and restore

**Files:**
- Modify: `software/c2/server.py` (the `<style>` block; new state and functions; `opshellPoll`)
- Test: `software/tests/test_operator_shell.py`

**Interfaces:**
- Produces:
  - `let opshellMinimised = false;`
  - `function opshellMinimise(ev)` — sets the flag, hides the card with `style.display`, and draws the parked card
  - `function opshellRestore(ev)` — the inverse
  - `function opshellParked(state)` — the parked card's markup: the `>_` glyph, the host, the channel's state; or `session ended` with the duration when `opshellLast` is set
  - `.opshell-parked` CSS: full width, `1px solid var(--red-dim)`, the glyph, **no status dot** — `--red-dim` is the border of `.agent-card.active`, so a parked shell must not read as a selected agent
- Consumes: `opshellLast`, `opshellTeardown`, `opshellRestore` from Task 4's chrome.

- [ ] **Step 1: Write the failing tests**

```python
    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_minimising_keeps_the_body_so_the_heartbeat_keeps_beating(self):
        """`opshellPoll` returns when `#opshell-body` is missing, and that
        poll is the claim's heartbeat. Taking the card apart would let the
        240-second lapse fire under a parked session."""
        got = self._node(
            "opshellSession = 'sid';\n"
            "els['opshell-card'] = el('opshell-card');\n"
            "els['opshell-body'] = el('opshell-body');\n"
            "els['sidebar'] = el('sidebar');\n"
            "opshellMinimise();\n"
            "nextReply = {ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot'}};\n"
            "await opshellPoll();\n"
            "console.log(JSON.stringify({minimised: opshellMinimised,"
            " hidden: els['opshell-card'].style.display,"
            " polls: posted.filter(p => p.url.includes('/state')).length,"
            " carries: posted[0] && posted[0].url.includes('session=')}));")
        self.assertTrue(got["minimised"])
        self.assertEqual(got["hidden"], "none")
        self.assertEqual(got["polls"], 1)
        self.assertTrue(got["carries"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_reload_comes_back_parked_and_as_one_card(self):
        """Review Focus 1."""
        got = self._node(
            "sessionStorage.setItem(opshellStore, 'kept');\n"
            "sessionStorage.setItem(opshellStore + '_min', '1');\n"
            "els['sidebar'] = el('sidebar'); els['content'] = el('content');\n"
            "replies = [{ok:true, status:200, body:{state:'live',"
            " channel:'open', host:'parrot', sessions:1}}];\n"
            "await opshellResume();\n"
            "console.log(JSON.stringify({minimised: opshellMinimised,"
            " parked: els['sidebar'].children.length}));")
        self.assertTrue(got["minimised"])
        self.assertEqual(got["parked"], 1)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_session_that_ended_while_parked_says_so(self):
        got = self._node(
            "opshellLast = {duration: 92};\n"
            "const html = opshellParked({state:'closed', channel:'closed',"
            " host:'parrot'});\n"
            "console.log(JSON.stringify({html}));")
        self.assertRegex(got["html"], r"(?i)session ended")
        self.assertIn("92", got["html"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_parked_card_does_not_claim_an_end_another_tab_refused(self):
        """Review Focus 4.

        Two tabs are two claims. The other tab's close answers "not the
        last", the channel stays up, and this parked card must keep saying
        the channel is open rather than announcing an end that did not
        happen.
        """
        got = self._node(
            "opshellLast = null;\n"
            "const html = opshellParked({state:'live', channel:'open',"
            " host:'parrot', reason:'another view is holding this channel'});\n"
            "console.log(JSON.stringify({html}));")
        self.assertNotRegex(got["html"], r"(?i)session ended")
        self.assertRegex(got["html"], r"(?i)open")

    def test_the_parked_card_is_not_mistakable_for_a_selected_agent(self):
        style = SERVER_SRC[SERVER_SRC.index(".opshell-parked"):]
        style = style[:style.index("}")]
        self.assertIn("--red-dim", style)
        # `.agent-card.active` is the other thing with that border, and it
        # carries a status dot. This one does not.
        parked = self.js_function("opshellParked")
        self.assertNotIn('class="dot', parked)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_operator_shell -v -k park`
Expected: FAIL — `no function opshellParked in server.py`.

- [ ] **Step 3: Add the state, the CSS and the three functions**

The parked card is appended to `.sidebar` **after** `.agent-list`; add the comment saying why, because `refreshAgents` rebuilds the list every 3 s and the next reader will want to tidy it inside. The minimised flag is also remembered in `sessionStorage` under `opshellStore + "_min"` so Task 2's resume can restore the state it was in.

- [ ] **Step 4: Register the new names in `_node`**

- [ ] **Step 5: Add the seven-property guard's eighth entry**

`test_the_count_of_behavioural_tests_has_not_quietly_dropped` names the properties that cost this branch a Critical. Add `test_minimising_keeps_the_body_so_the_heartbeat_keeps_beating`: a parked session whose heartbeat stops is a channel stopped under a working operator.

- [ ] **Step 6: Run the feature file**

Run: `/usr/bin/python3 -m unittest software.tests.test_operator_shell`
Expected: OK.

- [ ] **Step 7: Commit**

```bash
git add software/c2/server.py software/tests/test_operator_shell.py
git commit -m "feat(opshell): minimise parks the shell under the agent list"
```

---

### Task 6: The geometry comes from the real box

**Files:**
- Modify: `software/c2/server.py` (`opshellAttach`; a new function)
- Test: `software/tests/test_operator_shell.py`

**Interfaces:**
- Produces: `function opshellMeasure(host)` → `[cols, rows]`, measured from an off-screen probe span in `var(--mono)` at 12 px against `host.getBoundingClientRect()`, floored at `[20, 5]` and capped at `1000` (the wire's `SHELL_GEOMETRY_MAX`, which `opshell._dimension` already enforces server-side)
- Consumes: the card's body element from Task 4.

- [ ] **Step 1: Write the failing tests**

```python
    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_geometry_is_measured_from_the_card(self):
        got = self._node(
            "fakeBox(1600, 900);\n"
            "const host = el('opshell-term');\n"
            "host.box = {width: 1600, height: 900};\n"
            "console.log(JSON.stringify({pair: opshellMeasure(host)}));")
        cols, rows = got["pair"]
        self.assertGreater(cols, 120)
        self.assertGreater(rows, 40)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_a_window_too_narrow_still_gets_a_terminal(self):
        """Review Focus 3.

        A 0 or a negative would be clamped server-side by
        `opshell._dimension`, so the operator would get a 1-column
        terminal and no explanation. The floor is on this side.
        """
        for w, h in ((120, 40), (1, 1), (0, 0)):
            got = self._node(
                "const host = el('opshell-term');\n"
                "host.box = {width: %d, height: %d};\n"
                "console.log(JSON.stringify({pair: opshellMeasure(host)}));"
                % (w, h))
            cols, rows = got["pair"]
            self.assertGreaterEqual(cols, 20, (w, h))
            self.assertGreaterEqual(rows, 5, (w, h))
            self.assertLessEqual(cols, 1000, (w, h))
            self.assertLessEqual(rows, 1000, (w, h))

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_pair_that_is_measured_is_the_pair_that_is_sent(self):
        got = self._node(
            "els['opshell-term'] = el('opshell-term');\n"
            "els['opshell-term'].box = {width: 1000, height: 500};\n"
            "globalThis.Terminal = function(o){ globalThis.made = o;"
            " return fakeTerm(); };\n"
            "opshellSession = 'sid';\n"
            "nextReply = {ok:true, status:200, stream: fakeStream(['x'])};\n"
            "await opshellAttach({state:'live', host:'parrot'});\n"
            "const url = posted.find(p => p.url.includes('/stream')).url;\n"
            "console.log(JSON.stringify({made: [made.cols, made.rows],"
            " url}));")
        cols, rows = got["made"]
        self.assertIn("cols=%d&rows=%d" % (cols, rows), got["url"])
```

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_operator_shell -v -k geometry`
Expected: FAIL — `no function opshellMeasure in server.py`.

- [ ] **Step 3: Add `opshellMeasure(host)`**

The probe is created, measured and removed inside the function; it must not be left in the DOM. Where `getBoundingClientRect` reports a zero-size probe — a browser that has not laid out yet — fall back to the current `[120, 40]` rather than dividing by zero.

- [ ] **Step 4: Use it in `opshellAttach`**

Replace `(state.geometry||[120,40])` with the measured pair. `state.geometry` keeps its meaning — what a live session sent — and the strip keeps stating only that.

- [ ] **Step 5: Register the new name in `_node`**

- [ ] **Step 6: Run the feature file**

Run: `/usr/bin/python3 -m unittest software.tests.test_operator_shell`
Expected: OK, including `test_with_no_session_live_there_is_no_geometry_to_report`, which must not change.

- [ ] **Step 7: Commit**

```bash
git add software/c2/server.py software/tests/test_operator_shell.py
git commit -m "feat(opshell): the terminal is the size of the space it has"
```

---

### Task 7: Say it in the documentation

**Files:**
- Modify: `docs/C2_DEMO.md` (the Operator Shell paragraph, around `:89`)
- Modify: `docs/TUNNEL.md` (the lifetime paragraphs, around `:460-500`)
- Modify: `README.md` (the capability row, around `:608`)
- Test: `software/tests/test_docs.py`

**Interfaces:**
- Consumes: nothing. Produces the operator-facing account of Tasks 1–6.

- [ ] **Step 1: Write the failing test**

In `test_docs.py`:

```python
    def test_the_tunnel_page_states_what_a_closed_tab_now_costs(self):
        """The bound changed, and a page that still says "immediately"
        would be the lying documentation this branch keeps finding."""
        text = (REPO / "docs" / "TUNNEL.md").read_text()
        self.assertRegex(text, r"(?i)minimis|parked|window")
        self.assertRegex(text, r"240|four minutes")
        self.assertNotRegex(
            text, r"(?i)closing the (view|panel)[^.]*queues the shutdown",
            "the page still promises that closing the view queues the "
            "shutdown; only the cross does that now")
```

- [ ] **Step 2: Run it to verify it fails**

Run: `/usr/bin/python3 -m unittest software.tests.test_docs -v -k closed_tab`
Expected: FAIL.

- [ ] **Step 3: Rewrite the three passages**

- `docs/TUNNEL.md`: the window behaviour; `✕` ends it, `_` parks it and keeps it running; a reload restores the card and attaches a **new** shell; a closed tab now costs up to 240 s plus one interval instead of ending immediately, and why that is acceptable; a parked session holds a worker thread, a bridge, a pty and one of the shell port's four slots for as long as it is parked.
- `docs/C2_DEMO.md`: replace "Leaving the session queues the shutdown", which becomes false. Prose only — `test_docs.py` derives the README's section count from `^## \d+\. ` headings and its badge from the file count in `docs/screenshots`.
- `README.md`: the capability row gains the window behaviour in one clause.

- [ ] **Step 4: Run the docs file**

Run: `/usr/bin/python3 -m unittest software.tests.test_docs`
Expected: OK, including `test_every_header_button_is_named_in_the_tour` and `test_no_heading_has_its_paragraph_glued_to_it`.

- [ ] **Step 5: Run the full suite**

Run: `/usr/bin/python3 -m unittest discover -s software/tests -t .`
Expected: OK.

- [ ] **Step 6: Commit**

```bash
git add docs/C2_DEMO.md docs/TUNNEL.md README.md software/tests/test_docs.py
git commit -m "docs: the operator shell is a window now, and what that costs"
```
