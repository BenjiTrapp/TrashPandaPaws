# Operator Shell: the picker names the device `Open` will use — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When the operator shell cannot honour "the device the picker shows is the device `Open` will use", the picker offers nothing to open instead of handing back the alphabetically first device.

**Architecture:** Two edits to `software/c2/server.py`. The view's `opshellPicker` prepends an option with an empty value when no candidate equals `state.target`; the `api_opshell_open` route splits one answer into two, so "nothing was named" is told apart from "that device is unknown". The status strip, `opshellRender` and the remembered designation are not touched.

**Tech Stack:** Python 3.9 + Flask (the C2), vanilla JS in `server.py`'s inlined page, `unittest` with the suite's existing node harness for the view and Flask's test client for the route.

**Spec:** `docs/superpowers/specs/2026-11-26-operator-shell-device-designation-design.md`

## Global Constraints

- **No sentence in the status strip changes.** `opshellRender` is not edited. `TestTheViewDoesNotOverclaim` must pass untouched.
- **Two new strings, exactly these:** the option's label `choose a device`, and the route's error `choose a device first`.
- **The ordinary path renders byte-for-byte as today:** a `state.target` that is in `candidates` gets `selected` and no extra option.
- **`404 no such agent` keeps its `refused` field, capped at 64 characters.**
- **No new dependency**, in `software/requirements.txt` or `software/tests/requirements.txt`. Python 3.9 floor.
- **Every test is driven against a mutation of the line it covers**, with `__pycache__` cleared and `python3 -B` (`.superpowers` note of 2026-11-23: a stale `.pyc` once hid a mutation and it read green).
- **The suite's verdict is the process exit status**, not any `Ran N tests` line: one module starts a nested `unittest` in a subprocess.

## Review Focus

Five inputs the spec implies and no task's happy path exercises, most likely first. Each has its test in the task that owns the code.

1. **`{"agent": 123}`** — today `(body.get("agent") or ...).strip()` raises `AttributeError` on a non-string and answers `500`. Same family as the `c2.fallback: true` crash this repo already fixed. A reasonable operator expects a refusal, not a stack trace. → Task 2.
2. **An empty fleet.** No beacon has checked in, so `candidates` is `[]`. The picker must still offer nothing to open rather than an empty list the browser reads as nothing at all. → Task 1. (The route needs no test of its own here: its answer to an unnamed device does not depend on the fleet's size.)
3. **`{"agent": "   "}`** — a whitespace name is not a device. It must land in "nothing named", not in "unknown device". → Task 2.
4. **A body that names a device while another is remembered.** The split must not break the fallback that makes the placeholder work: a body naming nothing still opens the remembered designation. → Task 2.
5. **A beacon whose hostname is literally `choose a device`.** Agent names come from the device. The placeholder must be identifiable by its empty value, never by its label. → Task 1.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `software/c2/server.py` | the C2, the inlined page | `opshellPicker` (`:9421-9431`), `api_opshell_open` (`:2121-2126`) |
| `software/tests/test_operator_shell.py` | this feature's whole suite | add to `TestTheViewRunsAndIsNotJustRead` (`:4084`, owns `render`) and `TestOpeningTheChannel` (`:1201`, owns the open route's refusals) |
| `docs/superpowers/specs/2026-11-23-operator-shell-window-look-design.md` | part three's record | the known-limitation note at `:358-361` gets a superseded line |

No file is created. Both test homes already exist and already hold this feature's neighbours.

---

### Task 1: The picker offers nothing to open

**Files:**
- Modify: `software/c2/server.py:9421-9431` (`opshellPicker`)
- Test: `software/tests/test_operator_shell.py`, in `TestTheViewRunsAndIsNotJustRead` (`:4084`)

**Interfaces:**
- Consumes: `opshellPicker(state)` as it stands, and `_GuiCase.render(**state)`, which returns `opshellRender(state)`'s markup through the node harness.
- Produces: an `<option>` whose `value` is the empty string, present exactly when no entry of `state.candidates` equals `state.target`. Task 2 relies on the page therefore posting a body with no `agent` key in that state.

- [ ] **Step 1: Commit the design and this plan, on their own**

```bash
git add docs/superpowers/specs/2026-11-26-operator-shell-device-designation-design.md \
        docs/superpowers/plans/2026-11-26-operator-shell-device-designation.md
git commit -m "docs(opshell): the picker names the device Open will use"
```

- [ ] **Step 2: Write the failing tests**

In `TestTheViewRunsAndIsNotJustRead`, with `FLEET = ["badger", "clumsy-raccoon", "parrot"]` as a class attribute (`candidates` is `sorted(agents)`, so alphabetical order is the real order and `badger` is what the browser hands back today):

```python
def test_a_fleet_with_no_designation_offers_nothing_to_open(self):
    html = self.render(state="idle", channel="closed", candidates=self.FLEET)
    self.assertIn('<option value="">choose a device</option>', html)
    self.assertNotIn(" selected>", html)

def test_a_designation_that_left_the_fleet_offers_nothing_to_open(self):
    # The half no note carried: the strip names `raccoon-bandit` while the
    # browser would hand back `badger`, so Open took a shell on a device
    # the view had just named a different one.
    html = self.render(state="idle", channel="closed",
                       candidates=self.FLEET, target="raccoon-bandit")
    self.assertIn('<option value="">', html)
    self.assertNotIn(" selected>", html)

def test_a_designation_in_the_fleet_is_selected_and_gets_no_placeholder(self):
    html = self.render(state="idle", channel="closed",
                       candidates=self.FLEET, target="parrot")
    self.assertIn('<option value="parrot" selected>', html)
    self.assertNotIn('<option value="">', html)

def test_an_empty_fleet_offers_only_the_placeholder(self):
    html = self.render(state="idle", channel="closed", candidates=[])
    self.assertEqual(html.count("<option"), 1, html)
    self.assertIn('<option value="">', html)

def test_the_placeholder_is_told_by_its_empty_value_not_its_label(self):
    # Hostnames come from the device, so a beacon can be called this.
    html = self.render(state="idle", channel="closed",
                       candidates=["choose a device"])
    self.assertEqual(html.count('<option value="">'), 1, html)
    self.assertIn('<option value="choose a device">', html)
```

- [ ] **Step 3: Run them to verify they fail**

Run: `python3 -B -m unittest software.tests.test_operator_shell.TestTheViewRunsAndIsNotJustRead -v`
Expected: the four new tests FAIL — no `<option value="">` in the markup. `test_a_designation_in_the_fleet_...` passes already; it is the fence that the ordinary path does not change.

- [ ] **Step 4: Add the empty-valued option in `opshellPicker` (`software/c2/server.py:9421`)**

The list begins with `<option value="">choose a device</option>` when no entry of `state.candidates` equals `state.target`, and is otherwise exactly what it is today. One predicate over `(state.candidates || [])`, in the style of the `.map` already there; the label is a literal written here, so it needs no `esc`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python3 -B -m unittest software.tests.test_operator_shell -v`
Expected: PASS, and `TestTheViewDoesNotOverclaim` and `TestTheGlyphAndTheView` unchanged.

- [ ] **Step 6: Prove each test by mutation**

Delete `__pycache__` first. Three mutations, one at a time, each run under `python3 -B`:
1. The option is emitted unconditionally → `test_a_designation_in_the_fleet_...` must go red.
2. The condition is inverted → the first two must go red.
3. The condition tests `state.target` for emptiness instead of membership → `test_a_designation_that_left_the_fleet_...` must go red, and that mutation is the todo's original framing, so its death is the point.

Restore the file and `cmp` against a known-good copy: a mutation run that dies in a timeout leaves the mutation in the tree (`.superpowers` note, trap 3).

- [ ] **Step 7: Commit**

```bash
git add software/c2/server.py software/tests/test_operator_shell.py
git commit -m "fix(opshell): the picker offers nothing to open when nothing is designated"
```

---

### Task 2: The route tells "nothing named" from "unknown device"

**Files:**
- Modify: `software/c2/server.py:2121-2126` (`api_opshell_open`)
- Test: `software/tests/test_operator_shell.py`, in `TestOpeningTheChannel` (`:1201`)

**Interfaces:**
- Consumes: `opshell_target()` (`:1804`), which returns the remembered designation or `None`; `agents`, the fleet; `_RouteCase.post(path, payload)`, which returns the Flask response.
- Produces: `400 {"error": "choose a device first"}` when nothing is named from either source; `404 {"error": "no such agent", "refused": <name>}` otherwise, unchanged.

- [ ] **Step 1: Write the failing tests**

In `TestOpeningTheChannel`, beside `test_an_unknown_agent_is_refused_by_name` (`:1252`):

```python
def test_naming_nothing_is_not_reported_as_an_unknown_device(self):
    answer = self.post(self.url("/api/opshell/open"), {})
    self.assertEqual(answer.status_code, 400)
    self.assertEqual(answer.get_json()["error"], "choose a device first")
    self.assertEqual(self.sm.task_queues, {})

def test_a_remembered_designation_opens_for_a_body_that_names_nothing(self):
    # What makes the picker's placeholder safe: it posts no `agent` key,
    # and the fallback must survive the split. The designation is written
    # rather than earned by opening first -- a second open would be on
    # the adoption path and would prove this only incidentally. Writing
    # it is this suite's own pattern, from
    # `test_a_damaged_record_refuses_on_the_first_request_after_a_restart`.
    (self.data_dir / "opshell-target.json").write_text(
        '{"agent": "%s"}' % self.AGENT)
    answer = self.post(self.url("/api/opshell/open"), {})
    self.assertEqual(answer.status_code, 200)

def test_an_agent_field_that_is_not_a_string_is_refused_not_a_crash(self):
    # `.strip()` on an int answered 500. The same shape as the
    # `c2.fallback: true` crash on the beacon.
    for bad in (123, True, ["badger"], {"agent": "badger"}):
        answer = self.post(self.url("/api/opshell/open"), {"agent": bad})
        self.assertEqual(answer.status_code, 400, repr(bad))
        self.assertEqual(self.sm.task_queues, {}, repr(bad))

def test_a_whitespace_name_names_nothing(self):
    answer = self.post(self.url("/api/opshell/open"), {"agent": "   "})
    self.assertEqual(answer.status_code, 400)
```

And **extend the existing `test_an_unknown_agent_is_refused_by_name`
(`:1252`)** rather than adding a near-twin beside it — it already asserts
the `404` and the empty queue, and what this change adds is that the name
survives the split:

```python
    self.assertEqual(answer.get_json()["refused"], "no-such-raccoon")
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -B -m unittest software.tests.test_operator_shell.TestOpeningTheChannel -v`
Expected: FAIL — `404` where `400` is wanted, and a `500` (or `AttributeError` in the log) for the non-string cases.

- [ ] **Step 3: Split the resolve and the guard in `api_opshell_open` (`software/c2/server.py:2121`)**

Resolve the name through one helper that yields a string or the empty string — `_named(value) -> str`, returning `value.strip()` for a `str` and `""` for anything else — applied to both sources, because the designation file is hand-editable and can hold a non-string too:

```python
agent_name = _named(body.get("agent")) or _named(opshell_target())
```

Then two guards where there was one: an empty `agent_name` returns `400` with `choose a device first`; a name not in `agents` returns today's `404` with `refused: agent_name[:64]`. `400` for an incomplete request follows the close route's own `session is required` (`:2196`). Where `_named` lives is the builder's call.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -B -m unittest software.tests.test_operator_shell -v`
Expected: PASS, including `TestWhatOpenRefusesInsteadOfQueueing` — its three `409` refusals must still come back as `409`, so the new `400` sits before none of them wrongly.

- [ ] **Step 5: Prove each test by mutation**

Delete `__pycache__`. Four mutations, one at a time:
1. `400` → `404` → `test_naming_nothing_...` red.
2. The two guards merged back into `not agent_name or agent_name not in agents` → `test_naming_nothing_...` red.
3. `_named` returns `str(value).strip()` instead of `""` for a non-string → `test_an_agent_field_that_is_not_a_string_...` red.
4. The fallback `or _named(opshell_target())` dropped → `test_a_remembered_designation_...` red.

Restore and `cmp` against a known-good copy.

- [ ] **Step 6: Run the whole suite**

Run: `python3 -B -m unittest discover -s software/tests -t . 2>&1 | tail -40; echo "exit $?"`
Expected: the exit status is `0`. Read the exit status, not a `Ran N tests` line.

- [ ] **Step 7: Commit**

```bash
git add software/c2/server.py software/tests/test_operator_shell.py
git commit -m "fix(opshell): naming nothing is not the same as naming an unknown device"
```

---

### Task 3: The record says this was overtaken

**Files:**
- Modify: `docs/superpowers/specs/2026-11-23-operator-shell-window-look-design.md:358-361`

**Interfaces:**
- Consumes: nothing. No test pins this document (checked: no test module names it).
- Produces: nothing code reads.

- [ ] **Step 1: Mark the note superseded, where it stands**

Part three's *Found by looking, and covered by no test* bullet says the picker falls back to its first option and that it was left because it is a rendered sentence. Add below it that this work overtook it, naming what was actually wrong — that the option is the argument `Open` posts, and that a designation which left the fleet was the worse half — and pointing at the new design. The bullet itself is not edited away: it is the state before the work, which is the shape `f032820` used for the egress design's premise.

- [ ] **Step 2: Check the two documents do not now disagree**

Run: `grep -n "first option\|no device chosen" docs/superpowers/specs/2026-11-23-operator-shell-window-look-design.md docs/superpowers/specs/2026-11-26-operator-shell-device-designation-design.md`
Expected: part three's bullet reads as history with the superseded line under it; nothing claims the picker still falls back.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-11-23-operator-shell-window-look-design.md
git commit -m "docs(opshell): part three's picker note says what overtook it"
```

---

## Manual verification

Part three's record of this defect was made by looking, not by a test, so the last check is a pair of eyes. One beacon checks in as this host.

```bash
python3 tools/demo_env.py --operator-port 18500 --token demo-token --data-dir /tmp/opshell-check
```

Open `http://127.0.0.1:18500`, give it `demo-token`, press `>_`, and check in order:

1. **Nothing designated.** The picker reads `choose a device`; the strip reads `no device chosen`. The two agree.
2. **`Open a shell` without choosing.** The body says `choose a device first` — not `no such agent`.
3. **Choose the device, press `Open`.** It opens as before, and the designation is now remembered.
4. **A designation that left the fleet.** Stop the server, point the designation at a device that is not in the fleet, start it again:

```bash
printf '{"agent":"raccoon-bandit"}' > /tmp/opshell-check/opshell-target.json
```

   The picker reads `choose a device` again, the strip names `raccoon-bandit`, and `Open` without choosing answers `no such agent` with `raccoon-bandit` — which names the dead designation instead of silently opening a shell on another device.

If `tools/capture_gui.py` is used for a screenshot, kill its headless Chrome afterwards: it leaks one per failed step, and six of them reddened this suite once (project note of 2026-11-25).
