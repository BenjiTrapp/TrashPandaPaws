# An egress decider on the implant — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give a dropped drop-box three connection-establishing verbs and an operator-configured policy that picks one of them on its own when the team server cannot be reached.

**Architecture:** Three new verbs in the beacon's existing dispatch, a fixed gate in code that refuses anything reducing the implant's own reachability, and a rule evaluator over the rescue evidence the beacon already assembles. No model, no weights. The policy is read from `c2.egress_decider` by `beacon_config_from_fallback`, so it reaches the drop-box only.

**Tech Stack:** Python 3.9 stdlib only (`beacon.py` is served to a target as source text), `unittest`.

**Spec:** `docs/superpowers/specs/2026-11-20-implant-egress-decider-design.md`

## Global Constraints

- **Python 3.9 exactly.** CI asserts `sys.version_info[:2] == (3, 9)`. No `match`, no `dict | dict`, no `X | None`.
- **The suite is `unittest`, not pytest:** `python3 -m unittest discover -s software/tests -t .` from the repository root, ~530 s. pytest is not installed.
- **`software/c2/beacon.py` may import only the standard library** — never a module from this repository. It is served to a target as a single file.
- **Everything ships disabled.** `c2.egress_decider.enabled: false`, and a build with it disabled must behave exactly as the file does today.
- **The gate is in code, not in config.** Configuration selects from and orders the allowed set; it can never add to it.
- **One attempt per cycle, never a sweep.** `egress.py`'s rule and its reason: a dozen attempts from a device impersonating an IP phone is louder than the single short query that reported the problem.
- **The decider may not act on the first stuck cycle** — only from the second consecutive stuck cycle on, and only while no rescue tasking has arrived in this stuck window.
- **Allowed verbs, exactly three:** `egress proxy`, `egress rediscover`, `egress gsocket`. Anything else is refused when the policy is read.
- **Refused always, regardless of policy:** any `sleep`, disabling or deprioritising a leg, anything touching persistence, the watchdog or the tunnel.
- **`c2.proxy.mode: "none"` is a standing prohibition** on both proxy verbs, for the decider and for tasking alike.
- **`dot1x_seen` and `portal_answered` are refused in a policy** — declared in `dns_rescue.py` but never set by the beacon.
- **Drop-box only.** No generator field, no panel work; a generated build has no decider.

## Review Focus

1. **A policy whose first rule chooses `gsocket`, against one that does not.** The latch no longer fires on the first stuck cycle when the decider is enabled, so the carrier's timing is now a property of the policy. Both orderings need a test. Task 4.
2. **A stuck window that ends mid-decision.** An upstream leg delivering must close the window, reset the budget and the stuck counter, and leave no partial state that makes the next window start spent. Task 4.
3. **`egress proxy` naming a URL discovery never found**, and `egress proxy` on a build with `proxy.mode: "none"`. Both are refusals with reasons, and the second must refuse from tasking too, not only from the decider. Task 1.
4. **A policy that is syntactically fine and names a verb the gate refuses.** Refused when the block is read, with the verb in the message — not at the moment it would have fired, on a host nobody can reach. Task 3.
5. **A selection that succeeds and then carries no traffic.** `egress proxy` reporting success while the leg still fails is two different results, and the log must not conflate them. Task 1.

---

### Task 1: The three verbs, and the proxy prohibition

**Files:**
- Modify: `software/c2/beacon.py` — a dispatch arm beside `:9194` (`proxyinfo`), and the helpers it calls
- Test: `software/tests/test_egress_verbs.py`

**Interfaces:**
- Consumes: `ProxyDiscovery` (`beacon.py:2470`), `discover_all() -> list[dict]` returning `{"url", "source"}` entries, `self._proxy`, `self._proxy_session`, `_gsocket_start()`.
- Produces: `Beacon._exec_egress(args: str) -> str`, dispatched on `cmd == "egress"`; `Beacon._egress_select_proxy(target: str) -> str`; `Beacon._proxy_prohibited() -> bool`.

- [ ] **Step 1: Write the failing tests**

```python
def test_rediscover_reports_what_it_found(self):
    # as proxyinfo does; the point is that the list is refreshed
def test_select_by_index_makes_that_proxy_active(self):
    # _proxy._active_proxy and _proxy_session both move
def test_select_by_url_is_matched_against_discovery(self):
def test_a_url_discovery_never_found_is_refused_with_the_url_in_the_reason(self):
def test_both_proxy_verbs_are_refused_when_proxy_mode_is_none(self):
    # from tasking, not only from the decider: this is the gate, not a policy
def test_gsocket_starts_the_carrier_now(self):
def test_gsocket_on_a_build_without_the_leg_reports_that_and_changes_nothing(self):
def test_an_unknown_egress_argument_is_refused(self):
def test_a_selection_that_carries_no_traffic_is_reported_as_the_leg_failing(self):
    # the verb succeeded, the leg did not; the two must read differently
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest software.tests.test_egress_verbs -v`
Expected: FAIL — no `egress` arm in the dispatch.

- [ ] **Step 3: Implement the arm and its helpers**

`_proxy_prohibited()` reads the same config `_init_proxy` reads (`beacon.py:9411-9413`) and is consulted by both proxy sub-verbs before anything else, so the prohibition binds tasking as well as the decider. Keep the house habit of putting the offending value in every refusal.

- [ ] **Step 4: Run the tests, then the full suite**

Run: `python3 -m unittest software.tests.test_egress_verbs -v`, then the full suite.
Expected: PASS. Note that `test_agent_prompts.py` **will fail** at this point: it asserts set equality between the beacon's dispatch keys and the executor's `BEACON_VERBS`. That failure is Task 2's subject and must not be papered over here.

- [ ] **Step 5: Commit**

```bash
git add software/c2/beacon.py software/tests/test_egress_verbs.py
git commit -m "feat(beacon): three verbs for establishing a connection"
```

---

### Task 2: What the campaign model may do with them, which is nothing

**Files:**
- Modify: `software/agent/executor/beacon.py:39` (`BEACON_VERBS`)
- Modify: `software/agent/safety.py:917` (`_BEACON_HARD_VERBS`)
- Modify: `docs/AGENT.md` — the gate tables `test_docs.py` holds equal to `RISK_TABLE`
- Test: `software/tests/test_agent_safety.py`

**Interfaces:**
- Consumes: Task 1's `egress` verb.
- Produces: no new interface; `safety.classify` refuses `egress` at `TIER_HARD`.

- [ ] **Step 1: Write the failing test**

```python
def test_egress_is_hard_refused_for_the_campaign_model(self):
    # reconfig is hard "because it can move the callback"; egress proxy
    # moves the implant's egress path, which is the same hazard
def test_the_executor_knows_the_verb_exists(self):
    # the set-equality test is the forcing function, not the goal
```

- [ ] **Step 2: Run them, and the two tests Task 1 broke**

Run: `python3 -m unittest software.tests.test_agent_safety software.tests.test_agent_prompts -v`
Expected: the new test FAILS, and `test_agent_prompts`'s set equality still fails from Task 1.

- [ ] **Step 3: Add `"egress"` to `_BEACON_HARD_VERBS` and to `BEACON_VERBS`, and the `RISK_TABLE` row and `docs/AGENT.md` table entry that `test_docs.py` requires**

The verb reaches the model because a test forces it to; the refusal is what makes that safe. Write the reason beside the row in the voice the neighbouring rows use.

- [ ] **Step 4: Run the full suite**

Expected: PASS, including `test_docs.py`'s gate-table equality.

- [ ] **Step 5: Commit**

```bash
git add software/agent/ docs/AGENT.md software/tests/test_agent_safety.py
git commit -m "feat(agent): the egress verb is hard-refused for the campaign model"
```

---

### Task 3: The policy, read and refused loudly

**Files:**
- Modify: `software/c2/beacon.py` — `beacon_config_from_fallback:1912` and a reader beside it
- Test: `software/tests/test_egress_policy.py`

**Interfaces:**
- Consumes: `dns_rescue.CLASSES` class names (as a copy — `beacon.py` cannot import it), the four `_RESCUE_FLAG_*` constants (`:1717-1720`).
- Produces: `read_egress_policy(block) -> dict` returning `{"enabled": bool, "budget": int, "rules": [{"when": {...}, "try": str}]}`; `EGRESS_VERBS = ("proxy", "rediscover", "gsocket")`.

- [ ] **Step 1: Write the failing tests**

```python
def test_an_absent_block_reads_as_disabled(self):
def test_an_unusable_block_reads_as_disabled_and_logs_once(self):
    # the four transports' own behaviour; two cycles, one log line
def test_a_rule_naming_a_verb_the_gate_refuses_is_refused_when_read(self):
    # "sleep" and "persist", each with the verb in the message
def test_dot1x_seen_and_portal_answered_are_refused_as_flag_names(self):
    # declared in dns_rescue.py, never set by the beacon: a rule that
    # could never match is a trap in a file nobody can debug remotely
def test_proxy_found_and_dns_answered_are_accepted(self):
def test_an_unknown_class_name_is_refused_with_the_name_in_the_message(self):
def test_a_budget_below_one_is_refused(self):
def test_the_policy_shipped_in_raccoon_yaml_reads(self):
    # against the real file, once Task 5 has written it
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest software.tests.test_egress_policy -v`
Expected: FAIL — `read_egress_policy` does not exist.

- [ ] **Step 3: Implement `read_egress_policy` and wire `beacon_config_from_fallback` to carry its result at `c2.egress_decider`**

It refuses by returning the disabled shape and logging once, never by raising: this runs on an implant, and a refusal that stopped the beacon would cost the access to protect the policy. The class and flag names are a copy of `dns_rescue`'s, so add the comparison test the other copies have.

- [ ] **Step 4: Run the tests, then the full suite**

Expected: PASS, except `test_the_policy_shipped_in_raccoon_yaml_reads`, which Task 5 completes. Mark it `skipTest` with that reason, and Task 5 removes the skip.

- [ ] **Step 5: Commit**

```bash
git add software/c2/beacon.py software/tests/test_egress_policy.py
git commit -m "feat(beacon): read the egress policy, and refuse one that cannot work"
```

---

### Task 4: The decider, its timing, its budget and the latch

**Files:**
- Modify: `software/c2/beacon.py` — the stuck branch at `:9360-9380`, and `Beacon.__init__`
- Test: `software/tests/test_egress_decider.py`

**Interfaces:**
- Consumes: Task 1's verbs, Task 3's `read_egress_policy`, `_leg_status`, `_rescue_flags`, `_maybe_rescue()`, `_gsocket_start()`.
- Produces: `Beacon._egress_decide() -> Optional[str]` (the verb chosen, or `None`); `Beacon._egress_act() -> bool` (acted this cycle); `self._stuck_cycles: int`; `self._egress_spent: int`.

- [ ] **Step 1: Write the failing tests**

```python
def test_it_does_not_act_on_the_first_stuck_cycle(self):
    # the operator's decision: the server decides while it can be reached
def test_it_acts_from_the_second_stuck_cycle(self):
def test_it_does_not_act_while_rescue_tasking_arrived_in_this_window(self):
    # _maybe_rescue returned something: the server is reachable and deciding
def test_it_acts_when_the_rescue_could_not_even_be_sent(self):
    # dns disabled or never answered: nothing can leave, which is the case
    # this exists for, and beacon.py's own comment says so. Still the
    # *second* stuck cycle: a cycle must have passed without an answer,
    # and a cycle on which the rescue could not be sent is such a cycle.
def test_one_attempt_per_cycle_and_never_a_sweep(self):
def test_the_budget_is_spent_and_then_it_is_silent(self):
def test_an_upstream_leg_delivering_closes_the_window(self):
    # stuck counter and budget both reset; the next window starts unspent
def test_the_first_matching_rule_wins(self):
def test_no_matching_rule_means_no_attempt(self):
def test_with_the_decider_disabled_the_latch_is_exactly_todays_behaviour(self):
    # the default case; test_gsocket_leg.py's assertions must also pass
def test_with_the_decider_enabled_the_carrier_waits_for_the_decision(self):
    # no carrier on cycle one, which is the cost the docs state
def test_a_policy_whose_first_rule_is_gsocket_restores_the_old_timing(self):
def test_the_latch_is_the_fallback_when_the_decider_did_not_act(self):
    # declined, no match, or budget spent: the carrier still comes up
def test_every_attempt_is_logged_with_its_rule_and_its_outcome(self):
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest software.tests.test_egress_decider -v`
Expected: FAIL — `_egress_decide` does not exist.

- [ ] **Step 3: Implement the counter, the window and the evaluator**

`_stuck_cycles` increments in the stuck branch and resets wherever `_leg_recovered()` is called. `_egress_decide` reads only `_leg_status` and `_rescue_flags` and returns a verb or `None` — a single argument in, a choice out, which is the seam the spec names for a later decision engine.

- [ ] **Step 4: Rewire the latch, preserving the disabled case**

In the stuck branch, `_gsocket_start()` is called when the decider is **disabled** (today's position and behaviour, unchanged), or when it is enabled and did not act this cycle *and* may already act (`_stuck_cycles >= 2`). With the decider enabled, the first stuck cycle starts no carrier — that is the stated cost, and a policy whose first rule is `gsocket` undoes it.

- [ ] **Step 5: Run the tests, the gsocket suite, then the full suite**

Run: `python3 -m unittest software.tests.test_egress_decider software.tests.test_gsocket_leg -v`, then the full suite.
Expected: PASS, with `test_gsocket_leg.py` unchanged — if one of its latch assertions needed editing, the disabled case is not preserved and the rewiring is wrong.

- [ ] **Step 6: Commit**

```bash
git add software/c2/beacon.py software/tests/test_egress_decider.py
git commit -m "feat(beacon): decide one egress attempt when the server cannot be reached"
```

---

### Task 5: The shipped block, the guide and the limits

**Files:**
- Modify: `configs/raccoon.yaml` — `c2.egress_decider` after `c2.fallback`
- Create: `docs/EGRESS_DECIDER.md`
- Modify: `docs/AGENT.md` — *Known limits*; `README.md` — the feature table
- Modify: `software/tests/test_docs.py`, `software/tests/test_egress_policy.py` (remove Task 3's skip)

**Interfaces:**
- Consumes: everything above.
- Produces: no code interface.

- [ ] **Step 1: Write the failing documentation tests**

```python
def test_the_guide_states_what_the_decider_may_never_do(self):
    # the four refusals, before it states a single rule
def test_the_guide_states_the_one_cycle_cost(self):
    # with the decider enabled the carrier may come up a cycle later
def test_the_shipped_block_is_disabled_and_reads(self):
def test_known_limits_records_the_three_gsocket_decider_limits(self):
    # drop-box only; sleep is refused where the server-side model has it;
    # the two dead flags
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest software.tests.test_docs -v -k egress`

- [ ] **Step 3: Write the block, with its comments**

Say which side it is, as the four neighbouring blocks do, and point at the guide before the first key — every row in it is an action taken with nobody watching.

- [ ] **Step 4: Write `docs/EGRESS_DECIDER.md`**

In the house voice: why the decision moved to the implant at all (the server-side chooser sits on the far side of the connection it is establishing), what the decider may never do and why that is in code rather than config, the one-cycle cost and how a policy undoes it, how to read the log with `cat` once there is a connection, and the three limits. State plainly that `sleep` — the only verb the server-side model has for a stuck beacon — is the one the implant's decider may never use.

- [ ] **Step 5: Remove Task 3's skip and run the full suite**

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add configs/raccoon.yaml docs/ README.md software/tests/
git commit -m "docs(egress): the shipped policy, the guide and what it may never do"
```

---

## Manual verification

Everything above is testable offline. One thing is not, and it is the feature's whole point: a drop-box that has actually lost its egress. On a real implant, with the decider enabled and a policy whose first rule is `rediscover`:

1. Break the HTTPS leg (block the callback at the switch), leave DNS working, and confirm the server's `stuck` record arrives and `try_egress` still decides — the decider must stay silent while the server is reachable.
2. Break DNS as well. Confirm the decider acts on the second stuck cycle, spends its budget, logs each attempt, and then goes quiet.
3. Restore egress and confirm the window closes: the next outage starts with a full budget.
