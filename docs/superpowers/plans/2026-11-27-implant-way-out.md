# A way out the implant finds for itself — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Widen the implant's egress evidence with what the tap can see, order
the moves by cost behind an expected-value inequality that moves with time dark
and with the evidence, and put the evaluator on the device in a separate
process — so a dropped implant has a way out it can find on its own.

**Architecture:** A new process, the **scout** (`software/scout/`), runs from the
implant's venv, captures a narrow BPF slice of the bridge, and publishes one
JSON document. `beacon.py` stays a single stdlib-only Python 3.9 file: it writes
one state file when a stuck window opens, reads the scout's document when it is
fresh, carries a **copy** of the risk rows and the inequality, and gates every
rung through that arithmetic. The model half lives in the scout and ships off.

**Tech Stack:** Python 3.9 (implant), stdlib only in `beacon.py`; scapy + PyYAML
in the scout (its own requirements file); Ollama over loopback for stage 4;
Docker (arm64, `--cpus`/`--memory`) as the measurement bench.

**Spec:** `docs/superpowers/specs/2026-11-27-implant-way-out-design.md`

## Global Constraints

- `beacon.py` is **one stdlib-only Python 3.9 file served as source text**. No
  import of `software.*`, no third-party import. Anything shared with another
  module is a **copy** held by a comparison test (`beacon.py:1686-1692`).
- `software/requirements.txt` **does not grow**. The scout declares its own
  dependencies in `software/scout/requirements.txt`.
- **No inference listener except on loopback.** The scout dials
  `http://127.0.0.1:11434`; nothing in this plan binds a socket.
- **Drop-box builds only.** A generated single-file build has no
  `configs/raccoon.yaml`, so `c2.way_out` is absent and every behaviour added
  here is off. `test_status_quo.py` and `test_shipped_image.py` must stay green
  unchanged.
- **The rung order is arithmetic, not policy.** The loud rungs are reachable
  only by `points * p_success > risk_coefficient * p_detect`. A policy orders
  and chooses from `EGRESS_VERBS`; it cannot add to it and cannot invert the
  ladder.
- **Rung 4 is one-shot** and counts as **spent** when `nac_bypass.enabled` is
  true in the file.
- **Stage 4 (the model) ships default-off.**
- `c2.way_out` ships `enabled: false`, and is validated whether enabled or not,
  the way `c2.egress_decider` is.
- Prose-pinning tests: a reworded sentence in `docs/TUNNEL.md`, `README.md` or
  `docs/C2_DEMO.md` moves its pin in `software/tests/test_docs.py`.
- The suite's verdict is `python3 -m unittest discover -s software/tests -t . -v`
  **exit status**, never a summary line.

## Review Focus

1. **A truncated or non-JSON document** at the scout's path — the beacon must
   read it as absent, not raise on the beacon thread.
2. **A document from the future** (clock skew, `published` ahead of now) — must
   not be treated as eternally fresh.
3. **A document whose `evidence` does not match this cycle's** — the
   recommendation must be ignored and the policy used.
4. **A model answer that is a verb above the rung the arithmetic allows** —
   refused and logged, never acted on.
5. **A state directory that cannot be written** (read-only `/opt`, full disk) —
   the beacon keeps beaconing; the handoff degrades to "no scout".

---

### Task 1: The tap's evidence, as pure functions

**Files:**
- Create: `software/scout/__init__.py`
- Create: `software/scout/evidence.py`
- Create: `software/scout/requirements.txt`
- Test: `software/tests/test_scout_evidence.py`

**Interfaces:**
- Produces:
  - `BPF_FILTER: str` — the one filter the scout sniffs with.
  - `class Evidence` with `dot1x_seen: bool`, `portal_answered: bool`,
    `resolvers: Dict[str, int]` (resolver IP → answered query count),
    `tls_destinations: List[str]` (SNI, handshake completed),
    `proxies: List[str]` (`host:port` seen in CONNECT / PAC / WPAD),
    `credentials: List[dict]` (`{"kind", "user", "secret", "where"}`),
    `portal: Optional[dict]` (`{"url", "body", "content_type"}`),
    `host_mac: Optional[str]`, `host_ip: Optional[str]`.
  - `Evidence.observe(packet) -> None` — one scapy packet in.
  - `Evidence.flags() -> List[str]` — the live flag names this evidence sets,
    a subset of `("dot1x_seen", "portal_answered")`.
  - `Evidence.as_document_fields() -> dict` — the JSON-safe mapping Task 3
    publishes.

- [ ] **Step 1: Write the failing tests** in `software/tests/test_scout_evidence.py`,
      building packets with `scapy.all` the way `software/tests/test_sniffer.py` does:

```python
class TestTheTapSetsTheTwoDeadFlags(unittest.TestCase):
    def test_an_eapol_frame_sets_dot1x_seen(self):
        # Ether type 0x888e is the frame nac_bypass.py forwards; seeing one
        # is the whole evidence for dot1x_seen.
        e = evidence.Evidence()
        self.assertFalse(e.dot1x_seen)
        e.observe(Ether(dst="01:80:c2:00:00:03", type=0x888E) / Raw(b"\x01\x01\x00\x00"))
        self.assertTrue(e.dot1x_seen)
        self.assertEqual(e.flags(), ["dot1x_seen"])

    def test_a_redirect_alone_does_not_set_portal_answered(self):
        e = evidence.Evidence()
        e.observe(self.http_response(302, {"Location": "http://portal.lan/login"}))
        self.assertIsNone(e.portal)
        self.assertFalse(e.portal_answered)

    def test_a_redirect_then_an_answered_post_sets_portal_answered(self):
        e = evidence.Evidence()
        e.observe(self.http_response(302, {"Location": "http://portal.lan/login"}))
        e.observe(self.http_request("POST", "portal.lan", "/login",
                                    body=b"user=guest&accept=1"))
        e.observe(self.http_response(200, {}, src_host="portal.lan"))
        self.assertTrue(e.portal_answered)
        self.assertEqual(e.portal["url"], "http://portal.lan/login")
        self.assertEqual(e.portal["body"], "user=guest&accept=1")
```

      plus, in the same module: a `CONNECT` request adding `proxies`; a
      `Proxy-Authorization: Basic` header adding one `credentials` entry whose
      `secret` is the decoded password; an answered DNS response counting its
      resolver and an unanswered query counting none; a TLS `ClientHello`
      recording its SNI only once the server's `ServerHello` followed; a
      non-IP, truncated and malformed packet each leaving every field
      unchanged and raising nothing.

- [ ] **Step 2: Run them and watch them fail**

Run: `python3 -m unittest software.tests.test_scout_evidence -v`
Expected: FAIL — `No module named 'software.scout'`

- [ ] **Step 3: Implement `software/scout/evidence.py`**

`BPF_FILTER` is one expression covering exactly the table in the design:
`"ether proto 0x888e or udp port 53 or tcp port 80 or tcp port 8080 or tcp port 3128 or tcp port 443"`.
Parse HTTP and TLS from the TCP payload bytes rather than through scapy's
layers — `observe` must not raise on any input, so every parse is guarded and a
failure to parse is a packet ignored.

- [ ] **Step 4: Run them and watch them pass**

Run: `python3 -m unittest software.tests.test_scout_evidence -v`
Expected: OK

- [ ] **Step 5: Write `software/scout/requirements.txt`** — scapy (the C2's
      floor, copied, kept in step by `test_requirements_floors.py`) and PyYAML,
      with the header the agent's and tools' files carry: separate because
      `software/requirements.txt` must not grow.

- [ ] **Step 6: Extend `software/tests/test_requirements_floors.py`** so the
      scout's scapy and PyYAML floors are held equal to `software/requirements.txt`'s.

- [ ] **Step 7: Commit**

```bash
git add software/scout software/tests/test_scout_evidence.py software/tests/test_requirements_floors.py
git commit -m "feat(scout): the evidence the tap can see, as pure functions"
```

---

### Task 2: The bench — what a container measures, and what it cannot

**Files:**
- Create: `tools/way_out_bench.py`
- Create: `tools/way_out_bench.Dockerfile`
- Test: `software/tests/test_way_out_bench.py`

**Interfaces:**
- Consumes: `software.scout.evidence.Evidence`, `BPF_FILTER` (Task 1).
- Produces: `main(argv) -> int`; a `--json` report with keys `parse`,
  `handoff`, `arithmetic`, `model`, `not_measurable`.

- [ ] **Step 1: Write the failing test**

```python
class TestTheBenchReportsHonestly(unittest.TestCase):
    def test_latency_is_reported_as_an_optimistic_bound(self):
        report = bench.measure_parse(packets=200)
        self.assertIn("optimistic", report["caveat"])

    def test_watts_and_thermals_are_named_as_not_measurable(self):
        self.assertEqual(sorted(bench.NOT_MEASURABLE), ["thermals", "watts"])
        for name in bench.NOT_MEASURABLE:
            self.assertIn("no device", bench.NOT_MEASURABLE[name])
```

- [ ] **Step 2: Run it and watch it fail**

Run: `python3 -m unittest software.tests.test_way_out_bench -v`
Expected: FAIL — no module `tools.way_out_bench`

- [ ] **Step 3: Implement `tools/way_out_bench.py`** with
      `measure_parse(packets)`, `measure_handoff(rounds)`,
      `measure_arithmetic(rounds)`, `measure_model(endpoint, name, prompt)` and
      `NOT_MEASURABLE = {"watts": ..., "thermals": ...}`, each sentence naming
      that there is no device. `measure_parse` uses `time.process_time` per
      packet and reports µs/packet with the optimistic-bound caveat.

- [ ] **Step 4: Run it and watch it pass**

- [ ] **Step 5: Write `tools/way_out_bench.Dockerfile`** — `python:3.9-slim`
      (arm64), the scout's requirements, the repository mounted, entrypoint
      `python3 tools/way_out_bench.py`.

- [ ] **Step 6: Take the measurement** in an arm64 container with
      `--cpus 4 --memory 4g`, and record every number — including a bad one —
      in a new `## Measurements` section of the design document, latency marked
      as an optimistic bound and watts/thermals named as not measurable.

Run:
```bash
docker build -f tools/way_out_bench.Dockerfile -t raccoon-way-out-bench .
docker run --rm --platform linux/arm64 --cpus 4 --memory 4g \
  -v "$PWD:/repo" -w /repo raccoon-way-out-bench --json
```
Expected: a JSON report; `parse`, `handoff` and `arithmetic` populated.

- [ ] **Step 7: Commit**

```bash
git add tools/way_out_bench.py tools/way_out_bench.Dockerfile software/tests/test_way_out_bench.py docs/superpowers/specs/2026-11-27-implant-way-out-design.md
git commit -m "measure(way-out): the container's half of stage one"
```

---

### Task 3: The handoff — one file each way, fresh or ignored

**Files:**
- Create: `software/scout/handoff.py`
- Modify: `software/c2/beacon.py` (the way-out policy reader beside
  `read_egress_policy`; `_egress_state`; `_egress_decide`; `_leg_recovered`;
  `beacon_config_from_fallback`)
- Modify: `configs/raccoon.yaml` (the `c2.way_out` block, disabled)
- Test: `software/tests/test_way_out_handoff.py`

**Interfaces:**
- Produces, in `software/scout/handoff.py` (the scout's side):
  - `STATE_NAME = "way_out_state.json"`, `DOCUMENT_NAME = "way_out_scout.json"`,
    `TRAIL_NAME = "way_out_trail.jsonl"`,
    `CREDENTIALS_NAME = "way_out_credentials.json"`,
    `IDENTITY_REQUEST_NAME = "way_out_identity.json"`
  - `DOCUMENT_VERSION = 1`, `STATE_VERSION = 1`
  - `read_state(state_dir) -> Optional[dict]`
  - `write_document(state_dir, document) -> None` (atomic, 0600)
  - `append_trail(state_dir, line) -> None`
- Produces, in `beacon.py` (the beacon's copy, no import):
  - `read_way_out_policy(block) -> dict` with keys `enabled`, `state_dir`,
    `document_max_age_seconds`, `points_per_hour`, `points_max`,
    `risk_coefficient`, `ev_threshold`, `dot1x_detect`, `portal_detect`,
    `model`
  - `_WAY_OUT_STATE_NAME`, `_WAY_OUT_DOCUMENT_NAME`, `_WAY_OUT_TRAIL_NAME`,
    `_WAY_OUT_DOCUMENT_VERSION`, `_WAY_OUT_STATE_VERSION` — the copies
  - `Beacon._way_out_publish_state() -> None`,
    `Beacon._way_out_document() -> Optional[dict]`,
    `Beacon._way_out_clear_state() -> None`

- [ ] **Step 1: Write the failing tests** in `software/tests/test_way_out_handoff.py`:

```python
class TestTheBeaconsStateFile(WayOutCase):
    def test_a_stuck_window_writes_one_line_of_json_the_scout_can_read(self):
        beacon = self.beacon(way_out={"enabled": True, "state_dir": self.root})
        beacon._stuck_cycles = 2
        beacon._record_leg("https", 4)
        beacon._way_out_publish_state()
        state = handoff.read_state(self.root)
        self.assertEqual(state["version"], handoff.STATE_VERSION)
        self.assertEqual(state["stuck_cycles"], 2)
        self.assertEqual(state["evidence"]["legs"]["https"], "timed_out")
        self.assertNotIn("c2.example.com", json.dumps(state))

    def test_a_leg_delivering_removes_it(self):
        ...
        beacon._leg_recovered()
        self.assertIsNone(handoff.read_state(self.root))

    def test_a_state_directory_that_cannot_be_written_costs_nothing(self):
        # Review Focus 5: a read-only /opt must not cost the beacon its loop.
        beacon = self.beacon(way_out={"enabled": True,
                                      "state_dir": "/proc/not-a-directory"})
        beacon._stuck_cycles = 2
        beacon._way_out_publish_state()      # raises nothing
        self.assertIsNone(beacon._way_out_document())


class TestTheDocumentTheBeaconReads(WayOutCase):
    def test_a_fresh_recommendation_for_this_evidence_is_taken(self): ...
    def test_a_document_older_than_the_window_is_ignored(self): ...
    def test_a_document_published_in_the_future_is_ignored(self): ...   # RF 2
    def test_a_truncated_document_reads_as_absent(self): ...            # RF 1
    def test_a_recommendation_for_other_evidence_is_ignored(self): ...  # RF 3
    def test_without_a_document_the_policy_decides_exactly_as_today(self): ...


class TestTheTwoDeadFlagsAreAliveNow(WayOutCase):
    def test_the_document_sets_dot1x_seen_in_the_beacons_evidence(self):
        self.publish(flags=["dot1x_seen"])
        self.assertIn("dot1x_seen", self.beacon_with_document()._egress_state()["flags"])

    def test_a_policy_naming_them_is_no_longer_refused(self):
        policy = beacon_mod.read_egress_policy(
            {"enabled": True, "budget": 1,
             "rules": [{"when": {"flags": ["dot1x_seen"]}, "try": "gsocket"}]})
        self.assertTrue(policy["enabled"])

    def test_the_flag_bits_still_match_dns_rescue(self):
        self.assertEqual(beacon_mod._EGRESS_FLAG_BITS,
                         {"proxy_found": dns_rescue.FLAG_PROXY_FOUND,
                          "dns_answered": dns_rescue.FLAG_DNS_ANSWERED,
                          "dot1x_seen": dns_rescue.FLAG_DOT1X_SEEN,
                          "portal_answered": dns_rescue.FLAG_PORTAL_ANSWERED})
        self.assertEqual(beacon_mod._EGRESS_DEAD_FLAGS, {})


class TestTheFileNamesAreOneVocabulary(WayOutCase):
    def test_the_beacons_copies_match_the_scouts(self):
        self.assertEqual(beacon_mod._WAY_OUT_STATE_NAME, handoff.STATE_NAME)
        self.assertEqual(beacon_mod._WAY_OUT_DOCUMENT_NAME, handoff.DOCUMENT_NAME)
        self.assertEqual(beacon_mod._WAY_OUT_TRAIL_NAME, handoff.TRAIL_NAME)
        self.assertEqual(beacon_mod._WAY_OUT_DOCUMENT_VERSION, handoff.DOCUMENT_VERSION)
```

      plus, for `read_way_out_policy`, the refusal cases
      `read_egress_policy` already models: a non-mapping block, an unknown key,
      a non-boolean `enabled`, a non-numeric `points_per_hour`, a
      `document_max_age_seconds` below 1 — each refused with the offending
      value in one warning, the reader answering "off" and never raising.

- [ ] **Step 2: Run them and watch them fail**

Run: `python3 -m unittest software.tests.test_way_out_handoff -v`
Expected: FAIL — `read_way_out_policy` does not exist

- [ ] **Step 3: Implement the scout's side** in `software/scout/handoff.py`:
      atomic 0600 writes (scratch file in the same directory, `os.replace`),
      `read_state` answering None for absent/unreadable/unparseable/wrong
      version.

- [ ] **Step 4: Implement the beacon's side** in `beacon.py`: the reader beside
      `read_egress_policy`, the three methods, the copies with the comment the
      rescue record's copy carries, `_EGRESS_FLAG_BITS` grown to four and
      `_EGRESS_DEAD_FLAGS` emptied, `_egress_state` reading the document's flags
      in addition to `_rescue_flags`, `_egress_decide` preferring a fresh
      matching recommendation, `_leg_recovered` clearing the state file, and
      `beacon_config_from_fallback` always carrying `c2.way_out`.

- [ ] **Step 5: Run them and watch them pass**, then the two neighbouring
      modules that own this code

Run: `python3 -m unittest software.tests.test_way_out_handoff software.tests.test_egress_policy software.tests.test_egress_decider software.tests.test_dns_rescue -v`
Expected: OK

- [ ] **Step 6: Add the `c2.way_out` block to `configs/raccoon.yaml`**,
      `enabled: false`, every key written out with its reason, `model.enabled:
      false`.

- [ ] **Step 7: Commit**

```bash
git add software/scout/handoff.py software/c2/beacon.py configs/raccoon.yaml software/tests/test_way_out_handoff.py
git commit -m "feat(way-out): the handoff, and the two dead flags are alive"
```

---

### Task 4: The scout process

**Files:**
- Create: `software/scout/__main__.py`
- Create: `software/scout/scout.py`
- Create: `services/raccoon-scout.service`
- Modify: `services/install.sh`
- Test: `software/tests/test_scout.py`

**Interfaces:**
- Consumes: Task 1's `Evidence`/`BPF_FILTER`, Task 3's `handoff`.
- Produces: `class Scout(config: dict, state_dir: str)` with
  `publish_once(now: float) -> Optional[dict]` (collect → document, or None
  while the beacon is not stuck), `observe(packet)`, `stop()`;
  `Scout.credentials_path`; `main(argv) -> int`.

- [ ] **Step 1: Write the failing tests** in `software/tests/test_scout.py`:
      it publishes nothing while no state file says the beacon is stuck; it
      publishes a document carrying the evidence and the allowed-rung ceiling
      once one does; the document names `identity_pre_spent: true` when the
      config has `nac_bypass.enabled: true` and false when it does not; the
      credentials it harvested are written to their own 0600 file and **not**
      into the document; `publish_once` raises nothing when the state directory
      is unwritable; the trail gains one line per attempt the state file
      reports and keeps them after the state file is gone.

- [ ] **Step 2: Run them and watch them fail**

- [ ] **Step 3: Implement `software/scout/scout.py`** — a `scapy.sniff` with
      `BPF_FILTER` and `store=False` on the bridge named by
      `network.bridge_name`, started only while `read_state` reports a stuck
      window, and a publish loop on `document_max_age_seconds / 2`.

- [ ] **Step 4: Run them and watch them pass**

- [ ] **Step 5: Write `services/raccoon-scout.service`** following the three
      existing units (root, `/opt/raccoon`, `PYTHONPATH`, `Restart=always`,
      `PrivateTmp=true`), and install it from `services/install.sh` beside the
      others.

- [ ] **Step 6: Commit**

```bash
git add software/scout services/raccoon-scout.service services/install.sh software/tests/test_scout.py
git commit -m "feat(scout): the process that collects and publishes"
```

---

### Task 5: The arithmetic — the ladder that is a number

**Files:**
- Modify: `software/agent/safety.py` (three tier-2 rows)
- Modify: `software/c2/beacon.py` (the stdlib copy, the rung map, the gate in
  `_egress_act`)
- Test: `software/tests/test_way_out_gate.py`
- Modify: `software/tests/test_docs.py` (the gate lists in `docs/AGENT.md`)

**Interfaces:**
- Produces, in `safety.py`: `RISK_TABLE["way_out_borrow"]` (points=20,
  p_success=0.5, p_detect=0.35), `["way_out_radio"]` (20, 0.4, 0.5),
  `["way_out_identity"]` (20, 0.5, 0.8), all `TIER_KNOCK`, class `lifecycle`.
- Produces, in `beacon.py`: `_WAY_OUT_ROWS: Dict[str, Tuple[int, float, float]]`
  — the copy; `_WAY_OUT_RUNG_OF: Dict[str, int]` mapping each verb to its rung;
  `Beacon._way_out_points(hours_dark) -> int`;
  `Beacon._way_out_numbers(verb) -> dict` with keys `rung`, `points`,
  `p_success`, `p_detect`, `p_detect_prior`, `ev`, `threshold`,
  `risk_coefficient`, `allowed`, `override_decisive`;
  `Beacon._way_out_allows(verb) -> Tuple[bool, dict]`.

- [ ] **Step 1: Write the failing tests** in `software/tests/test_way_out_gate.py`:

```python
class TestTheCopyIsHeldAgainstTheRiskTable(unittest.TestCase):
    def test_every_row_matches_safetys(self):
        for key, (points, p_success, p_detect) in beacon_mod._WAY_OUT_ROWS.items():
            row = safety.RISK_TABLE[key]
            self.assertEqual((row.points, row.p_success, row.p_detect),
                             (points, p_success, p_detect), key)
            self.assertEqual(row.tier, safety.TIER_KNOCK, key)

    def test_beacon_py_does_not_import_the_agent(self):
        source = (REPO / "software" / "c2" / "beacon.py").read_text()
        self.assertNotIn("software.agent", source)
        self.assertNotIn("import safety", source)


class TestTheLadderIsArithmetic(GateCase):
    def test_the_quiet_rung_is_allowed_almost_immediately(self):
        self.assertTrue(self.allows("proxy", hours_dark=1))

    def test_the_radio_rung_waits_for_the_curve(self):
        self.assertFalse(self.allows("radio", hours_dark=4))
        self.assertTrue(self.allows("radio", hours_dark=5))

    def test_the_identity_rung_is_last(self):
        self.assertFalse(self.allows("identity", hours_dark=6))
        self.assertTrue(self.allows("identity", hours_dark=7))

    def test_dot1x_seen_pushes_the_identity_rung_later(self):
        self.assertFalse(self.allows("identity", hours_dark=7,
                                     flags=["dot1x_seen"]))
        self.assertTrue(self.allows("identity", hours_dark=9,
                                    flags=["dot1x_seen"]))

    def test_portal_answered_brings_the_borrow_rung_earlier(self):
        self.assertFalse(self.allows("portal", hours_dark=0))
        self.assertTrue(self.allows("portal", hours_dark=0,
                                    flags=["portal_answered"]))

    def test_the_curve_is_capped(self):
        self.assertEqual(self.beacon()._way_out_points(1000), 100)

    def test_a_model_estimate_is_clamped_to_the_prior_and_marked(self):
        allowed, numbers = self.numbers("identity", hours_dark=7,
                                        p_success=0.99)
        self.assertAlmostEqual(numbers["p_success"], 0.7)      # 0.5 + 0.2
        self.assertTrue(numbers["override_decisive"])


class TestBothPathsGoThroughIt(GateCase):
    def test_a_policy_rule_naming_a_loud_verb_is_refused_until_the_curve(self): ...
    def test_a_model_recommendation_is_refused_the_same_way(self): ...
    def test_a_refused_rung_costs_no_budget_and_is_logged_with_its_numbers(self): ...
```

- [ ] **Step 2: Run them and watch them fail**

- [ ] **Step 3: Add the three rows to `software/agent/safety.py`**, each with
      the reason sentence that is true of that rung alone, following
      `egress_control`'s own note about one tier over several hazards.

- [ ] **Step 4: Implement the copy and the gate in `beacon.py`** — the rows, the
      rung map, `_way_out_points` (`min(points_max, points + points_per_hour *
      int(hours_dark))`), `_way_out_numbers` (clamping an advisory `p_success`
      to ±0.2 the way `safety.clamp_llm_adjustment` does, and setting
      `override_decisive` when only the override crossed the threshold), and
      `_egress_act` consulting `_way_out_allows` **before** spending budget.

- [ ] **Step 5: Run them and watch them pass**

Run: `python3 -m unittest software.tests.test_way_out_gate software.tests.test_agent_safety software.tests.test_agent_gate software.tests.test_docs -v`
Expected: OK

- [ ] **Step 6: Commit**

```bash
git add software/agent/safety.py software/c2/beacon.py software/tests/test_way_out_gate.py software/tests/test_docs.py docs/AGENT.md
git commit -m "feat(way-out): the ladder is arithmetic, and both paths go through it"
```

---

### Task 6: Rung 2 — the borrow verbs

**Files:**
- Modify: `software/c2/beacon.py` (`EGRESS_VERBS`, `_exec_egress`, three new
  methods, `_egress_task`)
- Test: `software/tests/test_way_out_rungs.py`
- Modify: `software/tests/test_egress_policy.py` (the verb-set assertion)

**Interfaces:**
- Produces: `EGRESS_VERBS = ("proxy", "rediscover", "gsocket", "credential",
  "portal", "resolve")`;
  `Beacon._egress_credential(target) -> str`,
  `Beacon._egress_portal() -> str`,
  `Beacon._egress_resolve(target) -> str`.

- [ ] **Step 1: Write the failing tests**: `credential` with no credential file
      declines with a reason and spends nothing; with one, it makes the
      credential the active proxy's userinfo and says which user and which
      proxy, and never prints the secret; `portal` with no recorded answer
      declines; with one, it replays that one request once and reports the
      status it got, and says it is not a test of the leg; `resolve` with no
      answered resolver declines; with one, it resolves the callback host
      through it, pins the answer for this stuck window and reports both; the
      pin is dropped by `_leg_recovered`; each of the three refuses on a build
      whose `c2.proxy.mode` is `none` where that is the relevant prohibition;
      and `_exec_egress("nonesuch")` names all six forms.

- [ ] **Step 2: Run them and watch them fail**

- [ ] **Step 3: Implement the three verbs**, each one thing, none testing its
      own result, each answering what it changed — the shape `_egress_rediscover`
      and `_egress_select_proxy` already have.

- [ ] **Step 4: Run them and watch them pass**

- [ ] **Step 5: Commit**

```bash
git add software/c2/beacon.py software/tests/test_way_out_rungs.py software/tests/test_egress_policy.py
git commit -m "feat(way-out): rung two borrows what the host proves works"
```

---

### Task 7: Rung 3 — its own radio

**Files:**
- Modify: `software/c2/beacon.py` (`EGRESS_VERBS`, `_exec_egress`,
  `_egress_radio`)
- Test: `software/tests/test_way_out_radio.py`

**Interfaces:**
- Produces: `"radio"` in `EGRESS_VERBS`; `Beacon._egress_radio(target) -> str`;
  `Beacon._radio_candidates() -> List[dict]` (`{"ssid", "open"}`, from the
  scout's document, onboard radio only).

- [ ] **Step 1: Write the failing tests**: with no onboard wireless interface it
      declines and names that; a USB adapter is refused on the power budget with
      that reason; it associates time-boxed and installs a **scoped** route only
      — the test asserts the argv of every command and that no
      `ip route ... default` without a table or a source is among them; a
      failure to associate rolls back every command it ran, in reverse, before
      answering; it never takes the global default route; the answer says what
      was changed and does not claim the implant can now get out.

- [ ] **Step 2: Run them and watch them fail**

- [ ] **Step 3: Implement `_egress_radio`**, shelling out through the same
      `subprocess` shape `nac_bypass.py` uses, with a rollback list built as it
      goes.

- [ ] **Step 4: Run them and watch them pass**

- [ ] **Step 5: Commit**

```bash
git add software/c2/beacon.py software/tests/test_way_out_radio.py
git commit -m "feat(way-out): rung three leaves the tapped port, on a scoped route"
```

---

### Task 8: Rung 4 — the trigger into the bypass that already exists

**Files:**
- Create: `software/scout/trigger.py`
- Modify: `software/c2/beacon.py` (`EGRESS_VERBS`, `_egress_identity`, the
  one-shot latch)
- Modify: `software/main.py` (the poll)
- Test: `software/tests/test_way_out_identity.py`

**Interfaces:**
- Produces: `"identity"` in `EGRESS_VERBS`; `Beacon._egress_identity() -> str`;
  `software.scout.trigger.IdentityTrigger(state_dir)` with
  `pending() -> Optional[dict]` and `taken(detail: str) -> None`.

- [ ] **Step 1: Write the failing tests**: the verb writes one request file and
      says so, and says it is not a test of the leg; a second attempt in the
      same deployment is refused as spent even when the arithmetic allows it;
      `_leg_recovered` does **not** re-arm it; a document saying
      `identity_pre_spent: true` makes the first attempt refuse as already
      taken; **without a fresh document the rung is not offered at all**;
      `IdentityTrigger.pending()` answers once and then not again; `main.py`
      starts `NACBypass` when a request is pending and the component was not
      configured, and leaves a `taken` record the scout reads.

- [ ] **Step 2: Run them and watch them fail**

- [ ] **Step 3: Implement the three pieces.** `main.py` polls only when
      `c2.way_out.enabled` is true, inside its existing one-second loop.

- [ ] **Step 4: Run them and watch them pass**

Run: `python3 -m unittest software.tests.test_way_out_identity software.tests.test_nac_bypass -v`
Expected: OK

- [ ] **Step 5: Commit**

```bash
git add software/scout/trigger.py software/c2/beacon.py software/main.py software/tests/test_way_out_identity.py
git commit -m "feat(way-out): rung four triggers the bypass this repository already has"
```

---

### Task 9: The trail

**Files:**
- Modify: `software/c2/beacon.py` (`_egress_act` records the attempt into the
  state file)
- Modify: `software/scout/scout.py` (copies new attempts into the trail)
- Test: `software/tests/test_way_out_trail.py`

- [ ] **Step 1: Write the failing tests**: one trail line per attempt carrying
      the evidence, the rung, the verb **and its argument**, the gate's numbers,
      and whether the model or the policy chose; a line marked when the
      decision passed only on an override; the trail survives the state file's
      removal; the trail holds no secret — the credential verb's line names the
      user and not the password; the beacon still keeps exactly **one** file of
      its own.

- [ ] **Step 2–4: fail, implement, pass**

- [ ] **Step 5: Commit**

```bash
git add software/c2/beacon.py software/scout/scout.py software/tests/test_way_out_trail.py
git commit -m "feat(way-out): the trail, so a burned implant is a lesson"
```

---

### Task 10: Stage 4 — the model, default-off

**Files:**
- Create: `software/scout/model.py`
- Modify: `software/scout/scout.py`
- Test: `software/tests/test_scout_model.py`

**Interfaces:**
- Produces: `ask(endpoint, name, evidence, allowed, timeout) -> Optional[dict]`
  returning `{"verb", "argument", "p_success", "why"}` or None;
  `validate(answer, allowed) -> Optional[dict]`.

- [ ] **Step 1: Write the failing tests**: the client is off unless
      `c2.way_out.model.enabled` is true; it dials **loopback only** and a
      non-loopback endpoint is refused by name; an answer naming a verb outside
      `allowed` is a refusal, logged, not a crash; an answer above the rung
      ceiling is refused; a non-JSON answer, an empty answer and a timeout are
      each a refusal; a valid answer becomes the document's `recommendation`
      with `chose: "model"`.

- [ ] **Step 2: Run them and watch them fail**

- [ ] **Step 3: Implement `software/scout/model.py`** with `urllib` against
      `/api/generate`, `format: "json"`, and a prompt carrying the evidence and
      the allowed verbs and nothing else.

- [ ] **Step 4: Run them and watch them pass**

- [ ] **Step 5: Take the stage-4 measurement** — pull a real small model in an
      arm64 container, ask the question, and record what the validator accepted,
      including a bad result, in the design document's `## Measurements`.

Run:
```bash
docker run -d --name way-out-ollama --platform linux/arm64 \
  --cpus 4 --memory 4g -p 11434:11434 ollama/ollama
docker exec way-out-ollama ollama pull qwen2.5:0.5b
python3 tools/way_out_bench.py --model qwen2.5:0.5b --json
```

- [ ] **Step 6: Commit**

```bash
git add software/scout/model.py software/scout/scout.py software/tests/test_scout_model.py docs/superpowers/specs/2026-11-27-implant-way-out-design.md
git commit -m "feat(scout): the model answers one question, and ships off"
```

---

### Task 11: The operator's page, and the pins

**Files:**
- Create: `docs/WAY_OUT.md`
- Modify: `docs/EGRESS_DECIDER.md`, `README.md`, `docs/AGENT.md`
- Modify: `software/tests/test_docs.py`

- [ ] **Step 1: Write the failing tests** in `test_docs.py`: `docs/WAY_OUT.md`
      exists and is linked from `README.md` and from `docs/EGRESS_DECIDER.md`;
      the page's rung table names all four rungs in cost order; its crossing
      hours match `beacon.py`'s arithmetic computed in the test, not a number
      typed twice; the page says stage 4 ships off and says watts and thermals
      were not measured and why; `docs/EGRESS_DECIDER.md` no longer calls
      `dot1x_seen` and `portal_answered` dead and says what sets them now;
      `configs/raccoon.yaml` ships `c2.way_out.enabled: false` and
      `model.enabled: false`.

- [ ] **Step 2: Run them and watch them fail**

- [ ] **Step 3: Write the page and the edits.**

- [ ] **Step 4: Run them and watch them pass**

Run: `python3 -m unittest software.tests.test_docs -v`
Expected: OK

- [ ] **Step 5: Commit**

```bash
git add docs README.md software/tests/test_docs.py
git commit -m "docs(way-out): the page an operator reads before enabling it"
```

---

### Task 12: The load-dependent sidecar test

**Files:**
- Modify: `software/tests/test_tunnel_shell.py:1423-1444` (and the one other
  reader of a sidecar after `ended`)

- [ ] **Step 1: Read the failure.** `ended()` waits for the port to report no
      live session; the sidecar is written by the output direction's teardown,
      and `_write_private_json` renames it into place. The test asserts the
      **directory entry** and then reads, so a loaded machine can land between
      the slot being given back and the rename.

- [ ] **Step 2: Add `sidecar(path, timeout=20.0) -> dict`** to the recording
      test case: `_wait_until` the file's **bytes** parse as JSON, then return
      the document. Named so a failure says what never happened.

- [ ] **Step 3: Use it** in `test_the_sidecar_is_written_when_the_session_ends`
      and in the other post-`ended` reader, and correct `ended`'s docstring,
      which currently claims nothing has to poll for the file.

- [ ] **Step 4: Prove it**

Run: `python3 -m unittest software.tests.test_tunnel_shell -v`
Expected: OK, and the same under load (run it with the rest of the suite).

- [ ] **Step 5: Commit**

```bash
git add software/tests/test_tunnel_shell.py
git commit -m "test(tunnel): wait for the sidecar's bytes, not its directory entry"
```

---

### Task 13: The whole tree

- [ ] **Step 1: Mutation-check every new test module.** For each, delete
      `__pycache__`, run `python3 -B tools/mutation_check.py <target> <tests>
      <mutations.json>`, and diff the tree afterwards to prove the file came
      back.

- [ ] **Step 2: The suite, on exactly the measured tree.**

Run: `python3 -m unittest discover -s software/tests -t . -v`
Expected: exit status 0. A wall time outside 528–582 s is repeated with a
control run before anything is concluded from it, green or not. No subagent
runs while it does.

- [ ] **Step 3: The lab.**

Run: `python3 tools/e2e_lab.py`
Expected: exit status 0.

- [ ] **Step 4: Push, open the PR, and watch both workflows.**
</content>
</invoke>
