# A rescue channel over DNS — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give a beacon whose HTTPS, SMB and QUIC legs have all failed a way to say *why*, by carrying one short encrypted diagnostic out in a DNS query name through the relay that already exists.

**Architecture:** The beacon keeps the failure class and code it already computes and discards, packs them into a 14-byte struct, and on one exhaustion event sends `<p1>.<p2>.<base32(agent_id)>.r.<zone>`. The DNS listener recognises the `r` marker and calls `relay(payload, url=self.relay_url)` — the same call `smb.py:222` and `quic.py:253` already make — so no listener gains a key, no new route is needed (`relay`'s POST lands on `beacon_handler`, already in `_AGENT_SOCKET_ENDPOINTS`), and the server's existing `ServerCrypto.unwrap` decrypts it unchanged. The TXT answer carries the next tasking back in the same exchange.

**Tech Stack:** Python 3.9, standard library only on the beacon side (`struct`, `base64`, `json`), `unittest`.

**Spec:** `docs/superpowers/specs/2026-11-12-dns-rescue-channel-design.md`

## Global Constraints

- **The beacon is stdlib-only and that is asserted.** `software/tests/test_status_quo.py` must stay green. No import the beacon does not already have.
- **Python 3.9 syntax**, matching the surrounding files: `typing.Optional`/`Dict`/`List`/`Tuple`, `# type:` comments, `%` formatting. NO `X | Y` unions, NO builtin generics in annotations, NO `from __future__ import annotations`.
- **The test runner is `unittest`; pytest is NOT installed.** Full suite: `/usr/bin/python3 -m unittest discover -s software/tests -t . -q` — about six minutes, so use a generous shell timeout and **keep the output in a file**. One module: `/usr/bin/python3 -m unittest software.tests.test_dns_rescue -v`. Always `/usr/bin/python3`; the homebrew pythons on PATH lack the dependencies.
- **`_encrypt(data: dict)` raises `TypeError` for anything else**, and already uses `separators=(",", ":")`. Pass a dict; do not pre-serialise.
- **`_encrypt` returns base64.** The DNS label needs base32 of the **raw ciphertext**, so base64-decode first. Base32 of the base64 *string* is 116 characters and three labels: plausible, wrong, and invisible until it is on a live network.
- **A listener never holds a key.** `relay.py` "never decrypts, never validates and is never given a key -- two tests pin that". Those two tests must pass untouched.
- **`beacon.py` is served as source text** by the generator, so it cannot import shared constants from the listener package. Copies are the convention; `relay.py`'s own comment explains why.
- **No new runtime dependency.** Neither `software/requirements.txt` nor `software/agent/requirements.txt` grows.
- Comment voice follows the surrounding files: explain *why*, and name the failure a choice avoids.

## Review Focus

Five things the spec implies that no task's happy-path test would catch, each wired into the task that owns the code:

1. **A payload label that is not valid base32**, or one of the two labels missing, arriving at the listener. It must be answered exactly like any other query — no error, no different timing, no distinguishable response — or the listener becomes an oracle that tells an attacker whether a guess decrypted. Task 4.
2. **A rescue sent while the beacon has no agent id.** `self._agent_id or self._implant_id` means the label is an implant id, which the server cannot attach to an agent row. It must still be accepted and shown. Task 5.
3. **A zone long enough to push the name past 253 characters.** Must not send, must not truncate. Task 3.
4. **An exhaustion that repeats every cycle for an hour.** The latch must hold; a rate is the one thing a tunnel detector reliably finds. Task 3.
5. **A failure recorded in one cycle appearing in a later cycle's rescue.** The accumulator must be cleared at the top of each cycle, or the operator reads a stale reason as current. Task 2.

---

### Task 1: The record — pack, unpack, and the label arithmetic

**Files:**
- Create: `software/c2/dns_rescue.py`
- Test: `software/tests/test_dns_rescue.py`

**Interfaces:**
- Consumes: nothing.
- Produces, and both sides import it (the server side can; the beacon side **cannot** — see Task 2):
  - `VERSION = 1`
  - `CLASSES` — the failure-class enum as a dict of name to int, with `0` meaning "not attempted"
  - `FLAG_PROXY_FOUND`, `FLAG_DOT1X_SEEN`, `FLAG_PORTAL_ANSWERED`, `FLAG_DNS_ANSWERED` — single-bit masks
  - `pack(per_transport: dict, flags: int) -> bytes` — 14 bytes (class 1 byte, code **2** bytes), `struct`, order `https, dns, smb, quic`
  - `unpack(raw: bytes) -> dict` — raises `ValueError` on a wrong length or an unknown version
  - `to_labels(b64_ciphertext: str) -> Tuple[str, str]` — base64-decode, base32-encode unpadded lowercase, split at `ceil(len/2)`
  - `from_labels(label_1: str, label_2: str) -> str` — the inverse, returning base64 for `_decrypt`
  - `MARKER = "r"`

- [ ] **Step 1: Write the failing tests**

```python
def test_the_record_is_ten_bytes(self):
    raw = dns_rescue.pack(
        {"https": (dns_rescue.CLASSES["http_status"], 407),
         "dns": (dns_rescue.CLASSES["answered"], 0),
         "smb": (dns_rescue.CLASSES["refused"], 111),
         "quic": (dns_rescue.CLASSES["timed_out"], 0)},
        dns_rescue.FLAG_PROXY_FOUND | dns_rescue.FLAG_DNS_ANSWERED)
    self.assertEqual(len(raw), 10)

def test_pack_and_unpack_round_trip(self): ...

def test_a_wrong_length_or_version_is_refused(self):
    for bad in (b"", b"\x00" * 9, b"\x00" * 11, b"\xff" + b"\x00" * 9):
        with self.assertRaises(ValueError):
            dns_rescue.unpack(bad)

def test_a_code_above_255_is_refused_rather_than_truncated(self):
    # An HTTP status fits; a 4-digit vendor code does not, and silently
    # keeping the low byte would report a different failure than happened.
    with self.assertRaises(ValueError):
        dns_rescue.pack({"https": (dns_rescue.CLASSES["http_status"], 1000),
                         "dns": (0, 0), "smb": (0, 0), "quic": (0, 0)}, 0)

def test_the_payload_is_exactly_two_labels_of_at_most_63(self):
    # The real chain: pack -> _encrypt's dict wrapper -> AES-GCM -> base32.
    # Asserted, not assumed: the margin is one character wide.
    cipher_b64 = _encrypt_like_the_beacon({"d": base64.b64encode(raw).decode()})
    one, two = dns_rescue.to_labels(cipher_b64)
    self.assertEqual(len(one) + len(two), 84)
    for label in (one, two):
        self.assertLessEqual(len(label), 63)
        self.assertRegex(label, r"\A[a-z2-7]+\Z")

def test_base32_is_taken_from_the_bytes_not_from_the_base64_string(self):
    # The trap: base32 of the base64 text is 116 chars and three labels.
    one, two = dns_rescue.to_labels(cipher_b64)
    self.assertNotEqual(len(one) + len(two),
                        len(base64.b32encode(cipher_b64.encode())))

def test_labels_round_trip_back_to_the_base64(self):
    self.assertEqual(dns_rescue.from_labels(*dns_rescue.to_labels(c)), c)
```

`_encrypt_like_the_beacon` is a local helper in the test file that mirrors the beacon's `_encrypt` (dict → `json.dumps(separators=(",", ":"))` → AES-GCM → base64) with a fixed key, so the arithmetic is pinned without importing the implant.

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_dns_rescue -v`
Expected: FAIL — no module `software.c2.dns_rescue`.

- [ ] **Step 3: Implement `software/c2/dns_rescue.py`**

A module docstring saying what the file is for and why it is its own file: the record format is the one thing the implant, the listener and the server must agree on byte for byte, and the implant cannot import from the listener package. The listener and server import this; the beacon carries a copy (Task 2) and a test pins the two against each other (Task 2, step 5).

`pack` validates every code is `0 <= code <= 65535` and every class is a known value, and raises `ValueError` naming the field — a silently truncated code reports a failure that did not happen.

- [ ] **Step 4: Run the module's tests**

Run: `/usr/bin/python3 -m unittest software.tests.test_dns_rescue -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/c2/dns_rescue.py software/tests/test_dns_rescue.py
git commit -m "feat(rescue): the ten-byte diagnostic record and its two labels"
```

---

### Task 2: The beacon keeps what it already knows

**Files:**
- Modify: `software/c2/beacon.py` — the four `_beacon_<transport>` methods and a new accumulator
- Test: `software/tests/test_dns_rescue.py`

**Interfaces:**
- Consumes: Task 1's format, **by copy**. The beacon is served as source text and cannot import `software.c2.dns_rescue`.
- Produces: `self._leg_status` — a dict `transport -> (class, code)` on the beacon instance, cleared at the top of each cycle; and `self._rescue_flags`, an int.

- [ ] **Step 1: Write the failing tests**

```python
def test_each_leg_records_its_class_and_code(self):
    # Drive each _beacon_* method with a transport that fails in a known
    # way and assert the recorded pair, rather than reading the log.

def test_a_dns_query_that_answers_with_no_tasking_records_answered(self):
    # The distinction the whole feature rests on: `None` from _beacon_dns
    # means "failed" or "nothing to deliver", and only the recorded class
    # tells them apart.

def test_the_accumulator_is_cleared_at_the_top_of_each_cycle(self):
    # Cycle 1 fails on https; cycle 2 fails on smb only. The rescue built
    # in cycle 2 must show https as "not attempted", not cycle 1's failure.

def test_the_beacons_copy_of_the_record_format_matches_the_module(self):
    # Reads the constants out of beacon.py's source and compares them with
    # software.c2.dns_rescue. A copy that drifts is the failure mode this
    # arrangement buys, so it gets a test rather than a comment.
```

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_dns_rescue -v`
Expected: FAIL — no `_leg_status`.

- [ ] **Step 3: Implement the recording**

In each of `_beacon_https`, `_beacon_dns`, `_beacon_smb`, `_beacon_quic`: beside the existing `logger.debug`, record `(class, code)` into `self._leg_status`. **Keep the debug log** — it is the only thing an operator with console access has today, and the only thing that works when DNS is dead too.

`_beacon_dns` is the one that earns its keep: it must distinguish a query that was answered (record `answered`, set `FLAG_DNS_ANSWERED`) from one that failed to resolve, and it must do so without a second query — the information is in the exception it already catches and in whether `_dns_query` returned records.

- [ ] **Step 4: Run the module and the beacon tests**

Run: `/usr/bin/python3 -m unittest software.tests.test_dns_rescue software.tests.test_beacon software.tests.test_beacon_caps -v`
Expected: PASS.

- [ ] **Step 5: Confirm the promise holds**

Run: `/usr/bin/python3 -m unittest software.tests.test_status_quo -v`
Expected: PASS — the beacon's dependencies have not grown.

- [ ] **Step 6: Commit**

```bash
git add software/c2/beacon.py software/tests/test_dns_rescue.py
git commit -m "feat(rescue): keep the failure class each leg already computes"
```

---

### Task 3: The trigger and the query

**Files:**
- Modify: `software/c2/beacon.py` — `_beacon_loop`, plus a new `_send_rescue`
- Test: `software/tests/test_dns_rescue.py`

**Interfaces:**
- Consumes: `self._leg_status`, `self._rescue_flags` (Task 2); the beacon's copy of the format (Task 2).
- Produces: `self._rescue_sent` (the latch) and `_send_rescue() -> Optional[dict]`, which returns whatever tasking came back in the TXT answer, or `None`.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_rescue_goes_out_when_nothing_delivered_and_dns_answered(self):
    # Asserts the query name's shape: two base32 labels, the agent label,
    # the marker "r", the zone.

def test_no_rescue_when_the_resolver_did_not_answer(self):
    # The case the next project exists for: nothing can leave.

def test_no_rescue_when_dns_delivered_tasking(self):
    # The loop short-circuits smb and quic in that cycle, and a beacon
    # receiving tasking is not stuck.

def test_only_one_rescue_per_exhaustion(self):
    # Twenty failing cycles produce exactly one rescue query.

def test_the_latch_clears_when_a_leg_recovers(self):
    # Fail, rescue, succeed, fail again -> a second rescue, and only then.

def test_a_name_over_253_characters_is_not_sent(self):
    # A 200-character zone: no query, and the reason in the debug log.
    # Not truncated -- a truncated record is indistinguishable at the
    # server from an attacker's noise.

def test_the_record_carries_no_hostname_or_credential(self):
    # Walk the packed bytes and the dict handed to _encrypt for any
    # substring of the configured host, agent id, proxy URL or key.
```

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_dns_rescue -v`
Expected: FAIL — no `_send_rescue`.

- [ ] **Step 3: Implement `_send_rescue` and wire the trigger**

`_send_rescue` packs `self._leg_status` and `self._rescue_flags`, wraps the bytes as `{"d": base64}` , calls `self._encrypt`, converts to two labels, builds the name, and sends one TXT query through `_dns_query` — the same function `_beacon_dns` uses, with the same resolver and timeout. It returns the decrypted answer if one came back, so the rescue and the next tasking are one exchange.

The trigger goes in the `if tasking is None:` arm of `_beacon_loop`, beside the existing `_consecutive_failures` increment, and fires only when the recorded DNS class says the resolver answered and the latch is clear. The latch clears wherever `_consecutive_failures` is reset to 0.

- [ ] **Step 4: Run the module, the beacon and the status-quo suites**

Run: `/usr/bin/python3 -m unittest software.tests.test_dns_rescue software.tests.test_beacon software.tests.test_status_quo -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/c2/beacon.py software/tests/test_dns_rescue.py
git commit -m "feat(rescue): one query per exhaustion, and never when nothing can leave"
```

---

### Task 4: The listener relays it

**Files:**
- Modify: `software/c2/listeners/dns.py`
- Test: `software/tests/test_listeners.py`

**Interfaces:**
- Consumes: `software.c2.dns_rescue` (the listener *may* import it); `relay` from `.relay`, which `DnsListener` can already reach because `__init__` takes `relay_url` and keeps it.
- Produces: no new public name; the listener's query handler gains a branch. **No new configuration and no new server route** — `relay`'s POST lands on `beacon_handler`, which is already in `_AGENT_SOCKET_ENDPOINTS`.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_rescue_query_is_relayed_not_fetched(self):
    # Marker "r": relay() is called with the reassembled base64 and
    # fetch_tasking is not.

def test_a_tasking_query_still_fetches(self):
    # Marker "b": unchanged behaviour.

def test_the_answer_carries_what_the_relay_returned(self): ...

def test_a_malformed_payload_is_answered_like_any_other_query(self):
    # Review Focus 1. Not valid base32; only one label; three labels; a
    # label of 63 random characters. For each: the same response shape as
    # a tasking query with nothing queued, so the listener is no oracle.
    # Asserted on the response bytes, not on a log line.

def test_the_listener_still_holds_no_key(self):
    # The existing relay tests cover the module; this one covers the new
    # branch: no key, no decrypt call, no import of a crypto helper.
```

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_listeners -v`
Expected: FAIL — the marker is not recognised.

- [ ] **Step 3: Implement the branch**

Parse the marker label. On `r`: reassemble with `dns_rescue.from_labels` and call `relay(payload, url=self.relay_url, timeout=...)`, as `smb.py:222` does; put the returned base64 in the TXT answer. On `b`: `fetch_tasking`, untouched.

A malformed payload takes the same path as an empty queue. Extend the module docstring: its opening claim that this transport "carries nothing upstream" now has one exception, and the docstring is where a reader will look for it.

- [ ] **Step 4: Run the listener suite**

Run: `/usr/bin/python3 -m unittest software.tests.test_listeners -v`
Expected: PASS, including the two relay tests unchanged.

- [ ] **Step 5: Commit**

```bash
git add software/c2/listeners/dns.py software/tests/test_listeners.py
git commit -m "feat(rescue): the dns listener relays a rescue and still holds no key"
```

---

### Task 5: The server shows it

**Files:**
- Modify: `software/c2/server.py` — the beacon handler's response path and the agent-row rendering
- Modify: `docs/LISTENERS.md` and `docs/AGENT.md` if either states the download-only property
- Test: `software/tests/test_server.py`, `software/tests/test_c2_agent_gui.py`, `software/tests/test_docs.py`

**Interfaces:**
- Consumes: `software.c2.dns_rescue.unpack`; the existing `ServerCrypto.unwrap` path.
- Produces: a decoded diagnostic on the agent record, and the operator-facing text for it.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_relayed_rescue_reaches_the_agent_record(self):
    # Through the real beacon_handler and the real unwrap, with no
    # server-side decryption change.

def test_an_unattributed_rescue_is_kept(self):
    # Review Focus 2: the label carries an implant id because the beacon
    # never registered. It is shown, not dropped -- that beacon is the one
    # with the least other evidence.

def test_a_record_of_an_unknown_version_is_refused_without_a_traceback(self): ...

def test_the_via_dns_tooltip_no_longer_claims_results_are_never_reported(self):
    # test_c2_agent_gui already pins that copy; this changes what it pins.
```

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_server software.tests.test_c2_agent_gui -v`
Expected: FAIL.

- [ ] **Step 3: Implement the decode and the display**

The payload arrives through `beacon_handler` and `unwrap` with no change, so the work is recognising a rescue dict, calling `unpack`, and attaching the result to the agent record. Render it as a sentence an operator can act on — "HTTPS: proxy wanted authentication (407); SMB: connection refused; QUIC: timed out; DNS answered" — not a hex dump.

Rewrite the VIA DNS tooltip: tasking-only is still true for *results*, and no longer true for *why it is stuck*.

- [ ] **Step 4: Run the server, GUI and docs suites**

Run: `/usr/bin/python3 -m unittest software.tests.test_server software.tests.test_c2_agent_gui software.tests.test_docs -v`
Expected: PASS.

- [ ] **Step 5: Run the full suite**

Run: `/usr/bin/python3 -m unittest discover -s software/tests -t . -q` — about six minutes, output to a file.
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add software/c2/server.py software/tests/ docs/
git commit -m "feat(rescue): the operator sees why a dns-only beacon is stuck"
```

---

### Task 6: The agent answers

**Files:**
- Modify: `software/agent/tools/` — one new tool, in the module its siblings live in
- Modify: `software/agent/prompts.py` if the tool needs naming there
- Test: `software/tests/test_agent_tools.py`

**Interfaces:**
- Consumes: the decoded diagnostic from Task 5, through the C2 API the agent already uses.
- Produces: a tool the orchestrator can call to read a stuck beacon's diagnostic and queue one concrete next attempt.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_tool_reports_the_decoded_diagnostic(self): ...

def test_it_queues_exactly_one_next_attempt(self):
    # One candidate per call. A sweep of twelve is the loud thing the
    # design refused in approach C.

def test_a_beacon_with_no_diagnostic_is_reported_as_such(self):
    # Not an error: most beacons are fine and have nothing to report.
```

- [ ] **Step 2: Run them to verify they fail**

Run: `/usr/bin/python3 -m unittest software.tests.test_agent_tools -v`
Expected: FAIL — no such tool.

- [ ] **Step 3: Implement the tool**

Follow the shape of the existing tools in that package — the registry entry, the schema, the docstring the model reads. It reads the diagnostic and queues **one** attempt, because the alternative is the candidate sweep the design ruled out for being louder than the problem.

- [ ] **Step 4: Run the agent suites**

Run: `/usr/bin/python3 -m unittest software.tests.test_agent_tools software.tests.test_agent_prompts -v`
Expected: PASS.

- [ ] **Step 5: Run the full suite**

Run: `/usr/bin/python3 -m unittest discover -s software/tests -t . -q`, output to a file.
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add software/agent/ software/tests/test_agent_tools.py
git commit -m "feat(rescue): the agent reads the diagnostic and queues one attempt"
```
