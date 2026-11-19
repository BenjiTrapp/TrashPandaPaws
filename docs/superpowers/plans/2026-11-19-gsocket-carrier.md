# gsocket carrier as the beacon's fifth leg — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the hardware implant a fifth C2 leg that reaches the team server through the Global Socket Relay Network, so it still checks in when HTTPS, DNS, SMB and QUIC are all blocked.

**Architecture:** `gs-netcat` runs as a child process on both sides and carries the beacon's *existing* HTTP exchange — the implant's carrier opens a local forward, the leg POSTs to it, the team server's carrier forwards inbound GSRN connections into the beacon socket. No new wire protocol, no new crypto, and the carrier never holds the encryption key. One secret per implant, held in a JSON store on the team server modelled on `software/c2/tunnel/keys.py`.

**Tech Stack:** Python 3.9 stdlib only, `unittest`, `gs-netcat` (static aarch64 binary), systemd socket-less unit, Flask (team server, already present).

**Spec:** `docs/superpowers/specs/2026-11-15-gsocket-carrier-design.md`

## Global Constraints

- **Python 3.9 exactly.** CI asserts `sys.version_info[:2] == (3, 9)`. No `match`, no `dict | dict`, no `X | None` annotations.
- **The suite is `unittest`, not pytest.** Run it with `python3 -m unittest discover -s software/tests -t .` from the repository root. pytest is not installed and the suite is not written for it.
- **`software/c2/beacon.py` is served to a target as source text** by the generator. It may import only the Python standard library — never a module from this repository. Formats it shares with other files stay as copies that a test compares.
- **The secret never appears in `argv`.** `gs-netcat -k <file>` only, never `-s`. `ps` is world-readable.
- **File modes:** secret store directory `0o700`, secret files `0o600`, matching `_DIR_MODE` and `_FILE_MODE` in `software/c2/tunnel/keys.py`.
- **The leg goes last**, after `quic`, in both the tasking chain and the result-send chain.
- **`scheme` defaults to `"http"`** — `server.py`'s `--ssl` is off by default and every shipped `relay_url` is `http://127.0.0.1:8443`.
- **Everything ships disabled:** `c2.fallback.gsocket.enabled: false` and no carrier configured in a fresh checkout.
- **The carrier is lazy with a warm latch:** it does not run at beacon start; it starts the first time a cycle ends with no upstream leg having delivered, and then stays up for the life of the process.
- **One secret per implant.** No fleet-wide secret anywhere in the code or the shipped config.
- **The carrier holds no encryption key**, the property every listener rests on. A test must pin it, as `software/tests/test_listeners.py` does for the relay.
- **A disabled config block is validated exactly as strictly as an enabled one**, the rule `software/c2/listeners/registry.py` states and enforces.

## Review Focus

1. **A 16-byte v1 rescue record arriving after the version bump.** Every Pi already in the field and every already-generated build carries the old format. The server must read it as four transports with `gsocket` reading `not_attempted`, not drop it. Pinned in Task 1.
2. **A world-readable secret file.** `0o644` must be refused at startup with the mode in the message, not used. Pinned in Task 2.
3. **The binary missing, or present with a wrong SHA-256.** The leg must disable itself for the process's lifetime, log the reason once rather than per cycle, and record `binary_missing`. Pinned in Task 4.
4. **`local_port` already bound on the implant.** The carrier cannot listen; the leg must record `carrier_failed` and the cycle must move on rather than wedge. Pinned in Task 6.
5. **The carrier child killed mid-engagement.** The leg reports down, the beacon restarts the child after `restart_delay_seconds`, and `max_restarts: 0` means unlimited. Pinned in Task 6.

---

### Task 1: The rescue format grows a fifth transport and keeps reading v1

**Files:**
- Modify: `software/c2/dns_rescue.py` (`TRANSPORTS`, `VERSION`, `CLASSES`, `_STRUCT`, `RECORD_BYTES`, `PAYLOAD_CHARS`, `unpack`)
- Modify: `software/c2/beacon.py:1676-1760` (the copy: `_RESCUE_TRANSPORTS`, `_RESCUE_VERSION`, `_RESCUE_CLASSES`, `_RESCUE_STRUCT`, `_rescue_pack`)
- Test: `software/tests/test_dns_rescue.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `dns_rescue.TRANSPORTS == ("https", "dns", "smb", "quic", "gsocket")`; `dns_rescue.VERSION == 2`; `dns_rescue.RECORD_BYTES == 19`; `dns_rescue.PAYLOAD_CHARS == 103`; `CLASSES["binary_missing"] == 10`, `CLASSES["carrier_failed"] == 11`; `unpack(raw: bytes) -> dict` accepting 16- and 19-byte records and always returning all five transport keys.

- [ ] **Step 1: Write the failing tests**

```python
def test_gsocket_is_the_fifth_and_last_transport(self):
    self.assertEqual(dns_rescue.TRANSPORTS,
                     ("https", "dns", "smb", "quic", "gsocket"))

def test_a_five_transport_record_round_trips(self):
    packed = dns_rescue.pack(
        {"https": (dns_rescue.CLASSES["timed_out"], 0),
         "gsocket": (dns_rescue.CLASSES["carrier_failed"], 0)},
        dns_rescue.FLAG_DNS_ANSWERED, 0xBEEF)
    self.assertEqual(len(packed), 19)
    out = dns_rescue.unpack(packed)
    self.assertEqual(out["version"], 2)
    self.assertEqual(out["fingerprint"], 0xBEEF)
    self.assertEqual(out["gsocket"],
                     (dns_rescue.CLASSES["carrier_failed"], 0))

def test_a_v1_record_from_the_field_still_reads(self):
    # What an implant deployed before this change sends: 16 bytes,
    # version 1, four transports.
    v1 = struct.pack("!BHBHBHBHBHB", 1, 0xBEEF,
                     dns_rescue.CLASSES["timed_out"], 0,
                     dns_rescue.CLASSES["answered"], 0,
                     dns_rescue.CLASSES["not_attempted"], 0,
                     dns_rescue.CLASSES["not_attempted"], 0,
                     dns_rescue.FLAG_DNS_ANSWERED)
    out = dns_rescue.unpack(v1)
    self.assertEqual(out["version"], 1)
    self.assertEqual(out["https"], (dns_rescue.CLASSES["timed_out"], 0))
    self.assertEqual(out["gsocket"],
                     (dns_rescue.CLASSES["not_attempted"], 0))

def test_an_unknown_version_is_still_refused(self):
    with self.assertRaises(ValueError):
        dns_rescue.unpack(b"\x07" + b"\x00" * 18)
```

Update the two existing assertions that pin the old numbers:
`test_dns_rescue.py:141` becomes `self.assertEqual(dns_rescue.PAYLOAD_CHARS, 103)`, and line 429's use of `PAYLOAD_CHARS` follows it. Leave `test_dns_rescue.py:350-352` alone — it compares the two copies and must keep passing.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest software.tests.test_dns_rescue -v`
Expected: FAIL — `TRANSPORTS` has four entries, `unpack` refuses 19 bytes on length.

- [ ] **Step 3: Implement the format change in `software/c2/dns_rescue.py`**

Append `"gsocket"` to `TRANSPORTS` (the file states the order is positional, so append — do not reorder). `VERSION = 2`. Add `binary_missing: 10` and `carrier_failed: 11` to `CLASSES`. Keep the v1 struct alongside the new one:

```python
_STRUCT_V1 = struct.Struct("!BHBHBHBHBHB")     # 16 bytes, four transports
_STRUCT = struct.Struct("!BHBHBHBHBHBHB")      # 19 bytes, five
TRANSPORTS_V1 = ("https", "dns", "smb", "quic")
```

`unpack` selects the struct and the transport tuple by `len(raw)`, refuses any other length, refuses a version that does not match the length it arrived in, and fills transports absent from a v1 record with `(CLASSES["not_attempted"], 0)` so every caller still sees five keys. Update `PAYLOAD_CHARS` to 103 and the comment above it with the new chain (`19 -> 28 -> 36 -> 64 -> 103`), noting that the margin to `_MAX_PAYLOAD_CHARS` is now 23 characters.

- [ ] **Step 4: Mirror the change in `beacon.py`'s copy**

`_RESCUE_TRANSPORTS`, `_RESCUE_VERSION = 2`, `_RESCUE_CLASSES` and `_RESCUE_STRUCT` take the same values. `_rescue_pack` keeps clamping rather than raising — it runs on the failure path of every check-in. The beacon only ever *writes* v2, so it needs no v1 arm.

- [ ] **Step 5: Run the full suite**

Run: `python3 -m unittest discover -s software/tests -t .`
Expected: PASS. `test_dns_rescue.py:350` proves the two copies agree; `_handle_rescue` in `server.py` iterates `dns_rescue.TRANSPORTS` and needs no change.

- [ ] **Step 6: Commit**

```bash
git add software/c2/dns_rescue.py software/c2/beacon.py software/tests/test_dns_rescue.py
git commit -m "feat(rescue): a fifth transport in the record, and v1 still reads"
```

---

### Task 2: The per-implant secret store

**Files:**
- Create: `software/c2/gsocket/__init__.py`, `software/c2/gsocket/secrets.py`
- Test: `software/tests/test_gsocket_secrets.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `SECRETSTORE_RELPATH = ("gsocket", "secrets.json")`; `secretstore_path(data_dir) -> Path`; `class SecretStore(path)` with `register_implant(identity: str, secret: str) -> None`, `secret_for(identity: str) -> str`, `identities() -> List[str]`, `generate() -> str`, `secret_file_for(identity: str) -> Path`.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_registered_secret_comes_back(self):
def test_a_second_implant_gets_a_different_secret(self):
def test_a_duplicate_identity_is_refused_and_changes_nothing(self):
def test_a_secret_already_registered_to_another_implant_is_refused(self):
def test_the_store_file_is_not_readable_by_others(self):
    # 0o600 on the file, 0o700 on its directory
def test_a_world_readable_store_is_refused_on_load(self):
    # chmod 0o644, then SecretStore(path) raises ValueError naming the mode
def test_a_short_secret_is_refused(self):
    # anyone who guesses it reaches a port fronting the beacon socket
def test_secret_file_for_writes_0600_and_the_secret_alone(self):
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest software.tests.test_gsocket_secrets -v`
Expected: FAIL — `ModuleNotFoundError: software.c2.gsocket`.

- [ ] **Step 3: Implement `software/c2/gsocket/secrets.py`**

Mirror `software/c2/tunnel/keys.py`: one JSON file, `_DIR_MODE = 0o700`, `_FILE_MODE = 0o600`, atomic write, refuse a duplicate identity and a duplicate secret rather than overwriting either. `generate()` returns a secret of at least 24 characters from `secrets.choice` over an unambiguous alphabet; the minimum length is enforced in `register_implant` too, so a hand-written secret cannot be weaker than a generated one. `secret_file_for` writes the secret to a `0o600` file for `gs-netcat -k` and returns its path.

Write the module docstring in the house style: say that this store exists because a fleet-wide secret would let one recovered implant image reach the beacon socket for the whole fleet, and that the bound is the AES-256-GCM envelope — exactly as far as a compromised listener reaches.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest software.tests.test_gsocket_secrets -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/c2/gsocket/ software/tests/test_gsocket_secrets.py
git commit -m "feat(gsocket): a per-implant secret store"
```

---

### Task 3: Configuration for both sides, validated strictly

**Files:**
- Create: `software/c2/gsocket/config.py`
- Test: `software/tests/test_gsocket_config.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `@dataclass CarrierSpec(name, identity, enabled, beacon_host, beacon_port, binary_path, sha256, local_port=0)`; `load_carriers(config: Optional[dict]) -> List[CarrierSpec]` reading `c2.gsocket_carrier`; `validate_leg(block: Optional[dict]) -> dict` for `c2.fallback.gsocket`, returning the block with defaults filled; `LEG_DEFAULTS` holding `scheme="http"`, `local_port=16443`, `restart_delay_seconds=30`, `max_restarts=0`, `ready_timeout_seconds=20`.

- [ ] **Step 1: Write the failing tests**

```python
def test_no_block_yields_no_carriers(self):      # every existing deployment
def test_a_disabled_carrier_is_validated_as_strictly_as_an_enabled_one(self):
def test_two_carriers_with_one_identity_are_refused(self):
def test_a_carrier_without_an_identity_is_refused(self):
def test_a_beacon_port_outside_1_65535_is_refused(self):
def test_leg_defaults_scheme_to_http(self):
def test_an_enabled_leg_without_a_secret_file_is_refused(self):
def test_an_unknown_leg_setting_is_refused_rather_than_ignored(self):
    # a setting silently dropped looks exactly like one that was applied
def test_a_scheme_other_than_http_or_https_is_refused(self):
def test_a_relative_binary_path_is_refused(self):
    # cwd on the implant is not ours to assume
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest software.tests.test_gsocket_config -v`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement `software/c2/gsocket/config.py`**

Follow `software/c2/listeners/registry.py` closely, including its habit of putting the offending value in every message and validating disabled entries. Raise `ValueError` for everything refused. Carry the registry's comment about the two look-alike blocks forward: `c2.gsocket_carrier` is this host as a *server*, `c2.fallback.gsocket` is this host as a *client*.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest software.tests.test_gsocket_config -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/c2/gsocket/config.py software/tests/test_gsocket_config.py
git commit -m "feat(gsocket): configuration for both sides, refused loudly"
```

---

### Task 4: The carrier process — argv, hash check, spawn, probe

**Files:**
- Create: `software/c2/gsocket/carrier.py`
- Test: `software/tests/test_gsocket_carrier.py`
- Test fixture: `software/tests/data/fake_gs_netcat.sh`

**Interfaces:**
- Consumes: `CarrierSpec` and `LEG_DEFAULTS` from Task 3; `SecretStore.secret_file_for` from Task 2.
- Produces: `class GsocketCarrier(spec: CarrierSpec, secret_path: str)` with `argv() -> List[str]`, `verify_binary() -> Optional[str]` (a reason, or `None` when fine), `start() -> None`, `stop() -> None`, `is_running() -> bool`, `status() -> dict`, `probe(timeout: float = 5.0) -> bool`; `class CarrierError(Exception)`.

- [ ] **Step 1: Verify how `gs-netcat -p` binds, and record the answer**

Run a real `gs-netcat -k <file> -p 16443` and inspect the listening socket (`ss -ltnp` on Linux, `lsof -nP -iTCP -sTCP:LISTEN` on macOS). The man page does not say whether the client's forward binds `127.0.0.1` or every interface, and the spec's *Known limits* entry claims loopback.

**If it binds every interface:** stop and report it. The entry in `docs/AGENT.md` must then say so, and the implant needs a host firewall rule or the leg needs a different arrangement — that is a design change, not an implementation detail, and it goes back to the operator.

Record the finding as a comment above `argv()` either way, so the next reader does not have to re-run it.

- [ ] **Step 2: Write the failing tests**

```python
def test_the_secret_is_never_in_argv(self):
    # -k and a path, never -s. ps is world-readable.
def test_the_server_side_argv_forwards_into_the_beacon_socket(self):
    # -l -d <beacon_host> -p <beacon_port>, the spec's 127.0.0.1:8443
def test_the_implant_side_argv_waits_for_the_far_side(self):
    # -w, so a carrier started before the server's does not fail at once
def test_a_missing_binary_is_a_reason_not_an_exception(self):
def test_a_wrong_sha256_is_refused_with_both_digests_in_the_reason(self):
def test_an_empty_sha256_skips_the_check(self):   # as c2.sliver.sha256 does
def test_start_then_is_running_then_stop(self):   # against the fake binary
def test_stop_is_safe_when_nothing_is_running(self):
def test_the_carrier_never_holds_the_encryption_key(self):
    # no attribute, no argv entry, no environment variable carries it
```

- [ ] **Step 3: Run them to verify they fail**

Run: `python3 -m unittest software.tests.test_gsocket_carrier -v`
Expected: FAIL — module does not exist.

- [ ] **Step 4: Write the fake binary fixture**

`software/tests/data/fake_gs_netcat.sh`: a shell script that parses `-p` and listens on that TCP port until killed, so every test in this task and Task 5 runs offline. The anti-goal is a suite that needs the GSRN.

- [ ] **Step 5: Implement `software/c2/gsocket/carrier.py`**

`verify_binary` checks existence, the executable bit and the SHA-256 (empty means skip, as `c2.sliver.sha256` does) and returns a reason string rather than raising — the caller decides whether a reason is fatal. `start` verifies first and refuses to spawn otherwise. `probe` runs the binary with `-t`, which asks the GSRN whether the peer is listening without connecting it, and is the health check the panel uses.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python3 -m unittest software.tests.test_gsocket_carrier -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add software/c2/gsocket/carrier.py software/tests/test_gsocket_carrier.py software/tests/data/fake_gs_netcat.sh
git commit -m "feat(gsocket): the carrier process, its argv and its probe"
```

---

### Task 5: The team server supervises carriers, and the panel shows them

**Files:**
- Create: `software/c2/gsocket/supervisor.py`
- Modify: `software/c2/server.py:1196-1250` (`api_listeners`, `api_listener_action`)
- Test: `software/tests/test_gsocket_server.py`

**Interfaces:**
- Consumes: `GsocketCarrier` (Task 4), `load_carriers` (Task 3), `SecretStore` (Task 2).
- Produces: `class CarrierSupervisor(specs, store)` with `status() -> List[dict]`, `start(name) -> dict`, `stop(name) -> dict`, `managed: bool`; each status row carrying `{"name", "transport": "gsocket", "identity", "socket": None, "running", "pid", "uptime", "detail"}`.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_carrier_row_reports_no_socket(self):
    # where a listener reports bind host and port
def test_carriers_show_even_when_no_listeners_are_configured(self):
    # today this route answers "no listeners are configured"; that
    # sentence must not hide a configured carrier
def test_one_row_per_configured_implant(self):
def test_start_and_stop_reach_the_carrier_by_name(self):
def test_an_unknown_name_is_404_and_a_wrong_state_is_409(self):
    # the distinction api_listener_action already makes
def test_the_agent_socket_cannot_reach_this_route(self):
    # the cover answer, as for every operator route
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest software.tests.test_gsocket_server -v`
Expected: FAIL.

- [ ] **Step 3: Implement `CarrierSupervisor`**

Model it on `software/c2/listeners/supervisor.py`, keeping its three properties: every refusal carries a reason, `managed=False` is a first-class state and not an error, and no secret reaches a command line. The carrier's secret reaches it as a file path, written by `SecretStore.secret_file_for`.

- [ ] **Step 4: Wire both routes in `server.py`**

`api_listeners` merges carrier rows with listener rows and no longer short-circuits on `supervisor is None` when carriers exist; its `detail` sentence mentions both blocks. `api_listener_action` dispatches by name to whichever supervisor owns it, and reports a name owned by neither as 404.

- [ ] **Step 5: Add the panel row**

In `server.py`'s embedded SPA, render a carrier row with *no socket* where the sibling shows host and port, and its identity beside it.

- [ ] **Step 6: Run the suite**

Run: `python3 -m unittest discover -s software/tests -t .`
Expected: PASS, including the existing `test_listeners.py` and `test_c2_server.py`.

- [ ] **Step 7: Commit**

```bash
git add software/c2/gsocket/supervisor.py software/c2/server.py software/tests/test_gsocket_server.py
git commit -m "feat(gsocket): the team server supervises carriers and the panel shows them"
```

---

### Task 6: The beacon's fifth leg

**Files:**
- Modify: `software/c2/beacon.py` — `_FALLBACK_TRANSPORTS:1676`, `_RESCUE_UPSTREAM:1691`, `Beacon.__init__:4925-5000`, `_evasive_url:5091`, `_https_post:5398`, new `_gsocket_*` methods beside `_beacon_quic:6007`, `_beacon_loop:8369-8460`, the result chain at `:8356-8366`
- Test: `software/tests/test_gsocket_leg.py`

**Interfaces:**
- Consumes: the fake binary fixture from Task 4. Nothing from the `software.c2.gsocket` package — `beacon.py` may not import it.
- Produces: `Beacon._beacon_gsocket() -> Optional[dict]`, `Beacon._send_result_gsocket(task_id, status, output, data=None)`, `Beacon._gsocket_start() -> bool`, `Beacon._gsocket_ready() -> bool`.

- [ ] **Step 1: Write the failing tests**

```python
def test_gsocket_is_last_in_the_chain(self):
    self.assertEqual(beacon_mod._FALLBACK_TRANSPORTS,
                     ("https", "dns", "smb", "quic", "gsocket"))

def test_gsocket_is_an_upstream_leg(self):
    # bidirectional, so it may re-arm the rescue latch
    self.assertIn("gsocket", beacon_mod._RESCUE_UPSTREAM)

def test_the_carrier_does_not_run_while_https_delivers(self):
    # the lazy half of the latch: no child process at all
def test_the_carrier_starts_when_no_upstream_leg_delivered(self):
def test_the_carrier_stays_up_once_started(self):
    # the warm half: the second outage costs no readiness wait
def test_a_cycle_before_the_carrier_is_ready_records_carrier_failed(self):
def test_a_bound_local_port_records_carrier_failed_and_the_cycle_moves_on(self):
    # bind local_port first, then run one cycle
def test_a_missing_binary_disables_the_leg_and_logs_once(self):
    # two cycles, one log line, class binary_missing
def test_a_killed_child_is_restarted_after_the_delay(self):
def test_a_gsocket_failure_is_filed_against_gsocket_not_https(self):
    # _https_post hardcodes "https" in three _record_leg calls today
def test_a_full_cycle_over_gsocket_against_the_real_server_crypto(self):
    # register, task, result -- the real Beacon against the real
    # ServerCrypto through a local forward, no mocks of either
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest software.tests.test_gsocket_leg -v`
Expected: FAIL.

- [ ] **Step 3: Implement the leg**

Read the config in `__init__` the way `smb_cfg` and `quic_cfg` are read, with the defaults from the spec's config block.

Reuse the existing HTTP path rather than writing a second client. Both helpers take an optional base so the leg can aim at the forward:

```python
def _evasive_url(self, endpoint: str, base: Optional[str] = None) -> str:
def _https_post(self, endpoint: str, data: dict,
                base: Optional[str] = None,
                transport: str = "https") -> Optional[dict]:
```

`base` defaults to `self.callback_url.rsplit("/", 1)[0]`, which is what line 5092 does today, so every existing caller behaves identically. The leg passes `f"{self.gsocket_scheme}://127.0.0.1:{self.gsocket_local_port}/api/v1"`. The `transport` argument is what makes `_record_leg` name the right leg: that method currently hardcodes `"https"` in three places, and without it a gsocket failure would be filed against HTTPS.

The malleable C2 profile therefore applies inside the pipe too, unchanged — which is correct: the far end is the same beacon socket.

Record classes on every failure path beside the debug log, as `_https_post` does: `binary_missing` when `verify_binary` gives a reason, `carrier_failed` when the child is up but the port does not accept, and `_rescue_class_of(e)` otherwise.

The latch: start the carrier where `_beacon_loop` already decides `delivered_by not in _RESCUE_UPSTREAM`, and never stop it.

- [ ] **Step 4: Add the leg to both chains**

After `quic` in the tasking chain (`:8420-8430`) and after `quic` in the result chain (`:8362-8366`), promoting `_registered` on a successful cycle the way SMB and QUIC do.

- [ ] **Step 5: Run the tests, then the suite**

Run: `python3 -m unittest software.tests.test_gsocket_leg -v`
Then: `python3 -m unittest discover -s software/tests -t .`
Expected: PASS both. `beacon_config_from_fallback` needs no change — it loops over `_FALLBACK_TRANSPORTS`.

- [ ] **Step 6: Commit**

```bash
git add software/c2/beacon.py software/tests/test_gsocket_leg.py
git commit -m "feat(beacon): a fifth leg over gsocket, lazy with a warm latch"
```

---

### Task 7: Registration over the first upstream leg

**Files:**
- Modify: `software/c2/beacon.py:8369-8385` (the registration preamble) and `_register_https:5450`
- Test: `software/tests/test_gsocket_leg.py`

**Interfaces:**
- Consumes: Task 6's leg.
- Produces: `Beacon._register_upstream() -> bool`, which tries each enabled upstream leg in chain order.

- [ ] **Step 1: Write the failing test**

```python
def test_a_gsocket_only_beacon_registers(self):
    # https, dns, smb and quic all disabled: the case the whole feature
    # exists for. The agent must appear in the fleet.
def test_the_preamble_is_skipped_when_no_upstream_leg_is_enabled(self):
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m unittest software.tests.test_gsocket_leg -v -k register`
Expected: FAIL — the preamble is gated on `self.https_enabled`, so nothing registers.

- [ ] **Step 3: Generalise the preamble**

Replace the `if self.https_enabled:` gate with `_register_upstream`, which walks the enabled upstream legs in chain order and returns on the first success. Keep the ten-attempt ceiling, the backoff and the "proceeding unregistered" warning exactly as they are.

- [ ] **Step 4: Run the tests, then the suite**

Run: `python3 -m unittest discover -s software/tests -t .`
Expected: PASS. `test_beacon.py` covers the HTTPS registration path and must stay green.

- [ ] **Step 5: Commit**

```bash
git add software/c2/beacon.py software/tests/test_gsocket_leg.py
git commit -m "fix(beacon): register over the first upstream leg, not only HTTPS"
```

---

### Task 8: The generator refuses a leg it cannot deliver

**Files:**
- Modify: `software/c2/server.py:444-480` (`_beacon_gen_config`)
- Test: `software/tests/test_c2_server.py`

**Interfaces:**
- Consumes: nothing.
- Produces: a `ValueError` from `_beacon_gen_config` when `protocols` enables `gsocket`, which the route already turns into a 400.

- [ ] **Step 1: Write the failing test**

```python
def test_beacon_gen_refuses_an_enabled_gsocket_leg(self):
    # A generated build is a single file with no binary beside it, so the
    # leg could never work. Refused at generation, naming the reason,
    # rather than emitting a build with a dead fifth leg.
    # POST /api/server/beacon-gen with protocols={"gsocket":{"enabled":True}}
    # -> 400, and the body mentions the hardware implant

def test_beacon_gen_ignores_a_disabled_gsocket_leg(self):
    # enabled: false is what every config carries; it is not an error
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m unittest software.tests.test_c2_server -v -k gsocket`
Expected: FAIL — the key is ignored and a build is returned.

- [ ] **Step 3: Implement the refusal**

In `_beacon_gen_config`, raise `ValueError` when `protocols.get("gsocket", {}).get("enabled")` is true, with a message that says the leg needs a `gs-netcat` binary on disk and is available on the hardware implant only.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest software.tests.test_c2_server -v -k gsocket`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/c2/server.py software/tests/test_c2_server.py
git commit -m "feat(beacon-gen): refuse a gsocket leg a generated build cannot run"
```

---

### Task 9: Provisioning, the unit, the shipped config and the documentation

**Files:**
- Modify: `software/setup/build_image.sh:370-390`
- Create: `services/raccoon-gsocket.service`
- Modify: `services/install.sh`, `services/uninstall.sh`
- Modify: `configs/raccoon.yaml` (`c2.fallback.gsocket` after `quic:98-124`, `c2.gsocket_carrier` after `c2.listeners:150-176`)
- Modify: `docs/LISTENERS.md`, `docs/AGENT.md` (*Known limits*), `README.md` (the transport badge and the C2 Transport row)
- Test: `software/tests/test_docs.py`

**Interfaces:**
- Consumes: everything above.
- Produces: no code interface.

- [ ] **Step 1: Write the failing documentation tests**

```python
def test_the_gsrn_section_states_the_third_party_cost(self):
    # docs/LISTENERS.md must say both things before it says a flag:
    # the client's traffic crosses a third party, and this hides where
    # our C2 is, not that gsocket is in use
def test_known_limits_records_the_four_gsocket_limits(self):
    # generated builds have four legs; the carrier is a second process;
    # reachability depends on a third-party relay; the implant opens a
    # loopback forward
def test_the_shipped_gsocket_blocks_are_disabled(self):
    # configs/raccoon.yaml: enabled false on the leg, no carrier configured
def test_the_shipped_config_validates(self):
    # load_carriers and validate_leg accept what the file ships
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest software.tests.test_docs -v -k gsocket`
Expected: FAIL.

- [ ] **Step 3: Add the config blocks**

Both blocks, with the comments the spec specifies — including the warning above the leg to read the GSRN section before enabling it on an engagement, and the sentence that says which side each block is, as the four neighbouring blocks do.

- [ ] **Step 4: Provision the binary**

In `build_image.sh`, fetch the pinned static `aarch64` release into `/opt/raccoon/bin/gs-netcat` at image build time with a recorded SHA-256, never at runtime on the target. Pin the version in one shell variable beside `PARROT_VERSION`.

- [ ] **Step 5: Write the unit and wire install/uninstall**

`services/raccoon-gsocket.service` runs the carrier for a host that wants it without the panel. It needs no socket activation and no privileged port — unlike the three listener units — so it has no `.socket` sibling. Read the secret path from `/etc/raccoon/gsocket.env`, which must not be world-readable.

- [ ] **Step 6: Write the documentation**

The GSRN section in `docs/LISTENERS.md`, placed so it is read before the flags: the two costs from the spec's constraint 1, the per-implant secret and why it is not fleet-wide, `gs-netcat -g` for generating one, and the warm-up cycle an operator will otherwise read as a fault. Add the four entries to *Known limits* in `docs/AGENT.md`, in the severity group they belong to. Update the transport badge and the **C2 Transport** row in `README.md` to say five channels, naming gsocket as hardware-implant only.

- [ ] **Step 7: Run the whole suite**

Run: `python3 -m unittest discover -s software/tests -t .`
Expected: PASS. `test_docs.py` holds the *Known limits* list and its severity groups, so a mis-filed entry fails here.

- [ ] **Step 8: Commit**

```bash
git add software/setup/build_image.sh services/ configs/raccoon.yaml docs/ README.md software/tests/test_docs.py
git commit -m "docs(gsocket): the GSRN cost, the shipped blocks, the unit and the limits"
```

---

## Manual verification, once the suite is green

Nothing above touches the real GSRN. Before this is believed on an engagement, run the real thing once:

1. Team server: configure one carrier, start it from the panel, confirm the row shows *no socket* and a pid.
2. Implant: enable the leg, disable `https`, `dns`, `smb` and `quic`, and watch it register, take a task and report a result.
3. Kill the carrier child on the implant and confirm it comes back after `restart_delay_seconds`.
4. Stop the server-side carrier and confirm the leg reports `carrier_failed` rather than hanging the cycle.

Extend `tools/listener_rig.py`, or add a sibling rig, for steps 2 to 4 — and keep it out of CI, which must never need a relay operated by somebody else.
