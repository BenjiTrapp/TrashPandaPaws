# C2 Listeners Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the beacon's SMB and QUIC transports working server counterparts and DNS a tasking side channel, managed as configurable listeners from a 📡 panel in the operator interface, without adding a listening socket or a protocol parser to the team-server process.

**Architecture:** Each transport gets a small stdlib service that terminates its protocol and carries the opaque ciphertext to the team server's existing agent socket as an HTTP POST, then carries the answer back. No listener holds the encryption key: `ServerCrypto.unwrap` scans every field and then any string over 32 characters, so a listener can POST `{"d": "<ciphertext>"}` and the server finds it. Privileged ports are bound by `dockerd` (port mapping from a bridge network) or by `systemd` (socket activation), never by the listener process. The team server supervises listeners it started and reaches them over a loopback control socket.

**Tech Stack:** Python 3.9, stdlib only. No new dependency in `software/requirements.txt` or `software/agent/requirements.txt`.

**Spec:** `docs/superpowers/specs/2026-11-07-c2-listeners-design.md`

## Global Constraints

- **No new dependency.** Neither requirements file may grow. The beacon and every listener are stdlib-only.
- **Python 3.9.** No `match`, no `X | Y` type unions, no `str.removeprefix`.
- **The team-server process keeps exactly two listening sockets** and gains no protocol parser. The socket policy in `create_app` stays as it is: a request arriving on the agent socket cannot reach the operator interface.
- **No listener is given the encryption key**, in any deployment, by any path.
- **No control that silently does nothing.** Where an action is impossible, the control is visibly disabled and the reason is shown.
- **No setup step whose omission looks like a beacon failure.** Privilege is held by `dockerd` or `systemd`; no `iptables` rule, no `setcap`, no `cap_add`.
- **The beacon's bytes on the wire do not change** for a correctly formed payload. The beacon is the specification; counterparts conform to it.
- Baseline before the first commit: **2223 tests green**, whole-suite command
  `python3 -m unittest discover -s software/tests -t . -p "test_*.py"` (~230 s). `Port NNNNN is in use` appears 6 times and is pre-existing noise.
- **Never hardcode a port in a test.** Bind `('127.0.0.1', 0)` and read it back. On this machine `tls-viewer` holds 8443 and `rdpview` holds 8099; a hardcoded port once made a measurement return the opposite of the truth.
- Commit style `feat(scope): subject` for new capability, `fix(scope):` for a correction, blank line, prose explaining why.
- No `@deutschebahn.com` anywhere, including commit metadata.
- `software/tests/test_docs.py` holds `docs/AGENT.md`'s *Known limits* with one probe per finding. **Fixing a recorded finding fails that test until its entry is deleted** — that is deliberate, and Tasks 1 and 11 must handle it rather than work around it.

## Review Focus

Input classes the plan implies but no task's happy path exercises. Each has its test added to the owning task.

- **A listener receives traffic that is not a beacon.** A port scanner, `smbclient`, `dig`, a stray UDP datagram. Expect: no crash, no unbounded allocation, nothing forwarded to the team server, and no distinguishable error that fingerprints the service. → Tasks 3, 5, 6.
- **A QUIC reassembly that never completes.** A fragment arrives claiming `total=9` and the rest never comes. Expect bounded memory and expiry, not a leak that grows with every scan. → Task 3.
- **The team server is down, slow, or returns a non-200 while a listener relays.** Expect the beacon to see a failed exchange and back off on its own schedule, not a hang that holds the transport open. → Task 2.
- **Two beacons through one listener at the same time.** QUIC's `stream_id` and SMB's single accepted socket are both places where answers could cross. Expect each beacon to get its own answer. → Tasks 3, 5.
- **A listener started twice, or stopped mid-exchange.** Expect the second start to be refused with a reason rather than binding a second socket, and a stop to close cleanly without leaving a child behind. → Task 8.

---

## File Structure

| File | Responsibility |
|---|---|
| `software/c2/beacon.py` | `_encrypt` rejects a non-dict; three call sites pass dicts (T1) |
| `software/c2/listeners/__init__.py` | package marker (T2) |
| `software/c2/listeners/relay.py` | opaque payload → agent socket → opaque answer (T2) |
| `software/c2/listeners/quic.py` | UDP listener, the beacon's framing (T3) |
| `software/c2/listeners/smb.py` | SMB2 subset: handshake (T4), pipe exchange (T5) |
| `software/c2/listeners/dns.py` | authoritative TXT for one zone, tasking only (T6) |
| `software/c2/listeners/registry.py` | config parsing, listener descriptors, state (T7) |
| `software/c2/listeners/supervisor.py` | spawn, stop, control socket client (T8) |
| `software/c2/listeners/__main__.py` | one listener as a process; socket activation (T8, T10) |
| `software/c2/server.py` | `/api/server/listeners`, the 📡 panel (T9) |
| `configs/raccoon.yaml` | `c2.listeners` block; `smb`/`quic` under `c2.fallback` (T7) |
| `software/c2/docker-compose.yml` | three listener services on a bridge network (T10) |
| `services/raccoon-listener-*.{service,socket}` | systemd socket activation (T10) |
| `tools/listener_rig.py` | one transport end-to-end against a real beacon (T3, reused T5/T6) |
| `software/tests/test_listeners.py` | new; one class per transport plus the relay |
| `docs/LISTENERS.md` | operator guide (T11) |
| `docs/AGENT.md`, `README.md` | reconcile Known limits and the channel claims (T1, T11) |

Tasks 1 and 2 come first because every transport test needs a working client contract and a relay. Task 3 (QUIC, the simplest protocol) proves the whole shape before SMB's bulk.

---

### Task 1: The `_encrypt` contract, and its three callers

**Files:**
- Modify: `software/c2/beacon.py` — `_encrypt`, `_beacon_smb`, `_send_result_smb`, `_quic_send`
- Modify: `docs/AGENT.md` — delete the *Found while hardening* entry for the double serialisation
- Modify: `software/tests/test_docs.py` — remove `_smb_and_quic_double_serialise` and its row
- Test: `software/tests/test_listeners.py` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `_encrypt(data: dict) -> str` now raises `TypeError` for a non-dict. Tasks 3, 5 and 6 rely on the three call sites producing a payload the server can decrypt.

- [ ] **Step 1: Write the failing tests**

Class `TestTheEncryptContract`:

```python
def test_encrypt_refuses_a_str(self):
    # It currently accepts one and double-encodes silently.
def test_encrypt_refuses_bytes(self):
    # It currently raises TypeError from json.dumps -- assert the new,
    # explicit error names the parameter, not the value.
def test_encrypt_accepts_a_dict(self):
def test_the_refusal_never_contains_the_value(self):
def test_smb_checkin_payload_round_trips_through_server_crypto(self):
    # Build the payload _beacon_smb sends, hand it to ServerCrypto.unwrap
    # with the same key, and assert the dict comes back with
    # action == "register" and the agent id.
def test_smb_result_payload_round_trips(self):
def test_quic_payload_round_trips(self):
```

The three round-trip tests are the ones that matter: they prove the fix against the real `ServerCrypto`, not against a mock.

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest software.tests.test_listeners.TestTheEncryptContract -v`
Expected: the round-trip tests FAIL with `TypeError: Object of type bytes is not JSON serializable`; `test_encrypt_refuses_a_str` FAILS because no error is raised.

- [ ] **Step 3: Add the type guard and fix the three call sites**

`_encrypt` raises `TypeError` naming the parameter and the type received, never the value. The three call sites pass the dict. Decide per transport whether `_wrap_payload`'s decoy envelope belongs there — HTTP uses it to disguise a body; a named pipe and a UDP frame have no body to disguise — and record the choice in a comment at each site.

- [ ] **Step 4: Delete the Known-limits entry the fix closes**

`docs/AGENT.md`'s *Found while hardening* section records the double serialisation. Its probe in `test_docs.py` will now return `False` and the drift test will fail until the entry is removed. Delete both. The *correction to the audit's severity* entry beside it stays — it records a different thing.

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m unittest discover -s software/tests -t . -p "test_*.py"`
Expected: green. The count drops by nothing and rises by the new tests.

- [ ] **Step 6: Commit**

---

### Task 2: The relay — opaque payload to the agent socket and back

**Files:**
- Create: `software/c2/listeners/__init__.py`, `software/c2/listeners/relay.py`
- Test: `software/tests/test_listeners.py`

**Interfaces:**
- Consumes: nothing.
- Produces, and Tasks 3–6 all call this: `relay(payload: str, *, url: str, timeout: float = 30.0) -> Optional[str]` — POSTs `{"d": payload}` to `url`, returns the ciphertext string from the answer, or `None` on any failure. A `RelayError` is not raised; failure is `None`, because every caller's correct response is "tell the beacon this exchange failed".

- [ ] **Step 1: Write the failing tests**

Class `TestTheRelay`, against a real `make_server` on an ephemeral port, not a mock:

```python
def test_a_payload_reaches_the_server_and_the_answer_comes_back(self):
def test_the_relay_never_sees_the_key(self):
    # Assert the module imports nothing from the crypto modules and that
    # relay's signature takes no key. Source-level plus signature check.
def test_a_server_that_is_down_gives_None(self):
def test_a_server_that_hangs_gives_None_within_the_timeout(self):
    # Review Focus: a hang must not hold the transport open.
def test_a_non_200_gives_None(self):
def test_a_200_with_no_usable_field_gives_None(self):
def test_the_payload_field_name_is_one_the_server_scans_for(self):
    # Against ServerCrypto.unwrap, so a rename on either side is caught.
```

- [ ] **Step 2: Run them to verify they fail**

Expected: FAIL, module not found.

- [ ] **Step 3: Implement `relay`**

`urllib.request` with an explicit timeout. No retry: the beacon has its own schedule and a retry here would double it.

- [ ] **Step 4: Run the focused tests, then the whole suite**

- [ ] **Step 5: Commit**

---

### Task 3: The QUIC listener

The simplest of the three protocols, and it proves the whole shape — a listener, a relay, a real beacon, a full cycle.

**Files:**
- Create: `software/c2/listeners/quic.py`, `tools/listener_rig.py`
- Test: `software/tests/test_listeners.py`

**Interfaces:**
- Consumes: `relay` from Task 2.
- Produces: `QuicListener(bind_host, bind_port, *, relay_url, frag_size=1200)` with `serve_forever()` and `shutdown()`. `tools/listener_rig.py` exposes `run_cycle(transport: str) -> dict` returning what the cycle observed; Tasks 5 and 6 reuse it.

- [ ] **Step 1: Write the failing tests**

Class `TestTheQuicListener`:

```python
def test_a_real_beacon_completes_a_full_cycle_over_quic_alone(self):
    # The deliverable. Stand up a server, the listener, and a real Beacon
    # with only quic enabled. Assert: the agent appears in the fleet, a
    # queued task reaches it, and the result comes back.
def test_a_payload_larger_than_one_fragment_reassembles(self):
def test_an_incomplete_reassembly_is_dropped_and_bounded(self):
    # Review Focus: send frag 0 of 9 and nothing else, many times; assert
    # the buffer does not grow without limit and expires.
def test_two_beacons_at_once_each_get_their_own_answer(self):
    # Review Focus: distinct stream_ids must not cross.
def test_a_stray_datagram_is_ignored(self):
    # Review Focus: random bytes, a truncated header, a zero-length frame.
    # Assert nothing reaches the relay and the listener stays up.
def test_nothing_reaches_the_server_for_traffic_that_is_not_a_beacon(self):
```

- [ ] **Step 2: Run them to verify they fail**

- [ ] **Step 3: Implement the listener**

The framing is `beacon.py:2084-2152`: a frame is `[4-byte big-endian length][payload]`, fragmented into `frag_size` datagrams each prefixed `[len][stream_id][frag_idx][total]`. Reassemble by `stream_id`; reply with the same framing to the address the first fragment came from. Expire partial reassemblies — the exact policy is yours, but it must be bounded and must have a test.

- [ ] **Step 4: Run the focused tests, then the whole suite**

- [ ] **Step 5: Commit**

---

### Task 4: The SMB listener, part 1 — handshake to pipe open

Split from Task 5 because `_smb_connect` returning a socket is an independently testable deliverable, and because a reviewer could reasonably accept the handshake and reject the exchange.

**Files:**
- Create: `software/c2/listeners/smb.py`
- Test: `software/tests/test_listeners.py`

**Interfaces:**
- Consumes: nothing (the relay arrives in Task 5).
- Produces: `SmbListener(bind_host, bind_port, *, relay_url, pipe_name="msrpc_6e2f")` with `serve_forever()` and `shutdown()`. Task 5 fills in the exchange.

- [ ] **Step 1: Write the failing test**

```python
def test_a_real_beacon_opens_the_pipe(self):
    # Beacon._smb_connect returns a socket rather than None.
def test_a_wrong_pipe_name_is_refused(self):
def test_the_handshake_needs_no_credential(self):
    # beacon.py:1913-1916 sends NTLMSSP Negotiate (Type 1), anonymous.
    # Assert the listener holds no credential material at all.
```

- [ ] **Step 2: Run it to verify it fails**

- [ ] **Step 3: Implement the handshake**

The beacon's request builders are the specification: `_smb_netbios_wrap`, Negotiate, `_smb2_session_setup` (anonymous NTLMSSP Type 1), Tree Connect to `IPC$`, `_smb2_create_pipe`. Answer enough of SMB2 for that sequence. This is not a file server and must not become one.

- [ ] **Step 4: Run the focused tests, then the whole suite**

- [ ] **Step 5: Commit**

---

### Task 5: The SMB listener, part 2 — exchange and full cycle

**Files:**
- Modify: `software/c2/listeners/smb.py`
- Test: `software/tests/test_listeners.py`

**Interfaces:**
- Consumes: `relay` (Task 2), the handshake (Task 4), `run_cycle` (Task 3).
- Produces: nothing new.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_real_beacon_completes_a_full_cycle_over_smb_alone(self):
    # Including registration: _beacon_smb sends action "register" first.
def test_a_result_sent_over_smb_reaches_the_server(self):
def test_two_beacons_at_once_each_get_their_own_answer(self):
    # Review Focus.
def test_a_plain_smb_client_gets_nothing_useful(self):
    # Review Focus: an SMB2 client that negotiates and then asks for a
    # share, or opens a different pipe, must get a clean refusal and must
    # not reach the relay.
def test_a_truncated_write_does_not_wedge_the_listener(self):
```

- [ ] **Step 2: Run them to verify they fail**

- [ ] **Step 3: Implement the exchange**

Write and Read on the pipe (`_smb_write_pipe`, `_smb_read_pipe`), each write relayed and each answer returned on the following read.

- [ ] **Step 4: Run the focused tests, then the whole suite**

- [ ] **Step 5: Commit**

---

### Task 6: The DNS listener — tasking only

**Files:**
- Create: `software/c2/listeners/dns.py`
- Test: `software/tests/test_listeners.py`

**Interfaces:**
- Consumes: `relay` (Task 2), `run_cycle` (Task 3).
- Produces: `DnsListener(bind_host, bind_port, *, relay_url, zone)` with `serve_forever()` and `shutdown()`.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_registered_beacon_receives_tasking_over_dns(self):
    # The deliverable. Register over HTTPS, queue a task, then let a
    # DNS-only check-in collect it.
def test_an_unregistered_id_gets_an_empty_answer(self):
    # The design's hard limit: no registration goes over DNS.
def test_the_query_name_is_decoded_the_way_the_beacon_encodes_it(self):
    # base32, lowercased, padding stripped, under "<id>.b.<zone>".
def test_a_query_outside_the_zone_is_refused(self):
def test_a_malformed_query_does_not_crash_the_listener(self):
    # Review Focus: a truncated packet, a query with no question, a
    # compression pointer loop.
def test_no_result_path_is_offered(self):
    # Assert the listener exposes nothing that would accept a result, so
    # the documented limit cannot drift into a half-built upstream.
```

- [ ] **Step 2: Run them to verify they fail**

- [ ] **Step 3: Implement the listener**

Answer TXT for `<base32-id>.b.<zone>` with the wrapped ciphertext from the relay. Everything else gets an empty answer. The beacon's side is `beacon.py:1789-1807`.

- [ ] **Step 4: Run the focused tests, then the whole suite**

- [ ] **Step 5: Commit**

---

### Task 7: Configuration and the registry

**Files:**
- Create: `software/c2/listeners/registry.py`
- Modify: `configs/raccoon.yaml`
- Test: `software/tests/test_listeners.py`

**Interfaces:**
- Consumes: the three listener classes.
- Produces: `load_listeners(config: dict) -> List[ListenerSpec]` and a `ListenerSpec` carrying `name`, `transport`, `bind_host`, `bind_port`, `enabled`, `relay_url` and the transport's own settings. Tasks 8 and 9 both read `ListenerSpec`.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_shipped_config_defines_all_three_disabled(self):
def test_an_unknown_transport_is_refused_by_name(self):
def test_a_missing_relay_url_is_refused(self):
def test_two_listeners_on_one_port_are_refused(self):
def test_the_shipped_fallback_block_now_documents_smb_and_quic(self):
    # The beacon reads c2.fallback.smb and .quic today; the file never
    # mentioned them.
def test_the_server_side_and_beacon_side_blocks_are_not_confusable(self):
    # c2.listeners is the server; c2.fallback.* is the beacon. A comment
    # must say so, and this test holds it.
```

- [ ] **Step 2: Run them to verify they fail**

- [ ] **Step 3: Add the block and the registry**

- [ ] **Step 4: Run the whole suite**

- [ ] **Step 5: Commit**

---

### Task 8: Supervision and the control socket

This task adds a new control surface. It is the one a reviewer should push hardest on.

**Files:**
- Create: `software/c2/listeners/supervisor.py`, `software/c2/listeners/__main__.py`
- Test: `software/tests/test_listeners.py`

**Interfaces:**
- Consumes: `ListenerSpec` (Task 7).
- Produces: `Supervisor(specs, *, managed: bool)` with `start(name)`, `stop(name)`, `status()`. Task 9's panel calls exactly these three.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_listener_starts_and_reports_running(self):
def test_starting_a_running_listener_is_refused_with_a_reason(self):
    # Review Focus: not a second socket, and not a silent no-op.
def test_stop_leaves_no_child_behind(self):
    # Review Focus: assert the pid is gone, not just that stop returned.
def test_stop_during_an_exchange_closes_cleanly(self):
def test_status_of_a_listener_that_died_says_so(self):
def test_the_control_socket_binds_loopback_only(self):
def test_the_control_socket_requires_the_operator_token(self):
def test_the_control_socket_accepts_nothing_but_start_stop_status(self):
    # No path, no command, no key. Try each and assert refusal.
def test_managed_false_reports_unmanaged_rather_than_failing(self):
    # The Docker case: status works, start and stop say why not.
```

- [ ] **Step 2: Run them to verify they fail**

- [ ] **Step 3: Implement supervision**

`managed=True` spawns listeners as child processes. `managed=False` reports status only. `__main__.py` runs one listener as a process and takes a socket-activated descriptor when `$LISTEN_FDS` is set — `socket.socket(fileno=3)`, stdlib.

- [ ] **Step 4: Run the whole suite**

- [ ] **Step 5: Commit**

---

### Task 9: The 📡 panel

**Files:**
- Modify: `software/c2/server.py` — `/api/server/listeners`, the header button, the panel
- Test: `software/tests/test_listeners.py`, `software/tests/test_c2_hardening.py`

**Interfaces:**
- Consumes: `Supervisor.status()`, `.start()`, `.stop()`.
- Produces: nothing other tasks read.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_listeners_route_requires_the_operator_token(self):
def test_the_listeners_route_is_refused_on_the_agent_socket(self):
    # The two-socket property must cover the new route. This is the one
    # that matters: a new route is exactly how that property erodes.
def test_the_header_has_the_listeners_button_between_generator_and_loot(self):
def test_the_panel_states_the_dns_limit(self):
    # Tasking only, and only for an already-registered agent.
def test_the_controls_are_disabled_with_a_reason_when_unmanaged(self):
def test_no_response_carries_the_encryption_key(self):
```

- [ ] **Step 2: Run them to verify they fail**

- [ ] **Step 3: Implement the route and the panel**

The button is `&#128225;` between `showBeaconGen()` and `showLootViewer()`. Every value an agent influenced goes through `esc()`; the escaping helper escapes `'` as of the hardening pass, but an `on*` handler body still needs the handler attached in JavaScript rather than built as a string.

- [ ] **Step 4: Run the whole suite**

- [ ] **Step 5: Commit**

---

### Task 10: Deployment and the Docker rig

**Files:**
- Modify: `software/c2/docker-compose.yml`
- Create: `services/raccoon-listener-smb.{service,socket}`, `…-dns.{service,socket}`, `…-quic.{service,socket}`
- Modify: `software/tests/test_c2_hardening.py` (the installer and unit-file guards already there)
- Test: `software/tests/test_listeners.py`

**Interfaces:**
- Consumes: `__main__.py` (Task 8).
- Produces: nothing in code.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_listener_services_are_not_on_the_host_network(self):
    # Port mapping does not work under network_mode: host, and that is
    # why these get a bridge network.
def test_the_privileged_ports_are_published_not_bound(self):
    # "445:8445" and "53:8053/udp": dockerd holds the privilege.
def test_no_listener_service_adds_a_capability(self):
def test_no_listener_service_runs_as_root(self):
def test_the_socket_units_declare_the_privileged_port(self):
def test_the_service_units_run_as_an_unprivileged_user(self):
def test_every_unit_running_as_root_still_executes_a_root_owned_tree(self):
    # The installer guard from the hardening pass must keep holding with
    # three new units in the directory.
```

- [ ] **Step 2: Run them to verify they fail**

- [ ] **Step 3: Add the services and units**

Listeners reach the host-networked team server via `extra_hosts: ["host.docker.internal:host-gateway"]`.

- [ ] **Step 4: Bring the stack up and run one cycle per transport**

Not only green tests: start the compose stack, run a real beacon for each transport in turn, and record the cycle. Put the commands and raw output in the report.

- [ ] **Step 5: Run the whole suite**

- [ ] **Step 6: Commit**

---

### Task 11: Documentation reconciliation

**Files:**
- Create: `docs/LISTENERS.md`
- Modify: `README.md`, `docs/AGENT.md`, `software/tests/test_docs.py`
- Test: `software/tests/test_docs.py`

**Interfaces:**
- Consumes: the flag and config names every earlier task settled.
- Produces: nothing in code.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_listeners_guide_exists_and_the_readme_links_it(self):
def test_the_guide_names_the_real_config_keys(self):
    # Read them from the registry, not written as literals -- the drift
    # this project actually suffered was a renamed flag in a document.
def test_the_readme_no_longer_says_only_https_has_a_counterpart(self):
def test_the_dns_side_channel_statement_survives(self):
    # DNS stays a dependent channel after this work. The claim must not be
    # quietly upgraded to "four independent channels" again.
def test_known_limits_no_longer_records_what_this_work_fixed(self):
```

- [ ] **Step 2: Run them to verify they fail**

- [ ] **Step 3: Write the guide and reconcile the claims**

`README.md`'s transport section says only HTTPS has a counterpart — that becomes false here and must be rewritten. The DNS side-channel statement stays true and stays. `docs/AGENT.md`'s *Known limits* loses what this work closed and keeps what it did not: the QUIC client still accepts fragments without checking the source address or `stream_id`, which this work must record rather than fix, because the listener cannot compensate for a client that trusts any sender.

- [ ] **Step 4: Run the whole suite**

- [ ] **Step 5: Commit**

---

## Self-Review

**Spec coverage.** Goals 1 and 2 (full cycle over SMB and QUIC alone) are Tasks 3 and 5. Goal 3 (DNS as a tasking side channel) is Task 6. Goal 4 (first-class configurable listeners) is Tasks 7 and 8. Goal 5 (the 📡 entry) is Task 9. Goal 6 (works out of the box, no privilege granted) is Task 10, and is tested rather than asserted. Goal 7 (a local rig) starts in Task 3 and is exercised per transport in Task 10. Every non-goal has a test that holds it: no DNS result path (T6), the two-socket property (T9), no new dependency (every task's whole-suite run), no capability (T10).

**Type consistency.** `relay(payload, *, url, timeout)` is introduced in T2 and called in T3, T5, T6. `ListenerSpec` is introduced in T7 and read in T8 and T9. `Supervisor.start/stop/status` is introduced in T8 and is the only thing T9 calls. The three listener classes take `(bind_host, bind_port, *, relay_url, …)` uniformly, so the registry can construct them without a special case.

**Review Focus.** All five lines have an owning task and a named test. The two that worry me most are the incomplete QUIC reassembly (an unbounded buffer reachable by a port scanner) and the new control socket in T8, which is the only place this work adds a way to make the team server do something.

**Proportion.** Eleven tasks for three protocol implementations, a registry, a supervisor, a panel, deployment in two modes and the documentation. The SMB split is the one judgement call; it is split because the handshake alone is a real deliverable and because SMB is otherwise much larger than any other task.

**Risk I want a reviewer to look at.** Task 1 changes a function every transport uses, including the one that works today. If `_encrypt`'s new guard is wrong, HTTPS breaks — the one channel that has always worked. Its round-trip tests go through the real `ServerCrypto` for exactly that reason, and the whole suite is the gate on that task rather than a focused run.

**A process note, not a plan item.** This repository's provider has refused eleven subagent dispatches across two days, including a 5 KB diff review and the builder check on this plan's own design document. The per-task implementer and reviewer seats this plan assumes may not be available. Where a seat cannot be filled, the controller should say so at that task rather than quietly absorbing the work — and the full-cycle tests against a real beacon are the compensating control, because they do not depend on a model's judgement.
