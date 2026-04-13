# Epic: Sharp Edges — Harden Zoomies for Production Use

**Status**: Draft
**Created**: 2026-04-13
**Target**: v0.4.0
**Estimated Effort**: 40–60h
**Dependencies**: None (all changes are internal)
**Source**: Sharp edges audit of v0.3.2 (21 findings across protocol machinery, validation, and silent failures)

---

## Why This Matters

Zoomies has a clean API surface and solid test coverage (461 tests), but the implementation has gaps that will silently break against real-world QUIC peers. A user following the docs and examples will encounter: unrecoverable handshake stalls on packet loss, crashes when browsers send Huffman-encoded headers, unbounded memory growth under congestion, and no flow control by default.

**Consequences:**
1. Any packet loss during TLS handshake permanently stalls the connection (CRYPTO retransmit queue never drained)
2. Long-lived connections die silently after the first key update (key rotation implemented but never wired in)
3. HTTP/3 connections crash on first request from browsers (Huffman encoding unsupported, raises ValueError)
4. `max_data=0` disables flow control — a misbehaving peer can OOM the server
5. Server misconfiguration (empty cert/key) produces a confusing error on first datagram instead of at construction
6. Unknown QUIC extension frames break the entire parse loop, dropping subsequent frames

### Evidence Table

| # | Finding | Proposal Impact |
|---|---------|-----------------|
| 1 | `_crypto_retransmit` populated but never drained | FIXES (Sprint 1) |
| 2 | `update_keys()` exists but never called; key_phase never checked | FIXES (Sprint 1) |
| 3 | Huffman strings raise `ValueError` uncaught | FIXES (Sprint 2) |
| 4 | `max_data=0` means unlimited, not zero | FIXES (Sprint 3) |
| 5 | Peer address updated before packet authentication | FIXES (Sprint 1) |
| 6 | Server with empty cert/key — error deferred to first datagram | FIXES (Sprint 3) |
| 7 | `NewSessionTicket` event never emitted | FIXES (Sprint 2) |
| 8 | 0-RTT requires undocumented 6-step manual process | MITIGATES (Sprint 4) |
| 9 | Session tickets are in-memory random nonces | MITIGATES (Sprint 4) |
| 10 | Unknown frames break parse loop | FIXES (Sprint 1) |
| 11 | `_stream_send_queue` unbounded | FIXES (Sprint 1) |
| 12 | `except ValueError, BufferReadError:` deprecated syntax | FIXES (Sprint 3) |
| 13 | `PacketNumberSpace` defined in two modules | FIXES (Sprint 3) |
| 14 | H3 encoder stream data sent on wrong stream ID | FIXES (Sprint 2) |
| 15 | `handle_event()` and `stream_data_received()` both public | FIXES (Sprint 3) |
| 16 | `settings_data()` silently returns None on second call | FIXES (Sprint 3) |
| 17 | `verify_mode=True` with no `ca_certs` — error at handshake | FIXES (Sprint 3) |
| 18 | QPACK static table 58/99 entries | FIXES (Sprint 2) |
| 19 | `DynamicTable.lookup()` is O(n) | FIXES (Sprint 2) |
| 20 | `idle_timeout` inoperative without `handle_timer()` | MITIGATES (Sprint 4) |
| 21 | Broad `except Exception` in cert verification | FIXES (Sprint 3) |

### Invariants

These must remain true throughout or we stop and reassess:

1. **All 461 existing tests pass**: No sprint may break existing behavior. Every PR must pass `pytest tests/`.
2. **Sans-I/O contract preserved**: No sprint introduces I/O, threading, or implicit timers. The caller still owns all I/O.
3. **Public API stable**: Existing `QuicConnection` and `H3Connection` method signatures do not change. New parameters are keyword-only with backward-compatible defaults. Deprecations use warnings, not removals.

---

## Target Architecture

After this epic, Zoomies should be able to:
- Complete a TLS handshake under 5% packet loss without stalling
- Survive key updates from any RFC 9001-compliant peer
- Accept HTTP/3 requests from Chrome/Firefox (Huffman, full static table)
- Enforce flow control by default
- Reject invalid configuration at construction time
- Ignore unknown QUIC frame types per RFC 9000 §19

No new modules are needed. All changes are within existing files.

---

## Sprint Structure

| Sprint | Focus | Effort | Risk | Ships Independently? |
|--------|-------|--------|------|---------------------|
| 0 | Design: retransmit + key update architecture | 4h | Low | Yes (design doc) |
| 1 | Protocol machinery: retransmit, key update, parse loop, address validation | 16h | High | Yes |
| 2 | H3 correctness: Huffman, static table, encoder stream, session tickets | 12h | Medium | Yes |
| 3 | Fail-fast validation + API cleanup | 8h | Low | Yes |
| 4 | Documentation + ergonomics | 4h | Low | Yes |

---

## Sprint 0: Design & Validate

**Goal**: Solve the two hardest problems on paper before writing code — CRYPTO retransmission and key update integration.

### Task 0.1 — Design CRYPTO retransmission drain

The TLS layer owns the CRYPTO data. When a CRYPTO frame is lost, we need to re-queue the original bytes (not `b""`). Two options:

**Option A**: Store CRYPTO data in `_crypto_retransmit` at send time (alongside the TLS layer). Retransmit from this copy.
**Option B**: Have the TLS context expose a `get_crypto_data(offset, length)` method that replays from its buffer.

Decision criteria: Which approach minimizes memory duplication and coupling to the TLS layer?

**Acceptance**: Design decision documented in this file with rationale. At least one option prototyped to verify feasibility.

### Task 0.2 — Design key update receive path

RFC 9001 §6 requires:
- Detect key phase flip on incoming short-header packets
- Try decryption with next-generation keys
- If successful, commit the key update
- Keep old keys briefly for reordered packets

Design the state machine extension to `CryptoPair` and `QuicConnection._handle_short()`.

**Acceptance**: State diagram or pseudocode for key phase detection + key rollover. Edge cases documented (reordered packets, simultaneous key updates).

### Task 0.3 — Assess Huffman implementation scope

QPACK Huffman is specified in RFC 7541 Appendix B. Evaluate:
- Use `hpack` library's Huffman decoder (adds dependency)
- Implement minimal decode-only Huffman table (~1KB static table)
- Port from aioquic's implementation

**Acceptance**: Decision on approach. If implementing, static table verified against RFC 7541 Appendix B.

---

## Sprint 1: Protocol Machinery

**Goal**: Fix the four issues that cause silent connection death — CRYPTO retransmit, key updates, frame parsing, and address validation.

### Task 1.1 — Wire CRYPTO retransmission

Implement the approach chosen in Task 0.1. `_retransmit_lost()` must re-queue CRYPTO frames with actual data. `_build_packet()` (or equivalent send path) must drain `_crypto_retransmit`.

**Files**: `src/zoomies/core/connection.py` (lines 929–932, send path)
**Acceptance**:
- `rg '_crypto_retransmit' src/ | wc -l` shows both append and drain sites
- New test: handshake completes after simulated Initial packet loss
- `pytest tests/` passes

### Task 1.2 — Integrate key update receive path

Wire `CryptoPair.update_keys()` into `_handle_short()`. Check `key_phase` bit on incoming packets. On mismatch, attempt decryption with updated keys. On success, commit the update.

**Files**: `src/zoomies/core/connection.py` (`_handle_short`), `src/zoomies/crypto/quic_crypto.py`
**Acceptance**:
- New test: loopback connection survives a key update initiated by one side
- `rg 'key_phase' src/zoomies/core/connection.py` shows phase-check logic
- `pytest tests/` passes

### Task 1.3 — Fix unknown frame parsing (continue, don't break)

Change the `else: break` in `_parse_payload_frames()` to skip unknown frame types and continue parsing. Per RFC 9000 §19, unknown frames with types that are not flow-controlled should be ignored.

**Files**: `src/zoomies/core/connection.py` (line 881)
**Acceptance**:
- New test: packet with unknown frame type 0xFF followed by a STREAM frame — STREAM frame is delivered
- `pytest tests/` passes

### Task 1.4 — Defer `_peer_addr` update until after authentication

Move the `_peer_addr = addr` assignment from before decryption to after successful packet processing. During handshake, only update `_peer_addr` once the Initial/Handshake packet decrypts successfully.

**Files**: `src/zoomies/core/connection.py` (lines 349–351)
**Acceptance**:
- New test: malformed datagram from spoofed address does not overwrite `_peer_addr`
- `pytest tests/test_adversarial.py` passes

### Task 1.5 — Bound `_stream_send_queue`

Add a configurable `max_send_queue_size` to `QuicConfiguration` (default: 16MB). When the queue exceeds this, `send_stream_data()` raises `BufferError("Send queue full")`.

**Files**: `src/zoomies/core/configuration.py`, `src/zoomies/core/connection.py`
**Acceptance**:
- New test: exceeding queue limit raises `BufferError`
- `pytest tests/` passes

---

## Sprint 2: H3 Correctness

**Goal**: Make HTTP/3 work with real browsers — Huffman decoding, full static table, correct encoder stream, session ticket emission.

### Task 2.1 — Implement Huffman decoding

Implement the approach chosen in Task 0.3. At minimum, decode-only support (we can still encode without Huffman). Replace the `raise ValueError("Huffman-encoded strings not supported")` in `qpack_instructions.py:227`.

**Files**: `src/zoomies/h3/qpack_instructions.py`, possibly new `src/zoomies/h3/huffman.py`
**Acceptance**:
- New test: decode a Huffman-encoded header from RFC 7541 test vectors
- `rg 'Huffman.*not supported' src/` returns zero hits
- `pytest tests/` passes

### Task 2.2 — Complete QPACK static table (99 entries)

Add the remaining 41 entries from RFC 9204 Appendix A.

**Files**: `src/zoomies/h3/qpack.py`
**Acceptance**:
- `python3 -c "from zoomies.h3.qpack import STATIC_TABLE; print(len(STATIC_TABLE))"` prints 99
- `pytest tests/test_qpack*.py` passes

### Task 2.3 — Fix H3 encoder stream ID

`send_headers()` currently sends encoder stream data to `H3_STREAM_TYPE_ENCODER` (0x02) as a stream ID. This should be sent on a properly opened unidirectional encoder stream. Track the actual encoder stream ID in `H3Connection` and open it lazily on first use.

**Files**: `src/zoomies/h3/connection.py` (line 205)
**Acceptance**:
- Encoder instructions sent on a unidirectional stream with type prefix, not on stream ID 0x02
- `pytest tests/test_h3*.py` passes

### Task 2.4 — Emit `NewSessionTicket` event automatically

When the server sends a NewSessionTicket TLS message, `QuicConnection` should emit a `NewSessionTicket` event from `datagram_received()` / `_feed_crypto_to_client_tls()` instead of requiring manual `receive_new_session_ticket()` calls.

**Files**: `src/zoomies/core/connection.py`, `src/zoomies/crypto/tls.py`
**Acceptance**:
- New test: client receives `NewSessionTicket` event after handshake without manual intervention
- `pytest tests/test_psk.py` passes

### Task 2.5 — Add O(1) dynamic table lookup

Add a `dict[tuple[str, str], int]` index to `DynamicTable` alongside the FIFO list. Update on insert/evict.

**Files**: `src/zoomies/h3/dynamic_table.py`
**Acceptance**:
- `pytest tests/test_dynamic_table.py tests/test_qpack_dynamic.py` passes
- Benchmark: lookup of 100 entries in table of 500 completes in <1ms

---

## Sprint 3: Fail-Fast Validation & API Cleanup

**Goal**: Catch configuration errors at construction time, fix deprecated syntax, deduplicate types.

### Task 3.1 — Validate `QuicConfiguration` at construction

Add `__post_init__` to the frozen dataclass:
- Server mode (`is_client=False`): require non-empty `certificate` and `private_key`
- Client mode with `verify_mode=True`: require `ca_certs` is not None
- `max_data` and `max_stream_data`: change default from `0` to a sensible value (e.g., `1_048_576` = 1MB) or at minimum document that `0` means unlimited

**Files**: `src/zoomies/core/configuration.py`
**Acceptance**:
- `QuicConfiguration()` raises `ValueError` mentioning certificate
- `QuicConfiguration(is_client=True)` raises `ValueError` mentioning ca_certs
- All existing tests updated to provide required fields
- `pytest tests/` passes

### Task 3.2 — Fix `except ValueError, BufferReadError:` syntax

Change to `except (ValueError, BufferReadError):` in both locations.

**Files**: `src/zoomies/packet/header.py:75`, `src/zoomies/crypto/tls.py:405`
**Acceptance**:
- `rg 'except \w+, \w+:' src/` returns zero hits
- `pytest tests/` passes

### Task 3.3 — Deduplicate `PacketNumberSpace` enum

Remove the duplicate from `recovery/sent_packet.py`. Have everything import from `primitives/types.py`.

**Files**: `src/zoomies/recovery/sent_packet.py`, `src/zoomies/primitives/types.py`
**Acceptance**:
- `rg 'class PacketNumberSpace' src/` returns exactly 1 hit
- `pytest tests/` passes

### Task 3.4 — Make `settings_data()` raise on duplicate call

Replace `return None` with `raise RuntimeError("settings_data() already called")`.

**Files**: `src/zoomies/h3/connection.py` (line 153)
**Acceptance**:
- New test: second call raises `RuntimeError`
- `pytest tests/` passes

### Task 3.5 — Narrow cert verification exception handler

Replace `except Exception: continue` with `except (InvalidSignature, UnsupportedAlgorithm, ValueError): continue` in `_verify_certificate()`.

**Files**: `src/zoomies/crypto/tls.py` (~line 1080)
**Acceptance**:
- `rg 'except Exception' src/zoomies/crypto/tls.py` returns zero hits
- `pytest tests/` passes

### Task 3.6 — Deprecate `stream_data_received()` as public API

Make `stream_data_received()` a private method (`_stream_data_received`). Keep `handle_event()` as the single public entry point. Add a public `stream_data_received` that delegates and emits a `DeprecationWarning`.

**Files**: `src/zoomies/h3/connection.py`
**Acceptance**:
- Calling `stream_data_received()` directly emits a `DeprecationWarning`
- `handle_event()` still works
- `pytest tests/` passes

---

## Sprint 4: Documentation & Ergonomics

**Goal**: Document the sans-I/O contract, the 0-RTT flow, and session ticket limitations.

### Task 4.1 — Add timer contract to QuicConnection docstring

Document that `get_timer()` + `handle_timer()` must be called by the caller, and that `idle_timeout` is inoperative without them.

**Files**: `src/zoomies/core/connection.py` (class docstring)
**Acceptance**: `python3 -c "from zoomies import QuicConnection; help(QuicConnection)"` mentions `handle_timer` requirement

### Task 4.2 — Document 0-RTT flow end-to-end

Add a complete 0-RTT usage example to `docs/design/` or as a docstring on `QuicConfiguration.session_ticket`.

**Files**: `docs/design/0rtt-early-data-plan.md` or new example
**Acceptance**: A user can follow the documented steps to complete a 0-RTT handshake

### Task 4.3 — Document session ticket limitations

Add a prominent warning that session tickets are in-memory nonces, not stateless encrypted tokens. State that multi-instance deployment and restart persistence require a custom `RetryTokenHandler`-style ticket encryption layer.

**Files**: `src/zoomies/crypto/tls.py` (docstring on `generate_session_ticket`), README
**Acceptance**: Limitation is visible in `help(QuicConnection.generate_session_ticket)` output

### Task 4.4 — Document flow control defaults

If Task 3.1 keeps `max_data=0` as unlimited, add a clear warning to the `QuicConfiguration` docstring. If the default changes, update all examples.

**Files**: `src/zoomies/core/configuration.py`
**Acceptance**: `help(QuicConfiguration)` mentions flow control semantics

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| CRYPTO retransmit design couples too tightly to TLS layer | Medium | High | Sprint 0 evaluates two approaches before committing |
| Key update integration breaks existing handshake | Medium | High | Sprint 1 tests run full loopback handshake before and after |
| Huffman implementation is large/error-prone | Medium | Medium | Sprint 0 evaluates porting from existing library vs. new impl |
| Changing `max_data` default breaks existing users | Low | High | Sprint 3 uses `__post_init__` warning first, hard change in next major |
| `QuicConfiguration` validation breaks test fixtures | High | Low | Sprint 3 updates all test fixtures in same PR |
| Deprecating `stream_data_received` breaks downstream code (Pounce) | Medium | Medium | Use `DeprecationWarning` not removal; verify Pounce uses `handle_event()` |

---

## Success Metrics

| Metric | Current (v0.3.2) | After Sprint 1 | After Sprint 2 | After Sprint 4 |
|--------|------------------|-----------------|-----------------|-----------------|
| Handshake under 5% loss | Stalls | Completes | Completes | Completes |
| Key update survival | Fails | Works | Works | Works |
| Browser HTTP/3 request | Crashes | Crashes | Works | Works |
| Config validation errors | At runtime | At runtime | At runtime | At construction |
| QPACK static table coverage | 58/99 | 58/99 | 99/99 | 99/99 |
| Sharp edges remaining | 21 | 15 | 8 | 0 |

---

## Changelog

- 2026-04-13: Initial draft from sharp edges audit
