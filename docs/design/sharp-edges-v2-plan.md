# Epic: Sharp Edges v2 — Finish Hardening Zoomies for Production

**Status**: Complete
**Created**: 2026-04-13
**Target**: v0.4.0
**Estimated Effort**: 24–36h
**Dependencies**: None (all changes are internal)
**Source**: Re-audit of v0.3.2 after sharp-edges epic #20; 12 of 21 original findings fixed, 9 remain + 3 new findings

---

## Why This Matters

Sharp-edges epic #20 fixed 12 of 21 findings (CRYPTO retransmit, key updates, Huffman, static table, dynamic table O(1), address validation, config validation, send queue bounding, settings_data(), PacketNumberSpace dedup, broad except). The remaining 9 findings plus 3 newly discovered issues target the gaps between "tests pass" and "a developer can ship this in production without reading the source."

A user who follows the README and examples today will still encounter:
1. Unbounded memory growth from a misbehaving peer (`max_data=0` = unlimited flow control)
2. Silent crashes from a Python 2 `except` syntax bug that fails to catch `BufferReadError` in 5 locations
3. An invisible 0-RTT path that requires source-diving to discover
4. No diagnostic feedback when datagrams are silently dropped
5. An `idle_timeout=30.0` default that does nothing without undocumented caller integration

### Evidence Table

| # | Finding | Status after #20 | Proposal Impact |
|---|---------|-------------------|-----------------|
| 4 | `max_data=0` means unlimited, not disabled | **Unfixed** | FIXES (Sprint 1) |
| 12 | `except ValueError, BufferReadError:` — catches only ValueError, binds exception to name `BufferReadError` | **Unfixed** | FIXES (Sprint 1) |
| 10 | Unknown frames break parse loop (compounded by #12) | **Partially fixed** | FIXES (Sprint 1) |
| 7 | `NewSessionTicket` event defined but never emitted from `datagram_received()` | **Unfixed** | FIXES (Sprint 2) |
| 14 | H3 encoder stream requires caller-managed stream ID | **Partially fixed** | FIXES (Sprint 2) |
| 15 | `handle_event()` and `stream_data_received()` both public | **Partially fixed** | FIXES (Sprint 2) |
| 20 | `idle_timeout` inoperative without `handle_timer()` | **Unfixed** | FIXES (Sprint 3) |
| 8 | 0-RTT requires undocumented 6-step manual process | **Unfixed** | FIXES (Sprint 3) |
| 9 | Session tickets are in-memory nonces (undocumented limitation) | **Unfixed** | FIXES (Sprint 3) |
| N1 | Silent drops — 7+ early-return paths with no diagnostic event | **New** | FIXES (Sprint 1) |
| N2 | `QuicConfiguration` fields lack docstrings explaining semantics | **New** | FIXES (Sprint 3) |
| N3 | Examples are synthetic (fake packets), not realistic (socket loops) | **New** | FIXES (Sprint 3) |

### Invariants

These must remain true throughout or we stop and reassess:

1. **All existing tests pass**: Every PR must pass `pytest tests/`. No regressions.
2. **Sans-I/O contract preserved**: No sprint introduces I/O, threading, or implicit timers. The caller still owns all I/O.
3. **Public API backward compatible**: Existing method signatures don't change. New parameters are keyword-only with backward-compatible defaults. Deprecations use `DeprecationWarning`, not removals.

---

## Target Architecture

After this epic, Zoomies should be able to:
- **Enforce flow control by default** — sensible `max_data` and `max_stream_data` defaults prevent OOM
- **Survive unknown QUIC extensions** — unknown frames skipped cleanly per RFC 9000 §19
- **Emit all protocol events from `datagram_received()`** — including `NewSessionTicket`
- **Provide diagnostic feedback** — `PacketDropped` events for silent drops
- **Make 0-RTT discoverable** — documented end-to-end flow with example
- **Make the sans-I/O contract explicit** — timer integration documented and demonstrated
- **Auto-manage H3 streams** — encoder stream ID allocated internally

No new modules needed. All changes are within existing files, plus one new example.

---

## Sprint Structure

| Sprint | Focus | Effort | Risk | Ships Independently? |
|--------|-------|--------|------|---------------------|
| 0 | Design: flow control defaults, diagnostic event shape | 3h | Low | Yes (design decisions in this doc) |
| 1 | Correctness: except syntax, flow control defaults, parse loop, diagnostics | 10h | Medium | Yes |
| 2 | Sans-I/O contract: NewSessionTicket emission, H3 stream management, API cleanup | 10h | Medium | Yes |
| 3 | Ergonomics: documentation, examples, config docstrings | 8h | Low | Yes |

---

## Sprint 0: Design & Validate ✅

**Goal**: Make three design decisions on paper before writing code.

### Task 0.1 — Choose flow control defaults

`max_data=0` and `max_stream_data=0` currently mean "unlimited." Two options:

**Option A**: Change default to a sensible value (e.g., `1_048_576` = 1 MB). Existing users who relied on `0` = unlimited must now pass `max_data=0` explicitly.
**Option B**: Keep `0` as unlimited but change the field name to `max_data_limit` and add a loud `__post_init__` warning when the default is used.

Decision criteria: Which approach is least surprising to a new user AND least disruptive to existing users?

**Acceptance**: Decision documented in this file with rationale.

> **Decision: Option A — change defaults to 1 MB.**
>
> Rationale:
> - The library is pre-1.0 (v0.3.2 beta). Breaking changes are expected and acceptable.
> - `0` meaning "unlimited" is a semantic trap — every other networking library uses `0` to mean "disabled" or "none." Keeping this convention will repeatedly burn new users.
> - Changing the default to `1_048_576` (1 MB) is safe for most use cases. Users with large transfers can raise it explicitly. Users who truly want unlimited can pass `max_data=0` — but now it's a conscious choice, not an accident.
> - Option B (rename + warn) preserves the footgun for anyone who ignores warnings (which is most developers in production). A safe default is strictly better than a loud warning.
>
> Migration impact: All existing tests that construct `QuicConfiguration` without explicit `max_data`/`max_stream_data` will get the new 1 MB default. Tests that send >1 MB on a stream will need to pass explicit values. This is a one-PR change in Sprint 1.
>
> Implementation:
> ```python
> max_data: int = 1_048_576          # 1 MB — connection-level flow control
> max_stream_data: int = 1_048_576   # 1 MB — per-stream flow control
> ```
> The `flow_control_ok()` check in `stream.py` already enforces the limit when `> 0`. No logic changes needed — just the default value.

### Task 0.2 — Design `PacketDropped` diagnostic event

Silent early returns in `datagram_received()` need a lightweight diagnostic mechanism. Options:

**Option A**: New `PacketDropped(reason: str)` event in the events list. Callers can filter it.
**Option B**: Structured logging hook (`on_packet_dropped` callback in config). Keeps event stream clean.
**Option C**: Both — event for programmatic use, optional log callback for debugging.

Decision criteria: Which preserves sans-I/O purity while being most useful for debugging?

**Acceptance**: Decision documented. Event/callback shape defined.

> **Decision: Option A — `PacketDropped` event in the event stream.**
>
> Rationale:
> - Sans-I/O means "data in, events out." A diagnostic event is the natural output channel — it's how the library already communicates (`DecryptionFailed` is precedent for diagnostic-only events).
> - A callback (Option B) adds a new API surface and a new protocol. It's more complexity for the same information. Callbacks also tempt callers to do I/O inside them (logging), which muddies the sans-I/O contract.
> - Option C is overengineering — one mechanism is enough.
> - Callers who don't want diagnostic events can filter by type: `[e for e in events if not isinstance(e, PacketDropped)]`.
>
> Event shape:
> ```python
> @dataclass(frozen=True, slots=True)
> class PacketDropped:
>     """Diagnostic: a received datagram was dropped without processing.
>
>     Not a protocol error — just informational. Useful for debugging
>     connection stalls and silent failures.
>     """
>     reason: str  # Human-readable: "no initial crypto context", "invalid retry token", etc.
> ```
>
> Add to `QuicEvent` union in `events.py`. Emit from each early-return site in `datagram_received()` and its sub-handlers. Use short, stable reason strings that can be matched programmatically (e.g., `"no_initial_crypto"`, `"invalid_token"`, `"retry_already_received"`, `"invalid_integrity_tag"`).

### Task 0.3 — Design H3 encoder stream auto-allocation

`H3Connection` currently requires `encoder_stream_id` from the caller. Options:

**Option A**: Auto-allocate on first `send_headers()` when dynamic QPACK is enabled. Track allocation in H3Connection.
**Option B**: Require a `StreamAllocator` protocol that the caller provides (cleaner sans-I/O, but more API surface).

Decision criteria: Does auto-allocation violate the sans-I/O contract? (If H3Connection asks the QUIC layer for a stream ID, that's still sans-I/O — it's an internal protocol interaction, not I/O.)

**Acceptance**: Decision documented. Interface sketch for chosen approach.

> **Decision: Option A — auto-allocate internally, with an `is_client` parameter.**
>
> Rationale:
> - QUIC unidirectional stream IDs follow a deterministic scheme: client-initiated = `2, 6, 10, ...` (type 0x02), server-initiated = `3, 7, 11, ...` (type 0x03). H3Connection can compute the next ID without asking the QUIC layer.
> - This does NOT violate sans-I/O. Stream ID allocation is a protocol-internal concern — it's numbering, not I/O. The `H3StreamSender` protocol already abstracts the QUIC layer; H3Connection just needs to know which side it's on.
> - Option B (StreamAllocator protocol) adds API surface that users must implement for something the library can compute deterministically. It's unnecessary complexity.
> - The existing `encoder_stream_id` parameter stays for backward compat but becomes optional. If omitted and `qpack_max_table_capacity > 0`, auto-allocate.
>
> Implementation sketch:
> ```python
> class H3Connection:
>     def __init__(
>         self,
>         sender: H3StreamSender | None = None,
>         *,
>         is_client: bool = True,
>         qpack_max_table_capacity: int = 0,
>         qpack_blocked_streams: int = 0,
>         encoder_stream_id: int | None = None,  # deprecated, auto-allocated if None
>     ) -> None:
>         ...
>         self._is_client = is_client
>         self._next_uni_stream_id = 2 if is_client else 3  # first client/server uni stream
>
>         if qpack_max_table_capacity > 0 and encoder_stream_id is None:
>             self._encoder_stream_id = self._alloc_uni_stream_id()
>         elif encoder_stream_id is not None:
>             import warnings
>             warnings.warn(
>                 "encoder_stream_id is deprecated; H3Connection auto-allocates",
>                 DeprecationWarning, stacklevel=2,
>             )
>             self._encoder_stream_id = encoder_stream_id
>
>     def _alloc_uni_stream_id(self) -> int:
>         """Allocate next unidirectional stream ID (client: 2,6,10; server: 3,7,11)."""
>         sid = self._next_uni_stream_id
>         self._next_uni_stream_id += 4
>         return sid
> ```
>
> The decoder stream (type 0x03) can use the same allocator if needed in the future.

---

## Sprint 1: Correctness Fixes

**Goal**: Fix the bugs that cause crashes, memory exhaustion, or data loss.

### Task 1.1 — Fix `except ValueError, BufferReadError:` syntax (5 locations)

Change Python 2 comma syntax to tuple syntax. This is a correctness bug, not a style issue: the current code catches `ValueError` and binds the exception object to the name `BufferReadError`, meaning `BufferReadError` is **never caught**.

**Files**:
- `src/zoomies/core/connection.py:908` — unknown frame handling
- `src/zoomies/core/connection.py:910` — outer frame parse loop
- `src/zoomies/crypto/tls.py:406` — crypto feed
- `src/zoomies/crypto/tls.py:1081` — cert verification
- `src/zoomies/packet/header.py:75` — CID extraction

**Acceptance**:
- `rg 'except \w+, \w+:' src/` returns zero hits
- `pytest tests/` passes

### Task 1.2 — Change flow control defaults

Implement the approach chosen in Task 0.1. At minimum, users must be unable to accidentally deploy with unlimited flow control.

**Files**: `src/zoomies/core/configuration.py`, `src/zoomies/core/stream.py`
**Acceptance**:
- `QuicConfiguration()` with default `max_data` enforces a finite limit OR emits a loud warning
- New test: stream data exceeding default limit is rejected by `flow_control_ok()`
- `pytest tests/` passes (existing tests updated for new defaults)

### Task 1.3 — Fix unknown frame parsing (skip, don't break)

The parse loop at `connection.py:900-911` breaks on unknown frames. After fixing the `except` syntax (Task 1.1), the loop should `continue` instead of `break` when a frame can't be skipped. Add a `PacketDropped`-style diagnostic (per Task 0.2) when frames are skipped.

**Files**: `src/zoomies/core/connection.py` (lines 900-911)
**Acceptance**:
- New test: packet with unknown frame type followed by STREAM frame — STREAM frame is delivered
- New test: unknown frame without length prefix emits diagnostic, remaining frames still parsed
- `pytest tests/` passes

### Task 1.4 — Add diagnostic events for silent drops

Replace bare `return` / `return []` in `datagram_received()` and sub-handlers with diagnostic event emission (per Task 0.2 design).

**Files**: `src/zoomies/core/connection.py` — at least lines 287-288, 420, 427, 447-448, 500-501, 524-528, 546
**Acceptance**:
- New test: feeding invalid datagram returns a diagnostic event (not empty list)
- `pytest tests/` passes

---

## Sprint 2: Sans-I/O Contract Completeness

**Goal**: Make all protocol events flow through `datagram_received()` and clean up the H3 API surface.

### Task 2.1 — Emit `NewSessionTicket` from `datagram_received()`

When the server sends a NewSessionTicket TLS message (post-handshake), `_feed_crypto_to_client_tls()` should detect it and emit a `NewSessionTicket` event. The manual `receive_new_session_ticket()` method should be deprecated.

**Files**: `src/zoomies/core/connection.py`, `src/zoomies/crypto/tls.py`
**Acceptance**:
- New test: client receives `NewSessionTicket` event from `datagram_received()` after handshake
- `receive_new_session_ticket()` emits `DeprecationWarning`
- `pytest tests/` passes

### Task 2.2 — Auto-allocate H3 encoder stream ID

Implement the approach chosen in Task 0.3. Remove `encoder_stream_id` as a required caller concern.

**Files**: `src/zoomies/h3/connection.py`
**Acceptance**:
- `H3Connection(sender=quic)` with `qpack_max_table_capacity > 0` works without `encoder_stream_id`
- Encoder instructions sent on auto-allocated unidirectional stream
- `encoder_stream_id` parameter still accepted (backward compat) but deprecated
- `pytest tests/test_h3*.py` passes

### Task 2.3 — Complete `stream_data_received()` deprecation

The deprecation warning was added in #20 but the method is still prominently public. Make the internal method `_stream_data_received` truly private and ensure all internal callers use it directly. Update any examples or tests that call the deprecated method.

**Files**: `src/zoomies/h3/connection.py`, tests
**Acceptance**:
- `rg 'stream_data_received' tests/` shows no direct calls (all use `handle_event`)
- `pytest tests/` passes

---

## Sprint 3: Ergonomics & Documentation

**Goal**: Make the library self-documenting so users don't need to read source code to use it correctly.

### Task 3.1 — Add docstrings to `QuicConfiguration` fields

Document the semantic meaning of each field, especially non-obvious ones:
- `max_data` / `max_stream_data`: what 0 means (or meant), sensible ranges
- `idle_timeout`: requires `get_timer()` + `handle_timer()` integration
- `session_ticket`: for 0-RTT resumption, must be stored by caller
- `zero_rtt_policy`: link to usage example
- `verify_mode` / `ca_certs`: interaction between the two

**Files**: `src/zoomies/core/configuration.py`
**Acceptance**:
- `python3 -c "from zoomies import QuicConfiguration; help(QuicConfiguration)"` shows field-level docs
- Each field with non-obvious semantics has a docstring
- `idle_timeout` docs mention `handle_timer()` requirement

### Task 3.2 — Document 0-RTT flow end-to-end

Write a complete 0-RTT usage example showing all steps:
1. Server generates session ticket after handshake
2. Client receives `NewSessionTicket` event (after Task 2.1)
3. Client stores ticket
4. Client reconnects with `session_ticket=...` in config
5. Server implements `ZeroRttPolicy`
6. Both sides handle `ZeroRttAccepted` / `ZeroRttRejected`

**Files**: New `examples/zero_rtt_resumption.py` or update `docs/design/0rtt-early-data-plan.md`
**Acceptance**:
- A developer can follow the example to implement 0-RTT without reading source
- Example is runnable (not synthetic)

### Task 3.3 — Write realistic sans-I/O integration example

Replace or supplement the synthetic examples with a realistic one showing:
- UDP socket setup
- `datagram_received()` → event processing → `send_datagrams()` loop
- Timer integration (`get_timer()` → `select`/`poll` timeout → `handle_timer()`)
- Graceful shutdown

**Files**: New `examples/realistic_server.py` or update existing examples
**Acceptance**:
- Example runs against a real QUIC client (e.g., `curl --http3`)
- Timer loop is demonstrated
- Comments explain the sans-I/O contract

### Task 3.4 — Document session ticket limitations

Add warning that session tickets are in-memory random nonces. Multi-instance deployment and restart persistence require a custom ticket encryption layer.

**Files**: `src/zoomies/crypto/tls.py` (docstring on `SessionTicket` and `generate_session_ticket`)
**Acceptance**:
- `help(QuicConnection.generate_session_ticket)` mentions the limitation
- README or design doc links to guidance

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Changing `max_data` default breaks existing users/tests | High | Low | Sprint 0 evaluates options; Sprint 1 updates all test fixtures in same PR |
| `PacketDropped` events clutter event stream for users who don't want them | Medium | Low | Sprint 0 designs as opt-in or filterable subtype |
| Auto-allocated encoder stream ID conflicts with caller's stream allocation | Medium | Medium | Sprint 0 designs allocation protocol; Sprint 2 tests concurrent stream use |
| Deprecating `receive_new_session_ticket()` breaks downstream (Pounce) | Low | Medium | Use `DeprecationWarning` not removal; grep Pounce first |
| Realistic example is complex enough to discourage new users | Low | Low | Keep synthetic examples for quick-start; add realistic example as separate "production" guide |

---

## Success Metrics

| Metric | Current (post-#20) | After Sprint 1 | After Sprint 2 | After Sprint 3 |
|--------|---------------------|-----------------|-----------------|-----------------|
| `except X, Y:` sites | 5 | 0 | 0 | 0 |
| Flow control default safe | No (unlimited) | Yes | Yes | Yes |
| Events from `datagram_received()` complete | No (NST missing) | No | Yes | Yes |
| Silent drop sites with no diagnostic | 7+ | 0 | 0 | 0 |
| H3 requires caller stream ID mgmt | Yes | Yes | No | No |
| `help(QuicConfiguration)` shows field docs | No | No | No | Yes |
| 0-RTT documented with example | No | No | No | Yes |
| Realistic example with timer loop | No | No | No | Yes |
| Sharp edges remaining | 12 | 4 | 1 | 0 |

---

## Relationship to Existing Work

- **Sharp-edges epic #20** — predecessor — fixed 12 of 21 original findings. This plan addresses the remaining 9 + 3 new findings discovered in the re-audit.
- **Connection migration (#15)** — parallel — no conflicts; migration uses `handle_timer()` which this plan documents.
- **0-RTT sprint 0 design doc** — prerequisite reading — Task 3.2 builds on this design.

---

## Changelog

- 2026-04-13: Sprint 3 complete — Task 3.1 (QuicConfiguration docstrings), Task 3.2 (examples/zero_rtt_resumption.py), Task 3.3 (examples/realistic_server.py), Task 3.4 (SessionTicket limitation docs). Fixed test_adversarial.py assertion for PacketDropped. Added missing tests/__init__.py. Updated examples/README.md. All 460 tests pass.
- 2026-04-13: Sprint 2 complete — Task 2.1 (auto-emit NewSessionTicket from datagram_received), Task 2.2 (auto-allocate H3 encoder stream with is_client), Task 2.3 (deprecate stream_data_received, migrate tests to handle_event)
- 2026-04-13: Sprint 1 complete — Task 1.1 (fix 5 except syntax sites), Task 1.2 (14 PacketDropped diagnostic events), Task 1.3 (flow control defaults to 1MB)
- 2026-04-13: Sprint 0 complete — three design decisions documented (flow control: Option A/1MB default; diagnostics: Option A/PacketDropped event; H3 streams: Option A/auto-allocate with is_client)
- 2026-04-13: Initial draft from re-audit of v0.3.2 post-#20
