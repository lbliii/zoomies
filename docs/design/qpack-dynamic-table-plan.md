# Epic: QPACK Dynamic Table — Wire-Efficient Header Compression

**Status**: Complete
**Created**: 2026-04-09
**Target**: 0.3.x (Beta)
**Estimated Effort**: 18–28 hours
**Dependencies**: None (current static-table QPACK is sufficient foundation)
**Source**: Codebase analysis of `src/zoomies/h3/qpack.py`, `h3/connection.py`, `packet/transport_params.py`, RFC 9204

---

## Why This Matters

HTTP/3 headers repeat heavily across requests on the same connection (`:authority`, `cookie`, `authorization`, custom headers). Without a dynamic table, every non-static header is encoded as a full literal on every request — the compression ratio for real traffic is poor.

### Consequences of the current static-table-only implementation:

1. **Every custom header is a literal**: `x-request-id`, `authorization`, `server`, `vary` — all encoded as name+value bytes on every frame, even when repeated identically across hundreds of requests on the same connection
2. **No name-reference for non-static headers**: Even when the name matches a prior entry, the full name bytes are re-sent (no "indexed name" representation for dynamic entries)
3. **Interop gap**: Peers advertising `QPACK_MAX_TABLE_CAPACITY > 0` expect encoder/decoder stream handling (RFC 9204 §4.2); ignoring this works but leaves compression gains on the table
4. **SETTINGS frames not implemented**: `SETTINGS_QPACK_MAX_TABLE_CAPACITY` and `SETTINGS_QPACK_BLOCKED_STREAMS` are not negotiated in transport parameters or H3 SETTINGS, meaning the server can't advertise dynamic table support

### Evidence Table

| Source | Finding | Proposal Impact |
|--------|---------|-----------------|
| `qpack.py` | 154 LOC, static table only, `_find_static()` returns -1 for all custom headers | FIXES — dynamic table enables indexed encoding for repeated custom headers |
| `qpack.py:82-98` | `_encode_literal` always emits full name+value bytes (0x20 prefix) | FIXES — adds "indexed name" and "indexed name+value" representations |
| `h3/connection.py` | No encoder/decoder stream handling; no SETTINGS frame parsing | FIXES — adds control stream + SETTINGS negotiation |
| `transport_params.py` | No QPACK-related transport parameters | MITIGATES — QPACK settings travel in H3 SETTINGS frames, not QUIC transport params |
| `events.py` | No events for encoder/decoder stream data | FIXES — encoder/decoder streams are regular QUIC uni streams, processed inside H3Connection |

### The Fix

Add a QPACK dynamic table (RFC 9204 §§2-3) with encoder/decoder instructions, FIFO eviction, capacity negotiation via H3 SETTINGS, and encoder/decoder stream processing in H3Connection.

---

### Invariants

These must remain true throughout or we stop and reassess:

1. **Static-table backward compatibility**: All existing tests pass unmodified — dynamic table is additive, never changes static-table encoding/decoding behavior
2. **Round-trip correctness**: `decode(encode(headers)) == headers` holds for all header lists, verified by Hypothesis property tests covering both static and dynamic entries
3. **Sans-I/O contract**: No I/O, no threads, no global state. Dynamic table state lives on `H3Connection` instances, not module globals
4. **Memory bounded**: Dynamic table size is capped by negotiated `QPACK_MAX_TABLE_CAPACITY`; eviction fires before exceeding the cap. No unbounded growth.

---

## Target Architecture

```
┌─────────────────────────────────────────────────┐
│                  H3Connection                    │
│                                                  │
│  ┌──────────────┐   ┌──────────────────────┐    │
│  │ QpackEncoder │   │    QpackDecoder       │    │
│  │              │   │                       │    │
│  │ dynamic_table│   │ dynamic_table         │    │
│  │ (list[Entry])│   │ (list[Entry])         │    │
│  │ capacity: int│   │ capacity: int         │    │
│  │              │   │                       │    │
│  │ encode()  ───┼──►│ decode()              │    │
│  │              │   │                       │    │
│  │ encoder_stream_data() ──► uni stream 2   │    │
│  │              │   │ decoder_stream_data() │    │
│  │ uni stream 3 ◄── feed_decoder_stream()   │    │
│  └──────────────┘   └──────────────────────┘    │
│                                                  │
│  SETTINGS_QPACK_MAX_TABLE_CAPACITY = 4096       │
│  SETTINGS_QPACK_BLOCKED_STREAMS = 100           │
└─────────────────────────────────────────────────┘

Dynamic Table Entry = (name: str, value: str, size: int)
  where size = len(name) + len(value) + 32  (RFC 9204 §3.2.1)

Eviction: FIFO — oldest entries evicted first when inserting
  would exceed capacity.

Encoding priority:
  1. Static indexed (exact match)     → 0xC0 | index
  2. Dynamic indexed (exact match)    → indexed with post-base
  3. Dynamic name ref + literal value → name index + literal value
  4. Static name ref + literal value  → name index + literal value
  5. Full literal                     → 0x20 + name + value
```

---

## Sprint Structure

| Sprint | Focus | Effort | Risk | Ships Independently? |
|--------|-------|--------|------|---------------------|
| 0 | Design: table data structure, eviction, encoding decisions | 3h | Low | Yes (RFC only) |
| 1 | `DynamicTable` class + encoder/decoder instructions | 6h | Medium | Yes |
| 2 | Wire `QpackEncoder` / `QpackDecoder` into `H3Connection` | 5h | Medium | Yes |
| 3 | H3 SETTINGS frame + capacity negotiation | 4h | Medium | Yes |
| 4 | Property tests, interop vectors, adversarial cases | 4h | Low | Yes |

---

## Sprint 0: Design & Validate

**Goal**: Resolve the 3 hardest design questions on paper before writing code.

### Task 0.1 — Dynamic table data structure

Decide between:
- **Option A**: `list[tuple[str, str]]` with FIFO append/pop (simple, O(n) lookup)
- **Option B**: `list` + `dict` index for O(1) name+value lookup, O(1) name-only lookup

**Decision criteria**: Profile with 500-entry table. If O(n) scan < 1μs (likely for tables ≤ 4096 bytes), Option A wins on simplicity.

**Acceptance**: Decision documented, benchmark script in `benchmarks/`.

### Task 0.2 — Encoder stream instruction format

Map RFC 9204 §4.3 encoder instructions to concrete byte patterns:
- Set Dynamic Table Capacity
- Insert With Name Reference (static/dynamic)
- Insert With Literal Name
- Duplicate

Confirm: which instructions does the server encoder need to emit? Which does the decoder need to parse? (Answer: encoder emits all; decoder parses all. Decoder emits Section Acknowledgment, Stream Cancellation, Insert Count Increment on the decoder stream.)

**Acceptance**: Instruction table with byte prefixes, prefix lengths, and field layouts written in the plan doc.

### Task 0.3 — Blocked streams strategy

RFC 9204 §2.1.2 allows blocking when the decoder hasn't caught up. For the MVP:
- **Decision**: Use non-blocking mode only (Required Insert Count = 0 in all encoded header blocks). This avoids decoder stream synchronization complexity while still getting compression gains from the dynamic table for the encoder's own use.
- **Rationale**: Pounce is server-side only; the server controls what it encodes. Non-blocking mode means every header block is immediately decodable. Blocked-stream support can be added later without breaking changes.

**Acceptance**: Decision recorded. Non-blocking constraint documented as a code comment.

---

## Sprint 1: DynamicTable + Encoder/Decoder Instructions

**Goal**: Implement the core data structure and RFC 9204 instruction codec in isolation.

### Task 1.1 — `DynamicTable` class

New file: `src/zoomies/h3/dynamic_table.py`

```python
class DynamicTable:
    def __init__(self, capacity: int = 0) -> None: ...
    def insert(self, name: str, value: str) -> int: ...  # returns absolute index
    def lookup(self, name: str, value: str) -> tuple[int, bool] | None: ...  # (index, exact_match)
    def lookup_name(self, name: str) -> int | None: ...
    def set_capacity(self, capacity: int) -> None: ...  # evicts as needed
    def get(self, index: int) -> tuple[str, str]: ...
    @property
    def size(self) -> int: ...  # current size in bytes (RFC formula)
```

**Files**: `src/zoomies/h3/dynamic_table.py`
**Acceptance**:
- `pytest tests/test_dynamic_table.py` passes
- Insert + lookup round-trip for 100 entries
- Eviction fires correctly when capacity exceeded
- `table.size` never exceeds `table.capacity` after any insert

### Task 1.2 — Encoder instruction codec

Functions to encode/decode RFC 9204 §4.3 instructions:
- `encode_set_capacity(buf, capacity)`
- `encode_insert_name_ref(buf, is_static, name_index, value)`
- `encode_insert_literal(buf, name, value)`
- `encode_duplicate(buf, index)`
- Corresponding `decode_*` functions

**Files**: `src/zoomies/h3/qpack_instructions.py`
**Acceptance**:
- Round-trip property tests for each instruction type
- Byte patterns match RFC 9204 §4.3 examples

### Task 1.3 — Decoder stream instruction codec

Functions for RFC 9204 §4.4 decoder instructions:
- `encode_section_ack(buf, stream_id)`
- `encode_stream_cancellation(buf, stream_id)`
- `encode_insert_count_increment(buf, increment)`
- Corresponding `decode_*` functions

**Files**: `src/zoomies/h3/qpack_instructions.py` (same file)
**Acceptance**: Round-trip tests pass.

---

## Sprint 2: Wire into QpackEncoder / QpackDecoder

**Goal**: Replace literal-only encoding with dynamic-table-aware encoding in `qpack.py`.

### Task 2.1 — `QpackEncoder` class

Stateful encoder wrapping `DynamicTable`:

```python
class QpackEncoder:
    def __init__(self, max_table_capacity: int = 0) -> None: ...
    def encode(self, headers: list[Header]) -> bytes: ...  # header block
    def encoder_stream_data(self) -> bytes: ...  # pending instructions for encoder stream
    def set_capacity(self, capacity: int) -> None: ...
```

Encoding strategy (non-blocking):
1. Check static table (exact match → indexed static)
2. Check dynamic table (exact match → indexed dynamic)
3. Check dynamic table (name match → name ref + literal value; insert new entry)
4. Check static table (name match → static name ref + literal value)
5. Full literal (insert new entry if under capacity)

**Files**: `src/zoomies/h3/qpack.py`
**Acceptance**:
- Existing `encode_headers` tests still pass (backward compat)
- New tests: repeated headers across calls use dynamic references on 2nd+ call
- `encoder_stream_data()` returns valid encoder instructions

### Task 2.2 — `QpackDecoder` class

Stateful decoder wrapping `DynamicTable`:

```python
class QpackDecoder:
    def __init__(self, max_table_capacity: int = 0) -> None: ...
    def decode(self, data: bytes) -> list[Header]: ...
    def feed_encoder_stream(self, data: bytes) -> None: ...  # process encoder instructions
    def decoder_stream_data(self) -> bytes: ...  # pending acks for decoder stream
```

**Files**: `src/zoomies/h3/qpack.py`
**Acceptance**:
- Decodes header blocks produced by `QpackEncoder`
- Processes encoder stream instructions to populate its dynamic table
- Existing `decode_headers` tests still pass

### Task 2.3 — Integrate into H3Connection

- `H3Connection.__init__` creates `QpackEncoder` + `QpackDecoder`
- `send_headers` uses `QpackEncoder.encode()` + flushes encoder stream data to uni stream
- `stream_data_received` uses `QpackDecoder.decode()` for HEADERS frames
- Encoder/decoder stream uni-stream IDs (0x02, 0x03) handled in `stream_data_received`
- Module-level `encode_headers` / `decode_headers` remain as stateless convenience functions (static table only)

**Files**: `src/zoomies/h3/connection.py`
**Acceptance**:
- All existing `test_h3.py` tests pass unchanged
- New test: two sequential requests with same custom headers — second request's HEADERS frame is smaller
- `rg 'encode_headers_from_bytes' src/zoomies/h3/connection.py` shows it's replaced with `self._encoder.encode()` in `send_headers`

---

## Sprint 3: H3 SETTINGS + Capacity Negotiation

**Goal**: Negotiate dynamic table capacity via H3 SETTINGS frames so peers know the table is available.

### Task 3.1 — H3 SETTINGS frame codec

New constants and encode/decode for H3 SETTINGS frame (type 0x04):
- `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (0x01)
- `SETTINGS_QPACK_BLOCKED_STREAMS` (0x07)
- `SETTINGS_MAX_FIELD_SECTION_SIZE` (0x06)

**Files**: `src/zoomies/h3/connection.py`
**Acceptance**:
- `push_settings_frame` / `pull_settings_frame` round-trip tests
- Settings values correctly parsed from bytes

### Task 3.2 — Control stream (uni stream type 0x00)

H3Connection opens a unidirectional control stream on init and sends SETTINGS:
- Server sends SETTINGS with `QPACK_MAX_TABLE_CAPACITY` on control stream (stream type 0x00)
- Server parses client SETTINGS from client's control stream
- Encoder capacity set to `min(local_max, peer_advertised)`

**Files**: `src/zoomies/h3/connection.py`
**Acceptance**:
- H3Connection emits control stream data via sender on first `send_headers` or explicit init
- Client SETTINGS parsed correctly, encoder capacity updated
- `QPACK_MAX_TABLE_CAPACITY=0` from peer → encoder stays static-only (graceful fallback)

### Task 3.3 — Configuration knobs

Add to `H3Connection.__init__` (or a new `H3Configuration` dataclass):
- `qpack_max_table_capacity: int = 4096`
- `qpack_blocked_streams: int = 0` (non-blocking MVP)

**Files**: `src/zoomies/h3/connection.py`
**Acceptance**:
- Default capacity is 4096
- `capacity=0` disables dynamic table entirely
- Settings values appear in emitted SETTINGS frame

---

## Sprint 4: Property Tests, Interop Vectors, Adversarial Cases

**Goal**: Harden the implementation with comprehensive testing.

### Task 4.1 — Hypothesis property tests

- Arbitrary header lists → `encoder.encode()` + `decoder.decode()` round-trip
- Random insert/evict sequences → table size invariant holds
- Fuzz encoder stream instructions → decoder never crashes

**Files**: `tests/test_qpack_dynamic.py`
**Acceptance**: `pytest tests/test_qpack_dynamic.py -x --hypothesis-seed=0` passes

### Task 4.2 — RFC 9204 Appendix B interop vectors

Encode RFC 9204 Appendix B test vectors and verify byte-exact output.

**Files**: `tests/test_qpack_interop.py`
**Acceptance**: All Appendix B examples produce expected bytes

### Task 4.3 — Adversarial inputs

- Encoder stream with capacity exceeding negotiated max → error
- Decoder receives instruction referencing entry beyond table size → error, not crash
- Malformed varint in encoder stream → clean error
- Zero-capacity table + insert attempts → no-op, not crash

**Files**: `tests/test_qpack_adversarial.py`
**Acceptance**: All adversarial tests pass, no unhandled exceptions

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Dynamic table state desync between encoder/decoder | Medium | High | Sprint 0 decides non-blocking mode (Required Insert Count = 0), eliminating sync issues. Sprint 4 property tests verify round-trip. |
| Memory growth from unbounded table | Low | High | Invariant 4 enforces `size <= capacity`. Sprint 1 tests eviction. |
| Breaking existing static-table behavior | Low | High | Invariant 1: all existing tests must pass at every sprint. Module-level convenience functions preserved. |
| SETTINGS negotiation complexity with real clients | Medium | Medium | Sprint 3 handles `capacity=0` fallback. Interop tested against RFC vectors in Sprint 4. |
| Performance regression from table lookups | Low | Low | Sprint 0 benchmarks table lookup. O(n) scan on ≤128-entry table is sub-microsecond. |

---

## Success Metrics

| Metric | Current | After Sprint 2 | After Sprint 4 |
|--------|---------|----------------|----------------|
| QPACK encoding modes | 2 (indexed static, full literal) | 5 (+ dynamic indexed, dynamic name ref, static name ref) | 5 |
| Header block size for 10 repeated custom-header requests | ~100% of literal size | <40% of literal size (name+value cached) | <40%, verified by benchmark |
| Test coverage of `h3/qpack.py` | ~67 LOC tested | +200 LOC tested | +300 LOC, including adversarial |
| RFC 9204 Appendix B vectors passing | 0 | 0 (Sprint 4) | All |
| Existing test regressions | 0 | 0 | 0 |

---

## Relationship to Existing Work

- **Pounce integration** — parallel, no dependency. Pounce consumes `H3Connection` events; dynamic table is internal to `H3Connection`. No Pounce changes needed.
- **Client mode (roadmap 0.3.x)** — parallel. Client mode needs its own `QpackEncoder`/`QpackDecoder` pair, but the classes built here are role-agnostic (encoder/decoder, not client/server).
- **Retry packet generation (roadmap 0.3.x)** — unrelated.

---

## Changelog

- 2026-04-09: Initial draft from codebase analysis
