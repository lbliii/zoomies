# Epic: Connection Migration & CID Retirement — Mobile-Ready QUIC

**Status**: Draft
**Created**: 2026-04-12
**Target**: 0.3.x (Beta — Interoperable)
**Estimated Effort**: 18–28 hours
**Dependencies**: None (builds on existing frame/CID infrastructure)
**Source**: Codebase analysis of connection.py, frames/, packet/, events.py, configuration.py

---

## Why This Matters

**QUIC's headline advantage over TCP is seamless connection survival across network changes** — WiFi to cellular, IP reassignment, NAT rebinding. Without connection migration, Zoomies cannot deliver on this promise, and Pounce clients on mobile will experience dropped connections on every network switch.

### Concrete consequences of the current state

1. **Silent address overwrite**: `datagram_received()` (connection.py:324) sets `_peer_addr = addr` on every packet with zero validation — a spoofed packet from any address is silently accepted as the peer's new address
2. **No path validation**: PATH_CHALLENGE (0x1A) and PATH_RESPONSE (0x1B) frames have no pull/push functions and no handling logic — address changes cannot be validated per RFC 9000 §9.1
3. **CID lifecycle incomplete**: `_queue_new_connection_id()` always sends `retire_prior_to=0` (connection.py:950) — old CIDs accumulate forever, violating RFC 9000 §5.1.1
4. **`disable_active_migration` ignored**: Transport parameter is parsed and stored (transport_params.py:42) but never enforced — peers that advertise migration-disabled are still silently migrated
5. **No migration events**: Callers (Pounce) have no way to know when a client changes address — no logging, no metrics, no policy hooks
6. **No stateless reset**: Reset tokens are serialized in NEW_CONNECTION_ID frames but never used for connection termination without state (RFC 9000 §10.3)

**The fix**: Implement RFC 9000 §9 (Connection Migration) with path validation, CID retirement lifecycle, and migration events — completing the 0.3.x "Interoperable" milestone.

### Evidence Table

| Area | Finding | Proposal Impact |
|------|---------|-----------------|
| connection.py:324 | `_peer_addr` overwritten on every datagram, no comparison | FIXES — Sprint 2 adds migration detection |
| frames/ | PATH_CHALLENGE/PATH_RESPONSE not implemented (0x1A, 0x1B) | FIXES — Sprint 1 adds frame parsing + handling |
| connection.py:950 | `retire_prior_to` hardcoded to 0, CIDs never retired | FIXES — Sprint 3 adds CID lifecycle management |
| transport_params.py:42 | `disable_active_migration` parsed but not enforced | FIXES — Sprint 2 checks before accepting migration |
| events.py | No migration/path events | FIXES — Sprint 2 adds ConnectionMigrated event |
| connection.py:937-969 | Only 1 CID issued post-handshake, no pool | FIXES — Sprint 3 maintains CID pool |

### Invariants

These must remain true throughout or we stop and reassess:

1. **Existing tests pass**: Full `pytest` suite passes after every sprint — no regressions in handshake, streams, 0-RTT, retry, or recovery
2. **Sans-I/O contract**: No socket access, no asyncio, no OS calls added to any module — callers still own I/O
3. **Single-address connections unaffected**: A connection where the peer never changes address must behave identically to today — zero performance or correctness impact for the common case

---

## Target Architecture

### New frame types (frames/path.py)

```python
@dataclass(frozen=True)
class PathChallengeFrame:
    data: bytes  # exactly 8 bytes

@dataclass(frozen=True)
class PathResponseFrame:
    data: bytes  # exactly 8 bytes
```

### Path state (core/path.py — new module)

```python
@dataclass
class PathState:
    addr: tuple[str, int]
    validated: bool = False
    challenge_data: bytes | None = None  # pending PATH_CHALLENGE we sent
    challenge_sent_at: float = 0.0
    bytes_sent: int = 0  # anti-amplification tracking per path
    bytes_received: int = 0
```

### CID lifecycle (connection.py updates)

```
                   ┌─────────────┐
  handshake done ──▶ Issue CID pool (active_connection_id_limit CIDs)
                   └──────┬──────┘
                          │
              ┌───────────▼────────────┐
              │ Peer uses CID N        │
              │ → retire_prior_to = N  │
              │ → issue replacement    │
              └───────────┬────────────┘
                          │
              ┌───────────▼────────────┐
              │ Receive RETIRE(seq)    │
              │ → remove from _our_cids│
              │ → emit event           │
              └────────────────────────┘
```

### Migration flow (connection.py updates)

```
datagram_received(data, new_addr)
  │
  ├─ addr == _peer_addr? → normal processing (no change)
  │
  └─ addr != _peer_addr?
       ├─ disable_active_migration? → drop packet, emit event
       ├─ non-probing packet? → tentative migration:
       │    1. Store new_addr as _pending_peer_addr
       │    2. Send PATH_CHALLENGE to new_addr
       │    3. Continue processing on old path
       │    4. On PATH_RESPONSE match → complete migration:
       │         - _peer_addr = new_addr
       │         - Reset congestion state (RFC 9000 §9.4)
       │         - Emit ConnectionMigrated event
       │         - Send PATH_CHALLENGE to old_addr (reverse validation)
       └─ probing-only packet? → respond to PATH_CHALLENGE, don't migrate
```

### New events

```python
@dataclass(frozen=True)
class ConnectionMigrated:
    old_addr: tuple[str, int]
    new_addr: tuple[str, int]

@dataclass(frozen=True)
class PathValidationFailed:
    addr: tuple[str, int]
    reason: str
```

---

## Sprint Structure

| Sprint | Focus | Effort | Risk | Ships Independently? |
|--------|-------|--------|------|---------------------|
| 0 | Design: path state, CID pool sizing, anti-amp | 2–3h | Low | Yes (design doc only) |
| 1 | PATH_CHALLENGE / PATH_RESPONSE frames + echo | 3–4h | Low | Yes (new frames, no migration) |
| 2 | Migration detection + path validation | 6–10h | Medium | Yes (server validates migrating clients) |
| 3 | CID retirement lifecycle + pool management | 4–6h | Medium | Yes (proper CID rotation) |
| 4 | Integration tests + loopback migration | 3–5h | Low | Yes (test-only, proves end-to-end) |

---

## Sprint 0: Design & Validate

**Goal**: Resolve three design questions on paper before writing code.

### Task 0.1 — Path state design

Decide: flat `PathState` dataclass vs. per-path state machine? How many simultaneous paths to track (RFC 9000 §9 only requires old + new)?

**Decision criteria**: Does the design handle NAT rebinding (same CID, different addr) vs. deliberate migration (new CID, new addr)?

### Task 0.2 — CID pool sizing

RFC 9000 §5.1.1 says the peer advertises `active_connection_id_limit` (min 2). Current code issues exactly 1 CID post-handshake. Design pool: how many to pre-issue, when to refill, how `retire_prior_to` advances.

**Acceptance**: Written decision in this plan's changelog with rationale.

### Task 0.3 — Anti-amplification on new paths

RFC 9000 §9.3: "An endpoint MUST NOT send more than three times the number of bytes received" on an unvalidated path. Current anti-amp is connection-global (connection.py:1197-1210). Design per-path tracking.

**Acceptance**: Written decision with before/after data flow.

---

## Sprint 1: PATH_CHALLENGE / PATH_RESPONSE Frames

**Goal**: Parse, serialize, and echo PATH frames — the building blocks for path validation.

### Task 1.1 — Frame types

Add `frames/path.py` with `pull_path_challenge()`, `push_path_challenge()`, `pull_path_response()`, `push_path_response()`.

**Files**: `src/zoomies/frames/path.py` (new), `src/zoomies/frames/__init__.py`
**Acceptance**: `pytest tests/test_frames_path.py` passes — round-trip encode/decode for both frame types, 8-byte data validation.

### Task 1.2 — Frame dispatch in connection

Wire PATH_CHALLENGE and PATH_RESPONSE into `_process_frames()` in connection.py. On PATH_CHALLENGE: queue PATH_RESPONSE with same 8-byte data. On PATH_RESPONSE: store for validation (Sprint 2 uses it).

**Files**: `src/zoomies/core/connection.py`, `src/zoomies/primitives/types.py` (verify FrameType enum has 0x1A, 0x1B)
**Acceptance**: `pytest tests/test_connection_path.py` — unit test: feed a packet containing PATH_CHALLENGE, verify PATH_RESPONSE is queued in outbound datagrams with matching data.

### Task 1.3 — Export frame types

Add `PathChallengeFrame`, `PathResponseFrame` to public imports.

**Files**: `src/zoomies/__init__.py`
**Acceptance**: `python -c "from zoomies import PathChallengeFrame, PathResponseFrame"` succeeds.

---

## Sprint 2: Migration Detection + Path Validation

**Goal**: Detect when a peer's address changes, validate the new path with PATH_CHALLENGE, and complete migration only on validation success.

### Task 2.1 — Path state module

Create `src/zoomies/core/path.py` with `PathState` dataclass. Track: addr, validated flag, pending challenge data, anti-amplification counters.

**Files**: `src/zoomies/core/path.py` (new)
**Acceptance**: Unit test for PathState construction and validation transitions.

### Task 2.2 — Migration detection in datagram_received

Compare incoming `addr` against `_peer_addr`. If different and `disable_active_migration` is not set by peer: begin path validation instead of blindly overwriting.

**Files**: `src/zoomies/core/connection.py`
**Acceptance**:
- `rg '_peer_addr = addr' src/zoomies/core/connection.py` returns zero unconditional overwrites (only via validated migration path)
- Unit test: feed packet from new address → PATH_CHALLENGE is sent to new address, `_peer_addr` is NOT yet updated

### Task 2.3 — PATH_RESPONSE completes migration

When PATH_RESPONSE arrives matching our pending challenge: update `_peer_addr`, reset congestion controller (RFC 9000 §9.4), emit `ConnectionMigrated` event.

**Files**: `src/zoomies/core/connection.py`, `src/zoomies/events.py`
**Acceptance**:
- Unit test: full challenge-response flow → `ConnectionMigrated` event emitted with correct old/new addresses
- `pytest tests/` — full suite passes (invariant 1)

### Task 2.4 — Enforce disable_active_migration

If peer's transport params include `disable_active_migration=True`, drop packets from new addresses (or process but don't migrate).

**Files**: `src/zoomies/core/connection.py`
**Acceptance**: Unit test: set `disable_active_migration` in peer params → packet from new addr is processed but no migration occurs.

---

## Sprint 3: CID Retirement Lifecycle

**Goal**: Maintain a CID pool, advance `retire_prior_to`, and handle peer retirement requests properly.

### Task 3.1 — CID pool management

After handshake, issue `active_connection_id_limit` CIDs (default 2, per RFC). When a CID is retired, issue a replacement to maintain pool size.

**Files**: `src/zoomies/core/connection.py`
**Acceptance**: Unit test: after handshake, `len(_our_cids)` equals `active_connection_id_limit`. After receiving RETIRE, a new CID is immediately issued.

### Task 3.2 — Advance retire_prior_to

On migration, advance `retire_prior_to` so the old CID (associated with old path) is retired. This prevents linkability across paths.

**Files**: `src/zoomies/core/connection.py`
**Acceptance**: Unit test: migration completes → next NEW_CONNECTION_ID has `retire_prior_to > 0`.

### Task 3.3 — Handle peer's NEW_CONNECTION_ID

Process incoming NEW_CONNECTION_ID from peer: store CID in `_peer_cids` pool, respect `retire_prior_to` to retire stale peer CIDs, use fresh CID on migration.

**Files**: `src/zoomies/core/connection.py`
**Acceptance**: Unit test: receive NEW_CONNECTION_ID with `retire_prior_to=2` → all peer CIDs with seq < 2 are removed.

### Task 3.4 — active_connection_id_limit transport parameter

Parse and advertise `active_connection_id_limit` in transport parameters. Respect peer's limit when issuing CIDs.

**Files**: `src/zoomies/packet/transport_params.py`, `src/zoomies/core/configuration.py`
**Acceptance**: `rg 'active_connection_id_limit' src/` shows it in transport params encoding and connection CID issuance logic.

---

## Sprint 4: Integration Tests + Loopback Migration

**Goal**: Prove end-to-end migration works with real TLS, real packets, real CID rotation.

### Task 4.1 — Loopback migration test

Client and server complete handshake, exchange data, then client "migrates" (sends from new address), server validates path, migration completes, data continues flowing.

**Files**: `tests/test_migration_loopback.py` (new)
**Acceptance**: `pytest tests/test_migration_loopback.py -v` passes — full handshake → data → migrate → data on new path.

### Task 4.2 — CID rotation loopback test

Client and server exchange CIDs, client retires old CIDs, server issues replacements, connection continues.

**Files**: `tests/test_migration_loopback.py`
**Acceptance**: Test verifies CID pool stays at `active_connection_id_limit` throughout, and `retire_prior_to` advances.

### Task 4.3 — NAT rebinding test

Simulate NAT rebinding: same CID, different source address. Verify server sends PATH_CHALLENGE and validates before completing migration.

**Files**: `tests/test_migration_loopback.py`
**Acceptance**: Test verifies PATH_CHALLENGE sent, PATH_RESPONSE received, migration completes without connection drop.

### Task 4.4 — Update ROADMAP and docs

Mark connection migration / CID retirement as done in ROADMAP.md. Update architecture.md if needed.

**Files**: `docs/ROADMAP.md`, `docs/design/architecture.md`
**Acceptance**: `rg 'Connection migration' docs/ROADMAP.md` shows ~~strikethrough~~ **Done** marking.

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Migration breaks existing single-path connections | Low | High | Invariant 3 — all existing tests must pass; migration path only activates on address change |
| Anti-amplification regression on new paths | Medium | High | Sprint 0 Task 0.3 designs per-path tracking; Sprint 2 tests verify 3x limit on unvalidated paths |
| CID pool exhaustion under rapid migration | Low | Medium | Sprint 3 Task 3.1 — pool auto-refills on retirement; limit to `active_connection_id_limit` |
| Spoofed migration (attacker sends from forged addr) | Medium | High | Sprint 2 — PATH_CHALLENGE validates reachability before completing migration; anti-amp limits exposure |
| Congestion state reset causes throughput dip | Medium | Low | Expected per RFC 9000 §9.4 — document in migration event so callers can log/alert |

---

## Success Metrics

| Metric | Current | After Sprint 1 | After Sprint 4 |
|--------|---------|-----------------|-----------------|
| PATH frame support | 0/2 frames | 2/2 frames | 2/2 frames |
| Migration detection | None (silent overwrite) | N/A | Full validation flow |
| CID lifecycle | 1 CID issued, never retired | 1 CID issued | Pool managed, retire_prior_to advancing |
| RFC 9000 §9 compliance | Not implemented | Partial (frames only) | Complete |
| Migration-related tests | 0 | ~4 unit tests | ~12 unit + 3 integration tests |
| `disable_active_migration` enforced | No | No | Yes |

---

## Relationship to Existing Work

- **Version negotiation** — parallel / independent — can be done before or after migration, no overlap
- **Pounce integration** — downstream consumer — will use `ConnectionMigrated` event for logging and metrics; migration is transparent to ASGI apps
- **0-RTT early data** — prerequisite met — 0-RTT already works, migration doesn't affect it
- **Recovery (loss detection / congestion)** — dependency — Sprint 2 must reset congestion state on migration per RFC 9000 §9.4; existing recovery module supports this via `CongestionController` reset

---

## Changelog

- 2026-04-12: Initial draft from codebase analysis
