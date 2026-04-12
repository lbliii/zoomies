# Epic: Retry Packets — Stateless Address Validation

**Status**: Draft
**Created**: 2026-04-12
**Target**: 0.4.0
**Estimated Effort**: 12–18h
**Dependencies**: None (all primitives already exist)
**Source**: Codebase analysis + roadmap item (ROADMAP.md line 29)

---

## Why This Matters

**Without Retry, a QUIC server cannot validate a client's address before committing resources to the handshake.** The server trusts the source IP in the first Initial and immediately allocates TLS state, crypto contexts, and CID mappings — all before knowing the client can actually receive packets at that address.

### Consequences

1. **Amplification attack surface**: The 3× anti-amplification limit (`connection.py:1049-1064`) mitigates but doesn't eliminate amplification risk. A spoofed Initial triggers TLS state allocation and a multi-packet server response.
2. **No address validation before resource allocation**: `_handle_initial_server()` (`connection.py:355-395`) creates `CryptoPair`, `QuicTlsContext`, and CID state on the very first Initial — before any proof the client owns the address.
3. **Missing RFC 9000 §8.1 compliance**: Retry is the standard mechanism for stateless address validation. Without it, Zoomies cannot interoperate with deployments that require it.
4. **Client can't handle Retry from other servers**: Client mode (`_handle_initial_client()`) doesn't process incoming Retry packets, so Zoomies clients can't connect to servers that always Retry.

### Evidence Table

| Source | Finding | Proposal Impact |
|--------|---------|-----------------|
| `retry.py:1-46` | Retry encoding + integrity tag fully implemented | LEVERAGES (no changes needed) |
| `connection.py:355-395` | Server creates TLS/CID state on first Initial, no token check | FIXES — Sprint 2 adds gate |
| `connection.py:1049-1064` | 3× anti-amplification present but no address validation | FIXES — Retry validates address |
| `transport_params.py:9,23` | ODCID + retry_source_connection_id params defined, unused | FIXES — Sprint 2 wires them in |
| `header.py:31` | Token field parsed from Initial, never consumed | FIXES — Sprint 2 validates tokens |
| Client mode | No Retry packet handling in `datagram_received()` dispatch | FIXES — Sprint 3 adds client handling |

### Invariants

These must remain true throughout or we stop and reassess:

1. **Sans-I/O purity**: Token generation and validation use caller-supplied callbacks (like `ZeroRttPolicy`). No socket calls, no time calls, no filesystem access inside the library.
2. **Backwards compatibility**: Existing servers without Retry enabled behave identically. Retry is opt-in via configuration.
3. **Test suite green**: Full `pytest` suite passes after every sprint. No test removals without replacement.

---

## Target Architecture

```
Client                              Server
  │                                    │
  │── Initial (no token) ────────────▶│
  │                                    │ RetryTokenHandler.generate_token(odcid, addr)
  │◀──────────────── Retry (token) ───│ encode_quic_retry() [already exists]
  │                                    │
  │── Initial (with token) ──────────▶│ RetryTokenHandler.validate_token(token, addr)
  │                                    │ _address_validated = True
  │◀──── Handshake (normal flow) ─────│ ODCID in transport params
  │                                    │ retry_source_connection_id in transport params
```

### New Types

```python
# Protocol for caller-owned token generation (sans-I/O)
class RetryTokenHandler(Protocol):
    def generate_token(self, original_dcid: bytes, client_addr: tuple[str, int]) -> bytes: ...
    def validate_token(self, token: bytes, client_addr: tuple[str, int]) -> bytes | None: ...
    #                                                returns ODCID or None if invalid

# Configuration addition
@dataclass
class QuicConfiguration:
    retry_token_handler: RetryTokenHandler | None = None  # None = no Retry
```

### Client-Side Event

```python
@dataclass(frozen=True, slots=True)
class RetryReceived(QuicEvent):
    """Server sent Retry — connection will resend Initial with token."""
    retry_source_cid: bytes
```

---

## Sprint Structure

| Sprint | Focus | Effort | Risk | Ships Independently? |
|--------|-------|--------|------|---------------------|
| 0 | Design: token protocol + ODCID tracking | 2h | Low | Yes (design doc only) |
| 1 | Server-side Retry send | 4h | Medium | Yes (server can issue Retry) |
| 2 | Server-side token validation + ODCID plumbing | 4h | Medium | Yes (full server Retry) |
| 3 | Client-side Retry handling | 3h | Low | Yes (full client + server) |
| 4 | Loopback integration test + docs | 3h | Low | Yes (end-to-end proven) |

---

## Sprint 0: Design & Validate

**Goal**: Solve the hard design questions on paper before writing code.

### Task 0.1 — RetryTokenHandler protocol design

Decide the caller-facing token API. Key question: does the handler need a timestamp/TTL, or is that the caller's responsibility?

**Decision**: Caller's responsibility. The protocol is minimal — `generate_token(odcid, addr) -> bytes` and `validate_token(token, addr) -> odcid | None`. This mirrors the `ZeroRttPolicy` pattern already established. The library never touches time.

### Task 0.2 — ODCID tracking design

When Retry is used, the server's CID changes (the Retry packet has a new source CID). The server must:
- Remember the original destination CID (from the first Initial)
- Send it in transport params as `original_destination_connection_id`
- Send the Retry packet's source CID as `retry_source_connection_id`
- Re-derive Initial keys using the *new* CID (from the second Initial's destination)

**Files**: `connection.py` — add `_original_destination_cid: bytes | None` field.

### Task 0.3 — Client Retry handling design

When client receives Retry:
1. Validate integrity tag using `get_retry_integrity_tag()`
2. Store token from Retry packet
3. Reset crypto state — derive new Initial keys from Retry's source CID
4. Re-send Initial with token field populated
5. Use Retry's source CID as new destination CID

**Acceptance**: Design decisions documented in this plan (done — see above).

---

## Sprint 1: Server-Side Retry Send

**Goal**: Server can issue Retry packets when configured with a `RetryTokenHandler`.

### Task 1.1 — Add `RetryTokenHandler` protocol

Create the protocol type in `contracts/` or `core/`.

**Files**: `src/zoomies/contracts/retry.py` (new, ~15 lines)
**Acceptance**: `from zoomies.contracts.retry import RetryTokenHandler` works; `ty` passes.

### Task 1.2 — Add `retry_token_handler` to `QuicConfiguration`

Add the optional field. Default `None` means no Retry.

**Files**: `src/zoomies/core/configuration.py`
**Acceptance**: `QuicConfiguration(retry_token_handler=handler)` constructs without error.

### Task 1.3 — Issue Retry in `_handle_initial_server()`

When `_state == INITIAL` and `header.token` is empty and `retry_token_handler` is set:
1. Call `handler.generate_token(odcid=header.destination_cid, client_addr=addr)`
2. Generate a new server CID for the Retry
3. Call `encode_quic_retry()` (already exists)
4. Queue the Retry datagram for `send_datagrams()`
5. Store `_original_destination_cid` for later
6. Do NOT advance state — remain in `INITIAL`

**Files**: `src/zoomies/core/connection.py`
**Acceptance**:
- `rg 'retry_token_handler' src/zoomies/core/connection.py` returns hits
- Unit test: server with handler sends Retry when Initial has no token
- `pytest tests/ -x` passes

### Task 1.4 — Tests for Retry send

Test that:
- Server with no handler does NOT send Retry (backwards compat)
- Server with handler sends valid Retry packet when Initial has no token
- Retry packet has correct integrity tag (validated via `get_retry_integrity_tag()`)

**Files**: `tests/test_retry_connection.py` (new)
**Acceptance**: `pytest tests/test_retry_connection.py -v` passes.

---

## Sprint 2: Server-Side Token Validation + ODCID

**Goal**: Server validates token on second Initial, tracks ODCID, and sends transport params.

### Task 2.1 — Token validation in `_handle_initial_server()`

When `header.token` is non-empty and `retry_token_handler` is set:
1. Call `handler.validate_token(token=header.token, client_addr=addr)`
2. If returns ODCID: set `_address_validated = True`, store ODCID, proceed with handshake
3. If returns None: drop packet (invalid token)

When `header.token` is non-empty and handler is NOT set: proceed normally (token ignored — allows interop).

**Files**: `src/zoomies/core/connection.py`
**Acceptance**:
- Unit test: valid token → handshake proceeds, `_address_validated` is True
- Unit test: invalid token → packet dropped, no state change

### Task 2.2 — Wire ODCID + retry_source_cid into transport params

After Retry, server's transport params must include:
- `original_destination_connection_id` = ODCID from first Initial
- `retry_source_connection_id` = CID from Retry packet

**Files**: `src/zoomies/core/connection.py`, `src/zoomies/packet/transport_params.py` (encoding path)
**Acceptance**:
- `rg 'retry_source_connection_id' src/zoomies/core/connection.py` returns hits
- Loopback test: client receives correct ODCID in transport params

### Task 2.3 — Re-derive Initial keys from new CID

After Retry, the second Initial uses the Retry packet's source CID as destination. Server must derive Initial keys from this new CID, not the original.

**Files**: `src/zoomies/core/connection.py` (in `_handle_initial_server()`)
**Acceptance**: Second Initial after Retry decrypts successfully.

### Task 2.4 — Tests for token validation

**Files**: `tests/test_retry_connection.py` (extend)
**Acceptance**: `pytest tests/test_retry_connection.py -v` passes with all new cases.

---

## Sprint 3: Client-Side Retry Handling

**Goal**: Client processes incoming Retry packets and re-sends Initial with token.

### Task 3.1 — Dispatch Retry in `datagram_received()`

Add `PACKET_TYPE_RETRY` to the dispatch in `datagram_received()`. Route to `_handle_retry()`.

**Files**: `src/zoomies/core/connection.py`
**Acceptance**: `rg '_handle_retry' src/zoomies/core/connection.py` returns hits.

### Task 3.2 — Implement `_handle_retry()`

1. Validate integrity tag via `get_retry_integrity_tag()`
2. If invalid: drop silently (RFC 9000 §17.2.5.2)
3. If valid:
   - Store token from Retry
   - Store Retry source CID as new peer CID
   - Remember original destination CID
   - Reset Initial crypto with new destination CID
   - Queue new Initial packet with token
   - Emit `RetryReceived` event

**Files**: `src/zoomies/core/connection.py`
**Acceptance**:
- Unit test: valid Retry → client re-sends Initial with token
- Unit test: invalid Retry tag → packet dropped
- Unit test: client only accepts one Retry per connection (RFC 9000 §17.2.5.2)

### Task 3.3 — Add `RetryReceived` event

**Files**: `src/zoomies/core/events.py`, `src/zoomies/__init__.py`
**Acceptance**: `from zoomies import RetryReceived` works.

### Task 3.4 — Tests for client Retry

**Files**: `tests/test_retry_client.py` (new)
**Acceptance**: `pytest tests/test_retry_client.py -v` passes.

---

## Sprint 4: Integration Test + Docs

**Goal**: End-to-end Retry proven in loopback; docs and exports complete.

### Task 4.1 — Loopback integration test

Full client ↔ server test:
1. Client sends Initial
2. Server issues Retry
3. Client re-sends Initial with token
4. Handshake completes
5. HTTP/3 GET succeeds

**Files**: `tests/test_retry_integration.py` (new)
**Acceptance**: `pytest tests/test_retry_integration.py -v` passes.

### Task 4.2 — Public API exports

Export `RetryTokenHandler`, `RetryReceived` from `zoomies.__init__`.

**Files**: `src/zoomies/__init__.py`
**Acceptance**: `python -c "from zoomies import RetryTokenHandler, RetryReceived"` succeeds.

### Task 4.3 — Documentation

- Update `docs/ROADMAP.md` — mark Retry as done
- Add `docs/design/retry-packet-plan.md` (this document)
- Add site content for Retry feature

**Files**: `docs/ROADMAP.md`, `site/content/`
**Acceptance**: `bengal build` succeeds (if applicable).

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Token generation leaks timing info (side channel) | Low | Medium | Sprint 0 design: handler is caller-owned, library doesn't implement crypto token scheme |
| ODCID mismatch breaks handshake | Medium | High | Sprint 2 tests verify ODCID round-trips through transport params |
| Client Retry loop (server always retries) | Low | High | Sprint 3: client accepts at most one Retry per connection (RFC 9000 §17.2.5.2) |
| Initial key re-derivation wrong CID | Medium | High | Sprint 2.3 acceptance: second Initial decrypts successfully |
| Backwards compat regression | Low | High | Invariant 2 + Sprint 1.4 test: no handler → no Retry sent |

---

## Success Metrics

| Metric | Current | After Sprint 2 | After Sprint 4 |
|--------|---------|----------------|----------------|
| Server can validate client address before handshake | No | Yes (server-side complete) | Yes |
| Client handles Retry from any server | No | No | Yes |
| Retry packet encode/decode tested | Encode only (2 tests) | +6 server tests | +10 integration tests |
| Transport params ODCID/retry_scid used | Defined, unused | Wired in | Verified end-to-end |
| RFC 9000 §8.1 compliance | Partial (3× limit only) | Full (server) | Full (both sides) |

---

## Relationship to Existing Work

- **Anti-amplification** (`connection.py:1049-1064`) — Retry complements the 3× limit by adding proper address validation. Both mechanisms coexist.
- **0-RTT early data** — Retry and 0-RTT interact: if a server issues Retry, 0-RTT data from the first Initial is lost. Sprint 3 must ensure 0-RTT state is reset on Retry. This is a known interaction (RFC 9000 §8.1.4).
- **Version negotiation** (roadmap item) — Independent; no dependency in either direction.
- **Connection migration** (roadmap item) — Retry validates the initial address; migration validates path changes. Complementary but separate.

---

## Changelog

- 2026-04-12: Initial draft from codebase analysis
