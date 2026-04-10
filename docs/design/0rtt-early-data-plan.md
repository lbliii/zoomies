# Epic: 0-RTT Early Data — First-Flight Application Data for QUIC

**Status**: Complete
**Created**: 2026-04-10
**Completed**: 2026-04-10
**Target**: 0.4.0
**Estimated Effort**: 40–60 hours
**Dependencies**: None (all prerequisites exist in 0.2.0)
**Source**: Codebase analysis of crypto, connection, packet, recovery, events, and H3 layers

---

## Why This Matters

0-RTT lets clients send application data in the very first flight — before the handshake completes — eliminating one round trip for repeat connections. This is QUIC's single largest latency advantage over TCP+TLS.

**Consequences of not having it:**

1. Every connection pays a full round trip before sending data, even for repeat visitors
2. Zoomies cannot claim RFC 9001 compliance — 0-RTT is a core protocol feature
3. Pounce (the ASGI server) cannot compete with aioquic on time-to-first-byte for repeat clients
4. The `is_0rtt` flags on `StreamDataReceived` and `H3HeadersReceived` events are dead code — they exist but are never set to `True`
5. Interop testing against aioquic and other QUIC stacks will fail on 0-RTT scenarios

**Fix**: Add TLS 1.3 PSK/session ticket support, derive 0-RTT keys, and wire packet processing through the connection state machine.

### Evidence Table

| Layer | Key Finding | Proposal Impact |
|-------|-------------|-----------------|
| TLS/Crypto | 0 PSK infrastructure — no session tickets, no `pre_shared_key` extension, no `NewSessionTicket` message (tls.py, 754 lines) | FIXES — Sprint 1 adds full PSK/ticket support |
| Connection | `_handle_0rtt()` is `pass` stub (core/connection.py:297-298); 3 crypto contexts, 0 for 0-RTT | FIXES — Sprint 3 implements handler + crypto context |
| Packet | 0-RTT packet type defined (`PACKET_TYPE_ZERO_RTT = 1`), header parsing works (header.py:127-128) | LEVERAGES — no changes needed |
| Transport params | 6/6 flow-control params present (transport_params.py:8-23) | LEVERAGES — no changes needed |
| Events | `is_0rtt` flag on 2 events, plumbed through H3 (events.py:24,86) | LEVERAGES — flag propagation ready |
| Recovery | 3 packet spaces; no 0-RTT mapping (sent_packet.py:7-12) | MITIGATES — Sprint 4 maps 0-RTT to Application space |
| H3 | `is_0rtt` parameter accepted but never `True` (h3/connection.py:234) | FIXES — Sprint 5 adds early request handling |
| Tests | 0 tests for 0-RTT across 34 test files | FIXES — every sprint includes tests |

### Invariants

These must remain true throughout or we stop and reassess:

1. **Full handshake still works**: All existing tests pass — 0-RTT is additive, never breaks the 1-RTT path
2. **Sans-I/O contract holds**: No I/O calls introduced; caller still owns send/recv; 0-RTT data exposed through the same event/datagram API
3. **Anti-replay is explicit**: Server MUST reject 0-RTT by default unless the caller opts in with a replay-safe configuration; no silent acceptance of potentially replayed data

---

## Target Architecture

```
Client (repeat connection)              Server
─────────────────────────              ──────
1. Load saved session ticket + transport params
2. Derive early_secret from PSK
3. Build ClientHello with pre_shared_key + early_data extensions
4. Send Initial packet (ClientHello)
   + 0-RTT packets (early application data)  ──────────►
                                              5. Match PSK, derive early_secret
                                              6. Decrypt 0-RTT packets
                                              7. Deliver StreamDataReceived(is_0rtt=True)
                                              8. Send ServerHello (with PSK mode)
                                         ◄──  9. Send EncryptedExtensions (early_data accepted)
                                              10. Complete handshake
11. Handshake confirms 0-RTT accepted
12. Promote 0-RTT streams to 1-RTT
```

**New types:**

```python
@dataclass(frozen=True, slots=True)
class SessionTicket:
    """Opaque session ticket for 0-RTT resumption."""
    ticket: bytes
    resumption_secret: bytes
    max_early_data: int
    transport_parameters: QuicTransportParameters
    timestamp: float
    lifetime: int  # seconds

class ZeroRttState(StrEnum):
    NONE = "none"           # No 0-RTT attempted
    ATTEMPTING = "attempting"  # Client sent 0-RTT data
    ACCEPTED = "accepted"    # Server confirmed acceptance
    REJECTED = "rejected"    # Server rejected, resend as 1-RTT
```

**New crypto context:** `_zero_rtt_crypto: CryptoPair | None` derived from `early_secret` via HKDF.

---

## Sprint Structure

| Sprint | Focus | Effort | Risk | Ships Independently? |
|--------|-------|--------|------|---------------------|
| 0 | Design: PSK key schedule + anti-replay strategy | 4h | Low | Yes (RFC/design doc only) |
| 1 | TLS: PSK + session ticket infrastructure | 12h | High | Yes (ticket issue/accept, no 0-RTT data yet) |
| 2 | Crypto: 0-RTT key derivation | 6h | Medium | Yes (key material ready, not wired) |
| 3 | Connection: 0-RTT packet processing | 10h | High | Yes (server accepts 0-RTT data) |
| 4 | Client: 0-RTT send + rejection recovery | 8h | Medium | Yes (client can send early data) |
| 5 | H3 + integration: end-to-end 0-RTT HTTP/3 | 6h | Low | Yes (full feature) |

---

## Sprint 0: Design & Validate

**Goal**: Solve the three hardest design problems on paper before writing code.

### Task 0.1 — PSK Key Schedule Design

Map the RFC 9001 §4.5 key schedule for 0-RTT:
- Document derivation path: `PSK → early_secret → client_early_traffic_secret → 0-RTT keys`
- Confirm HKDF labels match existing `hkdf_expand_label` implementation
- Decide: store PSK in `SessionTicket` dataclass or separate store?

**Acceptance**: Design doc in `docs/design/` with key derivation diagram and HKDF label table.

### Task 0.2 — Anti-Replay Strategy

RFC 9001 §9.2 requires servers to limit 0-RTT replay. Design the strategy:
- **Option A**: Single-use ticket (server tracks used tickets in a set)
- **Option B**: Time-window rejection (server rejects tickets older than N seconds)
- **Option C**: Caller-provided callback (sans-I/O: caller decides)

Recommend Option C (fits sans-I/O contract — caller owns policy). Document the callback protocol.

**Acceptance**: Decision documented with rationale; callback `Protocol` type defined.

### Task 0.3 — 0-RTT Rejection & Resend Design

When the server rejects 0-RTT, the client must resend data as 1-RTT. Design:
- How does the client track which streams were 0-RTT?
- How does `StreamSendState` handle "resend from offset 0"?
- Does H3 need to know about rejection?

**Acceptance**: State diagram for client-side 0-RTT lifecycle (ATTEMPTING → ACCEPTED/REJECTED → resend).

---

## Sprint 1: TLS PSK + Session Ticket Infrastructure

**Goal**: Enable TLS 1.3 session resumption without yet sending 0-RTT data.

### Task 1.1 — NewSessionTicket Message

Add `NewSessionTicket` generation (server) and parsing (client) to `crypto/tls.py`.

- Server generates ticket after handshake completes (using `resumption_master_secret`)
- Client stores ticket as `SessionTicket` frozen dataclass
- Ticket includes: nonce, lifetime, max_early_data_size, encrypted state

**Files**: `src/zoomies/crypto/tls.py`, `src/zoomies/events.py`
**Acceptance**: `rg 'NewSessionTicket' src/` returns hits in tls.py; new `SessionTicketReceived` event exists.

### Task 1.2 — PSK Extension in ClientHello

When resuming, client includes `pre_shared_key` and `psk_key_exchange_modes` extensions in ClientHello.

- Build PSK binder (HMAC over truncated ClientHello)
- Support `psk_dhe_ke` mode only (PSK + ephemeral, per RFC 9001 §4.5)

**Files**: `src/zoomies/crypto/tls.py`
**Acceptance**: `pytest tests/test_tls*.py -v` passes; new test `test_psk_clienthello_roundtrip` verifies binder.

### Task 1.3 — Server PSK Acceptance

Server recognizes `pre_shared_key` extension, validates binder, selects PSK mode.

- ServerHello includes `pre_shared_key` extension with selected identity
- Key schedule switches to PSK-based derivation

**Files**: `src/zoomies/crypto/tls.py`
**Acceptance**: Loopback test completes full handshake using PSK resumption (no 0-RTT data). `test_psk_handshake_loopback` passes.

---

## Sprint 2: 0-RTT Key Derivation

**Goal**: Derive 0-RTT encryption keys so packets can be encrypted/decrypted.

### Task 2.1 — Early Secret Derivation

Add `derive_early_secret()` to the HKDF module:
- `early_secret = HKDF-Extract(PSK, salt=0)`
- `client_early_traffic_secret = Derive-Secret(early_secret, "c e traffic", ClientHello)`

**Files**: `src/zoomies/crypto/_hkdf.py`, `src/zoomies/crypto/quic_crypto.py`
**Acceptance**: Unit test derives known test vector from RFC 8448 §4.

### Task 2.2 — CryptoPair for 0-RTT

Add `setup_0rtt(early_secret, client_hello_hash)` to `CryptoPair`:
- Derives AEAD key + IV from `client_early_traffic_secret`
- Same AEAD (AES-128-GCM) as other epochs
- Header protection key derived same way

**Files**: `src/zoomies/crypto/quic_crypto.py`
**Acceptance**: `test_0rtt_encrypt_decrypt` passes — round-trip encrypt/decrypt with 0-RTT keys.

---

## Sprint 3: Server-Side 0-RTT Packet Processing

**Goal**: Server can receive, decrypt, and deliver 0-RTT application data.

### Task 3.1 — 0-RTT Crypto Context Setup

When server accepts PSK with `early_data`, set up `_zero_rtt_crypto` on `QuicConnection`.

**Files**: `src/zoomies/core/connection.py`
**Acceptance**: After PSK handshake, `connection._zero_rtt_crypto is not None`.

### Task 3.2 — Implement `_handle_0rtt()`

Replace the `pass` stub at connection.py:297-298:
- Decrypt 0-RTT payload using `_zero_rtt_crypto`
- Parse frames (STREAM, CRYPTO not allowed in 0-RTT)
- Deliver `StreamDataReceived(is_0rtt=True)` events
- Apply transport parameter flow-control limits from saved ticket

**Files**: `src/zoomies/core/connection.py`
**Acceptance**: `rg 'pass.*0-RTT' src/` returns zero hits; `test_server_receives_0rtt_stream_data` passes.

### Task 3.3 — Anti-Replay Callback

Add `ZeroRttValidator` protocol to `contracts.py`:
```python
class ZeroRttValidator(Protocol):
    def validate_0rtt(self, ticket: SessionTicket) -> bool: ...
```
Server calls validator before accepting 0-RTT. If rejected, discard 0-RTT data and proceed with 1-RTT handshake.

**Files**: `src/zoomies/contracts.py`, `src/zoomies/core/connection.py`
**Acceptance**: Test with rejecting validator confirms 0-RTT data is discarded; `StreamDataReceived` events have `is_0rtt=False`.

---

## Sprint 4: Client-Side 0-RTT Send + Rejection Recovery

**Goal**: Client can send 0-RTT data and recover from rejection.

### Task 4.1 — Client 0-RTT Packet Construction

When client has a saved `SessionTicket`:
- Derive 0-RTT keys from PSK
- Build 0-RTT long-header packets with early data
- Send alongside Initial (ClientHello)

**Files**: `src/zoomies/core/connection.py`, `src/zoomies/packet/builder.py`
**Acceptance**: `test_client_sends_0rtt_packets` captures outgoing datagrams with `PACKET_TYPE_ZERO_RTT`.

### Task 4.2 — 0-RTT Rejection Resend

If server's EncryptedExtensions does NOT include `early_data`:
- Mark 0-RTT as rejected
- Retransmit all 0-RTT stream data as 1-RTT frames
- Emit `ZeroRttRejected` event

**Files**: `src/zoomies/core/connection.py`, `src/zoomies/events.py`
**Acceptance**: `test_0rtt_rejection_resend` verifies data arrives via 1-RTT after rejection.

### Task 4.3 — 0-RTT Loss Recovery

Map 0-RTT sent packets to the Application packet space for loss detection. When 0-RTT is rejected, mark all 0-RTT packets as lost for retransmission.

**Files**: `src/zoomies/recovery/packet_space.py`, `src/zoomies/core/connection.py`
**Acceptance**: `test_0rtt_loss_recovery` confirms retransmission after packet loss in 0-RTT epoch.

---

## Sprint 5: H3 Integration + End-to-End

**Goal**: HTTP/3 GET request completes over 0-RTT in a loopback test.

### Task 5.1 — H3 0-RTT Request Handling

H3Connection passes `is_0rtt=True` through to `H3HeadersReceived` events (plumbing already exists). Add:
- Server-side: deliver 0-RTT headers to application
- Client-side: allow `send_headers()` + `send_data()` before handshake completes

**Files**: `src/zoomies/h3/connection.py`
**Acceptance**: `test_h3_0rtt_get_request` verifies headers arrive with `is_0rtt=True`.

### Task 5.2 — End-to-End Loopback Test

Full scenario: client connects, receives ticket, reconnects with 0-RTT GET, server responds.

**Files**: `tests/test_0rtt.py`
**Acceptance**: `pytest tests/test_0rtt.py -v` passes; test covers: ticket issuance → 0-RTT send → server delivery → response.

### Task 5.3 — Update Examples + Docs

- Add `examples/zero_rtt_client.py` showing 0-RTT usage
- Update `docs/ROADMAP.md` to mark 0-RTT as done
- Add `docs/design/0rtt-early-data-plan.md` (this document) to design docs

**Files**: `examples/zero_rtt_client.py`, `docs/ROADMAP.md`
**Acceptance**: `python examples/zero_rtt_client.py` runs without error.

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| PSK binder computation incorrect → interop failure | Medium | High | Sprint 0 validates against RFC 8448 test vectors; Sprint 1.2 tests binder round-trip |
| Anti-replay callback is too complex for callers | Low | Medium | Sprint 0.2 designs simple `Protocol`; default implementation provided |
| 0-RTT rejection resend loses data ordering | Medium | High | Sprint 0.3 designs resend strategy on paper; Sprint 4.2 tests ordering |
| Key schedule regression breaks existing handshake | Low | High | Invariant 1: all existing tests must pass at every sprint |
| `cryptography` library lacks needed PSK primitives | Low | High | Sprint 0.1 audits available HKDF/HMAC APIs (already used for handshake) |
| 0-RTT + congestion control interaction | Low | Medium | Sprint 4.3 maps 0-RTT to Application space; NewReno applies naturally |

---

## Success Metrics

| Metric | Current | After Sprint 3 | After Sprint 5 |
|--------|---------|----------------|----------------|
| 0-RTT packet types handled | 0 (stub) | 1 (server decrypt) | 2 (server + client) |
| `is_0rtt=True` events emitted | 0 | >0 (server side) | >0 (both sides) |
| Session ticket round-trip | N/A | Working (Sprint 1) | Working |
| E2E 0-RTT HTTP/3 test | 0 | 0 | 1+ |
| Test count for 0-RTT | 0 | ~15 | ~30 |
| RFC 9001 §4 compliance | Partial (no PSK) | PSK handshake | Full 0-RTT |

---

## Relationship to Existing Work

- **Beta 0.3.x (Retry, Version Negotiation)** — parallel — 0-RTT is independent of Retry; can proceed concurrently
- **Pounce ASGI integration** — prerequisite for — Pounce needs 0-RTT for competitive TTFB on repeat connections
- **aioquic interop** — validates — 0-RTT interop testing against aioquic is a natural follow-up

---

## Changelog

- 2026-04-10: Draft created from codebase analysis
- 2026-04-10: All 6 sprints completed. 412 tests pass (up from 383). Full 0-RTT E2E over H3 working.
