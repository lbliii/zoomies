# Sprint 0: 0-RTT Design — PSK Key Schedule, Anti-Replay, Rejection Recovery

**Status**: Complete
**Created**: 2026-04-10
**Parent**: [0rtt-early-data-plan.md](0rtt-early-data-plan.md)

---

## Task 0.1 — PSK Key Schedule

### Background

TLS 1.3 derives all keys from a key schedule rooted in two inputs: a **Pre-Shared Key (PSK)** and an **ephemeral (EC)DH shared secret**. The current implementation (`tls.py:315`) already walks this schedule but uses a zero PSK (`bytes(32)`), which is the standard full-handshake path per RFC 8446 §7.1.

For 0-RTT, we supply a *real* PSK from a prior session's resumption secret, enabling early traffic keys before the handshake completes.

### Key Schedule (RFC 8446 §7.1 + RFC 9001 §5)

```
             PSK (from SessionTicket.resumption_secret)
              |
              v
    early_secret = HKDF-Extract(salt=0, IKM=PSK)         <── NEW: real PSK
              |
              +--→ client_early_traffic_secret             <── NEW: 0-RTT keys
              |       = Derive-Secret(early_secret,
              |         "c e traffic", ClientHello)
              |
              +--→ early_exporter_master_secret             <── OPTIONAL (skip for now)
              |
              v
    derived   = Derive-Secret(early_secret, "derived", "")
              |
              v
    handshake_secret = HKDF-Extract(derived, DHE)          <── EXISTING (tls.py:317)
              |
              +--→ [c hs traffic, s hs traffic]             <── EXISTING
              |
              v
    derived2  = Derive-Secret(handshake_secret, "derived", transcript)
              |
              v
    master_secret = HKDF-Extract(derived2, 0)               <── EXISTING (tls.py:347)
              |
              +--→ [c ap traffic, s ap traffic]             <── EXISTING
              |
              +--→ resumption_master_secret                 <── NEW: for next ticket
                     = Derive-Secret(master_secret,
                       "res master", full_transcript)
```

### What changes vs. current code

| Step | Current (`tls.py`) | With PSK |
|------|-------------------|----------|
| `early_secret` (line 315) | `HKDF-Extract(0, 0)` — zero PSK | `HKDF-Extract(0, PSK)` — real PSK |
| `client_early_traffic_secret` | Not derived | `Derive-Secret(early_secret, "c e traffic", CH)` |
| `resumption_master_secret` | Not derived | `Derive-Secret(master_secret, "res master", full_transcript)` |
| Rest of schedule | Unchanged | Unchanged |

**Key insight**: The existing HKDF helpers (`hkdf_extract`, `hkdf_expand_label` in `_hkdf.py`) already support every operation needed. No new crypto primitives required.

### HKDF Label Table

All labels use the existing `hkdf_expand_label` function with `algorithm=SHA256`:

| Secret | Label | Context | Length | Used For |
|--------|-------|---------|--------|----------|
| `client_early_traffic_secret` | `b"c e traffic"` | ClientHello hash | 32 | 0-RTT AEAD keys |
| `resumption_master_secret` | `b"res master"` | Full transcript hash | 32 | Next session ticket |
| `resumption_psk` | `b"resumption"` | ticket_nonce | 32 | PSK for next connection |

### QUIC-Specific Key Derivation

Once `client_early_traffic_secret` is derived, QUIC keys follow the same pattern as other epochs (`quic_crypto.py:16-25`):

```python
# Identical to derive_key_iv_hp() — no new function needed
key = hkdf_expand_label(SHA256, client_early_traffic_secret, b"quic key", b"", 16)
iv  = hkdf_expand_label(SHA256, client_early_traffic_secret, b"quic iv",  b"", 12)
hp  = hkdf_expand_label(SHA256, client_early_traffic_secret, b"quic hp",  b"", 16)
```

### SessionTicket Type

```python
@dataclass(frozen=True, slots=True)
class SessionTicket:
    """Opaque session ticket for TLS 1.3 resumption and 0-RTT.

    Issued by server after handshake via NewSessionTicket message.
    Client stores and presents on reconnection.
    """
    ticket: bytes                              # Opaque ticket data
    resumption_secret: bytes                   # resumption_master_secret
    max_early_data: int                        # 0xFFFFFFFF = unlimited (RFC 8446 §4.6.1)
    transport_parameters: QuicTransportParameters  # Saved for 0-RTT flow control
    cipher_suite: int = CIPHER_SUITE_AES_128_GCM
    timestamp: float = 0.0                     # When ticket was issued (monotonic)
    lifetime: int = 7200                       # Server-specified lifetime in seconds
    age_add: int = 0                           # Obfuscated ticket age (RFC 8446 §4.6.1)
    nonce: bytes = b""                         # Ticket nonce for PSK derivation
```

**PSK derivation from ticket** (RFC 8446 §4.6.1):
```python
psk = hkdf_expand_label(SHA256, ticket.resumption_secret, b"resumption", ticket.nonce, 32)
```

### NewSessionTicket Message Format (RFC 8446 §4.6.1)

```
struct {
    uint32 ticket_lifetime;        # seconds
    uint32 ticket_age_add;         # obfuscation
    opaque ticket_nonce<0..255>;
    opaque ticket<1..2^16-1>;
    Extension extensions<0..2^16-2>;  # includes early_data with max_early_data_size
} NewSessionTicket;
```

Server sends this as a post-handshake message in the 1-RTT epoch. The `ticket` field is opaque to the client — the server can embed whatever state it needs (encrypted transport parameters, etc.).

### TLS Extensions Needed

| Extension | Type Code | Where | Purpose |
|-----------|-----------|-------|---------|
| `pre_shared_key` | 41 | ClientHello, ServerHello | Offer/select PSK identity |
| `psk_key_exchange_modes` | 45 | ClientHello | Require `psk_dhe_ke` (1) mode |
| `early_data` | 42 | ClientHello, EncryptedExtensions, NewSessionTicket | Signal 0-RTT intent/acceptance |

**Design decision**: Support only `psk_dhe_ke` mode (PSK + ephemeral DH). This is required by RFC 9001 §4.5 for QUIC — pure PSK mode (`psk_ke`) is not allowed because QUIC mandates forward secrecy.

### PSK Binder Computation (RFC 8446 §4.2.11.2)

The `pre_shared_key` extension in ClientHello includes a binder — an HMAC proving the client possesses the PSK. The binder is computed over a truncated ClientHello (everything up to but not including the binder value itself).

```python
binder_key = Derive-Secret(early_secret, "res binder", "")
binder = HMAC(binder_key, Transcript-Hash(truncated_ClientHello))
```

**Implementation note**: This requires computing the ClientHello in two passes:
1. Build ClientHello with placeholder binder (32 zero bytes)
2. Compute `early_secret` from PSK, derive `binder_key`
3. Hash truncated ClientHello (everything except binder bytes)
4. Compute HMAC, replace placeholder with real binder

---

## Task 0.2 — Anti-Replay Strategy

### The Problem

0-RTT data can be replayed by a network attacker — they can capture and re-send the client's Initial + 0-RTT packets. The server cannot distinguish a replayed 0-RTT from a legitimate one based on crypto alone (unlike 1-RTT, where the handshake proves liveness).

RFC 9001 §9.2 requires servers to either:
1. Reject all 0-RTT, or
2. Implement application-level replay protection

### Options Evaluated

| Option | Mechanism | Fits Sans-I/O? | Complexity |
|--------|-----------|----------------|------------|
| A. Single-use ticket set | Server stores used ticket IDs in a set, rejects duplicates | Partial — needs persistent state | Low |
| B. Time-window + strike register | Server rejects tickets with obfuscated_age outside a window | Partial — needs clock | Medium |
| C. Caller-provided callback | Protocol interface; caller decides policy | Yes | Low (for us) |
| D. Default reject + opt-in accept | Server rejects 0-RTT unless caller explicitly enables | Yes | Lowest |

### Decision: Option C + D combined

**Rationale**: Sans-I/O means the protocol layer cannot own I/O, state, or clocks. The caller (e.g., Pounce) owns all of these. Therefore:

1. **Default**: Server rejects 0-RTT (safe by default — invariant 3)
2. **Opt-in**: Caller provides a `ZeroRttPolicy` that the connection consults

```python
from typing import Protocol

class ZeroRttPolicy(Protocol):
    """Caller-provided 0-RTT replay policy.

    Sans-I/O contract: the protocol layer asks; the caller decides.
    The caller owns state (ticket stores), clocks, and I/O.
    """

    def allow_0rtt(self, ticket_data: bytes, obfuscated_age: int) -> bool:
        """Return True to accept 0-RTT data for this ticket.

        Args:
            ticket_data: Opaque ticket bytes from the client's ClientHello.
            obfuscated_age: Client-reported ticket age (obfuscated per RFC 8446).

        Returns:
            True to accept and decrypt 0-RTT data.
            False to reject (client will resend as 1-RTT).

        Implementation guidance for callers:
        - Simplest: return False (reject all 0-RTT — safe default)
        - Single-use: track ticket_data in a set, return True only once
        - Time-window: decode age, reject if outside acceptable window
        - Idempotent: return True if the request type is safe to replay (GET)
        """
        ...
```

### Integration with QuicConfiguration

```python
@dataclass
class QuicConfiguration:
    # ... existing fields ...
    zero_rtt_policy: ZeroRttPolicy | None = None  # None = reject all 0-RTT
```

When `zero_rtt_policy is None`, the server never sets up 0-RTT keys and ignores the `early_data` extension. When provided, it calls `allow_0rtt()` during ClientHello processing.

### Flow

```
Client sends ClientHello + 0-RTT packets
    |
    v
Server receives ClientHello with pre_shared_key + early_data
    |
    v
Is zero_rtt_policy configured?
    |
    +-- No  → Reject: don't set up 0-RTT keys, omit early_data from EE
    |
    +-- Yes → Call policy.allow_0rtt(ticket_data, obfuscated_age)
                |
                +-- False → Reject (same as above)
                |
                +-- True  → Accept: derive 0-RTT keys, decrypt packets,
                            include early_data in EncryptedExtensions
```

### What the caller (Pounce) would implement

```python
class SimpleReplayGuard:
    """Example: single-use ticket with TTL."""

    def __init__(self, max_age_seconds: int = 120):
        self._used: set[bytes] = set()
        self._max_age = max_age_seconds

    def allow_0rtt(self, ticket_data: bytes, obfuscated_age: int) -> bool:
        if ticket_data in self._used:
            return False
        self._used.add(ticket_data)
        return True
```

---

## Task 0.3 — 0-RTT Rejection & Resend

### The Problem

When the server rejects 0-RTT (no `early_data` in EncryptedExtensions), the client must:
1. Recognize the rejection
2. Discard 0-RTT crypto state
3. Resend all 0-RTT stream data as 1-RTT

This must be transparent to the application layer — data that was "sent" as 0-RTT must arrive at the server without the application resending it.

### Client-Side State Machine

```
                        ┌──────────────┐
                        │   NONE       │ No ticket, no 0-RTT attempted
                        └──────┬───────┘
                               │ Client has SessionTicket
                               v
                        ┌──────────────┐
                        │  ATTEMPTING  │ 0-RTT packets sent alongside Initial
                        └──────┬───────┘
                               │ Server responds
                       ┌───────┴────────┐
                       v                v
                ┌──────────┐    ┌───────────┐
                │ ACCEPTED │    │ REJECTED  │
                └──────┬───┘    └─────┬─────┘
                       │              │
                       v              v
                Promote 0-RTT    Resend all 0-RTT
                streams to       stream data as 1-RTT
                1-RTT (no-op     (automatic, from
                for app)         send buffer)
```

```python
class ZeroRttState(StrEnum):
    NONE = "none"
    ATTEMPTING = "attempting"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
```

### How StreamSendState Handles Resend

The existing `StreamSendState` already buffers sent data (`_send_buffer`, `_buffer_start`) for loss-based retransmission (`get_data(offset, length)` at `stream.py:100-105`). For 0-RTT rejection, we exploit this same buffer:

**On rejection:**
1. Reset `_sent_end` back to 0 (or to the start of 0-RTT data)
2. The send buffer still contains the original data
3. The next `send_datagrams()` call re-emits the data as 1-RTT STREAM frames

```python
# In StreamSendState — new method
def reset_for_0rtt_rejection(self) -> None:
    """Reset send offset to resend 0-RTT data as 1-RTT."""
    self._sent_end = 0
    self._fin_sent = False
```

**Why this works**: The send buffer is a `bytearray` that accumulates all data written. The `_sent_end` offset tracks what's been flushed to packets. Resetting `_sent_end` causes the existing send path to re-emit everything from offset 0 — identical behavior to loss retransmission, just triggered by rejection instead of timeout.

### Connection-Level Tracking

`QuicConnection` needs to track which streams carried 0-RTT data:

```python
# New fields on QuicConnection
self._zero_rtt_state: ZeroRttState = ZeroRttState.NONE
self._zero_rtt_streams: set[int] = set()  # stream IDs sent as 0-RTT
```

**On 0-RTT send**: Add stream_id to `_zero_rtt_streams`.
**On rejection**: For each stream in `_zero_rtt_streams`, call `stream._send.reset_for_0rtt_rejection()`.
**On acceptance**: Clear `_zero_rtt_streams` (data already delivered).

### Packet Space for 0-RTT

RFC 9000 §17.2.3: 0-RTT packets use long headers with packet type 1. Per RFC 9002 §A.3, 0-RTT packets share the Application packet number space (not Initial). This is because 0-RTT and 1-RTT are both "application data" — they use the same packet number sequence.

**Implementation**: 0-RTT sent packets go into `_application_space`. No new packet space needed. When 0-RTT is rejected, all 0-RTT packets in `_application_space` are marked lost, triggering retransmission via the normal recovery path.

### Events

Two new events for the application layer:

```python
@dataclass(frozen=True, slots=True)
class ZeroRttAccepted:
    """Server accepted 0-RTT data."""

@dataclass(frozen=True, slots=True)
class ZeroRttRejected:
    """Server rejected 0-RTT. Data will be resent as 1-RTT automatically."""

@dataclass(frozen=True, slots=True)
class SessionTicketReceived:
    """Server issued a session ticket for future 0-RTT."""
    ticket: SessionTicket
```

### H3 Interaction

H3 does **not** need special rejection handling. Rejection and resend happen at the QUIC layer:

1. Client sends H3 HEADERS + DATA as 0-RTT STREAM frames
2. Server rejects 0-RTT
3. QUIC layer resets stream send offsets, resends as 1-RTT
4. H3 on the server side receives the data normally (with `is_0rtt=False`)

The only H3 concern: **which methods are safe for 0-RTT?** RFC 9114 §4.1 says servers MAY process 0-RTT requests. The decision is the application's (via `ZeroRttPolicy`), not H3's. H3 just passes the `is_0rtt` flag through so the application can decide.

### Flow Control with Saved Transport Parameters

When sending 0-RTT, the client must use the **server's transport parameters from the previous connection** (stored in `SessionTicket.transport_parameters`), not any newly negotiated ones:

- `initial_max_data` → connection-level flow control for 0-RTT
- `initial_max_stream_data_bidi_local/remote` → per-stream limits
- `initial_max_streams_bidi/uni` → stream count limits

After the handshake completes, the client switches to the server's newly advertised parameters. If the new parameters are more restrictive than the saved ones, this is a connection error (RFC 9000 §7.4.1).

---

## Summary of New Types

| Type | File | Purpose |
|------|------|---------|
| `SessionTicket` | `events.py` or `crypto/tls.py` | Frozen dataclass for resumption state |
| `ZeroRttState` | `core/connection.py` | Client-side 0-RTT lifecycle enum |
| `ZeroRttPolicy` | `core/connection.py` (Protocol) | Caller-provided replay guard |
| `ZeroRttAccepted` | `events.py` | Event: server confirmed 0-RTT |
| `ZeroRttRejected` | `events.py` | Event: server rejected 0-RTT |
| `SessionTicketReceived` | `events.py` | Event: ticket issued by server |

## Summary of Code Changes by File

| File | Change |
|------|--------|
| `crypto/tls.py` | PSK in ClientHello, binder, NewSessionTicket, `early_data` extension, `pre_shared_key` extension, `psk_key_exchange_modes` extension, `resumption_master_secret` derivation |
| `crypto/quic_crypto.py` | `CryptoPair.setup_0rtt()` — single new method, uses existing `derive_key_iv_hp` |
| `crypto/_hkdf.py` | No changes — all labels already supported |
| `core/connection.py` | `_zero_rtt_crypto`, `_zero_rtt_state`, `_zero_rtt_streams`, `_handle_0rtt()` implementation, 0-RTT send path, rejection recovery |
| `core/stream.py` | `StreamSendState.reset_for_0rtt_rejection()` — one new method |
| `events.py` | 3 new event types, update `QuicEvent` union |
| `packet/header.py` | No changes — `PACKET_TYPE_ZERO_RTT` already defined |
| `packet/builder.py` | No changes — generic `push_quic_header` works for 0-RTT |
| `packet/transport_params.py` | No changes — all needed params exist |
| `recovery/` | No changes — 0-RTT uses Application space |

## Open Questions (to resolve during implementation)

1. **Where to store `SessionTicket`?** Option A: new `SessionTicket` type in `events.py` (alongside other frozen dataclasses). Option B: in `crypto/tls.py` (near TLS code). **Leaning toward**: `crypto/tls.py` since it's a TLS concept, then re-exported.

2. **Server ticket encryption**: The `ticket` field in `NewSessionTicket` is opaque. For now, use a simple scheme: server encrypts its state (PSK + transport params) with a server-side key. The server key management is the caller's responsibility (sans-I/O).

3. **Multiple tickets**: RFC 8446 allows servers to send multiple tickets. For simplicity, start with one ticket per handshake. Add multi-ticket support later if needed.
