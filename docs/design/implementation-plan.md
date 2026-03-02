# Zoomies Implementation Plan

Phased plan for implementing the QUIC/HTTP3 library. **See [primitives-first.md](primitives-first.md) for the S-tier design philosophy** — build from primitives up, with explicit contracts and canonical keys. This plan provides phase details and aioquic reference points.

**Current vs planned:** See [ROADMAP.md](../ROADMAP.md) for the phased roadmap (pre-alpha → alpha → beta → production). Summary:

| Phase | Status | Notes |
|-------|--------|-------|
| 1. Buffer, packet | Done | Buffer, header parse, frames, retry |
| 2. QUIC crypto | Done | Initial + Handshake + 1-RTT keys; TLS 1.3 handshake |
| 3. Streams | Done | Stream state, frame parsing |
| 4. Connection | Done | Initial, Handshake, Short header; CRYPTO, stream flush |
| 5. H3/QPACK | Done | H3Connection, QPACK static table |
| 6. Recovery | Not started | Congestion, RTT (optional) |

---

## aioquic Reference Summary

| aioquic Module | Size | Purpose | Zoomies Equivalent |
|----------------|------|---------|--------------------|
| `buffer.py` | 770 B | Python wrapper for `_buffer.c` | `core/buffer.py` (pure Python) |
| `_buffer.c` | 12 KB | C extension for fast buffer ops | **Omit** — use `io.BytesIO` or minimal Python buffer |
| `_crypto.c` | 12 KB | C extension for AEAD | **Omit** — use `cryptography` |
| `tls.py` | 76 KB | Custom TLS 1.3 handshake | `core/tls.py` — use `cryptography` TLS APIs |
| `quic/packet.py` | 20 KB | Packet decode/encode | `core/packet.py` |
| `quic/packet_builder.py` | 13 KB | Packet construction | `core/packet_builder.py` |
| `quic/crypto.py` | 8 KB | QUIC-specific crypto (keys, IV) | `core/quic_crypto.py` |
| `quic/stream.py` | 12 KB | Stream state | `core/stream.py` |
| `quic/rangeset.py` | 3 KB | ACK ranges | `core/rangeset.py` |
| `quic/retry.py` | 2 KB | Retry integrity | `core/retry.py` |
| `quic/recovery.py` | 13 KB | Congestion, RTT | `core/recovery.py` (later phase) |
| `quic/connection.py` | 140 KB | Connection state machine | `core/connection.py` |
| `quic/events.py` | 3 KB | QUIC events | `events.py` |
| `quic/configuration.py` | 5 KB | Config dataclass | `core/configuration.py` |
| `h3/connection.py` | 33 KB | HTTP/3 + QPACK | `h3/connection.py` |
| `asyncio/` | — | I/O glue | **Omit** — caller (Pounce) owns I/O |

**Key differences for Zoomies:**

- No C extensions → pure Python + `cryptography`
- No asyncio → sans-I/O; caller feeds datagrams, reads events
- No logger in core → orchestration layer logs
- Server-first → client handshake can be deferred

---

## Module Layout (Target)

```
src/zoomies/
├── __init__.py
├── events.py           # QuicEvent, H3Event, etc.
├── py.typed
├── core/               # Layer 1: Packet, Crypto, Stream
│   ├── __init__.py
│   ├── buffer.py       # Minimal read/write buffer (no C)
│   ├── packet.py       # Decode/encode QUIC packets
│   ├── packet_builder.py
│   ├── rangeset.py     # ACK ranges
│   ├── retry.py        # Retry integrity tag
│   ├── quic_crypto.py  # QUIC AEAD via cryptography
│   ├── tls.py          # TLS 1.3 via cryptography (or thin wrapper)
│   ├── stream.py       # Stream receive/send state
│   ├── configuration.py
│   └── connection.py   # Connection state machine (large)
├── recovery/           # Layer 1.5: Congestion (can defer)
│   ├── __init__.py
│   └── ...
└── h3/                 # Layer 3: HTTP/3
    ├── __init__.py
    ├── connection.py
    └── qpack.py        # QPACK encode/decode
```

---

## Phases

### Phase 1: Buffer and Packet (Foundation)

**Goal:** Parse and build QUIC packets. No crypto yet — use opaque payloads for tests.

**Deliverables:**

| File | Responsibility |
|------|----------------|
| `core/buffer.py` | `Buffer` with `pull_*`, `push_*`, `tell()`, `data_slice()`. Pure Python. |
| `core/packet.py` | `pull_quic_header`, `decode_packet_number`, frame types (ACK, STREAM, etc.), transport params |
| `core/packet_builder.py` | `push_quic_header`, `push_ack_frame`, etc. |
| `core/rangeset.py` | `RangeSet` for ACK ranges |
| `core/retry.py` | `get_retry_integrity_tag`, `encode_quic_retry` |

**Tests (mirror aioquic):**

- `tests/test_buffer.py` — Buffer read/write, bounds
- `tests/test_packet.py` — Header parse (initial, retry, VN, short), transport params, ACK frames
- Use RFC 9000/9001 appendix hex dumps and aioquic `test_crypto_v1` / `test_crypto_v2` packet fixtures (header only; payload stays opaque until Phase 2)

**aioquic patterns to reuse:**

- `Buffer(data=...)` / `Buffer(capacity=...)` constructor
- `pull_quic_header(buf, host_cid_length=8)` returning a header dataclass
- Round-trip tests: `pull_*` then `push_*` → compare bytes

---

### Phase 2: QUIC Crypto

**Goal:** Encrypt/decrypt packet payloads using QUIC's AEAD (RFC 9001). Use `cryptography` for ChaCha20-Poly1305 and AES-128-GCM.

**Deliverables:**

| File | Responsibility |
|------|----------------|
| `core/quic_crypto.py` | Key derivation (initial secrets, 1-RTT, etc.), packet protection (header + payload) |
| `core/tls.py` | TLS 1.3 handshake via `cryptography` — server handshake only initially |

**Tests:**

- `tests/test_quic_crypto.py` — Encrypt/decrypt round-trip; verify against known vectors (RFC or aioquic `test_crypto_v1` / `test_crypto_v2` hex dumps)
- `tests/test_tls.py` — Handshake state machine (server); certificate handling

**aioquic fixtures:**

- `LONG_CLIENT_ENCRYPTED_PACKET`, `LONG_SERVER_ENCRYPTED_PACKET` from `test_crypto_v1.py` and `test_crypto_v2.py` — use as golden vectors for decrypt validation

---

### Phase 3: Streams

**Goal:** QUIC stream receive/send state — ordered byte streams, flow control.

**Deliverables:**

| File | Responsibility |
|------|----------------|
| `core/stream.py` | `Stream` (or similar) — receive buffers, send offsets, FIN handling |

**Tests:**

- `tests/test_stream.py` — Reorder frames, FIN, flow control limits
- Mirror aioquic's `test_stream.py` structure

---

### Phase 4: Connection State Machine

**Goal:** Full QUIC connection lifecycle (server): Initial → Handshake → 1-RTT. Handle packets, emit events, produce outgoing packets.

**Deliverables:**

| File | Responsibility |
|------|----------------|
| `core/connection.py` | `QuicConnection` (server) — `datagram_received(data)` → events; `send_datagrams()` → list of bytes |
| `core/configuration.py` | `QuicConfiguration` — cert, key, limits |
| `events.py` | `DatagramReceived`, `StreamDataReceived`, `ConnectionClosed`, etc. |

**API (sans-I/O):**

```python
def datagram_received(self, data: bytes, addr: tuple[str, int]) -> list[QuicEvent]: ...
def send_datagrams(self) -> list[bytes]: ...
```

**Tests:**

- `tests/test_connection.py` — Handshake, stream open, data, close
- Use aioquic's `test_connection.py` as reference — many scenarios (version negotiation, retry, etc.)
- Integration: run server connection against a known client trace (e.g. aioquic client) or use pre-recorded datagrams

---

### Phase 5: HTTP/3 and QPACK

**Goal:** HTTP/3 over QUIC streams. QPACK for headers.

**Deliverables:**

| File | Responsibility |
|------|----------------|
| `h3/connection.py` | `H3Connection` — receive H3 frames, emit `H3HeadersReceived`, `H3DataReceived` |
| `h3/qpack.py` | QPACK encoder/decoder |

**Tests:**

- `tests/test_h3.py` — Request/response parsing, QPACK dynamic table
- `tests/test_qpack.py` — Header encode/decode round-trip
- Mirror aioquic `test_h3.py` scenarios

---

### Phase 6: Recovery (Optional / Later)

**Goal:** Congestion control, RTT estimation, loss detection. Can be simplified initially (e.g. basic RTT, no aggressive congestion).

**Deliverables:**

- `recovery/` — Congestion state, ACK handling, loss detection
- Integrate into `connection.py`

**Tests:** `tests/test_recovery.py` — RTT, loss, ACK generation

---

## Test Infrastructure

### Fixtures to Add

| Fixture | Source | Use |
|---------|--------|-----|
| `ssl_cert.pem`, `ssl_key.pem` | Generate or copy from aioquic | TLS server cert |
| `pycacert.pem` | aioquic or generate | CA for client cert validation (if needed) |
| `tls_*.bin` | aioquic `test_tls.py` | TLS message parsing tests |
| Packet hex dumps | aioquic `test_crypto_v1`, `test_crypto_v2`, `test_packet` | Golden vectors |

### Test Utils

Create `tests/utils.py`:

- `load(name: str) -> bytes` — Load fixture from `tests/` dir
- `generate_ec_certificate(...)` — For dynamic cert generation (reuse aioquic pattern, drop asyncio)
- `SERVER_CERTFILE`, `SERVER_KEYFILE` — Paths to fixtures

### Test Style

- **Unit:** Pure functions, no I/O. Use `pytest` + `pytest.mark.parametrize` for variants.
- **Integration:** `@pytest.mark.integration` — full handshake, optional network (or loopback).
- **Hypothesis:** Use for buffer/parser fuzzing in Phase 1 (e.g. `st.binary()` for packet payloads).

---

## aioquic Test Patterns to Reuse

1. **Header parse:** `buf = Buffer(data=hex_packet); header = pull_quic_header(buf); assert header.version == ...`
2. **Round-trip:** `pulled = pull_X(buf); pushed = Buffer(); push_X(pushed, pulled); assert pushed.data == buf.data`
3. **Error cases:** `with pytest.raises(ValueError, match="...")` for truncated, invalid, too-long
4. **RFC appendix vectors:** Use exact hex from RFC 9000/9001 appendices
5. **Crypto fixtures:** `test_crypto_v1.LONG_CLIENT_ENCRYPTED_PACKET` etc. — decrypt and check plaintext structure

---

## Dependencies

- **cryptography** — TLS 1.3, AEAD (ChaCha20-Poly1305, AES-128-GCM), X.509
- No aioquic dependency — reference only
- No asyncio in zoomies

---

## Order of Implementation

```
Phase 1: buffer → rangeset → retry → packet → packet_builder
Phase 2: quic_crypto → tls
Phase 3: stream
Phase 4: configuration → connection (with events)
Phase 5: qpack → h3/connection
Phase 6: recovery (optional)
```

Each phase ships with tests before moving on. Integration tests can start in Phase 4 once connection exists.

---

## Appendix: aioquic Crypto Fixtures (Phase 2)

Copy or adapt these vectors from aioquic `tests/test_crypto_v1.py` and `test_crypto_v2.py`:

| Constant | File | Use |
|----------|------|-----|
| `LONG_CLIENT_PLAIN_HEADER`, `LONG_CLIENT_PLAIN_PAYLOAD` | test_crypto_v1 | Decrypt `LONG_CLIENT_ENCRYPTED_PACKET` → verify |
| `LONG_CLIENT_ENCRYPTED_PACKET` | test_crypto_v1 | Golden decrypt test |
| `LONG_SERVER_PLAIN_HEADER`, `LONG_SERVER_PLAIN_PAYLOAD` | test_crypto_v1 | Decrypt `LONG_SERVER_ENCRYPTED_PACKET` |
| `LONG_SERVER_ENCRYPTED_PACKET` | test_crypto_v1 | Golden decrypt test |
| `CHACHA20_CLIENT_*`, `CHACHA20_SERVER_*` | test_crypto_v1 | ChaCha20-Poly1305 vectors (RFC 9001 A.5) |
| `derive_key_iv_hp` secret/key/iv/hp | test_crypto_v1 | Key derivation (RFC 9001 A.1) |

Initial setup: `CryptoPair.setup_initial(cid=..., is_client=..., version=...)` with `cid=8394c8f03e515708`.

---

## References

- [RFC 9000: QUIC](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 9001: TLS for QUIC](https://www.rfc-editor.org/rfc/rfc9001.html)
- [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
- [RFC 9204: QPACK](https://www.rfc-editor.org/rfc/rfc9204.html)
- [aioquic GitHub](https://github.com/aiortc/aioquic) — structure, tests, fixtures
- [pounce protocols/_base.py](https://github.com/lbliii/pounce) — sans-I/O handler pattern
