# Zoomies Architecture

Guiding design document for the Zoomies QUIC/HTTP3 library.

## Vision

- **Sans-I/O QUIC/HTTP3** for Python 3.14t
- **Server-first** — initial implementation serves HTTP/3; client and multipath later
- **Native to Pounce; usable standalone** — Pounce's H3Worker consumes zoomies; `pounce[h3]` depends on zoomies. Zero dependencies on Pounce, Chirp, or Bengal. Caller provides I/O.

## Principles

1. **Types as contracts** — Frozen dataclasses for events, Protocols for handlers. No `Any` in public APIs.

2. **Core/orchestrator split** — Protocol layer (core) is passive: no I/O, no logging. The caller (orchestrator) owns I/O and feeds datagrams.

3. **Composition over inheritance** — Mixins, not deep hierarchies. Each layer is focused.

4. **Free-threading native** — No C extensions with limited API. Use cryptography (3.14t-compatible) for TLS. Thread-safe by design.

## Layers

```
Layer 3: HTTP/3 (H3Connection, QPACK)     — Application
Layer 2: QUIC connection/stream state     — Transport
Layer 1: Packet encode/decode, crypto    — Protocol
Layer 0: I/O (datagram send/recv)         — Caller's responsibility
```

- **Packet** — Encode/decode QUIC packets
- **Crypto** — TLS 1.3 via cryptography
- **Stream** — QUIC stream state
- **Connection** — QUIC connection state machine
- **HTTP/3** — H3Connection, QPACK

## Integration

- **Pounce** — `_h3_handler.py` and `h3_bridge.py` stay; they consume zoomies events and build ASGI scope
- **Boundary** — Zoomies has zero pounce imports. The dependency is one-way: Pounce depends on zoomies.

## Design Philosophy

- **[primitives-first.md](primitives-first.md)** — Build from protocol primitives up; contracts, canonical keys, type-first.

## References

- [RFC 9000: QUIC](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
- [pounce protocols/_base.py](https://github.com/lbliii/pounce) — Sans-I/O pattern
